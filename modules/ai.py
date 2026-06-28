"""
VENOM AI — Unified AI Integration Module.
Handles sending target findings and chat history to Gemini, Groq, OpenRouter, and custom endpoints.
"""

import aiohttp
import json
from typing import List, Dict, Any

async def query_ai(
    provider: str,
    api_key: str,
    findings: Dict[str, Any],
    messages: List[Dict[str, str]],
    model: str = "",
    base_url: str = ""
) -> str:
    """
    Unified AI Query interface supporting Google Gemini, Groq, OpenRouter, and custom endpoints.
    """
    # Formulate a professional system instruction with target findings included.
    system_instruction = (
        "You are VENOM AI, an elite, strict, and precise OSINT Correlation Analyst Agent.\n"
        "Your sole objective is to analyze the provided JSON intelligence data gathered by the VENOM framework.\n\n"
        "CRITICAL DIRECTIVES:\n"
        "1. ZERO HALLUCINATION: You must ONLY state facts found directly within the JSON. If data is not present, explicitly state 'No data found' or do not mention it. Never guess, assume, or invent records.\n"
        "2. CORRELATION: Your primary value is connecting data. If you see a username in `social.found`, check if it matches the `name_inference` or `email` local part. If you see compromised passwords in `hibp.breaches` or `leakcheck`, highlight the severity.\n"
        "3. AUTONOMOUS RESEARCH: Review the `web_search_...` JSON keys. These contain live, real-time DuckDuckGo search snippets scraped from the internet just now. Use these snippets to cross-reference the target's current activities, latest mentions, or real-world identity.\n"
        "4. DOMAIN INTELLIGENCE: If `domain` or `ip` data exists, analyze the hosting provider (e.g., Shodan, GeoIP) and security posture (SPF/DMARC).\n"
        "5. ACTIONABILITY: Highlight critical vulnerabilities (e.g., 'Target has 4 compromised passwords in recent breaches' or 'Domain is missing DMARC and can be spoofed').\n"
        "6. TONE: Respond as a military-grade intelligence analyst. Use short, punchy sentences, bullet points, and bold text for emphasis. Do not use conversational filler.\n\n"
        f"TARGET OSINT SCAN DATA (JSON):\n{json.dumps(findings, default=str)}"
    )

    provider = provider.lower().strip()

    if provider == "gemini":
        return await query_gemini(api_key, system_instruction, messages, model)
    elif provider in ("groq", "openrouter", "custom"):
        return await query_openai_compatible(provider, api_key, system_instruction, messages, model, base_url)
    else:
        raise ValueError(f"Unknown AI provider: {provider}")


async def query_gemini(api_key: str, system_instruction: str, messages: List[Dict[str, str]], model: str = "") -> str:
    # Default model if none specified
    if not model:
        model = "gemini-1.5-flash"

    # Convert chat history to Gemini's API format
    contents = []
    for msg in messages:
        role = msg.get("role", "user")
        if role == "assistant":
            role = "model"
        # Make sure role is one of user/model
        if role not in ("user", "model"):
            role = "user"
            
        contents.append({
            "role": role,
            "parts": [{"text": msg.get("content", "")}]
        })
        
    payload = {
        "contents": contents,
        "systemInstruction": {
            "parts": [{"text": system_instruction}]
        },
        "generationConfig": {
            "temperature": 0.1,
            "maxOutputTokens": 2048
        }
    }
    
    headers = {
        "Content-Type": "application/json"
    }

    # Sequential candidates in case the requested model fails with a 404
    candidate_models = [model]
    fallbacks = ["gemini-1.5-flash", "gemini-1.5-flash-latest", "gemini-2.0-flash", "gemini-1.5-pro"]
    for fb in fallbacks:
        if fb not in candidate_models:
            candidate_models.append(fb)

    last_error = None
    
    async with aiohttp.ClientSession() as session:
        for current_model in candidate_models:
            url = f"https://generativelanguage.googleapis.com/v1beta/models/{current_model}:generateContent?key={api_key}"
            try:
                async with session.post(url, json=payload, headers=headers) as resp:
                    if resp.status == 404:
                        error_text = await resp.text()
                        try:
                            err_json = json.loads(error_text)
                            msg = err_json.get("error", {}).get("message", error_text)
                        except Exception:
                            msg = error_text
                        last_error = RuntimeError(f"Gemini API Error (status 404 for model {current_model}): {msg}")
                        continue
                        
                    if resp.status != 200:
                        error_text = await resp.text()
                        try:
                            err_json = json.loads(error_text)
                            msg = err_json.get("error", {}).get("message", error_text)
                        except Exception:
                            msg = error_text
                        raise RuntimeError(f"Gemini API Error (status {resp.status}): {msg}")
                    
                    resp_json = await resp.json()
                    try:
                        text_response = resp_json["candidates"][0]["content"]["parts"][0]["text"]
                        return text_response
                    except (KeyError, IndexError):
                        raise RuntimeError(f"Invalid response format from Gemini: {json.dumps(resp_json)}")
            except Exception as e:
                # Let 404 status continue to the next model
                if isinstance(e, RuntimeError) and "status 404" in str(e):
                    last_error = e
                    continue
                raise e

        if last_error:
            raise last_error
        raise RuntimeError("No Gemini models responded successfully.")


async def query_openai_compatible(
    provider: str,
    api_key: str,
    system_instruction: str,
    messages: List[Dict[str, str]],
    model: str = "",
    base_url: str = ""
) -> str:
    # Set default URL and Model
    if provider == "groq":
        url = "https://api.groq.com/openai/v1/chat/completions"
        if not model:
            model = "llama-3.3-70b-versatile"
    elif provider == "openrouter":
        url = "https://openrouter.ai/api/v1/chat/completions"
        if not model:
            model = "openrouter/free"
    elif provider == "custom":
        if not base_url:
            raise ValueError("Custom provider base URL must be set.")
        # Ensure base_url ends in /chat/completions
        url = base_url.strip()
        if not url.endswith("/chat/completions"):
            if url.endswith("/"):
                url += "chat/completions"
            else:
                url += "/chat/completions"
        if not model:
            model = "gpt-4o"
    else:
        raise ValueError(f"Unsupported OpenAI compatible provider: {provider}")

    # Build the messages array with system instruction first
    formatted_messages = [
        {"role": "system", "content": system_instruction}
    ]
    for msg in messages:
        role = msg.get("role", "user")
        if role == "model":
            role = "assistant"
        if role not in ("user", "assistant", "system"):
            role = "user"
        formatted_messages.append({
            "role": role,
            "content": msg.get("content", "")
        })

    payload = {
        "model": model,
        "messages": formatted_messages,
        "temperature": 0.1,
        "max_tokens": 2048
    }

    headers = {
        "Content-Type": "application/json"
    }
    if api_key:
        headers["Authorization"] = f"Bearer {api_key}"

    if provider == "openrouter":
        headers["HTTP-Referer"] = "https://github.com/ghostport-sudo/VENOM"
        headers["X-OpenRouter-Title"] = "VENOM OSINT Suite"

    async with aiohttp.ClientSession() as session:
        async with session.post(url, json=payload, headers=headers) as resp:
            if resp.status != 200:
                error_text = await resp.text()
                try:
                    err_json = json.loads(error_text)
                    msg = err_json.get("error", {}).get("message", error_text)
                except Exception:
                    msg = error_text
                raise RuntimeError(f"{provider.upper()} API Error (status {resp.status}): {msg}")

            resp_json = await resp.json()
            try:
                text_response = resp_json["choices"][0]["message"]["content"]
                return text_response
            except (KeyError, IndexError):
                raise RuntimeError(f"Invalid response format from {provider.upper()}: {json.dumps(resp_json)}")
