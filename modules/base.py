import abc
import asyncio
import random
from typing import Any, Dict, Optional, List
import aiohttp

# ── Dynamic Header Rotation & WAF Detection Helpers ─────────────────────────

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/121.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2.1 Safari/605.1.15",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36 Edg/122.0.0.0",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
]

def get_random_user_agent() -> str:
    """Return a randomly chosen legitimate User-Agent string."""
    try:
        return random.SystemRandom().choice(USER_AGENTS)
    except NotImplementedError:
        return random.choice(USER_AGENTS)

def is_waf_blocked(status: int, text: str) -> bool:
    """Check if the response status or body text indicates a Cloudflare or WAF block."""
    text_lower = text.lower()
    if status in (403, 503, 429):
        if any(keyword in text_lower for keyword in ["cloudflare", "just a moment", "ddos protection", "ray id", "sucuri"]):
            return True
    return any(keyword in text_lower for keyword in ["cloudflare", "just a moment", "ddos protection"])


class BaseOSINTModule(abc.ABC):
    """
    Abstract Base Class for all OSINT scanning modules.
    Standardizes initialization, execution flow, error handling, and output normalization.
    """
    def __init__(self, target: str, api_key: Optional[str] = None, proxy: Optional[str] = None):
        self.target = target
        self.api_key = api_key
        self.proxy = proxy

    @abc.abstractmethod
    async def fetch(self, session: aiohttp.ClientSession) -> Any:
        """
        Pure abstract network layer. Must handle the raw connection to the specific third-party API or website.
        """
        pass

    @abc.abstractmethod
    def normalize(self, raw_data: Any) -> Dict[str, Any]:
        """
        Pure abstract transformation layer. Must map and clean mismatched raw upstream payloads into a uniform schema.
        """
        pass

    async def _request(self, session: aiohttp.ClientSession, method: str, url: str, **kwargs) -> Any:
        """
        Helper method to make asynchronous HTTP requests with header rotation, proxy routing,
        WAF validation, and error handling.
        """
        headers = kwargs.get("headers", {}) or {}
        if "User-Agent" not in headers:
            headers["User-Agent"] = get_random_user_agent()
        kwargs["headers"] = headers

        if self.proxy and "proxy" not in kwargs:
            kwargs["proxy"] = self.proxy

        timeout_sec = kwargs.pop("timeout", 10)
        is_json = kwargs.pop("is_json_response", False)

        async with session.request(method, url, timeout=aiohttp.ClientTimeout(total=timeout_sec), **kwargs) as resp:
            status = resp.status
            
            # Read response body
            body_text = ""
            try:
                body_text = await resp.text()
            except Exception:
                try:
                    body_bytes = await resp.read()
                    body_text = body_bytes.decode('utf-8', errors='ignore')
                except Exception:
                    pass

            # Validate WAF
            if is_waf_blocked(status, body_text):
                return {"Status": "Protected/WAF", "status_code": status, "body": body_text}

            # Return appropriate format
            if is_json:
                try:
                    return await resp.json()
                except Exception:
                    # If JSON parsing fails, check if the response status is an error
                    if status >= 400:
                        resp.raise_for_status()
                    return {"error": "InvalidJSON", "body": body_text, "status_code": status}
            
            # For non-json, return text (or status if error)
            if status >= 400:
                resp.raise_for_status()
            return body_text

    async def run(self, session: aiohttp.ClientSession) -> Dict[str, Any]:
        """
        Concrete execution wrapper. Wraps fetch and normalize inside robust try-except blocks.
        """
        try:
            raw_data = await self.fetch(session)
            # Check if fetch returned a WAF or error dict directly
            if isinstance(raw_data, dict):
                if raw_data.get("Status") == "Protected/WAF":
                    return raw_data
                if raw_data.get("error") == "InvalidJSON":
                    return {"Status": f"Error JSON ({raw_data.get('status_code')})", "details": "Failed to parse JSON response"}
            return self.normalize(raw_data)
        except asyncio.TimeoutError as e:
            return {"error": "TimeoutError", "details": str(e), "Status": "Timeout"}
        except aiohttp.ClientResponseError as e:
            if e.status in (403, 503):
                return {"error": "HTTPError", "details": f"Status {e.status}", "Status": "Protected/WAF"}
            return {"error": "HTTPError", "details": f"Status {e.status}", "Status": f"Error {e.status}"}
        except aiohttp.ClientError as e:
            return {"error": "ClientError", "details": str(e), "Status": "ConnectionError"}
        except Exception as e:
            return {"error": "UnexpectedError", "details": str(e), "Status": "Failed"}
