"""
Breach and leak database lookups.
HIBP, BreachDirectory, LeakCheck v2, Leak-Lookup, Dehashed,
PSBDMP Pastebin archive, IntelligenceX, OTX email pulse search,
Phonebook.cz, and OSINTLeak.
All queries are rewritten to run asynchronously using aiohttp and BaseOSINTModule.
"""

import hashlib
import urllib.parse
import asyncio
from typing import Any, Dict, Optional, List
import aiohttp
import re

from modules.base import BaseOSINTModule, get_random_user_agent
from modules.config import LEAK_LOOKUP_PUBLIC_KEY

# ── Asynchronous OSINT Modules ───────────────────────────────────────────────

class HIBPBreachesModule(BaseOSINTModule):
    """Retrieves leaked record details from HaveIBeenPwned API."""
    async def fetch(self, session: aiohttp.ClientSession) -> Any:
        if not self.api_key:
            return None
        url = (f"https://haveibeenpwned.com/api/v3/breachedaccount/"
               f"{urllib.parse.quote(self.target)}?truncateResponse=false")
        headers = {"hibp-api-key": self.api_key, "User-Agent": "VenomOSINT"}
        try:
            async with session.get(url, headers=headers, timeout=aiohttp.ClientTimeout(total=10)) as resp:
                if resp.status == 200:
                    return await resp.json()
                if resp.status == 404:
                    return []
                if resp.status == 401:
                    return {"_bad_key": True}
                if resp.status == 429:
                    await asyncio.sleep(2)
                    return await self.fetch(session)
        except Exception:
            pass
        return None

    def normalize(self, raw_data: Any) -> Dict[str, Any]:
        if raw_data is None:
            return {"error": "Request failed", "breaches": []}
        if isinstance(raw_data, dict) and raw_data.get("_bad_key"):
            return {"error": "Invalid HIBP API Key", "breaches": []}
        return {"breaches": raw_data}


class HIBPPastesModule(BaseOSINTModule):
    """Checks HaveIBeenPwned API for paste bins containing target email."""
    async def fetch(self, session: aiohttp.ClientSession) -> Any:
        if not self.api_key:
            return []
        url = f"https://haveibeenpwned.com/api/v3/pasteaccount/{urllib.parse.quote(self.target)}"
        headers = {"hibp-api-key": self.api_key, "User-Agent": "VenomOSINT"}
        try:
            async with session.get(url, headers=headers, timeout=aiohttp.ClientTimeout(total=10)) as resp:
                if resp.status == 200:
                    return await resp.json()
                if resp.status == 404:
                    return []
        except Exception:
            pass
        return []

    def normalize(self, raw_data: Any) -> Dict[str, Any]:
        return {"pastes": raw_data or []}


class PasswordKAnonymityModule(BaseOSINTModule):
    """Secure password auditing check using k-anonymity SHA-1 lookup (password never sent in full)."""
    async def fetch(self, session: aiohttp.ClientSession) -> Any:
        # Target here is the raw password string. Hash locally.
        sha1 = hashlib.sha1(self.target.encode("utf-8")).hexdigest().upper()
        prefix, suffix = sha1[:5], sha1[5:]
        url = f"https://api.pwnedpasswords.com/range/{prefix}"
        try:
            res = await self._request(session, "GET", url, timeout=8)
            return {"suffix": suffix, "body": res}
        except Exception:
            return None

    def normalize(self, raw_data: Any) -> Dict[str, Any]:
        if not raw_data or not isinstance(raw_data, dict):
            return {"found": False, "count": 0}
        suffix = raw_data.get("suffix", "")
        body = raw_data.get("body", "")
        if not isinstance(body, str):
            return {"found": False, "count": 0}
            
        for line in body.splitlines():
            if ":" in line:
                h, count_str = line.split(":")
                if h == suffix:
                    return {"found": True, "count": int(count_str)}
        return {"found": False, "count": 0}


class BreachDirectoryModule(BaseOSINTModule):
    """Enriches data via BreachDirectory API (RapidAPI)."""
    async def fetch(self, session: aiohttp.ClientSession) -> Any:
        if not self.api_key:
            return {"error": "no_key"}
        url = (f"https://breachdirectory.p.rapidapi.com/"
               f"?func=auto&term={urllib.parse.quote(self.target)}")
        headers = {
            "X-RapidAPI-Key": self.api_key,
            "X-RapidAPI-Host": "breachdirectory.p.rapidapi.com"
        }
        try:
            return await self._request(session, "GET", url, headers=headers, timeout=10, is_json_response=True)
        except Exception as e:
            if hasattr(e, "status") and getattr(e, "status") in (401, 403):
                return {"error": "invalid_key"}
        return None

    def normalize(self, raw_data: Any) -> Dict[str, Any]:
        if not raw_data:
            return {"error": "Request failed"}
        if isinstance(raw_data, dict) and "error" in raw_data:
            return raw_data
        return {"results": raw_data}


class LeakCheckModule(BaseOSINTModule):
    """Performs credential breach checks using LeakCheck.io v2 API."""
    def __init__(self, target: str, query_type: str = "email", api_key: Optional[str] = None, proxy: Optional[str] = None):
        super().__init__(target, api_key, proxy)
        self.query_type = query_type

    async def fetch(self, session: aiohttp.ClientSession) -> Any:
        if not self.api_key:
            return {"_no_key": True}
        url = f"https://leakcheck.io/api/v2/query/{urllib.parse.quote(self.target)}"
        params = {"type": self.query_type}
        headers = {"X-API-Key": self.api_key, "User-Agent": "VenomOSINT/6.0"}
        try:
            async with session.get(url, params=params, headers=headers, timeout=aiohttp.ClientTimeout(total=12)) as r:
                if r.status == 200:
                    d = await r.json()
                    d["quota"] = r.headers.get("X-RateLimit-Remaining", "?")
                    return d
                if r.status == 401: return {"_bad_key": True}
                if r.status == 429: return {"_rate_limited": True}
                if r.status == 404: return {"found": False, "count": 0, "sources": []}
        except Exception:
            pass
        return None

    def normalize(self, raw_data: Any) -> Dict[str, Any]:
        if not raw_data:
            return {"found": False, "count": 0, "sources": []}
        if isinstance(raw_data, dict):
            if raw_data.get("_no_key"):
                return {"error": "Missing LeakCheck API Key", "found": False}
            if raw_data.get("_bad_key"):
                return {"error": "Invalid LeakCheck API Key", "found": False}
            if raw_data.get("_rate_limited"):
                return {"error": "Rate limited", "found": False}
            return {
                "found": raw_data.get("found", False),
                "count": raw_data.get("count", 0),
                "sources": raw_data.get("sources", []),
                "quota": raw_data.get("quota", "?")
            }
        return {"found": False, "count": 0, "sources": []}


class LeakLookupModule(BaseOSINTModule):
    """Enriches data leak indices using Leak-Lookup (public key default)."""
    def __init__(self, target: str, query_type: str = "email_address", api_key: Optional[str] = None, proxy: Optional[str] = None):
        super().__init__(target, api_key, proxy)
        self.query_type = query_type

    async def fetch(self, session: aiohttp.ClientSession) -> Any:
        key = self.api_key or LEAK_LOOKUP_PUBLIC_KEY
        url = "https://leak-lookup.com/api/search"
        data = {"key": key, "type": self.query_type, "query": self.target}
        try:
            return await self._request(session, "POST", url, data=data, timeout=14, is_json_response=True)
        except Exception:
            pass
        return None

    def normalize(self, raw_data: Any) -> Dict[str, Any]:
        if not isinstance(raw_data, dict):
            return {"found": False, "sources": [], "total": 0}
        if raw_data.get("error") is False:
            message = raw_data.get("message", {})
            if isinstance(message, dict):
                sources = list(message.keys())
                total = sum(len(v) if isinstance(v, list) else 1 for v in message.values())
                return {"found": bool(sources), "sources": sources, "total": total, "raw": message}
            return {"found": False, "sources": [], "total": 0}
        if raw_data.get("error"):
            err = raw_data.get("message", "")
            if "throttle" in str(err).lower():
                return {"error": "Rate limited / Throttled", "found": False}
            return {"error": str(err), "found": False}
        return {"found": False, "sources": [], "total": 0}


class PSBDMPModule(BaseOSINTModule):
    """Searches PSBDMP Pastebin index database for target strings."""
    async def fetch(self, session: aiohttp.ClientSession) -> Any:
        url = f"https://psbdmp.ws/api/v3/search/{urllib.parse.quote(self.target)}"
        try:
            return await self._request(session, "GET", url, timeout=14, is_json_response=True)
        except Exception:
            pass
        return None

    def normalize(self, raw_data: Any) -> Dict[str, Any]:
        if not isinstance(raw_data, dict):
            return {"count": 0, "pastes": []}
        pastes = raw_data.get("data", [])
        return {
            "count": raw_data.get("count", len(pastes)),
            "pastes": [{
                "id": p.get("id",""),
                "time": p.get("time",""),
                "url": f"https://pastebin.com/{p.get('id','')}"
            } for p in pastes[:10]],
        }


class DehashedModule(BaseOSINTModule):
    """Scrapes Dehashed website (or falls back to API) for leak existence counts."""
    async def fetch(self, session: aiohttp.ClientSession) -> Any:
        url = f"https://dehashed.com/search?query={urllib.parse.quote(self.target)}"
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/124.0.0.0 Safari/537.36",
            "Accept": "text/html,application/xhtml+xml;q=0.9,*/*;q=0.8",
        }
        try:
            # Bypass base _request for custom parsing
            async with session.get(url, headers=headers, timeout=aiohttp.ClientTimeout(total=14)) as resp:
                body = await resp.text()
                status = resp.status
                if status == 200:
                    return {"body": body, "status": status}
        except Exception:
            pass
        return None

    def normalize(self, raw_data: Any) -> Dict[str, Any]:
        if not raw_data:
            return {"total": 0, "src": "failed"}
        body = raw_data.get("body", "")
        for pat in [r'([\d,]+)\s+(?:result|entr|record)', r'total["\s:]+(\d+)', r'(\d+)\s+result']:
            m = re.search(pat, body, re.I)
            if m:
                return {"total": int(m.group(1).replace(",","")), "src": "html"}
        if any(x in body.lower() for x in ["result","entry","record"]):
            return {"total": -1, "src": "html_unknown"}
        return {"total": 0, "src": "html"}


class IntelXModule(BaseOSINTModule):
    """Performs IntelligenceX queries synchronously using polling."""
    async def fetch(self, session: aiohttp.ClientSession) -> Any:
        if not self.api_key:
            return {"_no_key": True}
        
        headers = {"x-key": self.api_key, "User-Agent": "VenomOSINT/6.0"}
        search_url = "https://2.intelx.io/intelligent/search"
        payload = {"term": self.target, "maxresults": 20, "media": 0, "target": 0, "timeout": 20}
        
        try:
            async with session.post(search_url, json=payload, headers=headers, timeout=aiohttp.ClientTimeout(total=18)) as resp:
                if resp.status == 401:
                    return {"_bad_key": True}
                if resp.status != 200:
                    return None
                search_data = await resp.json()
                
            sid = search_data.get("id")
            if not sid:
                return None
                
            # Wait for search execution to complete
            await asyncio.sleep(3)
            
            result_url = f"https://2.intelx.io/intelligent/search/result?id={sid}&limit=20"
            async with session.get(result_url, headers=headers, timeout=aiohttp.ClientTimeout(total=14)) as resp2:
                if resp2.status == 200:
                    return await resp2.json()
        except Exception:
            pass
        return None

    def normalize(self, raw_data: Any) -> Dict[str, Any]:
        if not raw_data:
            return {"results": []}
        if isinstance(raw_data, dict):
            if raw_data.get("_no_key"):
                return {"error": "Missing IntelX API Key"}
            if raw_data.get("_bad_key"):
                return {"error": "Invalid IntelX API Key"}
            return raw_data
        return {"results": raw_data}


class OTXEmailModule(BaseOSINTModule):
    """Queries AlienVault OTX for email presence in threat feeds."""
    async def fetch(self, session: aiohttp.ClientSession) -> Any:
        url = f"https://otx.alienvault.com/api/v1/search/pulses/?q={urllib.parse.quote(self.target)}&limit=5"
        headers = {"User-Agent": "VenomOSINT/6.0"}
        try:
            return await self._request(session, "GET", url, headers=headers, timeout=12, is_json_response=True)
        except Exception:
            pass
        return None

    def normalize(self, raw_data: Any) -> Dict[str, Any]:
        if not isinstance(raw_data, dict):
            return {"count": 0, "results": []}
        return {
            "count": raw_data.get("count", 0),
            "results": [{
                "name": p.get("name",""),
                "author": p.get("author",{}).get("username",""),
                "date": (p.get("created","") or "")[:10],
                "tags": p.get("tags",[])[:5]
            } for p in raw_data.get("results",[])[:5]]
        }


class PhonebookModule(BaseOSINTModule):
    """Queries Phonebook.cz API endpoints using built-in key."""
    def __init__(self, target: str, query_type: int = 1, api_key: Optional[str] = None, proxy: Optional[str] = None):
        super().__init__(target, api_key, proxy)
        self.query_type = query_type

    async def fetch(self, session: aiohttp.ClientSession) -> Any:
        headers = {"x-key": "a8e95f50-b6b0-4fd4-80ee-9e14e30b2b76", "User-Agent": "VenomOSINT/6.0"}
        search_url = "https://2.intelx.io/phonebook/search"
        payload = {"term": self.target, "maxresults": 100, "media": 0, "target": self.query_type, "terminate": [], "timeout": 20}
        
        try:
            async with session.post(search_url, json=payload, headers=headers, timeout=aiohttp.ClientTimeout(total=16)) as resp:
                if resp.status != 200:
                    return None
                search_data = await resp.json()
                
            sid = search_data.get("id")
            if not sid:
                return None
                
            # Wait for search execution to complete
            await asyncio.sleep(2)
            
            result_url = f"https://2.intelx.io/phonebook/search/result?id={sid}&limit=100&offset=0"
            async with session.get(result_url, headers=headers, timeout=aiohttp.ClientTimeout(total=14)) as resp2:
                if resp2.status == 200:
                    return await resp2.json()
        except Exception:
            pass
        return None

    def normalize(self, raw_data: Any) -> Dict[str, Any]:
        if not isinstance(raw_data, dict):
            return {"count": 0, "results": []}
        vals = [s.get("selectorvalue","") for s in raw_data.get("selectors",[]) if s.get("selectorvalue")]
        return {"count": len(vals), "results": vals[:50]}


class OSINTLeakModule(BaseOSINTModule):
    """Enriches data via OSINTLeak API credential breaches & malware logs."""
    async def fetch(self, session: aiohttp.ClientSession) -> Any:
        if not self.api_key:
            return {"error": "no_key"}
            
        # Detect target type
        qtype = "email"
        if "@" not in self.target:
            if self.target.startswith("+") or (self.target.isdigit() and len(self.target) >= 7):
                qtype = "phone"
            else:
                qtype = "username"
                
        url = "https://osintleak.com/api/v1/search_api"
        params = {"api_key": self.api_key, "query": self.target, "type": qtype}
        
        try:
            return await self._request(session, "GET", url, params=params, timeout=12, is_json_response=True)
        except Exception as e:
            return {"error": str(e)}

    def normalize(self, raw_data: Any) -> Dict[str, Any]:
        if not isinstance(raw_data, dict) or "error" in raw_data:
            return {"found": False, "count": 0, "results": [], "origins": [], "error": raw_data.get("error", "Request failed") if isinstance(raw_data, dict) else "Request failed"}
            
        results = raw_data.get("results", [])
        if not isinstance(results, list):
            results = [results] if results else []
            
        count = raw_data.get("total", len(results))
        origins = list(set(r.get("leak_name", r.get("database", "Unknown Source")) for r in results if isinstance(r, dict)))
        
        return {
            "found": len(results) > 0,
            "count": count,
            "results": results,
            "origins": origins
        }
