"""
Phone intelligence — validation, country prefix lookup, carrier enrichment.
All queries are rewritten to run asynchronously using aiohttp and BaseOSINTModule.
"""

import urllib.parse
from typing import Any, Dict, Optional
import aiohttp

from modules.base import BaseOSINTModule
from modules.config import COUNTRY_PREFIXES

# ── Non-Network Utilities ───────────────────────────────────────────────────

def check_phone(phone: str) -> dict:
    """Validate and identify country from phone number locally."""
    clean = "".join(c for c in phone if c.isdigit() or c == "+")
    result = {"raw": phone, "cleaned": clean, "valid": False, "info": {}}
    if len(clean.replace("+", "")) < 7:
        return result
    result["valid"] = True
    for prefix in sorted(COUNTRY_PREFIXES, key=len, reverse=True):
        if clean.startswith(prefix):
            result["info"]["country"] = COUNTRY_PREFIXES[prefix]
            result["info"]["prefix"]  = prefix
            break
    return result


# ── Asynchronous OSINT Modules ───────────────────────────────────────────────

class PhoneCarrierModule(BaseOSINTModule):
    """Retrieves carrier name, line type, and location details using NumLookup API."""
    async def fetch(self, session: aiohttp.ClientSession) -> Any:
        url = f"https://api.numlookupapi.com/v1/info/{urllib.parse.quote(self.target)}"
        try:
            return await self._request(session, "GET", url, timeout=8, is_json_response=True)
        except Exception:
            return None

    def normalize(self, raw_data: Any) -> Dict[str, Any]:
        out = {"carrier": "", "line_type": "", "location": ""}
        if not isinstance(raw_data, dict):
            return out
        out["carrier"]   = raw_data.get("carrier", "")
        out["line_type"] = raw_data.get("line_type", "")
        out["location"]  = raw_data.get("location", "")
        return out
