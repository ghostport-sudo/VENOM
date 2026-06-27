"""
Email intelligence — format checks, Gravatar, EmailRep, cert transparency,
SPF/DMARC/DKIM posture, TXT classification, RDAP admin contacts,
name inference, username permutations, Google probe, Holehe-style checks.
All queries are rewritten to run asynchronously using aiohttp and BaseOSINTModule.
"""

import hashlib
import re
import urllib.parse
import asyncio
from typing import Any, Dict, Optional, List
import aiohttp

from modules.base import BaseOSINTModule, get_random_user_agent
from modules.config import (
    DISPOSABLE_DOMAINS, CONSUMER_MAIL_DOMAINS, HOLEHE_SITES,
)

# Helper wrapper for config lambda compatibility
class ResponseWrapper:
    def __init__(self, status: int, text: str):
        self.status_code = status
        self.text = text


# ── Non-Network Utilities ───────────────────────────────────────────────────

def check_format(email: str) -> dict:
    """Validate format locally without network requests."""
    result = {"valid_format": False, "domain": "", "local": "", "disposable": False}
    if "@" not in email:
        return result
    parts = email.split("@")
    if len(parts) != 2 or not parts[0] or not parts[1]:
        return result
    result.update({"valid_format": True, "local": parts[0], "domain": parts[1]})
    result["disposable"] = parts[1].lower() in DISPOSABLE_DOMAINS
    return result


def infer_name(local: str) -> dict:
    """Infer name from local part of email (local check)."""
    clean = re.sub(r"\d+", "", local.split("+")[0].lower())
    parts = [p for p in re.split(r"[._\-]", clean) if len(p) >= 2]
    first = parts[0].title() if parts else ""
    last  = parts[-1].title() if len(parts) > 1 else ""
    female = {"emma","emily","sarah","laura","anna","lisa","kate","amy","jessica",
              "hannah","sophie","alice","maria","natalie","claire","helen","lucy",
              "victoria","grace","olivia","charlotte","mia","ella","ava","zoe",
              "chloe","lily","eleanor","eva","amber","leah","holly","jade","molly"}
    male = {"james","john","robert","michael","william","david","richard","joseph",
            "thomas","charles","daniel","matthew","anthony","mark","paul","steven",
            "andrew","joshua","kevin","brian","george","timothy","ryan","jacob",
            "gary","eric","jonathan","adam","liam","noah","oliver","elijah","mason",
            "logan","lucas","ethan","aiden","scott","frank","justin"}
    fname_l = first.lower()
    if fname_l in female:   gender = "likely female"
    elif fname_l in male:   gender = "likely male"
    elif fname_l.endswith("a") or fname_l.endswith("ie"): gender = "possibly female"
    elif fname_l.endswith("er") or fname_l.endswith("on"): gender = "possibly male"
    else:                   gender = "unknown"
    return {"first": first, "last": last, "gender": gender, "parts": parts}


def username_permutations(email: str) -> list:
    """Generate username variants from email (local check)."""
    local = email.split("@")[0].lower()
    if "+" in local:
        local = local.split("+")[0]
    variants: set = {local}
    for sep in [".", "_", "-"]:
        parts = local.split(sep)
        if len(parts) >= 2:
            first, last = parts[0], parts[-1]
            variants.update([first, last, first + last, last + first,
                             first[0] + last, first + last[0],
                             first + "." + last, first + "_" + last,
                             first[0] + "." + last])
            if len(parts) >= 3:
                mid = parts[1]
                variants.add(first + mid + last)
                variants.add(first[0] + mid[0] + last)
    stripped = re.sub(r"\d+$", "", local)
    if stripped and stripped != local:
        variants.add(stripped)
    return sorted(v for v in variants if len(v) >= 3)


# ── Asynchronous OSINT Modules ───────────────────────────────────────────────

class GravatarModule(BaseOSINTModule):
    """Checks Gravatar for profile picture and metadata."""
    async def fetch(self, session: aiohttp.ClientSession) -> Any:
        md5 = hashlib.md5(self.target.strip().lower().encode()).hexdigest()
        out = {
            "registered": False,
            "hash": md5,
            "avatar": f"https://www.gravatar.com/avatar/{md5}",
            "profile_url": f"https://gravatar.com/{md5}",
            "display_name": "",
            "real_name": "",
            "location": "",
            "bio": "",
            "accounts": []
        }
        
        # Check avatar existence (returns 404 if not registered)
        try:
            url = f"https://www.gravatar.com/avatar/{md5}?d=404"
            headers = {"User-Agent": get_random_user_agent()}
            async with session.get(url, headers=headers, timeout=aiohttp.ClientTimeout(total=6)) as resp:
                if resp.status == 200:
                    out["registered"] = True
                else:
                    return out
        except Exception:
            return out

        # Fetch profile JSON
        try:
            profile_url = f"https://gravatar.com/{md5}.json"
            headers = {"User-Agent": get_random_user_agent()}
            async with session.get(profile_url, headers=headers, timeout=aiohttp.ClientTimeout(total=8)) as resp:
                if resp.status == 200:
                    profile_json = await resp.json()
                    entry = profile_json.get("entry", [{}])[0]
                    out["display_name"] = entry.get("displayName", "")
                    out["real_name"]    = entry.get("name", {}).get("formatted", "")
                    out["location"]     = entry.get("currentLocation", "")
                    out["bio"]          = entry.get("aboutMe", "")
                    out["accounts"]     = [a.get("shortname", "") for a in entry.get("accounts", [])]
        except Exception:
            pass
        return out

    def normalize(self, raw_data: Any) -> Dict[str, Any]:
        return raw_data


class EmailRepModule(BaseOSINTModule):
    """Enriches email safety check via EmailRep.io."""
    async def fetch(self, session: aiohttp.ClientSession) -> Any:
        headers = {"User-Agent": "VenomOSINT/6.0"}
        if self.api_key:
            headers["Key"] = self.api_key
        url = f"https://emailrep.io/{urllib.parse.quote(self.target)}"
        
        try:
            async with session.get(url, headers=headers, timeout=aiohttp.ClientTimeout(total=10)) as resp:
                if resp.status == 200:
                    return await resp.json()
                if resp.status == 429:
                    return {"_rate_limited": True}
                if resp.status == 401:
                    return {"_bad_key": True}
        except Exception:
            pass
        return None

    def normalize(self, raw_data: Any) -> Dict[str, Any]:
        if not raw_data:
            return {"reputation": "unknown", "suspicious": False}
        return raw_data


class CrtshEmailModule(BaseOSINTModule):
    """Retrieves domains issued with certificate containing email address."""
    async def fetch(self, session: aiohttp.ClientSession) -> Any:
        url = f"https://crt.sh/?q={urllib.parse.quote(self.target)}&output=json"
        try:
            # Bypass base _request for custom parsing
            return await self._request(session, "GET", url, timeout=14, is_json_response=True)
        except Exception:
            return []

    def normalize(self, raw_data: Any) -> Dict[str, Any]:
        if not isinstance(raw_data, list):
            return {"domains": []}
        seen, out = set(), []
        for entry in raw_data[:60]:
            for name in entry.get("name_value", "").split("\n"):
                name = name.strip()
                if name and name not in seen:
                    seen.add(name)
                    out.append({
                        "domain": name,
                        "issued": entry.get("not_before", "")[:10],
                        "issuer": entry.get("issuer_cn", "")
                    })
        return {"domains": out}


class EmailSecurityPostureModule(BaseOSINTModule):
    """Queries SPF/DMARC/DKIM email records over Google DoH."""
    async def fetch(self, session: aiohttp.ClientSession) -> Any:
        if "@" in self.target:
            domain = self.target.split("@")[1]
        else:
            domain = self.target
        
        if not domain or domain.lower() in CONSUMER_MAIL_DOMAINS:
            return {"_consumer": True, "provider": domain or "unknown"}

        out = {
            "spf": {"present": False, "record": "", "policy": ""},
            "dmarc": {"present": False, "record": "", "policy": "", "rua": ""},
            "dkim": {"selectors": []}
        }
        
        # Async tasks for SPF & DMARC
        async def fetch_spf():
            try:
                url = f"https://dns.google/resolve?name={domain}&type=TXT"
                res = await self._request(session, "GET", url, timeout=8, is_json_response=True)
                if isinstance(res, dict):
                    for ans in res.get("Answer", []):
                        txt = ans.get("data", "").strip('"')
                        if txt.startswith("v=spf1"):
                            out["spf"]["present"] = True
                            out["spf"]["record"]  = txt
                            if "~all" in txt:   out["spf"]["policy"] = "softfail (~all)"
                            elif "-all" in txt: out["spf"]["policy"] = "hardfail (-all)"
                            elif "+all" in txt: out["spf"]["policy"] = "PASS ALL <- dangerous"
                            else:               out["spf"]["policy"] = "no explicit all"
            except Exception:
                pass

        async def fetch_dmarc():
            try:
                url = f"https://dns.google/resolve?name=_dmarc.{domain}&type=TXT"
                res = await self._request(session, "GET", url, timeout=8, is_json_response=True)
                if isinstance(res, dict):
                    for ans in res.get("Answer", []):
                        txt = ans.get("data", "").strip('"')
                        if "v=DMARC1" in txt:
                            out["dmarc"]["present"] = True
                            out["dmarc"]["record"]  = txt
                            m = re.search(r"p=(\w+)", txt)
                            if m: out["dmarc"]["policy"] = m.group(1)
                            m2 = re.search(r"rua=([^\s;]+)", txt)
                            if m2: out["dmarc"]["rua"] = m2.group(1)
            except Exception:
                pass

        # DKIM Selectors Probe
        async def check_dkim(sel):
            try:
                url = f"https://dns.google/resolve?name={sel}._domainkey.{domain}&type=TXT"
                res = await self._request(session, "GET", url, timeout=5, is_json_response=True)
                if isinstance(res, dict):
                    for ans in res.get("Answer", []):
                        if "v=DKIM1" in ans.get("data", ""):
                            out["dkim"]["selectors"].append(sel)
            except Exception:
                pass

        selectors = ["default", "google", "mail", "k1", "k2", "s1", "s2", "dkim",
                     "selector1", "selector2", "mimecast", "protonmail", "smtp"]

        # Run concurrently
        await asyncio.gather(
            fetch_spf(),
            fetch_dmarc(),
            *[check_dkim(s) for s in selectors]
        )
        return out

    def normalize(self, raw_data: Any) -> Dict[str, Any]:
        return raw_data or {}


class EmailTxtClassifyModule(BaseOSINTModule):
    """Classifies TXT records for verified platforms."""
    async def fetch(self, session: aiohttp.ClientSession) -> Any:
        if "@" in self.target:
            domain = self.target.split("@")[1]
        else:
            domain = self.target
        
        if not domain or domain.lower() in CONSUMER_MAIL_DOMAINS:
            return []

        patterns = [
            ("v=spf1", "SPF policy"), ("v=DMARC1", "DMARC policy"),
            ("google-site-verification=", "Google site verification"),
            ("MS=", "Microsoft 365 / Azure"),
            ("facebook-domain-verification=", "Facebook verification"),
            ("apple-domain-verification=", "Apple verification"),
            ("stripe-verification=", "Stripe"),
            ("atlassian-domain-verification=", "Atlassian / Jira"),
            ("docker-verification=", "Docker Hub"),
            ("keybase-site-verification=", "Keybase"),
            ("have-i-been-pwned-verification=", "HIBP domain"),
            ("notion-domain-verification=", "Notion"),
            ("hubspot-developer-verification=", "HubSpot"),
            ("github-challenge-", "GitHub Pages"),
            ("zoho-verification=", "Zoho"),
            ("v=DKIM1", "DKIM key"),
        ]
        out = []
        try:
            url = f"https://dns.google/resolve?name={domain}&type=TXT"
            res = await self._request(session, "GET", url, timeout=8, is_json_response=True)
            if isinstance(res, dict):
                for ans in res.get("Answer", []):
                    txt = ans.get("data", "").strip('"')
                    kind = "Unknown"
                    for prefix, label in patterns:
                        if prefix in txt:
                            kind = label
                            break
                    out.append({"record": txt[:120], "type": kind})
        except Exception:
            pass
        return out

    def normalize(self, raw_data: Any) -> Dict[str, Any]:
        return {"records": raw_data}


class RdapAdminEmailModule(BaseOSINTModule):
    """Extracts administrative/registrant contacts from RDAP WHOIS."""
    async def fetch(self, session: aiohttp.ClientSession) -> Any:
        if "@" in self.target:
            domain = self.target.split("@")[1]
        else:
            domain = self.target
        
        if not domain:
            return ""
        
        url = f"https://rdap.org/domain/{domain}"
        try:
            res = await self._request(session, "GET", url, timeout=10, is_json_response=True)
            if isinstance(res, dict):
                for entity in res.get("entities", []):
                    roles = entity.get("roles", [])
                    if "administrative" in roles or "registrant" in roles:
                        vcard = entity.get("vcardArray", [None, []])[1]
                        for field in vcard:
                            if field[0] == "email":
                                return field[3]
        except Exception:
            pass
        return ""

    def normalize(self, raw_data: Any) -> Dict[str, Any]:
        return {"email": raw_data}


class GoogleProbeModule(BaseOSINTModule):
    """Probes Google to identify account existence and profile photo."""
    async def fetch(self, session: aiohttp.ClientSession) -> Any:
        out = {"google_account": False, "profile_pic": "", "method": ""}
        
        # 1. Signin Flow Check
        try:
            headers = {
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/124.0.0.0 Safari/537.36",
                "Content-Type": "application/x-www-form-urlencoded",
                "Referer": "https://accounts.google.com/"
            }
            data = {
                "Email": self.target, 
                "continue": "https://accounts.google.com",
                "flowName": "GlifWebSignIn", 
                "flowEntry": "ServiceLogin"
            }
            async with session.post(
                "https://accounts.google.com/_/signin/sl/lookup",
                data=data,
                headers=headers,
                timeout=aiohttp.ClientTimeout(total=10)
            ) as resp:
                if resp.status == 200:
                    body = await resp.text()
                    body_l = body.lower()
                    if ("password" in body_l or "confirm it's you" in body_l
                            or ("sign in" in body_l and "couldn't find" not in body_l)):
                        out["google_account"] = True
                        out["method"] = "signin-flow"
                    elif "couldn't find your google account" in body_l:
                        out["method"] = "signin-flow"
        except Exception:
            pass
            
        # 2. Gravatar Redirect Check
        if not out["google_account"]:
            try:
                md5 = hashlib.md5(self.target.strip().lower().encode()).hexdigest()
                url = f"https://www.gravatar.com/avatar/{md5}?d=404"
                headers = {"User-Agent": get_random_user_agent()}
                async with session.get(url, headers=headers, timeout=aiohttp.ClientTimeout(total=6), allow_redirects=True) as resp:
                    if resp.status == 200:
                        final_url = str(resp.url)
                        if "googleusercontent" in final_url or "google" in final_url:
                            out["google_account"] = True
                            out["profile_pic"] = final_url
                            out["method"] = "gravatar-google-photo"
            except Exception:
                pass
        return out

    def normalize(self, raw_data: Any) -> Dict[str, Any]:
        return raw_data


class HoleheModule(BaseOSINTModule):
    """Asynchronously audits email registrations across multiple services (Holehe-style)."""
    async def fetch(self, session: aiohttp.ClientSession) -> Any:
        results = []
        headers_base = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/124.0.0.0 Safari/537.36",
            "Accept": "application/json, text/plain, */*",
            "Content-Type": "application/json",
        }

        async def check_one_site(site: str, cfg: dict):
            res = {"site": site, "registered": False, "confidence": "low", "error": ""}
            try:
                endpoint = cfg["endpoint"].format(email=urllib.parse.quote(self.target))
                
                # Dynamic request setup
                headers = {**headers_base}
                if cfg["method"] == "GET":
                    async with session.get(endpoint, headers=headers, timeout=aiohttp.ClientTimeout(total=10)) as r:
                        body = await r.text()
                        status = r.status
                elif cfg["json"]:
                    async with session.post(endpoint, json=cfg["data"](self.target), headers=headers, timeout=aiohttp.ClientTimeout(total=10)) as r:
                        body = await r.text()
                        status = r.status
                else:
                    headers["Content-Type"] = "application/x-www-form-urlencoded"
                    async with session.post(endpoint, data=cfg["data"](self.target), headers=headers, timeout=aiohttp.ClientTimeout(total=10)) as r:
                        body = await r.text()
                        status = r.status

                # Wrap for compatibility with existing lambda logic
                wrapped_resp = ResponseWrapper(status, body)
                
                if cfg["found_if"](wrapped_resp):
                    res["registered"] = True
                    res["confidence"] = "medium"
                elif cfg["not_found_if"](wrapped_resp):
                    res["confidence"] = "medium"
                else:
                    res["error"] = f"ambiguous (status {status})"
            except Exception as e:
                res["error"] = str(e)[:40]
            return res

        tasks = [check_one_site(s, c) for s, c in HOLEHE_SITES.items()]
        results = await asyncio.gather(*tasks)
        return sorted(results, key=lambda x: (not x["registered"], x["site"]))

    def normalize(self, raw_data: Any) -> Dict[str, Any]:
        return {"results": raw_data}
