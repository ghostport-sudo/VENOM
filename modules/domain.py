"""
Domain and IP intelligence.
DNS resolution, WHOIS/RDAP, IP geolocation, Shodan InternetDB,
Wayback Machine, SSL certificate grab, crt.sh subdomain enumeration,
MX blacklist checks, URLScan.io, OTX AlienVault, HackerTarget passive DNS
and reverse IP, Pulsedive threat feed, ProxyCheck, BGPView ASN, Hunter.io.
All queries are rewritten to run asynchronously using aiohttp and BaseOSINTModule.
"""

import re
import socket
import ssl
import urllib.parse
import asyncio
from typing import Any, Dict, Optional, List
import aiohttp

from modules.base import BaseOSINTModule, get_random_user_agent

# ── Asynchronous OSINT Modules ───────────────────────────────────────────────

class DNSModule(BaseOSINTModule):
    """Checks DNS records via Google DoH API."""
    async def fetch(self, session: aiohttp.ClientSession) -> Any:
        results = {"a": [], "mx": [], "ns": [], "txt": [], "provider": "unknown"}
        
        async def fetch_record(rtype: str, key: str):
            try:
                url = f"https://dns.google/resolve?name={self.target}&type={rtype}"
                res = await self._request(session, "GET", url, timeout=8, is_json_response=True)
                if isinstance(res, dict):
                    results[key] = [a.get("data","") for a in res.get("Answer",[])][:5]
            except Exception:
                pass

        await asyncio.gather(
            fetch_record("A", "a"),
            fetch_record("MX", "mx"),
            fetch_record("NS", "ns"),
            fetch_record("TXT", "txt")
        )
        return results

    def normalize(self, raw_data: Any) -> Dict[str, Any]:
        results = raw_data or {"a": [], "mx": [], "ns": [], "txt": [], "provider": "unknown"}
        mx = " ".join(results["mx"]).lower()
        if "google" in mx or "gmail" in mx:         results["provider"] = "Google Workspace / Gmail"
        elif "outlook" in mx or "microsoft" in mx:  results["provider"] = "Microsoft 365 / Outlook"
        elif "yahoo" in mx:                         results["provider"] = "Yahoo Mail"
        elif "protonmail" in mx:                    results["provider"] = "ProtonMail"
        elif "icloud" in mx or "apple" in mx:       results["provider"] = "Apple iCloud"
        elif "zoho" in mx:                          results["provider"] = "Zoho Mail"
        elif results["mx"]:                         results["provider"] = results["mx"][0].rstrip(".")
        return results


class WHOISModule(BaseOSINTModule):
    """Performs WHOIS queries using RDAP protocol."""
    async def fetch(self, session: aiohttp.ClientSession) -> Any:
        url = f"https://rdap.org/domain/{self.target}"
        try:
            return await self._request(session, "GET", url, timeout=10, is_json_response=True)
        except Exception:
            return None

    def normalize(self, raw_data: Any) -> Dict[str, Any]:
        result = {"registered": False, "registrar": "", "created": "", "expires": "", "nameservers": []}
        if not isinstance(raw_data, dict):
            return result
        result["registered"] = True
        for entity in raw_data.get("entities", []):
            if "registrar" in entity.get("roles", []):
                vcard = entity.get("vcardArray", [None, []])[1]
                for field in vcard:
                    if field[0] == "fn":
                        result["registrar"] = field[3]
        for event in raw_data.get("events", []):
            action = event.get("eventAction", "")
            date   = event.get("eventDate", "")[:10]
            if action == "registration": result["created"] = date
            if action == "expiration":   result["expires"] = date
        result["nameservers"] = [ns.get("ldhName","") for ns in raw_data.get("nameservers",[])[:4]]
        return result


class IPResolutionModule(BaseOSINTModule):
    """Resolves Domain to IP and fetches geolocation metadata."""
    async def fetch(self, session: aiohttp.ClientSession) -> Any:
        result = {"ip": "", "hostname": "", "geo": {}}
        loop = asyncio.get_running_loop()
        
        # Async host by name resolution
        try:
            ip = await loop.run_in_executor(None, socket.gethostbyname, self.target)
            result["ip"] = ip
        except Exception:
            return result

        # Async host by address lookup
        try:
            hostname = await loop.run_in_executor(None, socket.gethostbyaddr, ip)
            result["hostname"] = hostname[0]
        except Exception:
            pass

        # Fetch IP Info Geolocation
        try:
            url = f"https://ipinfo.io/{ip}/json"
            geo_res = await self._request(session, "GET", url, timeout=8, is_json_response=True)
            if isinstance(geo_res, dict):
                result["geo"] = {
                    "org": geo_res.get("org",""), "city": geo_res.get("city",""),
                    "region": geo_res.get("region",""), "country": geo_res.get("country",""),
                    "timezone": geo_res.get("timezone",""),
                }
        except Exception:
            pass
        return result

    def normalize(self, raw_data: Any) -> Dict[str, Any]:
        return raw_data


class ShodanInternetDBModule(BaseOSINTModule):
    """Enriches IP details via Shodan InternetDB."""
    async def fetch(self, session: aiohttp.ClientSession) -> Any:
        url = f"https://internetdb.shodan.io/{self.target}"
        try:
            return await self._request(session, "GET", url, timeout=10, is_json_response=True)
        except Exception:
            return None

    def normalize(self, raw_data: Any) -> Dict[str, Any]:
        if not isinstance(raw_data, dict):
            return {"ports": [], "vulns": [], "tags": [], "hostnames": [], "cpes": []}
        return raw_data


class WaybackModule(BaseOSINTModule):
    """Searches Wayback archive snapshots count."""
    async def fetch(self, session: aiohttp.ClientSession) -> Any:
        url = (f"https://web.archive.org/cdx/search/cdx"
               f"?url={urllib.parse.quote(self.target)}&output=json&fl=timestamp,statuscode"
               f"&limit=5&from=&to=&collapse=timestamp:6")
        try:
            return await self._request(session, "GET", url, timeout=16, is_json_response=True)
        except Exception:
            return None

    def normalize(self, raw_data: Any) -> Dict[str, Any]:
        if not isinstance(raw_data, list) or len(raw_data) <= 1:
            return {"total": 0, "first": "", "last": "", "samples": []}
        snaps = raw_data[1:]
        return {"total": len(snaps), "first": snaps[0][0], "last": snaps[-1][0], "samples": snaps[:4]}


class SSLCertModule(BaseOSINTModule):
    """Grasps SSL Certificate details from active socket."""
    async def fetch(self, session: aiohttp.ClientSession) -> Any:
        loop = asyncio.get_running_loop()
        
        def grab_cert():
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            try:
                with socket.create_connection((self.target, 443), timeout=8) as sock:
                    with ctx.wrap_socket(sock, server_hostname=self.target) as ssock:
                        cert = ssock.getpeercert()
                        if not cert:
                            return None
                        return {
                            "subject": dict(x[0] for x in cert.get("subject", [])),
                            "issuer":  dict(x[0] for x in cert.get("issuer", [])),
                            "not_before": cert.get("notBefore", ""),
                            "not_after":  cert.get("notAfter", ""),
                            "san": [v for t, v in cert.get("subjectAltName", []) if t == "DNS"],
                        }
            except Exception:
                return None

        return await loop.run_in_executor(None, grab_cert)

    def normalize(self, raw_data: Any) -> Dict[str, Any]:
        return raw_data or {}


class CrtshDomainModule(BaseOSINTModule):
    """Queries crt.sh certificate transparency database for subdomains."""
    async def fetch(self, session: aiohttp.ClientSession) -> Any:
        url = f"https://crt.sh/?q=%.{urllib.parse.quote(self.target)}&output=json"
        try:
            return await self._request(session, "GET", url, timeout=16, is_json_response=True)
        except Exception:
            return []

    def normalize(self, raw_data: Any) -> Dict[str, Any]:
        if not isinstance(raw_data, list):
            return {"subdomains": []}
        seen, out = set(), []
        for entry in raw_data:
            for name in entry.get("name_value", "").split("\n"):
                name = name.strip().lstrip("*.")
                if name and self.target in name and name not in seen:
                    seen.add(name)
                    out.append({
                        "subdomain": name,
                        "issued": entry.get("not_before","")[:10],
                        "issuer": entry.get("issuer_cn","")
                    })
        return {"subdomains": sorted(out, key=lambda x: x["subdomain"])}


class MXBlacklistModule(BaseOSINTModule):
    """Asynchronously checks RBL lists for domain spam blacklists."""
    async def fetch(self, session: aiohttp.ClientSession) -> Any:
        dnsbls = ["zen.spamhaus.org", "bl.spamcop.net", "b.barracudacentral.org",
                  "dnsbl.sorbs.net", "psbl.surriel.com"]
        hits, clean = [], []
        loop = asyncio.get_running_loop()

        async def check_dnsbl(bl):
            query = f"{self.target}.{bl}"
            try:
                await loop.run_in_executor(None, socket.getaddrinfo, query, None)
                hits.append(bl)
            except socket.gaierror:
                clean.append(bl)

        await asyncio.gather(*[check_dnsbl(b) for b in dnsbls])
        return {"blacklisted": hits, "clean": clean}

    def normalize(self, raw_data: Any) -> Dict[str, Any]:
        return raw_data


class IPGeoModule(BaseOSINTModule):
    """Queries ip-api.com for advanced IP geolocation metadata."""
    async def fetch(self, session: aiohttp.ClientSession) -> Any:
        url = f"http://ip-api.com/json/{self.target}?fields=status,country,regionName,city,isp,org,as,timezone,proxy,hosting"
        try:
            return await self._request(session, "GET", url, timeout=8, is_json_response=True)
        except Exception:
            return None

    def normalize(self, raw_data: Any) -> Dict[str, Any]:
        if isinstance(raw_data, dict) and raw_data.get("status") == "success":
            return raw_data
        return {}


class BGPViewModule(BaseOSINTModule):
    """Enriches IP routing info via BGPView API."""
    async def fetch(self, session: aiohttp.ClientSession) -> Any:
        url = f"https://api.bgpview.io/ip/{self.target}"
        try:
            return await self._request(session, "GET", url, timeout=10, is_json_response=True)
        except Exception:
            return None

    def normalize(self, raw_data: Any) -> Dict[str, Any]:
        if isinstance(raw_data, dict) and raw_data.get("status") == "ok":
            prefixes = raw_data.get("data", {}).get("prefixes", [])
            if prefixes:
                p = prefixes[0]
                return {
                    "asn": p.get("asn",{}).get("asn",""),
                    "asn_name": p.get("asn",{}).get("name",""),
                    "asn_desc": p.get("asn",{}).get("description",""),
                    "prefix": p.get("prefix",""),
                    "net_name": p.get("name",""),
                }
        return {}


class HunterDomainModule(BaseOSINTModule):
    """Searches corporate emails on Hunter.io API."""
    async def fetch(self, session: aiohttp.ClientSession) -> Any:
        key_param = f"&api_key={self.api_key}" if self.api_key else ""
        url = f"https://api.hunter.io/v2/domain-search?domain={urllib.parse.quote(self.target)}&limit=10{key_param}"
        try:
            return await self._request(session, "GET", url, timeout=12, is_json_response=True)
        except Exception:
            return None

    def normalize(self, raw_data: Any) -> Dict[str, Any]:
        return raw_data or {}


class URLScanModule(BaseOSINTModule):
    """Checks URLScan database for domain crawls."""
    async def fetch(self, session: aiohttp.ClientSession) -> Any:
        url = f"https://urlscan.io/api/v1/search/?q=domain:{urllib.parse.quote(self.target)}&size=10"
        try:
            return await self._request(session, "GET", url, timeout=14, is_json_response=True)
        except Exception:
            return None

    def normalize(self, raw_data: Any) -> Dict[str, Any]:
        if not isinstance(raw_data, dict):
            return {"results": []}
        out = []
        for hit in raw_data.get("results", []):
            page    = hit.get("page", {})
            verdict = hit.get("verdicts", {}).get("overall", {})
            out.append({
                "url": page.get("url",""), "ip": page.get("ip",""),
                "country": page.get("country",""), "server": page.get("server",""),
                "date": hit.get("task",{}).get("time","")[:10],
                "score": verdict.get("score",0),
                "malicious": verdict.get("malicious",False),
                "tags": verdict.get("tags",[]),
                "scan_id": hit.get("_id",""),
            })
        return {"results": out}


class OTXDomainModule(BaseOSINTModule):
    """Queries AlienVault OTX for domain general reputations."""
    async def fetch(self, session: aiohttp.ClientSession) -> Any:
        url = f"https://otx.alienvault.com/api/v1/indicators/domain/{urllib.parse.quote(self.target)}/general"
        headers = {"User-Agent": "VenomOSINT/6.0"}
        try:
            return await self._request(session, "GET", url, headers=headers, timeout=12, is_json_response=True)
        except Exception:
            return None

    def normalize(self, raw_data: Any) -> Dict[str, Any]:
        if not isinstance(raw_data, dict):
            return {}
        return {
            "pulse_count":   raw_data.get("pulse_info",{}).get("count",0),
            "malware_count": len(raw_data.get("malware_families",[])),
            "threat_score":  raw_data.get("reputation",0),
            "tags":          raw_data.get("pulse_info",{}).get("related",{}).get("industries",[]),
            "country":       raw_data.get("country_code",""),
        }


class OTXIPModule(BaseOSINTModule):
    """Queries AlienVault OTX for IP general intelligence."""
    async def fetch(self, session: aiohttp.ClientSession) -> Any:
        url = f"https://otx.alienvault.com/api/v1/indicators/IPv4/{self.target}/general"
        headers = {"User-Agent": "VenomOSINT/6.0"}
        try:
            return await self._request(session, "GET", url, headers=headers, timeout=12, is_json_response=True)
        except Exception:
            return None

    def normalize(self, raw_data: Any) -> Dict[str, Any]:
        if not isinstance(raw_data, dict):
            return {}
        return {
            "pulse_count": raw_data.get("pulse_info",{}).get("count",0),
            "reputation":  raw_data.get("reputation",0),
            "country":     raw_data.get("country_code",""),
            "city":        raw_data.get("city",""),
            "asn":         raw_data.get("asn",""),
            "related_malware": len(raw_data.get("malware_families",[])),
        }


class HackerTargetPassiveDNSModule(BaseOSINTModule):
    """Queries HackerTarget Passive DNS engine."""
    async def fetch(self, session: aiohttp.ClientSession) -> Any:
        url = f"https://api.hackertarget.com/hostsearch/?q={urllib.parse.quote(self.target)}"
        try:
            return await self._request(session, "GET", url, timeout=12)
        except Exception:
            return ""

    def normalize(self, raw_data: Any) -> Dict[str, Any]:
        if not isinstance(raw_data, str) or "error" in raw_data.lower()[:30]:
            return {"results": []}
        out = []
        for line in raw_data.strip().splitlines():
            parts = line.split(",")
            if len(parts) == 2:
                out.append({"hostname": parts[0].strip(), "ip": parts[1].strip()})
        return {"results": out}


class HackerTargetReverseIPModule(BaseOSINTModule):
    """Queries HackerTarget Reverse IP mapping engine."""
    async def fetch(self, session: aiohttp.ClientSession) -> Any:
        url = f"https://api.hackertarget.com/reverseiplookup/?q={self.target}"
        try:
            return await self._request(session, "GET", url, timeout=12)
        except Exception:
            return ""

    def normalize(self, raw_data: Any) -> Dict[str, Any]:
        if not isinstance(raw_data, str) or "error" in raw_data.lower()[:30]:
            return {"results": []}
        return {"results": [l.strip() for l in raw_data.strip().splitlines() if l.strip()]}


class PulsediveModule(BaseOSINTModule):
    """Checks indicators risk feed on Pulsedive API."""
    async def fetch(self, session: aiohttp.ClientSession) -> Any:
        url = f"https://pulsedive.com/api/info.php?indicator={urllib.parse.quote(self.target)}&pretty=1"
        headers = {"User-Agent": "VenomOSINT/6.0"}
        try:
            return await self._request(session, "GET", url, headers=headers, timeout=14, is_json_response=True)
        except Exception:
            return None

    def normalize(self, raw_data: Any) -> Dict[str, Any]:
        if not isinstance(raw_data, dict) or raw_data.get("error"):
            return {}
        return {
            "risk":      raw_data.get("risk","unknown"),
            "threats":   [t.get("name","") for t in raw_data.get("threats",[])[:5]],
            "feeds":     [f.get("name","") for f in raw_data.get("feeds",[])[:5]],
            "last_seen": (raw_data.get("stamp_seen") or "")[:10],
        }


class ProxyCheckModule(BaseOSINTModule):
    """Detects proxy, VPN and hosting servers on ProxyCheck API."""
    async def fetch(self, session: aiohttp.ClientSession) -> Any:
        url = f"https://proxycheck.io/v2/{self.target}?vpn=1&asn=1&risk=1"
        headers = {"User-Agent": "VenomOSINT/6.0"}
        try:
            return await self._request(session, "GET", url, headers=headers, timeout=8, is_json_response=True)
        except Exception:
            return None

    def normalize(self, raw_data: Any) -> Dict[str, Any]:
        if not isinstance(raw_data, dict):
            return {}
        ip_data = raw_data.get(self.target, {})
        return {
            "proxy": ip_data.get("proxy","no"),
            "type": ip_data.get("type",""),
            "risk": ip_data.get("risk",0),
            "country": ip_data.get("country",""),
            "isp": ip_data.get("provider",""),
            "asn": ip_data.get("asn",""),
            "city": ip_data.get("city",""),
        }
