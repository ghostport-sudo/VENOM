"""
Username enumeration and social-profile intelligence.
Platform sweeps, GitHub/GitLab/npm/PyPI profiles, Keybase identity,
Twitter oEmbed, Telegram resolve, Steam community, GitHub org membership,
and commit-email harvesting.
All queries are rewritten to run asynchronously using aiohttp and BaseOSINTModule.
"""

import re
import urllib.parse
import asyncio
from typing import Any, Dict, Optional, List, Tuple, Set
import aiohttp

from modules.base import BaseOSINTModule, get_random_user_agent, is_waf_blocked
from modules.config import SOCIAL_PLATFORMS

# ── Asynchronous OSINT Modules ───────────────────────────────────────────────

class SocialEnumerationModule(BaseOSINTModule):
    """Sweeps multiple social platforms concurrently with WAF protection."""
    
    async def fetch(self, session: aiohttp.ClientSession) -> Any:
        found: List[Tuple[str, str]] = []
        not_found: List[Tuple[str, str]] = []
        errors: List[Tuple[str, str, Any]] = []
        
        # Concurrency barrier
        sem = asyncio.Semaphore(30)
        
        async def check_platform(platform: str, url_template: str, not_exist_signals: List[str]):
            url = url_template.format(self.target)
            async with sem:
                try:
                    headers = {"User-Agent": get_random_user_agent()}
                    async with session.get(url, headers=headers, timeout=aiohttp.ClientTimeout(total=8), allow_redirects=True) as r:
                        body_text = ""
                        try:
                            body_text = await r.text()
                        except Exception:
                            try:
                                body_bytes = await r.read()
                                body_text = body_bytes.decode('utf-8', errors='ignore')
                            except Exception:
                                pass
                        
                        status = r.status
                        
                        # Cloudflare / WAF protection detection
                        if is_waf_blocked(status, body_text):
                            errors.append((platform, url, "Protected/WAF"))
                            return

                        if status == 200:
                            body_lower = body_text.lower()
                            generic = ["user not found", "page not found", "doesn't exist", "no user",
                                       "account suspended", "not available", "does not exist", "404 not found"]
                            all_signals = [s.lower() for s in not_exist_signals] + generic
                            
                            if any(sig in body_lower for sig in all_signals):
                                not_found.append((platform, url))
                            else:
                                found.append((platform, url))
                        elif status == 404:
                            not_found.append((platform, url))
                        else:
                            errors.append((platform, url, f"Status {status}"))
                except asyncio.TimeoutError:
                    errors.append((platform, url, "timeout"))
                except Exception as e:
                    errors.append((platform, url, str(e)))

        tasks = [
            check_platform(platform, tmpl, sigs)
            for platform, (tmpl, sigs) in SOCIAL_PLATFORMS.items()
        ]
        await asyncio.gather(*tasks)
        return {"found": found, "not_found": not_found, "errors": errors}

    def normalize(self, raw_data: Any) -> Dict[str, Any]:
        return raw_data


class GitHubUserModule(BaseOSINTModule):
    """Enriches username intelligence via GitHub API."""
    async def fetch(self, session: aiohttp.ClientSession) -> Any:
        result = {"found": False, "profile": {}, "repos": [], "gists": []}
        username_encoded = urllib.parse.quote(self.target)
        
        async def get_profile():
            try:
                url = f"https://api.github.com/users/{username_encoded}"
                res = await self._request(session, "GET", url, timeout=8, is_json_response=True)
                if isinstance(res, dict) and "login" in res:
                    result["found"] = True
                    result["profile"] = {
                        "name": res.get("name",""), "bio": res.get("bio",""), "email": res.get("email",""),
                        "company": res.get("company",""), "location": res.get("location",""),
                        "blog": res.get("blog",""), "followers": res.get("followers",0),
                        "repos": res.get("public_repos",0), "created": res.get("created_at","")[:10],
                        "url": res.get("html_url",""),
                    }
            except Exception:
                pass

        async def get_repos():
            try:
                url = f"https://api.github.com/users/{username_encoded}/repos?per_page=8&sort=updated"
                res = await self._request(session, "GET", url, timeout=8, is_json_response=True)
                if isinstance(res, list):
                    for repo in res:
                        result["repos"].append({
                            "name": repo.get("name"), "description": repo.get("description",""),
                            "stars": repo.get("stargazers_count",0), "language": repo.get("language",""),
                            "url": repo.get("html_url",""), "updated": repo.get("updated_at","")[:10],
                        })
            except Exception:
                pass

        async def get_gists():
            try:
                url = f"https://api.github.com/users/{username_encoded}/gists?per_page=5"
                res = await self._request(session, "GET", url, timeout=8, is_json_response=True)
                if isinstance(res, list):
                    for gist in res:
                        result["gists"].append({
                            "description": gist.get("description") or "(untitled)",
                            "url": gist.get("html_url",""),
                            "files": list(gist.get("files",{}).keys()),
                            "created": gist.get("created_at","")[:10],
                        })
            except Exception:
                pass

        await asyncio.gather(get_profile(), get_repos(), get_gists())
        return result

    def normalize(self, raw_data: Any) -> Dict[str, Any]:
        return raw_data


class GitHubEmailCommitsModule(BaseOSINTModule):
    """Searches GitHub commits for a specific email address (helper for email targets)."""
    async def fetch(self, session: aiohttp.ClientSession) -> Any:
        results = []
        try:
            url = f"https://api.github.com/search/commits?q={urllib.parse.quote(self.target)}&per_page=5"
            headers = {"Accept": "application/vnd.github.cloak-preview"}
            res = await self._request(session, "GET", url, headers=headers, timeout=10, is_json_response=True)
            if isinstance(res, dict) and "items" in res:
                for item in res.get("items", []):
                    commit = item.get("commit", {})
                    results.append({
                        "repo":    item.get("repository", {}).get("full_name",""),
                        "message": commit.get("message","")[:80],
                        "date":    commit.get("author",{}).get("date","")[:10],
                        "url":     item.get("html_url",""),
                    })
        except Exception:
            pass
        return results

    def normalize(self, raw_data: Any) -> Dict[str, Any]:
        return {"commits": raw_data}


class GitHubCommitEmailsModule(BaseOSINTModule):
    """Scans repositories for real email addresses in commit history (requires repos list passed in constructor)."""
    def __init__(self, target: str, repos: list, api_key: Optional[str] = None, proxy: Optional[str] = None):
        super().__init__(target, api_key, proxy)
        self.repos = repos

    async def fetch(self, session: aiohttp.ClientSession) -> Any:
        found = set()
        
        async def check_repo_commits(repo_name: str):
            try:
                url = f"https://api.github.com/repos/{urllib.parse.quote(self.target)}/{urllib.parse.quote(repo_name)}/commits?per_page=5"
                headers = {"Accept": "application/vnd.github+json"}
                res = await self._request(session, "GET", url, headers=headers, timeout=8, is_json_response=True)
                if isinstance(res, list):
                    for commit in res:
                        email = commit.get("commit",{}).get("author",{}).get("email","")
                        if email and "noreply" not in email and "@" in email:
                            found.add(email)
            except Exception:
                pass

        await asyncio.gather(*[check_repo_commits(r["name"]) for r in self.repos[:6]])
        return list(found)

    def normalize(self, raw_data: Any) -> Dict[str, Any]:
        return {"emails": raw_data}


class GitHubOrgsModule(BaseOSINTModule):
    """Enriches intelligence with organization memberships."""
    async def fetch(self, session: aiohttp.ClientSession) -> Any:
        try:
            url = f"https://api.github.com/users/{urllib.parse.quote(self.target)}/orgs"
            headers = {"Accept": "application/vnd.github+json"}
            res = await self._request(session, "GET", url, headers=headers, timeout=8, is_json_response=True)
            if isinstance(res, list):
                return [{"login": o.get("login",""), "url": o.get("html_url",""),
                         "description": (o.get("description") or "")[:80]}
                        for o in res]
        except Exception:
            pass
        return []

    def normalize(self, raw_data: Any) -> Dict[str, Any]:
        return {"organizations": raw_data}


class GitLabUserModule(BaseOSINTModule):
    """Queries GitLab API for user accounts."""
    async def fetch(self, session: aiohttp.ClientSession) -> Any:
        url = f"https://gitlab.com/api/v4/users?username={urllib.parse.quote(self.target)}"
        try:
            res = await self._request(session, "GET", url, timeout=10, is_json_response=True)
            if isinstance(res, list) and res:
                return res[0]
        except Exception:
            pass
        return None

    def normalize(self, raw_data: Any) -> Dict[str, Any]:
        if not raw_data:
            return {"exists": False}
        return {"exists": True, "profile": raw_data}


class NPMUserModule(BaseOSINTModule):
    """Checks npm public registry for user profiles."""
    async def fetch(self, session: aiohttp.ClientSession) -> Any:
        url = f"https://registry.npmjs.org/-/user/org.couchdb.user:{self.target}"
        try:
            return await self._request(session, "GET", url, timeout=8, is_json_response=True)
        except Exception:
            pass
        return None

    def normalize(self, raw_data: Any) -> Dict[str, Any]:
        if not raw_data or "error" in raw_data:
            return {"exists": False}
        return {"exists": True, "profile": raw_data}


class PyPIUserModule(BaseOSINTModule):
    """Enriches pyPI package index presence checks."""
    async def fetch(self, session: aiohttp.ClientSession) -> Any:
        url = f"https://pypi.org/user/{self.target}/"
        try:
            res = await self._request(session, "GET", url, timeout=8)
            if isinstance(res, str):
                count = len(re.findall(r'class="package-snippet"', res))
                return {"exists": True, "packages": count, "url": url}
        except Exception:
            pass
        return None

    def normalize(self, raw_data: Any) -> Dict[str, Any]:
        if not raw_data:
            return {"exists": False}
        return raw_data


class KeybaseModule(BaseOSINTModule):
    """Audits user keybase profile identities."""
    async def fetch(self, session: aiohttp.ClientSession) -> Any:
        url = f"https://keybase.io/_/api/1.0/user/lookup.json?username={urllib.parse.quote(self.target)}"
        try:
            res = await self._request(session, "GET", url, timeout=10, is_json_response=True)
            if isinstance(res, dict) and res.get("status", {}).get("code") == 0:
                them = res.get("them", [{}])[0] if res.get("them") else None
                if them:
                    profile = them.get("profile", {})
                    proofs  = them.get("proofs_summary", {}).get("all", [])
                    return {
                        "username":   them.get("basics", {}).get("username", ""),
                        "full_name":  profile.get("full_name", ""),
                        "bio":        profile.get("bio", ""),
                        "location":   profile.get("location", ""),
                        "twitter":    profile.get("twitter", ""),
                        "github":     profile.get("github", ""),
                        "reddit":     profile.get("reddit", ""),
                        "hackernews": profile.get("hackernews", ""),
                        "proofs": [{"service": p.get("proof_type",""),
                                    "name": p.get("nametag","")} for p in proofs],
                    }
        except Exception:
            pass
        return None

    def normalize(self, raw_data: Any) -> Dict[str, Any]:
        if not raw_data:
            return {"exists": False}
        return {"exists": True, **raw_data}


class TwitterOembedModule(BaseOSINTModule):
    """Verifies Twitter/X profile using oEmbed API."""
    async def fetch(self, session: aiohttp.ClientSession) -> Any:
        url = f"https://publish.twitter.com/oembed?url=https://twitter.com/{urllib.parse.quote(self.target)}"
        try:
            res = await self._request(session, "GET", url, timeout=10, is_json_response=True)
            if isinstance(res, dict) and "author_name" in res:
                return {"confirmed": True, "author_name": res.get("author_name",""), "author_url": res.get("author_url","")}
        except Exception as e:
            if hasattr(e, "status") and getattr(e, "status") == 404:
                return {"confirmed": False}
        return None

    def normalize(self, raw_data: Any) -> Dict[str, Any]:
        if not raw_data:
            return {"confirmed": False}
        return raw_data


class TelegramResolveModule(BaseOSINTModule):
    """Queries Telegram to check resolution status of handle."""
    async def fetch(self, session: aiohttp.ClientSession) -> Any:
        out = {"exists": False, "url": f"https://t.me/{self.target}"}
        try:
            url = f"https://t.me/{urllib.parse.quote(self.target)}"
            res = await self._request(session, "GET", url, timeout=8)
            if isinstance(res, str):
                body_l = res.lower()
                if self.target.lower() in body_l and "tg://resolve" not in body_l[:500]:
                    out["exists"] = True
                m = re.search(
                    r'<meta[^>]+property=["\']og:title["\'][^>]+content=["\']'
                    r'(.*?)["\']', res, re.I)
                if m:
                    out["display_name"] = m.group(1).strip()
        except Exception:
            pass
        return out

    def normalize(self, raw_data: Any) -> Dict[str, Any]:
        return raw_data


class SteamProfileModule(BaseOSINTModule):
    """Retrieves Steam user XML profile details."""
    async def fetch(self, session: aiohttp.ClientSession) -> Any:
        url = f"https://steamcommunity.com/id/{urllib.parse.quote(self.target)}?xml=1"
        try:
            res = await self._request(session, "GET", url, timeout=10)
            if isinstance(res, str) and "<steamID64>" in res:
                def _tag(tag):
                    m = re.search(rf"<{tag}><!\[CDATA\[(.*?)\]\]></{tag}>", res, re.S)
                    if not m:
                        m = re.search(rf"<{tag}>(.*?)</{tag}>", res, re.S)
                    return m.group(1).strip() if m else ""
                return {
                    "steam_id": _tag("steamID64"), "display": _tag("steamID"),
                    "state": _tag("onlineState"), "summary": _tag("summary")[:150],
                    "location": _tag("location"), "joined": _tag("memberSince"),
                    "url": f"https://steamcommunity.com/id/{self.target}",
                }
        except Exception:
            pass
        return None

    def normalize(self, raw_data: Any) -> Dict[str, Any]:
        if not raw_data:
            return {"exists": False}
        return {"exists": True, **raw_data}
