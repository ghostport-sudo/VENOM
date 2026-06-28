"""
Shared configuration, constants, HTTP session, and display helpers.

Everything that multiple modules need lives here — platform lists,
disposable-domain sets, the requests Session, the Rich console, etc.
"""

import urllib.parse
from datetime import datetime

import requests
from rich.console import Console
from rich.rule import Rule

# ── Rich console (single instance shared everywhere) ─────────────────────────

console = Console()

# ── HTTP session with a realistic UA ─────────────────────────────────────────

SESSION = requests.Session()
SESSION.headers.update({
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/120.0.0.0 Safari/537.36"
    )
})

# ── ASCII banner ─────────────────────────────────────────────────────────────

BANNER = r"""
 __      ________ _   _  ____  __  __ 
 \ \    / /  ____| \ | |/ __ \|  \/  |
  \ \  / /| |__  |  \| | |  | | \  / |
   \ \/ / |  __| | . ` | |  | | |\/| |
    \  /  | |____| |\  | |__| | |  | |
     \/   |______|_| \_|\____/|_|  |_|

  OSINT Breach Scanner v7.0
      By: ghostport
"""

# ── Social platform registry ─────────────────────────────────────────────────
# Detection methods:
#   "status_code" — relies on HTTP status (404 = not found, 200 = found)
#   "api_json"    — uses a JSON API endpoint; key/value checked for existence
#   "body_text"   — checks response body for not-found signals (last resort)
#
# Platforms that are SPA-only, require auth, or block all scrapers are REMOVED
# to eliminate false positives. Only platforms with reliable unauthenticated
# detection are included.

SOCIAL_PLATFORMS = {
    # ── Reliable status-code based (return 404 for missing users) ────────
    "GitHub": {
        "url": "https://api.github.com/users/{}",
        "method": "status_code",
        "error_codes": [404],
    },
    "GitLab": {
        "url": "https://gitlab.com/{}",
        "method": "status_code",
        "error_codes": [404],
    },
    "Reddit": {
        "url": "https://www.reddit.com/user/{}/about.json",
        "method": "api_json",
        "not_found_key": "error",
        "not_found_value": 404,
    },

    "Pastebin": {
        "url": "https://pastebin.com/u/{}",
        "method": "status_code",
        "error_codes": [404],
    },
    "HackerNews": {
        "url": "https://hacker-news.firebaseio.com/v0/user/{}.json",
        "method": "api_json",
        "found_if_not_null": True,
    },
    "DeviantArt": {
        "url": "https://www.deviantart.com/{}",
        "method": "status_code",
        "error_codes": [404],
    },
    "Flickr": {
        "url": "https://www.flickr.com/people/{}/",
        "method": "status_code",
        "error_codes": [404],
    },
    "Gravatar": {
        "url": "https://en.gravatar.com/{}.json",
        "method": "status_code",
        "error_codes": [404],
    },
    "Keybase": {
        "url": "https://keybase.io/_/api/1.0/user/lookup.json?username={}",
        "method": "api_json",
        "found_key": "status",
        "found_check": lambda d: isinstance(d, dict) and d.get("status", {}).get("code") == 0,
    },
    "Steam": {
        "url": "https://steamcommunity.com/id/{}/?xml=1",
        "method": "body_text",
        "found_signals": ["<steamID64>"],
        "not_found_signals": ["The specified profile could not be found"],
    },
    "SoundCloud": {
        "url": "https://soundcloud.com/{}",
        "method": "status_code",
        "error_codes": [404],
    },
    "Replit": {
        "url": "https://replit.com/@{}",
        "method": "status_code",
        "error_codes": [404],
    },
    "Vimeo": {
        "url": "https://vimeo.com/{}",
        "method": "status_code",
        "error_codes": [404],
    },
    "Bitbucket": {
        "url": "https://bitbucket.org/!api/2.0/users/{}",
        "method": "status_code",
        "error_codes": [404],
    },
    "Codepen": {
        "url": "https://codepen.io/{}",
        "method": "status_code",
        "error_codes": [404],
    },
    "Dribbble": {
        "url": "https://dribbble.com/{}",
        "method": "status_code",
        "error_codes": [404],
    },
    "LeetCode": {
        "url": "https://leetcode.com/{}",
        "method": "status_code",
        "error_codes": [404],
    },
    "PyPI": {
        "url": "https://pypi.org/simple/{}/",
        "method": "status_code",
        "error_codes": [404],
    },
    "NPM": {
        "url": "https://www.npmjs.com/~{}",
        "method": "status_code",
        "error_codes": [404],
    },
    "Lichess": {
        "url": "https://lichess.org/api/user/{}",
        "method": "status_code",
        "error_codes": [404],
    },
    "Last.fm": {
        "url": "https://www.last.fm/user/{}",
        "method": "status_code",
        "error_codes": [404],
    },
    "Letterboxd": {
        "url": "https://letterboxd.com/{}",
        "method": "status_code",
        "error_codes": [404],
    },
    "Mastodon": {
        "url": "https://mastodon.social/@{}",
        "method": "status_code",
        "error_codes": [404, 410],
    },
    "DockerHub": {
        "url": "https://hub.docker.com/v2/users/{}",
        "method": "status_code",
        "error_codes": [404],
    },
    "Sourceforge": {
        "url": "https://sourceforge.net/u/{}/profile/",
        "method": "status_code",
        "error_codes": [404],
    },
    "Duolingo": {
        "url": "https://www.duolingo.com/2017-06-30/users?username={}",
        "method": "api_json",
        "found_check": lambda d: isinstance(d, dict) and d.get("users") and len(d["users"]) > 0,
    },
    "Telegram": {
        "url": "https://t.me/{}",
        "method": "body_text",
        "found_signals": ["tg://resolve"],
        "not_found_signals": [],
        "invert": True,  # tg://resolve present = NOT found (preview page)
    },
    "Medium": {
        "url": "https://medium.com/@{}",
        "method": "status_code",
        "error_codes": [404, 410],
    },
    "Behance": {
        "url": "https://www.behance.net/{}",
        "method": "status_code",
        "error_codes": [404],
    },
    "Mixcloud": {
        "url": "https://api.mixcloud.com/{}",
        "method": "api_json",
        "found_check": lambda d: isinstance(d, dict) and "username" in d,
    },
    "Codeforces": {
        "url": "https://codeforces.com/api/user.info?handles={}",
        "method": "api_json",
        "found_check": lambda d: isinstance(d, dict) and d.get("status") == "OK",
    },
    "Chess.com": {
        "url": "https://api.chess.com/pub/player/{}",
        "method": "status_code",
        "error_codes": [404],
    },
    "Imgur": {
        "url": "https://imgur.com/user/{}",
        "method": "status_code",
        "error_codes": [404],
    },
    "Trakt": {
        "url": "https://trakt.tv/users/{}",
        "method": "status_code",
        "error_codes": [404],
    },
    "AboutMe": {
        "url": "https://about.me/{}",
        "method": "status_code",
        "error_codes": [404],
    },
    "Wattpad": {
        "url": "https://www.wattpad.com/user/{}",
        "method": "status_code",
        "error_codes": [404],
    },
}

# ── Country calling-code prefixes ────────────────────────────────────────────

COUNTRY_PREFIXES = {
    "+44": "United Kingdom", "+1": "USA / Canada", "+61": "Australia",
    "+49": "Germany", "+33": "France", "+34": "Spain", "+39": "Italy",
    "+31": "Netherlands", "+46": "Sweden", "+47": "Norway", "+45": "Denmark",
    "+358": "Finland", "+353": "Ireland", "+41": "Switzerland",
    "+43": "Austria", "+32": "Belgium", "+48": "Poland", "+420": "Czech Republic",
    "+7": "Russia / Kazakhstan", "+86": "China", "+91": "India",
    "+81": "Japan", "+82": "South Korea", "+55": "Brazil", "+52": "Mexico",
    "+27": "South Africa", "+234": "Nigeria", "+20": "Egypt",
    "+971": "UAE", "+966": "Saudi Arabia", "+65": "Singapore",
}

# ── Disposable / temporary email domains ─────────────────────────────────────

DISPOSABLE_DOMAINS = {
    "mailinator.com", "guerrillamail.com", "tempmail.com", "10minutemail.com",
    "throwaway.email", "yopmail.com", "sharklasers.com", "guerrillamailblock.com",
    "grr.la", "spam4.me", "dispostable.com", "trashmail.com", "maildrop.cc",
    "fakeinbox.com", "getairmail.com", "trashmail.net", "tempr.email",
    "discard.email", "spamgourmet.com", "mintemail.com", "spamfree24.org",
}

# ── Consumer mail domains (SPF/DMARC belong to the provider, not the user) ──

CONSUMER_MAIL_DOMAINS = {
    "gmail.com", "googlemail.com",
    "outlook.com", "hotmail.com", "hotmail.co.uk", "hotmail.fr",
    "live.com", "live.co.uk", "msn.com",
    "yahoo.com", "yahoo.co.uk", "yahoo.fr", "yahoo.de",
    "icloud.com", "me.com", "mac.com",
    "protonmail.com", "proton.me",
    "tutanota.com", "tutamail.com",
    "aol.com", "yandex.com", "yandex.ru",
    "zoho.com", "fastmail.com", "fastmail.fm",
    "gmx.com", "gmx.de", "gmx.net", "mail.com", "cock.li",
}

# ── Holehe-style email registration probe sites ──────────────────────────────

HOLEHE_SITES = {
    "Adobe": {
        "endpoint": "https://accounts.adobe.com/renga/service/IMS/v2/login/widget/",
        "method": "POST",
        "data":   lambda e: {"client_id": "CreativeCloudInstaller", "scope": "openid",
                             "locale": "en_US", "email": e},
        "json":   True,
        "found_if":     lambda r: r.status_code == 200 and '"action":"EMAIL_READY"' in r.text,
        "not_found_if": lambda r: "EMAIL_ACCOUNT_NOT_FOUND" in r.text or r.status_code == 400,
    },
    "Snapchat": {
        "endpoint": "https://accounts.snapchat.com/accounts/get_username_suggestions",
        "method": "POST",
        "data":   lambda e: {"email": e},
        "json":   False,
        "found_if":     lambda r: r.status_code == 200 and "username_suggestions" in r.text,
        "not_found_if": lambda r: "email_not_found" in r.text.lower(),
    },
    "Twitter/X": {
        "endpoint": "https://api.twitter.com/i/users/email_available.json?email={email}",
        "method": "GET",
        "data":   None,
        "json":   False,
        "found_if":     lambda r: r.status_code == 200 and '"valid":false' in r.text,
        "not_found_if": lambda r: '"valid":true' in r.text,
    },
    "Firefox/Mozilla": {
        "endpoint": "https://api.accounts.firefox.com/v1/account/status",
        "method": "POST",
        "data":   lambda e: {"email": e},
        "json":   True,
        "found_if":     lambda r: r.status_code == 200 and '"exists":true' in r.text,
        "not_found_if": lambda r: '"exists":false' in r.text,
    },
    "Proton Mail": {
        "endpoint": "https://api.protonmail.ch/pks/lookup?op=index&search={email}",
        "method": "GET",
        "data":   None,
        "json":   False,
        "found_if":     lambda r: r.status_code == 200 and "pub" in r.text.lower(),
        "not_found_if": lambda r: r.status_code == 404 or "not found" in r.text.lower(),
    },
    "Spotify": {
        "endpoint": "https://spclient.wg.spotify.com/signup/public/v1/account?validate=1&email={email}",
        "method": "GET",
        "data":   None,
        "json":   False,
        "found_if":     lambda r: r.status_code == 200 and '"status":20' in r.text,
        "not_found_if": lambda r: '"status":10' in r.text,
    },
    "Lastpass": {
        "endpoint": "https://lastpass.com/iterations.php",
        "method": "POST",
        "data":   lambda e: {"email": e},
        "json":   False,
        "found_if":     lambda r: (r.status_code == 200
                                   and r.text.strip().isdigit()
                                   and int(r.text.strip()) > 1),
        "not_found_if": lambda r: r.text.strip() == "1" or r.status_code != 200,
    },
    "Imgur": {
        "endpoint": "https://api.imgur.com/3/emailverification",
        "method": "POST",
        "data":   lambda e: {"email": e},
        "json":   True,
        "found_if":     lambda r: r.status_code == 200 and '"success":true' in r.text,
        "not_found_if": lambda r: '"success":false' in r.text,
    },
    "Duolingo": {
        "endpoint": "https://www.duolingo.com/2017-06-30/users?email={email}",
        "method": "GET",
        "data":   None,
        "json":   False,
        "found_if":     lambda r: r.status_code == 200 and '"totalItems":1' in r.text,
        "not_found_if": lambda r: '"totalItems":0' in r.text,
    },
    "Dropbox": {
        "endpoint": "https://www.dropbox.com/ajax_login",
        "method": "POST",
        "data":   lambda e: {"login_email": e, "login_password": "x", "t": ""},
        "json":   False,
        "found_if":     lambda r: (r.status_code == 200
                                   and "password" in r.text.lower()
                                   and "not exist" not in r.text.lower()),
        "not_found_if": lambda r: ("not exist" in r.text.lower()
                                   or "no account" in r.text.lower()),
    },
}

# ── Leak-Lookup public API key (documented by h8mail) ────────────────────────

LEAK_LOOKUP_PUBLIC_KEY = "1bf94ff907f68d511de9a610a6ff9263"


# ── Display helpers ──────────────────────────────────────────────────────────

def print_banner():
    """Print the ASCII banner and session metadata."""
    console.print(f"[bold green]{BANNER}[/bold green]")
    console.print(f"[dim]  Started : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}[/dim]")
    console.print(
        f"[dim]  v7.0 — HIBP · LeakCheck · Leak-Lookup · BreachDir · Dehashed · "
        f"PSBDMP · Phonebook.cz · Google · Holehe({len(HOLEHE_SITES)}) · EmailRep · "
        f"OTX · Pulsedive · URLScan · HackerTarget · Social({len(SOCIAL_PLATFORMS)}) · "
        f"GitHub · GitLab · Keybase · Twitter · Telegram · Steam · "
        f"DNS/WHOIS · Shodan · ProxyCheck · IntelX · Dorks · Phone[/dim]\n"
    )


def section(title: str):
    """Print a green section divider."""
    console.print()
    console.print(Rule(f"[bold green] {title} [/bold green]", style="green"))
