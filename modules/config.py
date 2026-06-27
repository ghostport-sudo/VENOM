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

  OSINT Breach Scanner v6.0
      By: ghostport
"""

# ── Social platform registry ─────────────────────────────────────────────────
# Each entry maps a human-readable name to (URL template, not-exist signals).
# The URL template uses {} as a placeholder for the username.

SOCIAL_PLATFORMS = {
    # ── Original platforms ────────────────────────────────────────────────
    "GitHub":       ("https://github.com/{}",                          ["not found"]),
    "Twitter/X":    ("https://twitter.com/{}",                         ["this account doesn't exist"]),
    "Instagram":    ("https://www.instagram.com/{}/",                  ["page not found", "sorry, this"]),
    "Reddit":       ("https://www.reddit.com/user/{}",                 ["nobody on reddit goes by that name"]),
    "TikTok":       ("https://www.tiktok.com/@{}",                     ["couldn't find this account"]),
    "LinkedIn":     ("https://www.linkedin.com/in/{}",                 ["page not found"]),
    "Pinterest":    ("https://www.pinterest.com/{}/",                  ["sorry! we couldn't find that page"]),
    "Twitch":       ("https://www.twitch.tv/{}",                       ["sorry. unless you"]),
    "YouTube":      ("https://www.youtube.com/@{}",                    ["this page isn't available"]),
    "Snapchat":     ("https://www.snapchat.com/add/{}",                ["this profile doesn't exist"]),
    "Tumblr":       ("https://{}.tumblr.com",                          ["there's nothing here"]),
    "Pastebin":     ("https://pastebin.com/u/{}",                      ["not found"]),
    "Keybase":      ("https://keybase.io/{}",                          ["not found"]),
    "GitLab":       ("https://gitlab.com/{}",                          ["404", "not found"]),
    "HackerNews":   ("https://news.ycombinator.com/user?id={}",        ["no such user"]),
    "DeviantArt":   ("https://www.deviantart.com/{}",                  ["not found"]),
    "Flickr":       ("https://www.flickr.com/people/{}",               ["not found"]),
    "Gravatar":     ("https://en.gravatar.com/{}",                     ["profile not found"]),
    "Codecademy":   ("https://www.codecademy.com/profiles/{}",         ["404"]),
    "Replit":       ("https://replit.com/@{}",                         ["not found"]),
    "Mastodon":     ("https://mastodon.social/@{}",                    ["not found", "no such account"]),
    "Steam":        ("https://steamcommunity.com/id/{}",               ["the specified profile could not be found"]),
    "SoundCloud":   ("https://soundcloud.com/{}",                      ["404", "not found"]),
    "Medium":       ("https://medium.com/@{}",                         ["page not found"]),
    "Substack":     ("https://{}.substack.com",                        ["page not found", "404"]),
    "ProductHunt":  ("https://www.producthunt.com/@{}",                ["404", "not found"]),
    "Behance":      ("https://www.behance.net/{}",                     ["page not found"]),
    "Dribbble":     ("https://dribbble.com/{}",                        ["whoops, that page is gone"]),
    "Fiverr":       ("https://www.fiverr.com/{}",                      ["not found"]),
    "HackerEarth":  ("https://www.hackerearth.com/@{}",                ["not found"]),
    "LeetCode":     ("https://leetcode.com/{}",                        ["user not found"]),
    "Codeforces":   ("https://codeforces.com/profile/{}",              ["not found"]),
    "DockerHub":    ("https://hub.docker.com/u/{}",                    ["404"]),
    "PyPI":         ("https://pypi.org/user/{}/",                      ["not found"]),
    "AboutMe":      ("https://about.me/{}",                            ["page not found"]),
    "Telegram":     ("https://t.me/{}",                                ["tg://resolve"]),
    "Spotify":      ("https://open.spotify.com/user/{}",               ["not found"]),
    "NPM":          ("https://www.npmjs.com/~{}",                      ["not found"]),
    "Etsy":         ("https://www.etsy.com/shop/{}",                   ["shop not found"]),
    # ── v3 additions ─────────────────────────────────────────────────────
    "Bluesky":      ("https://bsky.app/profile/{}",                    ["profile not found", "not found"]),
    "Threads":      ("https://www.threads.net/@{}",                    ["page not found"]),
    "VKontakte":    ("https://vk.com/{}",                              ["page not found"]),
    "Roblox":       ("https://www.roblox.com/user.aspx?username={}",   ["page not found"]),
    "Chess.com":    ("https://www.chess.com/member/{}",                ["this member", "404"]),
    "Bandcamp":     ("https://{}.bandcamp.com",                        ["sorry, that something"]),
    "Vimeo":        ("https://vimeo.com/{}",                           ["page not found"]),
    "Bitbucket":    ("https://bitbucket.org/{}/",                      ["404"]),
    "Codepen":      ("https://codepen.io/{}",                          ["404", "not found"]),
    "500px":        ("https://500px.com/p/{}",                         ["page not found"]),
    "Patreon":      ("https://www.patreon.com/{}",                     ["page not found"]),
    "Upwork":       ("https://www.upwork.com/freelancers/~{}",         ["not found"]),
    "Hackaday":     ("https://hackaday.io/{}",                         ["page not found"]),
    "TryHackMe":    ("https://tryhackme.com/p/{}",                     ["page not found", "not found"]),
    "HackTheBox":   ("https://app.hackthebox.com/users/{}",            ["page not found"]),
    # ── v5 additions ─────────────────────────────────────────────────────
    "Cashapp":      ("https://cash.app/${}",                           ["not found", "page not found"]),
    "Venmo":        ("https://venmo.com/{}",                           ["venmo user not found"]),
    "OnlyFans":     ("https://onlyfans.com/{}",                        ["this page is not available"]),
    "Linktree":     ("https://linktr.ee/{}",                           ["sorry, this page isn"]),
    "Ko-fi":        ("https://ko-fi.com/{}",                           ["page not found"]),
    "itch.io":      ("https://{}.itch.io",                             ["page not found"]),
    "Newgrounds":   ("https://{}.newgrounds.com",                      ["doesn't exist"]),
    "Wattpad":      ("https://www.wattpad.com/user/{}",                ["this page does not exist"]),
    "Goodreads":    ("https://www.goodreads.com/{}",                   ["page not found"]),
    "Strava":       ("https://www.strava.com/athletes/{}",             ["not found"]),
    "MyFitnessPal": ("https://www.myfitnesspal.com/profile/{}",        ["this page is private"]),
    "Quora":        ("https://www.quora.com/profile/{}",               ["page not found"]),
    "Clubhouse":    ("https://www.clubhouse.com/@{}",                  ["not found"]),
    "Imgur":        ("https://imgur.com/user/{}",                      ["there's nothing here"]),
    "Ask.fm":       ("https://ask.fm/{}",                              ["this user does not exist"]),
    "Dailymotion":  ("https://www.dailymotion.com/{}",                 ["page not found"]),
    "VK":           ("https://vk.com/{}",                              ["page not found"]),
    "Duolingo":     ("https://www.duolingo.com/profile/{}",            ["404"]),
    "Lichess":      ("https://lichess.org/@/{}",                       ["not found"]),
    "Letterboxd":   ("https://letterboxd.com/{}",                      ["we couldn't find this person"]),
    "Last.fm":      ("https://www.last.fm/user/{}",                    ["not found"]),
    "Trakt":        ("https://trakt.tv/users/{}",                      ["page not found"]),
    "Livejournal":  ("https://{}.livejournal.com",                     ["was not found"]),
    "WordPress":    ("https://{}.wordpress.com",                       ["doesn't exist"]),
    "Blogspot":     ("https://{}.blogspot.com",                        ["not found", "sorry"]),
    "Sourceforge":  ("https://sourceforge.net/u/{}/profile/",          ["not found"]),
    "Gitea":        ("https://gitea.com/{}",                           ["not found"]),
    "Freelancer":   ("https://www.freelancer.com/u/{}",                ["oops", "not found"]),
    "Mixcloud":     ("https://www.mixcloud.com/{}",                    ["not found"]),
    "Reverbnation": ("https://www.reverbnation.com/{}",                ["page not found"]),
    "Audiomack":    ("https://audiomack.com/{}",                       ["page not found"]),
    "Minds":        ("https://www.minds.com/{}",                       ["page not found"]),
    "MeWe":         ("https://mewe.com/i/{}",                          ["not found"]),
    "Gab":          ("https://gab.com/{}",                             ["page not found"]),
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
        f"[dim]  v6.0 — HIBP · LeakCheck · Leak-Lookup · BreachDir · Dehashed · "
        f"PSBDMP · Phonebook.cz · Google · Holehe({len(HOLEHE_SITES)}) · EmailRep · "
        f"OTX · Pulsedive · URLScan · HackerTarget · Social({len(SOCIAL_PLATFORMS)}) · "
        f"GitHub · GitLab · Keybase · Twitter · Telegram · Steam · "
        f"DNS/WHOIS · Shodan · ProxyCheck · IntelX · Dorks · Phone[/dim]\n"
    )


def section(title: str):
    """Print a green section divider."""
    console.print()
    console.print(Rule(f"[bold green] {title} [/bold green]", style="green"))
