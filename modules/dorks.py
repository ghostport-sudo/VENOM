"""
Google dork generation, extended paste/leak dorks, and dark-web manual links.
"""

import urllib.parse


def generate_dorks(email: str = "", username: str = "", domain: str = "") -> list:
    """Core dork queries — returns list of (query_string, google_url) tuples."""
    dorks = []
    if email:
        e = urllib.parse.quote(email)
        dorks += [
            (f'site:pastebin.com "{email}"',
             f"https://www.google.com/search?q=site:pastebin.com+%22{e}%22"),
            (f'"{email}" filetype:sql OR filetype:txt',
             f"https://www.google.com/search?q=%22{e}%22+filetype:sql+OR+filetype:txt"),
            (f'"{email}" password OR credentials OR leak',
             f"https://www.google.com/search?q=%22{e}%22+password+OR+credentials+OR+leak"),
            (f'"{email}" site:github.com OR site:gitlab.com',
             f"https://www.google.com/search?q=%22{e}%22+site:github.com+OR+site:gitlab.com"),
            (f'intext:"{email}" site:trello.com OR site:notion.so',
             f"https://www.google.com/search?q=intext:%22{e}%22+site:trello.com+OR+site:notion.so"),
        ]
    if username:
        u = urllib.parse.quote(username)
        dorks += [
            (f'"{username}" site:pastebin.com',
             f"https://www.google.com/search?q=%22{u}%22+site:pastebin.com"),
            (f'"{username}" site:reddit.com OR site:twitter.com',
             f"https://www.google.com/search?q=%22{u}%22+site:reddit.com+OR+site:twitter.com"),
            (f'"{username}" doxxed OR leaked OR exposed',
             f"https://www.google.com/search?q=%22{u}%22+doxxed+OR+leaked+OR+exposed"),
            (f'"{username}" email OR phone OR address',
             f"https://www.google.com/search?q=%22{u}%22+email+OR+phone+OR+address"),
        ]
    if domain:
        d = urllib.parse.quote(domain)
        dorks += [
            (f'site:{domain} filetype:env OR filetype:conf OR filetype:log',
             f"https://www.google.com/search?q=site:{d}+filetype:env+OR+filetype:conf+OR+filetype:log"),
            (f'site:github.com "{domain}" password OR secret OR key',
             f"https://www.google.com/search?q=site:github.com+%22{d}%22+password+OR+secret+OR+key"),
        ]
    return dorks


def extra_dorks(email: str = "", username: str = "", domain: str = "") -> list:
    """Additional paste-site, breach-forum, and leak-focused dorks."""
    dorks = []
    if email:
        e = urllib.parse.quote(email)
        dorks += [
            (f'"{email}" site:raidforums.com OR site:breachforums.com',
             f"https://www.google.com/search?q=%22{e}%22+site:raidforums.com+OR+site:breachforums.com"),
            (f'"{email}" site:ghostbin.co OR site:hastebin.com OR site:dpaste.org',
             f"https://www.google.com/search?q=%22{e}%22+site:ghostbin.co+OR+site:hastebin.com+OR+site:dpaste.org"),
            (f'"{email}" intext:password site:pastebin.com',
             f"https://www.google.com/search?q=%22{e}%22+intext:password+site:pastebin.com"),
            (f'"{email}" filetype:csv OR filetype:xlsx',
             f"https://www.google.com/search?q=%22{e}%22+filetype:csv+OR+filetype:xlsx"),
            (f'"{email}" site:scribd.com OR site:slideshare.net',
             f"https://www.google.com/search?q=%22{e}%22+site:scribd.com+OR+site:slideshare.net"),
        ]
    if username:
        u = urllib.parse.quote(username)
        dorks += [
            (f'"{username}" site:pastebin.com OR site:ghostbin.co',
             f"https://www.google.com/search?q=%22{u}%22+site:pastebin.com+OR+site:ghostbin.co"),
            (f'"{username}" site:raidforums.com OR site:cracked.io',
             f"https://www.google.com/search?q=%22{u}%22+site:raidforums.com+OR+site:cracked.io"),
            (f'inurl:"{username}" site:trello.com',
             f"https://www.google.com/search?q=inurl:%22{u}%22+site:trello.com"),
        ]
    if domain:
        d = urllib.parse.quote(domain)
        dorks += [
            (f'site:{domain} inurl:wp-admin OR inurl:phpmyadmin OR inurl:adminer',
             f"https://www.google.com/search?q=site:{d}+inurl:wp-admin+OR+inurl:phpmyadmin"),
            (f'site:github.com "{domain}" token OR apikey OR password OR secret',
             f"https://www.google.com/search?q=site:github.com+%22{d}%22+token+OR+apikey"),
        ]
    return dorks


def darkweb_links(email: str = "", username: str = "", domain: str = "") -> list:
    """Pre-built investigation URLs for dark-web indexes and paste aggregators."""
    links = []
    targets = [t for t in [email, username, domain] if t]
    for t in targets:
        q = urllib.parse.quote(t)
        links += [
            ("IntelX (free account needed)", f"https://intelx.io/?s={q}"),
            ("Leak-Lookup",                  f"https://leak-lookup.com/search?query={q}&type=auto"),
            ("WhiteIntel (dark web index)",  f"https://whiteintel.io/search?query={q}"),
            ("Snusbase (paid)",              f"https://snusbase.com/search?term={q}"),
            ("PSBDMP Pastebin archive",      f"https://psbdmp.ws/api/v3/search/{q}"),
            ("Scylla.so breach DB",          f"https://scylla.so/search?q={q}"),
            ("DeHashed (paid)",              f"https://dehashed.com/search?query={q}"),
            ("LeakRadar (paid)",             f"https://leakradar.io/?query={q}"),
            ("LibraryOfLeaks",               f"https://libraryofleaks.com/?search={q}"),
            ("Google: paste sites",
             f"https://www.google.com/search?q=%22{q}%22+site:pastebin.com+OR+site:ghostbin.co+OR+site:hastebin.com"),
            ("Google: breach forums",
             f"https://www.google.com/search?q=%22{q}%22+site:breachforums.com+OR+site:raidforums.com"),
            ("Telegram channel search",      f"https://t.me/s/{q}"),
        ]
    return links
