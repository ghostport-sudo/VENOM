"""
Terminal output rendering — VENOM OSINT v7.0
Industry-grade density: CME/netexec style, no HTTP narration spam.
"""

import sys
from rich.table import Table
from rich import box
from rich.rule import Rule
from rich.text import Text

from modules.config import console, SOCIAL_PLATFORMS, COUNTRY_PREFIXES

# ── Safe encoding ────────────────────────────────────────────────────────────

def _safe(char: str, fallback: str) -> str:
    try:
        (sys.stdout.encoding or "ascii").encode  # attr check
        char.encode(sys.stdout.encoding or "ascii")
        return char
    except Exception:
        return fallback

CHECK   = _safe("✓", "+")
CROSS   = _safe("✗", "x")
FLAG    = _safe("⚑", "!")
WARN    = _safe("⚠", "!")
BULLET  = _safe("•", "*")
STAR    = _safe("★", "*")
ELLIP   = _safe("…", "...")
DASH    = _safe("—", "-")
PIPE    = "|"

# ── Severity colour helper ───────────────────────────────────────────────────

def _sev(level: str) -> str:
    """Return a Rich colour tag for a severity string."""
    return {"critical": "bold red", "high": "red", "medium": "yellow",
            "low": "dim yellow", "none": "green", "info": "cyan"}.get(level, "white")

# ── Section divider ──────────────────────────────────────────────────────────

def section(title: str):
    console.print()
    console.print(Rule(f"[bold green] {title} [/bold green]", style="green"))

# ── Tag row helper ───────────────────────────────────────────────────────────

def _kv(label: str, value: str, col: str = "white", width: int = 22):
    if value:
        console.print(f"  [dim]{label:<{width}}[/dim] [{col}]{value}[/{col}]")

# ── HIBP ─────────────────────────────────────────────────────────────────────

def render_hibp(breaches: list, pastes: list):
    if not breaches and not pastes:
        console.print(f"  [green]{CHECK} HIBP            no breach or paste records[/green]")
        return
    if breaches:
        t = Table(box=box.SIMPLE_HEAD, show_header=True, header_style="bold red",
                  min_width=78, padding=(0, 1))
        t.add_column("Breach",      style="bold white",  min_width=22)
        t.add_column("Date",        style="dim",         width=10)
        t.add_column("Records",     justify="right",     width=10)
        t.add_column("Data classes",                     min_width=26)
        t.add_column("Sens",        width=6)
        for b in sorted(breaches, key=lambda x: x.get("BreachDate", ""), reverse=True):
            sensitive = b.get("IsSensitive", False)
            col       = "red" if sensitive else "yellow"
            classes   = ", ".join(b.get("DataClasses", [])[:5])
            if len(b.get("DataClasses", [])) > 5:
                classes += f" +{len(b['DataClasses']) - 5}"
            t.add_row(
                f"[{col}]{b.get('Name', '')}[/{col}]",
                b.get("BreachDate", "")[:7],
                f"{b.get('PwnCount', 0):,}",
                classes,
                "[red]YES[/red]" if sensitive else "[dim]no[/dim]",
            )
        console.print(f"  [red]{CROSS} HIBP            {len(breaches)} breach(es)[/red]")
        console.print(t)
    if pastes:
        console.print(f"  [yellow]{WARN} HIBP pastes     {len(pastes)} paste(s)[/yellow]")
        for p in pastes[:8]:
            console.print(f"    [dim]{BULLET}[/dim] {p.get('Source','?')} {DASH} "
                          f"{p.get('Date','')[:10]} {DASH} "
                          f"{p.get('Title') or '(untitled)'}")

# ── BreachDirectory ──────────────────────────────────────────────────────────

def render_breach_directory(data: dict):
    import base64, binascii
    if not data:
        console.print(f"  [dim]  BreachDir       no response[/dim]"); return
    if data.get("error") == "no_key":
        console.print(f"  [dim]  BreachDir       skipped — pass --bd-key (RapidAPI free tier)[/dim]"); return
    results = data.get("result", [])
    if not results and not data.get("found"):
        console.print(f"  [green]{CHECK} BreachDir       no records[/green]"); return
    console.print(f"  [red]{CROSS} BreachDir       {len(results)} record(s)[/red]")
    t = Table(box=box.SIMPLE_HEAD, show_header=True, header_style="bold red", padding=(0, 1))
    t.add_column("Source",    min_width=22)
    t.add_column("Type",      width=12)
    t.add_column("Hash / Hint", style="yellow")
    for rec in results[:20]:
        src  = (rec.get("sources") or ["?"])
        src  = src[0] if isinstance(src, list) else str(src)
        hint = rec.get("password", "")
        hsh  = str(rec.get("sha1") or rec.get("hash") or "")
        try:
            if any(c in hsh for c in "+/=") and len(hsh) > 20:
                hsh = binascii.hexlify(base64.b64decode(hsh)).decode()
        except Exception:
            pass
        display = f"{hint} {PIPE} {hsh}" if hint and hsh and hint != hsh else hsh or hint or "N/A"
        t.add_row(src, str(rec.get("hash_type", "unknown")), display)
    console.print(t)

# ── DNS / WHOIS / IP ─────────────────────────────────────────────────────────

def render_dns_whois(domain: str, dns: dict, whois: dict, ip: dict):
    geo = (ip or {}).get("geo", {})
    loc = ", ".join(p for p in [geo.get("city"), geo.get("region"), geo.get("country")] if p)
    _kv("Provider",     dns.get("provider", ""))
    if ip and ip.get("ip"):
        _kv("IP",       f"{ip['ip']}{f'  ({loc})' if loc else ''}", "cyan")
    if geo.get("org"):
        _kv("Hosting / ASN",  geo["org"])
    if whois and whois.get("registered"):
        _kv("Registrar",      whois.get("registrar", ""))
        _kv("Registered",     whois.get("created", ""))
        _kv("Expires",        whois.get("expires", ""))
    if dns and dns.get("ns"):
        _kv("Nameservers",    ", ".join(dns["ns"][:2]))
    if dns and dns.get("txt"):
        console.print(f"  [dim]{'TXT records':<22}[/dim]")
        for t in dns["txt"][:4]:
            console.print(f"    [dim]{BULLET}[/dim] {t[:100]}")

# ── GitHub ───────────────────────────────────────────────────────────────────

def render_github_user(gh: dict):
    if not gh["found"]:
        console.print(f"  [dim]  GitHub          no account found[/dim]"); return
    p = gh["profile"]
    console.print(f"  [green]{CHECK} GitHub          {p['url']}[/green]")
    for label, key in [("Name","name"),("Bio","bio"),("Email","email"),
                       ("Company","company"),("Location","location"),("Blog","blog")]:
        _kv(label, p.get(key, ""))
    console.print(f"  [dim]{'Stats':<22}[/dim] "
                  f"{p['followers']} followers {BULLET} "
                  f"{p['repos']} repos {BULLET} joined {p['created']}")
    if gh["repos"]:
        console.print(f"  [dim]Repos:[/dim]")
        for r in gh["repos"][:5]:
            lang  = f" [{r['language']}]" if r["language"] else ""
            stars = f" {STAR}{r['stars']}" if r["stars"] else ""
            console.print(f"    [green]{BULLET}[/green] {r['name']}{lang}{stars}  "
                          f"[dim]{r['url']}[/dim]")
    if gh["gists"]:
        console.print(f"  [dim]Gists:[/dim]")
        for g in gh["gists"][:3]:
            console.print(f"    [dim]{BULLET}[/dim] {g['description'][:60]}  [dim]{g['url']}[/dim]")

def render_github_commits(commits: list):
    if not commits:
        console.print(f"  [dim]  GitHub commits  no email exposure[/dim]"); return
    console.print(f"  [yellow]{WARN} GitHub commits  email in {len(commits)} public commit(s)[/yellow]")
    for c in commits:
        console.print(f"    [dim]{BULLET}[/dim] {c['repo']}  [dim]{c['date']}[/dim]")
        console.print(f"      [dim]{c['message'][:70]}[/dim]")
        console.print(f"      [dim]{c['url']}[/dim]")

def render_v4_github_orgs(orgs: list, username: str):
    if not orgs:
        console.print(f"  [dim]  GitHub orgs     none[/dim]"); return
    console.print(f"  [yellow]{FLAG} GitHub orgs     {len(orgs)} org(s)[/yellow]")
    for o in orgs[:10]:
        desc = f" {DASH} {o['description']}" if o.get("description") else ""
        console.print(f"    [dim]{BULLET}[/dim] [bold]{o['login']}[/bold]{desc}  [dim]{o['url']}[/dim]")

# ── Google Dorks ─────────────────────────────────────────────────────────────

def render_dorks(dorks: list):
    console.print(f"  [dim]{len(dorks)} queries — paste into browser to run:[/dim]")
    for query, url in dorks:
        console.print(f"  [green]>[/green] [bold]{query}[/bold]")
        console.print(f"    [dim]{url}[/dim]")

def render_v4_extra_dorks(dorks: list):
    if not dorks:
        return
    console.print(f"\n  [dim]Paste / leak site dorks:[/dim]")
    for query, url in dorks:
        console.print(f"  [yellow]>[/yellow] [bold]{query}[/bold]")
        console.print(f"    [dim]{url}[/dim]")

# ── Username enumeration ─────────────────────────────────────────────────────

def render_username_results(found, not_found, errors):
    if found:
        console.print(f"  [green]{CHECK} Social          {len(found)} platform(s) found[/green]")
        for platform, url in sorted(found, key=lambda x: x[0]):
            console.print(f"    [green]{BULLET}[/green] [bold]{platform:<18}[/bold] [dim]{url}[/dim]")
    else:
        console.print(f"  [dim]  Social          no accounts detected[/dim]")
    if not_found:
        nf    = ", ".join(p for p, _ in sorted(not_found, key=lambda x: x[0])[:12])
        extra = f" +{len(not_found)-12} more" if len(not_found) > 12 else ""
        console.print(f"  [dim]  Not found: {nf}{extra}[/dim]")

# ── LeakCheck (legacy, kept for compat) ──────────────────────────────────────

def render_leakcheck(data: dict):
    if not data:
        console.print(f"  [dim]  LeakCheck       no response[/dim]"); return
    if data.get("success") and data.get("found", 0) > 0:
        console.print(f"  [red]{CROSS} LeakCheck       {data['found']} source(s)[/red]")
        for src in data.get("sources", [])[:10]:
            name = src if isinstance(src, str) else src.get("name", str(src))
            console.print(f"    [dim]{BULLET}[/dim] {name}")
    else:
        console.print(f"  [green]{CHECK} LeakCheck       no exposures[/green]")

# ── Gravatar ─────────────────────────────────────────────────────────────────

def render_ext_gravatar(g: dict):
    if not g["registered"]:
        console.print(f"  [dim]  Gravatar        not registered  "
                      f"[dim]hash: {g['hash'][:12]}{ELLIP}[/dim]")
        return
    console.print(f"  [yellow]{FLAG} Gravatar        registered  "
                  f"[dim]hash: {g['hash'][:12]}{ELLIP}[/dim][/yellow]")
    for label, key in [("Display name","display_name"),("Real name","real_name"),
                       ("Location","location"),("Bio","bio")]:
        _kv(label, g.get(key, ""), "yellow")
    if g.get("accounts"):
        _kv("Linked accounts", ", ".join(g["accounts"]))
    _kv("Profile URL", g["profile_url"])

# ── EmailRep ─────────────────────────────────────────────────────────────────

def v5_render_emailrep(data: dict | None):
    if not data:
        console.print(f"  [dim]  EmailRep        no response[/dim]"); return
    if data.get("_rate_limited"):
        console.print(f"  [yellow]{WARN} EmailRep        rate limited — pass --emailrep-key[/yellow]"); return
    if data.get("_bad_key"):
        console.print(f"  [yellow]{WARN} EmailRep        invalid key[/yellow]"); return
    rep  = data.get("reputation", "unknown")
    susp = data.get("suspicious", False)
    refs = data.get("references", 0)
    col  = "red" if susp else ("yellow" if rep in ("low","none") else "green")
    icon = CROSS if susp else CHECK
    console.print(f"  [{col}]{icon} EmailRep        rep={rep}  refs={refs}"
                  f"{'  SUSPICIOUS' if susp else ''}[/{col}]")
    details = data.get("details", {})
    tags = details.get("tags", [])
    if tags:
        console.print(f"    [dim]Tags:[/dim] {', '.join(tags)}")
    for key, label, bad in [
        ("malicious_activity",        "Malicious activity",  True),
        ("malicious_activity_recent", "Recent malicious",    True),
        ("spam",                      "Spam source",         True),
        ("blacklisted",               "Blacklisted",         True),
        ("data_breach",               "Seen in breach",      False),
        ("free_provider",             "Free provider",       False),
        ("disposable",                "Disposable",          True),
        ("first_seen",                "First seen",          False),
        ("last_seen",                 "Last seen",           False),
    ]:
        val = details.get(key)
        if val is None:
            continue
        if isinstance(val, bool):
            if val:
                c = "red" if bad else "yellow"
                console.print(f"    [{c}]{FLAG} {label}[/{c}]")
        else:
            console.print(f"    [dim]{label}:[/dim] {val}")

# ── crt.sh ───────────────────────────────────────────────────────────────────

def render_ext_crtsh_email(results: list):
    if not results:
        console.print(f"  [dim]  crt.sh email    no cert records[/dim]"); return
    console.print(f"  [yellow]{FLAG} crt.sh email    {len(results)} certificate(s)[/yellow]")
    for c in results[:8]:
        console.print(f"    [dim]{BULLET}[/dim] {c['domain']}  "
                      f"[dim]{c['issued']}  {c['issuer']}[/dim]")

def render_ext_crtsh_domain(results: list):
    if not results:
        console.print(f"  [dim]  crt.sh subs     none found[/dim]"); return
    console.print(f"  [yellow]{FLAG} crt.sh subs     {len(results)} subdomain(s)[/yellow]")
    for c in results[:20]:
        console.print(f"    [dim]{BULLET}[/dim] {c['subdomain']}  [dim]{c['issued']}[/dim]")
    if len(results) > 20:
        console.print(f"    [dim]{ELLIP} and {len(results)-20} more[/dim]")

# ── Shodan ───────────────────────────────────────────────────────────────────

def render_ext_shodan(entry: dict, ip: str, geo: dict | None, asn: dict | None):
    if not entry:
        console.print(f"  [dim]  Shodan          no data[/dim]"); return
    ports = entry.get("ports", [])
    vulns = entry.get("vulns", [])
    tags  = entry.get("tags",  [])
    cpes  = entry.get("cpes",  [])
    col   = "red" if vulns else ("yellow" if ports else "green")
    loc_str = ""
    if geo:
        loc_str = f"  [dim]{geo.get('city','')}, {geo.get('country','')}[/dim]"
    asn_str = f"  [dim]{asn.get('asn_name','')}  AS{asn.get('asn','')}[/dim]" if asn else ""
    console.print(f"  [{col}]{BULLET} Shodan          {ip}[/{col}]{loc_str}{asn_str}")
    if ports:
        console.print(f"    [dim]Ports:[/dim] {', '.join(str(p) for p in ports[:20])}")
    if cpes:
        console.print(f"    [dim]CPEs: [/dim] {', '.join(cpes[:4])}")
    if vulns:
        console.print(f"    [red]CVEs:  {', '.join(vulns[:8])}[/red]")
    if tags:
        console.print(f"    [dim]Tags:  {', '.join(tags)}[/dim]")

# ── Wayback Machine ──────────────────────────────────────────────────────────

def render_ext_wayback(wb: dict | None):
    if not wb:
        console.print(f"  [dim]  Wayback         no snapshots[/dim]"); return
    def _fmt(ts): return f"{ts[:4]}-{ts[4:6]}-{ts[6:8]}" if len(ts) >= 8 else ts
    console.print(f"  [dim]  Wayback         first={_fmt(wb['first'])}  "
                  f"last={_fmt(wb['last'])}  total={wb['total']}+[/dim]")

# ── SSL Certificate ──────────────────────────────────────────────────────────

def render_ext_ssl(cert: dict | None):
    if not cert:
        console.print(f"  [dim]  SSL cert        could not retrieve[/dim]"); return
    subj = cert.get("subject", {})
    iss  = cert.get("issuer",  {})
    san  = cert.get("san",     [])
    console.print(f"  [bold]SSL Certificate[/bold]")
    for label, val, col in [
        ("CN",          subj.get("commonName", ""),         "white"),
        ("Organisation",subj.get("organizationName", ""),   "yellow"),
        ("Country",     subj.get("countryName", ""),        "white"),
        ("Issuer",      iss.get("organizationName", ""),    "white"),
        ("Valid until", cert.get("not_after", ""),          "white"),
    ]:
        _kv(label, val, col)
    if san:
        _kv("SAN domains", ", ".join(san[:8]) + (f" +{len(san)-8} more" if len(san) > 8 else ""))

# ── DNS Blacklist ─────────────────────────────────────────────────────────────

def render_ext_blacklist(bl: dict):
    hits = bl.get("blacklisted", [])
    if hits:
        console.print(f"  [red]{CROSS} DNS blacklist   {', '.join(hits)}[/red]")
    else:
        console.print(f"  [green]{CHECK} DNS blacklist   clean[/green]")

# ── GitLab / npm / PyPI ──────────────────────────────────────────────────────

def render_ext_gitlab(data: dict | None):
    if not data:
        console.print(f"  [dim]  GitLab          not found[/dim]"); return
    console.print(f"  [green]{CHECK} GitLab          https://gitlab.com/{data.get('username','')}[/green]")
    for label, key in [("Name","name"),("Bio","bio"),("Location","location"),
                       ("Website","website_url"),("Joined","created_at")]:
        _kv(label, str(data.get(key, ""))[:80])

def render_ext_npm(data: dict | None):
    if not data or not data.get("name"):
        console.print(f"  [dim]  npm             not found[/dim]"); return
    console.print(f"  [yellow]{FLAG} npm             {data.get('name','')}[/yellow]")
    if data.get("email"):
        _kv("Email (exposed)", data["email"], "yellow")

def render_ext_pypi(data: dict | None):
    if not data or not data.get("exists"):
        console.print(f"  [dim]  PyPI            not found[/dim]"); return
    console.print(f"  [yellow]{FLAG} PyPI            {data.get('packages', 0)} package(s)  "
                  f"[dim]{data.get('url','')}[/dim][/yellow]")

def render_ext_commit_emails(emails: set):
    if not emails:
        console.print(f"  [dim]  Commit emails   none exposed[/dim]"); return
    console.print(f"  [yellow]{FLAG} Commit emails   {', '.join(sorted(emails))}[/yellow]")

# ── Hunter.io ────────────────────────────────────────────────────────────────

def render_ext_hunter(data: dict | None):
    if not data:
        console.print(f"  [dim]  Hunter.io       no response[/dim]"); return
    emails = data.get("data", {}).get("emails", [])
    if not emails:
        console.print(f"  [dim]  Hunter.io       no emails found[/dim]"); return
    console.print(f"  [yellow]{FLAG} Hunter.io       {len(emails)} email(s)[/yellow]")
    t = Table(box=box.SIMPLE, show_header=True, header_style="bold yellow", padding=(0, 1))
    t.add_column("Email",      min_width=28)
    t.add_column("Name",       min_width=16)
    t.add_column("Position",   min_width=16)
    t.add_column("Conf",       justify="right", width=6)
    for em in emails[:12]:
        name = f"{em.get('first_name','')} {em.get('last_name','')}".strip()
        t.add_row(em.get("value",""), name,
                  em.get("position","") or "", f"{em.get('confidence',0)}%")
    console.print(t)

# ── Email Security Posture ───────────────────────────────────────────────────

def v5_render_posture(domain: str, posture: dict):
    if posture.get("_consumer"):
        console.print(f"  [dim]  Email posture   skipped (consumer: {posture.get('provider')})[/dim]")
        return
    console.print(f"  [bold]Email security posture — {domain}[/bold]")
    spf = posture["spf"]
    if spf["present"]:
        col = "red" if "dangerous" in spf["policy"] else ("yellow" if "soft" in spf["policy"] else "green")
        console.print(f"  [green]{CHECK} SPF[/green]   [{col}]{spf['policy']}[/{col}]")
    else:
        console.print(f"  [red]{CROSS} SPF   not configured — domain spoofable[/red]")
    dmarc = posture["dmarc"]
    if dmarc["present"]:
        pol = dmarc.get("policy", "?")
        col = "green" if pol in ("reject","quarantine") else "yellow"
        line = f"  [green]{CHECK} DMARC[/green] p={pol}  [{col}]{'strong' if pol=='reject' else 'partial'}[/{col}]"
        if dmarc.get("rua"): line += f"  [dim]rua={dmarc['rua']}[/dim]"
        console.print(line)
    else:
        console.print(f"  [red]{CROSS} DMARC not configured[/red]")
    sels = posture["dkim"].get("selectors", [])
    if sels:
        console.print(f"  [green]{CHECK} DKIM[/green]  selectors: {', '.join(sels)}")
    else:
        console.print(f"  [yellow]{WARN} DKIM  no common selectors detected[/yellow]")

# ── TXT Record Classification ────────────────────────────────────────────────

def v5_render_txt(classified: list, domain: str = ""):
    if not classified:
        console.print(f"  [dim]  TXT records     none[/dim]"); return
    console.print(f"  [bold]TXT records ({len(classified)}):[/bold]")
    for item in classified:
        col = "yellow" if item["type"] != "Unknown" else "dim"
        console.print(f"    [{col}]{BULLET} {item['type']}[/{col}]")
        console.print(f"      [dim]{item['record'][:110]}"
                      f"{ELLIP if len(item['record']) > 110 else ''}[/dim]")

# ── IntelligenceX ────────────────────────────────────────────────────────────

def v5_render_intelx(data: dict | None, query: str):
    if not data:
        console.print(f"  [dim]  IntelX          no response[/dim]"); return
    if data.get("_no_key"):
        console.print(f"  [dim]  IntelX          skipped — pass --intelx-key[/dim]"); return
    if data.get("_bad_key"):
        console.print(f"  [yellow]{WARN} IntelX          invalid key[/yellow]"); return
    records = data.get("records", [])
    if not records:
        console.print(f"  [green]{CHECK} IntelX          no indexed records[/green]"); return
    console.print(f"  [red]{CROSS} IntelX          {len(records)} indexed record(s)[/red]")
    t = Table(box=box.SIMPLE, show_header=True, header_style="bold red", padding=(0, 1))
    t.add_column("Type",   width=14)
    t.add_column("Date",   width=12)
    t.add_column("Source", min_width=30)
    for rec in records[:12]:
        t.add_row(rec.get("mediah",""), (rec.get("date") or "")[:10], rec.get("name",""))
    console.print(t)

# ── Username Permutations ─────────────────────────────────────────────────────

def render_ext_permutations(permutations: list, found_map: dict):
    console.print(f"  [bold]Username permutations ({len(permutations)} derived):[/bold]")
    for u in permutations:
        hits = found_map.get(u, [])
        if hits:
            platforms = ", ".join(p for p, _ in hits)
            console.print(f"    [yellow]{FLAG}[/yellow] [bold]{u}[/bold]  -> {platforms}")
        else:
            console.print(f"    [dim]  {u}[/dim]")

# ── Name Inference ───────────────────────────────────────────────────────────

def render_ext_name(info: dict):
    if not info.get("first"):
        return
    console.print(f"  [bold]Name inference (heuristic):[/bold]")
    _kv("Inferred first", info["first"], "yellow")
    if info.get("last"):
        _kv("Inferred last",  info["last"],  "yellow")
    _kv("Gender hint", info["gender"])
    console.print(f"  [dim]  (not authoritative — derived from local-part only)[/dim]")

# ── URLScan.io ───────────────────────────────────────────────────────────────

def render_v4_urlscan(results: list):
    if not results:
        console.print(f"  [dim]  URLScan.io      no historical scans[/dim]"); return
    console.print(f"  [yellow]{FLAG} URLScan.io      {len(results)} scan(s)[/yellow]")
    for r in results[:5]:
        mal = " [red]MALICIOUS[/red]" if r["malicious"] else ""
        tags = f" ({', '.join(r['tags'])})" if r["tags"] else ""
        console.print(f"    [dim]{BULLET}[/dim] {r['date']} {DASH} {r['url']}{mal}{tags} "
                      f"[dim]IP:{r['ip']} Server:{r['server']}[/dim]")

# ── OTX AlienVault ───────────────────────────────────────────────────────────

def render_v4_otx_domain(data: dict | None):
    if not data:
        console.print(f"  [dim]  OTX domain      no data[/dim]"); return
    pulses  = data.get("pulse_count", 0)
    malware = data.get("malware_count", 0)
    score   = data.get("threat_score", 0)
    col     = "red" if (pulses or malware or score) else "green"
    console.print(f"  [{col}]{FLAG} OTX domain      pulses={pulses}  malware={malware}"
                  f"{f'  score={score}/100' if score else ''}[/{col}]")

def render_v4_otx_ip(data: dict | None, ip: str):
    if not data:
        console.print(f"  [dim]  OTX IP          no data[/dim]"); return
    pulses = data.get("pulse_count", 0)
    rep    = data.get("reputation", 0)
    col    = "red" if (pulses or rep) else "green"
    console.print(f"  [{col}]{FLAG} OTX IP          {ip}  pulses={pulses}  rep={rep}[/{col}]")

def render_v4_otx_email(data: dict | None):
    if not data or not data.get("count"):
        console.print(f"  [dim]  OTX email       no threat pulses[/dim]"); return
    count = data.get("count", 0)
    console.print(f"  [red]{CROSS} OTX email       {count} pulse(s)[/red]")
    for r in data.get("results", []):
        tags = f" ({', '.join(r['tags'])})" if r["tags"] else ""
        console.print(f"    [dim]{BULLET}[/dim] [bold]{r['name']}[/bold]{tags}  "
                      f"[dim]{r['author']}  {r['date']}[/dim]")

# ── HackerTarget ─────────────────────────────────────────────────────────────

def render_v4_hackertarget_dns(results: list):
    if not results:
        console.print(f"  [dim]  HackerTarget    no passive DNS records[/dim]"); return
    console.print(f"  [yellow]{FLAG} HackerTarget    {len(results)} DNS host(s)[/yellow]")
    for r in results[:12]:
        console.print(f"    [dim]{BULLET}[/dim] {r['hostname']} [dim]-> {r['ip']}[/dim]")
    if len(results) > 12:
        console.print(f"    [dim]{ELLIP} and {len(results)-12} more[/dim]")

def render_v4_hackertarget_reverse(results: list, ip: str):
    if not results:
        console.print(f"  [dim]  HackerTarget    no reverse hostnames[/dim]"); return
    extra = f" +{len(results)-12} more" if len(results) > 12 else ""
    console.print(f"  [yellow]{FLAG} HackerTarget    {ip}  {', '.join(results[:12])}{extra}[/yellow]")

# ── Pulsedive ────────────────────────────────────────────────────────────────

def v5_render_pulsedive(data: dict | None, indicator: str):
    if not data:
        console.print(f"  [dim]  Pulsedive       no response[/dim]"); return
    risk = data.get("risk", "unknown")
    col  = "green" if risk == "none" else ("yellow" if risk in ("low","medium") else "red")
    console.print(f"  [{col}]{FLAG} Pulsedive       risk={risk.upper()}[/{col}]")
    if data.get("threats"):
        console.print(f"    [dim]Threats: {', '.join(data['threats'])}[/dim]")
    if data.get("feeds"):
        console.print(f"    [dim]Feeds:   {', '.join(data['feeds'])}[/dim]")
    if data.get("last_seen"):
        console.print(f"    [dim]Last seen: {data['last_seen']}[/dim]")

# ── Keybase ──────────────────────────────────────────────────────────────────

def render_v4_keybase(data: dict | None):
    if not data:
        console.print(f"  [dim]  Keybase         not found[/dim]"); return
    console.print(f"  [green]{CHECK} Keybase         https://keybase.io/{data.get('username','')}[/green]")
    for label, key in [("Full Name","full_name"),("Bio","bio"),("Location","location")]:
        _kv(label, data.get(key, ""), "yellow" if key == "full_name" else "white")
    linked = [f"{s}:{data[s]}" for s in ["twitter","github","reddit","hackernews"] if data.get(s)]
    if linked:
        _kv("Profile links", ", ".join(linked))
    if data.get("proofs"):
        _kv("Proofs", ", ".join(f"{p['service']}:{p['name']}" for p in data["proofs"][:10]))

# ── Twitter / Telegram / Steam ───────────────────────────────────────────────

def render_v4_twitter(data: dict | None, username: str):
    if not data:
        console.print(f"  [dim]  Twitter/X       not found or private[/dim]"); return
    if data.get("confirmed"):
        console.print(f"  [green]{CHECK} Twitter/X       https://twitter.com/{username}[/green]")
        if data.get("author_name"):
            _kv("Display Name", data["author_name"], "yellow")
    else:
        console.print(f"  [dim]  Twitter/X       not found[/dim]")

def render_v4_telegram(data: dict):
    if data.get("exists"):
        disp = f" ({data.get('display_name','')})" if data.get("display_name") else ""
        console.print(f"  [green]{CHECK} Telegram        {data['url']}{disp}[/green]")
    else:
        console.print(f"  [dim]  Telegram        handle not active[/dim]")

def render_v4_steam(data: dict | None):
    if not data:
        console.print(f"  [dim]  Steam           not found[/dim]"); return
    console.print(f"  [green]{CHECK} Steam           {data.get('url','')}[/green]")
    _kv("Display Name", data.get("display",""), "yellow")
    for label, key in [("SteamID64","steam_id"),("Member Since","joined"),
                       ("Location","location"),("Online State","state")]:
        _kv(label, data.get(key,""))
    if data.get("summary"):
        _kv("Summary", data["summary"])

# ── Dehashed ─────────────────────────────────────────────────────────────────

def v5_render_dehashed(data: dict | None):
    if not data:
        console.print(f"  [dim]  Dehashed        no response[/dim]"); return
    total = data.get("total", 0)
    src   = data.get("src", "")
    if total > 0:
        console.print(f"  [red]{CROSS} Dehashed        ~{total:,} hit(s)  [dim]({src})[/dim][/red]")
        console.print(f"    [dim]Search dehashed.com to view credentials[/dim]")
    elif total == 0:
        console.print(f"  [green]{CHECK} Dehashed        no hits[/green]")
    else:
        console.print(f"  [yellow]{WARN} Dehashed        entries detected (scraped)[/yellow]")

# ── Leak-Lookup ──────────────────────────────────────────────────────────────

def v5_render_leak_lookup(data: dict | None):
    if not data:
        console.print(f"  [dim]  Leak-Lookup     no response[/dim]"); return
    if data.get("_throttled"):
        console.print(f"  [yellow]{WARN} Leak-Lookup     throttled (public key limit)[/yellow]"); return
    if not data.get("found"):
        console.print(f"  [green]{CHECK} Leak-Lookup     not found[/green]"); return
    total   = data.get("total", 0)
    sources = data.get("sources", [])
    console.print(f"  [red]{CROSS} Leak-Lookup     {total} record(s) in {len(sources)} breach(es)[/red]")
    for src in sources[:12]:
        console.print(f"    [dim]{BULLET}[/dim] {src}")
    if len(sources) > 12:
        console.print(f"    [dim]{ELLIP} and {len(sources)-12} more[/dim]")

# ── PSBDMP ───────────────────────────────────────────────────────────────────

def v5_render_psbdmp(data: dict | None):
    if not data:
        console.print(f"  [dim]  PSBDMP          no response[/dim]"); return
    count = data.get("count", 0)
    if not count:
        console.print(f"  [green]{CHECK} PSBDMP          no Pastebin dumps[/green]"); return
    console.print(f"  [red]{CROSS} PSBDMP          {count} Pastebin dump(s)[/red]")
    for p in data.get("pastes", [])[:8]:
        console.print(f"    [dim]{BULLET}[/dim] {p['url']}  [dim]({p['time']})[/dim]")

# ── ProxyCheck ───────────────────────────────────────────────────────────────

def v5_render_proxycheck(data: dict | None, ip: str):
    if not data:
        console.print(f"  [dim]  ProxyCheck      no response[/dim]"); return
    proxy = data.get("proxy", "no")
    risk  = data.get("risk", 0)
    if proxy == "yes":
        console.print(f"  [red]{CROSS} ProxyCheck      {ip}  VPN/Proxy/Tor  "
                      f"type={data.get('type','?')}  risk={risk}%[/red]")
    else:
        console.print(f"  [green]{CHECK} ProxyCheck      {ip}  residential  risk={risk}%[/green]")

# ── Dark-web links ────────────────────────────────────────────────────────────

def v5_render_darkweb_links(links: list):
    if not links:
        return
    console.print(f"\n  [dim]Dark web / breach aggregator investigation links:[/dim]")
    for name, url in links:
        console.print(f"    [dim]{BULLET}[/dim] [bold]{name:<28}[/bold] [dim]{url}[/dim]")

# ── LeakCheck v2 ─────────────────────────────────────────────────────────────

def v6_render_leakcheck(data: dict | None):
    if not data:
        console.print(f"  [dim]  LeakCheck v2    no response[/dim]"); return
    if data.get("_no_key"):
        console.print(f"  [dim]  LeakCheck v2    skipped — pass --leakcheck-key (free 5/day)[/dim]"); return
    if data.get("_bad_key"):
        console.print(f"  [yellow]{WARN} LeakCheck v2    invalid key[/yellow]"); return
    if data.get("_rate_limited"):
        console.print(f"  [yellow]{WARN} LeakCheck v2    daily quota reached (5/day free)[/yellow]"); return
    if not data.get("found"):
        console.print(f"  [green]{CHECK} LeakCheck v2    not found[/green]"); return
    count   = data.get("count", 0)
    sources = data.get("sources", [])
    quota   = data.get("quota", "?")
    console.print(f"  [red]{CROSS} LeakCheck v2    {count} record(s) in {len(sources)} source(s)  "
                  f"[dim]quota left: {quota}[/dim][/red]")
    t = Table(box=box.SIMPLE_HEAD, show_header=True, header_style="bold red", padding=(0, 1))
    t.add_column("Source",     min_width=28)
    t.add_column("Date",       width=11, style="dim")
    t.add_column("Fields",     min_width=20)
    for src in sources[:20]:
        if isinstance(src, dict):
            name   = src.get("name", "?")
            date   = (src.get("breach_date") or src.get("date") or "")[:10]
            fields = ", ".join(src.get("fields", [])[:5])
        else:
            name, date, fields = str(src), "", ""
        t.add_row(name, date, fields)
    console.print(t)

# ── Phonebook.cz ─────────────────────────────────────────────────────────────

def v6_render_phonebook(data: dict | None, query: str):
    if not data:
        console.print(f"  [dim]  Phonebook.cz    no response[/dim]"); return
    count = data.get("count", 0)
    if not count:
        console.print(f"  [green]{CHECK} Phonebook.cz    no indexed records[/green]"); return
    console.print(f"  [yellow]{FLAG} Phonebook.cz    {count} item(s)[/yellow]")
    for val in data.get("results", [])[:20]:
        console.print(f"    [dim]{BULLET}[/dim] {val}")
    if count > 20:
        console.print(f"    [dim]{ELLIP} and {count-20} more[/dim]")

# ── Google account probe ──────────────────────────────────────────────────────

def v6_render_google_probe(data: dict):
    if data.get("google_account"):
        console.print(f"  [yellow]{FLAG} Google account   likely exists  "
                      f"[dim]method={data.get('method','')}[/dim][/yellow]")
        if data.get("profile_pic"):
            console.print(f"    [dim]Photo: {data['profile_pic'][:80]}[/dim]")
    else:
        console.print(f"  [dim]  Google account   not detected[/dim]")

# ── Holehe site registration ──────────────────────────────────────────────────

def v6_render_holehe(results: list):
    if not results:
        console.print(f"  [dim]  Site probe       no results[/dim]"); return
    registered = [r for r in results if r["registered"]]
    not_found  = [r for r in results if not r["registered"] and r["confidence"] == "medium"]
    ambiguous  = [r for r in results if r["confidence"] == "low"]
    if registered:
        console.print(f"  [yellow]{FLAG} Site probe       registered on {len(registered)} platform(s):[/yellow]")
        for r in registered:
            console.print(f"    [green]{BULLET}[/green] [bold]{r['site']}[/bold]")
    else:
        console.print(f"  [dim]  Site probe       no confirmed registrations[/dim]")
    if not_found:
        console.print(f"  [dim]  Not found: {', '.join(r['site'] for r in not_found)}[/dim]")
    if ambiguous:
        console.print(f"  [dim]  Ambiguous: {', '.join(r['site'] for r in ambiguous)}[/dim]")

# ── OSINTLeak & Password Audit ───────────────────────────────────────────────

def render_osint_leak(data: dict):
    if not data:
        console.print(f"  [dim]  OSINTLeak       no response[/dim]"); return
    if data.get("error") == "no_key":
        console.print(f"  [dim]  OSINTLeak       skipped — pass --osintleak-key[/dim]"); return
    if data.get("error"):
        console.print(f"  [yellow]{WARN} OSINTLeak       error: {data['error']}[/yellow]"); return
    
    count = data.get("count", 0)
    origins = data.get("origins", [])
    if count > 0:
        console.print(f"  [red]{CROSS} OSINTLeak       {count} finding(s) in {len(origins)} leak origin(s)[/red]")
        for orig in origins[:10]:
            console.print(f"    [dim]{BULLET}[/dim] {orig}")
        if len(origins) > 10:
            console.print(f"    [dim]{ELLIP} and {len(origins)-10} more[/dim]")
    else:
        console.print(f"  [green]{CHECK} OSINTLeak       no logs or leak records detected[/green]")

def render_password_audit(data: dict):
    if not data:
        console.print(f"  [dim]  Password Audit  no response[/dim]"); return
    if data.get("found"):
        console.print(f"  [bold red]{CROSS} Password Audit  EXPOSED {data['count']:,} times in HaveIBeenPwned![/bold red]")
    else:
        console.print(f"  [bold green]{CHECK} Password Audit  Secure! Not found in HaveIBeenPwned range database.[/bold green]")

# ── Scan Summary ─────────────────────────────────────────────────────────────

def render_ext_summary(report: dict, args):
    console.print()
    console.print(Rule("[bold green] SCAN SUMMARY [/bold green]", style="green"))
    f = report.get("findings", {})

    target_email = getattr(args, "email", None)
    target_username = getattr(args, "username", None)
    target_domain = getattr(args, "domain", None)
    target_password = getattr(args, "password", None)

    if target_email:
        ni = f.get("name_inference", {})
        if ni.get("first"):
            _kv("Inferred name",
                f"{ni['first']} {ni.get('last','')}  [{ni.get('gender','')}]", "yellow")

        er = f.get("emailrep", {})
        if er:
            rep  = er.get("reputation", "unknown")
            susp = er.get("suspicious", False)
            col  = "red" if susp else ("yellow" if rep in ("low","none") else "green")
            _kv("EmailRep", f"{rep}{f'  {FLAG} SUSPICIOUS' if susp else ''}", col)

        if f.get("gravatar", {}).get("registered"):
            grav = f["gravatar"]
            rn = f"  ({grav['real_name']})" if grav.get("real_name") else ""
            _kv("Gravatar", f"registered{rn}", "yellow")

        posture = f.get("posture", {})
        if posture and not posture.get("_consumer") and "spf" in posture:
            score = sum([posture["spf"]["present"], posture["dmarc"]["present"],
                         bool(posture["dkim"].get("selectors"))])
            col = "green" if score == 3 else ("yellow" if score >= 1 else "red")
            _kv("Email security", f"{score}/3 (SPF/DMARC/DKIM)", col)
        elif posture and posture.get("_consumer"):
            _kv("Email security", "n/a (consumer provider)")

        hibp = f.get("hibp", {})
        bc   = len(hibp.get("breaches", []))
        pc   = len(hibp.get("pastes",   []))
        if bc or pc:
            _kv("HIBP", f"{bc} breach(es)" + (f"  {pc} paste(s)" if pc else ""), "red")

        lc = f.get("leakcheck", {})
        if lc and lc.get("found"):
            _kv("LeakCheck v2", f"{lc.get('count',0)} record(s)  {len(lc.get('sources',[]))} source(s)", "red")

        ol = f.get("osintleak", {})
        if ol and ol.get("found"):
            _kv("OSINTLeak", f"{ol.get('count',0)} finding(s) across {len(ol.get('origins',[]))} leak(s)", "red")

        hol = [r for r in f.get("holehe",[]) if r.get("registered")]
        if hol:
            _kv("Site probe", ", ".join(r["site"] for r in hol), "yellow")

        gp = f.get("google_probe", {})
        if gp and gp.get("google_account"):
            _kv("Google account", "detected", "yellow")

    if target_username:
        social = f.get("social", {})
        sc     = len(social.get("found", []))
        _kv("Social accounts", f"{sc} found", "yellow" if sc else "green")
        ce = f.get("commit_emails", [])
        if ce:
            _kv("Commit emails", ", ".join(ce), "yellow")

    if target_domain or (target_email and not getattr(args, "no_dns", False)):
        dom_f = f.get("domain", {})
        if dom_f:
            subs  = dom_f.get("subdomains", [])
            if subs:
                _kv("Subdomains", str(len(subs)), "yellow")
            shod_vulns = dom_f.get("shodan", {})
            vulns = len(shod_vulns.get("vulns", [])) if isinstance(shod_vulns, dict) else 0
            if vulns:
                _kv("CVEs (Shodan)", str(vulns), "red")
            wb = dom_f.get("wayback")
            if wb:
                def _fmt(ts): return f"{ts[:4]}-{ts[4:6]}-{ts[6:8]}" if len(ts) >= 8 else ts
                _kv("First seen", _fmt(wb["first"]))
            bl = dom_f.get("blacklist", {})
            if bl and bl.get("blacklisted"):
                _kv("Blacklisted", ", ".join(bl["blacklisted"]), "red")

    if target_password:
        pw = f.get("password_audit", {})
        if pw:
            if pw.get("found"):
                _kv("Password Audit", f"EXPOSED {pw.get('count',0):,} times!", "red")
            else:
                _kv("Password Audit", "Secure (not found)", "green")

    console.print()

