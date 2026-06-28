#!/usr/bin/env python3
"""
VENOM — OSINT Synthesis & Correlation Framework v7.0
Main Entrypoint &Click CLI orchestrator.
Fully asynchronous execution engine running over aiohttp with WAF evasion.
"""

import sys
import asyncio
from datetime import datetime
import json
import re
import random
from typing import Dict, Any, Optional
import aiohttp
import click

from modules.config import print_banner, console, SOCIAL_PLATFORMS
from modules.render import (
    section,
    render_hibp,
    render_breach_directory,
    render_dns_whois,
    render_github_user,
    render_github_commits,
    render_v4_github_orgs,
    render_dorks,
    render_v4_extra_dorks,
    render_username_results,
    render_ext_gravatar,
    v5_render_emailrep,
    render_ext_crtsh_email,
    render_ext_crtsh_domain,
    render_ext_shodan,
    render_ext_wayback,
    render_ext_ssl,
    render_ext_blacklist,
    render_ext_gitlab,
    render_ext_npm,
    render_ext_pypi,
    render_ext_commit_emails,
    render_ext_hunter,
    v5_render_posture,
    v5_render_txt,
    v5_render_intelx,
    render_ext_permutations,
    render_ext_name,
    render_v4_urlscan,
    render_v4_otx_domain,
    render_v4_otx_ip,
    render_v4_otx_email,
    render_v4_hackertarget_dns,
    render_v4_hackertarget_reverse,
    v5_render_pulsedive,
    render_v4_keybase,
    render_v4_twitter,
    render_v4_telegram,
    render_v4_steam,
    v5_render_dehashed,
    v5_render_leak_lookup,
    v5_render_psbdmp,
    v5_render_proxycheck,
    v5_render_darkweb_links,
    v6_render_leakcheck,
    v6_render_phonebook,
    v6_render_google_probe,
    v6_render_holehe,
    render_osint_leak,
    render_password_audit,
    render_ext_summary
)

from modules.email import (
    check_format as check_email_format,
    infer_name as ext_infer_name,
    username_permutations as ext_username_permutations,
    GravatarModule,
    EmailRepModule,
    CrtshEmailModule,
    EmailSecurityPostureModule,
    EmailTxtClassifyModule,
    RdapAdminEmailModule,
    GoogleProbeModule,
    HoleheModule
)

from modules.username import (
    SocialEnumerationModule,
    GitHubUserModule,
    GitHubEmailCommitsModule,
    GitHubCommitEmailsModule,
    GitHubOrgsModule,
    GitLabUserModule,
    NPMUserModule,
    PyPIUserModule,
    KeybaseModule,
    TwitterOembedModule,
    TelegramResolveModule,
    SteamProfileModule
)

from modules.domain import (
    DNSModule,
    WHOISModule,
    IPResolutionModule,
    ShodanInternetDBModule,
    WaybackModule,
    SSLCertModule,
    CrtshDomainModule,
    MXBlacklistModule,
    IPGeoModule,
    BGPViewModule,
    HunterDomainModule,
    URLScanModule,
    OTXDomainModule,
    OTXIPModule,
    HackerTargetPassiveDNSModule,
    HackerTargetReverseIPModule,
    PulsediveModule,
    ProxyCheckModule
)

from modules.phone import (
    check_phone,
    PhoneCarrierModule
)

from modules.breach import (
    HIBPBreachesModule,
    HIBPPastesModule,
    PasswordKAnonymityModule,
    BreachDirectoryModule,
    LeakCheckModule,
    LeakLookupModule,
    PSBDMPModule,
    DehashedModule,
    IntelXModule,
    OTXEmailModule,
    PhonebookModule,
    OSINTLeakModule
)

from modules.search import DuckDuckGoModule
from modules.dorks import (
    generate_dorks,
    extra_dorks as v4_extra_dorks,
    darkweb_links as v5_darkweb_links
)

from modules.export import export_html, export_json, export_csv

# ── Shared Options Decorator ──────────────────────────────────────────────────

def common_options(f):
    options = [
        click.option("--hibp-key", help="HaveIBeenPwned API key"),
        click.option("--bd-key", help="BreachDirectory RapidAPI key"),
        click.option("--hunter-key", help="Hunter.io key"),
        click.option("--emailrep-key", help="EmailRep.io key"),
        click.option("--intelx-key", help="IntelX key"),
        click.option("--leak-lookup-key", help="Leak-Lookup private key"),
        click.option("--leakcheck-key", help="LeakCheck v2 API key"),
        click.option("--osintleak-key", help="OSINTLeak API key"),
        click.option("--proxy", help="Single proxy URL (e.g. http://127.0.0.1:8080)"),
        click.option("--proxy-list", type=click.Path(exists=True), help="Path to file containing proxies (rotated)"),
        click.option("--no-social", is_flag=True, help="Skip social media account sweeps"),
        click.option("--no-github", is_flag=True, help="Skip GitHub analysis"),
        click.option("--no-dns", is_flag=True, help="Skip DNS/WHOIS records lookup"),
        click.option("--no-dorks", is_flag=True, help="Skip dorks generation"),
        click.option("--no-leakcheck", is_flag=True, help="Skip LeakCheck audits"),
        click.option("--no-intelx", is_flag=True, help="Skip IntelligenceX searches"),
        click.option("--no-wayback", is_flag=True, help="Skip Wayback archive counts"),
        click.option("--no-ssl", is_flag=True, help="Skip SSL certificate queries"),
        click.option("--no-permute", is_flag=True, help="Skip username permutations"),
        click.option("--no-urlscan", is_flag=True, help="Skip URLScan.io scans"),
        click.option("--no-otx", is_flag=True, help="Skip AlienVault OTX pulses"),
        click.option("--no-pulsedive", is_flag=True, help="Skip Pulsedive feeds"),
        click.option("--no-keybase", is_flag=True, help="Skip Keybase checks"),
        click.option("--no-steam", is_flag=True, help="Skip Steam profiles lookup"),
        click.option("--no-darkweb", is_flag=True, help="Skip dark-web manual links"),
        click.option("--no-holehe", is_flag=True, help="Skip Holehe email probe"),
        click.option("--no-phonebook", is_flag=True, help="Skip Phonebook.cz scans"),
        click.option("--no-google", is_flag=True, help="Skip Google account probe"),
        click.option("-o", "--output", type=click.Path(), help="Output to JSON file"),
        click.option("--html", type=click.Path(), help="Output to dark HTML report"),
        click.option("--csv", type=click.Path(), help="Output to CSV sheet")
    ]
    for option in reversed(options):
        f = option(f)
    return f

# ── CLI & Group Definitions ──────────────────────────────────────────────────

@click.group()
def cli():
    """VENOM — OSINT Synthesis & Correlation Framework"""
    pass

@cli.group()
def scan():
    """Perform OSINT scanning across various targets"""
    pass

# ── Unified Scanning Core ─────────────────────────────────────────────────────

async def run_scan_engine(targets: Dict[str, str], opts: Dict[str, Any]) -> None:
    """
    Asynchronous scanning orchestrator.
    Manages connections, triggers parallel scans, and exports multi-format reports.
    """
    print_banner()
    report = {
        "timestamp": datetime.now().isoformat(),
        "targets": targets,
        "findings": {}
    }

    # Proxy selection
    proxy = opts.get("proxy")
    if opts.get("proxy_list"):
        try:
            with open(opts["proxy_list"], "r", encoding="utf-8") as fh:
                proxies = [line.strip() for line in fh if line.strip()]
            if proxies:
                proxy = random.choice(proxies)
        except Exception as e:
            console.print(f"  [yellow]⚠ Failed to load proxy list: {e}[/yellow]")

    # Run tasks concurrently in event loop
    async with aiohttp.ClientSession() as session:
        tasks = {}

        # ── Trigger Email Tasks ───────────────────────────────────────────────
        if "email" in targets:
            email = targets["email"]
            fmt = check_email_format(email)
            domain = fmt.get("domain", "")

            section("EMAIL INTELLIGENCE")
            console.print(f"  [dim]{'Address':<24}[/dim] {email}")
            console.print(f"  [dim]{'Domain':<24}[/dim] {domain}")
            if fmt.get("disposable"):
                console.print("  [red]  ⚑ Disposable / temporary email domain[/red]")

            # DNS / WHOIS
            if not opts.get("no_dns") and domain:
                tasks["dns"] = DNSModule(domain, proxy=proxy).run(session)
                tasks["whois"] = WHOISModule(domain, proxy=proxy).run(session)
                tasks["ip"] = IPResolutionModule(domain, proxy=proxy).run(session)

            # Posture and TXT
            if domain:
                tasks["posture"] = EmailSecurityPostureModule(email, proxy=proxy).run(session)
                tasks["txt_records"] = EmailTxtClassifyModule(email, proxy=proxy).run(session)
                tasks["rdap_admin_email"] = RdapAdminEmailModule(email, proxy=proxy).run(session)

            tasks["gravatar"] = GravatarModule(email, proxy=proxy).run(session)

            if not opts.get("no_google"):
                tasks["google_probe"] = GoogleProbeModule(email, proxy=proxy).run(session)

            tasks["emailrep"] = EmailRepModule(email, api_key=opts.get("emailrep_key"), proxy=proxy).run(session)

            if not opts.get("no_holehe"):
                tasks["holehe"] = HoleheModule(email, proxy=proxy).run(session)

            tasks["crtsh_email"] = CrtshEmailModule(email, proxy=proxy).run(session)

            if not opts.get("no_otx"):
                tasks["otx_email"] = OTXEmailModule(email, proxy=proxy).run(session)

            tasks["dehashed"] = DehashedModule(email, proxy=proxy).run(session)

            if not opts.get("no_pulsedive"):
                tasks["pulsedive_email"] = PulsediveModule(email, proxy=proxy).run(session)

            if opts.get("hibp_key"):
                tasks["hibp_breaches"] = HIBPBreachesModule(email, api_key=opts["hibp_key"], proxy=proxy).run(session)
                tasks["hibp_pastes"] = HIBPPastesModule(email, api_key=opts["hibp_key"], proxy=proxy).run(session)

            tasks["breach_directory"] = BreachDirectoryModule(email, api_key=opts.get("bd_key"), proxy=proxy).run(session)

            if not opts.get("no_leakcheck"):
                tasks["leakcheck"] = LeakCheckModule(email, api_key=opts.get("leakcheck_key"), proxy=proxy).run(session)

            tasks["leak_lookup"] = LeakLookupModule(email, api_key=opts.get("leak_lookup_key"), proxy=proxy).run(session)
            tasks["psbdmp"] = PSBDMPModule(email, proxy=proxy).run(session)

            if not opts.get("no_phonebook"):
                tasks["phonebook"] = PhonebookModule(email, proxy=proxy).run(session)

            if not opts.get("no_intelx"):
                tasks["intelx_email"] = IntelXModule(email, api_key=opts.get("intelx_key"), proxy=proxy).run(session)

            if opts.get("osintleak_key"):
                tasks["osintleak"] = OSINTLeakModule(email, api_key=opts["osintleak_key"], proxy=proxy).run(session)

            if not opts.get("no_github"):
                tasks["github_commits"] = GitHubEmailCommitsModule(email, proxy=proxy).run(session)

        # ── Trigger Username Tasks ────────────────────────────────────────────
        if "username" in targets:
            username = targets["username"]
            section("USERNAME ENUMERATION")

            if not opts.get("no_social"):
                tasks["social"] = SocialEnumerationModule(username, proxy=proxy).run(session)

            if not opts.get("no_github"):
                tasks["github_user"] = GitHubUserModule(username, proxy=proxy).run(session)
                tasks["github_orgs"] = GitHubOrgsModule(username, proxy=proxy).run(session)

            tasks["gitlab"] = GitLabUserModule(username, proxy=proxy).run(session)
            tasks["npm"] = NPMUserModule(username, proxy=proxy).run(session)
            tasks["pypi"] = PyPIUserModule(username, proxy=proxy).run(session)

            if not opts.get("no_keybase"):
                tasks["keybase"] = KeybaseModule(username, proxy=proxy).run(session)

            tasks["twitter"] = TwitterOembedModule(username, proxy=proxy).run(session)
            tasks["telegram"] = TelegramResolveModule(username, proxy=proxy).run(session)

            if not opts.get("no_steam"):
                tasks["steam"] = SteamProfileModule(username, proxy=proxy).run(session)

            if not opts.get("no_leakcheck"):
                tasks["leakcheck_u"] = LeakCheckModule(username, query_type="username", api_key=opts.get("leakcheck_key"), proxy=proxy).run(session)

            tasks["leak_lookup_u"] = LeakLookupModule(username, query_type="username", api_key=opts.get("leak_lookup_key"), proxy=proxy).run(session)
            tasks["psbdmp_u"] = PSBDMPModule(username, proxy=proxy).run(session)

            if not opts.get("no_phonebook"):
                tasks["phonebook_u"] = PhonebookModule(username, proxy=proxy).run(session)

            if not opts.get("no_intelx"):
                tasks["intelx_u"] = IntelXModule(username, api_key=opts.get("intelx_key"), proxy=proxy).run(session)

            if opts.get("osintleak_key"):
                tasks["osintleak_u"] = OSINTLeakModule(username, api_key=opts["osintleak_key"], proxy=proxy).run(session)

        # ── Trigger Phone Tasks ───────────────────────────────────────────────
        if "phone" in targets:
            phone = targets["phone"]
            section("PHONE INTELLIGENCE")
            ph = check_phone(phone)
            
            if ph["valid"]:
                console.print(f"  [dim]{'Country':<22}[/dim] {ph['info'].get('country','')}")
                console.print(f"  [dim]{'Prefix':<22}[/dim] {ph['info'].get('prefix','')}")
                tasks["phone_carrier"] = PhoneCarrierModule(ph["cleaned"], proxy=proxy).run(session)
            else:
                console.print("  [yellow]  ⚠ Invalid phone format. Use E.164 (e.g. +1234567890)[/yellow]")

            if not opts.get("no_leakcheck") and ph["valid"]:
                tasks["leakcheck_p"] = LeakCheckModule(ph["cleaned"], query_type="phone", api_key=opts.get("leakcheck_key"), proxy=proxy).run(session)

            if ph["valid"]:
                tasks["leak_lookup_p"] = LeakLookupModule(ph["cleaned"], query_type="phone", api_key=opts.get("leak_lookup_key"), proxy=proxy).run(session)
                if not opts.get("no_intelx"):
                    tasks["intelx_p"] = IntelXModule(ph["cleaned"], api_key=opts.get("intelx_key"), proxy=proxy).run(session)
                if opts.get("osintleak_key"):
                    tasks["osintleak_p"] = OSINTLeakModule(ph["cleaned"], api_key=opts["osintleak_key"], proxy=proxy).run(session)

        # ── Trigger Domain Tasks ───────────────────────────────────────────────
        if "domain" in targets:
            domain = re.sub(r"^https?://", "", targets["domain"].strip().lower()).rstrip("/")
            section("DOMAIN / IP INTELLIGENCE")
            console.print(f"  [dim]{'Target':<22}[/dim] {domain}\n")

            tasks["dns"] = DNSModule(domain, proxy=proxy).run(session)
            tasks["whois"] = WHOISModule(domain, proxy=proxy).run(session)
            tasks["ip"] = IPResolutionModule(domain, proxy=proxy).run(session)
            tasks["posture"] = EmailSecurityPostureModule(domain, proxy=proxy).run(session)
            tasks["txt_records"] = EmailTxtClassifyModule(domain, proxy=proxy).run(session)

            if not opts.get("no_urlscan"):
                tasks["urlscan"] = URLScanModule(domain, proxy=proxy).run(session)

            if not opts.get("no_otx"):
                tasks["otx_domain"] = OTXDomainModule(domain, proxy=proxy).run(session)

            tasks["ht_dns"] = HackerTargetPassiveDNSModule(domain, proxy=proxy).run(session)

            if not opts.get("no_pulsedive"):
                tasks["pulsedive"] = PulsediveModule(domain, proxy=proxy).run(session)

            if not opts.get("no_wayback"):
                tasks["wayback"] = WaybackModule(domain, proxy=proxy).run(session)

            if not opts.get("no_ssl"):
                tasks["ssl"] = SSLCertModule(domain, proxy=proxy).run(session)

            tasks["crt_subs"] = CrtshDomainModule(domain, proxy=proxy).run(session)
            tasks["blacklist"] = MXBlacklistModule(domain, proxy=proxy).run(session)
            tasks["hunter"] = HunterDomainModule(domain, api_key=opts.get("hunter_key"), proxy=proxy).run(session)

            if not opts.get("no_phonebook"):
                tasks["phonebook_d"] = PhonebookModule(domain, query_type=2, proxy=proxy).run(session)

            if not opts.get("no_intelx"):
                tasks["intelx_d"] = IntelXModule(domain, api_key=opts.get("intelx_key"), proxy=proxy).run(session)

        # ── Trigger Password Tasks ────────────────────────────────────────────
        if "password" in targets:
            section("PASSWORD BREACH CHECK")
            tasks["password_audit"] = PasswordKAnonymityModule(targets["password"], proxy=proxy).run(session)

        # ── Trigger AI Agent Web Search ──────────────────────────────────────
        for t_type, t_val in targets.items():
            if t_type in ("email", "username", "domain"):
                tasks[f"web_search_{t_type}"] = DuckDuckGoModule(t_val, proxy=proxy).run(session)

        # ── Run the Harvest concurrently ──────────────────────────────────────
        if tasks:
            with console.status("[bold green]Harvesting target intelligence...[/bold green]", spinner="dots"):
                results = await asyncio.gather(*tasks.values())
            raw_findings = dict(zip(tasks.keys(), results))
        else:
            raw_findings = {}

        # ── Process Findings ──────────────────────────────────────────────────
        if "hibp_breaches" in raw_findings or "hibp_pastes" in raw_findings:
            b_data = raw_findings.pop("hibp_breaches", None)
            p_data = raw_findings.pop("hibp_pastes", None)
            report["findings"]["hibp"] = {
                "breaches": b_data.get("breaches", []) if b_data else [],
                "pastes": p_data.get("pastes", []) if p_data else []
            }

        # Subdomain mapping helper
        if "crt_subs" in raw_findings or "dns" in raw_findings or "whois" in raw_findings or "ip" in raw_findings:
            # Group domain specific findings into domain sub-dictionary for render compatibility
            dom_report = {}
            if "dns" in raw_findings: dom_report["dns"] = raw_findings.pop("dns")
            if "whois" in raw_findings: dom_report["whois"] = raw_findings.pop("whois")
            if "ip" in raw_findings:
                ip_res = raw_findings.pop("ip")
                dom_report["ip"] = ip_res
                # Trigger IP metadata if IP resolved
                raw_ip = ip_res.get("ip")
                if raw_ip:
                    shodan_task = ShodanInternetDBModule(raw_ip, proxy=proxy).run(session)
                    geo_task = IPGeoModule(raw_ip, proxy=proxy).run(session)
                    bgp_task = BGPViewModule(raw_ip, proxy=proxy).run(session)
                    proxy_task = ProxyCheckModule(raw_ip, proxy=proxy).run(session)
                    otx_ip_task = OTXIPModule(raw_ip, proxy=proxy).run(session)
                    ht_rev_task = HackerTargetReverseIPModule(raw_ip, proxy=proxy).run(session)
                    
                    with console.status("[bold green]Analyzing hosting IP signatures...[/bold green]", spinner="dots"):
                        ip_details = await asyncio.gather(shodan_task, geo_task, bgp_task, proxy_task, otx_ip_task, ht_rev_task)
                    
                    dom_report["shodan"] = ip_details[0]
                    dom_report["geo"] = ip_details[1]
                    dom_report["bgp"] = ip_details[2]
                    dom_report["proxy_check"] = ip_details[3]
                    dom_report["otx_ip"] = ip_details[4]
                    dom_report["ht_rev"] = ip_details[5]

            if "crt_subs" in raw_findings: dom_report["subdomains"] = raw_findings.pop("crt_subs").get("subdomains", [])
            if "blacklist" in raw_findings: dom_report["blacklist"] = raw_findings.pop("blacklist")
            if "wayback" in raw_findings: dom_report["wayback"] = raw_findings.pop("wayback")
            report["findings"]["domain"] = dom_report

        # Assign remaining findings to report
        for k, v in raw_findings.items():
            report["findings"][k] = v

        # Local Name Inference
        if "email" in targets:
            name_info = ext_infer_name(fmt.get("local", email.split("@")[0]))
            report["findings"]["name_inference"] = name_info

        # Username Permutations sweep
        if "email" in targets and not opts.get("no_permute"):
            perms = ext_username_permutations(email)
            console.print(f"\n  [dim]Sweeping {len(perms)} username variants across {len(SOCIAL_PLATFORMS)} platforms...[/dim]")
            perm_map = {}
            
            async def check_perm(uname: str):
                mod = SocialEnumerationModule(uname, proxy=proxy)
                r = await mod.run(session)
                found = r.get("found", [])
                if found:
                    perm_map[uname] = found
            
            with console.status("[bold yellow]Scanning username variants...[/bold yellow]", spinner="dots"):
                await asyncio.gather(*[check_perm(u) for u in perms])
            report["findings"]["permutations"] = {"variants": perms, "hits": perm_map}

        # Dorks & Darkweb links mapping
        for t_type, t_val in targets.items():
            if t_type in ("email", "username", "domain"):
                if not opts.get("no_dorks"):
                    kw = {t_type: t_val}
                    if t_type == "email" and domain:
                        kw["domain"] = domain
                    report["findings"]["dorks"] = generate_dorks(**kw) + v4_extra_dorks(**kw)
                if not opts.get("no_darkweb"):
                    report["findings"]["darkweb_links"] = [{"label": l, "url": u} for l, u in v5_darkweb_links(**{t_type: t_val})]

        # ── Render Outputs (flawless terminal display) ────────────────────────
        # 1. Domain details
        d_finds = report["findings"].get("domain", {})
        if d_finds and "dns" in d_finds:
            render_dns_whois(targets.get("domain", domain), d_finds["dns"], d_finds.get("whois"), d_finds.get("ip"))
            if d_finds.get("shodan"):
                console.print("\n  [bold]Shodan / IP intel:[/bold]")
                render_ext_shodan(d_finds["shodan"], d_finds.get("ip",{}).get("ip",""), d_finds.get("geo"), d_finds.get("bgp"))
                v5_render_proxycheck(d_finds.get("proxy_check"), d_finds.get("ip",{}).get("ip",""))
                if not opts.get("no_otx"):
                    render_v4_otx_ip(d_finds.get("otx_ip"), d_finds.get("ip",{}).get("ip",""))
                render_v4_hackertarget_reverse(d_finds.get("ht_rev", {}).get("results", []), d_finds.get("ip",{}).get("ip",""))

        # 2. Email details
        if "email" in targets:
            render_ext_name(report["findings"].get("name_inference", {}))
            if "posture" in report["findings"]:
                console.print()
                v5_render_posture(domain, report["findings"]["posture"])
                console.print()
                v5_render_txt(report["findings"].get("txt_records", {}).get("records", []), domain)
                if report["findings"].get("rdap_admin_email", {}).get("email"):
                    console.print(f"  [yellow]⚑ RDAP admin email: {report['findings']['rdap_admin_email']['email']}[/yellow]")
            if "gravatar" in report["findings"]:
                console.print()
                render_ext_gravatar(report["findings"]["gravatar"])
            if "google_probe" in report["findings"]:
                console.print()
                v6_render_google_probe(report["findings"]["google_probe"])
            if "emailrep" in report["findings"]:
                console.print()
                v5_render_emailrep(report["findings"]["emailrep"])
            if "holehe" in report["findings"]:
                console.print()
                v6_render_holehe(report["findings"]["holehe"].get("results", []))
            if "crtsh_email" in report["findings"]:
                console.print()
                render_ext_crtsh_email(report["findings"]["crtsh_email"].get("domains", []))
            if "otx_email" in report["findings"]:
                console.print()
                render_v4_otx_email(report["findings"]["otx_email"])
            if "dehashed" in report["findings"]:
                console.print()
                v5_render_dehashed(report["findings"]["dehashed"])
            if "pulsedive_email" in report["findings"]:
                console.print()
                v5_render_pulsedive(report["findings"]["pulsedive_email"], email)
            if "hibp" in report["findings"]:
                console.print()
                render_hibp(report["findings"]["hibp"].get("breaches", []), report["findings"]["hibp"].get("pastes", []))
            if "breach_directory" in report["findings"]:
                console.print()
                render_breach_directory(report["findings"]["breach_directory"])
            if "leakcheck" in report["findings"]:
                console.print()
                v6_render_leakcheck(report["findings"]["leakcheck"])
            if "leak_lookup" in report["findings"]:
                console.print()
                v5_render_leak_lookup(report["findings"]["leak_lookup"])
            if "psbdmp" in report["findings"]:
                console.print()
                v5_render_psbdmp(report["findings"]["psbdmp"])
            if "phonebook" in report["findings"]:
                console.print()
                v6_render_phonebook(report["findings"]["phonebook"], email)
            if "intelx_email" in report["findings"]:
                console.print()
                v5_render_intelx(report["findings"]["intelx_email"], email)
            if "osintleak" in report["findings"]:
                console.print()
                render_osint_leak(report["findings"]["osintleak"])
            if "github_commits" in report["findings"]:
                console.print()
                render_github_commits(report["findings"]["github_commits"].get("commits", []))
            if "permutations" in report["findings"]:
                console.print()
                render_ext_permutations(report["findings"]["permutations"]["variants"], report["findings"]["permutations"]["hits"])

        # 3. Username details
        if "username" in targets:
            username = targets["username"]
            if "social" in report["findings"]:
                soc = report["findings"]["social"]
                render_username_results(soc.get("found", []), soc.get("not_found", []), soc.get("errors", []))
            if "github_user" in report["findings"]:
                gh = report["findings"]["github_user"]
                render_github_user(gh)
                if gh.get("found") and gh.get("repos") and not opts.get("no_github"):
                    # Check commit emails
                    ce_mod = GitHubCommitEmailsModule(username, gh["repos"], proxy=proxy)
                    ce_res = await ce_mod.run(session)
                    render_ext_commit_emails(ce_res.get("emails", []))
                    report["findings"]["commit_emails"] = ce_res.get("emails", [])
            if "github_orgs" in report["findings"]:
                render_v4_github_orgs(report["findings"]["github_orgs"].get("organizations", []), username)
            if "gitlab" in report["findings"]:
                console.print()
                render_ext_gitlab(report["findings"]["gitlab"].get("profile") if report["findings"]["gitlab"].get("exists") else None)
            if "npm" in report["findings"]:
                console.print()
                render_ext_npm(report["findings"]["npm"].get("profile") if report["findings"]["npm"].get("exists") else None)
            if "pypi" in report["findings"]:
                console.print()
                render_ext_pypi(report["findings"]["pypi"])
            if "keybase" in report["findings"]:
                console.print()
                render_v4_keybase(report["findings"]["keybase"] if report["findings"]["keybase"].get("exists") else None)
            if "twitter" in report["findings"]:
                console.print()
                render_v4_twitter(report["findings"]["twitter"], username)
            if "telegram" in report["findings"]:
                console.print()
                render_v4_telegram(report["findings"]["telegram"])
            if "steam" in report["findings"]:
                console.print()
                render_v4_steam(report["findings"]["steam"] if report["findings"]["steam"].get("exists") else None)
            if "leakcheck_u" in report["findings"]:
                console.print()
                v6_render_leakcheck(report["findings"]["leakcheck_u"])
            if "leak_lookup_u" in report["findings"]:
                console.print()
                v5_render_leak_lookup(report["findings"]["leak_lookup_u"])
            if "psbdmp_u" in report["findings"]:
                console.print()
                v5_render_psbdmp(report["findings"]["psbdmp_u"])
            if "phonebook_u" in report["findings"]:
                console.print()
                v6_render_phonebook(report["findings"]["phonebook_u"], username)
            if "intelx_u" in report["findings"]:
                console.print()
                v5_render_intelx(report["findings"]["intelx_u"], username)
            if "osintleak_u" in report["findings"]:
                console.print()
                render_osint_leak(report["findings"]["osintleak_u"])

        # 4. Phone details
        if "phone" in targets:
            if "phone_carrier" in report["findings"]:
                carrier = report["findings"]["phone_carrier"]
                for label, key in [("Carrier","carrier"),("Line type","line_type"),("Location","location")]:
                    if carrier.get(key):
                        console.print(f"  [dim]{label:<22}[/dim] {carrier[key]}")
            if "leakcheck_p" in report["findings"]:
                console.print()
                v6_render_leakcheck(report["findings"]["leakcheck_p"])
            if "leak_lookup_p" in report["findings"]:
                console.print()
                v5_render_leak_lookup(report["findings"]["leak_lookup_p"])
            if "intelx_p" in report["findings"]:
                console.print()
                v5_render_intelx(report["findings"]["intelx_p"], targets["phone"])
            if "osintleak_p" in report["findings"]:
                console.print()
                render_osint_leak(report["findings"]["osintleak_p"])

        # 5. Domain extras
        if "domain" in targets:
            if "posture" in report["findings"]:
                console.print()
                v5_render_posture(domain, report["findings"]["posture"])
            if "txt_records" in report["findings"]:
                console.print()
                v5_render_txt(report["findings"]["txt_records"].get("records", []), domain)
            if "urlscan" in report["findings"]:
                console.print()
                render_v4_urlscan(report["findings"]["urlscan"].get("results", []))
            if "otx_domain" in report["findings"]:
                console.print()
                render_v4_otx_domain(report["findings"]["otx_domain"])
            if "ht_dns" in report["findings"]:
                console.print()
                render_v4_hackertarget_dns(report["findings"]["ht_dns"].get("results", []))
            if "pulsedive" in report["findings"]:
                console.print()
                v5_render_pulsedive(report["findings"]["pulsedive"], domain)
            if "ssl" in report["findings"]:
                console.print()
                render_ext_ssl(report["findings"]["ssl"])
            if d_finds.get("subdomains"):
                console.print()
                render_ext_crtsh_domain([{"subdomain": s, "issued": ""} for s in d_finds["subdomains"]])
            if d_finds.get("blacklist"):
                console.print()
                render_ext_blacklist(d_finds["blacklist"])
            if "hunter" in report["findings"]:
                console.print()
                render_ext_hunter(report["findings"]["hunter"])
            if "phonebook_d" in report["findings"]:
                console.print()
                v6_render_phonebook(report["findings"]["phonebook_d"], domain)
            if "intelx_d" in report["findings"]:
                console.print()
                v5_render_intelx(report["findings"]["intelx_d"], domain)

        # 6. Password details
        if "password" in targets:
            render_password_audit(report["findings"].get("password_audit", {}))

        # 7. Render Dorks
        if not opts.get("no_dorks") and "dorks" in report["findings"]:
            section("GOOGLE DORK QUERIES")
            dorks = report["findings"]["dorks"]
            dorks_only = [d for d in dorks if "pastebin" not in d[0] and "raidforums" not in d[0] and "ghostbin" not in d[0]]
            extra_dorks_only = [d for d in dorks if d not in dorks_only]
            render_dorks(dorks_only)
            render_v4_extra_dorks(extra_dorks_only)

        # 8. Dark-web links
        if not opts.get("no_darkweb") and "darkweb_links" in report["findings"]:
            v5_render_darkweb_links([(l["label"], l["url"]) for l in report["findings"]["darkweb_links"]])

        # ── Scan Summary ──────────────────────────────────────────────────────
        class ArgsNamespace:
            pass
        args_obj = ArgsNamespace()
        setattr(args_obj, "email", targets.get("email"))
        setattr(args_obj, "username", targets.get("username"))
        setattr(args_obj, "domain", targets.get("domain"))
        setattr(args_obj, "password", targets.get("password"))
        setattr(args_obj, "no_dns", opts.get("no_dns", False))
        
        render_ext_summary(report, args_obj)
        section("SCAN COMPLETE")

        # ── Output Exporters ──────────────────────────────────────────────────
        if opts.get("output"):
            export_json(report, opts["output"])
            console.print(f"\n  [green]JSON saved:[/green] {opts['output']}")

        if opts.get("html"):
            export_html(report, opts["html"])
            console.print(f"  [green]HTML saved:[/green] {opts['html']}")

        if opts.get("csv"):
            export_csv(report, opts["csv"])
            console.print(f"  [green]CSV saved:[/green] {opts['csv']}")
        console.print()

# ── Click Command Handlers ────────────────────────────────────────────────────

@scan.command("email")
@click.argument("target")
@common_options
def scan_email(target, **kwargs):
    """Scan an email address target"""
    asyncio.run(run_scan_engine({"email": target}, kwargs))

@scan.command("username")
@click.argument("target")
@common_options
def scan_username(target, **kwargs):
    """Scan a social handle / username target"""
    asyncio.run(run_scan_engine({"username": target}, kwargs))

@scan.command("domain")
@click.argument("target")
@common_options
def scan_domain(target, **kwargs):
    """Scan a domain / IP target"""
    asyncio.run(run_scan_engine({"domain": target}, kwargs))

@scan.command("phone")
@click.argument("target")
@common_options
def scan_phone(target, **kwargs):
    """Scan a phone number target"""
    asyncio.run(run_scan_engine({"phone": target}, kwargs))

@scan.command("password")
@click.argument("target")
@common_options
def scan_password(target, **kwargs):
    """Audit a password target locally (SHA-1 prefix range checks)"""
    asyncio.run(run_scan_engine({"password": target}, kwargs))

@scan.command("all")
@click.argument("target")
@common_options
def scan_all(target, **kwargs):
    """Scan target by auto-detecting target format (Email/Phone/Domain/Username)"""
    targets = {}
    if "@" in target:
        targets["email"] = target
    elif target.startswith("+") or (target.isdigit() and len(target) >= 7):
        targets["phone"] = target
    elif "." in target and not target.endswith("."):
        targets["domain"] = target
    else:
        targets["username"] = target
        
    asyncio.run(run_scan_engine(targets, kwargs))

@cli.command("web")
@click.option("--host", default="127.0.0.1", help="Host address to bind to")
@click.option("--port", default=5000, help="Port to bind the web server")
def start_web(host, port):
    """Start the VENOM local web interface server"""
    from modules.web import start_server
    start_server(host=host, port=port)

if __name__ == "__main__":
    cli()
