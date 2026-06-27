"""
VENOM Web Server — aiohttp.web REST API + WebSocket backend.
Serves the React frontend and exposes /api/ endpoints for scanning.
"""

import asyncio
import json
import re
import uuid
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

import aiohttp
from aiohttp import web

# ── Module Imports (same surface as venom.py CLI) ─────────────────────────────

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
    HoleheModule,
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
    SteamProfileModule,
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
    ProxyCheckModule,
)

from modules.phone import check_phone, PhoneCarrierModule

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
    OSINTLeakModule,
)

from modules.dorks import (
    generate_dorks,
    extra_dorks as v4_extra_dorks,
    darkweb_links as v5_darkweb_links,
)

from modules.export import export_html, export_json, export_csv

# ── Scan Store (in-memory) ────────────────────────────────────────────────────

_scans: Dict[str, Dict] = {}
_ws_clients: Dict[str, List[web.WebSocketResponse]] = {}


def _default_serialiser(o: Any) -> Any:
    """Fallback serialiser for json.dumps."""
    if isinstance(o, datetime):
        return o.isoformat()
    if isinstance(o, set):
        return list(o)
    return str(o)


async def _broadcast(scan_id: str, data: dict) -> None:
    """Push a JSON message to every WebSocket subscriber of *scan_id*."""
    dead: List[web.WebSocketResponse] = []
    for ws in _ws_clients.get(scan_id, []):
        try:
            await ws.send_str(json.dumps(data, default=_default_serialiser))
        except (ConnectionError, RuntimeError):
            dead.append(ws)
    for ws in dead:
        _ws_clients[scan_id].remove(ws)


async def _push(scan_id: str, stage: str, detail: str = "") -> None:
    """Helper — update scan log + broadcast."""
    entry = {"ts": datetime.now().isoformat(), "stage": stage, "detail": detail}
    if scan_id in _scans:
        _scans[scan_id]["log"].append(entry)
        await _broadcast(scan_id, {
            "type": "progress",
            "stage": stage,
            "detail": detail,
            "progress": _scans[scan_id]["progress"],
            "log": _scans[scan_id]["log"],
        })


# ── Scan Engine (web-optimised — headless, JSON-only) ─────────────────────────

async def _execute_scan(scan_id: str, target: str, scan_type: str, opts: dict) -> None:
    """Run the full OSINT pipeline and populate _scans[scan_id] with results."""
    scan = _scans[scan_id]
    scan["status"] = "running"

    # Detect targets
    targets: Dict[str, str] = {}
    if scan_type == "auto":
        if "@" in target:
            targets["email"] = target
        elif target.startswith("+") or (target.replace("-", "").isdigit() and len(target) >= 7):
            targets["phone"] = target
        elif "." in target and not target.endswith("."):
            targets["domain"] = target
        else:
            targets["username"] = target
    else:
        targets[scan_type] = target

    scan["targets"] = targets
    scan["detected_type"] = list(targets.keys())

    report: Dict[str, Any] = {
        "timestamp": datetime.now().isoformat(),
        "targets": targets,
        "findings": {},
    }

    proxy = opts.get("proxy")

    try:
        async with aiohttp.ClientSession() as session:
            tasks: Dict[str, Any] = {}

            # ── Email Tasks ───────────────────────────────────────────────
            if "email" in targets:
                email = targets["email"]
                fmt = check_email_format(email)
                domain = fmt.get("domain", "")
                report["findings"]["email_format"] = fmt
                await _push(scan_id, "email", f"Scanning {email}")
                scan["progress"] = 5

                if domain:
                    tasks["dns"] = DNSModule(domain, proxy=proxy).run(session)
                    tasks["whois"] = WHOISModule(domain, proxy=proxy).run(session)
                    tasks["ip"] = IPResolutionModule(domain, proxy=proxy).run(session)
                    tasks["posture"] = EmailSecurityPostureModule(email, proxy=proxy).run(session)
                    tasks["txt_records"] = EmailTxtClassifyModule(email, proxy=proxy).run(session)
                    tasks["rdap_admin_email"] = RdapAdminEmailModule(email, proxy=proxy).run(session)

                tasks["gravatar"] = GravatarModule(email, proxy=proxy).run(session)
                tasks["google_probe"] = GoogleProbeModule(email, proxy=proxy).run(session)
                tasks["emailrep"] = EmailRepModule(email, api_key=opts.get("emailrep_key"), proxy=proxy).run(session)
                tasks["holehe"] = HoleheModule(email, proxy=proxy).run(session)
                tasks["crtsh_email"] = CrtshEmailModule(email, proxy=proxy).run(session)
                tasks["otx_email"] = OTXEmailModule(email, proxy=proxy).run(session)
                tasks["dehashed"] = DehashedModule(email, proxy=proxy).run(session)
                tasks["pulsedive_email"] = PulsediveModule(email, proxy=proxy).run(session)

                if opts.get("hibp_key"):
                    tasks["hibp_breaches"] = HIBPBreachesModule(email, api_key=opts["hibp_key"], proxy=proxy).run(session)
                    tasks["hibp_pastes"] = HIBPPastesModule(email, api_key=opts["hibp_key"], proxy=proxy).run(session)

                tasks["breach_directory"] = BreachDirectoryModule(email, api_key=opts.get("bd_key"), proxy=proxy).run(session)
                tasks["leakcheck"] = LeakCheckModule(email, api_key=opts.get("leakcheck_key"), proxy=proxy).run(session)
                tasks["leak_lookup"] = LeakLookupModule(email, api_key=opts.get("leak_lookup_key"), proxy=proxy).run(session)
                tasks["psbdmp"] = PSBDMPModule(email, proxy=proxy).run(session)
                tasks["phonebook"] = PhonebookModule(email, proxy=proxy).run(session)

                if opts.get("intelx_key"):
                    tasks["intelx_email"] = IntelXModule(email, api_key=opts["intelx_key"], proxy=proxy).run(session)
                if opts.get("osintleak_key"):
                    tasks["osintleak"] = OSINTLeakModule(email, api_key=opts["osintleak_key"], proxy=proxy).run(session)

                tasks["github_commits"] = GitHubEmailCommitsModule(email, proxy=proxy).run(session)

            # ── Username Tasks ────────────────────────────────────────────
            if "username" in targets:
                username = targets["username"]
                await _push(scan_id, "username", f"Enumerating {username}")
                scan["progress"] = 5

                tasks["social"] = SocialEnumerationModule(username, proxy=proxy).run(session)
                tasks["github_user"] = GitHubUserModule(username, proxy=proxy).run(session)
                tasks["github_orgs"] = GitHubOrgsModule(username, proxy=proxy).run(session)
                tasks["gitlab"] = GitLabUserModule(username, proxy=proxy).run(session)
                tasks["npm"] = NPMUserModule(username, proxy=proxy).run(session)
                tasks["pypi"] = PyPIUserModule(username, proxy=proxy).run(session)
                tasks["keybase"] = KeybaseModule(username, proxy=proxy).run(session)
                tasks["twitter"] = TwitterOembedModule(username, proxy=proxy).run(session)
                tasks["telegram"] = TelegramResolveModule(username, proxy=proxy).run(session)
                tasks["steam"] = SteamProfileModule(username, proxy=proxy).run(session)
                tasks["leakcheck_u"] = LeakCheckModule(username, query_type="username", api_key=opts.get("leakcheck_key"), proxy=proxy).run(session)
                tasks["leak_lookup_u"] = LeakLookupModule(username, query_type="username", api_key=opts.get("leak_lookup_key"), proxy=proxy).run(session)
                tasks["psbdmp_u"] = PSBDMPModule(username, proxy=proxy).run(session)
                tasks["phonebook_u"] = PhonebookModule(username, proxy=proxy).run(session)

                if opts.get("intelx_key"):
                    tasks["intelx_u"] = IntelXModule(username, api_key=opts["intelx_key"], proxy=proxy).run(session)
                if opts.get("osintleak_key"):
                    tasks["osintleak_u"] = OSINTLeakModule(username, api_key=opts["osintleak_key"], proxy=proxy).run(session)

            # ── Phone Tasks ───────────────────────────────────────────────
            if "phone" in targets:
                phone = targets["phone"]
                ph = check_phone(phone)
                report["findings"]["phone_info"] = ph
                await _push(scan_id, "phone", f"Looking up {phone}")
                scan["progress"] = 5

                if ph["valid"]:
                    tasks["phone_carrier"] = PhoneCarrierModule(ph["cleaned"], proxy=proxy).run(session)
                    tasks["leakcheck_p"] = LeakCheckModule(ph["cleaned"], query_type="phone", api_key=opts.get("leakcheck_key"), proxy=proxy).run(session)
                    tasks["leak_lookup_p"] = LeakLookupModule(ph["cleaned"], query_type="phone", api_key=opts.get("leak_lookup_key"), proxy=proxy).run(session)
                    if opts.get("intelx_key"):
                        tasks["intelx_p"] = IntelXModule(ph["cleaned"], api_key=opts["intelx_key"], proxy=proxy).run(session)
                    if opts.get("osintleak_key"):
                        tasks["osintleak_p"] = OSINTLeakModule(ph["cleaned"], api_key=opts["osintleak_key"], proxy=proxy).run(session)

            # ── Domain Tasks ──────────────────────────────────────────────
            if "domain" in targets:
                domain = re.sub(r"^https?://", "", targets["domain"].strip().lower()).rstrip("/")
                await _push(scan_id, "domain", f"Resolving {domain}")
                scan["progress"] = 5

                tasks["dns"] = DNSModule(domain, proxy=proxy).run(session)
                tasks["whois"] = WHOISModule(domain, proxy=proxy).run(session)
                tasks["ip"] = IPResolutionModule(domain, proxy=proxy).run(session)
                tasks["posture"] = EmailSecurityPostureModule(domain, proxy=proxy).run(session)
                tasks["txt_records"] = EmailTxtClassifyModule(domain, proxy=proxy).run(session)
                tasks["urlscan"] = URLScanModule(domain, proxy=proxy).run(session)
                tasks["otx_domain"] = OTXDomainModule(domain, proxy=proxy).run(session)
                tasks["ht_dns"] = HackerTargetPassiveDNSModule(domain, proxy=proxy).run(session)
                tasks["pulsedive"] = PulsediveModule(domain, proxy=proxy).run(session)
                tasks["wayback"] = WaybackModule(domain, proxy=proxy).run(session)
                tasks["ssl"] = SSLCertModule(domain, proxy=proxy).run(session)
                tasks["crt_subs"] = CrtshDomainModule(domain, proxy=proxy).run(session)
                tasks["blacklist"] = MXBlacklistModule(domain, proxy=proxy).run(session)
                tasks["hunter"] = HunterDomainModule(domain, api_key=opts.get("hunter_key"), proxy=proxy).run(session)
                tasks["phonebook_d"] = PhonebookModule(domain, query_type=2, proxy=proxy).run(session)

                if opts.get("intelx_key"):
                    tasks["intelx_d"] = IntelXModule(domain, api_key=opts["intelx_key"], proxy=proxy).run(session)

            # ── Password Tasks ────────────────────────────────────────────
            if "password" in targets:
                await _push(scan_id, "password", "Performing k-anonymity audit")
                scan["progress"] = 5
                tasks["password_audit"] = PasswordKAnonymityModule(targets["password"], proxy=proxy).run(session)

            # ── Harvest concurrently ──────────────────────────────────────
            await _push(scan_id, "harvest", f"Launching {len(tasks)} concurrent probes...")
            scan["progress"] = 15

            if tasks:
                results = await asyncio.gather(*tasks.values(), return_exceptions=True)
                raw_findings: Dict[str, Any] = {}
                for key, result in zip(tasks.keys(), results):
                    if isinstance(result, Exception):
                        raw_findings[key] = {"_error": str(result)}
                    else:
                        raw_findings[key] = result
            else:
                raw_findings = {}

            scan["progress"] = 60
            await _push(scan_id, "processing", "Processing findings...")

            # ── Post-process (same logic as CLI engine) ───────────────────
            if "hibp_breaches" in raw_findings or "hibp_pastes" in raw_findings:
                b_data = raw_findings.pop("hibp_breaches", None)
                p_data = raw_findings.pop("hibp_pastes", None)
                report["findings"]["hibp"] = {
                    "breaches": b_data.get("breaches", []) if isinstance(b_data, dict) else [],
                    "pastes": p_data.get("pastes", []) if isinstance(p_data, dict) else [],
                }

            # Domain sub-grouping
            if any(k in raw_findings for k in ("crt_subs", "dns", "whois", "ip")):
                dom_report: Dict[str, Any] = {}
                if "dns" in raw_findings:
                    dom_report["dns"] = raw_findings.pop("dns")
                if "whois" in raw_findings:
                    dom_report["whois"] = raw_findings.pop("whois")
                if "ip" in raw_findings:
                    ip_res = raw_findings.pop("ip")
                    dom_report["ip"] = ip_res
                    raw_ip = ip_res.get("ip") if isinstance(ip_res, dict) else None
                    if raw_ip:
                        await _push(scan_id, "ip_intel", f"Deep-scanning {raw_ip}")
                        scan["progress"] = 70
                        ip_tasks = [
                            ShodanInternetDBModule(raw_ip, proxy=proxy).run(session),
                            IPGeoModule(raw_ip, proxy=proxy).run(session),
                            BGPViewModule(raw_ip, proxy=proxy).run(session),
                            ProxyCheckModule(raw_ip, proxy=proxy).run(session),
                            OTXIPModule(raw_ip, proxy=proxy).run(session),
                            HackerTargetReverseIPModule(raw_ip, proxy=proxy).run(session),
                        ]
                        ip_details = await asyncio.gather(*ip_tasks, return_exceptions=True)
                        labels = ["shodan", "geo", "bgp", "proxy_check", "otx_ip", "ht_rev"]
                        for lbl, val in zip(labels, ip_details):
                            dom_report[lbl] = val if not isinstance(val, Exception) else {"_error": str(val)}

                if "crt_subs" in raw_findings:
                    cs = raw_findings.pop("crt_subs")
                    dom_report["subdomains"] = cs.get("subdomains", []) if isinstance(cs, dict) else []
                if "blacklist" in raw_findings:
                    dom_report["blacklist"] = raw_findings.pop("blacklist")
                if "wayback" in raw_findings:
                    dom_report["wayback"] = raw_findings.pop("wayback")
                report["findings"]["domain"] = dom_report

            for k, v in raw_findings.items():
                report["findings"][k] = v

            scan["progress"] = 80
            await _push(scan_id, "enrichment", "Running enrichment passes...")

            # Name inference for email targets
            if "email" in targets:
                email = targets["email"]
                fmt = check_email_format(email)
                report["findings"]["name_inference"] = ext_infer_name(fmt.get("local", email.split("@")[0]))

            # Dorks
            for t_type, t_val in targets.items():
                if t_type in ("email", "username", "domain"):
                    kw = {t_type: t_val}
                    if t_type == "email":
                        kw["domain"] = check_email_format(t_val).get("domain", "")
                    report["findings"]["dorks"] = generate_dorks(**kw) + v4_extra_dorks(**kw)
                    report["findings"]["darkweb_links"] = [
                        {"label": l, "url": u} for l, u in v5_darkweb_links(**{t_type: t_val})
                    ]

            scan["progress"] = 100
            scan["status"] = "complete"
            scan["findings"] = report["findings"]
            scan["report"] = report
            scan["completed"] = datetime.now().isoformat()
            await _push(scan_id, "complete", "Scan finished")
            await _broadcast(scan_id, {
                "type": "complete",
                "scan_id": scan_id,
                "report": report,
            })

    except Exception as exc:
        scan["status"] = "error"
        scan["error"] = str(exc)
        scan["progress"] = 100
        await _push(scan_id, "error", str(exc))
        await _broadcast(scan_id, {"type": "error", "error": str(exc)})


# ── Route Handlers ────────────────────────────────────────────────────────────

async def handle_index(request: web.Request) -> web.Response:
    """Serve the React SPA."""
    html_path = Path(__file__).parent / "webui" / "index.html"
    return web.FileResponse(html_path, headers={"Content-Type": "text/html; charset=utf-8"})


async def handle_api_status(request: web.Request) -> web.Response:
    """Health check."""
    return web.json_response({
        "status": "online",
        "version": "7.0",
        "engine": "VENOM OSINT Framework",
        "scans_active": sum(1 for s in _scans.values() if s["status"] == "running"),
        "scans_total": len(_scans),
    })


async def handle_api_scan_start(request: web.Request) -> web.Response:
    """POST /api/scan — launch a new scan."""
    try:
        body = await request.json()
    except Exception:
        return web.json_response({"error": "Invalid JSON body"}, status=400)

    target = body.get("target", "").strip()
    if not target:
        return web.json_response({"error": "target is required"}, status=400)

    scan_type = body.get("type", "auto")
    options = body.get("options", {})
    scan_id = uuid.uuid4().hex[:10]

    _scans[scan_id] = {
        "id": scan_id,
        "status": "queued",
        "target": target,
        "type": scan_type,
        "progress": 0,
        "findings": {},
        "log": [],
        "started": datetime.now().isoformat(),
    }

    asyncio.create_task(_execute_scan(scan_id, target, scan_type, options))
    return web.json_response({"scan_id": scan_id, "status": "started"})


async def handle_api_scan_status(request: web.Request) -> web.Response:
    """GET /api/scan/{scan_id} — poll scan state."""
    scan_id = request.match_info["scan_id"]
    if scan_id not in _scans:
        return web.json_response({"error": "Scan not found"}, status=404)
    return web.json_response(_scans[scan_id], default=_default_serialiser)


async def handle_api_scan_export(request: web.Request) -> web.Response:
    """GET /api/scan/{scan_id}/export?format=json|csv|html — download report."""
    scan_id = request.match_info["scan_id"]
    if scan_id not in _scans:
        return web.json_response({"error": "Scan not found"}, status=404)

    scan = _scans[scan_id]
    if scan["status"] != "complete":
        return web.json_response({"error": "Scan not complete yet"}, status=400)

    fmt = request.query.get("format", "json")
    report = scan.get("report", {})

    if fmt == "json":
        return web.json_response(report, default=_default_serialiser, headers={
            "Content-Disposition": f'attachment; filename="venom_{scan_id}.json"',
        })
    elif fmt == "csv":
        import io, csv
        buf = io.StringIO()
        w = csv.writer(buf)
        w.writerow(["Target Type", "Target Value", "Source", "Metric", "Value"])
        for ttype, tval in report.get("targets", {}).items():
            for src, data in report.get("findings", {}).items():
                if isinstance(data, dict):
                    for k, v in data.items():
                        w.writerow([ttype, tval, src, k, json.dumps(v, default=str)])
                else:
                    w.writerow([ttype, tval, src, "data", json.dumps(data, default=str)])
        return web.Response(
            text=buf.getvalue(),
            content_type="text/csv",
            headers={"Content-Disposition": f'attachment; filename="venom_{scan_id}.csv"'},
        )
    elif fmt == "html":
        import tempfile, os
        tmp = Path(tempfile.mktemp(suffix=".html"))
        export_html(report, str(tmp))
        html_content = tmp.read_text(encoding="utf-8")
        tmp.unlink(missing_ok=True)
        return web.Response(
            text=html_content,
            content_type="text/html",
            headers={"Content-Disposition": f'attachment; filename="venom_{scan_id}.html"'},
        )

    return web.json_response({"error": f"Unknown format: {fmt}"}, status=400)


async def handle_api_history(request: web.Request) -> web.Response:
    """GET /api/history — return all completed scans (summary only)."""
    history = []
    for sid, s in _scans.items():
        history.append({
            "id": sid,
            "target": s.get("target", ""),
            "type": s.get("type", ""),
            "status": s.get("status", ""),
            "progress": s.get("progress", 0),
            "started": s.get("started", ""),
            "completed": s.get("completed", ""),
        })
    return web.json_response(history)


async def handle_ws(request: web.Request) -> web.WebSocketResponse:
    """WebSocket /ws/{scan_id} — real-time progress stream."""
    ws = web.WebSocketResponse(heartbeat=15.0)
    await ws.prepare(request)
    scan_id = request.match_info["scan_id"]

    _ws_clients.setdefault(scan_id, []).append(ws)

    # Send current state immediately
    if scan_id in _scans:
        await ws.send_str(json.dumps({
            "type": "state",
            **_scans[scan_id],
        }, default=_default_serialiser))

    try:
        async for msg in ws:
            if msg.type == aiohttp.WSMsgType.TEXT:
                pass  # Client messages not needed for now
            elif msg.type in (aiohttp.WSMsgType.ERROR, aiohttp.WSMsgType.CLOSE):
                break
    finally:
        if scan_id in _ws_clients and ws in _ws_clients[scan_id]:
            _ws_clients[scan_id].remove(ws)

    return ws


# ── CORS Middleware ───────────────────────────────────────────────────────────

@web.middleware
async def cors_middleware(request: web.Request, handler):
    """Permissive CORS for local development."""
    if request.method == "OPTIONS":
        resp = web.Response()
    else:
        try:
            resp = await handler(request)
        except web.HTTPException as ex:
            resp = ex
    resp.headers["Access-Control-Allow-Origin"] = "*"
    resp.headers["Access-Control-Allow-Methods"] = "GET, POST, OPTIONS"
    resp.headers["Access-Control-Allow-Headers"] = "Content-Type"
    return resp


# ── Application Factory ──────────────────────────────────────────────────────

def create_app() -> web.Application:
    """Build and return the aiohttp web application."""
    app = web.Application(middlewares=[cors_middleware])

    app.router.add_get("/", handle_index)
    app.router.add_get("/api/status", handle_api_status)
    app.router.add_post("/api/scan", handle_api_scan_start)
    app.router.add_get("/api/scan/{scan_id}", handle_api_scan_status)
    app.router.add_get("/api/scan/{scan_id}/export", handle_api_scan_export)
    app.router.add_get("/api/history", handle_api_history)
    app.router.add_get("/ws/{scan_id}", handle_ws)

    # Static assets (favicon, etc.)
    static_dir = Path(__file__).parent / "webui"
    if static_dir.is_dir():
        app.router.add_static("/static/", static_dir, show_index=False)

    return app


def start_server(host: str = "127.0.0.1", port: int = 5000) -> None:
    """Start the web server (blocking call)."""
    app = create_app()
    print(f"\n  [+] VENOM Web Interface running at \033[1mhttp://{host}:{port}\033[0m")
    print(f"  \033[2m  Press Ctrl+C to stop\033[0m\n")
    web.run_app(app, host=host, port=port, print=None)
