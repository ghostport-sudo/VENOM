"""
HTML, JSON, and CSV report export utilities.
Generates an advanced, premium dark-themed HTML report containing all target findings,
along with flat spreadsheets (CSV) and structured machine-readable logs (JSON).
"""

import json
import csv
from typing import Dict, Any

def esc(s):
    """HTML escape helper."""
    return str(s).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")

def export_json(report: Dict[str, Any], path: str) -> None:
    """Save raw structured JSON report for SIEM ingestion."""
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(report, fh, indent=2, default=str)

def export_csv(report: Dict[str, Any], path: str) -> None:
    """Save flat, analyst-friendly CSV sheets."""
    targets = report.get("targets", {})
    findings = report.get("findings", {})
    
    rows = []
    for t_type, t_val in targets.items():
        for source, data in findings.items():
            if isinstance(data, dict):
                for k, v in data.items():
                    rows.append({
                        "Target Type": t_type,
                        "Target Value": t_val,
                        "Source": source,
                        "Metric": k,
                        "Value": str(v)
                    })
            elif isinstance(data, list):
                for idx, item in enumerate(data):
                    val_str = json.dumps(item) if isinstance(item, (dict, list)) else str(item)
                    rows.append({
                        "Target Type": t_type,
                        "Target Value": t_val,
                        "Source": source,
                        "Metric": f"Item_{idx}",
                        "Value": val_str
                    })
            else:
                rows.append({
                    "Target Type": t_type,
                    "Target Value": t_val,
                    "Source": source,
                    "Metric": "Value",
                    "Value": str(data)
                })

    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=["Target Type", "Target Value", "Source", "Metric", "Value"])
        writer.writeheader()
        writer.writerows(rows)

def export_html(report: Dict[str, Any], path: str) -> None:
    """Save highly stylized interactive dark-mode HTML reports."""
    ts = report.get("timestamp", "")
    tgts = report.get("targets", {})
    finds = report.get("findings", {})

    target_str = " · ".join(f"{k.upper()}: {esc(v)}" for k, v in tgts.items())
    sections_html = []

    # ── 1. HIBP BREACHES & PASTES ─────────────────────────────────────────────
    hibp = finds.get("hibp", {})
    breaches = hibp.get("breaches", [])
    pastes = hibp.get("pastes", [])
    
    if breaches:
        br_rows = "".join(
            f"<tr><td>{esc(b.get('Name',''))}</td><td>{esc(b.get('BreachDate','')[:7])}</td>"
            f"<td class='count'>{b.get('PwnCount',0):,}</td><td>{esc(', '.join(b.get('DataClasses',[])[:5]))}</td></tr>"
            for b in breaches
        )
        sections_html.append(f"""
        <div class="card">
            <h2>HaveIBeenPwned Breaches <span class="badge red">{len(breaches)}</span></h2>
            <div class="table-container">
                <table class="searchable">
                    <thead>
                        <tr><th>Breach Site</th><th>Date</th><th>Compromised Records</th><th>Exposed Data Types</th></tr>
                    </thead>
                    <tbody>
                        {br_rows}
                    </tbody>
                </table>
            </div>
        </div>
        """)

    if pastes:
        pst_rows = "".join(
            f"<tr><td>{esc(p.get('Source',''))}</td><td>{esc(p.get('Title',''))}</td>"
            f"<td><a href='https://pastebin.com/{esc(p.get('Id',''))}' target='_blank'>{esc(p.get('Id',''))} ↗</a></td></tr>"
            for p in pastes
        )
        sections_html.append(f"""
        <div class="card">
            <h2>HaveIBeenPwned Pastes <span class="badge warning">{len(pastes)}</span></h2>
            <div class="table-container">
                <table class="searchable">
                    <thead>
                        <tr><th>Source</th><th>Title</th><th>Paste Link</th></tr>
                    </thead>
                    <tbody>
                        {pst_rows}
                    </tbody>
                </table>
            </div>
        </div>
        """)

    # ── 2. IDENTITY & EXPOSURE SUMMARY ───────────────────────────────────────
    emailrep = finds.get("emailrep", {})
    gravatar = finds.get("gravatar", {})
    name_inf = finds.get("name_inference", {})
    google_pr = finds.get("google_probe", {})
    osint_leak = finds.get("osintleak", {})

    if emailrep or gravatar or name_inf or google_pr or osint_leak:
        rows = []
        if name_inf.get("first"):
            rows.append(f"<tr><td><strong>Inferred Name</strong></td><td>{esc(name_inf.get('first',''))} {esc(name_inf.get('last',''))} ({esc(name_inf.get('gender',''))})</td></tr>")
        if emailrep:
            rep = emailrep.get("reputation", "unknown")
            susp = emailrep.get("suspicious", False)
            rep_class = "green" if rep == "high" else "red"
            rows.append(f"<tr><td><strong>Email Reputation</strong></td><td>Reputation: <span class='badge {rep_class}'>{esc(rep)}</span> | Suspicious: <span class='badge {'red' if susp else 'green'}'>{esc(susp)}</span></td></tr>")
        if google_pr:
            exists = google_pr.get("google_account", False)
            rows.append(f"<tr><td><strong>Google Account</strong></td><td>Exists: <span class='badge {'green' if exists else 'red'}'>{esc(exists)}</span> (Method: {esc(google_pr.get('method',''))})</td></tr>")
        if gravatar.get("registered"):
            rows.append(f"<tr><td><strong>Gravatar</strong></td><td>Registered | Display: {esc(gravatar.get('display_name',''))} | Location: {esc(gravatar.get('location',''))} | <a href='{esc(gravatar.get('profile_url',''))}' target='_blank'>Profile ↗</a></td></tr>")
        if osint_leak and osint_leak.get("found"):
            rows.append(f"<tr><td><strong>OSINTLeak Logs</strong></td><td>Breaches Found: <span class='badge red'>{osint_leak.get('count', 0)}</span> | Origins: {esc(', '.join(osint_leak.get('origins', [])))}</td></tr>")
        
        if rows:
            sections_html.append(f"""
            <div class="card">
                <h2>Identity &amp; Reputation Intel</h2>
                <div class="table-container">
                    <table>
                        <tbody>
                            {"".join(rows)}
                        </tbody>
                    </table>
                </div>
            </div>
            """)

    # ── 3. SOCIAL ACCOUNTS ENUMERATION ────────────────────────────────────────
    social = finds.get("social", {})
    found_social = social.get("found", [])
    if found_social:
        sr_rows = "".join(
            f"<tr><td>{esc(item.get('platform',''))}</td><td><a href='{esc(item.get('url',''))}' target='_blank'>{esc(item.get('url',''))} ↗</a></td></tr>"
            for item in found_social
        )
        sections_html.append(f"""
        <div class="card">
            <h2>Social Profiles Found <span class="badge green">{len(found_social)}</span></h2>
            <div class="table-container">
                <table class="searchable">
                    <thead>
                        <tr><th>Platform</th><th>Profile URL</th></tr>
                    </thead>
                    <tbody>
                        {sr_rows}
                    </tbody>
                </table>
            </div>
        </div>
        """)

    # ── 4. HOLEHE REGISTRATION PROBES ─────────────────────────────────────────
    holehe = finds.get("holehe", {}).get("results", []) if isinstance(finds.get("holehe"), dict) else finds.get("holehe", [])
    reg_holehe = [r for r in holehe if isinstance(r, dict) and r.get("registered")]
    if reg_holehe:
        hh_rows = "".join(
            f"<tr><td>{esc(r.get('site',''))}</td><td><span class='badge green'>Registered</span> (Confidence: {esc(r.get('confidence',''))})</td></tr>"
            for r in reg_holehe
        )
        sections_html.append(f"""
        <div class="card">
            <h2>Site Registrations (Holehe Audits) <span class="badge green">{len(reg_holehe)}</span></h2>
            <div class="table-container">
                <table class="searchable">
                    <thead>
                        <tr><th>Platform</th><th>Status</th></tr>
                    </thead>
                    <tbody>
                        {hh_rows}
                    </tbody>
                </table>
            </div>
        </div>
        """)

    # ── 5. DOMAIN / DNS / WHOIS / IP GEOLOCATION ──────────────────────────────
    dom_finds = finds.get("domain", {})
    if dom_finds:
        dns = dom_finds.get("dns", {})
        whois = dom_finds.get("whois", {})
        ip_info = dom_finds.get("ip", {})
        
        dns_rows = []
        if dns:
            dns_rows.append(f"<tr><td><strong>MX Provider</strong></td><td>{esc(dns.get('provider','unknown'))}</td></tr>")
            dns_rows.append(f"<tr><td><strong>A Records</strong></td><td>{esc(', '.join(dns.get('a',[])))}</td></tr>")
            dns_rows.append(f"<tr><td><strong>MX Records</strong></td><td>{esc(', '.join(dns.get('mx',[])))}</td></tr>")
        if whois.get("registered"):
            dns_rows.append(f"<tr><td><strong>Registrar</strong></td><td>{esc(whois.get('registrar',''))} (Created: {esc(whois.get('created',''))}, Expires: {esc(whois.get('expires',''))})</td></tr>")
        if ip_info.get("ip"):
            geo = ip_info.get("geo", {})
            dns_rows.append(f"<tr><td><strong>Resolved IP</strong></td><td>{esc(ip_info.get('ip',''))} ({esc(geo.get('org',''))} - {esc(geo.get('city',''))}, {esc(geo.get('country',''))})</td></tr>")

        if dns_rows:
            sections_html.append(f"""
            <div class="card">
                <h2>Domain &amp; DNS Intelligence</h2>
                <div class="table-container">
                    <table>
                        <tbody>
                            {"".join(dns_rows)}
                        </tbody>
                    </table>
                </div>
            </div>
            """)

    # ── 6. GOOGLE DORKS ───────────────────────────────────────────────────────
    dorks = finds.get("dorks", [])
    if dorks:
        dr_rows = "".join(
            f"<tr><td><code>{esc(q)}</code></td><td><a href='{esc(u)}' target='_blank' class='btn'>Run Dork ↗</a></td></tr>"
            for q, u in dorks
        )
        sections_html.append(f"""
        <div class="card">
            <h2>Google Dork Queries <span class="badge blue">{len(dorks)}</span></h2>
            <div class="table-container">
                <table class="searchable">
                    <thead>
                        <tr><th>Dork Query</th><th>Action</th></tr>
                    </thead>
                    <tbody>
                        {dr_rows}
                    </tbody>
                </table>
            </div>
        </div>
        """)

    # ── HTML RENDER ───────────────────────────────────────────────────────────
    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Venom OSINT Report — {esc(ts[:10])}</title>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;600;700&family=Outfit:wght@400;600;700&family=JetBrains+Mono:wght@400;700&display=swap" rel="stylesheet">
    <style>
        :root {{
            --bg-color: #0b0f19;
            --card-bg: #111827;
            --border-color: #1f2937;
            --primary: #10b981;
            --primary-glow: rgba(16, 185, 129, 0.15);
            --text-main: #f3f4f6;
            --text-muted: #9ca3af;
            --red: #ef4444;
            --blue: #3b82f6;
            --warning: #f59e0b;
        }}
        
        body {{
            font-family: 'Inter', sans-serif;
            background: var(--bg-color);
            color: var(--text-main);
            margin: 0;
            padding: 2.5rem;
            line-height: 1.6;
        }}

        h1, h2, h3 {{
            font-family: 'Outfit', sans-serif;
        }}

        h1 {{
            color: var(--primary);
            font-size: 2.2rem;
            font-weight: 700;
            letter-spacing: -0.03em;
            margin-bottom: 0.2rem;
            text-shadow: 0 0 20px var(--primary-glow);
        }}

        .meta {{
            color: var(--text-muted);
            font-size: 0.9rem;
            margin: 0.3rem 0;
        }}

        .search-wrapper {{
            margin: 2rem 0;
            display: flex;
            gap: 1rem;
        }}

        .search-bar {{
            flex: 1;
            background: var(--card-bg);
            border: 1px solid var(--border-color);
            border-radius: 8px;
            padding: 0.8rem 1.2rem;
            color: var(--text-main);
            font-size: 0.95rem;
            transition: all 0.2s ease;
        }}

        .search-bar:focus {{
            outline: none;
            border-color: var(--primary);
            box-shadow: 0 0 10px var(--primary-glow);
        }}

        .card {{
            background: var(--card-bg);
            border: 1px solid var(--border-color);
            border-radius: 12px;
            padding: 1.8rem;
            margin-bottom: 2rem;
            box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.1), 0 2px 4px -1px rgba(0, 0, 0, 0.06);
        }}

        h2 {{
            color: var(--primary);
            font-size: 1.25rem;
            font-weight: 600;
            margin-top: 0;
            margin-bottom: 1.2rem;
            border-bottom: 1px solid var(--border-color);
            padding-bottom: 0.6rem;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }}

        .badge {{
            font-family: 'Outfit', sans-serif;
            font-size: 0.75rem;
            font-weight: 600;
            padding: 0.2rem 0.6rem;
            border-radius: 9999px;
            text-transform: uppercase;
        }}

        .badge.green {{ background: rgba(16, 185, 129, 0.15); color: #34d399; }}
        .badge.red {{ background: rgba(239, 68, 68, 0.15); color: #f87171; }}
        .badge.blue {{ background: rgba(59, 130, 246, 0.15); color: #60a5fa; }}
        .badge.warning {{ background: rgba(245, 158, 11, 0.15); color: #fbbf24; }}

        .table-container {{
            overflow-x: auto;
        }}

        table {{
            width: 100%;
            border-collapse: collapse;
            font-size: 0.9rem;
            text-align: left;
        }}

        th {{
            background: rgba(255, 255, 255, 0.02);
            color: var(--text-muted);
            padding: 0.8rem 1rem;
            font-weight: 600;
            border-bottom: 2px solid var(--border-color);
        }}

        td {{
            padding: 0.8rem 1rem;
            border-bottom: 1px solid var(--border-color);
            color: var(--text-main);
        }}

        tr:hover td {{
            background: rgba(255, 255, 255, 0.01);
        }}

        a {{
            color: var(--primary);
            text-decoration: none;
            transition: color 0.15s ease;
        }}

        a:hover {{
            color: #34d399;
            text-decoration: underline;
        }}

        code {{
            font-family: 'JetBrains Mono', monospace;
            background: rgba(255, 255, 255, 0.05);
            padding: 0.2rem 0.4rem;
            border-radius: 4px;
            color: #fb7185;
            font-size: 0.85rem;
        }}

        pre {{
            font-family: 'JetBrains Mono', monospace;
            background: #070a13;
            padding: 1.2rem;
            overflow: auto;
            font-size: 0.8rem;
            border-radius: 8px;
            border: 1px solid var(--border-color);
        }}

        .btn {{
            background: var(--primary);
            color: var(--bg-color) !important;
            font-weight: 600;
            padding: 0.4rem 0.8rem;
            border-radius: 6px;
            font-size: 0.8rem;
            display: inline-block;
        }}

        .btn:hover {{
            background: #34d399;
            text-decoration: none;
        }}
    </style>
</head>
<body>
    <h1>VENOM OSINT REPORT</h1>
    <div class="meta">Generated: {esc(ts)}</div>
    <div class="meta"><strong>Target Parameters:</strong> {target_str}</div>
    
    <div class="search-wrapper">
        <input type="text" id="reportSearch" class="search-bar" placeholder="Filter tables by keyword (e.g. gmail, breach site name, platform)..." onkeyup="filterTables()">
    </div>

    {"".join(sections_html)}
    
    <div class="card">
        <h2>Raw SIEM Logs (JSON)</h2>
        <pre><code>{esc(json.dumps(report, indent=2, default=str))}</code></pre>
    </div>

    <script>
        function filterTables() {{
            var input = document.getElementById("reportSearch");
            var filter = input.value.toLowerCase();
            var tables = document.querySelectorAll("table.searchable");
            
            tables.forEach(function(table) {{
                var rows = table.getElementsByTagName("tr");
                for (var i = 1; i < rows.length; i++) {{
                    var row = rows[i];
                    var cells = row.getElementsByTagName("td");
                    var found = false;
                    for (var j = 0; j < cells.length; j++) {{
                        if (cells[j].innerText.toLowerCase().indexOf(filter) > -1) {{
                            found = true;
                            break;
                        }}
                    }}
                    row.style.display = found ? "" : "none";
                }}
            }});
        }}
    </script>
</body>
</html>"""

    with open(path, "w", encoding="utf-8") as f:
        f.write(html)
