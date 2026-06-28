<div align="center">

```
 __      ________ _   _  ____  __  __ 
 \ \    / /  ____| \ | |/ __ \|  \/  |
  \ \  / /| |__  |  \| | |  | | \  / |
   \ \/ / |  __| | . ` | |  | | |\/| |
    \  /  | |____| |\  | |__| | |  | |
     \/   |______|_| \_|\____/|_|  |_|
```

**OSINT Synthesis & Correlation Framework**

[![Python](https://img.shields.io/badge/python-3.8%2B-blue?style=flat-square&logo=python)](https://www.python.org/)
[![Version](https://img.shields.io/badge/version-7.0-emerald?style=flat-square)](https://github.com/ghostport-sudo/venom)
[![License](https://img.shields.io/badge/license-MIT-blue?style=flat-square)](LICENSE)
[![Stars](https://img.shields.io/github/stars/ghostport-sudo/venom?style=flat-square)](https://github.com/ghostport-sudo/venom/stargazers)

</div>

---

**VENOM v7.0** is an enterprise-grade, high-performance, fully asynchronous OSINT synthesis framework designed to audit and map digital footprints across **emails, usernames, phone numbers, passwords, and domains**. 

Leveraging a concurrent `aiohttp` execution pipeline, VENOM sweeps dozens of APIs, breach records, threat intelligence registries, and social networks in seconds. 

---

## ⚡ New in v7.0: Glassmorphic Web UI & Autonomous AI Agent

VENOM now features a built-in, local web server exposing a fully interactive React-based liquid-glass interface. Real-time scanning statuses are streamed instantly to the UI via WebSockets.

**Autonomous AI Analyst (Zero-Hallucination):**
The web dashboard includes a specialized AI Agent (supporting Gemini, Groq, and OpenRouter) that autonomously conducts **live DuckDuckGo web scraping** during a scan. It cross-references its live search findings with the OSINT breach data to deliver a military-grade, 100% fact-checked target correlation report.

**100% Accurate Social Enumeration:**
The username enumeration engine has been rewritten at the network layer to strictly forbid redirect-following, completely eliminating the false-positive 200 OK responses common in legacy OSINT tools. If VENOM says the profile exists, it exists.

To launch the web interface:
```bash
python venom.py web --port 5000
```
Then navigate to `http://localhost:5000` in your web browser.

---

## Features

| Category | Probes & Integrations |
|---|---|
| **Web UI Dashboard** | React 18, WebSocket status streams, tabbed data explorer, visual metrics, multi-format reports |
| **Breach Databases** | HIBP, LeakCheck, BreachDirectory, Leak-Lookup, Dehashed, PSBDMP, IntelligenceX, Phonebook.cz |
| **Email Intelligence** | EmailRep, Gravatar, Google account probe, Holehe site registration, SPF/DMARC/DKIM posture, TXT record classifications, OTX threat pulses |
| **Username Enumeration** | 80+ social platforms concurrently, GitLab, npm, PyPI, Keybase, Twitter/X, Telegram, Steam, GitHub profiles/orgs/exposed commit emails |
| **Domain & Host** | DNS/WHOIS/RDAP, Shodan InternetDB, URLScan, OTX AlienVault, HackerTarget passive DNS, Pulsedive, Wayback Machine, SSL certificate chain, crt.sh subdomains, DNS Blacklists, Hunter.io, ProxyCheck |
| **Phone Recon** | Prefix detection, carrier verification, line type lookup, leak records |
| **Generative Probes** | Automated Google dorks, dark web investigator links, username permutation sweeps |
| **Auditing & Exports** | SHA-1 password k-anonymity checks, JSON (SIEM-ready), CSV, and dark-mode standalone HTML exports |

---

## Installation

```bash
git clone https://github.com/ghostport-sudo/venom
cd venom
python install.py
```

`install.py` will verify your python environment, download the updated requirements, and install VENOM on your user PATH for system-wide execution.

### Dependencies
- **aiohttp** (Asynchronous HTTP Networking)
- **click** (Subcommand Command-line Interface)
- **rich** (Beautiful Terminal Formatting)

---

## CLI Usage Reference

VENOM uses a click-driven subcommand structure.

```bash
# General Help
python venom.py --help

# Run a unified scan auto-detecting target format (Email/Phone/Domain/Username)
python venom.py scan all target@domain.com

# Scan specific targets
python venom.py scan email target@domain.com
python venom.py scan domain target-domain.com
python venom.py scan username target_user
python venom.py scan phone +1234567890

# k-Anonymity password check
python venom.py scan password "secretPassword123"

# Start the web dashboard server
python venom.py web --port 5000
```

---

## Directory Architecture

```
venom/
├── venom.py              # Main CLI entry point and click command router
├── install.py            # Windows/Linux/macOS installer
├── requirements.txt      # Core asynchronous requirements
├── modules/
│   ├── base.py           # BaseOSINTModule abstract base class
│   ├── config.py         # Global session, banners, and platforms lists
│   ├── email.py          # Email security posture, classification, Gravatar, etc.
│   ├── username.py       # Social network sweeps, GitHub, npm, PyPI, Steam, GitLab
│   ├── domain.py         # DNS/WHOIS, Shodan, URLScan, OTX, certificates, subdomains
│   ├── phone.py          # Phone formatting, carrier lookup
│   ├── breach.py         # HIBP, Dehashed, LeakCheck, OSINTLeak modules
│   ├── dorks.py          # Generative dorks & Onion links
│   ├── render.py         # Color-coded terminal rich console output
│   ├── export.py         # SIEM-ready JSON, CSV, and premium HTML reports
│   ├── web.py            # aiohttp.web backend & WebSocket API router
│   └── webui/
│       └── index.html    # Glassmorphic React 18 frontend dashboard SPA
```

---

## Legal & Ethics

This tool is intended strictly for security audits, authorized penetration testing, and digital footprint validation. Operating this software against targets without permission is illegal. The authors assume no liability for misuse.
