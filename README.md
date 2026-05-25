# DomainRecon

<p align="center">
  <img src="https://i.ibb.co/HLGGw0X0/Logo-DR3.png" alt="DomainRecon" width="100">
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Python-3.10+-blue?logo=python&logoColor=white">
  <img src="https://img.shields.io/badge/FastAPI-0.115+-009688?logo=fastapi&logoColor=white">
  <img src="https://img.shields.io/badge/Docker-ready-2496ED?logo=docker&logoColor=white">
  <img src="https://img.shields.io/badge/modules-55+-blueviolet">
  <img src="https://img.shields.io/badge/license-MIT-green">
</p>

DomainRecon is an OSINT platform designed for domain reconnaissance. It runs more than 55 passive and active modules in parallel to gather comprehensive domain intelligence, without requiring API keys for most sources.

> **Legal use only.** This tool is designed for penetration testers, security researchers, and system administrators analyzing domains they own or have written authorization to test. Do not use it against systems you do not have permission to scan.

---

## What it does

DomainRecon runs a single scan and consolidates everything useful about a target domain, including DNS records, infrastructure details, security posture, reputation, and history. It aggregates public passive sources (such as crt.sh, AlienVault OTX, URLScan.io, and the Wayback Machine) and performs lightweight active checks (HTTP headers, TLS, and common ports). Results are accessible through a dark-themed web interface or a REST API.

Typical use cases include external security audits, bug bounty recon, initial penetration testing, and exposure monitoring.

---

## Capabilities

The application runs a wide range of modules categorized into four core areas:

*   **DNS and Infrastructure:** Resolves standard records (A, AAAA, MX, NS, TXT, CNAME, SOA, CAA) and performs passive subdomain discovery via HackerTarget, RapidDNS, AlienVault OTX, URLScan, and crt.sh. It also checks for zone transfers (AXFR), wildcard DNS, DNSSEC configuration, and resolves reverse DNS (PTR) records.
*   **Security Posture:** Evaluates TLS/SSL certificates for validity, legacy protocols, weak ciphers, and OCSP status. Checks for 7 essential OWASP security headers (CSP, HSTS, X-Frame-Options, etc.), cookie security flags (Secure, HttpOnly, SameSite), CORS misconfigurations, and detects the presence of WAFs or CDNs.
*   **Web and Tech Footprint:** Fingerprints frameworks and CMS versions (WordPress, Joomla, Drupal), parses web files (robots.txt, sitemaps, security.txt), reveals Spring Boot Actuator/GraphQL endpoints, performs homograph typosquatting checks, and maps external or linked scripts.
*   **OSINT and Threat Intel:** Runs threat intelligence queries using VirusTotal and AbuseIPDB, checks domain presence on 16 IP blacklists (DNSBL), reviews historical URL entries via URLScan.io and the Wayback Machine, scans JavaScript files for hardcoded secrets, and performs public repository searches for potential credential leaks (GitHub dorking).

---

## Installation

### Docker (Recommended)

Requires Docker and Docker Compose:

```bash
git clone https://github.com/w4ll-i/DomainRecon.git
cd DomainRecon
docker-compose up -d --build
```

The application will be accessible at http://localhost:9000. Data (including the SQLite database and captured screenshots) is persisted inside the `domainrecon_data` volume.

To stop the containers:

```bash
docker-compose down
```

### Local Setup

Requires Python 3.10 or higher:

```bash
git clone https://github.com/w4ll-i/DomainRecon.git
cd DomainRecon

python -m venv .venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate

pip install -r requirements.txt
python run.py
```

The application will open automatically in your default browser at http://localhost:9000.

To capture website screenshots, install Playwright:

```bash
pip install playwright
playwright install chromium
```

Without Playwright, the rest of the application functions normally, and the screenshot module will simply remain empty.

---

## Usage

### Web Interface

1. Open http://localhost:9000 in your browser.
2. Enter a domain (for example, example.com), select the Quick or Full profile, and click Scan.
3. Modules run in parallel (taking about 20 seconds for the Quick profile, and around 3 minutes for the Full profile).
4. Explore the results using the tabs: General, Security, Infrastructure, Web, and OSINT.
5. Export findings to JSON or PDF format.

### REST API

Detailed Swagger documentation is available at http://localhost:9000/api/docs.

Run a new scan:

```bash
curl -X POST http://localhost:9000/api/scan \
  -H "Content-Type: application/json" \
  -d '{"domain": "example.com", "profile": "full"}'
```

Retrieve a past scan by ID:

```bash
curl http://localhost:9000/api/scan/1
```

Get live scan progress via WebSockets:

Connect to `ws://localhost:9000/api/ws/scan` and send the payload:

```json
{"domain": "example.com", "profile": "full"}
```

---

## Security Scoring

The scoring engine evaluates six categories to compute a unified security score from 0 to 100:

*   **TLS (20 points):** Valid certificates, modern protocols, strong ciphers.
*   **Headers (20 points):** Proper implementation of security headers like CSP and HSTS.
*   **Email (15 points):** SPF, DKIM, and DMARC record verification, SMTP open relay detection.
*   **Reputation (15 points):** Checks against DNSBL blacklists and abuse databases.
*   **Infrastructure (15 points):** Closed ports, secure CORS policies, secure zone transfers.
*   **OSINT (15 points):** Absence of hardcoded secrets, admin panels, or risky HTTP methods.

Scans are graded from A+ (95-100) down to F (0-39).

---

## Optional API Keys

While most modules function out of the box, you can add credentials in the Settings panel of the web interface to enable advanced features:

*   **Shodan:** Detailed host indexing and open service mapping.
*   **VirusTotal / AlienVault OTX:** Deep threat intelligence and reputation checking.
*   **SecurityTrails / Censys:** Additional passive subdomain discovery and indexed host details.
*   **URLScan.io:** Private scans and history logs.
*   **BuiltWith:** Comprehensive technology stack analysis.
*   **AbuseIPDB:** Detailed IP reputation scores.
*   **CIRCL (Username/Password):** Historical passive DNS databases.
*   **IntelX:** Intelligence X searches for exposed credentials and leaks.
*   **Safe Browsing / PhishTank:** Phishing and malware blacklists.
*   **LeakIX:** Exposed services and leak detection.
*   **GitHub Token:** Higher rate limits for code leak searches.

---

## VPN Integration

DomainRecon supports Mullvad VPN to protect your scans:

*   **Local installation:** If the Mullvad CLI is installed on the host machine, you can connect, disconnect, and switch exit countries directly from the web UI.
*   **Docker:** Traffic routes through the host's VPN tunnel. On Linux hosts, the CLI binary can be mounted to enable dashboard controls inside the container.

---

## License

MIT. See [LICENSE](LICENSE).
