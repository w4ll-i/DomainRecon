# DomainRecon

<p align="center">
  <img src="https://i.ibb.co/HLGGw0X0/Logo-DR3.png" alt="DomainRecon" width="100">
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Python-3.10+-blue?logo=python&logoColor=white">
  <img src="https://img.shields.io/badge/FastAPI-0.115+-009688?logo=fastapi&logoColor=white">
  <img src="https://img.shields.io/badge/Docker-ready-2496ED?logo=docker&logoColor=white">
  <img src="https://img.shields.io/badge/modules-50%2B-blueviolet">
  <img src="https://img.shields.io/badge/license-MIT-green">
</p>

Plateforme OSINT de reconnaissance de domaines — **50+ modules** exécutés en parallèle, sans clé API requise pour la majorité des sources.

> **Usage légal uniquement.** Cet outil est destiné aux pentesters, chercheurs en sécurité et admins système analysant des domaines **dont ils ont l'autorisation**. Ne jamais l'utiliser sur des systèmes tiers sans autorisation écrite.

---

## Objectif

DomainRecon centralise en un seul scan toutes les informations utiles sur un domaine : DNS, infrastructure, sécurité, réputation, historique. L'outil agrège des sources passives publiques (crt.sh, AlienVault OTX, URLScan.io, Wayback Machine, etc.) et effectue des vérifications actives discrètes (headers HTTP, TLS, ports). Les résultats sont accessibles via une interface web dark minimaliste ou via l'API REST.

**Cas d'usage :** audits de sécurité externes, bug bounty, reconnaissance initiale, monitoring d'exposition.

---

## Modules

| # | Module | Type |
|---|--------|------|
| 1 | DNS Records (A, AAAA, MX, NS, TXT, CNAME, SOA, CAA, BIMI) | Passif DNS |
| 2 | Subdomain Discovery — 5 sources (crt.sh, HackerTarget, RapidDNS, OTX, URLScan) | Passif |
| 3 | Security Headers (7 headers OWASP) | Actif discret |
| 4 | TLS Certificate (validité, protocole, cipher, SAN, expiration) | Actif discret |
| 5 | Port Scanner (22 ports courants) | Actif |
| 6 | Geolocation (pays, ville, ASN via ip-api.com) | Passif |
| 7 | WHOIS (registrar, dates, statuts, NS) | Passif |
| 8 | Technology Detection (CMS, frameworks, CDN, analytics) | Actif discret |
| 9 | Email Security — SPF, DKIM (60+ sélecteurs), DMARC | Passif DNS |
| 10 | WAF Detection (14 WAF/CDN identifiables) | Actif discret |
| 11 | HTTP Redirect Chain | Actif discret |
| 12 | Web Files (robots.txt, sitemap.xml, security.txt, fichiers sensibles) | Actif discret |
| 13 | Cookie Security (Secure, HttpOnly, SameSite) | Actif discret |
| 14 | CORS Misconfiguration | Actif discret |
| 15 | Subdomain Takeover (32 services détectés) | Actif discret |
| 16 | Reverse DNS (PTR) | Passif DNS |
| 17 | Extended Network (reverse IP, ASN via ipinfo.io) | Passif |
| 18 | Security Score (0–100, grade A–F) | Calcul |
| 19 | Screenshot (Playwright headless — optionnel) | Actif discret |
| 20 | URLScan.io — historique des scans, IPs observées | 100% Passif |
| 21 | Wayback Machine — archives, première/dernière apparition | 100% Passif |
| 22 | Threat Intelligence — OTX reputation, passive DNS, malware families | 100% Passif |
| 23 | JS File Analysis — endpoints, patterns de secrets, APIs tierces | Actif discret |
| 24 | Favicon Hash — MurmurHash3 compatible Shodan/Censys | Actif discret |
| 25 | Linked Domains — trackers, scripts tiers, dépendances | Actif discret |
| 26 | Email Blacklist — vérification 10 DNSBL (Spamhaus, SpamCop, SORBS…) | Quasi-passif DNS |
| 27 | HSTS Preload — statut Chromium via hstspreload.org | 100% Passif |
| 28 | Zone Transfer — détection de transfert de zone DNS ouvert | Actif discret |
| 29 | Wildcard DNS — détection de wildcard DNS | Passif DNS |
| 30 | DNS Rebinding — détection de configurations vulnérables | Passif DNS |
| 31 | TLS Deep Scan — audit protocoles/ciphers, OCSP (full) | Actif discret |
| 32 | CSP Grading — notation de la Content-Security-Policy | Actif discret |
| 33 | HSTS Deep Analysis — audit strict-transport-security | Actif discret |
| 34 | Admin Panels — découverte de panneaux d'administration (full) | Actif |
| 35 | HTML Intelligence — emails, commentaires, formulaires cachés | Actif discret |
| 36 | HTTP Methods — détection de méthodes dangereuses (PUT, DELETE…) | Actif discret |
| 37 | SMTP Security — TLS, STARTTLS, AUTH (full) | Actif discret |
| 38 | Banner Grabbing — banners des ports ouverts | Actif |
| 39 | Typosquatting Detection — variantes homographes (full) | Passif DNS |
| 40 | Robtex — historique IP/DNS via Robtex | 100% Passif |
| 41 | Shodan — données d'indexation IP (clé API optionnelle) | 100% Passif |
| 42 | crt.sh Certificate Transparency — certificats émis | 100% Passif |
| 43 | CIRCL Passive DNS — historique DNS passif (credentials optionnels) | 100% Passif |
| 44 | BuiltWith — stack technologique enrichie (clé API optionnelle) | 100% Passif |
| 45 | BGPView — informations ASN/réseau (full) | 100% Passif |
| 46 | DAST-lite — tests de sécurité dynamiques légers (full) | Actif discret |
| 47 | Mozilla Observatory — audit headers de sécurité (full) | 100% Passif |
| 48 | Certificate Pinning — vérification du pinning TLS | Actif discret |
| 49 | EmailRep — réputation des adresses email découvertes | 100% Passif |
| 50 | AbuseIPDB — réputation IP (clé API optionnelle) | 100% Passif |

---

## Installation

### Docker (recommandé)

Prérequis : Docker + Docker Compose

```bash
git clone https://github.com/w4ll-i/DomainRecon.git
cd DomainRecon
docker-compose up -d --build
```

L'application démarre sur **http://localhost:8000**. Les données (SQLite + screenshots) sont persistées dans un volume Docker nommé `domainrecon_data`.

Pour arrêter :

```bash
docker-compose down
```

---

### Local (Python)

Prérequis : Python 3.10+

```bash
git clone https://github.com/w4ll-i/DomainRecon.git
cd DomainRecon

python -m venv .venv

# Windows
.venv\Scripts\activate
# Linux / macOS
source .venv/bin/activate

pip install -r requirements.txt

python run.py
```

L'application s'ouvre automatiquement sur **http://localhost:8000**.

**Screenshots (optionnel)** — nécessite Playwright :

```bash
pip install playwright
playwright install chromium
```

Sans Playwright, tous les autres modules fonctionnent normalement. Le module screenshot retournera simplement vide.

---

## Utilisation

### Interface web

1. Ouvrir **http://localhost:8000**
2. Entrer un domaine (ex: `example.com`), choisir le profil **Quick** ou **Full**, puis cliquer sur **Analyser**
3. Les modules s'exécutent en parallèle (~20s en Quick, ~3min en Full)
4. Naviguer via les onglets : Général / Sécurité / Infrastructure / Web / OSINT
5. Exporter en **JSON** ou **PDF**

### API REST

Documentation Swagger disponible sur **http://localhost:8000/api/docs**

```bash
# Lancer un scan (profil: "quick" ou "full")
curl -X POST http://localhost:8000/api/scan \
  -H "Content-Type: application/json" \
  -d '{"domain": "example.com", "profile": "full"}'

# Récupérer un scan par ID
curl http://localhost:8000/api/scan/1

# Historique paginé
curl "http://localhost:8000/api/history?limit=10&offset=0"

# Mettre à jour tags / notes
curl -X PATCH http://localhost:8000/api/scan/1/meta \
  -H "Content-Type: application/json" \
  -d '{"tags": ["pentest", "client"], "notes": "À investiguer"}'

# Supprimer un scan
curl -X DELETE http://localhost:8000/api/scan/1

# Timeline DNS d'un domaine
curl http://localhost:8000/api/dns-timeline/example.com
```

---

## Architecture

```
DomainRecon/
├── backend/
│   ├── migrate.py        # Migration idempotente de la base de données
│   └── app/
│       ├── main.py       # FastAPI — routes API, schémas Pydantic
│       ├── scanner.py    # Orchestrateur — 50+ modules async (2 vagues)
│       ├── models.py     # ORM SQLAlchemy
│       ├── database.py   # SQLite / PostgreSQL
│       └── scanners/     # Modules de scan (dns, tls, web, email, ports…)
├── frontend/
│   └── index.html        # SPA vanilla (HTML/CSS/JS)
├── data/
│   ├── domainrecon.db    # Base SQLite (auto-créée)
│   └── screenshots/      # Captures d'écran (auto-créé)
├── docker-compose.yml
├── run.py                # Lanceur local
└── requirements.txt
```

**Stack :** Python 3.10 · FastAPI · SQLAlchemy · SQLite · httpx · dnspython · Playwright (optionnel) · Chart.js · Cytoscape.js · Leaflet.js · jsPDF

---

## Score de sécurité

| Critère | Poids |
|---------|-------|
| Security Headers | 25 pts |
| TLS Certificate | 20 pts |
| Email Security (SPF/DKIM/DMARC) | 15 pts |
| WAF / CDN | 10 pts |
| Cookies | 10 pts |
| CORS | 10 pts |
| HTTPS Redirect | 5 pts |
| Subdomain Takeover | 5 pts |
| **Total** | **100 pts** |

Grades : **A** (90–100) · **B** (75–89) · **C** (55–74) · **D** (35–54) · **F** (0–34)

---

## Clés API (optionnelles)

Les modules suivants fonctionnent sans clé, mais peuvent être enrichis via la page **Paramètres** de l'interface :

| Service | Module enrichi | Sans clé |
|---------|---------------|----------|
| SecurityTrails | Subdomain Discovery (+6ème source) | 5 sources passives |
| Censys | Extended Network (détails hôte indexé) | ipinfo.io uniquement |
| URLScan.io | URLScan — scans privés + résultats étendus | Scans publics uniquement |
| Shodan | Données d'indexation IP enrichies | Désactivé |
| BuiltWith | Stack technologique détaillée | Désactivé |
| AbuseIPDB | Score de réputation IP | Désactivé |
| CIRCL (user/pass) | Passive DNS historique | Désactivé |
| VirusTotal | Threat Intelligence étendue | Sources OTX publiques |

Configurer les clés : `http://localhost:8000` → bouton **Paramètres** → section Clés API.

---

## Licence

MIT — voir [LICENSE](LICENSE).

---

<p align="center">
  <strong>DomainRecon</strong> — Built for security researchers 🔐<br>
  <em>50+ modules · Majority passive · Optional API keys · Legal OSINT only</em>
</p>
