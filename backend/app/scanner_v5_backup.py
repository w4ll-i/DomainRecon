# =============================================================================
# DomainRecon - Module de Scan OSINT v4.0
# =============================================================================
# 27 Modules :
#   DNS (+ CAA), Subdomains (5 sources passives), Security Headers, TLS,
#   Ports, Geolocation, WHOIS, Technology Detection (étendu), Email Security,
#   WAF Detection, Redirect Chain, Web Files (étendu), Cookie Analysis,
#   CORS Check, Subdomain Takeover, Reverse DNS, Extended Network,
#   Security Score, Screenshot,
#   --- NOUVEAUX ---
#   URLScan.io (passif), Wayback Machine (passif), Threat Intel OTX (passif),
#   JS Analysis (actif discret), Favicon Hash (Shodan), Linked Domains,
#   Email Blacklist DNSBL, HSTS Preload
# =============================================================================

import asyncio
import base64
import hashlib
import json
import re
import socket
import ssl
import struct
from datetime import datetime
from typing import Optional
from urllib.parse import urljoin, urlparse

import dns.resolver
import httpx
import tldextract
import whois


# =============================================================================
# Configuration
# =============================================================================

SECURITY_HEADERS = [
    "Strict-Transport-Security",
    "X-Frame-Options",
    "X-Content-Type-Options",
    "Content-Security-Policy",
    "X-XSS-Protection",
    "Referrer-Policy",
    "Permissions-Policy",
]

COMMON_PORTS = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP",
    53: "DNS", 80: "HTTP", 110: "POP3", 143: "IMAP",
    443: "HTTPS", 445: "SMB", 587: "SMTP/TLS", 993: "IMAPS",
    995: "POP3S", 3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL",
    5900: "VNC", 6379: "Redis", 8080: "HTTP-Proxy", 8443: "HTTPS-Alt",
    8888: "HTTP-Alt", 27017: "MongoDB",
}

DNS_RECORD_TYPES = ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA", "CAA"]

TECH_HEADER_SIGS = {
    "server": {
        "nginx": "Nginx", "apache": "Apache", "microsoft-iis": "Microsoft IIS",
        "cloudflare": "Cloudflare", "litespeed": "LiteSpeed",
        "openresty": "OpenResty", "caddy": "Caddy", "gunicorn": "Gunicorn",
        "envoy": "Envoy Proxy", "varnish": "Varnish Cache",
        "tomcat": "Apache Tomcat", "jetty": "Jetty", "webrick": "WEBrick",
        "iplanet": "Sun Java System", "zeus": "Zeus Web Server",
    },
    "x-powered-by": {
        "php": "PHP", "asp.net": "ASP.NET", "express": "Express.js",
        "next.js": "Next.js", "nuxt": "Nuxt.js", "flask": "Flask",
        "django": "Django", "rails": "Ruby on Rails", "laravel": "Laravel",
        "symfony": "Symfony", "fastapi": "FastAPI", "spring": "Spring Boot",
    },
    "x-generator": {
        "drupal": "Drupal", "joomla": "Joomla", "wordpress": "WordPress",
    },
}

TECH_BODY_SIGS = {
    "wp-content": ("WordPress", "CMS"),
    "wp-includes": ("WordPress", "CMS"),
    "/media/jui/": ("Joomla", "CMS"),
    "drupal.js": ("Drupal", "CMS"),
    "/sites/default/files": ("Drupal", "CMS"),
    "__NEXT_DATA__": ("Next.js", "Framework JS"),
    "__nuxt": ("Nuxt.js", "Framework JS"),
    "_nuxt/": ("Nuxt.js", "Framework JS"),
    "gatsby-": ("Gatsby", "Générateur"),
    "shopify": ("Shopify", "E-commerce"),
    "woocommerce": ("WooCommerce", "E-commerce"),
    "prestashop": ("PrestaShop", "E-commerce"),
    "magento": ("Magento", "E-commerce"),
    "opencart": ("OpenCart", "E-commerce"),
    "typo3": ("TYPO3", "CMS"),
    "contao": ("Contao", "CMS"),
    "craft cms": ("Craft CMS", "CMS"),
    "squarespace": ("Squarespace", "Builder"),
    "wix.com": ("Wix", "Builder"),
    "webflow": ("Webflow", "Builder"),
    "ghost.io": ("Ghost", "CMS"),
    "laravel": ("Laravel", "Framework PHP"),
    "symfony": ("Symfony", "Framework PHP"),
    "django": ("Django", "Framework Python"),
    "rails": ("Ruby on Rails", "Framework Ruby"),
    "react-app": ("Create React App", "Framework JS"),
    "svelte": ("Svelte", "Framework JS"),
    "ember": ("Ember.js", "Framework JS"),
    "backbone": ("Backbone.js", "Framework JS"),
}

# DKIM selectors étendus (60+)
DKIM_SELECTORS = [
    "default", "google", "selector1", "selector2", "selector3",
    "k1", "k2", "k3", "mail", "dkim", "s1", "s2", "s3",
    "protonmail", "protonmail2", "protonmail3", "pm1", "pm2", "pm3",
    "zoho", "amazonses", "ses", "mandrill", "sendgrid", "mailchimp",
    "mailjet", "smtp", "email", "mimecast", "mxvault", "postmark",
    "key1", "key2", "key3", "sig1", "sig2", "dkimkey",
    "m1", "m2", "x", "y", "z", "a", "b",
    "20161025", "20200301", "20210112", "20220601",
    "2020", "2021", "2022", "2023", "2024",
    "dkim1", "dkim2", "dk", "mx", "auth", "authenticate",
    "office365", "o365", "exchange", "gsuite", "workspace",
    "sparkpost", "mailgun", "sendpulse", "brevo", "sendinblue",
]

# Patterns de détection de secrets dans JS (patterns suspects seulement, pas les valeurs)
JS_SECRET_PATTERNS = [
    (r'(?i)(api[_-]?key|apikey)\s*[:=]\s*["\']([A-Za-z0-9_\-]{16,})["\']', "API Key"),
    (r'(?i)(secret[_-]?key|secretkey)\s*[:=]\s*["\']([A-Za-z0-9_\-]{16,})["\']', "Secret Key"),
    (r'(?i)(access[_-]?token)\s*[:=]\s*["\']([A-Za-z0-9_\-\.]{20,})["\']', "Access Token"),
    (r'(?i)(firebase[^"\']*)\s*[:=]\s*["\']([A-Za-z0-9_\-]{20,})["\']', "Firebase Key"),
    (r'AIza[0-9A-Za-z_\-]{35}', "Google API Key"),
    (r'(?i)aws[_\-]?(?:access[_\-]?key[_\-]?id|secret[_\-]?access[_\-]?key)\s*[:=]\s*["\']([^"\']+)["\']', "AWS Key"),
]

JS_ENDPOINT_PATTERNS = [
    r'(?:url|endpoint|path|href)\s*[:=]\s*["\']([/][^"\'<>\s]{2,100})["\']',
    r'fetch\(["\']([/][^"\'<>]{2,200})["\']',
    r'axios\.[a-z]+\(["\']([/][^"\'<>]{2,200})["\']',
    r'["\'](/api/[^"\'<>\s]{1,200})["\']',
    r'["\'](/v\d+/[^"\'<>\s]{1,200})["\']',
    r'["\'](/rest/[^"\'<>\s]{1,200})["\']',
    r'["\'](/graphql[^"\'<>\s]{0,100})["\']',
]

# DNSBL servers pour vérification blacklist email
DNSBL_SERVERS = [
    "zen.spamhaus.org",
    "bl.spamcop.net",
    "dnsbl.sorbs.net",
    "b.barracudacentral.org",
    "dnsbl-1.uceprotect.net",
    "spam.dnsbl.sorbs.net",
    "xbl.spamhaus.org",
    "pbl.spamhaus.org",
    "sbl.spamhaus.org",
    "cbl.abuseat.org",
]

# Domaines sociaux/CDN pour catégorisation
SOCIAL_DOMAINS = [
    "twitter.com", "x.com", "facebook.com", "linkedin.com",
    "instagram.com", "youtube.com", "github.com", "t.me",
    "tiktok.com", "reddit.com", "discord.com", "pinterest.com",
]
CDN_INDICATORS = ["cdn", "static", "assets", "media", "img", "js.", "css."]


# =============================================================================
# Utilitaires
# =============================================================================

def extract_domain(url_or_domain: str) -> str:
    """Extrait le domaine principal d'une URL ou d'un domaine."""
    stripped = url_or_domain.strip()
    extracted = tldextract.extract(stripped)
    return f"{extracted.domain}.{extracted.suffix}"


async def resolve_ip(domain: str) -> Optional[str]:
    """Résout l'adresse IP d'un domaine (async)."""
    loop = asyncio.get_event_loop()
    try:
        return await loop.run_in_executor(None, socket.gethostbyname, domain)
    except socket.gaierror:
        return None



def _mmh3_hash(data: bytes) -> int:
    """MurmurHash3 32-bit signé — compatible avec Shodan favicon search."""
    seed = 0
    c1 = 0xcc9e2d51
    c2 = 0x1b873593
    length = len(data)
    h1 = seed
    rounded_end = length & 0xFFFFFFFC

    for i in range(0, rounded_end, 4):
        k1 = int.from_bytes(data[i:i + 4], "little")
        k1 = (k1 * c1) & 0xFFFFFFFF
        k1 = ((k1 << 15) | (k1 >> 17)) & 0xFFFFFFFF
        k1 = (k1 * c2) & 0xFFFFFFFF
        h1 ^= k1
        h1 = ((h1 << 13) | (h1 >> 19)) & 0xFFFFFFFF
        h1 = (h1 * 5 + 0xe6546b64) & 0xFFFFFFFF

    tail = data[rounded_end:]
    k1 = 0
    if len(tail) >= 3:
        k1 ^= tail[2] << 16
    if len(tail) >= 2:
        k1 ^= tail[1] << 8
    if len(tail) >= 1:
        k1 ^= tail[0]
        k1 = (k1 * c1) & 0xFFFFFFFF
        k1 = ((k1 << 15) | (k1 >> 17)) & 0xFFFFFFFF
        k1 = (k1 * c2) & 0xFFFFFFFF
        h1 ^= k1

    h1 ^= length
    h1 ^= h1 >> 16
    h1 = (h1 * 0x85ebca6b) & 0xFFFFFFFF
    h1 ^= h1 >> 13
    h1 = (h1 * 0xc2b2ae35) & 0xFFFFFFFF
    h1 ^= h1 >> 16

    # Convert to signed 32-bit
    if h1 >= 0x80000000:
        h1 -= 0x100000000
    return h1


# =============================================================================
# Module 1 : DNS Records (dnspython)
# =============================================================================

def _scan_dns_sync(domain: str) -> dict:
    """Scan DNS synchrone - exécuté dans un thread."""
    records = {}
    resolver = dns.resolver.Resolver()
    resolver.timeout = 5
    resolver.lifetime = 5

    for rtype in DNS_RECORD_TYPES:
        try:
            answers = resolver.resolve(domain, rtype)
            if rtype == "MX":
                records[rtype] = [
                    {"priority": r.preference, "value": str(r.exchange).rstrip(".")}
                    for r in answers
                ]
            elif rtype == "SOA":
                soa = answers[0]
                records[rtype] = [{
                    "mname": str(soa.mname).rstrip("."),
                    "rname": str(soa.rname).rstrip("."),
                    "serial": soa.serial,
                    "refresh": soa.refresh,
                    "retry": soa.retry,
                    "expire": soa.expire,
                    "minimum": soa.minimum,
                }]
            elif rtype == "CAA":
                records[rtype] = [
                    {"flags": r.flags, "tag": r.tag.decode(), "value": r.value.decode()}
                    for r in answers
                ]
            else:
                records[rtype] = [str(r).strip('"') for r in answers]
        except Exception:
            records[rtype] = []

    # DMARC
    try:
        dmarc = resolver.resolve(f"_dmarc.{domain}", "TXT")
        records["DMARC"] = [str(r).strip('"') for r in dmarc]
    except Exception:
        records["DMARC"] = []

    # BIMI
    try:
        bimi = resolver.resolve(f"default._bimi.{domain}", "TXT")
        records["BIMI"] = [str(r).strip('"') for r in bimi]
    except Exception:
        records["BIMI"] = []

    return records


async def scan_dns_records(domain: str) -> dict:
    """Scan tous les enregistrements DNS d'un domaine."""
    loop = asyncio.get_event_loop()
    return await loop.run_in_executor(None, _scan_dns_sync, domain)


# =============================================================================
# Module 2 : Subdomain Discovery (5 sources passives)
# =============================================================================

async def find_subdomains(domain: str, securitytrails_key: Optional[str] = None) -> list:
    """Découverte de sous-domaines via 5 sources passives + SecurityTrails (optionnel).

    Sources : crt.sh (CT logs), HackerTarget, RapidDNS, AlienVault OTX, URLScan.io
    + SecurityTrails si clé configurée (historique DNS + subdomains étendus)
    Toutes ces sources sont 100% passives — aucun contact direct avec la cible.
    """
    subdomains: set = set()

    async def _crtsh():
        try:
            async with httpx.AsyncClient(timeout=15.0) as client:
                resp = await client.get(
                    f"https://crt.sh/?q=%.{domain}&output=json",
                    headers={"User-Agent": "DomainRecon/4.0"},
                )
                if resp.status_code == 200:
                    for entry in resp.json():
                        for line in entry.get("name_value", "").split("\n"):
                            line = line.strip().lower()
                            if line and not line.startswith("*") and line.endswith(f".{domain}"):
                                subdomains.add(line)
        except Exception:
            pass

    async def _hackertarget():
        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                resp = await client.get(
                    f"https://api.hackertarget.com/hostsearch/?q={domain}",
                    headers={"User-Agent": "DomainRecon/4.0"},
                )
                if resp.status_code == 200 and "error" not in resp.text[:50].lower():
                    for line in resp.text.strip().splitlines():
                        parts = line.split(",")
                        if parts and parts[0].strip().endswith(f".{domain}"):
                            subdomains.add(parts[0].strip().lower())
        except Exception:
            pass

    async def _rapiddns():
        try:
            async with httpx.AsyncClient(timeout=12.0, follow_redirects=True) as client:
                resp = await client.get(
                    f"https://rapiddns.io/subdomain/{domain}?full=1&down=1",
                    headers={"User-Agent": "Mozilla/5.0 (compatible; DomainRecon/4.0)"},
                )
                if resp.status_code == 200:
                    for m in re.findall(
                        r'<td>([a-zA-Z0-9._-]+\.' + re.escape(domain) + r')</td>',
                        resp.text
                    ):
                        subdomains.add(m.lower())
        except Exception:
            pass

    async def _alienvault():
        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                resp = await client.get(
                    f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns",
                    headers={"User-Agent": "DomainRecon/4.0"},
                )
                if resp.status_code == 200:
                    for entry in resp.json().get("passive_dns", []):
                        h = entry.get("hostname", "")
                        if h and h.endswith(f".{domain}"):
                            subdomains.add(h.lower())
        except Exception:
            pass

    async def _urlscan():
        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                resp = await client.get(
                    f"https://urlscan.io/api/v1/search/?q=domain:{domain}&size=200",
                    headers={"User-Agent": "DomainRecon/4.0"},
                )
                if resp.status_code == 200:
                    for result in resp.json().get("results", []):
                        pd = result.get("page", {}).get("domain", "")
                        if pd and pd.endswith(f".{domain}"):
                            subdomains.add(pd.lower())
        except Exception:
            pass

    async def _securitytrails():
        if not securitytrails_key:
            return
        try:
            async with httpx.AsyncClient(timeout=12.0) as client:
                resp = await client.get(
                    f"https://api.securitytrails.com/v1/domain/{domain}/subdomains",
                    headers={"APIKEY": securitytrails_key, "User-Agent": "DomainRecon/5.0"},
                )
                if resp.status_code == 200:
                    for sub in resp.json().get("subdomains", []):
                        full = f"{sub}.{domain}".lower()
                        subdomains.add(full)
        except Exception:
            pass

    await asyncio.gather(
        _crtsh(), _hackertarget(), _rapiddns(), _alienvault(), _urlscan(), _securitytrails(),
        return_exceptions=True,
    )

    subdomains.discard(domain)
    subdomain_list = sorted(subdomains)[:50]

    async def resolve_sub(sub: str):
        ip = await resolve_ip(sub)
        return {"subdomain": sub, "ip": ip}

    results = await asyncio.gather(*[resolve_sub(s) for s in subdomain_list])
    return list(results)


# =============================================================================
# Module 3 : Security Headers
# =============================================================================

async def check_security_headers(domain: str) -> dict:
    """Analyse les headers de sécurité HTTP selon les recommandations OWASP."""
    result = {
        "headers_found": {},
        "headers_missing": [],
        "score": "0/7",
        "error": None,
    }

    async with httpx.AsyncClient(
        timeout=10.0, follow_redirects=True, verify=False
    ) as client:
        for url in [f"https://{domain}", f"http://{domain}"]:
            try:
                response = await client.head(url)
                for header in SECURITY_HEADERS:
                    value = response.headers.get(header)
                    if value:
                        result["headers_found"][header] = value
                    else:
                        result["headers_missing"].append(header)
                found = len(result["headers_found"])
                result["score"] = f"{found}/{len(SECURITY_HEADERS)}"
                return result
            except Exception as e:
                result["error"] = str(e)

    result["headers_missing"] = SECURITY_HEADERS.copy()
    return result


# =============================================================================
# Module 4 : TLS Certificate
# =============================================================================

def _check_tls_sync(domain: str) -> dict:
    """Analyse TLS synchrone - exécuté dans un thread."""
    try:
        context = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                protocol = ssock.version()
                cipher = ssock.cipher()

                subject = dict(x[0] for x in cert.get("subject", ()))
                issuer = dict(x[0] for x in cert.get("issuer", ()))

                not_before = cert.get("notBefore", "")
                not_after = cert.get("notAfter", "")

                days_remaining = None
                try:
                    expiry = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
                    days_remaining = (expiry - datetime.utcnow()).days
                except Exception:
                    pass

                return {
                    "subject": subject.get("commonName", ""),
                    "issuer_org": issuer.get("organizationName", ""),
                    "issuer_cn": issuer.get("commonName", ""),
                    "serial_number": cert.get("serialNumber", ""),
                    "version": cert.get("version", ""),
                    "not_before": not_before,
                    "not_after": not_after,
                    "days_remaining": days_remaining,
                    "san": [entry[1] for entry in cert.get("subjectAltName", ())],
                    "protocol": protocol,
                    "cipher": cipher[0] if cipher else None,
                    "cipher_bits": cipher[2] if cipher else None,
                    "error": None,
                }
    except Exception as e:
        return {"error": str(e)}


async def check_tls_certificate(domain: str) -> dict:
    """Analyse le certificat TLS/SSL d'un domaine."""
    loop = asyncio.get_event_loop()
    return await loop.run_in_executor(None, _check_tls_sync, domain)


# =============================================================================
# Module 5 : Port Scanner
# =============================================================================


async def _check_port(ip: str, port: int, timeout: float = 2.0) -> Optional[dict]:
    """Test de connexion à un port."""
    try:
        _, writer = await asyncio.wait_for(
            asyncio.open_connection(ip, port),
            timeout=timeout,
        )
        writer.close()
        await writer.wait_closed()
        return {
            "port": port,
            "state": "open",
            "service": COMMON_PORTS.get(port, "unknown"),
        }
    except Exception:
        return None


async def scan_ports(ip: str) -> list:
    """Scan les ports communs d'une IP."""
    if not ip:
        return []
    tasks = [_check_port(ip, port) for port in COMMON_PORTS.keys()]
    results = await asyncio.gather(*tasks)
    return [r for r in results if r is not None]


# =============================================================================
# Module 6 : Geolocation (ip-api.com)
# =============================================================================

async def get_geo_data(ip: str) -> dict:
    """Géolocalise une IP via ip-api.com (gratuit, pas de clé)."""
    if not ip:
        return {}

    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            resp = await client.get(f"http://ip-api.com/json/{ip}")
            if resp.status_code == 200:
                data = resp.json()
                if data.get("status") == "success":
                    return {
                        "ip": ip,
                        "country": data.get("country", ""),
                        "country_code": data.get("countryCode", ""),
                        "region": data.get("regionName", ""),
                        "city": data.get("city", ""),
                        "zip": data.get("zip", ""),
                        "lat": data.get("lat", 0),
                        "lon": data.get("lon", 0),
                        "timezone": data.get("timezone", ""),
                        "isp": data.get("isp", ""),
                        "org": data.get("org", ""),
                        "as_info": data.get("as", ""),
                    }
    except Exception:
        pass
    return {}


# =============================================================================
# Module 7 : WHOIS
# =============================================================================

def _get_whois_sync(domain: str) -> dict:
    """Requête WHOIS synchrone - exécuté dans un thread."""
    try:
        w = whois.whois(domain)

        def format_date(date_val):
            if isinstance(date_val, list):
                return str(date_val[0]) if date_val else None
            return str(date_val) if date_val else None

        return {
            "registrar": w.registrar,
            "creation_date": format_date(w.creation_date),
            "expiration_date": format_date(w.expiration_date),
            "updated_date": format_date(getattr(w, "updated_date", None)),
            "name_servers": (
                w.name_servers if isinstance(w.name_servers, list)
                else [w.name_servers] if w.name_servers else []
            ),
            "status": (
                w.status if isinstance(w.status, list)
                else [w.status] if w.status else []
            ),
            "dnssec": getattr(w, "dnssec", None),
            "registrant": getattr(w, "org", None),
            "emails": (
                w.emails if isinstance(getattr(w, "emails", None), list)
                else [w.emails] if getattr(w, "emails", None) else []
            ),
            "error": None,
        }
    except Exception as e:
        return {
            "registrar": None, "creation_date": None,
            "expiration_date": None, "updated_date": None,
            "name_servers": [], "status": [],
            "dnssec": None, "registrant": None, "emails": [],
            "error": str(e),
        }


async def get_whois_data(domain: str) -> dict:
    """Récupère les informations WHOIS d'un domaine."""
    loop = asyncio.get_event_loop()
    return await loop.run_in_executor(None, _get_whois_sync, domain)


# =============================================================================
# Module 8 : Technology Detection (étendu)
# =============================================================================

async def detect_technologies(domain: str) -> list:
    """Détecte les technologies utilisées par un site web (signatures étendues)."""
    technologies = []
    seen = set()

    def add_tech(name: str, category: str):
        key = name.lower()
        if key not in seen:
            seen.add(key)
            technologies.append({"name": name, "category": category})

    async with httpx.AsyncClient(
        timeout=10.0, follow_redirects=True, verify=False
    ) as client:
        for url in [f"https://{domain}", f"http://{domain}"]:
            try:
                response = await client.get(url)
                headers = response.headers
                body = response.text[:20000]
                body_lower = body.lower()

                # --- Headers ---
                for header_name, signatures in TECH_HEADER_SIGS.items():
                    header_value = headers.get(header_name, "").lower()
                    if header_value:
                        matched = False
                        for sig, tech_name in signatures.items():
                            if sig in header_value:
                                cat = "Serveur Web" if header_name == "server" else "Framework"
                                add_tech(tech_name, cat)
                                matched = True
                        if not matched:
                            cat = "Serveur Web" if header_name == "server" else "Framework"
                            add_tech(headers.get(header_name, ""), cat)

                # --- Body signatures ---
                for sig, (tech_name, cat) in TECH_BODY_SIGS.items():
                    if sig.lower() in body_lower:
                        add_tech(tech_name, cat)

                # --- Meta generator ---
                gen_match = re.search(
                    r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']([^"\']+)["\']',
                    body, re.I,
                )
                if gen_match:
                    add_tech(gen_match.group(1).strip(), "Générateur")

                # --- JS Frameworks ---
                if "jquery" in body_lower:
                    add_tech("jQuery", "Librairie JS")
                if "bootstrap" in body_lower:
                    add_tech("Bootstrap", "Framework CSS")
                if "tailwind" in body_lower:
                    add_tech("Tailwind CSS", "Framework CSS")
                if "bulma" in body_lower:
                    add_tech("Bulma", "Framework CSS")
                if "foundation" in body_lower:
                    add_tech("Foundation", "Framework CSS")
                if "react" in body_lower and "reactdom" in body_lower.replace("-", "").replace(".", ""):
                    add_tech("React", "Framework JS")
                if "vue.js" in body_lower or "vue.min.js" in body_lower or "vue@" in body_lower:
                    add_tech("Vue.js", "Framework JS")
                if "angular" in body_lower and ("ng-app" in body_lower or "ng-version" in body_lower):
                    add_tech("Angular", "Framework JS")
                if "alpine" in body_lower and "x-data" in body_lower:
                    add_tech("Alpine.js", "Framework JS")
                if "htmx" in body_lower:
                    add_tech("HTMX", "Librairie JS")
                if "three.js" in body_lower or "threejs" in body_lower:
                    add_tech("Three.js", "Graphique 3D")

                # --- Analytics / Tracking ---
                if "google-analytics.com" in body_lower or "gtag(" in body or "ga(" in body:
                    add_tech("Google Analytics", "Analytics")
                if "googletagmanager" in body_lower:
                    add_tech("Google Tag Manager", "Tag Manager")
                if "hotjar" in body_lower:
                    add_tech("Hotjar", "Analytics")
                if "matomo" in body_lower or "piwik" in body_lower:
                    add_tech("Matomo", "Analytics")
                if "mixpanel" in body_lower:
                    add_tech("Mixpanel", "Analytics")
                if "segment.com" in body_lower or "analytics.js" in body_lower:
                    add_tech("Segment", "Analytics")
                if "intercom" in body_lower:
                    add_tech("Intercom", "Support")
                if "zendesk" in body_lower:
                    add_tech("Zendesk", "Support")
                if "crisp.chat" in body_lower:
                    add_tech("Crisp", "Support")
                if "sentry.io" in body_lower or "sentry" in body_lower:
                    add_tech("Sentry", "Monitoring")

                # --- CDN ---
                if "cloudflare" in body_lower:
                    add_tech("Cloudflare CDN", "CDN")
                if "cdn.jsdelivr.net" in body_lower:
                    add_tech("jsDelivr", "CDN")
                if "cdnjs.cloudflare.com" in body_lower:
                    add_tech("cdnjs", "CDN")
                if "akamai" in body_lower:
                    add_tech("Akamai", "CDN")
                if "fastly.net" in body_lower:
                    add_tech("Fastly", "CDN")

                # HTTP/2 detection via header
                protocol_version = getattr(response, "http_version", None)
                if protocol_version == "HTTP/2":
                    add_tech("HTTP/2", "Protocole")
                elif protocol_version == "HTTP/3":
                    add_tech("HTTP/3", "Protocole")

                break
            except Exception:
                continue

    return technologies


# =============================================================================
# Module 9 : Email Security (SPF/DKIM/DMARC Analysis)
# =============================================================================

def _analyze_email_security_sync(domain: str) -> dict:
    """Analyse approfondie de la sécurité email - SPF, DKIM, DMARC."""
    resolver = dns.resolver.Resolver()
    resolver.timeout = 3
    resolver.lifetime = 3

    result = {
        "spf": {"found": False, "record": None, "issues": [], "grade": "F"},
        "dmarc": {"found": False, "record": None, "policy": None, "issues": [], "grade": "F"},
        "dkim": {"found": False, "selectors_found": [], "issues": []},
        "overall_grade": "F",
        "recommendations": [],
    }

    # --- SPF ---
    try:
        txt_records = resolver.resolve(domain, "TXT")
        for record in txt_records:
            txt = str(record).strip('"')
            if txt.startswith("v=spf1"):
                result["spf"]["found"] = True
                result["spf"]["record"] = txt
                issues = []
                if "+all" in txt:
                    issues.append("SPF avec +all (tout le monde peut envoyer)")
                elif "~all" in txt:
                    issues.append("SPF softfail (~all) — préférer -all")
                elif "?all" in txt:
                    issues.append("SPF neutral (?all) — non protecteur")
                elif "-all" in txt:
                    result["spf"]["grade"] = "A"
                if "redirect=" in txt:
                    issues.append("SPF utilise une redirection")
                if txt.count("include:") > 10:
                    issues.append("Trop de lookups SPF (>10 risque de dépasser la limite)")
                result["spf"]["issues"] = issues
                if not issues:
                    result["spf"]["grade"] = "A"
                elif any("all" in i and "+" in i for i in issues):
                    result["spf"]["grade"] = "F"
                else:
                    result["spf"]["grade"] = "B"
                break
    except Exception:
        result["spf"]["issues"].append("Aucun enregistrement SPF trouvé")

    # --- DMARC ---
    try:
        dmarc_records = resolver.resolve(f"_dmarc.{domain}", "TXT")
        for record in dmarc_records:
            txt = str(record).strip('"')
            if "v=DMARC1" in txt:
                result["dmarc"]["found"] = True
                result["dmarc"]["record"] = txt
                issues = []
                policy_match = re.search(r'p=(\w+)', txt)
                if policy_match:
                    policy = policy_match.group(1)
                    result["dmarc"]["policy"] = policy
                    if policy == "none":
                        issues.append("Politique DMARC 'none' — pas de protection")
                        result["dmarc"]["grade"] = "D"
                    elif policy == "quarantine":
                        result["dmarc"]["grade"] = "B"
                    elif policy == "reject":
                        result["dmarc"]["grade"] = "A"
                pct_match = re.search(r'pct=(\d+)', txt)
                if pct_match and int(pct_match.group(1)) < 100:
                    issues.append(f"Seulement {pct_match.group(1)}% des mails couverts")
                if "rua=" not in txt:
                    issues.append("Pas de rapport agrégé (rua= manquant)")
                result["dmarc"]["issues"] = issues
                break
    except Exception:
        result["dmarc"]["issues"].append("Aucun enregistrement DMARC trouvé")

    # --- DKIM (test des sélecteurs — liste étendue) ---
    for sel in DKIM_SELECTORS:
        try:
            resolver.resolve(f"{sel}._domainkey.{domain}", "TXT")
            result["dkim"]["found"] = True
            result["dkim"]["selectors_found"].append(sel)
        except Exception:
            continue

    if not result["dkim"]["found"]:
        result["dkim"]["issues"].append("Aucun sélecteur DKIM standard trouvé")

    # --- Score global ---
    scores = {"A": 4, "B": 3, "C": 2, "D": 1, "F": 0}
    total = scores.get(result["spf"]["grade"], 0) + scores.get(result["dmarc"]["grade"], 0)
    if result["dkim"]["found"]:
        total += 3
    avg = total / 3
    if avg >= 3.5:
        result["overall_grade"] = "A"
    elif avg >= 2.5:
        result["overall_grade"] = "B"
    elif avg >= 1.5:
        result["overall_grade"] = "C"
    elif avg >= 0.5:
        result["overall_grade"] = "D"
    else:
        result["overall_grade"] = "F"

    if not result["spf"]["found"]:
        result["recommendations"].append("Ajouter un enregistrement SPF")
    if not result["dmarc"]["found"]:
        result["recommendations"].append("Ajouter un enregistrement DMARC")
    elif result["dmarc"]["policy"] == "none":
        result["recommendations"].append("Passer la politique DMARC de 'none' à 'quarantine' ou 'reject'")
    if not result["dkim"]["found"]:
        result["recommendations"].append("Configurer DKIM pour signer les emails")

    return result


async def analyze_email_security(domain: str) -> dict:
    """Analyse de sécurité email (SPF/DKIM/DMARC)."""
    loop = asyncio.get_event_loop()
    return await loop.run_in_executor(None, _analyze_email_security_sync, domain)


# =============================================================================
# Module 10 : WAF Detection
# =============================================================================

WAF_SIGNATURES = {
    "Cloudflare": {
        "headers": {"server": "cloudflare", "cf-ray": ""},
        "cookies": ["__cfduid", "__cf_bm", "cf_clearance"],
    },
    "AWS WAF": {
        "headers": {"x-amzn-requestid": "", "x-amz-cf-id": ""},
        "cookies": ["awsalb", "awsalbcors"],
    },
    "Akamai": {
        "headers": {"x-akamai-transformed": "", "server": "akamaighost"},
        "cookies": ["akacd_", "akaalb_"],
    },
    "Sucuri": {
        "headers": {"server": "sucuri", "x-sucuri-id": ""},
        "cookies": ["sucuri_cloudproxy"],
    },
    "Imperva/Incapsula": {
        "headers": {"x-cdn": "incapsula", "x-iinfo": ""},
        "cookies": ["incap_ses_", "visid_incap_"],
    },
    "F5 BIG-IP": {
        "headers": {"server": "big-ip", "x-wa-info": ""},
        "cookies": ["bigipserver", "f5_cspm"],
    },
    "Barracuda": {
        "headers": {"server": "barracuda"},
        "cookies": ["barra_counter_session"],
    },
    "ModSecurity": {
        "headers": {"server": "mod_security"},
        "cookies": [],
    },
    "DDoS-Guard": {
        "headers": {"server": "ddos-guard"},
        "cookies": ["__ddg1_", "__ddg2_"],
    },
    "Fastly": {
        "headers": {"x-fastly-request-id": "", "via": "varnish"},
        "cookies": [],
    },
    "Azure Front Door": {
        "headers": {"x-azure-ref": ""},
        "cookies": [],
    },
    "Google Cloud Armor": {
        "headers": {"server": "gws", "via": "google"},
        "cookies": [],
    },
    "Nginx WAF": {
        "headers": {"x-nginx-cache": ""},
        "cookies": [],
    },
    "Wordfence": {
        "headers": {},
        "cookies": ["wfvt_", "wordfence"],
    },
}


async def detect_waf(domain: str) -> dict:
    """Détecte la présence d'un WAF/CDN."""
    result = {
        "detected": False,
        "waf_name": None,
        "confidence": "none",
        "evidence": [],
    }

    async with httpx.AsyncClient(
        timeout=10.0, follow_redirects=True, verify=False
    ) as client:
        for url in [f"https://{domain}", f"http://{domain}"]:
            try:
                response = await client.get(url)
                headers = {k.lower(): v.lower() for k, v in response.headers.items()}
                cookies = [c.lower() for c in response.cookies.keys()]

                for waf_name, sigs in WAF_SIGNATURES.items():
                    evidence = []
                    for header_key, header_val in sigs["headers"].items():
                        if header_key in headers:
                            if not header_val or header_val in headers[header_key]:
                                evidence.append(f"Header: {header_key}")
                    for cookie_sig in sigs["cookies"]:
                        for cookie in cookies:
                            if cookie_sig.lower() in cookie:
                                evidence.append(f"Cookie: {cookie}")

                    if evidence:
                        result["detected"] = True
                        result["waf_name"] = waf_name
                        result["evidence"] = evidence
                        result["confidence"] = "high" if len(evidence) >= 2 else "medium"
                        return result

                waf_headers = ["x-waf-event", "x-waf-status", "x-firewall", "x-waf-score"]
                for wh in waf_headers:
                    if wh in headers:
                        result["detected"] = True
                        result["waf_name"] = "WAF Inconnu"
                        result["evidence"] = [f"Header: {wh}"]
                        result["confidence"] = "low"
                        return result

                return result
            except Exception:
                continue

    return result


# =============================================================================
# Module 11 : HTTP Redirect Chain
# =============================================================================

async def trace_redirects(domain: str) -> dict:
    """Trace la chaîne de redirections HTTP."""
    chain = []

    async with httpx.AsyncClient(
        timeout=10.0, follow_redirects=False, verify=False
    ) as client:
        url = f"http://{domain}"
        max_hops = 10

        for i in range(max_hops):
            try:
                response = await client.get(url)
                entry = {
                    "url": str(url),
                    "status_code": response.status_code,
                    "server": response.headers.get("server", ""),
                }
                chain.append(entry)

                if response.is_redirect or response.status_code in (301, 302, 303, 307, 308):
                    location = response.headers.get("location", "")
                    if location:
                        if location.startswith("/"):
                            parsed = urlparse(str(url))
                            location = f"{parsed.scheme}://{parsed.netloc}{location}"
                        url = location
                    else:
                        break
                else:
                    break
            except Exception as e:
                chain.append({"url": str(url), "status_code": 0, "error": str(e)})
                break

    return {
        "chain": chain,
        "total_hops": len(chain) - 1 if chain else 0,
        "forces_https": any("https://" in c.get("url", "") for c in chain[1:]) if len(chain) > 1 else False,
        "final_url": chain[-1]["url"] if chain else None,
    }


# =============================================================================
# Module 12 : Web Files (étendu — fichiers sensibles inclus)
# =============================================================================
# ⚠️  AVERTISSEMENT : Ce module effectue des requêtes GET sur des chemins
#     publics standard. La détection de fichiers exposés (.env, .git/HEAD,
#     etc.) est une pratique légale de reconnaissance défensive. Ne jamais
#     télécharger ou exploiter le contenu de fichiers sensibles découverts.
# =============================================================================

SENSITIVE_PATHS = [
    ("/.git/HEAD", "git_exposed", "Dépôt Git exposé — CRITIQUE"),
    ("/.env", "env_exposed", "Fichier .env exposé — CRITIQUE"),
    ("/.env.local", "env_exposed", "Fichier .env.local exposé — CRITIQUE"),
    ("/.env.production", "env_exposed", "Fichier .env.production exposé — CRITIQUE"),
    ("/.htaccess", "htaccess_exposed", "Fichier .htaccess exposé"),
    ("/wp-config.php", "wpconfig_exposed", "wp-config.php accessible — CRITIQUE"),
    ("/phpinfo.php", "phpinfo_exposed", "phpinfo.php exposé"),
    ("/config.php", "config_exposed", "config.php exposé"),
    ("/config.json", "config_exposed", "config.json exposé"),
    ("/composer.json", "composer_exposed", "composer.json exposé"),
    ("/package.json", "package_exposed", "package.json exposé"),
    ("/humans.txt", "humans_txt", "humans.txt présent"),
    ("/ads.txt", "ads_txt", "ads.txt présent"),
    ("/app-ads.txt", "app_ads_txt", "app-ads.txt présent"),
    ("/manifest.json", "manifest", "manifest.json présent"),
    ("/.well-known/openid-configuration", "oidc_config", "OpenID Connect exposé"),
    ("/.well-known/change-password", "change_password", "Change-password endpoint"),
    ("/crossdomain.xml", "crossdomain", "crossdomain.xml présent"),
    ("/clientaccesspolicy.xml", "clientaccess", "clientaccesspolicy.xml présent"),
]


async def check_web_files(domain: str) -> dict:
    """Vérifie robots.txt, sitemap.xml, security.txt + fichiers sensibles."""
    result = {
        "robots_txt": {"found": False, "content": None, "disallowed": [], "sitemaps": []},
        "sitemap_xml": {"found": False, "url_count": 0},
        "security_txt": {"found": False, "content": None, "contact": None},
        "sensitive_files": [],
    }

    async with httpx.AsyncClient(
        timeout=8.0, follow_redirects=True, verify=False
    ) as client:
        # robots.txt
        for proto in ["https", "http"]:
            try:
                resp = await client.get(f"{proto}://{domain}/robots.txt")
                if resp.status_code == 200 and "user-agent" in resp.text.lower():
                    result["robots_txt"]["found"] = True
                    content = resp.text[:3000]
                    result["robots_txt"]["content"] = content
                    for line in content.splitlines():
                        line = line.strip()
                        if line.lower().startswith("disallow:"):
                            path = line.split(":", 1)[1].strip()
                            if path:
                                result["robots_txt"]["disallowed"].append(path)
                        elif line.lower().startswith("sitemap:"):
                            result["robots_txt"]["sitemaps"].append(line.split(":", 1)[1].strip())
                    break
            except Exception:
                continue

        # sitemap.xml
        for proto in ["https", "http"]:
            try:
                resp = await client.get(f"{proto}://{domain}/sitemap.xml")
                if resp.status_code == 200 and ("<?xml" in resp.text[:100] or "<urlset" in resp.text[:200]):
                    result["sitemap_xml"]["found"] = True
                    result["sitemap_xml"]["url_count"] = resp.text.count("<loc>")
                    break
            except Exception:
                continue

        # security.txt
        for path in ["/.well-known/security.txt", "/security.txt"]:
            for proto in ["https", "http"]:
                try:
                    resp = await client.get(f"{proto}://{domain}{path}")
                    if resp.status_code == 200 and ("contact:" in resp.text.lower() or "policy:" in resp.text.lower()):
                        result["security_txt"]["found"] = True
                        result["security_txt"]["content"] = resp.text[:2000]
                        for line in resp.text.splitlines():
                            if line.lower().startswith("contact:"):
                                result["security_txt"]["contact"] = line.split(":", 1)[1].strip()
                                break
                        break
                except Exception:
                    continue
            if result["security_txt"]["found"]:
                break

        # Fichiers sensibles
        for path, key, description in SENSITIVE_PATHS:
            for proto in ["https", "http"]:
                try:
                    resp = await client.get(f"{proto}://{domain}{path}", timeout=5.0)
                    if resp.status_code == 200 and len(resp.text) > 5:
                        severity = "critical" if "CRITIQUE" in description else "info"
                        result["sensitive_files"].append({
                            "path": path,
                            "key": key,
                            "description": description,
                            "severity": severity,
                            "size": len(resp.content),
                        })
                        break
                except Exception:
                    continue

    return result


# =============================================================================
# Module 13 : Cookie Security Analysis
# =============================================================================

async def analyze_cookies(domain: str) -> dict:
    """Analyse la sécurité des cookies HTTP."""
    result = {"cookies": [], "issues": [], "score": "N/A"}

    async with httpx.AsyncClient(
        timeout=10.0, follow_redirects=True, verify=False
    ) as client:
        for url in [f"https://{domain}", f"http://{domain}"]:
            try:
                response = await client.get(url)
                set_cookie_headers = [
                    v for k, v in response.headers.multi_items()
                    if k.lower() == "set-cookie"
                ]

                if not set_cookie_headers:
                    result["score"] = "N/A"
                    return result

                total_issues = 0
                for raw_cookie in set_cookie_headers:
                    cookie_info = {
                        "name": "",
                        "secure": False,
                        "httponly": False,
                        "samesite": None,
                        "path": "/",
                        "issues": [],
                    }
                    parts = raw_cookie.split(";")
                    if parts:
                        name_val = parts[0].strip().split("=", 1)
                        cookie_info["name"] = name_val[0].strip()

                    raw_lower = raw_cookie.lower()
                    cookie_info["secure"] = "secure" in raw_lower
                    cookie_info["httponly"] = "httponly" in raw_lower

                    ss_match = re.search(r'samesite=(\w+)', raw_lower)
                    cookie_info["samesite"] = ss_match.group(1) if ss_match else None

                    if not cookie_info["secure"]:
                        cookie_info["issues"].append("Pas de flag Secure")
                        total_issues += 1
                    if not cookie_info["httponly"]:
                        cookie_info["issues"].append("Pas de flag HttpOnly")
                        total_issues += 1
                    if not cookie_info["samesite"]:
                        cookie_info["issues"].append("Pas de SameSite")
                        total_issues += 1
                    elif cookie_info["samesite"] == "none" and not cookie_info["secure"]:
                        cookie_info["issues"].append("SameSite=None sans Secure")
                        total_issues += 1

                    result["cookies"].append(cookie_info)

                max_issues = len(result["cookies"]) * 3
                if max_issues > 0:
                    ratio = 1 - (total_issues / max_issues)
                    if ratio >= 0.9:
                        result["score"] = "A"
                    elif ratio >= 0.7:
                        result["score"] = "B"
                    elif ratio >= 0.5:
                        result["score"] = "C"
                    else:
                        result["score"] = "D"

                return result
            except Exception:
                continue

    return result


# =============================================================================
# Module 14 : CORS Misconfiguration Check
# =============================================================================

async def check_cors(domain: str) -> dict:
    """Vérifie les erreurs de configuration CORS."""
    result = {
        "cors_enabled": False,
        "misconfigured": False,
        "allows_any_origin": False,
        "allows_credentials_with_wildcard": False,
        "reflects_origin": False,
        "details": [],
    }

    test_origins = [
        "https://evil.com",
        "https://attacker.example.com",
        f"https://{domain}.evil.com",
        "null",
    ]

    async with httpx.AsyncClient(
        timeout=8.0, follow_redirects=True, verify=False
    ) as client:
        for url in [f"https://{domain}", f"http://{domain}"]:
            try:
                resp = await client.get(url)
                acao = resp.headers.get("access-control-allow-origin", "")
                if acao:
                    result["cors_enabled"] = True
                    if acao == "*":
                        result["allows_any_origin"] = True
                        result["details"].append("Access-Control-Allow-Origin: * (ouvert à tous)")
                        acac = resp.headers.get("access-control-allow-credentials", "")
                        if acac.lower() == "true":
                            result["allows_credentials_with_wildcard"] = True
                            result["misconfigured"] = True
                            result["details"].append("CRITIQUE: Credentials avec wildcard origin")

                for test_origin in test_origins:
                    try:
                        resp2 = await client.get(url, headers={"Origin": test_origin})
                        reflected_origin = resp2.headers.get("access-control-allow-origin", "")
                        if reflected_origin == test_origin:
                            result["reflects_origin"] = True
                            result["misconfigured"] = True
                            result["details"].append(f"Reflète l'origin malveillant: {test_origin}")
                            break
                    except Exception:
                        continue

                return result
            except Exception:
                continue

    return result


# =============================================================================
# Module 15 : Subdomain Takeover Detection
# =============================================================================

TAKEOVER_FINGERPRINTS = {
    "github.io": "There isn't a GitHub Pages site here",
    "herokuapp.com": "no such app",
    "pantheonsite.io": "404 error unknown site",
    "ghost.io": "404 Not Found",
    "myshopify.com": "Sorry, this shop is currently unavailable",
    "tumblr.com": "There's nothing here",
    "wordpress.com": "Do you want to register",
    "teamwork.com": "Oops - We didn't find your site",
    "helpjuice.com": "We could not find what you're looking for",
    "helpscoutdocs.com": "No settings were found",
    "s3.amazonaws.com": "NoSuchBucket",
    "zendesk.com": "Help Center Closed",
    "statuspage.io": "Status page launched",
    "uservoice.com": "This UserVoice subdomain is currently available",
    "surge.sh": "project not found",
    "bitbucket.io": "Repository not found",
    "smartling.com": "Domain is not configured",
    "acquia-test.co": "Web Site Not Found",
    "fastly.net": "Fastly error: unknown domain",
    "kinsta.cloud": "No Site For Domain",
    "ngrok.io": "Tunnel .* not found",
    "tilda.ws": "Domain has been assigned",
    "webflow.io": "The page you are looking for doesn't exist",
    "netlify.app": "Not found",
    "fly.dev": "404 Not Found",
    "vercel.app": "404",
    "azurewebsites.net": "Error 404",
    "cloudfront.net": "Bad Request",
    "render.com": "Page Not Found",
    "railway.app": "Application not found",
}


async def check_subdomain_takeover(subdomains: list) -> list:
    """Vérifie si des sous-domaines sont vulnérables au takeover via CNAME."""
    vulnerable = []
    if not subdomains:
        return vulnerable

    resolver = dns.resolver.Resolver()
    resolver.timeout = 3
    resolver.lifetime = 3

    async with httpx.AsyncClient(timeout=5.0, verify=False) as client:
        for sub_info in subdomains[:20]:
            sub = sub_info.get("subdomain", "")
            if not sub or "@" in sub or " " in sub:
                continue

            try:
                loop = asyncio.get_event_loop()
                try:
                    cname_answers = await asyncio.wait_for(
                        loop.run_in_executor(
                            None, lambda s=sub: resolver.resolve(s, "CNAME")
                        ),
                        timeout=5,
                    )
                    cname = str(cname_answers[0].target).rstrip(".")
                except (Exception, asyncio.CancelledError):
                    continue

                for service, fingerprint in TAKEOVER_FINGERPRINTS.items():
                    if service in cname.lower():
                        try:
                            resp = await client.get(f"http://{sub}", follow_redirects=True)
                            body = resp.text[:5000].lower()
                            if fingerprint.lower() in body or resp.status_code == 404:
                                vulnerable.append({
                                    "subdomain": sub,
                                    "cname": cname,
                                    "service": service,
                                    "risk": "high",
                                    "fingerprint_matched": True,
                                })
                                break
                        except Exception:
                            vulnerable.append({
                                "subdomain": sub,
                                "cname": cname,
                                "service": service,
                                "risk": "medium",
                                "fingerprint_matched": False,
                            })
                            break
            except Exception:
                continue

    return vulnerable


# =============================================================================
# Module 16 : Reverse DNS
# =============================================================================

async def reverse_dns(ip: str) -> dict:
    """Reverse DNS lookup - PTR record."""
    if not ip:
        return {"ptr": None, "error": None}

    try:
        loop = asyncio.get_event_loop()
        hostnames = await loop.run_in_executor(None, socket.gethostbyaddr, ip)
        return {
            "ptr": hostnames[0] if hostnames else None,
            "aliases": list(hostnames[1]) if len(hostnames) > 1 else [],
            "error": None,
        }
    except Exception as e:
        return {"ptr": None, "aliases": [], "error": str(e)}


# =============================================================================
# Module 17 : Extended Network Scan (Reverse IP / ASN)
# =============================================================================

async def extended_network_scan(
    ip: str,
    domain: str,
    censys_id: Optional[str] = None,
    censys_secret: Optional[str] = None,
) -> dict:
    """Scan réseau étendu : reverse IP neighbors, ASN info, Censys (optionnel)."""
    result = {
        "reverse_ip_neighbors": [],
        "asn_info": {},
        "ip_range": None,
        "censys": {},
    }
    if not ip:
        return result

    # ASN info via ipinfo.io
    try:
        async with httpx.AsyncClient(timeout=8.0) as client:
            resp = await client.get(f"https://ipinfo.io/{ip}/json")
            if resp.status_code == 200:
                data = resp.json()
                result["asn_info"] = {
                    "asn": data.get("org", "").split(" ")[0] if data.get("org") else None,
                    "org": " ".join(data.get("org", "").split(" ")[1:]) if data.get("org") else None,
                    "hostname": data.get("hostname"),
                    "anycast": data.get("anycast", False),
                }
                result["ip_range"] = data.get("ip", "") + " / " + (data.get("org", "N/A"))
    except Exception:
        pass

    # Reverse IP neighbors via HackerTarget
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.get(
                f"https://api.hackertarget.com/reverseiplookup/?q={ip}",
                headers={"User-Agent": "DomainRecon/5.0"},
            )
            if resp.status_code == 200 and "error" not in resp.text.lower():
                neighbors = [
                    line.strip() for line in resp.text.strip().splitlines()
                    if line.strip() and line.strip() != domain
                ][:50]
                result["reverse_ip_neighbors"] = neighbors
    except Exception:
        pass

    # Censys (si clés configurées)
    if censys_id and censys_secret:
        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                resp = await client.get(
                    f"https://search.censys.io/api/v2/hosts/{ip}",
                    auth=(censys_id, censys_secret),
                    headers={"User-Agent": "DomainRecon/5.0"},
                )
                if resp.status_code == 200:
                    data = resp.json().get("result", {})
                    result["censys"] = {
                        "autonomous_system": data.get("autonomous_system", {}),
                        "services": [
                            {
                                "port": s.get("port"),
                                "transport_protocol": s.get("transport_protocol"),
                                "service_name": s.get("service_name"),
                                "extended_service_name": s.get("extended_service_name"),
                            }
                            for s in data.get("services", [])[:20]
                        ],
                        "labels": data.get("labels", []),
                        "last_updated": data.get("last_updated_at"),
                    }
        except Exception:
            pass

    return result


# =============================================================================
# Module 18 : Security Score Computation
# =============================================================================

def compute_security_score(scan_data: dict) -> dict:
    """Calcule un score de sécurité global 0-100 basé sur tous les modules."""
    score = 0
    max_score = 100
    breakdown = {}

    # 1. Security Headers (0-25 points)
    sec = scan_data.get("security_headers", {})
    headers_score_str = sec.get("score", "0/7")
    try:
        found, total = map(int, headers_score_str.split("/"))
        pts = round((found / max(total, 1)) * 25)
    except Exception:
        pts = 0
    score += pts
    breakdown["headers"] = {"score": pts, "max": 25, "detail": headers_score_str}

    # 2. TLS (0-20 points)
    tls = scan_data.get("tls_certificate", {})
    tls_pts = 0
    if tls and not tls.get("error"):
        tls_pts += 10
        days = tls.get("days_remaining", 0)
        if days and days > 30:
            tls_pts += 5
        elif days and days > 7:
            tls_pts += 2
        proto = tls.get("protocol", "")
        if "1.3" in str(proto):
            tls_pts += 5
        elif "1.2" in str(proto):
            tls_pts += 3
    score += tls_pts
    breakdown["tls"] = {"score": tls_pts, "max": 20, "detail": tls.get("protocol", "N/A")}

    # 3. Email Security (0-15 points)
    email = scan_data.get("email_security", {})
    email_grade = email.get("overall_grade", "F")
    email_map = {"A": 15, "B": 12, "C": 8, "D": 4, "F": 0}
    email_pts = email_map.get(email_grade, 0)
    score += email_pts
    breakdown["email"] = {"score": email_pts, "max": 15, "detail": f"Grade {email_grade}"}

    # 4. WAF (0-10 points)
    waf = scan_data.get("waf", {})
    waf_pts = 10 if waf.get("detected") else 0
    score += waf_pts
    breakdown["waf"] = {"score": waf_pts, "max": 10, "detail": waf.get("waf_name", "Aucun")}

    # 5. Cookies (0-10 points)
    cookies = scan_data.get("cookie_security", {})
    cookie_grade = cookies.get("score", "N/A")
    cookie_map = {"A": 10, "B": 7, "C": 4, "D": 2, "N/A": 5}
    cookie_pts = cookie_map.get(cookie_grade, 0)
    score += cookie_pts
    breakdown["cookies"] = {"score": cookie_pts, "max": 10, "detail": f"Grade {cookie_grade}"}

    # 6. CORS (0-10 points)
    cors = scan_data.get("cors", {})
    cors_pts = 10
    if cors.get("misconfigured"):
        cors_pts = 0
    elif cors.get("allows_any_origin"):
        cors_pts = 4
    score += cors_pts
    breakdown["cors"] = {"score": cors_pts, "max": 10, "detail": "Misconfigured" if cors.get("misconfigured") else "OK"}

    # 7. HTTPS redirect (0-5 points)
    redir = scan_data.get("redirect_chain", {})
    https_pts = 5 if redir.get("forces_https") else 0
    score += https_pts
    breakdown["https_redirect"] = {"score": https_pts, "max": 5, "detail": "Oui" if redir.get("forces_https") else "Non"}

    # 8. Subdomain Takeover (0-5 points)
    takeover = scan_data.get("subdomain_takeover", [])
    takeover_pts = 5 if not takeover else 0
    score += takeover_pts
    breakdown["takeover"] = {"score": takeover_pts, "max": 5, "detail": f"{len(takeover)} vulnérable(s)"}

    # Bonus HSTS Preload (informatif)
    hsts = scan_data.get("hsts_preload", {})
    breakdown["hsts_preload"] = {
        "score": 0, "max": 0,
        "detail": "Préchargé ✓" if hsts.get("preloaded") else "Non préchargé"
    }

    # Bonus Threat Intel (informatif)
    threat = scan_data.get("threat_intel", {})
    breakdown["threat_intel"] = {
        "score": 0, "max": 0,
        "detail": f"⚠ {threat.get('pulse_count', 0)} pulses malveillants" if threat.get("malicious") else "Aucune menace connue"
    }

    if score >= 90:
        grade = "A"
    elif score >= 75:
        grade = "B"
    elif score >= 55:
        grade = "C"
    elif score >= 35:
        grade = "D"
    else:
        grade = "F"

    return {
        "score": score,
        "max_score": max_score,
        "grade": grade,
        "breakdown": breakdown,
    }


# =============================================================================
# Module 19 : Screenshot Capture (Playwright)
# =============================================================================

async def capture_screenshot(domain: str, output_dir: str) -> Optional[str]:
    """Capture un screenshot de la page d'accueil du domaine."""
    try:
        from playwright.async_api import async_playwright
    except ImportError:
        return None

    import os
    os.makedirs(output_dir, exist_ok=True)
    filename = f"{domain.replace('.', '_')}_{int(datetime.now().timestamp())}.png"
    filepath = os.path.join(output_dir, filename)

    try:
        async with async_playwright() as p:
            browser = await p.chromium.launch(headless=True)
            page = await browser.new_page(viewport={"width": 1280, "height": 720})
            await page.goto(f"https://{domain}", wait_until="domcontentloaded", timeout=15000)
            await page.wait_for_timeout(2000)
            await page.screenshot(path=filepath, full_page=False)
            await browser.close()
        return filename
    except Exception:
        try:
            async with async_playwright() as p:
                browser = await p.chromium.launch(headless=True)
                page = await browser.new_page(viewport={"width": 1280, "height": 720})
                await page.goto(f"http://{domain}", wait_until="domcontentloaded", timeout=15000)
                await page.wait_for_timeout(2000)
                await page.screenshot(path=filepath, full_page=False)
                await browser.close()
            return filename
        except Exception:
            return None


# =============================================================================
# Module 20 : URLScan.io Lookup (100% Passif)
# =============================================================================

async def urlscan_lookup(domain: str, urlscan_key: Optional[str] = None) -> dict:
    """Interroge URLScan.io pour les scans historiques existants du domaine.

    100% passif — aucun nouveau scan lancé, consultation uniquement.
    Si urlscan_key fournie : accès aux scans privés et résultats étendus.
    """
    result = {
        "total_scans": 0,
        "last_scan": None,
        "ips_seen": [],
        "countries_seen": [],
        "verdicts": [],
        "screenshot_url": None,
        "page_title": None,
        "ads_blocked": None,
    }

    headers = {"User-Agent": "DomainRecon/5.0"}
    if urlscan_key:
        headers["API-Key"] = urlscan_key

    try:
        async with httpx.AsyncClient(timeout=12.0) as client:
            resp = await client.get(
                f"https://urlscan.io/api/v1/search/?q=domain:{domain}&size=20",
                headers=headers,
            )
            if resp.status_code == 200:
                data = resp.json()
                results = data.get("results", [])
                result["total_scans"] = data.get("total", 0)

                if results:
                    latest = results[0]
                    result["last_scan"] = latest.get("task", {}).get("time")
                    result["screenshot_url"] = latest.get("screenshot")
                    result["page_title"] = latest.get("page", {}).get("title")

                    ips_seen = set()
                    countries_seen = set()

                    for r in results[:10]:
                        page = r.get("page", {})
                        if page.get("ip"):
                            ips_seen.add(page["ip"])
                        if page.get("country"):
                            countries_seen.add(page["country"])
                        verdict = r.get("verdicts", {}).get("overall", {})
                        if verdict.get("malicious") or verdict.get("score", 0) > 0:
                            result["verdicts"].append({
                                "score": verdict.get("score", 0),
                                "malicious": verdict.get("malicious", False),
                                "categories": verdict.get("categories", []),
                            })

                    result["ips_seen"] = list(ips_seen)[:10]
                    result["countries_seen"] = list(countries_seen)
    except Exception:
        pass

    return result


# =============================================================================
# Module 21 : Wayback Machine (100% Passif)
# =============================================================================

async def check_wayback_machine(domain: str) -> dict:
    """Interroge l'archive Wayback Machine (archive.org) pour l'historique du domaine.

    100% passif — consultation des archives existantes uniquement.
    """
    result = {
        "available": False,
        "first_seen": None,
        "last_seen": None,
        "years_active": [],
        "total_captures": 0,
        "sample_old_urls": [],
    }

    try:
        async with httpx.AsyncClient(timeout=15.0) as client:
            # Obtenir les snapshots groupés par année
            resp = await client.get(
                f"https://web.archive.org/cdx/search/cdx"
                f"?url={domain}/*&output=json&fl=timestamp,original"
                f"&collapse=timestamp:4&limit=100",
                headers={"User-Agent": "DomainRecon/4.0"},
            )
            if resp.status_code == 200 and resp.text.strip():
                try:
                    data = resp.json()
                    rows = data[1:] if len(data) > 1 else []
                    if rows:
                        result["available"] = True
                        result["total_captures"] = len(rows)
                        result["first_seen"] = rows[0][0][:8]
                        result["last_seen"] = rows[-1][0][:8]
                        years = sorted(set(row[0][:4] for row in rows if row))
                        result["years_active"] = years
                        urls = list({row[1] for row in rows[:30] if len(row) > 1 and row[1]})
                        result["sample_old_urls"] = urls[:15]
                except Exception:
                    pass
    except Exception:
        pass

    return result


# =============================================================================
# Module 22 : Threat Intelligence — AlienVault OTX (100% Passif, sans clé API)
# =============================================================================

async def check_threat_intelligence(domain: str) -> dict:
    """Vérifie la réputation du domaine via AlienVault OTX (gratuit, sans clé).

    100% passif — consultation de la base de données publique OTX.
    """
    result = {
        "malicious": False,
        "pulse_count": 0,
        "threat_types": [],
        "sources": [],
        "passive_dns": [],
        "malware_families": [],
    }

    try:
        async with httpx.AsyncClient(timeout=12.0) as client:
            # Informations générales + pulse count
            resp = await client.get(
                f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/general",
                headers={"User-Agent": "DomainRecon/4.0"},
            )
            if resp.status_code == 200:
                data = resp.json()
                pulse_info = data.get("pulse_info", {})
                result["pulse_count"] = pulse_info.get("count", 0)

                if result["pulse_count"] > 0:
                    result["malicious"] = True
                    for pulse in pulse_info.get("pulses", [])[:5]:
                        result["sources"].append(pulse.get("name", "")[:80])
                        result["threat_types"].extend(pulse.get("tags", [])[:3])
                        for mf in pulse.get("malware_families", []):
                            result["malware_families"].append(mf.get("display_name", ""))

                result["threat_types"] = list(set(result["threat_types"]))[:10]
                result["malware_families"] = list(set(result["malware_families"]))[:5]

            # Passive DNS historique
            resp2 = await client.get(
                f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns",
                headers={"User-Agent": "DomainRecon/4.0"},
            )
            if resp2.status_code == 200:
                pdns = resp2.json().get("passive_dns", [])[:15]
                result["passive_dns"] = [
                    {
                        "ip": entry.get("address"),
                        "first": entry.get("first"),
                        "last": entry.get("last"),
                        "record_type": entry.get("record_type"),
                        "asn": entry.get("asn"),
                        "country": entry.get("flag", {}).get("code") if isinstance(entry.get("flag"), dict) else None,
                    }
                    for entry in pdns
                    if entry.get("address")
                ]
    except Exception:
        pass

    return result


# =============================================================================
# Module 23 : JS File Analysis (Actif discret — requêtes publiques uniquement)
# =============================================================================
# ⚠️  AVERTISSEMENT : Ce module analyse uniquement des fichiers JavaScript
#     publiquement accessibles. Les endpoints découverts sont informatifs.
#     Ne jamais tenter d'exploiter les endpoints ou secrets trouvés sans
#     autorisation écrite du propriétaire du domaine.
# =============================================================================

async def analyze_js_files(domain: str) -> dict:
    """Extrait endpoints, APIs et patterns suspects des fichiers JS publics."""
    result = {
        "js_files_found": 0,
        "endpoints": [],
        "secrets_patterns": [],
        "external_apis": [],
        "js_files": [],
    }

    js_urls: set = set()

    try:
        async with httpx.AsyncClient(
            timeout=12.0, follow_redirects=True, verify=False
        ) as client:
            # Récupérer la homepage et extraire les fichiers JS
            for url in [f"https://{domain}", f"http://{domain}"]:
                try:
                    resp = await client.get(url)
                    body = resp.text[:50000]
                    base = str(resp.url)
                    parsed_base = urlparse(base)

                    for match in re.findall(
                        r'<script[^>]+src=["\']([^"\']+\.js[^"\'?#]*(?:\?[^"\']*)?)["\']',
                        body, re.I
                    )[:20]:
                        if match.startswith("http"):
                            js_urls.add(match)
                        elif match.startswith("//"):
                            js_urls.add(f"https:{match}")
                        elif match.startswith("/"):
                            js_urls.add(f"{parsed_base.scheme}://{parsed_base.netloc}{match}")
                    break
                except Exception:
                    continue

            result["js_files_found"] = len(js_urls)
            endpoints: set = set()
            secrets: list = []
            ext_apis: set = set()

            for js_url in list(js_urls)[:8]:
                try:
                    js_resp = await client.get(js_url, timeout=8.0)
                    if js_resp.status_code != 200:
                        continue

                    js_content = js_resp.text[:120000]
                    js_size = len(js_content)

                    # Endpoints internes
                    for pattern in JS_ENDPOINT_PATTERNS:
                        for m in re.findall(pattern, js_content, re.I)[:30]:
                            if 3 < len(m) < 200:
                                endpoints.add(m)

                    # Patterns secrets (noms de variables suspects seulement)
                    for pattern, label in JS_SECRET_PATTERNS:
                        if re.search(pattern, js_content):
                            secrets.append({
                                "type": label,
                                "js_file": js_url.split("?")[0][-60:],
                                "warning": "Pattern détecté — vérifier manuellement",
                            })

                    # APIs externes référencées
                    for api_domain in re.findall(r'https?://([a-zA-Z0-9.-]+\.[a-z]{2,})/[^"\'<>\s]*', js_content):
                        if domain not in api_domain and "." in api_domain:
                            ext_apis.add(api_domain)

                    result["js_files"].append({
                        "url": js_url.split("?")[0][-80:],
                        "size_kb": round(js_size / 1024, 1),
                    })
                except Exception:
                    continue

            result["endpoints"] = sorted(list(endpoints))[:50]
            result["secrets_patterns"] = secrets[:10]
            result["external_apis"] = sorted(list(ext_apis))[:20]
    except Exception:
        pass

    return result


# =============================================================================
# Module 24 : Favicon Hash — Shodan Compatible (Actif discret)
# =============================================================================

async def compute_favicon_hash(domain: str) -> dict:
    """Calcule le hash MurmurHash3 du favicon pour recherche dans Shodan/Censys.

    Le hash permet de trouver des serveurs utilisant le même favicon
    (infrastructure partagée, honeypots, etc.).
    """
    result = {
        "found": False,
        "favicon_url": None,
        "hash_mmh3": None,
        "hash_md5": None,
        "shodan_query": None,
        "size_bytes": 0,
    }

    try:
        async with httpx.AsyncClient(
            timeout=8.0, follow_redirects=True, verify=False
        ) as client:
            favicon_candidates = [
                f"https://{domain}/favicon.ico",
                f"http://{domain}/favicon.ico",
            ]

            # Chercher le lien favicon dans la homepage
            try:
                resp = await client.get(f"https://{domain}", timeout=6.0)
                for pattern in [
                    r'<link[^>]+rel=["\'](?:shortcut )?icon["\'][^>]+href=["\']([^"\']+)["\']',
                    r'<link[^>]+href=["\']([^"\']+)["\'][^>]+rel=["\'](?:shortcut )?icon["\']',
                ]:
                    m = re.search(pattern, resp.text[:5000], re.I)
                    if m:
                        href = m.group(1)
                        if href.startswith("http"):
                            favicon_candidates.insert(0, href)
                        elif href.startswith("/"):
                            favicon_candidates.insert(0, f"https://{domain}{href}")
                        break
            except Exception:
                pass

            for fav_url in favicon_candidates:
                try:
                    fav_resp = await client.get(fav_url, timeout=6.0)
                    if fav_resp.status_code == 200 and len(fav_resp.content) > 0:
                        data = fav_resp.content
                        b64 = base64.b64encode(data)
                        # Shodan encode avec newlines tous les 76 caractères
                        b64_chunks = b"\n".join(b64[i:i + 76] for i in range(0, len(b64), 76)) + b"\n"
                        hash_val = _mmh3_hash(b64_chunks)
                        md5_val = hashlib.md5(data).hexdigest()

                        result["found"] = True
                        result["favicon_url"] = fav_url
                        result["hash_mmh3"] = hash_val
                        result["hash_md5"] = md5_val
                        result["shodan_query"] = f"http.favicon.hash:{hash_val}"
                        result["size_bytes"] = len(data)
                        break
                except Exception:
                    continue
    except Exception:
        pass

    return result


# =============================================================================
# Module 25 : Linked Domains — Cartographie des dépendances (Actif discret)
# =============================================================================

async def extract_linked_domains(domain: str) -> dict:
    """Cartographie les domaines externes liés depuis la page d'accueil."""
    result = {
        "total_external": 0,
        "external_domains": [],
        "cdn_domains": [],
        "social_media": [],
        "third_party_scripts": [],
        "analytics_trackers": [],
    }

    ANALYTICS_DOMAINS = [
        "google-analytics.com", "googletagmanager.com", "doubleclick.net",
        "hotjar.com", "segment.io", "mixpanel.com", "amplitude.com",
        "heap.io", "fullstory.com", "logrocket.io", "clarity.ms",
    ]

    try:
        async with httpx.AsyncClient(
            timeout=10.0, follow_redirects=True, verify=False
        ) as client:
            for url in [f"https://{domain}", f"http://{domain}"]:
                try:
                    resp = await client.get(url)
                    body = resp.text[:100000]

                    ext_domains: set = set()
                    cdn_domains: set = set()
                    social: set = set()
                    scripts: set = set()
                    analytics: set = set()

                    # Extraire tous les domaines référencés
                    for ref in re.findall(
                        r'(?:src|href|action|data-src)\s*=\s*["\']https?://([^/"\'<>\s#?]+)',
                        body, re.I
                    ):
                        ref = ref.lower().strip()
                        if not ref or domain in ref:
                            continue
                        ext_domains.add(ref)

                        for s in SOCIAL_DOMAINS:
                            if s in ref:
                                social.add(ref)

                        for cdn in CDN_INDICATORS:
                            if cdn in ref:
                                cdn_domains.add(ref)

                        for at in ANALYTICS_DOMAINS:
                            if at in ref:
                                analytics.add(ref)

                    # Scripts externes
                    for s in re.findall(
                        r'<script[^>]+src=["\']https?://([^/"\'<>\s]+)',
                        body, re.I
                    ):
                        if domain not in s.lower():
                            scripts.add(s.lower())

                    result["total_external"] = len(ext_domains)
                    result["external_domains"] = sorted(list(ext_domains))[:50]
                    result["cdn_domains"] = sorted(list(cdn_domains))[:20]
                    result["social_media"] = sorted(list(social))[:10]
                    result["third_party_scripts"] = sorted(list(scripts))[:20]
                    result["analytics_trackers"] = sorted(list(analytics))[:15]
                    break
                except Exception:
                    continue
    except Exception:
        pass

    return result


# =============================================================================
# Module 26 : Email Blacklist / DNSBL (Quasi-passif — requêtes DNS uniquement)
# =============================================================================

async def check_email_blacklists(ip: str) -> dict:
    """Vérifie si l'IP est listée dans les blacklists email DNSBL majeures.

    Utilise uniquement des requêtes DNS inverses — très discret.
    """
    result = {
        "blacklisted": False,
        "blacklists_hit": [],
        "blacklists_clean": [],
        "checked": 0,
        "reputation": "clean",
    }

    if not ip or ":" in ip:  # Skip IPv6 (not supported by most DNSBL)
        return result

    reversed_ip = ".".join(reversed(ip.split(".")))
    loop = asyncio.get_event_loop()

    async def check_single_dnsbl(dnsbl: str) -> tuple:
        try:
            resolver = dns.resolver.Resolver()
            resolver.timeout = 3
            resolver.lifetime = 3
            await loop.run_in_executor(
                None, lambda: resolver.resolve(f"{reversed_ip}.{dnsbl}", "A")
            )
            return (dnsbl, True)
        except Exception:
            return (dnsbl, False)

    dnsbl_results = await asyncio.gather(
        *[check_single_dnsbl(dnsbl) for dnsbl in DNSBL_SERVERS],
        return_exceptions=True,
    )

    for res in dnsbl_results:
        if isinstance(res, Exception):
            continue
        dnsbl, listed = res
        result["checked"] += 1
        if listed:
            result["blacklisted"] = True
            result["blacklists_hit"].append(dnsbl)
        else:
            result["blacklists_clean"].append(dnsbl)

    if result["blacklisted"]:
        hits = len(result["blacklists_hit"])
        result["reputation"] = "critical" if hits >= 3 else "suspicious"

    return result


# =============================================================================
# Module 27 : HSTS Preload Status (100% Passif)
# =============================================================================

async def check_hsts_preload(domain: str) -> dict:
    """Vérifie le statut HSTS Preload du domaine via hstspreload.org.

    100% passif — consultation de la liste Chromium Preload.
    """
    result = {
        "preloaded": False,
        "status": None,
        "include_subdomains": False,
        "eligible": False,
        "https_forced": False,
    }

    try:
        async with httpx.AsyncClient(timeout=8.0) as client:
            resp = await client.get(
                f"https://hstspreload.org/api/v2/status?domain={domain}",
                headers={"User-Agent": "DomainRecon/4.0"},
            )
            if resp.status_code == 200:
                data = resp.json()
                status = data.get("status", "")
                result["status"] = status
                result["preloaded"] = status == "preloaded"
                result["include_subdomains"] = data.get("includeSubDomains", False)
                result["eligible"] = status in ("preloaded", "pending")
    except Exception:
        pass

    return result


# =============================================================================
# Scan Complet (Orchestrateur)

async def perform_full_scan(url_or_domain: str, settings=None) -> dict:
    """Effectue un scan complet d'un domaine avec 27 modules en parallèle."""
    domain = extract_domain(url_or_domain)
    ip_address = await resolve_ip(domain)

    # Extraire les clés API depuis les settings
    securitytrails_key  = getattr(settings, "securitytrails_key", None)
    censys_id           = getattr(settings, "censys_id", None)
    censys_secret       = getattr(settings, "censys_secret", None)
    urlscan_key         = getattr(settings, "urlscan_key", None)
    scan_timeout        = getattr(settings, "scan_timeout", None) or 60

    from pathlib import Path
    SCREENSHOTS_DIR = str(Path(__file__).resolve().parent.parent.parent / "data" / "screenshots")

    async def _ed(): return {}
    async def _el(): return []

    # Vague 1 : tous les modules indépendants en parallèle
    tasks = [
        scan_dns_records(domain),                                                                    # 0
        find_subdomains(domain, securitytrails_key=securitytrails_key),                             # 1
        check_security_headers(domain),                                                             # 2
        check_tls_certificate(domain),                                                              # 3
        detect_technologies(domain),                                                                # 4
        get_geo_data(ip_address) if ip_address else _ed(),                                          # 5
        get_whois_data(domain),                                                                     # 6
        scan_ports(ip_address) if ip_address else _el(),                                            # 7
        analyze_email_security(domain),                                                             # 8
        detect_waf(domain),                                                                         # 9
        trace_redirects(domain),                                                                    # 10
        check_web_files(domain),                                                                    # 11
        analyze_cookies(domain),                                                                    # 12
        check_cors(domain),                                                                         # 13
        reverse_dns(ip_address) if ip_address else _ed(),                                           # 14
        extended_network_scan(ip_address, domain, censys_id, censys_secret) if ip_address else _ed(),  # 15
        capture_screenshot(domain, SCREENSHOTS_DIR),                                                # 16
        urlscan_lookup(domain, urlscan_key=urlscan_key),                                            # 17
        check_wayback_machine(domain),                                                              # 18
        check_threat_intelligence(domain),                                                          # 19
        analyze_js_files(domain),                                                                   # 20
        compute_favicon_hash(domain),                                                               # 21
        extract_linked_domains(domain),                                                             # 22
        check_email_blacklists(ip_address) if ip_address else _ed(),                               # 23
        check_hsts_preload(domain),                                                                 # 24
    ]

    wrapped = [asyncio.wait_for(t, timeout=scan_timeout) for t in tasks]
    results = await asyncio.gather(*wrapped, return_exceptions=True)

    def safe(val, default):
        return default if isinstance(val, BaseException) else val

    dns_records        = safe(results[0],  {})
    subdomains         = safe(results[1],  [])
    security_headers   = safe(results[2],  {"headers_found": {}, "headers_missing": SECURITY_HEADERS, "score": "0/7", "error": None})
    tls_certificate    = safe(results[3],  {})
    technologies       = safe(results[4],  [])
    geo_data           = safe(results[5],  {})
    whois_data         = safe(results[6],  {})
    open_ports         = safe(results[7],  [])
    email_security     = safe(results[8],  {})
    waf                = safe(results[9],  {})
    redirect_chain     = safe(results[10], {})
    web_files          = safe(results[11], {})
    cookie_security    = safe(results[12], {})
    cors               = safe(results[13], {})
    reverse_dns_data   = safe(results[14], {})
    network_extended   = safe(results[15], {})
    screenshot_file    = safe(results[16], None)
    urlscan_data       = safe(results[17], {})
    wayback_data       = safe(results[18], {})
    threat_intel       = safe(results[19], {})
    js_analysis        = safe(results[20], {})
    favicon_hash       = safe(results[21], {})
    linked_domains     = safe(results[22], {})
    email_blacklist    = safe(results[23], {})
    hsts_preload       = safe(results[24], {})

    # Vague 2 : subdomain takeover (dépend de find_subdomains)
    takeover_results = []
    if subdomains:
        try:
            takeover_results = await asyncio.wait_for(
                check_subdomain_takeover(subdomains), timeout=30
            )
        except (Exception, asyncio.CancelledError):
            takeover_results = []

    status = "success"
    error_message = None
    if not ip_address:
        status = "partial"
        error_message = "Impossible de résoudre l'adresse IP du domaine"
    if not ip_address and security_headers.get("error"):
        status = "error"
        error_message = f"Scan échoué: {security_headers.get('error')}"

    scan_data = {
        "security_headers": security_headers,
        "tls_certificate": tls_certificate,
        "email_security": email_security,
        "waf": waf,
        "cookie_security": cookie_security,
        "cors": cors,
        "redirect_chain": redirect_chain,
        "subdomain_takeover": takeover_results,
        "hsts_preload": hsts_preload,
        "threat_intel": threat_intel,
    }
    security_score = compute_security_score(scan_data)

    return {
        "domain": domain,
        "ip_address": ip_address,
        "dns_records": dns_records,
        "subdomains": subdomains,
        "security_headers": security_headers,
        "tls_certificate": tls_certificate,
        "technologies": technologies,
        "geo_data": geo_data,
        "whois_data": whois_data,
        "open_ports": open_ports,
        "email_security": email_security,
        "waf": waf,
        "redirect_chain": redirect_chain,
        "web_files": web_files,
        "cookie_security": cookie_security,
        "cors": cors,
        "reverse_dns": reverse_dns_data,
        "subdomain_takeover": takeover_results,
        "network_extended": network_extended,
        "security_score": security_score,
        "screenshot_path": screenshot_file,
        "urlscan_data": urlscan_data,
        "wayback_data": wayback_data,
        "threat_intel": threat_intel,
        "js_analysis": js_analysis,
        "favicon_hash": favicon_hash,
        "linked_domains": linked_domains,
        "email_blacklist": email_blacklist,
        "hsts_preload": hsts_preload,
        "status": status,
        "error_message": error_message,
    }
