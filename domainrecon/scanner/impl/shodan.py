# =============================================================================
# DomainRecon - Shodan : API hôte (avec clé) et InternetDB (gratuit, sans clé)
# =============================================================================
# Sources :
#   - API REST Shodan https://developer.shodan.io/api : GET /shodan/host/{ip}?key=…
#     (la clé voyage dans l'URL, seul mode que l'API documente : elle ne figure
#     jamais dans un message ni un journal, le journal d'httpx étant coupé) ;
#     404 : adresse non indexée ; 401 : clé refusée ; 429 : quota ;
#   - InternetDB https://internetdb.shodan.io/{ip} : ports, noms d'hôte, CPE, tags
#     et CVE de l'adresse, sans clé, rafraîchi chaque semaine (usage non
#     commercial) ; 404 « No information available » : adresse inconnue.
# Les CVE sont DÉDUITES par Shodan de la version annoncée dans la bannière : un
# correctif rétroporté par la distribution les rend parfois caduques. Elles sont
# donc rapportées comme « à vérifier », jamais comme une vulnérabilité confirmée.
# =============================================================================

import re

import httpx

from ...i18n import msg
from ..errors import ModuleError
from . import network_http as nh

HOST_URL = "https://api.shodan.io/shodan/host/{ip}"
INTERNETDB_URL = "https://internetdb.shodan.io/{ip}"
SERVICE = "Shodan"
SERVICE_DB = "Shodan InternetDB"

MAX_SERVICES = 60
MAX_VULNS = 100
MAX_BANNER = 300
MAX_CPES = 5

_CVE_RE = re.compile(r"CVE-\d{4}-\d{4,9}", re.IGNORECASE)
clean_text = nh.clean_text


def _strings(value: object, limit: int = 30) -> list[str]:
    if not isinstance(value, list):
        return []
    return [clean_text(item, 120) for item in value if isinstance(item, str) and item][:limit]


def _number(value: object) -> float:
    return float(value) if isinstance(value, (int, float)) and not isinstance(value, bool) else 0.0


def normalize_vulns(top: object, services: list[dict]) -> list[dict]:
    """CVE de l'hôte : liste de ids (hôte) ou dict {id: détails}, et celles de chaque service ; triées par CVSS."""
    found: dict[str, dict] = {}

    def add(cve: object, details: object = None) -> None:
        # Shodan préfixe d'un « ! » les CVE qu'il n'a pas pu vérifier : l'identifiant seul est gardé.
        cve = cve.strip().lstrip("!") if isinstance(cve, str) else ""
        if not _CVE_RE.fullmatch(cve):
            return
        cve = cve.upper()
        info = details if isinstance(details, dict) else {}
        entry = found.setdefault(cve, {"id": cve, "cvss": 0.0, "summary": "", "verified": False})
        entry["cvss"] = max(entry["cvss"], _number(info.get("cvss")))
        entry["summary"] = entry["summary"] or clean_text(info.get("summary"), 240)
        entry["verified"] = entry["verified"] or info.get("verified") is True

    if isinstance(top, dict):
        for cve, details in top.items():
            add(cve, details)
    elif isinstance(top, list):
        for cve in top:
            add(cve)
    for service in services:
        details = service.get("vulns")
        if isinstance(details, dict):
            for cve, info in details.items():
                add(cve, info)
    return sorted(found.values(), key=lambda v: (-v["cvss"], v["id"]))


def normalize_host(raw: dict, ip: str) -> dict:
    """Réponse de /shodan/host/{ip} réduite aux champs utiles (types JSON, listes bornées)."""
    entries = [e for e in raw.get("data") or [] if isinstance(e, dict)]
    services = []
    for entry in entries[:MAX_SERVICES]:
        port = entry.get("port")
        services.append(
            {
                "port": port if isinstance(port, int) else None,
                "protocol": clean_text(entry.get("transport") or "tcp", 8),
                "product": clean_text(entry.get("product"), 80),
                "version": clean_text(entry.get("version"), 60),
                "banner": clean_text(entry.get("data")),
                "cpe": _strings(entry.get("cpe"), MAX_CPES),
                "module": clean_text((entry.get("_shodan") or {}).get("module"), 40)
                if isinstance(entry.get("_shodan"), dict)
                else "",
            }
        )
    vulns = normalize_vulns(raw.get("vulns"), entries)
    ports = sorted({p for p in raw.get("ports") or [] if isinstance(p, int) and not isinstance(p, bool)})
    return {
        "ip": str(raw.get("ip_str") or ip),
        "ports": ports,
        "services": services,
        "services_total": len(entries),
        "vulns": vulns[:MAX_VULNS],
        "vuln_count": len(vulns),
        "hostnames": _strings(raw.get("hostnames")),
        "domains": _strings(raw.get("domains")),
        "tags": _strings(raw.get("tags"), 20),
        "cpes": sorted({c for s in services for c in s["cpe"]})[:20],
        "org": clean_text(raw.get("org"), 120),
        "isp": clean_text(raw.get("isp"), 120),
        "asn": clean_text(raw.get("asn"), 20),
        "os": clean_text(raw.get("os"), 60),
        "country": clean_text(raw.get("country_name"), 60),
        "city": clean_text(raw.get("city"), 60),
        "last_update": clean_text(raw.get("last_update"), 40),
    }


def normalize_internetdb(raw: dict, ip: str) -> dict:
    """Réponse d'InternetDB (ports, hostnames, cpes, tags, vulns) au même format que l'API hôte."""
    vulns = normalize_vulns(raw.get("vulns"), [])
    ports = sorted({p for p in raw.get("ports") or [] if isinstance(p, int) and not isinstance(p, bool)})
    return {
        "ip": str(raw.get("ip") or ip),
        "ports": ports,
        "services": [],
        "services_total": 0,
        "vulns": vulns[:MAX_VULNS],
        "vuln_count": len(vulns),
        "hostnames": _strings(raw.get("hostnames")),
        "domains": [],
        "tags": _strings(raw.get("tags"), 20),
        "cpes": _strings(raw.get("cpes"), 20),
        "org": "",
        "isp": "",
        "asn": "",
        "os": "",
        "country": "",
        "city": "",
        "last_update": "",
    }


async def host(client: httpx.AsyncClient | None, ip: str, key: str) -> dict | None:
    """Données Shodan de l'adresse avec la clé ; None si l'adresse n'est pas indexée.

    Lève ModuleError : clé refusée (401/403), quota (429), autre code HTTP, réseau, réponse illisible.
    """
    async with nh.use_client(client, timeout=20) as http:
        response = await nh.get(http, HOST_URL.format(ip=ip), service=SERVICE, params={"key": key})
    if response.status_code == 404:
        return None
    if response.status_code in (401, 403):
        raise ModuleError(msg("shodan.key_rejected"))
    if response.status_code != 200:
        raise nh.status_error(SERVICE, response.status_code)
    raw = nh.parse_json(response)
    if not isinstance(raw, dict):
        raise ModuleError(msg("shodan.unreadable", service=SERVICE))
    return normalize_host(raw, ip)


async def internetdb(client: httpx.AsyncClient | None, ip: str) -> dict | None:
    """Données d'InternetDB (sans clé) ; None si l'adresse est inconnue."""
    async with nh.use_client(client, timeout=15) as http:
        response = await nh.get(http, INTERNETDB_URL.format(ip=ip), service=SERVICE_DB)
    if response.status_code == 404:
        return None
    if response.status_code != 200:
        raise nh.status_error(SERVICE_DB, response.status_code)
    raw = nh.parse_json(response)
    if not isinstance(raw, dict):
        raise ModuleError(msg("shodan.unreadable", service=SERVICE_DB))
    return normalize_internetdb(raw, ip)
