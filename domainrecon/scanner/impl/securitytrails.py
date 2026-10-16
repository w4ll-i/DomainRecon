# =============================================================================
# DomainRecon - SecurityTrails : sous-domaines et historique DNS (clé d'API)
# =============================================================================
# Documentation : https://docs.securitytrails.com/reference/ (HTTPS obligatoire,
# clé dans l'en-tête APIKEY, jamais dans l'URL) :
#   - GET /v1/domain/{domaine}/subdomains : {"subdomains": ["www", ...]} (labels
#     relatifs au domaine) ;
#   - GET /v1/history/{domaine}/dns/a : {"records": [{"first_seen", "last_seen",
#     "organizations": [...], "values": [{"ip": "...", "ip_count": n}]}], "pages": n}.
# L'offre gratuite est minuscule (quota non confirmé : ne rien promettre) : une
# requête par appel, résultats gardés 24 h. 401/403 : clé refusée ou hors offre,
# 429 : quota.
# =============================================================================

import re

import httpx

from ...i18n import msg
from ..cache import LONG_TTL, cached
from ..common import proxy_scope
from ..errors import ModuleError
from . import dns_http

BASE = "https://api.securitytrails.com/v1"
SERVICE = "SecurityTrails"
MAX_SUBDOMAINS = 5000
MAX_HISTORY = 50
_LABEL = re.compile(r"[a-z0-9_]([a-z0-9_.-]*[a-z0-9_])?")


def _check_status(status: int) -> None:
    if status in (401, 403):
        raise ModuleError(msg("securitytrails.key_rejected"))
    if status == 429:
        raise ModuleError(msg("network.quota", service=SERVICE))
    if status != 200:
        raise ModuleError(msg("network.http_status", status=status, service=SERVICE))


def _json(reply: dns_http.Reply) -> dict:
    try:
        data = reply.json()
    except ValueError:
        raise ModuleError(msg("securitytrails.unreadable")) from None
    if not isinstance(data, dict):
        raise ModuleError(msg("securitytrails.unreadable"))
    return data


@cached(LONG_TTL, scope=proxy_scope, ignore=("client", "key"), max_entries=32)
async def fetch_subdomains(client: httpx.AsyncClient | None, key: str, domain: str) -> list[str]:
    """Noms complets des sous-domaines connus de SecurityTrails ; lève ModuleError (clé, quota, réseau, réponse)."""
    async with dns_http.session(client, 20) as http:
        reply = await dns_http.get(
            http,
            f"{BASE}/domain/{domain}/subdomains",
            service=SERVICE,
            params={"children_only": "false", "include_inactive": "true"},
            headers={"APIKEY": key, "Accept": "application/json"},
            timeout=20,
        )
    _check_status(reply.status)
    labels = _json(reply).get("subdomains")
    if not isinstance(labels, list):
        raise ModuleError(msg("securitytrails.unreadable"))
    names = []
    for label in labels[:MAX_SUBDOMAINS]:
        if isinstance(label, str) and _LABEL.fullmatch(label.strip().lower()):
            names.append(f"{label.strip().lower()}.{domain}")
    return sorted(set(names))


@cached(LONG_TTL, scope=proxy_scope, ignore=("client", "key"), max_entries=32)
async def fetch_history(client: httpx.AsyncClient | None, key: str, domain: str) -> list[dict]:
    """Historique des adresses IPv4 (enregistrements A) du domaine, du plus récent au plus ancien."""
    async with dns_http.session(client, 20) as http:
        reply = await dns_http.get(
            http,
            f"{BASE}/history/{domain}/dns/a",
            service=SERVICE,
            headers={"APIKEY": key, "Accept": "application/json"},
            timeout=20,
        )
    _check_status(reply.status)
    records = _json(reply).get("records")
    if not isinstance(records, list):
        raise ModuleError(msg("securitytrails.unreadable"))
    history: list[dict] = []
    for record in records:
        if not isinstance(record, dict):
            continue
        values = record.get("values")
        ips = [v["ip"] for v in values if isinstance(v, dict) and isinstance(v.get("ip"), str)]
        orgs = record.get("organizations")
        history.append(
            {
                "first_seen": str(record.get("first_seen") or "")[:10],
                "last_seen": str(record.get("last_seen") or "")[:10],
                "ips": ips[:10],
                "organizations": [o for o in orgs if isinstance(o, str)][:5]
                if isinstance(orgs, list)
                else [],
            }
        )
    history.sort(key=lambda item: item["last_seen"], reverse=True)
    return history[:MAX_HISTORY]
