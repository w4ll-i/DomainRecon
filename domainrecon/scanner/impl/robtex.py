# =============================================================================
# DomainRecon - Robtex : DNS passif (enregistrements historiques d'un nom ou d'une IP)
# =============================================================================
# API gratuite, sans clé, HTTPS (https://www.robtex.com/api/) :
#   - /pdns/forward/<nom> : enregistrements vus pour un nom, une ligne JSON chacun
#     {rrname, rrdata, rrtype, time_first, time_last, count} ;
#   - /ipquery/<ip> : ASN, réseau et noms vus sur l'adresse (champ « pas »).
# Quota très serré : 10 requêtes par heure et par adresse (HTTP 429, corps
# {"status":"ratelimited"}). Un module n'envoie donc qu'UNE requête par scan et
# chaque réponse est gardée en cache une heure.
# =============================================================================

import json
from datetime import datetime, timezone

import httpx

from ...i18n import msg
from ..cache import MEDIUM_TTL, cached
from ..common import proxy_scope
from ..errors import ModuleError
from . import network_http as nh

BASE = "https://freeapi.robtex.com"
SERVICE = "Robtex"
MAX_RECORDS = 200
MAX_NAMES = 100
_ADDRESS_TYPES = ("A", "AAAA")


def _iso(timestamp: object) -> str | None:
    if isinstance(timestamp, bool) or not isinstance(timestamp, (int, float)) or timestamp <= 0:
        return None
    try:
        return datetime.fromtimestamp(timestamp, tz=timezone.utc).strftime("%Y-%m-%d")
    except (OverflowError, OSError, ValueError):
        return None


def _is_ratelimited(response: httpx.Response) -> bool:
    if response.status_code == 429:
        return True
    return response.status_code == 200 and response.text.lstrip().startswith('{"status":"ratelimited"')


@cached(MEDIUM_TTL, scope=proxy_scope, ignore=("client",), max_entries=64)
async def forward(client: httpx.AsyncClient | None, host: str) -> dict:
    """Enregistrements DNS passifs d'un nom : {records, total}. Lève ModuleError (quota, réseau, illisible)."""
    async with nh.use_client(client, timeout=20) as http:
        response = await nh.get(http, f"{BASE}/pdns/forward/{host}", service=SERVICE)
    if _is_ratelimited(response):
        raise ModuleError(msg("network.quota", service=SERVICE))
    if response.status_code != 200:
        raise nh.status_error(SERVICE, response.status_code)
    if len(response.content) > nh.MAX_JSON_BYTES:
        raise ModuleError(msg("robtex.unreadable"))
    records: list[dict] = []
    seen: set[tuple] = set()
    bad_lines = 0
    for line in response.text.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            row = json.loads(line)
        except ValueError:
            bad_lines += 1
            continue
        if not isinstance(row, dict) or not isinstance(row.get("rrdata"), str) or not row.get("rrtype"):
            bad_lines += 1
            continue
        key = (str(row["rrtype"]), row["rrdata"].lower())
        if key in seen:
            continue
        seen.add(key)
        records.append(
            {
                "type": str(row["rrtype"]),
                "data": row["rrdata"].lower().rstrip("."),
                "first_seen": _iso(row.get("time_first")),
                "last_seen": _iso(row.get("time_last")),
                "count": row.get("count") if isinstance(row.get("count"), int) else None,
            }
        )
    if bad_lines and not records:
        raise ModuleError(msg("robtex.unreadable"))
    records.sort(key=lambda r: (r["type"], r["data"]))
    return {"records": records[:MAX_RECORDS], "total": len(records)}


@cached(MEDIUM_TTL, scope=proxy_scope, ignore=("client",), max_entries=64)
async def ip_query(client: httpx.AsyncClient | None, ip: str) -> dict:
    """Réseau et noms vus sur une adresse : {asn, network, as_name, country, names, names_total}."""
    async with nh.use_client(client, timeout=20) as http:
        response = await nh.get(http, f"{BASE}/ipquery/{ip}", service=SERVICE)
    if _is_ratelimited(response):
        raise ModuleError(msg("network.quota", service=SERVICE))
    if response.status_code != 200:
        raise nh.status_error(SERVICE, response.status_code)
    data = nh.parse_json(response)
    if not isinstance(data, dict) or data.get("status") != "ok":
        raise ModuleError(msg("robtex.unreadable"))
    names: list[str] = []
    for entry in (data.get("pas") or []) + (data.get("act") or []):
        name = entry.get("o") if isinstance(entry, dict) else entry
        if isinstance(name, str) and name and name.lower() not in names:
            names.append(name.lower())
    asn = data.get("as")
    return {
        "asn": f"AS{asn}" if isinstance(asn, int) and not isinstance(asn, bool) else None,
        "network": str(data.get("bgproute") or "") or None,
        "as_name": str(data.get("asname") or "") or None,
        "country": str(data.get("country") or "") or None,
        "names": names[:MAX_NAMES],
        "names_total": len(names),
    }
