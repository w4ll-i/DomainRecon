# =============================================================================
# DomainRecon - DNS passif : historique des enregistrements d'un domaine
# =============================================================================
# Sources, interrogées en parallèle (une source en échec ne bloque pas les autres) :
#   circl     CIRCL Passive DNS, https://www.circl.lu/pdns/query/<domaine> (HTTP Basic,
#             NDJSON, accès réservé sur demande : identifiants facultatifs)
#   otx       AlienVault OTX, .../api/v1/indicators/domain/<domaine>/passive_dns
#             (l'accès anonyme y répond 429 depuis 2026 : clé facultative, sans clé la
#             source est passée sans requête)
#   robtex    https://freeapi.robtex.com/pdns/forward/<domaine> (gratuit, sans clé,
#             10 requêtes par heure et par adresse : une requête par scan, 1 h de cache)
# Les enregistrements des trois sources sont fusionnés dans une même forme :
#   {rrname, rrtype, rdata, first_seen, last_seen, count, sources}
# Les identifiants ne partent que dans l'en-tête Authorization ou X-OTX-API-KEY,
# jamais dans une URL, un message ou un journal.
# =============================================================================

import asyncio
import json
from datetime import datetime, timezone
from typing import NamedTuple

import httpx

from ...i18n import msg
from ..cache import MEDIUM_TTL, cached
from ..common import proxy_scope
from ..errors import ModuleError
from . import dns_http

MAX_RECORDS = 300
SOURCE_TIMEOUT = 25.0
ADDRESS_TYPES = ("A", "AAAA")


class Record(NamedTuple):
    rrname: str
    rrtype: str
    rdata: str
    first_seen: str
    last_seen: str
    count: int | None


class SourceReport(NamedTuple):
    name: str
    status: str  # ok | error | skipped
    count: int
    error: object | None = None

    def as_dict(self) -> dict:
        return {"name": self.name, "status": self.status, "count": self.count, "error": self.error}


def to_date(value: object) -> str:
    """Date AAAA-MM-JJ d'un horodatage Unix ou d'un texte ISO ; chaîne vide si illisible."""
    if isinstance(value, bool):
        return ""
    if isinstance(value, (int, float)) and value > 0:
        try:
            return datetime.fromtimestamp(value, tz=timezone.utc).strftime("%Y-%m-%d")
        except (OverflowError, OSError, ValueError):
            return ""
    if isinstance(value, str):
        return value.strip()[:10]
    return ""


def _record(
    rrname: object, rrtype: object, rdata: object, first: object, last: object, count: object
) -> Record | None:
    if not all(isinstance(v, str) and v.strip() for v in (rrname, rrtype, rdata)):
        return None
    number = count if isinstance(count, int) and not isinstance(count, bool) else None
    return Record(
        rrname.strip().lower().rstrip("."),
        rrtype.strip().upper(),
        rdata.strip().rstrip(".") if rrtype.upper() not in ("TXT",) else rdata.strip(),
        to_date(first),
        to_date(last),
        number,
    )


def parse_ndjson(text: str) -> list[Record]:
    """Lignes JSON {rrname, rrtype, rdata|rrdata, time_first, time_last, count} (CIRCL, Robtex)."""
    records = []
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            item = json.loads(line)
        except ValueError:
            continue
        if not isinstance(item, dict):
            continue
        record = _record(
            item.get("rrname"),
            item.get("rrtype"),
            item.get("rdata", item.get("rrdata")),
            item.get("time_first"),
            item.get("time_last"),
            item.get("count"),
        )
        if record:
            records.append(record)
    return records


# --- Sources ---------------------------------------------------------------------


@cached(MEDIUM_TTL, scope=proxy_scope, ignore=("client", "user", "password"), max_entries=32)
async def fetch_circl(
    client: httpx.AsyncClient | None, user: str, password: str, domain: str
) -> list[Record]:
    service = "CIRCL"
    async with dns_http.session(client, SOURCE_TIMEOUT) as http:
        reply = await dns_http.get(
            http,
            f"https://www.circl.lu/pdns/query/{domain}",
            service=service,
            headers={"Accept": "application/x-ndjson"},
            auth=(user, password),
            timeout=SOURCE_TIMEOUT,
        )
    if reply.status in (401, 403):
        raise ModuleError(msg("pdns_data.circl_rejected"))
    if reply.status == 404:
        return []
    if reply.status != 200:
        raise dns_http.status_error(service, reply.status)
    return parse_ndjson(reply.text)


@cached(MEDIUM_TTL, scope=proxy_scope, ignore=("client", "key"), max_entries=32)
async def fetch_otx(client: httpx.AsyncClient | None, key: str, domain: str) -> list[Record]:
    service = "AlienVault OTX"
    async with dns_http.session(client, SOURCE_TIMEOUT) as http:
        reply = await dns_http.get(
            http,
            f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns",
            service=service,
            headers={"X-OTX-API-KEY": key, "Accept": "application/json"},
            timeout=SOURCE_TIMEOUT,
        )
    if reply.status in (401, 403):
        raise ModuleError(msg("pdns_data.otx_rejected"))
    if reply.status != 200:
        raise dns_http.status_error(service, reply.status)
    try:
        data = reply.json()
    except ValueError:
        raise ModuleError(msg("pdns_data.unreadable", service=service)) from None
    entries = data.get("passive_dns") if isinstance(data, dict) else None
    if not isinstance(entries, list):
        raise ModuleError(msg("pdns_data.unreadable", service=service))
    records = []
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        record = _record(
            entry.get("hostname"),
            entry.get("record_type"),
            entry.get("address"),
            entry.get("first"),
            entry.get("last"),
            None,
        )
        if record:
            records.append(record)
    return records


@cached(MEDIUM_TTL, scope=proxy_scope, ignore=("client",), max_entries=32)
async def fetch_robtex(client: httpx.AsyncClient | None, domain: str) -> list[Record]:
    service = "Robtex"
    async with dns_http.session(client, SOURCE_TIMEOUT) as http:
        reply = await dns_http.get(
            http, f"https://freeapi.robtex.com/pdns/forward/{domain}", service=service, timeout=SOURCE_TIMEOUT
        )
    if reply.status == 429 or (
        reply.status == 200 and reply.text.lstrip().startswith('{"status":"ratelimited"')
    ):
        raise ModuleError(msg("network.quota", service=service))
    if reply.status != 200:
        raise dns_http.status_error(service, reply.status)
    return parse_ndjson(reply.text)


# --- Fusion ----------------------------------------------------------------------


def merge(per_source: dict[str, list[Record]]) -> list[dict]:
    """Fusionne les enregistrements identiques (nom, type, valeur) de toutes les sources."""
    merged: dict[tuple, dict] = {}
    for source, records in per_source.items():
        for record in records:
            key = (record.rrname, record.rrtype, record.rdata)
            item = merged.setdefault(
                key,
                {
                    "rrname": record.rrname,
                    "rrtype": record.rrtype,
                    "rdata": record.rdata[:300],
                    "first_seen": record.first_seen,
                    "last_seen": record.last_seen,
                    "count": record.count,
                    "sources": [],
                },
            )
            if source not in item["sources"]:
                item["sources"].append(source)
            if record.first_seen and (not item["first_seen"] or record.first_seen < item["first_seen"]):
                item["first_seen"] = record.first_seen
            if record.last_seen > item["last_seen"]:
                item["last_seen"] = record.last_seen
            if record.count is not None:
                item["count"] = max(item["count"] or 0, record.count)
    return sorted(merged.values(), key=lambda r: (r["last_seen"], r["rrname"], r["rdata"]), reverse=True)


async def _guard(name: str, call) -> tuple[list[Record], SourceReport]:
    try:
        records = await asyncio.wait_for(call, timeout=SOURCE_TIMEOUT + 5)
    except ModuleError as e:
        return [], SourceReport(name, "error", 0, e.message)
    except (asyncio.TimeoutError, TimeoutError):
        return [], SourceReport(name, "error", 0, msg("net.timeout"))
    return records, SourceReport(name, "ok", len(records))


async def collect(
    client: httpx.AsyncClient | None,
    domain: str,
    *,
    circl_user: str | None = None,
    circl_password: str | None = None,
    otx_key: str | None = None,
) -> dict:
    """Historique DNS passif de `domain`. Lève ModuleError si aucune source n'a répondu."""
    tasks: list = []
    reports: list[SourceReport] = []
    if circl_user and circl_password:
        tasks.append(("circl", _guard("circl", fetch_circl(client, circl_user, circl_password, domain))))
    else:
        reports.append(
            SourceReport("circl", "skipped", 0, msg("pdns_data.credentials_needed", service="CIRCL"))
        )
    if otx_key:
        tasks.append(("otx", _guard("otx", fetch_otx(client, otx_key, domain))))
    else:
        reports.append(
            SourceReport("otx", "skipped", 0, msg("pdns_data.credentials_needed", service="AlienVault OTX"))
        )
    tasks.append(("robtex", _guard("robtex", fetch_robtex(client, domain))))

    outcomes = await asyncio.gather(*(task for _, task in tasks))
    per_source: dict[str, list[Record]] = {}
    for (name, _), (records, report) in zip(tasks, outcomes, strict=True):
        reports.append(report)
        if report.status == "ok":
            per_source[name] = records
    if not per_source:
        errors = [r.error for r in reports if r.status == "error"]
        raise ModuleError(msg("pdns_data.all_failed", errors=errors, sep="; "))

    records = merge(per_source)
    addresses = sorted({r["rdata"] for r in records if r["rrtype"] in ADDRESS_TYPES})
    types: dict[str, int] = {}
    for record in records:
        types[record["rrtype"]] = types.get(record["rrtype"], 0) + 1
    return {
        "measured": True,
        "error": None,
        "domain": domain,
        "total": len(records),
        "records": records[:MAX_RECORDS],
        "unique_ips": addresses[:100],
        "unique_ip_count": len(addresses),
        "record_types": dict(sorted(types.items())),
        "sources": [r.as_dict() for r in reports],
    }
