# =============================================================================
# DomainRecon - Implémentation : Wayback Machine (API CDX d'archive.org)
# =============================================================================
# Sources (sans clé, vivantes en octobre 2026) :
#   - https://web.archive.org/cdx/search/cdx (index des captures) ;
#   - https://archive.org/wayback/available (capture la plus proche d'aujourd'hui).
#
# Piège évité : lire la première et la dernière LIGNE d'une requête sur
# « domaine/* », triée par URL et non par date, avec limit=100, donnerait des dates
# « première » et « dernière » fausses et un « nombre de captures » qui ne serait
# qu'un nombre de lignes. Ici, première et
# dernière captures sont celles de la page d'accueil (URL exacte, triée par date
# par le CDX : limit=1 pour la plus ancienne, limit=-1 pour la plus récente), la
# plus proche vient de l'API de disponibilité, les années actives d'un
# regroupement par année et quelques URL archivées d'un regroupement par URL.
# L'API est appelée en https:// : en http://, sans suivre la redirection, le
# résultat serait vide sans erreur.
#
# Les cinq requêtes partent ensemble, chacune avec son délai : le CDX est lent
# (plusieurs dizaines de secondes pour un domaine très archivé) et limite le
# débit (HTTP 429). Une requête manquante rend le résultat « partiel » ; seul
# l'échec de toutes les requêtes essentielles est une erreur.
# =============================================================================

import asyncio
import re
from urllib.parse import urlsplit

import httpx

from ...i18n import msg
from .. import common
from ..cache import MEDIUM_TTL, cached
from ..errors import ModuleError

CDX_URL = "https://web.archive.org/cdx/search/cdx"
AVAILABLE_URL = "https://archive.org/wayback/available"
SERVICE = "Wayback Machine"

# Délais de chaque requête (s) et attente maximale de l'ensemble.
TIMEOUT_FIRST = 25
TIMEOUT_LAST = 40
TIMEOUT_AVAILABLE = 15
TIMEOUT_YEARS = 40
TIMEOUT_URLS = 35
TOTAL_BUDGET = 48

MAX_YEARS = 60
MAX_SAMPLE_URLS = 15
MAX_URL_LENGTH = 200

_TIMESTAMP_RE = re.compile(r"^\d{14}$")
_YEAR_RE = re.compile(r"^\d{4}")
_ARCHIVE_HOSTS = ("web.archive.org", "archive.org")


class Partial(Exception):
    """Résultat incomplet (une requête manque) : utilisable, mais jamais gardé en cache."""

    def __init__(self, result: dict) -> None:
        super().__init__("partiel")
        self.result = result


class Reply:
    """Issue d'une requête : data (JSON lu) ou failure (« quota », « http », « timeout », « network », « unreadable »)."""

    __slots__ = ("data", "detail", "failure")

    def __init__(self, data: object = None, failure: str | None = None, detail: str = "") -> None:
        self.data, self.failure, self.detail = data, failure, detail


async def _fetch(client: httpx.AsyncClient, url: str, params: dict, timeout: float) -> Reply:
    """GET JSON borné. Jamais str(exception) : seul le nom du type est gardé."""
    try:
        response = await client.get(url, params=params, timeout=timeout)
    except httpx.TimeoutException:
        return Reply(failure="timeout", detail="timeout")
    except httpx.HTTPError as e:
        return Reply(failure="network", detail=type(e).__name__)
    if response.status_code == 429:
        return Reply(failure="quota")
    if response.status_code != 200:
        return Reply(failure="http", detail=str(response.status_code))
    if not response.content.strip():
        return Reply(data=[])  # le CDX répond par un corps vide quand rien n'est archivé
    try:
        return Reply(data=response.json())
    except ValueError:
        return Reply(failure="unreadable")


def _rows(reply: Reply) -> list[list[str]] | None:
    """Lignes de données d'une réponse CDX (la première ligne, d'en-têtes, est écartée) ; None si échec."""
    if reply.failure is not None or not isinstance(reply.data, list):
        return None
    return [r for r in reply.data[1:] if isinstance(r, list) and r and all(isinstance(c, str) for c in r)]


def _timestamp_row(rows: list[list[str]] | None) -> list[str] | None:
    """Première ligne dont la première colonne est un horodatage CDX à 14 chiffres."""
    for row in rows or []:
        if _TIMESTAMP_RE.match(row[0]):
            return row
    return None


def _date(row: list[str] | None) -> str | None:
    """« AAAAMMJJ » d'une ligne CDX."""
    return row[0][:8] if row else None


def _clean_url(url: str) -> str | None:
    """URL archivée gardée (http/https), tronquée : donnée externe non fiable, jamais suivie."""
    parts = urlsplit(url)
    if parts.scheme not in ("http", "https") or not parts.hostname:
        return None
    return url[:MAX_URL_LENGTH]


def _closest(reply: Reply) -> dict | None:
    """Capture la plus proche de l'API de disponibilité ; l'URL doit rester sur archive.org."""
    data = reply.data if reply.failure is None else None
    snapshots = data.get("archived_snapshots") if isinstance(data, dict) else None
    closest = snapshots.get("closest") if isinstance(snapshots, dict) else None
    if not isinstance(closest, dict) or closest.get("available") is not True:
        return None
    stamp, url, status = closest.get("timestamp"), closest.get("url"), closest.get("status")
    if not (isinstance(stamp, str) and _TIMESTAMP_RE.match(stamp) and isinstance(url, str)):
        return None
    parts = urlsplit(url)
    if parts.scheme not in ("http", "https") or parts.hostname not in _ARCHIVE_HOSTS:
        return None
    return {
        "timestamp": stamp,
        "url": url[: MAX_URL_LENGTH * 2],
        "status": status if isinstance(status, str) else None,
    }


def _failure_error(replies: dict[str, Reply]) -> ModuleError:
    """Erreur du module quand toutes les requêtes essentielles ont échoué."""
    failures = [r for r in replies.values() if r.failure]
    if any(r.failure == "quota" for r in failures):
        return ModuleError(msg("network.quota", service=SERVICE))
    first = failures[0] if failures else Reply(failure="network")
    if first.failure == "http":
        return ModuleError(msg("network.http_status", status=first.detail, service=SERVICE))
    if first.failure == "unreadable":
        return ModuleError(msg("wayback_data.unreadable"))
    return ModuleError(
        msg("network.service_error", context=SERVICE, detail=first.detail or first.failure or "?")
    )


def build_result(domain: str, replies: dict[str, Reply]) -> dict:
    """Résultat du module ; lève ModuleError si les requêtes essentielles ont toutes échoué, Partial s'il en manque."""
    essential = [replies[k] for k in ("first", "last", "available") if k in replies]
    if essential and all(r.failure for r in essential):
        raise _failure_error(replies)

    first_row = _timestamp_row(_rows(replies["first"])) if "first" in replies else None
    last_row = _timestamp_row(_rows(replies["last"])) if "last" in replies else None
    closest = _closest(replies["available"]) if "available" in replies else None

    first_seen, last_seen = _date(first_row), _date(last_row)
    # Requête manquante : la capture la plus proche (date récente) sert de repli pour la dernière.
    if last_seen is None and closest:
        last_seen = closest["timestamp"][:8]
    years = sorted(
        {
            row[0][:4]
            for row in (_rows(replies["years"]) if "years" in replies else None) or []
            if _YEAR_RE.match(row[0])
        }
    )
    sample: list[str] = []
    for row in (_rows(replies["urls"]) if "urls" in replies else None) or []:
        cleaned = _clean_url(row[0])
        if cleaned and cleaned not in sample:
            sample.append(cleaned)

    complete = all(not r.failure for r in replies.values())
    result = {
        "measured": True,
        "error": None,
        "available": bool(first_seen or last_seen or closest),
        "first_seen": first_seen,
        "last_seen": last_seen,
        "years_active": years[:MAX_YEARS],
        "closest": closest,
        "sample_urls": sample[:MAX_SAMPLE_URLS],
        "archive_url": "https://web.archive.org/web/*/" + domain,
        "partial": not complete,
    }
    if not complete:
        raise Partial(result)
    return result


@cached(MEDIUM_TTL, scope=common.proxy_scope, ignore=("client",))
async def _collect(client: httpx.AsyncClient, domain: str) -> dict:
    """Interroge archive.org ; seul un résultat complet est gardé (un partiel lève Partial)."""
    base = {"output": "json", "url": domain}
    fields = {"fl": "timestamp,original,statuscode"}
    jobs = {
        "first": _fetch(client, CDX_URL, {**base, **fields, "limit": "1"}, TIMEOUT_FIRST),
        "last": _fetch(
            client, CDX_URL, {**base, **fields, "limit": "-1", "fastLatest": "true"}, TIMEOUT_LAST
        ),
        "available": _fetch(client, AVAILABLE_URL, {"url": domain}, TIMEOUT_AVAILABLE),
        "years": _fetch(
            client,
            CDX_URL,
            {**base, "fl": "timestamp", "collapse": "timestamp:4", "filter": "statuscode:200", "limit": "60"},
            TIMEOUT_YEARS,
        ),
        "urls": _fetch(
            client,
            CDX_URL,
            {
                **base,
                "matchType": "host",
                "fl": "original",
                "collapse": "urlkey",
                "filter": "statuscode:200",
                "limit": str(MAX_SAMPLE_URLS * 2),
            },
            TIMEOUT_URLS,
        ),
    }
    tasks = {name: asyncio.ensure_future(job) for name, job in jobs.items()}
    try:
        await asyncio.wait(tasks.values(), timeout=TOTAL_BUDGET)
    finally:
        for task in tasks.values():
            if not task.done():
                task.cancel()
    replies: dict[str, Reply] = {}
    for name, task in tasks.items():
        if task.done() and not task.cancelled() and task.exception() is None:
            replies[name] = task.result()
        else:
            replies[name] = Reply(failure="timeout", detail="timeout")
    return build_result(domain, replies)


async def analyze(client: httpx.AsyncClient, domain: str) -> dict:
    """Historique d'archivage du domaine (complet ou partiel ; ModuleError si rien d'essentiel n'a répondu)."""
    try:
        return await _collect(client, domain)
    except Partial as partial:
        return partial.result
