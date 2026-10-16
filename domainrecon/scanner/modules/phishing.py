# =============================================================================
# DomainRecon - Module « phishing » : flux d'hameçonnage PhishTank et OpenPhish
# =============================================================================
# Sources (téléchargées puis recherchées en local : aucune URL de la cible
# n'est envoyée à un tiers) :
#   - PhishTank, flux « verified_online » (CSV, ~12 Mo, mis à jour toutes les
#     heures, utilisable sans clé) : https://data.phishtank.com/data/online-valid.csv
#     redirigé vers un CDN signé. Documentation : https://phishtank.org/developer_info.php.
#     Si le flux est indisponible, repli sur l'API checkurl (POST, URL exacte) ;
#   - OpenPhish, flux communautaire (liste d'URL) : https://openphish.com/feed.txt
#     (redirigé vers le dépôt public openphish/public_feed).
#
# Ne compter que « in_database » serait trompeur : PhishTank connaît des entrées non vérifiées
# ou invalides (example.com y figure, verified=false, valid=false). Ici, seules
# les entrées vérifiées et en ligne comptent.
#
# Lecture des correspondances (faux positifs) :
#   - « racine » : l'adresse d'accueil du site lui-même est listée (site
#     lui-même dédié à l'hameçonnage ou piraté) -> constat grave ;
#   - « pages » : des pages précises de l'hôte sont listées (site compromis, ou
#     grande plateforme d'hébergement abusée : google.com compte plus de 6000
#     entrées) -> constat moyen, faible au-delà de 50 entrées ;
#   - sur une plateforme mutualisée (suffixe privé de la liste PSL), seul le
#     sous-domaine de la cible compte, pas toute la plateforme.
# Les index sont gardés 1 h en mémoire (un seul téléchargement pour plusieurs scans).
# =============================================================================

import asyncio
import base64
import csv
import io
import time
from collections.abc import Callable
from urllib.parse import urljoin, urlsplit

import httpx

from ...i18n import msg
from ..common import ACCEPT_ENCODING, proxy_scope
from ..errors import ModuleError, TargetNotAllowedError
from ..http_utils import read_body_limited
from ..registry import ModuleSpec, ScanContext
from ..rules import FindingInput, FindingRule, Outcome, ScoreRule, hit
from ..score import as_dict, as_int, as_list

PHISHTANK_FEED = "https://data.phishtank.com/data/online-valid.csv"
PHISHTANK_CHECK = "https://checkurl.phishtank.com/checkurl/"
OPENPHISH_FEED = "https://openphish.com/feed.txt"
# PhishTank refuse les User-Agent génériques : il demande « phishtank/<nom de l'application> ».
PHISHTANK_UA = "phishtank/domainrecon"

_PHISHTANK_MAX_BYTES = 80 * 1024 * 1024
_OPENPHISH_MAX_BYTES = 10 * 1024 * 1024
_DOWNLOAD_TIMEOUT = 45
_MAX_REDIRECTS = 4
# Durée de vie des index en mémoire, en secondes (PhishTank se met à jour toutes les heures).
_INDEX_TTL = 3600
_MAX_SAMPLES_PER_HOST = 5
_MAX_HITS = 10
_URL_LIMIT = 200
# À partir de ce nombre de pages listées, l'hôte est une plateforme abusée plutôt qu'un site piraté.
ABUSED_PLATFORM_PAGES = 50

# Index : hôte -> [entrées racine, entrées pages, échantillons (url, id, cible, date)].
Index = dict[str, list]
# {(portée du proxy, source): (horodatage, index)}
_INDEXES: dict[tuple[str | None, str], tuple[float, Index]] = {}


def clear_indexes() -> None:
    """Vide les index en mémoire (tests)."""
    _INDEXES.clear()


# -----------------------------------------------------------------------------
# Téléchargement et indexation
# -----------------------------------------------------------------------------


async def _download(
    client: httpx.AsyncClient, url: str, limit: int, service: str, user_agent: str | None = None
) -> bytes:
    """Télécharge un flux en suivant au plus 4 redirections (le client n'en suit aucune), taille bornée."""
    headers = {"Accept-Encoding": ACCEPT_ENCODING}
    if user_agent:
        headers["User-Agent"] = user_agent
    for _ in range(_MAX_REDIRECTS + 1):
        async with client.stream("GET", url, headers=headers, timeout=_DOWNLOAD_TIMEOUT) as response:
            status = response.status_code
            if status in (301, 302, 303, 307, 308):
                location = response.headers.get("location")
                if not location:
                    raise ModuleError(msg("network.http_status", status=status, service=service))
                url = urljoin(url, location)
                if urlsplit(url).scheme != "https":
                    raise ModuleError(msg("phishing.insecure_redirect"))
                continue
            if status == 429:
                raise ModuleError(msg("network.quota", service=service))
            if status != 200:
                raise ModuleError(msg("network.http_status", status=status, service=service))
            body, truncated = await read_body_limited(response, limit)
            if truncated:
                raise ModuleError(msg("phishing.feed_too_large"))
            return body
    raise ModuleError(msg("http.too_many_redirects", max=_MAX_REDIRECTS))


def _add(index: Index, url: str, phish_id: str | None, target: str | None, when: str | None) -> None:
    try:
        parts = urlsplit(url.strip())
        host = (parts.hostname or "").lower().rstrip(".")
    except ValueError:
        return
    if not host:
        return
    entry = index.setdefault(host, [0, 0, []])
    entry[0 if parts.path in ("", "/") and not parts.query else 1] += 1
    if len(entry[2]) < _MAX_SAMPLES_PER_HOST:
        entry[2].append((url.strip()[:_URL_LIMIT], phish_id, target, when))


def parse_phishtank_csv(text: str) -> Index:
    """Index du CSV PhishTank (phish_id,url,phish_detail_url,submission_time,verified,verification_time,online,target)."""
    index: Index = {}
    reader = csv.reader(io.StringIO(text))
    header = next(reader, None)
    if not header or "url" not in header:
        raise ModuleError(msg("phishing.feed_unreadable", source="PhishTank"))
    column = {name: i for i, name in enumerate(header)}

    def cell(row: list[str], name: str) -> str | None:
        i = column.get(name)
        return row[i] if i is not None and i < len(row) and row[i] else None

    for row in reader:
        # Seules les entrées vérifiées et en ligne comptent (le flux ne contient que celles-là).
        if cell(row, "verified") not in (None, "yes") or cell(row, "online") not in (None, "yes"):
            continue
        url = cell(row, "url")
        if url:
            _add(index, url, cell(row, "phish_id"), cell(row, "target"), cell(row, "submission_time"))
    return index


def parse_openphish(text: str) -> Index:
    index: Index = {}
    for line in text.splitlines():
        line = line.strip()
        if line.startswith(("http://", "https://")):
            _add(index, line, None, None, None)
    if not index:
        raise ModuleError(msg("phishing.feed_unreadable", source="OpenPhish"))
    return index


async def _index(
    client: httpx.AsyncClient,
    source: str,
    url: str,
    limit: int,
    service: str,
    parse: Callable[[str], Index],
    user_agent: str | None = None,
) -> Index:
    """Index d'un flux, gardé 1 h par proxy."""
    key = (proxy_scope(), source)
    cached = _INDEXES.get(key)
    if cached and time.monotonic() - cached[0] < _INDEX_TTL:
        return cached[1]
    body = await _download(client, url, limit, service, user_agent)
    index = await asyncio.to_thread(parse, body.decode("utf-8", errors="replace"))
    if len(_INDEXES) > 16:
        _INDEXES.clear()
    _INDEXES[key] = (time.monotonic(), index)
    return index


# -----------------------------------------------------------------------------
# Recherche
# -----------------------------------------------------------------------------


def match_index(index: Index, scope: str) -> dict:
    """Entrées de l'index dont l'hôte est `scope` ou l'un de ses sous-domaines."""
    suffix = f".{scope}"
    root = pages = 0
    samples: list[tuple] = []
    for host, (root_count, page_count, entries) in index.items():
        if host == scope or host.endswith(suffix):
            root += root_count
            pages += page_count
            samples.extend((host, *sample) for sample in entries)
    return {"root": root, "pages": pages, "samples": samples}


async def _phishtank_api(client: httpx.AsyncClient, scope: str) -> dict:
    """Repli : API checkurl de PhishTank sur les adresses d'accueil (http/https, avec et sans www)."""
    root = pages = 0
    samples: list[tuple] = []
    hosts = [scope] if scope.startswith("www.") else [scope, f"www.{scope}"]
    for host in hosts:
        for scheme in ("http", "https"):
            url = f"{scheme}://{host}/"
            try:
                response = await client.post(
                    PHISHTANK_CHECK,
                    data={"url": base64.b64encode(url.encode()).decode("ascii"), "format": "json"},
                    headers={"User-Agent": PHISHTANK_UA},
                    timeout=15,
                )
            except httpx.TimeoutException:
                raise ModuleError(
                    msg("network.service_error", context="PhishTank", detail=msg("net.timeout"))
                ) from None
            except (httpx.HTTPError, TargetNotAllowedError) as e:
                raise ModuleError(
                    msg("network.service_error", context="PhishTank", detail=type(e).__name__)
                ) from None
            if response.status_code == 429:
                raise ModuleError(msg("network.quota", service="PhishTank"))
            if response.status_code != 200:
                raise ModuleError(
                    msg("network.http_status", status=response.status_code, service="PhishTank")
                )
            try:
                results = as_dict(as_dict(response.json()).get("results"))
            except ValueError:
                raise ModuleError(msg("phishing.feed_unreadable", source="PhishTank")) from None
            # in_database seul ne suffit pas : l'entrée doit être vérifiée et valide (en ligne).
            if (
                results.get("in_database") is True
                and results.get("verified") is True
                and results.get("valid") is True
            ):
                root += 1
                phish_id = results.get("phish_id")
                samples.append(
                    (host, url, str(phish_id) if phish_id else None, None, results.get("verified_at"))
                )
    return {"root": root, "pages": pages, "samples": samples}


def _target_scope(context: ScanContext) -> str:
    """Hôte dont les correspondances comptent : domaine enregistrable, ou site de la cible sur une plateforme."""
    if context.is_ip_target:
        return context.domain
    return context.site if context.shared_platform else context.apex


async def _source(coro, service: str) -> tuple[dict | None, object | None]:
    """Résultat d'une source, ou son erreur : l'échec d'une source ne fait pas perdre l'autre."""
    try:
        return await coro, None
    except ModuleError as e:
        return None, e.message
    except (httpx.HTTPError, TargetNotAllowedError) as e:
        # Jamais str(e) : le texte d'une erreur httpx cite l'URL.
        return None, msg("network.service_error", context=service, detail=type(e).__name__)


async def _phishtank(client: httpx.AsyncClient, scope: str) -> dict:
    try:
        index = await _index(
            client,
            "phishtank",
            PHISHTANK_FEED,
            _PHISHTANK_MAX_BYTES,
            "PhishTank",
            parse_phishtank_csv,
            PHISHTANK_UA,
        )
    except (ModuleError, httpx.HTTPError, TargetNotAllowedError):
        # Flux indisponible : API de repli, dont l'erreur éventuelle est celle de la source.
        found = await _phishtank_api(client, scope)
        return {**found, "mode": "api", "entries": None}
    return {**match_index(index, scope), "mode": "feed", "entries": sum(sum(v[:2]) for v in index.values())}


async def _openphish(client: httpx.AsyncClient, scope: str) -> dict:
    index = await _index(
        client, "openphish", OPENPHISH_FEED, _OPENPHISH_MAX_BYTES, "OpenPhish", parse_openphish
    )
    return {**match_index(index, scope), "mode": "feed", "entries": sum(sum(v[:2]) for v in index.values())}


async def run(context: ScanContext) -> dict:
    scope = _target_scope(context)
    (phishtank, phishtank_error), (openphish, openphish_error) = await asyncio.gather(
        _source(_phishtank(context.http, scope), "PhishTank"),
        _source(_openphish(context.http, scope), "OpenPhish"),
    )
    if phishtank is None and openphish is None:
        raise ModuleError(msg("phishing.no_source"))

    sources: dict[str, dict] = {}
    hits: list[dict] = []
    root = pages = 0
    for name, found, error in (
        ("phishtank", phishtank, phishtank_error),
        ("openphish", openphish, openphish_error),
    ):
        if found is None:
            sources[name] = {"status": "failed", "error": error}
            continue
        sources[name] = {
            "status": "ok",
            "mode": found["mode"],
            "entries": found["entries"],
            "root": found["root"],
            "pages": found["pages"],
        }
        root += found["root"]
        pages += found["pages"]
        for host, url, phish_id, target, when in found["samples"]:
            hits.append(
                {
                    "source": name,
                    "host": host,
                    "url": url,
                    "phish_id": phish_id,
                    "target": target,
                    "submitted": when,
                    "detail_url": f"https://www.phishtank.com/phish_detail.php?phish_id={phish_id}"
                    if phish_id
                    else None,
                }
            )
    hits.sort(key=lambda h: (h["source"], h["url"]))
    return {
        "measured": True,
        "error": None,
        "scope": scope,
        "listed": bool(root or pages),
        "root_hits": root,
        "page_hits": pages,
        "abused_platform": pages >= ABUSED_PLATFORM_PAGES,
        "sources": sources,
        "failed_sources": [name for name, s in sources.items() if s["status"] == "failed"],
        "hits": hits[:_MAX_HITS],
    }


# -----------------------------------------------------------------------------
# Constats et score
# -----------------------------------------------------------------------------


def _sources_with_hits(data: dict) -> str:
    names = sorted({h.get("source", "") for h in map(as_dict, as_list(data.get("hits"))) if h.get("source")})
    return ", ".join(n for n in names) or "-"


def _sample(data: dict) -> str:
    hits = [as_dict(h) for h in as_list(data.get("hits"))]
    return str(hits[0].get("url", "")) if hits else ""


def _check_root(f: FindingInput):
    data = as_dict(f.data)
    count = as_int(data.get("root_hits")) or 0
    if count < 1:
        return None
    return {
        "count": count,
        "sources": _sources_with_hits(data),
        "scope": str(data.get("scope", "")),
        "sample": _sample(data),
    }


def _check_pages(f: FindingInput):
    data = as_dict(f.data)
    count = as_int(data.get("page_hits")) or 0
    if count < 1:
        return None
    severity = "low" if count >= ABUSED_PLATFORM_PAGES else "medium"
    return hit(
        severity=severity,
        count=count,
        sources=_sources_with_hits(data),
        scope=str(data.get("scope", "")),
        sample=_sample(data),
    )


def _score(data: dict) -> Outcome:
    result = as_dict(data.get("phishing"))
    root = as_int(result.get("root_hits")) or 0
    pages = as_int(result.get("page_hits")) or 0
    if root:
        return Outcome(0, msg("phishing.score_root", count=root), True)
    if pages >= ABUSED_PLATFORM_PAGES:
        return Outcome(4, msg("phishing.score_platform", count=pages), True)
    if pages:
        return Outcome(2, msg("phishing.score_pages", count=pages), True)
    return Outcome(5, msg("phishing.score_clean"), True)


SPEC = ModuleSpec(
    name="phishing",
    family="reputation",
    category="passif",
    run=run,
    wave=1,
    timeout=90,
    optional=True,
    verdict=True,
    order=650,
    findings=(
        FindingRule(code="finding.phishing.root_listed", severity="high", check=_check_root),
        FindingRule(code="finding.phishing.pages_listed", severity="medium", check=_check_pages),
    ),
    score_rules=(ScoreRule(criterion="phishing", weight=5, evaluate=_score),),
)
