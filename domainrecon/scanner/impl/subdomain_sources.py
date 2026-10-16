# =============================================================================
# DomainRecon - Sous-domaines : sources passives gratuites
# =============================================================================
# Sources interrogées en parallèle, chacune bornée dans le temps ; une source
# en échec n'empêche pas les autres.
# Aucune ne touche la cible : ce sont des archives publiques.
#
#   (crt.sh et Cert Spotter, journaux Certificate Transparency : scanner.dns.find_subdomains,
#   appelé par le module et fusionné avec les sources ci-dessous)
#   hackertarget           https://api.hackertarget.com/hostsearch/?q=<domaine>
#                          (texte « hôte,ip » ; 50 appels/jour sans compte, quota
#                          annoncé dans le corps d'une réponse 200)
#   rapiddns               https://rapiddns.io/subdomain/<domaine>?full=1 (page HTML)
#   anubis                 https://anubisdb.com/anubis/subdomains/<domaine> (liste JSON ;
#                          l'ancien jldc.me redirige)
#   otx                    https://otx.alienvault.com/api/v1/indicators/domain/<domaine>/url_list
#                          (passive_dns exige désormais une clé : l'hôte des URL vues suffit)
#   urlscan                https://urlscan.io/api/v1/search/?q=domain:<domaine> (sans clé)
#   wayback                https://web.archive.org/cdx/search/cdx?url=<domaine>&matchType=domain
#                          (lent : dernière source, délai propre)
#   securitytrails         avec clé (facultative), impl/securitytrails.py
# Morts et retirés : Sonar/omnisint, ThreatCrowd, Columbus (injoignable en 2026).
# =============================================================================

import asyncio
import re
from collections.abc import Awaitable, Callable, Iterable
from typing import NamedTuple
from urllib.parse import urlsplit

import httpx

from ...i18n import msg
from ..common import logger
from ..errors import ModuleError, TargetNotAllowedError
from ..targets import is_valid_target
from . import dns_http, securitytrails

SOURCE_TIMEOUT = 18.0
WAYBACK_TIMEOUT = 24.0

_CELL = re.compile(r"<td>\s*([A-Za-z0-9._*-]+)\s*</td>")


class SourceReport(NamedTuple):
    """État d'une source dans le résultat du module (JSON : voir as_dict)."""

    name: str
    status: str  # "ok", "error" ou "skipped"
    count: int
    error: object | None = None

    def as_dict(self) -> dict:
        return {"name": self.name, "status": self.status, "count": self.count, "error": self.error}


def clean_names(candidates: Iterable[object], domain: str) -> set[str]:
    """Sous-domaines STRICTS de `domain` dans `candidates` (frontière de label, noms valides, jokers ôtés)."""
    suffix = "." + domain
    names: set[str] = set()
    for item in candidates:
        if not isinstance(item, str):
            continue
        name = item.strip().lower().rstrip(".")
        if name.startswith("*."):
            name = name[2:]
        if name.startswith("*") or not name.endswith(suffix) or len(name) > 253:
            continue
        if is_valid_target(name):
            names.add(name)
    return names


# --- Sources ------------------------------------------------------------------


async def _hackertarget(client: httpx.AsyncClient | None, domain: str) -> set[str]:
    service = "HackerTarget"
    async with dns_http.session(client) as http:
        reply = await dns_http.get(
            http, "https://api.hackertarget.com/hostsearch/", service=service, params={"q": domain}
        )
    if reply.status != 200:
        raise dns_http.status_error(service, reply.status)
    text = reply.text.strip()
    lowered = text.lower()
    if "api count exceeded" in lowered or "increase quota" in lowered:
        raise ModuleError(msg("network.quota", service=service))
    if lowered.startswith("error") or lowered.startswith("no records"):
        return set()
    return clean_names((line.split(",", 1)[0] for line in text.splitlines()), domain)


async def _rapiddns(client: httpx.AsyncClient | None, domain: str) -> set[str]:
    service = "RapidDNS"
    async with dns_http.session(client) as http:
        reply = await dns_http.get(
            http, f"https://rapiddns.io/subdomain/{domain}", service=service, params={"full": "1"}
        )
    if reply.status != 200:
        raise dns_http.status_error(service, reply.status)
    return clean_names(_CELL.findall(reply.text), domain)


async def _anubis(client: httpx.AsyncClient | None, domain: str) -> set[str]:
    service = "Anubis"
    async with dns_http.session(client) as http:
        reply = await dns_http.get(http, f"https://anubisdb.com/anubis/subdomains/{domain}", service=service)
    if reply.status == 404:
        return set()
    if reply.status != 200:
        raise dns_http.status_error(service, reply.status)
    try:
        data = reply.json()
    except ValueError:
        raise ModuleError(
            msg("network.service_error", context=service, detail=msg("subdomains_passive.unreadable"))
        ) from None
    return clean_names(data, domain) if isinstance(data, list) else set()


async def _otx(client: httpx.AsyncClient | None, domain: str) -> set[str]:
    service = "AlienVault OTX"
    async with dns_http.session(client) as http:
        reply = await dns_http.get(
            http,
            f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/url_list",
            service=service,
            params={"limit": "500", "page": "1"},
        )
    if reply.status != 200:
        raise dns_http.status_error(service, reply.status)
    try:
        data = reply.json()
    except ValueError:
        raise ModuleError(
            msg("network.service_error", context=service, detail=msg("subdomains_passive.unreadable"))
        ) from None
    entries = data.get("url_list") if isinstance(data, dict) else None
    if not isinstance(entries, list):
        return set()
    return clean_names((e.get("hostname") for e in entries if isinstance(e, dict)), domain)


async def _urlscan(client: httpx.AsyncClient | None, domain: str) -> set[str]:
    service = "urlscan.io"
    async with dns_http.session(client) as http:
        reply = await dns_http.get(
            http,
            "https://urlscan.io/api/v1/search/",
            service=service,
            params={"q": f"domain:{domain}", "size": "100"},
        )
    if reply.status != 200:
        raise dns_http.status_error(service, reply.status)
    try:
        data = reply.json()
    except ValueError:
        raise ModuleError(
            msg("network.service_error", context=service, detail=msg("subdomains_passive.unreadable"))
        ) from None
    results = data.get("results") if isinstance(data, dict) else None
    if not isinstance(results, list):
        return set()
    hosts: list[object] = []
    for result in results:
        if not isinstance(result, dict):
            continue
        for part in ("page", "task"):
            section = result.get(part)
            if isinstance(section, dict):
                hosts.append(section.get("domain"))
    return clean_names(hosts, domain)


async def _wayback(client: httpx.AsyncClient | None, domain: str) -> set[str]:
    service = "Wayback Machine"
    async with dns_http.session(client, WAYBACK_TIMEOUT) as http:
        reply = await dns_http.get(
            http,
            "https://web.archive.org/cdx/search/cdx",
            service=service,
            params={
                "url": domain,
                "matchType": "domain",
                "fl": "original",
                "collapse": "urlkey",
                "output": "json",
                "limit": "500",
                "filter": "statuscode:200",
            },
            timeout=WAYBACK_TIMEOUT,
        )
    if reply.status != 200:
        raise dns_http.status_error(service, reply.status)
    try:
        rows = reply.json()
    except ValueError:
        raise ModuleError(
            msg("network.service_error", context=service, detail=msg("subdomains_passive.unreadable"))
        ) from None
    hosts: list[object] = []
    for row in rows[1:] if isinstance(rows, list) else []:
        original = row[0] if isinstance(row, list) and row else None
        if isinstance(original, str):
            try:
                hosts.append(urlsplit(original).hostname)
            except ValueError:
                continue
    return clean_names(hosts, domain)


# --- Orchestration ---------------------------------------------------------------

Source = Callable[[httpx.AsyncClient | None, str], Awaitable[set[str]]]

# Sources sans clé, hors journaux CT, et leur délai.
FREE_SOURCES: tuple[tuple[str, Source, float], ...] = (
    ("hackertarget", _hackertarget, SOURCE_TIMEOUT),
    ("rapiddns", _rapiddns, SOURCE_TIMEOUT),
    ("anubis", _anubis, SOURCE_TIMEOUT),
    ("otx", _otx, SOURCE_TIMEOUT),
    ("urlscan", _urlscan, SOURCE_TIMEOUT),
    ("wayback", _wayback, WAYBACK_TIMEOUT),
)


async def _guard(name: str, timeout: float, call: Awaitable[set[str]]) -> tuple[set[str], SourceReport]:
    """Exécute une source sous délai : ses noms et son rapport ; jamais d'exception (sauf annulation).

    Toute erreur d'une source, même inattendue, est isolée : elle ne doit jamais faire échouer le module.
    """
    try:
        names = await asyncio.wait_for(call, timeout=timeout)
    except ModuleError as e:
        return set(), SourceReport(name, "error", 0, e.message)
    except (asyncio.TimeoutError, TimeoutError):
        return set(), SourceReport(name, "error", 0, msg("net.timeout"))
    except (httpx.HTTPError, TargetNotAllowedError) as e:
        detail = type(e).__name__
        return set(), SourceReport(
            name, "error", 0, msg("network.service_error", context=name, detail=detail)
        )
    except Exception as e:
        logger.debug("Source de sous-domaines %s en échec : %r", name, e)
        detail = type(e).__name__
        return set(), SourceReport(
            name, "error", 0, msg("network.service_error", context=name, detail=detail)
        )
    return names, SourceReport(name, "ok", len(names))


async def collect_extra(
    client: httpx.AsyncClient | None, domain: str, securitytrails_key: str | None = None
) -> tuple[dict[str, set[str]], list[SourceReport]]:
    """Noms des sources autres que les journaux CT : ({nom: {sources}}, rapports). Ne lève jamais."""
    tasks = [_guard(name, timeout, call(client, domain)) for name, call, timeout in FREE_SOURCES]
    if securitytrails_key:
        tasks.append(
            _guard(
                "securitytrails", SOURCE_TIMEOUT, _securitytrails_names(client, securitytrails_key, domain)
            )
        )
    found: dict[str, set[str]] = {}
    reports: list[SourceReport] = []
    for names, report in await asyncio.gather(*tasks):
        reports.append(report)
        for name in names:
            found.setdefault(name, set()).add(report.name)
    return found, reports


async def _securitytrails_names(client: httpx.AsyncClient | None, key: str, domain: str) -> set[str]:
    return set(await securitytrails.fetch_subdomains(client, key, domain))
