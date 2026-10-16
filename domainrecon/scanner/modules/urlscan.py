# =============================================================================
# DomainRecon - Module « urlscan » : historique des analyses publiques d'urlscan.io
# =============================================================================
# Aucun scan n'est lancé : le module consulte l'historique public.
#   - GET https://urlscan.io/api/v1/search/?q=…   (recherche, 30/min sans clé) ;
#   - GET https://urlscan.io/api/v1/result/{uuid}/ (verdicts des 2 analyses les
#     plus récentes de la cible).
# Documentation : https://docs.urlscan.io/apis/urlscan-openapi/search/ et
# https://docs.urlscan.io/pages/api-rate-limits. La clé (facultative, en-tête
# « API-Key ») élève les quotas et donne accès aux analyses non listées.
#
# Pièges évités (vérifiés le
# 15/10/2026) :
#   - la requête « domain:exemple.com » renvoie aussi les pages d'AUTRES sites qui
#     chargent une ressource du domaine : le module cherche les pages dont l'hôte
#     est la cible ET qui ont été soumises pour cette cible (task et page), pour
#     que le verdict ne soit pas celui d'un tiers ;
#   - la recherche ne contient pas de verdicts (le champ « verdicts » est null) :
#     les verdicts sont donc lus dans
#     le résultat détaillé des analyses les plus récentes (clé requise : la lecture
#     d'un résultat est refusée en 403 sans compte, l'historique reste visible sans clé) ;
#   - ordre déterministe (adresses et pays triés par fréquence puis nom), 429
#     signalé, objets bruts non recopiés (seuls les champs utiles sont gardés).
# =============================================================================

import json
from collections import Counter

import httpx

from ...i18n import msg
from ..cache import LONG_TTL, MEDIUM_TTL, cached
from ..common import proxy_scope
from ..errors import ModuleError, TargetNotAllowedError
from ..http_utils import read_body_limited
from ..keys import ApiKey
from ..registry import ModuleSpec, ScanContext
from ..rules import FindingInput, FindingRule, Outcome, ScoreRule, hit
from ..score import as_dict, as_int, as_list
from ..targets import is_ip_literal

_SEARCH = "https://urlscan.io/api/v1/search/"
_RESULT = "https://urlscan.io/api/v1/result/{uuid}/"
_REPORT = "https://urlscan.io/result/{uuid}/"
_SERVICE = "urlscan.io"
_TIMEOUT = 20
_SEARCH_SIZE = 50
# Analyses dont le résultat détaillé est lu (1 requête chacune, 20 par minute sans clé).
_VERDICT_SCANS = 2
_RESULT_MAX_BYTES = 8 * 1024 * 1024
_MAX_LIST = 10


def _headers(key: str) -> dict:
    headers = {"Accept": "application/json"}
    if key:
        headers["API-Key"] = key
    return headers


def _fail(error: BaseException) -> ModuleError:
    # Jamais str(error) : le texte d'une erreur httpx cite l'URL.
    if isinstance(error, httpx.TimeoutException):
        return ModuleError(msg("network.service_error", context=_SERVICE, detail=msg("net.timeout")))
    return ModuleError(msg("network.service_error", context=_SERVICE, detail=type(error).__name__))


def build_query(domain: str, apex: str, is_ip: bool, shared: bool) -> str:
    """Requête de recherche : pages dont l'hôte est la cible et soumises pour elle (ou par IP pour une IP)."""
    if is_ip:
        return f'page.ip:"{domain}"'
    if domain == apex and not shared:
        return f"task.apexDomain:{apex} AND page.apexDomain:{apex}"
    return f"task.domain:{domain} AND page.domain:{domain}"


@cached(MEDIUM_TTL, scope=proxy_scope, ignore=("client", "key"))
async def _search(client: httpx.AsyncClient, key: str, query: str) -> dict:
    try:
        response = await client.get(
            _SEARCH,
            params={"q": query, "size": str(_SEARCH_SIZE)},
            headers=_headers(key),
            timeout=_TIMEOUT,
        )
    except (httpx.HTTPError, TargetNotAllowedError) as e:
        raise _fail(e) from None
    if response.status_code == 429:
        raise ModuleError(msg("network.quota", service=_SERVICE))
    if response.status_code != 200:
        raise ModuleError(msg("network.http_status", status=response.status_code, service=_SERVICE))
    try:
        data = as_dict(response.json())
    except ValueError:
        raise ModuleError(msg("urlscan.unreadable")) from None
    if not isinstance(data.get("results"), list):
        raise ModuleError(msg("urlscan.unreadable"))
    return data


@cached(LONG_TTL, scope=proxy_scope, ignore=("client", "key"))
async def _verdict(client: httpx.AsyncClient, key: str, uuid: str) -> dict:
    """Verdict global d'une analyse (résultat détaillé, immuable : gardé 24 h)."""
    try:
        async with client.stream(
            "GET", _RESULT.format(uuid=uuid), headers=_headers(key), timeout=_TIMEOUT
        ) as r:
            status = r.status_code
            body, truncated = (
                (await read_body_limited(r, _RESULT_MAX_BYTES)) if status == 200 else (b"", False)
            )
    except (httpx.HTTPError, TargetNotAllowedError) as e:
        raise _fail(e) from None
    if status == 429:
        raise ModuleError(msg("network.quota", service=_SERVICE))
    if status != 200 or truncated:
        raise ModuleError(msg("network.http_status", status=status, service=_SERVICE))
    try:
        overall = as_dict(as_dict(as_dict(json.loads(body)).get("verdicts")).get("overall"))
    except ValueError:
        raise ModuleError(msg("urlscan.unreadable")) from None
    return {
        "measured": True,
        "error": None,
        "has_verdicts": overall.get("hasVerdicts") in (1, True),
        "malicious": overall.get("malicious") is True,
        "score": as_int(overall.get("score")) or 0,
        "categories": [c for c in as_list(overall.get("categories")) if isinstance(c, str)][:_MAX_LIST],
        "brands": [
            b.get("name") if isinstance(b, dict) else b
            for b in as_list(overall.get("brands"))
            if (isinstance(b, dict) and isinstance(b.get("name"), str)) or isinstance(b, str)
        ][:_MAX_LIST],
    }


def _ranked(counter: Counter) -> list[str]:
    """Valeurs triées par fréquence décroissante puis par nom (ordre déterministe)."""
    return [value for value, _ in sorted(counter.items(), key=lambda item: (-item[1], item[0]))][:_MAX_LIST]


def _summarize(data: dict) -> dict:
    results = [as_dict(r) for r in as_list(data.get("results"))]
    ips: Counter = Counter()
    countries: Counter = Counter()
    servers: Counter = Counter()
    for r in results:
        page = as_dict(r.get("page"))
        for counter, field in ((ips, "ip"), (countries, "country"), (servers, "server")):
            if isinstance(page.get(field), str) and page[field]:
                counter[page[field]] += 1
    latest = results[0] if results else {}
    task = as_dict(latest.get("task"))
    page = as_dict(latest.get("page"))
    times = sorted(t for t in (as_dict(r.get("task")).get("time") for r in results) if isinstance(t, str))
    uuid = task.get("uuid") if isinstance(task.get("uuid"), str) else None
    return {
        "total_scans": as_int(data.get("total")) or 0,
        "analyzed_scans": len(results),
        "last_scan": times[-1] if times else None,
        "first_scan": times[0] if times else None,
        "ips_seen": _ranked(ips),
        "countries_seen": _ranked(countries),
        "servers_seen": _ranked(servers),
        "page_title": page.get("title") if isinstance(page.get("title"), str) else None,
        "screenshot_url": latest.get("screenshot") if isinstance(latest.get("screenshot"), str) else None,
        "report_url": _REPORT.format(uuid=uuid) if uuid else None,
    }


async def run(context: ScanContext) -> dict:
    key = context.secrets.get("urlscan_key", "")
    is_ip = is_ip_literal(context.domain)
    query = build_query(context.domain, context.apex, is_ip, context.shared_platform)
    data = await _search(context.http, key, query)
    result = {"measured": True, "error": None, "query": query, "authenticated": bool(key), **_summarize(data)}
    verdicts: list[dict] = []
    # Verdicts : seulement pour une cible nommée (sur une IP, les analyses concernent des sites tiers)
    # et avec une clé : urlscan.io répond 403 « not logged in » aux lectures de résultat anonymes (15/10/2026).
    if not is_ip and key:
        for item in as_list(data.get("results"))[:_VERDICT_SCANS]:
            uuid = as_dict(as_dict(item).get("task")).get("uuid")
            if not isinstance(uuid, str):
                continue
            try:
                verdict = await _verdict(context.http, key, uuid)
            except ModuleError:
                # Verdicts facultatifs : une limite de débit ne fait pas perdre l'historique déjà obtenu.
                continue
            when = as_dict(as_dict(item).get("task")).get("time")
            verdicts.append(
                {
                    "report_url": _REPORT.format(uuid=uuid),
                    "time": when if isinstance(when, str) else None,
                    **{k: v for k, v in verdict.items() if k not in ("measured", "error")},
                }
            )
    result["verdicts"] = verdicts
    result["malicious_scans"] = sum(1 for v in verdicts if v["malicious"])
    return result


# -----------------------------------------------------------------------------
# Constats et score
# -----------------------------------------------------------------------------


def _check_malicious(f: FindingInput):
    data = as_dict(f.data)
    flagged = [v for v in as_list(data.get("verdicts")) if as_dict(v).get("malicious") is True]
    if not flagged:
        return None
    newest = as_dict(flagged[0])
    return hit(
        severity="high",
        count=len(flagged),
        categories=", ".join(str(c) for c in as_list(newest.get("categories"))) or "-",
        report=newest.get("report_url") or "",
    )


def _score(data: dict) -> Outcome:
    result = as_dict(data.get("urlscan"))
    verdicts = [as_dict(v) for v in as_list(result.get("verdicts")) if as_dict(v).get("has_verdicts")]
    if not verdicts:
        return Outcome(0, msg("urlscan.score_unknown"), False)
    if any(v.get("malicious") is True for v in verdicts):
        return Outcome(0, msg("urlscan.score_malicious"), True)
    return Outcome(3, msg("urlscan.score_clean", count=as_int(result.get("total_scans")) or 0), True)


SPEC = ModuleSpec(
    name="urlscan",
    family="reputation",
    category="passif",
    run=run,
    keys=(ApiKey(name="urlscan_key", service="urlscan", label="urlscan.io", required=False),),
    wave=1,
    timeout=60,
    optional=True,
    order=660,
    findings=(FindingRule(code="finding.urlscan.malicious", severity="high", check=_check_malicious),),
    score_rules=(ScoreRule(criterion="urlscan", weight=3, evaluate=_score),),
)
