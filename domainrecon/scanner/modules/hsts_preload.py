# =============================================================================
# DomainRecon - Module « hsts_preload » : HSTS approfondi et liste de précharge
# =============================================================================
# Deux volets :
#   - HSTS approfondi : max-age, includeSubDomains, preload, note A à F ;
#   - statut dans la liste de précharge des navigateurs.
# Le statut renvoyé par hstspreload.org est normalisé (son JSON brut n'est pas
# exploitable tel quel) ; « éligible » signifie réellement que
# l'en-tête remplit les exigences de la liste (max-age >= 1 an, includeSubDomains,
# preload) et non « preloaded ou pending » ; les obstacles à la soumission sont
# lus par l'API /preloadable ; l'en-tête est lu sur la PREMIÈRE réponse HTTPS du
# domaine (celle qu'évalue la liste), pas sur la page finale d'une redirection.
# Source : https://hstspreload.org/api/v2/status (gratuit, sans clé, vérifié
# le 15/10/2026). Le domaine interrogé est le domaine enregistrable.
# =============================================================================

import httpx

from ...i18n import msg
from .. import common
from ..errors import ModuleError
from ..http_utils import FETCH_ERRORS, describe_error, fetch
from ..impl import hsts_preload as logic
from ..registry import ModuleSpec, ScanContext, skip_for_ip_target
from ..rules import FindingInput, FindingRule, Outcome, ScoreRule
from ..score import as_dict

_HEADER_TIMEOUT = 10.0


async def _first_response(client: httpx.AsyncClient, host: str) -> dict:
    """Première réponse HTTPS de `host`, sans suivre de redirection : (en-tête HSTS, redirection)."""
    try:
        fetched = await fetch(
            client, f"https://{common.url_host(host)}", site=host, max_bytes=0, max_redirects=0
        )
    except FETCH_ERRORS as e:
        return {"reachable": False, "error": describe_error(e), "hsts": logic.parse_hsts(None)}
    headers = fetched.headers
    return {
        "reachable": True,
        "error": None,
        "url": fetched.url,
        "status_code": fetched.status_code,
        "hsts": logic.parse_hsts(headers.get("strict-transport-security")),
    }


async def _preload(context: ScanContext, domain: str, hsts_ready: bool) -> dict:
    """Statut dans la liste de précharge (et obstacles si le domaine n'y est pas)."""
    try:
        status = await logic.preload_status(context.http, domain)
    except ModuleError as e:
        return {"measured": False, "error": e.message, "status": None, "blockers": None}
    result = {**status, "blockers": None}
    if status["status"] == "unknown" and hsts_ready:
        try:
            blockers = await logic.preload_blockers(context.http, domain)
            result["blockers"] = {"errors": blockers["errors"], "warnings": blockers["warnings"]}
        except ModuleError:
            result["blockers"] = None
    return result


async def run(context: ScanContext) -> dict:
    domain = context.domain
    query = context.apex if not context.shared_platform else domain
    async with common._http_client(timeout=_HEADER_TIMEOUT, follow_redirects=False) as client:
        first = await _first_response(client, domain)
        apex_first = await _first_response(client, query) if query != domain else None
    apex_response = apex_first or first
    apex_hsts = apex_response["hsts"] if apex_response["reachable"] else None
    ready = bool(apex_hsts and apex_hsts["preload_eligible"])
    preload = await _preload(context, query, ready)
    if not first["reachable"] and not preload["measured"]:
        raise ModuleError(msg("http.unreachable", errors=[first["error"], preload["error"]]))
    status = preload.get("status")
    return {
        "measured": True,
        "error": None,
        "domain": domain,
        "preload_domain": query,
        "https": first["reachable"],
        "https_error": first["error"],
        "url": first.get("url"),
        "status_code": first.get("status_code"),
        "hsts": first["hsts"],
        "apex_hsts": apex_first["hsts"] if apex_first and apex_first["reachable"] else None,
        "preload": preload,
        "preloaded": status == "preloaded",
        "pending": status == "pending",
        "grade": "A" if status == "preloaded" else first["hsts"]["grade"],
    }


def _data(f: FindingInput) -> dict | None:
    data = as_dict(f.data)
    return data if data.get("https") is True else None


def _check_no_subdomains(f: FindingInput) -> bool:
    data = _data(f)
    if data is None or data.get("preloaded") is True:
        return False
    hsts = as_dict(data.get("hsts"))
    return bool(hsts.get("valid") and hsts.get("max_age") and not hsts.get("include_subdomains"))


def _check_preload_unready(f: FindingInput) -> bool:
    data = _data(f)
    if data is None or data.get("preloaded") is True:
        return False
    hsts = as_dict(data.get("hsts"))
    return bool(hsts.get("preload") and not hsts.get("preload_eligible"))


def _check_not_preloaded(f: FindingInput) -> bool:
    data = _data(f)
    if data is None or data.get("domain") != data.get("preload_domain"):
        return False
    status = as_dict(data.get("preload")).get("status")
    return status == "unknown" and bool(as_dict(data.get("hsts")).get("preload_eligible"))


_POINTS = {"A": 5, "B": 4, "C": 3, "D": 1, "F": 0}


def _score(data: dict) -> Outcome:
    result = as_dict(data.get("hsts_preload"))
    if result.get("https") is not True:
        return Outcome(0, msg("hsts_preload.score_no_https"), False, applicable=False)
    if result.get("preloaded") is True:
        return Outcome(5, msg("hsts_preload.score_preloaded"), True)
    hsts = as_dict(result.get("hsts"))
    grade = str(hsts.get("grade") or "F")
    return Outcome(_POINTS.get(grade, 0), msg("hsts_preload.score_grade", grade=grade), True)


SPEC = ModuleSpec(
    name="hsts_preload",
    family="web",
    category="passif",
    run=run,
    quick=False,
    order=32,
    skip_reason=skip_for_ip_target,
    optional=True,
    findings=(
        FindingRule(code="finding.hsts_preload.no_subdomains", severity="low", check=_check_no_subdomains),
        FindingRule(
            code="finding.hsts_preload.preload_unready", severity="low", check=_check_preload_unready
        ),
        FindingRule(code="finding.hsts_preload.not_preloaded", severity="low", check=_check_not_preloaded),
    ),
    score_rules=(ScoreRule(criterion="hsts_preload", weight=5, evaluate=_score, not_applicable_for_ip=True),),
)
