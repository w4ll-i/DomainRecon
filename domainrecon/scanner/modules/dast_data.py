# =============================================================================
# DomainRecon - Module « dast_data » : divulgations légères (versions, débogage, 404 bavarde)
# =============================================================================
# Contrôles DAST légers, sans injection :
#   - en-têtes de version (Server, X-Powered-By, X-AspNet-Version…) lus sur la page
#     d'accueil partagée du scan ;
#   - en-têtes de débogage (X-Debug-Token-Link…) ;
#   - UNE requête vers une URL inexistante : une page d'erreur qui montre une trace
#     d'appels, un chemin de fichier ou la page de débogage d'un framework.
# Réutilise la page d'accueil et la collecte d'en-têtes déjà faites par les autres
# modules (pas de second GET), et durcit les empreintes de page d'erreur (voir impl/dast_data.py). Catégorie « actif » :
# requête vers une URL inexistante et recherche de fuites d'information.
# =============================================================================

import secrets as _secrets

from ...i18n import msg
from .. import common
from ..errors import ModuleError
from ..http_utils import FETCH_ERRORS, describe_error, fetch
from ..impl import dast_data as logic
from ..registry import ModuleSpec, ScanContext
from ..rules import FindingInput, FindingRule, Outcome, ScoreRule, hit
from ..score import as_dict, as_list

_NOT_FOUND_TIMEOUT = 10.0
_NOT_FOUND_MAX_BYTES = 16 * 1024
_SEVERITY_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


async def run(context: ScanContext) -> dict:
    home = await context.homepage()
    if not home.reachable:
        raise ModuleError(home.error or msg("orchestrator.module_failed"))
    headers = logic.analyze_headers(home.headers)
    findings = list(headers["findings"])

    not_found: dict = {"tested": False, "status_code": None, "catch_all": False, "analyzed": False}
    origin = f"{'https' if home.https else 'http'}://{common.url_host(context.domain)}"
    path = f"/dr404-{_secrets.token_hex(6)}"
    try:
        async with common._http_client(timeout=_NOT_FOUND_TIMEOUT) as client:
            fetched = await fetch(client, origin + path, site=context.domain, max_bytes=_NOT_FOUND_MAX_BYTES)
    except FETCH_ERRORS as e:
        not_found["error"] = describe_error(e)
    else:
        analysis = logic.analyze_not_found(fetched.status_code, fetched.text, home.text)
        not_found.update(
            tested=True,
            status_code=fetched.status_code,
            catch_all=analysis["catch_all"],
            analyzed=analysis["analyzed"],
        )
        findings.extend(analysis["findings"])

    findings.sort(key=lambda item: _SEVERITY_RANK.get(item["severity"], 9))
    return {
        "measured": True,
        "error": None,
        "url": home.url,
        "banners": headers["banners"],
        "findings": findings,
        "finding_count": len(findings),
        "severity_summary": logic.summarize(findings),
        "not_found": not_found,
    }


def _of_type(data: object, kind: str) -> list[dict]:
    items = [as_dict(item) for item in as_list(as_dict(data).get("findings"))]
    return [item for item in items if item.get("type") == kind]


def _worst(items: list[dict]) -> str:
    return min((str(i.get("severity")) for i in items), key=lambda s: _SEVERITY_RANK.get(s, 9), default="low")


def _check_versions(f: FindingInput) -> object:
    items = _of_type(f.data, "version_disclosure")
    if not items:
        return None
    return {"headers": "; ".join(f"{i.get('header')}: {i.get('value')}" for i in items[:5])}


def _check_debug(f: FindingInput) -> object:
    items = _of_type(f.data, "debug_header")
    if not items:
        return None
    return hit(severity=_worst(items), headers=", ".join(str(i.get("header")) for i in items[:5]))


def _check_verbose_404(f: FindingInput) -> object:
    items = _of_type(f.data, "verbose_404")
    if not items:
        return None
    severity = _worst(items)
    return hit(
        severity=severity if severity in ("high", "medium", "low") else "low",
        frameworks=", ".join(str(i.get("framework")) for i in items[:5]),
    )


def _score(data: dict) -> Outcome:
    result = as_dict(data.get("dast_data"))
    items = [as_dict(i) for i in as_list(result.get("findings"))]
    worst = _worst(items) if items else "info"
    points = {"critical": 0, "high": 0, "medium": 1, "low": 2}.get(worst, 3)
    return Outcome(points, msg("dast_data.score_detail", count=len(items)), True)


SPEC = ModuleSpec(
    name="dast_data",
    family="web",
    category="actif",
    run=run,
    order=170,
    findings=(
        FindingRule(code="finding.dast_data.version_disclosure", severity="low", check=_check_versions),
        FindingRule(code="finding.dast_data.debug_header", severity="medium", check=_check_debug),
        FindingRule(code="finding.dast_data.verbose_404", severity="medium", check=_check_verbose_404),
    ),
    score_rules=(ScoreRule(criterion="dast_data", weight=3, evaluate=_score),),
)
