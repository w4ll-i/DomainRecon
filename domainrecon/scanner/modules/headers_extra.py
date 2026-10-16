# =============================================================================
# DomainRecon - Module « headers_extra » : isolation d'origine croisée et en-têtes obsolètes
# =============================================================================
# Complète « security_headers » (6 en-têtes notés) avec :
#   - COOP, COEP, CORP (isolation d'origine croisée) évalués par valeur ;
#   - les en-têtes obsolètes à retirer : HPKP (Public-Key-Pins), Expect-CT,
#     X-XSS-Protection actif, Feature-Policy, CSP préfixées.
# Source : la page d'accueil partagée du scan (aucune requête de plus).
# Références : MDN (Cross-Origin-Opener-Policy, Cross-Origin-Embedder-Policy,
# Cross-Origin-Resource-Policy), OWASP Secure Headers Project.
# =============================================================================

from ...i18n import msg
from ..errors import ModuleError
from ..impl import headers_extra as logic
from ..registry import ModuleSpec, ScanContext
from ..rules import FindingInput, FindingRule, Outcome, ScoreRule, hit
from ..score import as_dict, as_list

# Points du critère (sur 5) : COOP 2, COEP 1, CORP 1, aucun en-tête obsolète actif 1.
_POINTS_COOP = {"ok": 2, "partial": 1}
_POINTS_OTHER = {"ok": 1, "partial": 1}


async def run(context: ScanContext) -> dict:
    home = await context.homepage()
    if not home.reachable:
        raise ModuleError(home.error or msg("orchestrator.module_failed"))
    evaluation = logic.evaluate(home.headers)
    return {
        "measured": True,
        "error": None,
        "url": home.url,
        "https": home.https,
        "status_code": home.status_code,
        **evaluation,
    }


def _status(data: object, key: str) -> str:
    return str(as_dict(as_dict(as_dict(data).get("checks")).get(key)).get("status") or "missing")


def _check_coop(f: FindingInput) -> bool:
    data = as_dict(f.data)
    return data.get("https") is True and _status(data, "coop") in ("missing", "weak", "invalid")


def _check_obsolete(f: FindingInput) -> object:
    items = [as_dict(item) for item in as_list(as_dict(f.data).get("obsolete"))]
    if not items:
        return None
    headers = ", ".join(str(item.get("header")) for item in items)
    severity = "medium" if any(item.get("severity") == "medium" for item in items) else "low"
    return hit(severity=severity, headers=headers)


def _score(data: dict) -> Outcome:
    result = as_dict(data.get("headers_extra"))
    points = _POINTS_COOP.get(_status(result, "coop"), 0)
    for key in ("coep", "corp"):
        points += _POINTS_OTHER.get(_status(result, key), 0)
    if not as_list(result.get("obsolete")):
        points += 1
    present = sum(1 for key in ("coop", "coep", "corp") if _status(result, key) != "missing")
    return Outcome(min(points, 5), msg("headers_extra.score_detail", present=present, total=3), True)


SPEC = ModuleSpec(
    name="headers_extra",
    family="web",
    category="passif",
    run=run,
    quick=True,
    order=35,
    findings=(
        FindingRule(code="finding.headers_extra.coop_missing", severity="low", check=_check_coop),
        FindingRule(code="finding.headers_extra.obsolete", severity="low", check=_check_obsolete),
    ),
    score_rules=(ScoreRule(criterion="headers_extra", weight=5, evaluate=_score),),
)
