# =============================================================================
# DomainRecon - Module « csp_grade » : note de la Content-Security-Policy
# =============================================================================
# Note A à F de la CSP réellement appliquée (en-tête Content-Security-Policy et
# balises <meta http-equiv>), lue sur la page d'accueil partagée du scan : aucune
# requête de plus. Notation corrigée (voir impl/csp_grade.py) : « script-src * »
# ou 'unsafe-inline' sans nonce plafonnent la note à D, nonces, hashes et
# 'strict-dynamic' sont compris, base-uri / object-src / frame-ancestors /
# form-action sont contrôlés, et la politique « report-only » n'est pas notée.
# La présence/absence de la CSP reste jugée par
# « security_headers » : une CSP absente n'entre pas deux fois dans le score.
# Référence : https://www.w3.org/TR/CSP3/ et OWASP CSP Cheat Sheet.
# =============================================================================

from ...i18n import msg
from ..errors import ModuleError
from ..impl import csp_grade as logic
from ..registry import ModuleSpec, ScanContext
from ..rules import FindingInput, FindingRule, Outcome, ScoreRule, hit
from ..score import as_dict, as_list

# Plafond de caractères conservés de l'en-tête dans le résultat.
_MAX_HEADER = 2000


async def run(context: ScanContext) -> dict:
    home = await context.homepage()
    if not home.reachable:
        raise ModuleError(home.error or msg("orchestrator.module_failed"))
    header = home.headers.get("content-security-policy", "").strip()
    report_only = home.headers.get("content-security-policy-report-only", "").strip()
    metas = logic.meta_policies(home.text) if home.text else []

    policies: list[tuple[dict, bool]] = [(p, False) for p in logic.parse_policies(header)]
    policies += [(p, True) for meta in metas for p in logic.parse_policies(meta)]
    xfo = home.headers.get("x-frame-options", "").strip().lower()
    framed_protected = xfo in ("deny", "sameorigin")

    result = {
        "measured": True,
        "error": None,
        "url": home.url,
        "present": bool(policies),
        "source": "+".join(s for s, ok in (("header", header), ("meta", metas)) if ok) or None,
        "report_only": bool(report_only),
        "header": header[:_MAX_HEADER] or None,
        "grade": None,
        "score": None,
        "max_score": 100,
        "policies": 0,
        "issues": [],
    }
    if policies:
        graded = logic.grade_policies(policies, framed_protected=framed_protected)
        result.update(
            grade=graded["grade"],
            score=graded["score"],
            policies=graded["policies"],
            issues=[
                {key: issue[key] for key in ("code", "points", "severity", "label")}
                for issue in graded["issues"]
            ],
            critical=graded["critical"],
        )
    return result


def _check_weak(f: FindingInput) -> object:
    data = as_dict(f.data)
    if data.get("present") is not True or data.get("grade") not in ("D", "F"):
        return None
    issues = [as_dict(i) for i in as_list(data.get("issues"))]
    shown = [i for i in issues if i.get("severity") == "high"] or issues
    labels = [i["label"] for i in shown[:4] if i.get("label")]
    severity = "high" if data.get("grade") == "F" or data.get("critical") is True else "medium"
    return hit(severity=severity, grade=data.get("grade"), issues=msg("common.join", items=labels))


def _check_report_only(f: FindingInput) -> bool:
    data = as_dict(f.data)
    return data.get("present") is False and data.get("report_only") is True


_POINTS = {"A": 5, "B": 4, "C": 3, "D": 1, "F": 0}


def _score(data: dict) -> Outcome:
    result = as_dict(data.get("csp_grade"))
    if result.get("present") is not True:
        if result.get("report_only") is True:
            return Outcome(0, msg("csp_grade.score_report_only"), True)
        # Pas de CSP : déjà sanctionné par le critère des en-têtes de sécurité.
        return Outcome(0, msg("csp_grade.score_absent"), False, applicable=False)
    grade = str(result.get("grade") or "F")
    return Outcome(
        _POINTS.get(grade, 0), msg("csp_grade.score_grade", grade=grade, score=result.get("score") or 0), True
    )


SPEC = ModuleSpec(
    name="csp_grade",
    family="web",
    category="passif",
    run=run,
    quick=True,
    order=36,
    findings=(
        FindingRule(code="finding.csp_grade.weak", severity="medium", check=_check_weak),
        FindingRule(code="finding.csp_grade.report_only", severity="low", check=_check_report_only),
    ),
    score_rules=(ScoreRule(criterion="csp_grade", weight=5, evaluate=_score),),
)
