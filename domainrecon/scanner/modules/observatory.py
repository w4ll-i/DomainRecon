# =============================================================================
# DomainRecon - Module « observatory » : MDN HTTP Observatory
# =============================================================================
# Note A+ à F du MDN HTTP Observatory (ex-Mozilla Observatory) : synthèse des
# contrôles de sécurité HTTP (CSP, HSTS, cookies, redirections, SRI…) réalisée
# par les serveurs de Mozilla. Passif du point de vue de l'utilisateur (c'est le
# service qui interroge la cible), sans clé API.
# Migration : l'API v1 (http-observatory.security.mozilla.org) est arrêtée ; le
# module utilise l'API v2 (POST /api/v2/scan, vérifiée le 15/10/2026), qui
# répond directement avec la note, sans sondage par répétition.
# Documentation : https://developer.mozilla.org/en-US/observatory/docs/faq
# Limites : un nouveau scan du même hôte au plus toutes les 60 s ; réponse
# concise (pas de liste détaillée des tests, un lien vers le rapport MDN).
# Optionnel : un service tiers indisponible ne dégrade pas le scan.
# =============================================================================

from ...i18n import msg
from ..errors import ModuleError
from ..impl import observatory as logic
from ..registry import ModuleSpec, ScanContext, skip_for_ip_target
from ..rules import FindingInput, FindingRule, Outcome, ScoreRule, hit
from ..score import as_dict


async def run(context: ScanContext) -> dict:
    if context.http is None:
        raise ModuleError(msg("orchestrator.module_failed"))
    return await logic.scan_host(context.http, context.domain)


def _grade(data: object) -> str:
    return str(as_dict(data).get("grade") or "")


def _check_low_grade(f: FindingInput) -> object:
    grade = _grade(f.data)
    if grade[:1] not in ("D", "F"):
        return None
    return hit(severity="medium" if grade[:1] == "F" else "low", grade=grade)


_POINTS = {"A": 5, "B": 4, "C": 3, "D": 1, "F": 0}


def _score(data: dict) -> Outcome:
    grade = _grade(data.get("observatory"))
    if not grade:
        return Outcome(0, msg("observatory.score_unknown"), False)
    return Outcome(_POINTS.get(grade[:1], 0), msg("observatory.score_grade", grade=grade), True)


SPEC = ModuleSpec(
    name="observatory",
    family="web",
    category="passif",
    run=run,
    order=160,
    timeout=60,
    skip_reason=skip_for_ip_target,
    optional=True,
    findings=(FindingRule(code="finding.observatory.low_grade", severity="medium", check=_check_low_grade),),
    score_rules=(ScoreRule(criterion="observatory", weight=5, evaluate=_score, not_applicable_for_ip=True),),
)
