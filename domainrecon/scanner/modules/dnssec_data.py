# =============================================================================
# DomainRecon - Module « dnssec_data » : DNSSEC du domaine
# =============================================================================
# Vérifie la chaîne de confiance DNSSEC du domaine enregistrable : DNSKEY, DS chez
# le parent et correspondance réelle entre les deux, signatures (échéance dépassée), validation
# par un résolveur public qui valide (bit AD), détection d'une chaîne cassée (domaine
# inaccessible pour les résolveurs qui valident), déni d'existence NSEC / NSEC3.
# Note de A à F. Logique : impl/dnssec.py (lecture réelle
# des RRSIG et du bit AD). Passif : requêtes DNS publiques. Sans objet pour une adresse IP.
# =============================================================================

import asyncio

from ...i18n import msg
from ..errors import ModuleError
from ..impl import dnssec as engine
from ..registry import ModuleSpec, ScanContext, skip_for_ip_target
from ..rules import FindingInput, FindingRule, Outcome, ScoreRule
from ..score import as_dict, as_int, as_list

# Points du critère selon la note (poids 5).
_POINTS = {"A": 5, "B": 4, "C": 3, "D": 1, "F": 0}


async def run(context: ScanContext) -> dict:
    try:
        result = await asyncio.to_thread(engine.analyze, context.apex)
    except engine.Unavailable:
        raise ModuleError(msg("dnssec_data.unavailable")) from None
    return {"measured": True, "error": None, **result}


def _status(f: FindingInput) -> str:
    return str(as_dict(f.data).get("status") or "")


def _check_unsigned(f: FindingInput) -> bool:
    return _status(f) == "unsigned"


def _check_broken(f: FindingInput) -> bool:
    return _status(f) == "broken"


def _check_no_ds(f: FindingInput) -> bool:
    return _status(f) == "incomplete"


def _check_weak_algorithm(f: FindingInput) -> dict | None:
    names = [
        str(as_dict(a).get("name"))
        for a in as_list(as_dict(f.data).get("algorithms"))
        if as_dict(a).get("weak")
    ]
    return {"algorithms": names} if names else None


def _score(data: dict) -> Outcome:
    result = as_dict(data.get("dnssec_data"))
    grade = str(result.get("grade") or "F")
    status = str(result.get("status") or "unsigned")
    cap = msg("dnssec_data.cap_broken") if status == "broken" else None
    if status == "unsigned":
        return Outcome(0, msg("dnssec_data.score_unsigned"), True)
    detail = msg("dnssec_data.score_grade", grade=grade, count=as_int(result.get("key_count")))
    return Outcome(_POINTS.get(grade, 0), detail, True, cap_reason=cap)


SPEC = ModuleSpec(
    name="dnssec_data",
    family="dns",
    category="passif",
    run=run,
    skip_reason=skip_for_ip_target,
    order=25,
    findings=(
        FindingRule(code="finding.dnssec_data.broken", severity="critical", check=_check_broken),
        FindingRule(code="finding.dnssec_data.no_ds", severity="medium", check=_check_no_ds),
        FindingRule(code="finding.dnssec_data.unsigned", severity="medium", check=_check_unsigned),
        FindingRule(
            code="finding.dnssec_data.weak_algorithm", severity="medium", check=_check_weak_algorithm
        ),
    ),
    score_rules=(ScoreRule(criterion="dnssec_data", weight=5, evaluate=_score, not_applicable_for_ip=True),),
)
