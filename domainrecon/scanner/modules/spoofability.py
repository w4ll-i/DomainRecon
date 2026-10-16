# =============================================================================
# DomainRecon - Module « spoofability » : score d'usurpabilité du domaine
# =============================================================================
# Combine SPF et DMARC (lus dans le résultat d'email_security, sans nouvelle requête)
# en un score de 0 à 100 (100 = n'importe qui peut envoyer un message au nom du
# domaine), un niveau de risque, un verdict (usurpable, partiel, protégé) et des
# scénarios d'attaque en clair. DKIM et catch-all ne comptent pas comme
# protections : ils n'empêchent pas l'usurpation.
# Pas de critère de score propre : il reprendrait SPF/DMARC déjà notés par email_security.
# Logique : scanner/impl/spoofability.py.
# =============================================================================

from ...i18n import msg
from ..errors import ModuleError
from ..impl import spoofability as impl
from ..registry import ModuleSpec, ScanContext, skip_for_ip_target
from ..rules import FindingInput, FindingRule
from ..score import as_dict, as_int


async def run(context: ScanContext) -> dict:
    email = context.results.get("email_security")
    if not isinstance(email, dict) or email.get("measured") is False:
        raise ModuleError(msg("spoofability.no_email_data"))
    result = impl.compute(context.domain, email)
    if not result["measured"]:
        raise ModuleError(result["error"])
    return result


def skip_reason(context: ScanContext) -> object | None:
    if context.shared_platform:
        return msg("orchestrator.skip_shared_platform")
    return skip_for_ip_target(context)


def _verdict_params(f: FindingInput, verdict: str) -> dict | None:
    data = as_dict(f.data)
    if data.get("verdict") != verdict:
        return None
    return {"score": as_int(data.get("score")), "risk": data.get("risk")}


def _check_spoofable(f: FindingInput) -> dict | None:
    return _verdict_params(f, "spoofable")


def _check_partial(f: FindingInput) -> dict | None:
    return _verdict_params(f, "partial")


def _check_subdomains(f: FindingInput) -> bool:
    data = as_dict(f.data)
    return data.get("subdomain_exposed") is True and data.get("verdict") != "spoofable"


SPEC = ModuleSpec(
    name="spoofability",
    family="email",
    category="passif",
    run=run,
    skip_reason=skip_reason,
    # Vague 2 : lit le résultat d'email_security.
    wave=2,
    depends_on=("email_security",),
    # Calcul pur : aussi rapide que sa dépendance, donc du profil rapide.
    quick=True,
    timeout=10,
    optional=True,
    order=94,
    findings=(
        FindingRule(code="finding.spoofability.spoofable", severity="high", check=_check_spoofable),
        FindingRule(code="finding.spoofability.partial", severity="medium", check=_check_partial),
        FindingRule(code="finding.spoofability.subdomains", severity="medium", check=_check_subdomains),
    ),
)
