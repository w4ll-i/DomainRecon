# =============================================================================
# DomainRecon - Module « subdomain_takeover » : sous-domaines détournables
# =============================================================================
# Adaptateur de scanner/takeover.py (check_subdomain_takeover). Lit le résultat
# du module « subdomains » (depends_on) dans ScanContext.results, où un module
# en échec ne figure pas :
#   - énumération en échec ou hors délai : « non vérifié » (ModuleError) ;
#   - aucun sous-domaine trouvé : sans objet ;
#   - adresse IP : sans objet, comme l'énumération.
# Même vague que l'énumération : l'orchestrateur le lance dès qu'elle est finie.
# Constats et critère de score : findings.py et score.py (TAKEOVER_*).
# =============================================================================

from collections.abc import Mapping

from ...i18n import msg
from .. import findings, score, takeover
from ..errors import ModuleError
from ..families import takeover_never_checked
from ..registry import ModuleSpec, ScanContext

# Délai propre du module, en secondes (orchestrator.TAKEOVER_TIMEOUT) : plus court
# que les autres, il part d'une énumération déjà faite.
TAKEOVER_TIMEOUT = 30


async def run(context: ScanContext) -> list:
    subdomains = context.results.get("subdomains")
    if subdomains is None:
        raise ModuleError(msg("orchestrator.takeover_not_checked"))
    return await takeover.check_subdomain_takeover(subdomains)


def skip_reason(context: ScanContext) -> object | None:
    if context.is_ip_target:
        return msg("orchestrator.skip_ip_target")
    subdomains = context.results.get("subdomains")
    if subdomains is not None and not subdomains:
        return msg("orchestrator.skip_no_subdomains")
    return None


def _score_extras(values: Mapping[str, object], measured: bool) -> dict:
    """Sous-domaines réellement testés : ceux de takeover_candidates() (noms valides,
    sans doublon, en nombre borné) ; 0 si le takeover n'a pas été mesuré. Le barème
    les cite avec son verdict."""
    if not measured:
        return {"subdomains_checked": 0}
    return {"subdomains_checked": len(takeover.takeover_candidates(values.get("subdomains")))}


def _no_list(error: object) -> list:
    """Sans résultat : liste vide (le module renvoie une liste)."""
    return []


def _legacy_measured(scan: dict, value: object) -> bool:
    """Scan antérieur : liste vide d'un takeover jamais vérifié (selon le barème) = non mesuré."""
    if not value and takeover_never_checked(scan):
        return False
    return isinstance(value, list)


SPEC = ModuleSpec(
    name="subdomain_takeover",
    family="dns",
    category="actif",  # sonde HTTP des sous-domaines candidats : autorisation requise
    run=run,
    wave=1,
    depends_on=("subdomains",),
    timeout=TAKEOVER_TIMEOUT,
    skip_reason=skip_reason,
    order=180,
    column="subdomain_takeover",
    verdict=True,
    findings=findings.TAKEOVER_FINDINGS,
    score_rules=(score.TAKEOVER_RULE,),
    score_extras=_score_extras,
    placeholder=_no_list,
    legacy_measured=_legacy_measured,
)
