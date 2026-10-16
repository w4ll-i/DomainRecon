# =============================================================================
# DomainRecon - Module « open_ports » : ports ouverts (51 ports, niveau de risque)
# =============================================================================
# Adaptateur de scanner/impl/open_ports.py (scan_ports) : 51 ports,
# avec un niveau de risque par service. Sur l'adresse principale de la cible ;
# sans objet si la cible n'a pas résolu.
# Catégorie « actif » : le module ouvre des connexions TCP vers la cible, il
# exige donc la case d'autorisation et n'est pas dans le profil rapide.
# =============================================================================

from ..impl import open_ports as ports
from ..registry import ModuleSpec, ScanContext, skip_without_address


async def run(context: ScanContext) -> list:
    return await ports.scan_ports(context.ip_address)


def _no_list(error: object) -> list:
    """Sans résultat : liste vide (le module renvoie une liste)."""
    return []


SPEC = ModuleSpec(
    name="open_ports",
    family="network",
    category="actif",  # scan de ports TCP : sondes envoyées à la cible, autorisation requise
    run=run,
    skip_reason=skip_without_address,
    order=80,
    column="open_ports",
    verdict=True,
    findings=ports.PORT_FINDINGS,
    score_rules=(ports.PORT_PENALTY_RULE,),
    placeholder=_no_list,
)
