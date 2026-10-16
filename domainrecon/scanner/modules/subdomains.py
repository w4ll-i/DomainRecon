# =============================================================================
# DomainRecon - Module « subdomains » : énumération des sous-domaines
# =============================================================================
# Adaptateur de scanner/dns.py (find_subdomains), sur le domaine du site (voir
# ScanContext.site). Sans objet pour une adresse IP. Hors du profil « rapide » :
# l'énumération (journaux CT) est le module le plus lent.
# =============================================================================

from .. import dns
from ..registry import ModuleSpec, ScanContext, skip_for_ip_target


async def run(context: ScanContext) -> list:
    return await dns.find_subdomains(context.site)


def _status_extras(value: object) -> dict:
    """Ajouts à module_status : nombre de noms trouvés avant la coupe (SUBDOMAIN_MAX_RESULTS),
    source (crt.sh, ou Cert Spotter en secours, dont la liste est partielle)."""
    extras: dict = {}
    total_found = getattr(value, "total_found", None)
    if isinstance(total_found, int) and not isinstance(total_found, bool):
        extras["total_found"] = total_found
    source = getattr(value, "source", None)
    if isinstance(source, str):
        extras["source"] = source
        extras["partial"] = bool(getattr(value, "partial", False))
    return extras


def _no_list(error: object) -> list:
    """Sans résultat : liste vide (le module renvoie une liste)."""
    return []


SPEC = ModuleSpec(
    name="subdomains",
    family="dns",
    category="passif",
    run=run,
    skip_reason=skip_for_ip_target,
    order=20,
    column="subdomains",
    verdict=True,
    status_extras=_status_extras,
    placeholder=_no_list,
)
