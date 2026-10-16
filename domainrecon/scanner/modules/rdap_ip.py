# =============================================================================
# DomainRecon - Module « rdap_ip » : registre RDAP de l'adresse IP
# =============================================================================
# Interroge le registre régional compétent (ARIN, RIPE NCC, APNIC, LACNIC,
# AFRINIC) par RDAP, gratuit et sans clé : bloc d'adresses, nom du réseau,
# pays, dates d'enregistrement, organisation titulaire et contact « abuse ».
# Voir impl/rdap_ip.py (amorçage IANA, redirections, minimisation des données
# personnelles). Source : https://www.rfc-editor.org/rfc/rfc9082.
# =============================================================================

from ...i18n import msg
from ..errors import ModuleSkipped
from ..impl import rdap_ip
from ..registry import ModuleSpec, ScanContext, skip_without_address
from ..targets import is_public_address


async def run(context: ScanContext) -> dict:
    ip = context.ip_address
    if ip is None or not is_public_address(ip):
        raise ModuleSkipped(msg("rdap_ip.not_public"))
    result = await rdap_ip.lookup(context.http, ip)
    return {"measured": True, "error": None, "ip": ip, **result}


SPEC = ModuleSpec(
    name="rdap_ip",
    family="network",
    category="passif",
    run=run,
    skip_reason=skip_without_address,
    wave=1,
    timeout=30,
    optional=True,
    order=220,
)
