# =============================================================================
# DomainRecon - Module « censys » : hôte indexé par Censys (Platform API v3)
# =============================================================================
# L'API Legacy Search étant éteinte depuis le 30 septembre 2026, le module utilise
# la Censys Platform
# (https://docs.censys.com/reference/get-started) : services, logiciels,
# étiquettes, certificats et ASN de l'adresse IP de la cible.
#   - censys_secret : jeton d'accès personnel (PAT), requis ;
#   - censys_id     : identifiant d'organisation, facultatif (en-tête
#     X-Organization-ID, utile aux comptes d'organisation).
# Une consultation d'hôte coûte 1 crédit (100 par mois offerts) : une seule par scan.
# Limites : Censys décrit l'adresse telle que ses sondes l'ont vue ; derrière un
# CDN, c'est le CDN qui est décrit.
# =============================================================================

from ...i18n import msg
from ..errors import ModuleSkipped
from ..impl import censys as censys_api
from ..keys import ApiKey
from ..registry import ModuleSpec, ScanContext, skip_without_address
from ..targets import is_public_address


async def run(context: ScanContext) -> dict:
    ip = context.ip_address
    if ip is None or not is_public_address(ip):
        raise ModuleSkipped(msg("censys.not_public"))
    token = context.secrets.get("censys_secret")
    if not token:
        raise ModuleSkipped(msg("censys.no_key"))
    data = await censys_api.host(context.http, ip, token, context.secrets.get("censys_id"))
    result = {"measured": True, "error": None, "ip": ip, "found": data is not None}
    if data is not None:
        result.update(data)
    return result


SPEC = ModuleSpec(
    name="censys",
    family="network",
    category="cle_api",
    run=run,
    keys=(
        ApiKey(name="censys_secret", service="censys", label="Censys"),
        ApiKey(name="censys_id", service="censys", label="Censys", free_text=True, required=False),
    ),
    skip_reason=skip_without_address,
    wave=1,
    timeout=40,
    optional=True,
    order=250,
)
