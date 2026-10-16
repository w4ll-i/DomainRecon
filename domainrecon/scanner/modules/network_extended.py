# =============================================================================
# DomainRecon - Module « network_extended » : ASN, préfixe, voisins de l'adresse IP
# =============================================================================
# Adaptateur de scanner/impl/network_extended.py (extended_network_scan) : ASN,
# titulaire, préfixe, pays et registre (RIPEstat, Team Cymru, ipinfo.io avec
# jeton facultatif), voisins reverse-IP (HackerTarget, repli Robtex, bruit
# .arpa écarté). Inclut le voisinage reverse IP. Sans
# objet si la cible n'a pas résolu. Hors du profil « rapide » : il interroge
# plusieurs services tiers.
# =============================================================================

from ..impl import network_extended as extended
from ..registry import ModuleSpec, ScanContext, skip_without_address
from .geo_data import IPINFO_KEY


async def run(context: ScanContext) -> dict:
    return await extended.extended_network_scan(
        context.ip_address,
        context.domain,
        token=context.secrets.get("ipinfo_token"),
        client=context.http,
    )


SPEC = ModuleSpec(
    name="network_extended",
    family="network",
    category="passif",
    run=run,
    keys=(IPINFO_KEY,),
    skip_reason=skip_without_address,
    order=160,
    column="network_extended",
)
