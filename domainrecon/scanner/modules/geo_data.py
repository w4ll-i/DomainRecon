# =============================================================================
# DomainRecon - Module « geo_data » : géolocalisation et réseau de l'adresse IP
# =============================================================================
# Adaptateur de scanner/impl/geo_data.py (get_geo_data) : ipinfo.io (jeton
# facultatif « ipinfo_token »), ASN et titulaire complétés par RIPEstat et Team
# Cymru, repli RIPEstat si ipinfo.io échoue. Sur l'adresse principale de la
# cible ; sans objet si la cible n'a pas résolu.
# =============================================================================

from ..impl import geo_data as geo
from ..keys import ApiKey, KeyTest, Probe
from ..registry import ModuleSpec, ScanContext, skip_without_address

# Clé facultative partagée avec network_extended (déclaration identique).
IPINFO_KEY = ApiKey(name="ipinfo_token", service="ipinfo", label="ipinfo.io", required=False)


def _ipinfo_probes(secrets) -> list[Probe]:
    return [
        Probe(
            "https://ipinfo.io/8.8.8.8/json",
            headers={"Authorization": f"Bearer {secrets['ipinfo_token']}", "Accept": "application/json"},
        )
    ]


async def run(context: ScanContext) -> dict:
    return await geo.get_geo_data(
        context.ip_address, token=context.secrets.get("ipinfo_token"), client=context.http
    )


SPEC = ModuleSpec(
    name="geo_data",
    family="network",
    category="passif",
    run=run,
    keys=(IPINFO_KEY,),
    key_tests={"ipinfo": KeyTest(label="ipinfo.io", fields=("ipinfo_token",), probes=_ipinfo_probes)},
    skip_reason=skip_without_address,
    quick=True,
    order=60,
    column="geo_data",
)
