# =============================================================================
# DomainRecon - Module « reverse_dns » : DNS inverse de l'adresse IP
# =============================================================================
# Adaptateur de scanner/dns.py (reverse_dns), sur l'adresse principale de la
# cible. Sans objet si la cible n'a pas résolu.
# =============================================================================

from .. import dns
from ..registry import ModuleSpec, ScanContext, skip_without_address


async def run(context: ScanContext) -> dict:
    return await dns.reverse_dns(context.ip_address)


SPEC = ModuleSpec(
    name="reverse_dns",
    family="dns",
    category="passif",
    run=run,
    skip_reason=skip_without_address,
    quick=True,
    order=150,
    column="reverse_dns",
)
