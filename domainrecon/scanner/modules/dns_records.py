# =============================================================================
# DomainRecon - Module « dns_records » : enregistrements DNS
# =============================================================================
# Adaptateur de scanner/dns.py (scan_dns_records). Sans objet pour une adresse IP.
# =============================================================================

from .. import dns
from ..registry import ModuleSpec, ScanContext, skip_for_ip_target


async def run(context: ScanContext) -> dict:
    return await dns.scan_dns_records(context.domain)


def _nxdomain(value: object) -> bool:
    """Le DNS déclare le domaine inexistant (résumé « domaine inexistant » du scan)."""
    return isinstance(value, dict) and bool(value.get("nxdomain"))


SPEC = ModuleSpec(
    name="dns_records",
    family="dns",
    category="passif",
    run=run,
    skip_reason=skip_for_ip_target,
    quick=True,
    order=10,
    column="dns_records",
    nxdomain=_nxdomain,
)
