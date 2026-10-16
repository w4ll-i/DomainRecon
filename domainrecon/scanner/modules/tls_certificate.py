# =============================================================================
# DomainRecon - Module « tls_certificate » : certificat et protocole TLS
# =============================================================================
# Adaptateur de scanner/tls.py (check_tls_certificate).
# =============================================================================

from .. import findings, score, tls
from ..registry import ModuleSpec, ScanContext


async def run(context: ScanContext) -> dict:
    return await tls.check_tls_certificate(context.domain)


def _legacy_measured(scan: dict, value: object) -> bool:
    """Scan antérieur à module_status : erreur « certificate verify failed » = certificat refusé, donc mesuré."""
    return isinstance(value, dict) and bool(value) and score.tls_measured(value)


SPEC = ModuleSpec(
    name="tls_certificate",
    family="tls",
    category="passif",
    run=run,
    quick=True,
    order=40,
    column="tls_certificate",
    verdict=True,
    findings=findings.TLS_FINDINGS,
    score_rules=(score.TLS_RULE,),
    legacy_measured=_legacy_measured,
)
