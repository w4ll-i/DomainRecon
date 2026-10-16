# =============================================================================
# DomainRecon - Module « security_headers » : en-têtes de sécurité HTTP
# =============================================================================
# Adaptateur de scanner/headers.py (check_security_headers). Le verdict TLS
# (headers.apply_tls_verdict) est appliqué en fin de scan (finalize), une fois
# le module TLS connu. Ses constats (et la rétrogradation HTTPS -> HTTP) et son
# critère de score sont définis dans findings.py et score.py.
# =============================================================================

from collections.abc import Mapping

from .. import findings, headers, score
from ..registry import ModuleSpec, ScanContext


async def run(context: ScanContext) -> dict:
    return await headers.check_security_headers(context.domain)


def _finalize(value: object, values: Mapping[str, object], context: ScanContext) -> object:
    """Les en-têtes sont lus sans vérifier le certificat : un HSTS servi avec un
    certificat invalide (mesuré par le module TLS) est sans effet."""
    return headers.apply_tls_verdict(value, values.get("tls_certificate"), context.domain)


SPEC = ModuleSpec(
    name="security_headers",
    family="web",
    category="passif",
    run=run,
    quick=True,
    order=30,
    column="security_headers",
    verdict=True,
    http_probe=True,
    findings=findings.HEADERS_FINDINGS,
    score_rules=(score.HEADERS_RULE,),
    finalize=_finalize,
    placeholder=headers.empty_headers_result,
)
