# =============================================================================
# DomainRecon - Module « cors » : configuration CORS
# =============================================================================
# Adaptateur de scanner/cors.py (check_cors).
# =============================================================================

from .. import cors, findings, score
from ..registry import ModuleSpec, ScanContext


async def run(context: ScanContext) -> dict:
    return await cors.check_cors(context.domain)


SPEC = ModuleSpec(
    name="cors",
    family="web",
    category="passif",
    run=run,
    quick=True,
    order=140,
    column="cors",
    verdict=True,
    http_probe=True,
    findings=findings.CORS_FINDINGS,
    score_rules=(score.CORS_RULE,),
)
