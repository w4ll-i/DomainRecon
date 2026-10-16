# =============================================================================
# DomainRecon - Module « waf » : détection de WAF / CDN
# =============================================================================
# Adaptateur de scanner/waf.py (detect_waf).
# =============================================================================

from .. import score, waf
from ..registry import ModuleSpec, ScanContext


async def run(context: ScanContext) -> dict:
    return await waf.detect_waf(context.domain)


SPEC = ModuleSpec(
    name="waf",
    family="web",
    category="passif",
    run=run,
    quick=True,
    order=100,
    column="waf",
    http_probe=True,
    score_rules=(score.WAF_RULE,),
)
