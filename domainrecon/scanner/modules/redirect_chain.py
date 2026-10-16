# =============================================================================
# DomainRecon - Module « redirect_chain » : chaîne de redirections
# =============================================================================
# Adaptateur de scanner/redirects.py (trace_redirects).
# =============================================================================

from .. import findings, redirects, score
from ..registry import ModuleSpec, ScanContext


async def run(context: ScanContext) -> dict:
    return await redirects.trace_redirects(context.domain)


SPEC = ModuleSpec(
    name="redirect_chain",
    family="web",
    category="passif",
    run=run,
    quick=True,
    order=110,
    column="redirect_chain",
    verdict=True,
    http_probe=True,
    findings=findings.REDIRECT_FINDINGS,
    score_rules=(score.HTTPS_REDIRECT_RULE,),
)
