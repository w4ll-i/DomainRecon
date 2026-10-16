# =============================================================================
# DomainRecon - Module « cookie_security » : sécurité des cookies
# =============================================================================
# Adaptateur de scanner/cookies.py (analyze_cookies).
# =============================================================================

from .. import cookies, findings, score
from ..registry import ModuleSpec, ScanContext


async def run(context: ScanContext) -> dict:
    return await cookies.analyze_cookies(context.domain)


SPEC = ModuleSpec(
    name="cookie_security",
    family="web",
    category="passif",
    run=run,
    quick=True,
    order=130,
    column="cookie_security",
    verdict=True,
    http_probe=True,
    findings=findings.COOKIE_FINDINGS,
    score_rules=(score.COOKIES_RULE,),
)
