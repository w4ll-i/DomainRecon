# =============================================================================
# DomainRecon - Module « web_files » : robots.txt, sitemap, security.txt
# =============================================================================
# Adaptateur de scanner/web_files.py (check_web_files).
# =============================================================================

from .. import findings, web_files
from ..registry import ModuleSpec, ScanContext


async def run(context: ScanContext) -> dict:
    return await web_files.check_web_files(context.domain)


SPEC = ModuleSpec(
    name="web_files",
    family="web",
    category="passif",
    run=run,
    quick=True,
    order=120,
    column="web_files",
    verdict=True,
    findings=findings.WEB_FILES_FINDINGS,
)
