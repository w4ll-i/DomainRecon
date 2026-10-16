# =============================================================================
# DomainRecon - Module « technologies » : détection des technologies du site
# =============================================================================
# Adaptateur de scanner/technologies.py (detect_technologies).
# =============================================================================

from .. import technologies
from ..registry import ModuleSpec, ScanContext


async def run(context: ScanContext) -> list:
    return await technologies.detect_technologies(context.domain)


def _no_list(error: object) -> list:
    """Sans résultat : liste vide (le module renvoie une liste)."""
    return []


SPEC = ModuleSpec(
    name="technologies",
    family="web",
    category="passif",
    run=run,
    quick=True,
    order=50,
    column="technologies",
    placeholder=_no_list,
)
