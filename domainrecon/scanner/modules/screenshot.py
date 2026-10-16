# =============================================================================
# DomainRecon - Module « screenshot » : capture d'écran de la page d'accueil
# =============================================================================
# Adaptateur de scanner/screenshot.py (capture_screenshot) : renvoie le nom du
# fichier créé dans SCREENSHOTS_DIR. Sans Playwright ou Chromium, la fonction
# renvoie None : le module est alors « sans objet » (ModuleSkipped), pas en
# échec. Sans objet aussi si la cible n'a pas résolu, ou si les Réglages
# désactivent la capture (orchestrateur). Hors du profil « rapide » : lancer
# Chromium est lent.
# =============================================================================

from ...i18n import msg
from .. import screenshot
from ..errors import ModuleSkipped
from ..registry import ModuleSpec, ScanContext, skip_without_address


async def run(context: ScanContext) -> str:
    path = await screenshot.capture_screenshot(context.domain, str(screenshot.SCREENSHOTS_DIR))
    if path is None:
        raise ModuleSkipped(msg("orchestrator.skip_no_playwright"))
    return path


def _no_capture(error: object) -> None:
    """Sans capture : aucun nom de fichier."""
    return None


def _legacy_measured(scan: dict, value: object) -> bool:
    """Scan antérieur à module_status : un chemin ou rien, aucun résultat à vérifier."""
    return True


SPEC = ModuleSpec(
    name="screenshot",
    family="identity",
    category="passif",
    run=run,
    skip_reason=skip_without_address,
    order=170,
    # Colonne historique : le nom du fichier de capture.
    column="screenshot_path",
    placeholder=_no_capture,
    legacy_measured=_legacy_measured,
)
