# =============================================================================
# DomainRecon - Rapports : PDF
# =============================================================================
# Le PDF est imprimé depuis la page HTML du rapport par le Chromium de
# Playwright (le même que la capture d'écran). La page est chargée depuis la
# mémoire, JavaScript est désactivé et toute requête réseau est refusée : le
# rapport ne contacte rien. Chromium absent : PdfUnavailableError, les autres
# formats restent disponibles.
# =============================================================================

from __future__ import annotations

import logging

logger = logging.getLogger(__name__)

_BROWSER_MISSING_MARKER = "executable doesn't exist"

INSTALL_HINT = "python -m playwright install --only-shell chromium"


class PdfUnavailableError(RuntimeError):
    """Le PDF ne peut pas être produit (Playwright ou Chromium absent, ou démarrage impossible)."""


async def _refuse_network(route) -> None:
    # Seules les ressources en mémoire (data:, about:) sont admises.
    await route.abort()


async def html_to_pdf(html: str) -> bytes:
    """PDF (A4) de la page `html`."""
    try:
        from playwright.async_api import async_playwright
    except ImportError as e:
        raise PdfUnavailableError("Playwright n'est pas installé") from e

    try:
        async with async_playwright() as p:
            try:
                browser = await p.chromium.launch(headless=True)
            except Exception as e:
                detail = str(e).lower()
                # Le message de Playwright contient un chemin local : journal seulement.
                logger.warning("Chromium indisponible pour le PDF : %s", e)
                if _BROWSER_MISSING_MARKER in detail:
                    raise PdfUnavailableError(f"Chromium n'est pas installé ({INSTALL_HINT})") from e
                raise PdfUnavailableError("Chromium n'a pas pu démarrer") from e
            try:
                context = await browser.new_context(java_script_enabled=False, service_workers="block")
                await context.route("**/*", _refuse_network)
                page = await context.new_page()
                await page.set_content(html, wait_until="load")
                return await page.pdf(
                    format="A4",
                    print_background=True,
                    margin={"top": "15mm", "bottom": "15mm", "left": "12mm", "right": "12mm"},
                )
            finally:
                await browser.close()
    except PdfUnavailableError:
        raise
    except Exception as e:
        logger.warning("Génération du PDF échouée : %s", e)
        raise PdfUnavailableError("La génération du PDF a échoué") from e
