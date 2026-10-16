# =============================================================================
# DomainRecon - Tests de l'adaptateur du module « screenshot » (sans navigateur)
# =============================================================================
# La capture elle-même (Chromium, proxy filtrant anti-SSRF) est testée dans
# tests/scanner/test_screenshot.py ; ici : le contrat du module.
# =============================================================================

import pytest

from domainrecon.i18n import render
from domainrecon.scanner import screenshot
from domainrecon.scanner.errors import ModuleError, ModuleSkipped
from domainrecon.scanner.modules import screenshot as module

SPEC = module.SPEC


class _Appels(list):
    reponse: dict


@pytest.fixture
def capture(monkeypatch):
    """Remplace capture_screenshot ; rend la liste des appels (domaine, dossier)."""
    appels = _Appels()
    reponse = {"valeur": "example_com_1700000000_0a1b2c3d.png"}

    async def faux(domain, directory):
        appels.append((domain, directory))
        valeur = reponse["valeur"]
        if isinstance(valeur, BaseException):
            raise valeur
        return valeur

    monkeypatch.setattr(screenshot, "capture_screenshot", faux)
    appels.reponse = reponse
    return appels


def test_succes_renvoie_le_nom_du_fichier(contexte, outils, capture):
    sortie = outils.executer(SPEC, contexte())
    assert sortie == "example_com_1700000000_0a1b2c3d.png"
    assert screenshot.SCREENSHOT_NAME_RE.match(sortie)
    assert capture == [("example.com", str(screenshot.SCREENSHOTS_DIR))]


def test_sans_playwright_ni_chromium_sans_objet(contexte, outils, capture):
    capture.reponse["valeur"] = None
    with pytest.raises(ModuleSkipped) as erreur:
        outils.executer(SPEC, contexte())
    assert "Playwright" in render(erreur.value.message, "fr")


def test_echec_de_la_capture_remonte(contexte, outils, capture):
    capture.reponse["valeur"] = ModuleError({"code": "orchestrator.module_failed", "params": {}})
    with pytest.raises(ModuleError):
        outils.executer(SPEC, contexte())


def test_sans_adresse_sans_objet(contexte):
    assert SPEC.skip_reason(contexte(addresses=[])) is not None
    assert SPEC.skip_reason(contexte()) is None


def test_valeur_de_repli_sans_capture():
    assert SPEC.placeholder({"code": "x", "params": {}}) is None
    assert SPEC.column == "screenshot_path"


def test_declaration():
    assert SPEC.family == "identity" and SPEC.category == "passif" and SPEC.quick is False
