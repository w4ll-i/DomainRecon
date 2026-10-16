# =============================================================================
# DomainRecon - Tests des emplacements (core/paths.py)
# =============================================================================
# Trois modes : sources (développement), exécutable installé, portable.
# L'exécutable PyInstaller est simulé (sys.frozen, sys.executable, sys._MEIPASS).
# =============================================================================

import sys
from pathlib import Path

import pytest

from domainrecon.core import paths

REPO = Path(__file__).resolve().parents[2]


@pytest.fixture
def env_propre(monkeypatch):
    """Ni DATA_DIR (posé par conftest), ni mode portable forcé, ni XDG."""
    for name in ("DATA_DIR", "DOMAINRECON_PORTABLE", "XDG_DATA_HOME"):
        monkeypatch.delenv(name, raising=False)


@pytest.fixture
def fige(monkeypatch, tmp_path):
    """Exécutable PyInstaller (onedir) simulé dans tmp_path/app."""
    app = tmp_path / "app"
    (app / "_internal").mkdir(parents=True)
    monkeypatch.setattr(sys, "frozen", True, raising=False)
    monkeypatch.setattr(sys, "executable", str(app / "DomainRecon.exe"))
    monkeypatch.setattr(sys, "_MEIPASS", str(app / "_internal"), raising=False)
    return app


def test_sources_dossiers_du_depot(env_propre):
    assert paths.is_frozen() is False
    assert paths.app_dir() == REPO
    assert paths.package_dir() == REPO / "domainrecon"
    assert paths.web_dir() == REPO / "domainrecon" / "web"
    assert paths.i18n_dir() == REPO / "domainrecon" / "i18n"
    assert paths.is_portable() is False
    # Données des sources dans private/data/ (ignoré par git), jamais à la racine du dépôt.
    assert paths.data_dir() == REPO / "private" / "data"
    assert paths.source_data_dir() == REPO / "private" / "data"
    assert paths.env_files() == [REPO / "private" / "data" / ".env", REPO / ".env"]


def test_data_dir_prioritaire(env_propre, monkeypatch, tmp_path):
    monkeypatch.setenv("DATA_DIR", str(tmp_path / "ailleurs"))
    assert paths.data_dir() == tmp_path / "ailleurs"
    monkeypatch.setenv("DATA_DIR", "relatif/donnees")
    assert paths.data_dir() == REPO / "relatif" / "donnees"
    # Valeur vide : variable absente.
    monkeypatch.setenv("DATA_DIR", "   ")
    assert paths.data_dir() == REPO / "private" / "data"


@pytest.mark.parametrize("valeur", ["1", "true", "YES", "on"])
def test_portable_par_variable(env_propre, monkeypatch, valeur):
    monkeypatch.setenv("DOMAINRECON_PORTABLE", valeur)
    assert paths.is_portable() is True
    assert paths.data_dir() == REPO / "data"


def test_fige_installe_windows(env_propre, fige, monkeypatch, tmp_path):
    monkeypatch.setattr(sys, "platform", "win32")
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path / "Local"))
    assert paths.is_frozen() is True
    assert paths.app_dir() == fige
    assert paths.package_dir() == fige / "_internal" / "domainrecon"
    assert paths.web_dir() == fige / "_internal" / "domainrecon" / "web"
    assert paths.i18n_dir() == fige / "_internal" / "domainrecon" / "i18n"
    assert paths.is_portable() is False
    assert paths.data_dir() == tmp_path / "Local" / "DomainRecon"
    # Figé : pas de .env à côté de l'exécutable, seulement dans les données.
    assert paths.env_files() == [tmp_path / "Local" / "DomainRecon" / ".env"]


def test_fige_installe_linux_xdg(env_propre, fige, monkeypatch, tmp_path):
    monkeypatch.setattr(sys, "platform", "linux")
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "xdg"))
    assert paths.data_dir() == tmp_path / "xdg" / "domainrecon"


def test_fige_installe_linux_sans_xdg(env_propre, fige, monkeypatch, tmp_path):
    monkeypatch.setattr(sys, "platform", "linux")
    monkeypatch.setattr(Path, "home", classmethod(lambda cls: tmp_path / "maison"))
    assert paths.data_dir() == tmp_path / "maison" / ".local" / "share" / "domainrecon"


def test_xdg_relatif_ignore(env_propre, fige, monkeypatch, tmp_path):
    """La spécification XDG impose un chemin absolu : un chemin relatif est ignoré."""
    monkeypatch.setattr(sys, "platform", "linux")
    monkeypatch.setenv("XDG_DATA_HOME", "relatif")
    monkeypatch.setattr(Path, "home", classmethod(lambda cls: tmp_path / "maison"))
    assert paths.data_dir() == tmp_path / "maison" / ".local" / "share" / "domainrecon"


def test_fige_portable_par_marqueur(env_propre, fige, monkeypatch):
    monkeypatch.setattr(sys, "platform", "win32")
    (fige / paths.PORTABLE_FLAG).write_text("", encoding="utf-8")
    assert paths.is_portable() is True
    assert paths.data_dir() == fige / "data"
    assert paths.env_files() == [fige / "data" / ".env"]


def test_data_dir_prioritaire_meme_fige(env_propre, fige, monkeypatch, tmp_path):
    monkeypatch.setattr(sys, "platform", "win32")
    monkeypatch.setenv("DATA_DIR", "donnees")
    # Relatif : depuis le dossier de l'exécutable.
    assert paths.data_dir() == fige / "donnees"


def test_onefile_marqueur_embarque_donnees_a_cote_de_l_exe(env_propre, fige, monkeypatch, tmp_path):
    """Monofichier : marqueur dans _MEIPASS (dossier d'extraction), données à côté du .exe."""
    monkeypatch.setattr(sys, "platform", "win32")
    meipass = tmp_path / "_MEI123"
    meipass.mkdir()
    (meipass / paths.PORTABLE_FLAG).write_text("", encoding="utf-8")
    monkeypatch.setattr(sys, "_MEIPASS", str(meipass), raising=False)
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path / "local"))
    assert paths.is_onefile_portable() is True
    assert paths.is_portable() is True
    assert paths.data_dir() == fige / paths.ONEFILE_DATA_DIR
    assert paths.ONEFILE_DATA_DIR == "DomainRecon-data"
    assert paths.env_files() == [fige / "DomainRecon-data" / ".env"]


def test_onefile_data_dir_prioritaire(env_propre, fige, monkeypatch, tmp_path):
    monkeypatch.setattr(sys, "platform", "win32")
    meipass = tmp_path / "_MEI123"
    meipass.mkdir()
    (meipass / paths.PORTABLE_FLAG).write_text("", encoding="utf-8")
    monkeypatch.setattr(sys, "_MEIPASS", str(meipass), raising=False)
    monkeypatch.setenv("DATA_DIR", "donnees")
    assert paths.data_dir() == fige / "donnees"


def test_onedir_sans_marqueur_embarque_inchange(env_propre, fige, monkeypatch):
    monkeypatch.setattr(sys, "platform", "win32")
    assert paths.is_onefile_portable() is False
    assert paths.is_portable() is False


def test_zip_portable_garde_son_dossier_data(env_propre, fige, monkeypatch):
    """Marqueur à côté de l'exécutable (zip) : data/, pas DomainRecon-data/."""
    monkeypatch.setattr(sys, "platform", "win32")
    (fige / paths.PORTABLE_FLAG).write_text("", encoding="utf-8")
    assert paths.is_onefile_portable() is False
    assert paths.data_dir() == fige / "data"


def test_sources_donnees_ignorees_par_git(env_propre):
    """private/ est ignoré par .gitignore : les données des sources ne peuvent pas être commitées."""
    lines = (REPO / ".gitignore").read_text(encoding="utf-8").splitlines()
    assert paths.source_data_dir().relative_to(REPO).parts[0] == "private"
    assert "/private/" in lines


def test_fige_ignore_le_dossier_des_sources(env_propre, fige, monkeypatch, tmp_path):
    """Installé : dossier de l'utilisateur, jamais private/data/ (propre aux sources)."""
    monkeypatch.setattr(sys, "platform", "win32")
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path / "Local"))
    assert paths.data_dir() == tmp_path / "Local" / "DomainRecon"
    assert paths.data_dir() != paths.source_data_dir()


def test_sources_jamais_onefile(env_propre):
    assert paths.is_onefile_portable() is False
