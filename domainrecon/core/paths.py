# =============================================================================
# DomainRecon - Emplacements : code, interface construite, catalogues, données
# =============================================================================
# Trois façons de lancer l'application :
#   - depuis les sources (développement) : données dans private/data/ du
#     dépôt (dossier ignoré par git) ;
#   - installée (exécutable PyInstaller) : données dans le dossier de
#     l'utilisateur (%LOCALAPPDATA%\DomainRecon, ~/.local/share/domainrecon) ;
#   - portable (fichier portable.flag à côté de l'exécutable, ou
#     DOMAINRECON_PORTABLE=1) : données dans data/ à côté de l'exécutable.
#   - exécutable portable en un seul fichier (PyInstaller onefile) : marqueur
#     portable.flag embarqué dans le bundle (sys._MEIPASS) ; données dans
#     DomainRecon-data/ à côté du .exe, rien dans %LOCALAPPDATA%.
# DATA_DIR reste prioritaire dans tous les cas. Ce module ne lit que
# l'environnement : il est importé avant la configuration (config.py), dont
# il désigne les fichiers de réglages.
# =============================================================================

import os
import sys
from pathlib import Path

# Marqueur de la version portable, à côté de l'exécutable.
PORTABLE_FLAG = "portable.flag"

# Dossier de données de l'exécutable portable monofichier, à côté du .exe.
ONEFILE_DATA_DIR = "DomainRecon-data"

# Dossier de données d'un lancement depuis les sources, relatif à la racine du dépôt.
SOURCE_DATA_DIR = Path("private") / "data"

_TRUE_VALUES = {"1", "true", "yes", "on"}


def _env(name: str) -> str | None:
    """Variable d'environnement sans espaces autour ; None si absente ou vide."""
    value = os.environ.get(name)
    if value is None or not value.strip():
        return None
    return value.strip()


def is_frozen() -> bool:
    """Vrai dans un exécutable PyInstaller."""
    return bool(getattr(sys, "frozen", False))


def app_dir() -> Path:
    """Dossier de l'application : celui de l'exécutable, ou la racine du dépôt."""
    if is_frozen():
        return Path(sys.executable).resolve().parent
    return Path(__file__).resolve().parents[2]


def package_dir() -> Path:
    """Dossier du package domainrecon (extrait par PyInstaller dans sys._MEIPASS)."""
    if is_frozen():
        return Path(getattr(sys, "_MEIPASS", app_dir())) / "domainrecon"
    return Path(__file__).resolve().parents[1]


def web_dir() -> Path:
    """Interface construite par le frontend (index.html, assets/)."""
    return package_dir() / "web"


def i18n_dir() -> Path:
    """Catalogues des messages (fr.json, en.json)."""
    return package_dir() / "i18n"


def is_onefile_portable() -> bool:
    """Exécutable monofichier portable : marqueur embarqué dans le bundle extrait (sys._MEIPASS).

    Les livrables onedir (installeur, zip) ne l'embarquent jamais : build.py
    refuse un portable.flag dans le dossier de l'application.
    """
    if not is_frozen():
        return False
    bundle = getattr(sys, "_MEIPASS", None)
    return bundle is not None and (Path(bundle) / PORTABLE_FLAG).is_file()


def is_portable() -> bool:
    """Version portable : DOMAINRECON_PORTABLE, marqueur embarqué (monofichier) ou à côté de l'exécutable."""
    if (_env("DOMAINRECON_PORTABLE") or "").lower() in _TRUE_VALUES:
        return True
    if is_onefile_portable():
        return True
    return is_frozen() and (app_dir() / PORTABLE_FLAG).exists()


def _user_data_dir() -> Path:
    """Dossier de données d'une installation, propre à l'utilisateur."""
    if sys.platform == "win32":
        base = _env("LOCALAPPDATA")
        root = Path(base) if base else Path.home() / "AppData" / "Local"
        return root / "DomainRecon"
    base = _env("XDG_DATA_HOME")
    # La spécification XDG ignore un chemin relatif.
    root = Path(base) if base and Path(base).is_absolute() else Path.home() / ".local" / "share"
    return root / "domainrecon"


def data_dir() -> Path:
    """Dossier des données (base SQLite, captures, .env, journaux).

    DATA_DIR prime ; relatif, il part du dossier de l'application.
    """
    value = _env("DATA_DIR")
    if value is not None:
        path = Path(value).expanduser()
        return path if path.is_absolute() else app_dir() / path
    if is_onefile_portable():
        return app_dir() / ONEFILE_DATA_DIR
    if is_portable():
        return app_dir() / "data"
    if is_frozen():
        return _user_data_dir()
    return source_data_dir()


def source_data_dir() -> Path:
    """Dossier de données par défaut d'un lancement depuis les sources : private/data/ du dépôt."""
    return app_dir() / SOURCE_DATA_DIR


def env_files() -> list[Path]:
    """Fichiers de réglages, par priorité décroissante : données, puis ./.env (sources)."""
    files = [data_dir() / ".env"]
    if not is_frozen():
        files.append(app_dir() / ".env")
    return files
