"""Aides à la construction : utilisées par packaging/domainrecon.spec (PyInstaller) et packaging/build.py.

Le dossier packaging/ n'est pas un paquet Python (pas de __init__.py) : il
masquerait la bibliothèque « packaging » de PyPI. Ce module est donc chargé
par son chemin de fichier (importlib), jamais par un import de paquet.
"""

from __future__ import annotations

import os
import re
import sys
from collections.abc import Iterable, Mapping
from pathlib import Path

APP_NAME = "DomainRecon"
LINUX_EXECUTABLE = "domainrecon"
WINDOWS_EXECUTABLES = ("DomainRecon.exe", "DomainRecon-console.exe")
CONTENTS_DIR = "_internal"

# Dossiers de sortie, relatifs à la racine du dépôt (tous deux ignorés par git) :
#   private/build/      travail de la construction (PyInstaller, Chromium,
#                       dossier intermédiaire dist/ de l'application) ;
#   release/<version>/  livrables finaux, SHA256SUMS et NOTES.md.
# Variables d'environnement pour les déplacer (chemin absolu, ou relatif à la
# racine du dépôt) ; build.py --build-dir / --release-dir les définissent.
BUILD_DIR_ENV = "DOMAINRECON_BUILD_DIR"
RELEASE_DIR_ENV = "DOMAINRECON_RELEASE_DIR"
DEFAULT_BUILD_DIR = Path("private") / "build"
DEFAULT_RELEASE_DIR = Path("release")

_VERSION_RE = re.compile(r'^__version__\s*=\s*"(\d+\.\d+\.\d+)"\s*$', re.MULTILINE)
_SEMVER_RE = re.compile(r"(\d+)\.(\d+)\.(\d+)")
_SHELL_NAMES = ("chrome-headless-shell", "chrome-headless-shell.exe")
# Navigateurs embarqués : _internal/browsers. Un chemin court compte : Windows
# refuse de lancer un exécutable dont le chemin dépasse 260 caractères, et les
# navigateurs installés avec PLAYWRIGHT_BROWSERS_PATH=0 (dans le paquet
# Playwright) ajoutent 136 caractères au dossier de l'application (mesuré :
# « spawn … chrome-headless-shell.exe ENOENT » dès 124 caractères).
BROWSERS_DIR_NAME = "browsers"
# Composants installés par `playwright install` à côté du navigateur, inutiles ici.
# .links/ ne contient que le chemin absolu du Playwright de la machine de build.
_UNUSED_BROWSER_PREFIXES = ("ffmpeg-", "winldd-", ".links")
# Navigateurs qu'une installation avec PLAYWRIGHT_BROWSERS_PATH=0 aurait laissés
# dans le paquet Playwright : le hook de Playwright les collecterait en double.
PLAYWRIGHT_LOCAL_BROWSERS = "playwright/driver/package/.local-browsers"

# Bibliothèques de la pile graphique Linux (GTK, WebKitGTK, GLib, Pango,
# Cairo, X11/Wayland…) : prises dans le système au lieu d'être embarquées.
# Des copies venues d'Ubuntu 22.04 entreraient en conflit avec le WebKitGTK,
# plus récent, des distributions suivantes (symboles introuvables).
LINUX_SYSTEM_LIB_PREFIXES = (
    "libatk-1.0.",
    "libatk-bridge-2.0.",
    "libatspi.",
    "libcairo.",
    "libcairo-gobject.",
    "libdatrie.",
    "libdbus-1.",
    "libepoxy.",
    "libfontconfig.",
    "libfreetype.",
    "libfribidi.",
    "libgdk-3.",
    "libgdk_pixbuf-2.0.",
    "libgio-2.0.",
    "libgirepository-1.0.",
    "libglib-2.0.",
    "libgmodule-2.0.",
    "libgobject-2.0.",
    "libgraphite2.",
    "libgthread-2.0.",
    "libgtk-3.",
    "libharfbuzz.",
    "libjavascriptcoregtk-4.1.",
    "libpango-1.0.",
    "libpangocairo-1.0.",
    "libpangoft2-1.0.",
    "libpixman-1.",
    "libpng16.",
    "libsoup-3.0.",
    "libthai.",
    "libwayland-",
    "libwebkit2gtk-4.1.",
    "libX",
    "libxcb",
    "libxkbcommon.",
)


def read_version(root: Path) -> str:
    """Version de l'application, lue dans domainrecon/__init__.py sans importer le package."""
    text = (root / "domainrecon" / "__init__.py").read_text(encoding="utf-8")
    match = _VERSION_RE.search(text)
    if match is None:
        raise ValueError('__version__ introuvable dans domainrecon/__init__.py (format attendu : "X.Y.Z")')
    return match.group(1)


def version_tuple(version: str) -> tuple[int, int, int, int]:
    """« 1.0.0 » -> (1, 0, 0, 0) : format des ressources de version Windows."""
    match = _SEMVER_RE.fullmatch(version)
    if match is None:
        raise ValueError(f"Version invalide : {version!r} (attendu : X.Y.Z)")
    major, minor, patch = (int(part) for part in match.groups())
    return (major, minor, patch, 0)


def package_datas(root: Path, platform: str = sys.platform) -> list[tuple[str, str]]:
    """Données du package domainrecon à embarquer : interface construite, catalogues (fragments des modules
    compris), icône de fenêtre (Linux)."""
    package = root / "domainrecon"
    web = package / "web"
    if not (web / "index.html").is_file():
        raise FileNotFoundError(
            f"Interface absente ({web / 'index.html'}) : lancez « npm ci && npm run build » dans frontend/."
        )
    catalogs = sorted((package / "i18n").glob("*.json"))
    if not catalogs:
        raise FileNotFoundError("Catalogues de messages absents (domainrecon/i18n/*.json).")
    datas = [
        (str(path), (Path("domainrecon") / path.parent.relative_to(package)).as_posix())
        for path in sorted(web.rglob("*"))
        if path.is_file()
    ]
    datas += [(str(path), "domainrecon/i18n") for path in catalogs]
    # Fragments des modules (i18n/modules/<clé>.<langue>.json), fusionnés au catalogue à la lecture.
    fragments = sorted((package / "i18n" / "modules").glob("*.json"))
    datas += [(str(path), "domainrecon/i18n/modules") for path in fragments]
    icon = package / "desktop" / "icon.png"
    # Icône PNG pour GTK seulement. Sous Windows, pywebview (WinForms) passe le même
    # paramètre à System.Drawing.Icon, qui n'accepte qu'un .ico : « ArgumentException :
    # 'picture' », la fenêtre plante au démarrage. Sans icône embarquée, le lanceur n'en
    # transmet aucune et la fenêtre prend l'icône de DomainRecon.exe.
    if platform.startswith("linux") and icon.is_file():
        datas.append((str(icon), "domainrecon/desktop"))
    return datas


def _dir_setting(root: Path, name: str, default: Path, environ: Mapping[str, str] | None) -> Path:
    """Dossier lu dans la variable `name` (absolu, ou relatif à `root`), sinon root/default."""
    env = os.environ if environ is None else environ
    value = (env.get(name) or "").strip()
    if not value:
        return root / default
    path = Path(value).expanduser()
    return path if path.is_absolute() else root / path


def build_dir(root: Path, environ: Mapping[str, str] | None = None) -> Path:
    """Dossier de travail de la construction : private/build/ (ou DOMAINRECON_BUILD_DIR)."""
    return _dir_setting(root, BUILD_DIR_ENV, DEFAULT_BUILD_DIR, environ)


def build_dist_dir(root: Path, environ: Mapping[str, str] | None = None) -> Path:
    """Sortie intermédiaire de PyInstaller (dossier DomainRecon/ de l'application) : <build>/dist."""
    return build_dir(root, environ) / "dist"


def release_root(root: Path, environ: Mapping[str, str] | None = None) -> Path:
    """Dossier des livrables, toutes versions : release/ (ou DOMAINRECON_RELEASE_DIR)."""
    return _dir_setting(root, RELEASE_DIR_ENV, DEFAULT_RELEASE_DIR, environ)


def release_dir(root: Path, version: str, environ: Mapping[str, str] | None = None) -> Path:
    """Livrables d'une version : release/<version>/."""
    return release_root(root, environ) / version


def build_browsers_dir(root: Path, environ: Mapping[str, str] | None = None) -> Path:
    """Dossier où le build installe Chromium (PLAYWRIGHT_BROWSERS_PATH pendant le build) : <build>/ms-playwright."""
    return build_dir(root, environ) / "ms-playwright"


def headless_shell_executables(browsers_dir: Path) -> list[Path]:
    """Exécutables du « headless shell » de Chromium présents dans un dossier de navigateurs Playwright."""
    return sorted(
        path
        for path in browsers_dir.glob("chromium_headless_shell-*/*/*")
        if path.name in _SHELL_NAMES and path.is_file()
    )


def browser_datas(browsers_dir: Path) -> list[tuple[str, str]]:
    """Tous les fichiers des navigateurs installés par le build (bibliothèques .so/.dll comprises), vers _internal/browsers.

    Les dossiers ffmpeg-* (enregistrement vidéo) et winldd-* (contrôle des
    DLL sous Windows) que Playwright installe avec le headless shell ne
    servent pas aux captures d'écran : laissés de côté, comme .links (chemin
    absolu de la machine de build, sans usage à l'exécution).
    """
    if not headless_shell_executables(browsers_dir):
        raise FileNotFoundError(
            f"Chromium (headless shell) absent de {browsers_dir} : lancez packaging/build.py, ou "
            "« PLAYWRIGHT_BROWSERS_PATH=private/build/ms-playwright python -m playwright install --only-shell chromium »."
        )
    return [
        (str(path), (Path(BROWSERS_DIR_NAME) / path.parent.relative_to(browsers_dir)).as_posix())
        for path in sorted(browsers_dir.rglob("*"))
        if path.is_file()
        and path.name != "debug.log"
        and not path.relative_to(browsers_dir).parts[0].startswith(_UNUSED_BROWSER_PREFIXES)
    ]


def drop_dest_prefix(entries: Iterable[tuple], prefix: str) -> list[tuple]:
    """Retire de la liste PyInstaller (destination, source, type) les entrées dont la destination commence par `prefix`."""
    return [entry for entry in entries if not Path(entry[0]).as_posix().startswith(prefix)]


def filter_system_libs(
    binaries: Iterable[tuple], prefixes: tuple[str, ...] = LINUX_SYSTEM_LIB_PREFIXES
) -> list[tuple]:
    """Retire de la liste PyInstaller (destination, source, type) les bibliothèques graphiques du système.

    Seules les bibliothèques placées à la racine de _internal/ sont concernées :
    celles du navigateur embarqué restent en place.
    """
    kept = []
    for entry in binaries:
        dest = Path(entry[0])
        if dest.parent == Path(".") and dest.name.startswith(prefixes):
            continue
        kept.append(entry)
    return kept


def hooks_config() -> dict:
    """Réglages des hooks PyInstaller de PyGObject (Linux) : GTK 3, thème et icônes Adwaita, FR/EN."""
    return {
        "gi": {
            "icons": ["Adwaita"],
            "themes": ["Adwaita"],
            "languages": ["fr", "en"],
            "module-versions": {"Gtk": "3.0"},
        }
    }


def windows_version_info(version: str, original_filename: str):
    """Ressource de version Windows (onglet « Détails » des propriétés du fichier .exe)."""
    from PyInstaller.utils.win32.versioninfo import (
        FixedFileInfo,
        StringFileInfo,
        StringStruct,
        StringTable,
        VarFileInfo,
        VarStruct,
        VSVersionInfo,
    )

    numbers = version_tuple(version)
    strings = [
        StringStruct("CompanyName", APP_NAME),
        StringStruct("FileDescription", "DomainRecon - reconnaissance OSINT de domaines"),
        StringStruct("FileVersion", version),
        StringStruct("InternalName", APP_NAME),
        StringStruct("LegalCopyright", "Copyright (c) 2025-2026 W4ll-I - tous droits réservés"),
        StringStruct("OriginalFilename", original_filename),
        StringStruct("ProductName", APP_NAME),
        StringStruct("ProductVersion", version),
    ]
    return VSVersionInfo(
        ffi=FixedFileInfo(filevers=numbers, prodvers=numbers, mask=0x3F, flags=0x0, OS=0x40004, fileType=0x1),
        kids=[
            StringFileInfo([StringTable("040C04B0", strings)]),
            VarFileInfo([VarStruct("Translation", [0x040C, 1200])]),
        ],
    )
