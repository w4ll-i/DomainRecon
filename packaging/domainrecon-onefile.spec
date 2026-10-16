# -*- mode: python ; coding: utf-8 -*-
# =============================================================================
# DomainRecon - Spécification PyInstaller (mode onefile, Windows seulement)
# =============================================================================
# Exécutable portable en un seul fichier, fenêtré : DomainRecon-<version>-portable.exe,
# produit dans private/build/dist/ puis rangé par build.py dans release/<version>/.
# Même analyse, mêmes données (interface, Chromium dans browsers/) et mêmes
# métadonnées que domainrecon.spec (la référence), avec en plus le marqueur
# portable.flag à la racine du bundle extrait (sys._MEIPASS) : domainrecon.core.paths
# y reconnaît le mode portable monofichier (données dans DomainRecon-data/ à
# côté du .exe, rien dans %LOCALAPPDATA%). Lancée par packaging/build.py :
#   python -m PyInstaller --noconfirm --clean --distpath private/build/dist --workpath private/build/pyinstaller-onefile packaging/domainrecon-onefile.spec
# =============================================================================

import importlib.util
import sys
from pathlib import Path

from PyInstaller.utils.hooks import collect_data_files, collect_submodules

PACKAGING_DIR = Path(SPECPATH).resolve()  # SPECPATH : fourni par PyInstaller
ROOT = PACKAGING_DIR.parent
IS_WINDOWS = sys.platform == "win32"
IS_LINUX = sys.platform.startswith("linux")

if not IS_WINDOWS:
    raise SystemExit("domainrecon-onefile.spec : exécutable monofichier prévu pour Windows seulement.")

# packaging/ n'est pas un paquet Python : module d'aide chargé par son chemin.
_helpers_spec = importlib.util.spec_from_file_location("drpkg_pyi_helpers", PACKAGING_DIR / "pyi_helpers.py")
pyi_helpers = importlib.util.module_from_spec(_helpers_spec)
sys.modules[_helpers_spec.name] = pyi_helpers
_helpers_spec.loader.exec_module(pyi_helpers)

# domainrecon importable pendant l'analyse (collect_submodules l'importe).
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

VERSION = pyi_helpers.read_version(ROOT)
ICON = PACKAGING_DIR / "icons" / "domainrecon.ico"

datas = pyi_helpers.package_datas(ROOT)
# Marqueur du mode portable, embarqué à la racine de _MEIPASS (jamais dans le dossier onedir).
PORTABLE_MARKER = pyi_helpers.build_dir(ROOT) / "onefile" / "portable.flag"
PORTABLE_MARKER.parent.mkdir(parents=True, exist_ok=True)
PORTABLE_MARKER.write_text("Executable portable DomainRecon (monofichier).\n", encoding="utf-8")
datas.append((str(PORTABLE_MARKER), "."))
# Liste des suffixes publics embarquée par tldextract (aucun accès réseau) et
# données de python-whois : fichiers non Python, oubliés sans cela.
datas += collect_data_files("tldextract")
datas += collect_data_files("whois")
# Chromium headless shell complet (bibliothèques .so/.dll comprises) -> _internal/browsers.
datas += pyi_helpers.browser_datas(pyi_helpers.build_browsers_dir(ROOT))

hiddenimports = collect_submodules("domainrecon")
if IS_WINDOWS:
    hiddenimports += ["webview.platforms.winforms", "webview.platforms.edgechromium", "clr"]
    # plyer charge son implémentation par plateforme dynamiquement (notifications de bureau).
    hiddenimports += collect_submodules("plyer.platforms.win")
elif IS_LINUX:
    hiddenimports += [
        "webview.platforms.gtk",
        "gi",
        "gi.repository.GLib",
        "gi.repository.GObject",
        "gi.repository.Gio",
        "gi.repository.Gdk",
        "gi.repository.Gtk",
    ]
    hiddenimports += collect_submodules("plyer.platforms.linux")

a = Analysis(
    [str(PACKAGING_DIR / "entry" / "domainrecon_entry.py")],
    pathex=[str(ROOT)],
    binaries=[],
    datas=datas,
    hiddenimports=hiddenimports,
    hookspath=[],
    hooksconfig=pyi_helpers.hooks_config(),
    runtime_hooks=[str(PACKAGING_DIR / "rthooks" / "pyi_rth_domainrecon.py")],
    excludes=["tkinter", "pytest", "_pytest", "ruff"],
    noarchive=False,
    optimize=0,
)
# Navigateurs laissés dans le paquet Playwright par une installation avec
# PLAYWRIGHT_BROWSERS_PATH=0 : collectés en double par le hook de Playwright.
a.datas = pyi_helpers.drop_dest_prefix(a.datas, pyi_helpers.PLAYWRIGHT_LOCAL_BROWSERS)
a.binaries = pyi_helpers.drop_dest_prefix(a.binaries, pyi_helpers.PLAYWRIGHT_LOCAL_BROWSERS)
if IS_LINUX:
    # GTK, WebKitGTK, GLib, X11… : bibliothèques du système (voir pyi_helpers).
    a.binaries = pyi_helpers.filter_system_libs(a.binaries)

pyz = PYZ(a.pure)

EXE_NAME = f"DomainRecon-{VERSION}-portable"

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name=EXE_NAME,
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    console=False,
    icon=str(ICON),
    version=pyi_helpers.windows_version_info(VERSION, f"{EXE_NAME}.exe"),
)
