# -*- mode: python ; coding: utf-8 -*-
# =============================================================================
# DomainRecon - Spécification PyInstaller (mode onedir)
# =============================================================================
# Lancée par packaging/build.py, après la construction de l'interface
# (domainrecon/web) et l'installation de Chromium dans private/build/ms-playwright
# (PLAYWRIGHT_BROWSERS_PATH), embarqué dans _internal/browsers :
#   python -m PyInstaller --noconfirm --clean --distpath private/build/dist --workpath private/build/pyinstaller packaging/domainrecon.spec
# Résultat : private/build/dist/DomainRecon/ avec, sous Windows, DomainRecon.exe (fenêtré)
# et DomainRecon-console.exe (console, version portable), qui partagent le
# même dossier _internal/ ; sous Linux, l'exécutable domainrecon.
# =============================================================================

import importlib.util
import sys
from pathlib import Path

from PyInstaller.utils.hooks import collect_data_files, collect_submodules

PACKAGING_DIR = Path(SPECPATH).resolve()  # SPECPATH : fourni par PyInstaller
ROOT = PACKAGING_DIR.parent
IS_WINDOWS = sys.platform == "win32"
IS_LINUX = sys.platform.startswith("linux")

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


def _exe(name, console):
    return EXE(
        pyz,
        a.scripts,
        [],
        exclude_binaries=True,
        name=name,
        debug=False,
        bootloader_ignore_signals=False,
        strip=False,
        upx=False,
        console=console,
        icon=str(ICON) if IS_WINDOWS else None,
        version=pyi_helpers.windows_version_info(VERSION, f"{name}.exe") if IS_WINDOWS else None,
        contents_directory=pyi_helpers.CONTENTS_DIR,
    )


if IS_WINDOWS:
    executables = [_exe("DomainRecon", console=False), _exe("DomainRecon-console", console=True)]
else:
    executables = [_exe(pyi_helpers.LINUX_EXECUTABLE, console=True)]

coll = COLLECT(
    *executables,
    a.binaries,
    a.datas,
    strip=False,
    upx=False,
    upx_exclude=[],
    name=pyi_helpers.APP_NAME,
)
