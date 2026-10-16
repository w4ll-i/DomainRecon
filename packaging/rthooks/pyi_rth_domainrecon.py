"""Hook d'exécution PyInstaller de DomainRecon : exécuté avant le programme, dans l'exécutable seulement.

1. Chromium embarqué : PLAYWRIGHT_BROWSERS_PATH=<_internal>/browsers fait
   chercher le navigateur là où le build l'a placé (chemin court : Windows
   refuse de lancer un exécutable dont le chemin dépasse 260 caractères), même
   si l'utilisateur a défini cette variable pour une autre installation.
2. Linux : le chargeur de PyInstaller place le dossier de l'application en
   tête de LD_LIBRARY_PATH. Les programmes lancés ensuite (navigateur par
   défaut via xdg-open, Chromium) chargeraient nos copies des bibliothèques
   au lieu de celles du système : la valeur d'origine leur est rendue. Le
   processus courant n'est pas concerné (le chargeur dynamique ne lit la
   variable qu'au démarrage).
Les flux standard absents de l'exécutable fenêtré sont gérés par
domainrecon.desktop.launcher.ensure_std_streams().
"""

import os
import posixpath
import sys

# Dossier des navigateurs dans _internal/ (même valeur que pyi_helpers.BROWSERS_DIR_NAME).
BROWSERS_DIR_NAME = "browsers"


def force_bundled_browsers(environ, bundle_dir: str) -> None:
    """Impose le Chromium embarqué : <_internal>/browsers."""
    environ["PLAYWRIGHT_BROWSERS_PATH"] = os.path.join(bundle_dir, BROWSERS_DIR_NAME)


def restore_library_path(environ, platform: str, bundle_dir: str) -> None:
    """Linux : rend aux processus enfants le LD_LIBRARY_PATH d'avant PyInstaller."""
    if not platform.startswith("linux"):
        return
    if "LD_LIBRARY_PATH_ORIG" in environ:
        environ["LD_LIBRARY_PATH"] = environ["LD_LIBRARY_PATH_ORIG"]
        return
    bundle = posixpath.normpath(bundle_dir) if bundle_dir else None
    kept = [
        entry
        for entry in environ.get("LD_LIBRARY_PATH", "").split(":")
        if entry and posixpath.normpath(entry) != bundle
    ]
    if kept:
        environ["LD_LIBRARY_PATH"] = ":".join(kept)
    else:
        environ.pop("LD_LIBRARY_PATH", None)


if getattr(sys, "frozen", False):
    _bundle_dir = getattr(sys, "_MEIPASS", os.path.dirname(sys.executable))
    force_bundled_browsers(os.environ, _bundle_dir)
    restore_library_path(os.environ, sys.platform, _bundle_dir)
