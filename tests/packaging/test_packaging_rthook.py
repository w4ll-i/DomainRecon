"""Hook d'exécution PyInstaller (packaging/rthooks/pyi_rth_domainrecon.py)."""

import os

from pkgload import load

BUNDLE = "/opt/domainrecon/_internal"


# Chargé hors exécutable (sys.frozen absent) : le bloc final du hook ne s'exécute pas.
rthook = load("rthook", "rthooks/pyi_rth_domainrecon.py")


def test_force_bundled_browsers_ecrase_la_valeur_utilisateur():
    """Chromium embarqué : une installation Playwright de l'utilisateur ne doit pas être utilisée."""
    env = {"PLAYWRIGHT_BROWSERS_PATH": "/home/alice/.cache/ms-playwright"}
    rthook.force_bundled_browsers(env, BUNDLE)
    assert env["PLAYWRIGHT_BROWSERS_PATH"] == os.path.join(BUNDLE, "browsers")


def test_force_bundled_browsers_sans_valeur_prealable():
    env = {}
    rthook.force_bundled_browsers(env, BUNDLE)
    assert env == {"PLAYWRIGHT_BROWSERS_PATH": os.path.join(BUNDLE, "browsers")}


def test_dossier_des_navigateurs_identique_a_la_spec():
    helpers = load("pyi_helpers", "pyi_helpers.py")
    assert rthook.BROWSERS_DIR_NAME == helpers.BROWSERS_DIR_NAME


def test_restore_library_path_valeur_d_origine():
    """Environnement Linux : xdg-open et Chromium retrouvent le LD_LIBRARY_PATH de l'utilisateur."""
    env = {"LD_LIBRARY_PATH": f"{BUNDLE}:/usr/local/lib", "LD_LIBRARY_PATH_ORIG": "/usr/local/lib"}
    rthook.restore_library_path(env, "linux", BUNDLE)
    assert env["LD_LIBRARY_PATH"] == "/usr/local/lib"


def test_restore_library_path_retire_le_dossier_de_l_application():
    env = {"LD_LIBRARY_PATH": f"{BUNDLE}:/opt/autre"}
    rthook.restore_library_path(env, "linux", BUNDLE)
    assert env["LD_LIBRARY_PATH"] == "/opt/autre"
    env = {"LD_LIBRARY_PATH": f"{BUNDLE}/"}
    rthook.restore_library_path(env, "linux", BUNDLE)
    assert "LD_LIBRARY_PATH" not in env


def test_restore_library_path_sans_variable():
    env = {}
    rthook.restore_library_path(env, "linux", BUNDLE)
    assert env == {}


def test_restore_library_path_ignore_windows():
    env = {"LD_LIBRARY_PATH": "C:/x"}
    rthook.restore_library_path(env, "win32", "C:/app/_internal")
    assert env == {"LD_LIBRARY_PATH": "C:/x"}
