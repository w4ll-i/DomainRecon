# =============================================================================
# DomainRecon - Tests de la commande `domainrecon` (__main__.py)
# =============================================================================
# Le lanceur est simulé : aucun serveur n'est démarré, sauf dans le dernier
# test (sous-processus avec un faux uvicorn).
# =============================================================================

import os
import subprocess
import sys
import textwrap
from pathlib import Path

import pytest

import domainrecon
from domainrecon import __main__ as commande
from domainrecon.core import config
from domainrecon.desktop import launcher

ROOT = Path(domainrecon.__file__).resolve().parents[1]

# Variables lues par la commande : neutralisées (ni environnement du
# développeur ni .env).
_VARIABLES = ("HOST", "PORT")


@pytest.fixture
def faux_run(monkeypatch):
    appels = []

    def run(mode, **kwargs):
        appels.append((mode, kwargs))
        return 0

    monkeypatch.setattr(launcher, "run", run)
    for nom in _VARIABLES:
        monkeypatch.delenv(nom, raising=False)
    return appels


def test_version(faux_run, capsys):
    assert commande.main(["--version"]) == 0
    assert capsys.readouterr().out.strip() == "DomainRecon 1.0.0"
    assert faux_run == []


def test_mode_fenetre_par_defaut(faux_run):
    assert commande.main([]) == 0
    assert faux_run == [("window", {"host": "127.0.0.1", "port": 0, "open_browser": True})]


def test_mode_navigateur_sans_ouverture(faux_run):
    assert commande.main(["--browser", "--no-open"]) == 0
    assert faux_run == [("browser", {"host": "127.0.0.1", "port": 0, "open_browser": False})]


def test_modes_exclusifs(faux_run):
    with pytest.raises(SystemExit) as sortie:
        commande.main(["--browser", "--server"])
    assert sortie.value.code == 2
    assert faux_run == []


def test_mode_serveur_par_defaut(faux_run):
    assert commande.main(["--server"]) == 0
    assert faux_run == [("server", {"host": "127.0.0.1", "port": 8000, "open_browser": True})]


def test_variables_host_et_port(faux_run, monkeypatch):
    monkeypatch.setenv("HOST", "::1")
    monkeypatch.setenv("PORT", "9123")
    assert commande.main(["--server"]) == 0
    mode, kwargs = faux_run[0]
    assert (mode, kwargs["host"], kwargs["port"]) == ("server", "::1", 9123)


def test_options_prioritaires_sur_l_environnement(faux_run, monkeypatch):
    monkeypatch.setenv("HOST", "0.0.0.0")
    monkeypatch.setenv("PORT", "9000")
    assert commande.main(["--server", "--host", "127.0.0.1", "--port", "8123"]) == 0
    kwargs = faux_run[0][1]
    assert (kwargs["host"], kwargs["port"]) == ("127.0.0.1", 8123)


def test_port_hors_plage_refuse(faux_run, capsys):
    assert commande.main(["--port", "70000"]) == 2
    assert faux_run == []
    assert "Port invalide" in capsys.readouterr().err


def test_exposition_reseau_signalee(faux_run, monkeypatch, capsys):
    monkeypatch.setattr(config, "API_TOKEN", None)
    monkeypatch.setattr(config, "ALLOWED_HOSTS", ["localhost", "127.0.0.1", "::1"])
    assert commande.main(["--server", "--host", "0.0.0.0"]) == 0
    err = capsys.readouterr().err
    assert "joignable depuis le réseau" in err
    assert "API_TOKEN" in err
    assert "ALLOWED_HOSTS" in err


def test_ctrl_c_en_mode_serveur_rend_0(monkeypatch, capsys):
    """uvicorn rejoue SIGINT après l'arrêt propre : code 0 et pas de traceback."""
    import uvicorn

    class ServeurInterrompu:
        def __init__(self, config):
            pass

        def run(self):
            raise KeyboardInterrupt

    for nom in _VARIABLES:
        monkeypatch.delenv(nom, raising=False)
    monkeypatch.setattr(launcher, "_uvicorn_config", lambda host, port: None)
    monkeypatch.setattr(uvicorn, "Server", ServeurInterrompu)
    assert commande.main(["--server"]) == 0
    assert "Traceback" not in capsys.readouterr().err


def test_pas_d_avertissement_en_local(faux_run, capsys):
    assert commande.main([]) == 0
    assert "joignable depuis le réseau" not in capsys.readouterr().err


def test_fichier_env_illisible_message_clair(faux_run, monkeypatch, capsys):
    """Un .env mal encodé : message lisible, pas de traceback, pas de serveur."""

    def illisible():
        raise RuntimeError("Fichier .env illisible : enregistrez-le en UTF-8 (octet invalide en position 0).")

    monkeypatch.setattr(commande, "_load_config", illisible)
    assert commande.main([]) == 1
    assert faux_run == []
    assert "[!] Fichier .env illisible" in capsys.readouterr().err


def test_version_de_python_trop_ancienne(faux_run, monkeypatch, capsys):
    monkeypatch.setattr(commande, "MIN_PYTHON", (99, 0))
    assert commande.main([]) == 1
    assert faux_run == []
    assert "99.0" in capsys.readouterr().err


def test_sortie_redirigee_non_utf8_ne_plante_pas(tmp_path):
    """Sortie en ASCII strict (cas cp1252 sous Windows) : aucune UnicodeEncodeError."""
    faux = tmp_path / "faux"
    faux.mkdir()
    (faux / "uvicorn.py").write_text(
        textwrap.dedent(
            """
            class Config:
                def __init__(self, app, **kwargs):
                    self.kwargs = kwargs


            class Server:
                def __init__(self, config):
                    self.config = config

                def run(self):
                    print("FAKE-RUN host=%s port=%s" % (self.config.kwargs["host"], self.config.kwargs["port"]))
            """
        ),
        encoding="utf-8",
    )
    env = {
        k: v
        for k, v in os.environ.items()
        if k not in _VARIABLES and k not in ("PYTHONIOENCODING", "PYTHONUTF8")
    }
    env.update(
        {
            "PYTHONPATH": os.pathsep.join([str(faux), str(ROOT)]),
            "PYTHONIOENCODING": "ascii",  # erreurs strictes
            "PYTHONUTF8": "0",
            "API_TOKEN": "",
        }
    )
    # --host 0.0.0.0 : déclenche aussi les avertissements accentués.
    result = subprocess.run(
        [sys.executable, "-m", "domainrecon", "--server", "--host", "0.0.0.0", "--port", "8123"],
        cwd=tmp_path,
        env=env,
        capture_output=True,
        timeout=120,
    )
    sortie = result.stdout.decode("ascii", "replace") + result.stderr.decode("ascii", "replace")
    assert result.returncode == 0, sortie
    assert "UnicodeEncodeError" not in sortie
    assert "FAKE-RUN host=0.0.0.0 port=8123" in sortie
    assert "joignable depuis le r?seau" in sortie


@pytest.mark.parametrize("mode", [["--browser"], []], ids=["navigateur", "fenetre"])
def test_hote_du_reseau_autorise_en_mode_navigateur_ou_fenetre(faux_run, monkeypatch, capsys, mode):
    """Revue finale M4 : `--host <IP>` ouvre cette adresse, dont l'en-tête Host doit passer le contrôle."""
    monkeypatch.setattr(config, "API_TOKEN", None)
    monkeypatch.setattr(config, "ALLOWED_HOSTS", ["localhost", "127.0.0.1", "::1"])
    assert commande.main([*mode, "--host", "192.168.1.10"]) == 0
    assert config.ALLOWED_HOSTS == ["localhost", "127.0.0.1", "::1", "192.168.1.10"]
    err = capsys.readouterr().err
    assert "joignable depuis le réseau" in err  # l'avertissement reste donné
    assert "192.168.1.10" in err  # et cite la liste effective


def test_hote_du_reseau_non_ajoute_en_mode_serveur(faux_run, monkeypatch):
    """Mode serveur : l'application n'ouvre rien elle-même, ALLOWED_HOSTS reste le choix de l'utilisateur."""
    monkeypatch.setattr(config, "ALLOWED_HOSTS", ["localhost", "127.0.0.1", "::1"])
    assert commande.main(["--server", "--host", "192.168.1.10"]) == 0
    assert config.ALLOWED_HOSTS == ["localhost", "127.0.0.1", "::1"]


@pytest.fixture
def sans_console(monkeypatch):
    """Exécutable fenêtré : la boîte de message native est un faux qui note ses appels."""
    boites = []
    monkeypatch.setattr(launcher, "_console_absent", True)
    monkeypatch.setattr(launcher, "_log_file", None)
    monkeypatch.setattr(
        launcher, "show_message_box", lambda texte, titre="", error=False: boites.append(texte)
    )
    return boites


def test_fichier_env_illisible_affiche_dans_une_boite_sans_console(
    faux_run, sans_console, monkeypatch, capsys
):
    """Revue finale M3 : double-clic sur DomainRecon.exe avec un .env en ANSI = une boîte, pas le silence."""

    def illisible():
        raise RuntimeError("Fichier .env illisible : enregistrez-le en UTF-8 (octet invalide en position 0).")

    monkeypatch.setattr(commande, "_load_config", illisible)
    assert commande.main([]) == 1
    assert faux_run == []
    assert sans_console == [
        "Fichier .env illisible : enregistrez-le en UTF-8 (octet invalide en position 0)."
    ]
    assert "[!] Fichier .env illisible" in capsys.readouterr().err


def test_configuration_impossible_a_charger_message_et_boite(faux_run, sans_console, monkeypatch, capsys):
    def impossible():
        raise PermissionError(13, "Permission denied", "D:/Programmes/DomainRecon/data")

    monkeypatch.setattr(commande, "_load_config", impossible)
    assert commande.main([]) == 1
    assert faux_run == []
    (texte,) = sans_console
    assert texte.startswith("Démarrage impossible : PermissionError : [Errno 13] Permission denied")
    assert "[!] Démarrage impossible" in capsys.readouterr().err
