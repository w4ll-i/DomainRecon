# =============================================================================
# DomainRecon - Tests du lanceur (desktop/launcher.py)
# =============================================================================
# pywebview, le navigateur et, pour run(), le serveur sont simulés ; un vrai
# serveur uvicorn est démarré sur un port libre de 127.0.0.1 pour le test de
# bout en bout.
# =============================================================================

import asyncio
import http.client
import http.server
import json
import logging
import os
import socket
import sys
import threading
import time
import types
import urllib.request
from pathlib import Path

import pytest

from domainrecon.core import config
from domainrecon.desktop import launcher

# Vraie fonction, gardée avant que la fixture ci-dessous ne la remplace : un test qui
# laisserait appeler os._exit terminerait pytest.
_HARD_EXIT_REEL = launcher._hard_exit


@pytest.fixture(autouse=True)
def sortie_forcee(monkeypatch):
    """Remplace launcher._hard_exit dans tout le module : liste des codes de sortie demandés."""
    appels = []
    monkeypatch.setattr(launcher, "_hard_exit", appels.append)
    return appels


# --- Adresses (tests portés de l'ancien run.py) ------------------------------


@pytest.mark.parametrize(
    ("host", "expected"),
    [
        ("127.0.0.1", "http://127.0.0.1:8000"),
        ("0.0.0.0", "http://127.0.0.1:8000"),
        ("", "http://127.0.0.1:8000"),
        ("::", "http://[::1]:8000"),
        ("::1", "http://[::1]:8000"),
        ("192.168.1.20", "http://192.168.1.20:8000"),
        ("localhost", "http://localhost:8000"),
    ],
)
def test_browser_url_pointe_vers_l_adresse_reelle(host, expected):
    assert launcher.browser_url(host, 8000) == expected


@pytest.mark.parametrize(
    ("host", "expected"),
    [
        ("127.0.0.1", True),
        ("127.0.0.2", True),
        ("::1", True),
        ("localhost", True),
        ("LOCALHOST", True),
        ("0.0.0.0", False),
        ("::", False),
        ("192.168.1.20", False),
        ("mon-poste.lan", False),
    ],
)
def test_is_loopback(host, expected):
    assert launcher.is_loopback(host) is expected


@pytest.mark.parametrize(
    ("platform", "expected"), [("win32", "none"), ("linux", "auto"), ("darwin", "auto"), ("cygwin", "auto")]
)
def test_server_loop(monkeypatch, platform, expected):
    monkeypatch.setattr(launcher.sys, "platform", platform)
    assert launcher.server_loop() == expected


def test_port_libre():
    port = launcher.find_free_port()
    assert 1 <= port <= 65535
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", port))


# --- Flux standard absents (exécutable fenêtré) --------------------------------


def test_flux_absents_rediriges_vers_un_journal(monkeypatch, tmp_path):
    """Review Focus n° 1 : DomainRecon.exe (fenêtré) démarre sans sys.stdout ni sys.stderr."""
    monkeypatch.setenv("DATA_DIR", str(tmp_path))
    monkeypatch.setattr(sys, "stdout", None)
    monkeypatch.setattr(sys, "stderr", None)
    monkeypatch.setattr(launcher, "_console_absent", False)  # remis à sa valeur à la fin du test
    monkeypatch.setattr(launcher, "_log_file", None)
    journal = launcher.ensure_std_streams()
    try:
        assert journal == tmp_path / "logs" / "domainrecon.log"
        assert launcher._log_file == journal  # citée par la boîte d'erreur de démarrage
        assert launcher._console_absent is True
        assert sys.stdout.isatty() is False  # uvicorn l'appelle au démarrage
        print("démarrage", file=sys.stderr)
        sys.stderr.flush()
        assert "démarrage" in journal.read_text(encoding="utf-8")
    finally:
        sys.stdout.close()


def test_flux_absents_dossier_de_donnees_inscriptible_impossible(monkeypatch, tmp_path):
    """Dossier de données inutilisable : repli sur os.devnull, jamais d'exception."""
    fichier = tmp_path / "pas-un-dossier"
    fichier.write_text("", encoding="utf-8")
    monkeypatch.setenv("DATA_DIR", str(fichier))  # <données>/logs ne peut pas être créé
    monkeypatch.setattr(sys, "stdout", None)
    monkeypatch.setattr(sys, "stderr", None)
    monkeypatch.setattr(launcher, "_console_absent", False)
    monkeypatch.setattr(launcher, "_log_file", None)
    journal = launcher.ensure_std_streams()
    try:
        assert journal == Path(os.devnull)
        assert launcher._log_file is None  # os.devnull n'est pas un journal à citer
        assert sys.stdout is not None and sys.stderr is not None
        print("démarrage", file=sys.stderr)  # sans erreur
        sys.stderr.flush()
    finally:
        sys.stdout.close()


def test_flux_presents_inchanges(monkeypatch):
    monkeypatch.setattr(launcher, "_console_absent", False)
    assert launcher.ensure_std_streams() is None
    assert launcher._console_absent is False


# --- Fenêtre native -----------------------------------------------------------


@pytest.fixture
def faux_webview(monkeypatch):
    appels = {}
    module = types.ModuleType("webview")

    def create_window(title, url, **kwargs):
        appels["fenetre"] = (title, url, kwargs)

    def start(**kwargs):
        appels["start"] = kwargs

    module.create_window = create_window
    module.start = start
    # Réglages globaux de pywebview (dictionnaire module.settings en 6.x).
    module.settings = {"ALLOW_DOWNLOADS": False}
    appels["settings"] = module.settings
    monkeypatch.setitem(sys.modules, "webview", module)
    monkeypatch.setattr(launcher, "webview2_available", lambda: True)
    return appels


def test_fenetre_native_parametres_et_stockage_persistant(faux_webview, monkeypatch, tmp_path):
    """Review Focus n° 4 : sans private_mode=False, la langue choisie est perdue à chaque lancement."""
    monkeypatch.setenv("DATA_DIR", str(tmp_path))
    assert launcher.open_window("http://127.0.0.1:5000") is True
    titre, url, options = faux_webview["fenetre"]
    assert (titre, url) == ("DomainRecon", "http://127.0.0.1:5000")
    assert (options["width"], options["height"], options["min_size"]) == (1280, 820, (960, 640))
    assert faux_webview["start"]["private_mode"] is False
    assert faux_webview["start"]["storage_path"] == str(tmp_path / "webview")
    assert (tmp_path / "webview").is_dir()
    # Exports PDF / JSON de l'interface (lien blob: + download) : refusés par défaut par pywebview.
    assert faux_webview["settings"]["ALLOW_DOWNLOADS"] is True


def test_fenetre_indisponible_si_le_moteur_manque(faux_webview, monkeypatch):
    def echec(**kwargs):
        raise RuntimeError("You must have either QT or GTK with Python extensions installed")

    monkeypatch.setattr(sys.modules["webview"], "start", echec)
    assert launcher.open_window("http://127.0.0.1:5000") is False


def test_fenetre_indisponible_sans_webview2(faux_webview, monkeypatch):
    monkeypatch.setattr(launcher, "webview2_available", lambda: False)
    assert launcher.open_window("http://127.0.0.1:5000") is False
    assert "fenetre" not in faux_webview


def test_fenetre_indisponible_sans_pywebview(monkeypatch):
    monkeypatch.setitem(sys.modules, "webview", None)  # import webview → ImportError
    monkeypatch.setattr(launcher, "webview2_available", lambda: True)
    assert launcher.open_window("http://127.0.0.1:5000") is False


def test_detection_de_webview2(monkeypatch):
    monkeypatch.setattr(launcher.sys, "platform", "win32")
    monkeypatch.setattr(launcher, "_webview2_version", lambda: "129.0.2792.65")
    assert launcher.webview2_available() is True
    monkeypatch.setattr(launcher, "_webview2_version", lambda: None)
    assert launcher.webview2_available() is False
    monkeypatch.setattr(launcher.sys, "platform", "linux")
    assert launcher.webview2_available() is True


# --- Attente et serveur réel -----------------------------------------------------


def _serveur_de_sante(status: int) -> http.server.ThreadingHTTPServer:
    class Sante(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            self.send_response(status)
            self.end_headers()

        def log_message(self, *args):
            pass

    serveur = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Sante)
    threading.Thread(target=serveur.serve_forever, daemon=True).start()
    return serveur


def test_attente_du_serveur_sans_proxy(monkeypatch):
    # Un proxy d'entreprise ne doit jamais intercepter 127.0.0.1.
    for nom in ("HTTP_PROXY", "http_proxy", "ALL_PROXY", "all_proxy"):
        monkeypatch.setenv(nom, "http://127.0.0.1:9")
    for nom in ("NO_PROXY", "no_proxy"):
        monkeypatch.setenv(nom, "")
    for status in (200, 503):  # base en lecture seule : le serveur répond quand même
        serveur = _serveur_de_sante(status)
        try:
            url = f"http://127.0.0.1:{serveur.server_address[1]}"
            assert launcher.wait_until_healthy(url, timeout=5) is True
        finally:
            serveur.shutdown()
            serveur.server_close()


def test_attente_du_serveur_expire():
    port = launcher.find_free_port()
    assert launcher.wait_until_healthy(f"http://127.0.0.1:{port}", timeout=0.5) is False


def test_attente_abandonnee_des_que_le_serveur_est_mort():
    """Serveur lancé mort (port occupé…) : échec immédiat, sans attendre le délai."""
    port = launcher.find_free_port()
    debut = time.monotonic()
    assert launcher.wait_until_healthy(f"http://127.0.0.1:{port}", timeout=20, alive=lambda: False) is False
    assert time.monotonic() - debut < 2


def test_reponse_d_un_autre_service_refusee_si_le_serveur_est_mort():
    """--port déjà pris par un autre service : sa réponse HTTP n'est pas celle de DomainRecon."""
    autre = _serveur_de_sante(200)
    try:
        url = f"http://127.0.0.1:{autre.server_address[1]}"
        assert launcher.wait_until_healthy(url, timeout=5, alive=lambda: False) is False
        assert launcher.wait_until_healthy(url, timeout=5, alive=lambda: True) is True
    finally:
        autre.shutdown()
        autre.server_close()


# --- Port de l'application ---------------------------------------------------------


def test_port_prefere_libre_est_utilise(monkeypatch):
    monkeypatch.setattr(launcher, "PREFERRED_APP_PORT", launcher.find_free_port())
    assert launcher.choose_app_port("127.0.0.1") == launcher.PREFERRED_APP_PORT


def test_port_prefere_occupe_repli_sur_un_port_libre(monkeypatch):
    with socket.socket() as occupant:
        occupant.bind(("127.0.0.1", 0))
        occupant.listen()
        monkeypatch.setattr(launcher, "PREFERRED_APP_PORT", occupant.getsockname()[1])
        assert launcher.is_port_free("127.0.0.1", launcher.PREFERRED_APP_PORT) is False
        port = launcher.choose_app_port("127.0.0.1")
    assert port != launcher.PREFERRED_APP_PORT
    assert 1 <= port <= 65535


def test_port_prefere_par_defaut():
    assert launcher.PREFERRED_APP_PORT == 47815


def test_serveur_reel_demarre_repond_et_s_arrete():
    port = launcher.find_free_port()
    handle = launcher.start_server("127.0.0.1", port)
    try:
        assert handle.url == f"http://127.0.0.1:{port}"
        assert launcher.wait_until_healthy(handle.url, timeout=20) is True
        ouvreur = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        with ouvreur.open(f"{handle.url}/api/health", timeout=5) as reponse:
            assert json.load(reponse)["api"] == "healthy"
    finally:
        handle.stop()
    assert handle.is_alive() is False


def test_configuration_uvicorn_sans_confiance_dans_les_en_tetes_de_proxy():
    """X-Forwarded-For ne doit pas pouvoir falsifier request.client.host.

    POST /api/system/open-data-dir juge « machine locale » sur cette adresse :
    avec proxy_headers actif (le défaut d'uvicorn pour 127.0.0.1), un client
    distant derrière une redirection locale pourrait se faire passer pour elle.
    """
    config = launcher._uvicorn_config("127.0.0.1", 8123)
    assert config.proxy_headers is False
    assert (config.host, config.port) == ("127.0.0.1", 8123)
    # Pas de rechargement automatique, quel que soit le mode.
    assert config.reload is False


def test_arret_du_serveur_avec_un_flux_sse_ouvert(monkeypatch):
    """Un flux GET /api/scans/{id}/events ouvert ne doit pas bloquer l'arrêt du serveur."""
    from domainrecon.api.app import app
    from domainrecon.api.jobs import JobManager
    from domainrecon.api.routes import jobs as jobs_routes

    async def resoudre(host):
        return ["93.184.216.34"]

    async def scan_bloque(domain, on_module, **plan):
        on_module("dns_records", "ok", 0.01)
        await asyncio.Event().wait()  # le scan ne se termine jamais : le flux reste ouvert

    monkeypatch.setattr(jobs_routes, "ensure_target_allowed", resoudre)
    gestionnaire = JobManager(2, runner=scan_bloque)
    app.dependency_overrides[jobs_routes.get_job_manager] = lambda: gestionnaire

    port = launcher.find_free_port()
    handle = launcher.start_server("127.0.0.1", port)
    flux = lancement = None
    try:
        assert launcher.wait_until_healthy(handle.url, timeout=20) is True
        lancement = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
        lancement.request(
            "POST",
            "/api/scans",
            body='{"domain": "example.com"}',
            headers={"Content-Type": "application/json"},
        )
        reponse = lancement.getresponse()
        assert reponse.status == 202
        job_id = json.loads(reponse.read())["id"]

        flux = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
        flux.request("GET", f"/api/scans/{job_id}/events")
        reponse = flux.getresponse()
        assert reponse.status == 200
        assert reponse.readline().startswith(b"event:")  # le flux est bien ouvert

        debut = time.monotonic()
        handle.stop()
        duree = time.monotonic() - debut
    finally:
        app.dependency_overrides.pop(jobs_routes.get_job_manager, None)
        for connexion in (flux, lancement):
            if connexion is not None:
                connexion.close()
        handle.stop()
    assert handle.is_alive() is False
    assert duree < launcher.STOP_TIMEOUT


# --- run() : choix du mode, repli, arrêt ---------------------------------------


class FausseInstance:
    def __init__(self, url: str) -> None:
        self.url = url
        self.arretee = False
        self.arret_reussi = True  # False : le thread du serveur tourne encore après STOP_TIMEOUT

    def is_alive(self) -> bool:
        return False

    def stop(self) -> bool:
        self.arretee = True
        return self.arret_reussi


@pytest.fixture
def faux_serveur(monkeypatch):
    etat = {"ouvertures": [], "instances": []}

    def demarrer(host, port):
        instance = FausseInstance(launcher.browser_url(host, port))
        etat["instances"].append(instance)
        return instance

    monkeypatch.setattr(launcher, "start_server", demarrer)
    monkeypatch.setattr(launcher, "wait_until_healthy", lambda url, timeout=20.0, alive=None: True)
    monkeypatch.setattr(launcher.webbrowser, "open", etat["ouvertures"].append)
    # Port préféré pris : repli sur le port libre simulé (5123).
    monkeypatch.setattr(launcher, "is_port_free", lambda host, port: False)
    monkeypatch.setattr(launcher, "find_free_port", lambda host="127.0.0.1": 5123)
    monkeypatch.setattr(launcher, "_console_absent", False)
    return etat


def test_mode_fenetre(faux_serveur, monkeypatch):
    fenetres = []
    monkeypatch.setattr(launcher, "open_window", lambda url: fenetres.append(url) or True)
    assert launcher.run("window") == 0
    assert fenetres == ["http://127.0.0.1:5123"]
    assert faux_serveur["ouvertures"] == []
    # Fermer la fenêtre arrête le serveur.
    assert faux_serveur["instances"][0].arretee is True


def test_mode_fenetre_repli_sur_le_navigateur(faux_serveur, monkeypatch, capsys):
    monkeypatch.setattr(launcher, "open_window", lambda url: False)
    assert launcher.run("window") == 0
    assert faux_serveur["ouvertures"] == ["http://127.0.0.1:5123"]
    assert "navigateur" in capsys.readouterr().out
    assert faux_serveur["instances"][0].arretee is True


def test_mode_navigateur_ouvre_l_url(faux_serveur, capsys):
    assert launcher.run("browser", port=8123) == 0
    assert faux_serveur["ouvertures"] == ["http://127.0.0.1:8123"]
    sortie = capsys.readouterr().out
    assert "http://127.0.0.1:8123" in sortie
    assert "Fermez cette fenêtre" in sortie


def test_mode_navigateur_sans_ouverture(faux_serveur):
    assert launcher.run("browser", open_browser=False) == 0
    assert faux_serveur["ouvertures"] == []


def test_serveur_qui_ne_demarre_pas(faux_serveur, monkeypatch, capsys):
    monkeypatch.setattr(launcher, "wait_until_healthy", lambda url, timeout=20.0, alive=None: False)
    assert launcher.run("browser") == 1
    assert faux_serveur["instances"][0].arretee is True
    assert "n'a pas démarré" in capsys.readouterr().err


def test_l_attente_du_serveur_surveille_son_thread(faux_serveur, monkeypatch):
    recu = {}

    def attendre(url, timeout=20.0, alive=None):
        recu["alive"] = alive
        return True

    monkeypatch.setattr(launcher, "wait_until_healthy", attendre)
    assert launcher.run("browser", open_browser=False) == 0
    assert recu["alive"] == faux_serveur["instances"][0].is_alive


def test_port_prefere_libre_utilise_par_run(faux_serveur, monkeypatch):
    monkeypatch.setattr(launcher, "is_port_free", lambda host, port: True)
    assert launcher.run("browser") == 0
    assert faux_serveur["ouvertures"] == [f"http://127.0.0.1:{launcher.PREFERRED_APP_PORT}"]


def test_port_explicite_inchange(faux_serveur, monkeypatch):
    monkeypatch.setattr(launcher, "is_port_free", lambda host, port: True)
    assert launcher.run("browser", port=8123) == 0
    assert faux_serveur["ouvertures"] == ["http://127.0.0.1:8123"]


def test_mode_serveur_au_premier_plan(monkeypatch):
    lances = []
    monkeypatch.setattr(launcher, "serve_blocking", lambda host, port: lances.append((host, port)))
    assert launcher.run("server", host="0.0.0.0", port=0) == 0
    assert lances == [("0.0.0.0", 8000)]


def test_ctrl_c_en_mode_serveur_sort_proprement(monkeypatch):
    """uvicorn rejoue SIGINT après l'arrêt propre : KeyboardInterrupt ne doit pas remonter."""
    import uvicorn

    class ServeurInterrompu:
        def __init__(self, config):
            pass

        def run(self):
            raise KeyboardInterrupt

    monkeypatch.setattr(launcher, "_uvicorn_config", lambda host, port: None)
    monkeypatch.setattr(uvicorn, "Server", ServeurInterrompu)
    launcher.serve_blocking("127.0.0.1", 8123)  # sans exception
    assert launcher.run("server", host="127.0.0.1", port=8123) == 0


# --- Exécutable sans console : boîte de message au lieu d'un serveur invisible ------


@pytest.fixture
def sans_console(monkeypatch):
    """Windows, exécutable fenêtré ; la boîte de message et l'attente sont des faux."""
    etat = {"boites": [], "erreurs": [], "attentes": 0, "reponse": True}

    def boite(texte, titre=launcher.WINDOW_TITLE, error=False):
        etat["boites"].append(texte)
        etat["erreurs"].append(error)
        return etat["reponse"]

    def attente(handle):
        etat["attentes"] += 1

    monkeypatch.setattr(launcher.sys, "platform", "win32")
    monkeypatch.setattr(launcher, "_console_absent", True)
    monkeypatch.setattr(launcher, "_log_file", None)
    monkeypatch.setattr(launcher, "show_message_box", boite)
    monkeypatch.setattr(launcher, "_wait_while_running", attente)
    return etat


def test_sans_console_repli_navigateur_boite_bloquante(faux_serveur, sans_console, monkeypatch):
    monkeypatch.setattr(launcher, "open_window", lambda url: False)
    assert launcher.run("window") == 0
    assert faux_serveur["ouvertures"] == ["http://127.0.0.1:5123"]
    assert len(sans_console["boites"]) == 1
    texte = sans_console["boites"][0]
    assert "WebView2" in texte
    assert "http://127.0.0.1:5123" in texte
    assert "OK pour arrêter DomainRecon" in texte
    assert sans_console["attentes"] == 0
    # La fermeture de la boîte arrête le serveur.
    assert faux_serveur["instances"][0].arretee is True


def test_sans_console_mode_navigateur_boite_bloquante(faux_serveur, sans_console):
    assert launcher.run("browser", open_browser=False) == 0
    assert len(sans_console["boites"]) == 1
    assert "WebView2" not in sans_console["boites"][0]
    assert sans_console["attentes"] == 0
    assert faux_serveur["instances"][0].arretee is True


def test_sans_console_fenetre_native_sans_boite(faux_serveur, sans_console, monkeypatch):
    monkeypatch.setattr(launcher, "open_window", lambda url: True)
    assert launcher.run("window") == 0
    assert sans_console["boites"] == []
    assert sans_console["attentes"] == 0


def test_sans_console_boite_indisponible_attente_habituelle(faux_serveur, sans_console, monkeypatch):
    sans_console["reponse"] = False
    monkeypatch.setattr(launcher, "open_window", lambda url: False)
    assert launcher.run("window") == 0
    assert sans_console["attentes"] == 1


def test_avec_console_comportement_inchange(faux_serveur, sans_console, monkeypatch):
    monkeypatch.setattr(launcher, "_console_absent", False)
    monkeypatch.setattr(launcher, "open_window", lambda url: False)
    assert launcher.run("window") == 0
    assert sans_console["boites"] == []
    assert sans_console["attentes"] == 1


def test_hors_windows_comportement_inchange(faux_serveur, sans_console, monkeypatch):
    monkeypatch.setattr(launcher.sys, "platform", "linux")
    monkeypatch.setattr(launcher, "open_window", lambda url: False)
    assert launcher.run("window") == 0
    assert sans_console["boites"] == []
    assert sans_console["attentes"] == 1


def test_boite_de_message_windows(monkeypatch):
    import ctypes

    appels = []

    def message_box(*args):
        appels.append(args)
        return 1  # IDOK

    faux = types.SimpleNamespace(user32=types.SimpleNamespace(MessageBoxW=message_box))
    monkeypatch.setattr(ctypes, "windll", faux, raising=False)
    assert launcher.show_message_box("Bonjour", "DomainRecon") is True
    # MB_OK | MB_ICONINFORMATION
    assert appels == [(None, "Bonjour", "DomainRecon", 0x40)]
    faux.user32.MessageBoxW = lambda *args: 0  # échec de l'API
    assert launcher.show_message_box("Bonjour") is False
    # Boîte d'erreur : MB_OK | MB_ICONERROR.
    faux.user32.MessageBoxW = message_box
    appels.clear()
    assert launcher.show_message_box("Échec", "DomainRecon", error=True) is True
    assert appels == [(None, "Échec", "DomainRecon", 0x10)]


def test_boite_de_message_indisponible(monkeypatch):
    import ctypes

    monkeypatch.delattr(ctypes, "windll", raising=False)  # hors Windows
    assert launcher.show_message_box("Bonjour") is False


def test_mode_inconnu():
    with pytest.raises(ValueError):
        launcher.run("kiosque")


# --- Revue finale : arrêt signalé, hôte ouvert autorisé, échecs de démarrage ---------------


def test_arret_signale_un_thread_encore_vivant(monkeypatch, caplog):
    """stop() ne reste pas muet quand le serveur ne s'arrête pas dans STOP_TIMEOUT."""
    liberer = threading.Event()
    thread = threading.Thread(target=liberer.wait, args=(10,), daemon=True)
    thread.start()
    serveur = types.SimpleNamespace(should_exit=False)
    handle = launcher.ServerHandle(url="http://127.0.0.1:1", _server=serveur, _thread=thread)
    monkeypatch.setattr(launcher, "STOP_TIMEOUT", 0.05)
    with caplog.at_level(logging.WARNING, logger=launcher.logger.name):
        assert handle.stop() is False
    assert serveur.should_exit is True
    assert "ne s'est pas arrêté" in caplog.text
    liberer.set()
    thread.join(timeout=5)
    caplog.clear()
    assert handle.stop() is True
    assert "ne s'est pas arrêté" not in caplog.text


@pytest.mark.parametrize("status", [400, 404, 500])
def test_attente_refuse_une_reponse_http_qui_n_est_pas_la_sante(status):
    """Un 400 (Host refusé) ou une page d'un autre service n'est pas un démarrage réussi : échec immédiat."""
    serveur = _serveur_de_sante(status)
    try:
        url = f"http://127.0.0.1:{serveur.server_address[1]}"
        debut = time.monotonic()
        assert launcher.wait_until_healthy(url, timeout=20) is False
        assert time.monotonic() - debut < 5
    finally:
        serveur.shutdown()
        serveur.server_close()


@pytest.mark.parametrize(
    ("hote", "ajoute"),
    [
        ("192.168.1.10", "192.168.1.10"),  # --host <IP du réseau> : l'URL ouverte porte cette adresse
        ("127.0.0.1", "127.0.0.1"),  # ALLOWED_HOSTS personnalisé sans localhost
        ("0.0.0.0", "127.0.0.1"),  # écoute partout, ouverture par 127.0.0.1
        ("::", "::1"),
        ("mon-poste.lan", "mon-poste.lan"),
    ],
)
def test_hote_ouvert_par_l_application_autorise(monkeypatch, hote, ajoute):
    liste = ["recon.example.com"]
    monkeypatch.setattr(config, "ALLOWED_HOSTS", liste)
    launcher.allow_app_host(hote)
    assert config.ALLOWED_HOSTS == ["recon.example.com", ajoute]
    assert liste == ["recon.example.com"]  # la liste d'origine n'est pas modifiée
    launcher.allow_app_host(hote)  # idempotent
    assert config.ALLOWED_HOSTS == ["recon.example.com", ajoute]


def test_hote_deja_autorise_ou_controle_desactive_inchange(monkeypatch):
    monkeypatch.setattr(config, "ALLOWED_HOSTS", ["localhost", "127.0.0.1", "::1"])
    launcher.allow_app_host("127.0.0.1")
    launcher.allow_app_host("LOCALHOST")
    launcher.allow_app_host("::")
    assert config.ALLOWED_HOSTS == ["localhost", "127.0.0.1", "::1"]
    monkeypatch.setattr(config, "ALLOWED_HOSTS", ["*"])
    launcher.allow_app_host("192.168.1.10")
    assert config.ALLOWED_HOSTS == ["*"]


def test_serveur_reel_hote_ouvert_par_l_application(monkeypatch):
    """ALLOWED_HOSTS sans 127.0.0.1 : sans allow_app_host la fenêtre verrait un 400, avec elle le serveur répond."""
    from domainrecon.api.app import app

    monkeypatch.setattr(config, "ALLOWED_HOSTS", ["recon.example.com"])
    monkeypatch.setattr(app, "middleware_stack", None)  # reconstruite avec la liste ci-dessus
    refuse = launcher.start_server("127.0.0.1", launcher.find_free_port())
    try:
        assert launcher.wait_until_healthy(refuse.url, timeout=20, alive=refuse.is_alive) is False
    finally:
        refuse.stop()

    launcher.allow_app_host("127.0.0.1")
    monkeypatch.setattr(app, "middleware_stack", None)
    handle = launcher.start_server("127.0.0.1", launcher.find_free_port())
    try:
        assert launcher.wait_until_healthy(handle.url, timeout=20, alive=handle.is_alive) is True
    finally:
        handle.stop()


def test_description_d_une_exception():
    assert launcher.describe_error(PermissionError(13, "Permission denied")) == (
        "PermissionError : [Errno 13] Permission denied"
    )
    assert launcher.describe_error(ValueError("ligne 1\nligne 2")) == "ValueError : ligne 1"
    assert launcher.describe_error(RuntimeError()) == "RuntimeError"


def test_serveur_impossible_a_demarrer_message_sans_traceback(faux_serveur, monkeypatch, capsys):
    """start_server lève (données en lecture seule…) : [!] et code 1, pas de traceback brut."""

    def echec(host, port):
        raise PermissionError(13, "Permission denied", "C:\\donnees")

    monkeypatch.setattr(launcher, "start_server", echec)
    assert launcher.run("browser") == 1
    err = capsys.readouterr().err
    assert err.startswith("[!] Le serveur local n'a pas pu démarrer : PermissionError")
    assert "Traceback" not in err
    assert faux_serveur["instances"] == []


def test_port_libre_introuvable_message_sans_traceback(faux_serveur, monkeypatch, capsys):
    """find_free_port (via choose_app_port) dans le try : adresse d'écoute impossible = message et code 1."""

    def echec(host="127.0.0.1"):
        raise OSError("[Errno 11001] getaddrinfo failed")

    monkeypatch.setattr(launcher, "find_free_port", echec)
    assert launcher.run("window", host="hote-inconnu") == 1
    err = capsys.readouterr().err
    assert "[!] Le serveur local n'a pas pu démarrer : OSError : [Errno 11001] getaddrinfo failed" in err
    assert "Traceback" not in err


def test_mode_serveur_echec_au_demarrage_message_sans_traceback(monkeypatch, capsys):
    def echec(host, port):
        raise PermissionError(13, "Permission denied", "C:\\donnees")

    monkeypatch.setattr(launcher, "serve_blocking", echec)
    monkeypatch.setattr(launcher, "_console_absent", False)
    assert launcher.run("server", port=8123) == 1
    err = capsys.readouterr().err
    assert "[!] Le serveur n'a pas pu démarrer : PermissionError" in err
    assert "Traceback" not in err


def test_sans_console_echec_de_demarrage_dans_une_boite_d_erreur(
    faux_serveur, sans_console, monkeypatch, capsys
):
    """Revue finale M3 : DomainRecon.exe sans console affiche la cause, pas un échec silencieux."""

    def echec(host, port):
        raise PermissionError(13, "Permission denied", "C:\\donnees")

    monkeypatch.setattr(launcher, "start_server", echec)
    monkeypatch.setattr(launcher, "_log_file", Path("C:/donnees/logs/domainrecon.log"))
    assert launcher.run("window") == 1
    (texte,) = sans_console["boites"]
    assert "Le serveur local n'a pas pu démarrer : PermissionError" in texte
    assert "Permission denied" in texte
    assert "domainrecon.log" in texte  # où chercher le détail
    assert sans_console["erreurs"] == [True]  # icône d'erreur
    err = capsys.readouterr().err
    assert "[!] Le serveur local n'a pas pu démarrer" in err
    assert "Traceback" in err  # la trace va au journal (stderr redirigé), pas dans la boîte
    assert "Traceback" not in texte


def test_avec_console_pas_de_boite_pour_un_echec_de_demarrage(faux_serveur, sans_console, monkeypatch):
    monkeypatch.setattr(launcher, "_console_absent", False)
    monkeypatch.setattr(launcher, "start_server", lambda host, port: 1 / 0)
    assert launcher.run("window") == 1
    assert sans_console["boites"] == []


def test_sans_console_serveur_mort_au_demarrage_affiche_la_cause(
    faux_serveur, sans_console, monkeypatch, capsys
):
    """Base illisible, schéma à migrer : uvicorn arrête son thread, la cause notée par le lifespan est affichée."""
    from domainrecon.api.app import app
    from domainrecon.core.database import SchemaMigrationError

    monkeypatch.setattr(launcher, "wait_until_healthy", lambda url, timeout=20.0, alive=None: False)
    erreur = SchemaMigrationError("La colonne scans.x est obligatoire : migration manuelle requise.\nSuite")
    monkeypatch.setattr(app.state, "startup_error", erreur, raising=False)
    assert launcher.run("window") == 1
    (texte,) = sans_console["boites"]
    assert (
        "Le serveur local n'a pas démarré : SchemaMigrationError : La colonne scans.x est obligatoire"
        in texte
    )
    assert "Suite" not in texte  # première ligne seulement
    assert sans_console["erreurs"] == [True]
    assert faux_serveur["instances"][0].arretee is True
    assert "n'a pas démarré : SchemaMigrationError" in capsys.readouterr().err


def test_serveur_mort_sans_cause_connue_renvoie_aux_journaux(faux_serveur, sans_console, monkeypatch):
    from domainrecon.api.app import app

    monkeypatch.setattr(launcher, "wait_until_healthy", lambda url, timeout=20.0, alive=None: False)
    monkeypatch.setattr(app.state, "startup_error", None, raising=False)
    assert launcher.run("browser") == 1
    (texte,) = sans_console["boites"]
    assert texte == "Le serveur local n'a pas démarré (voir les journaux)."


# --- Arrêt forcé du processus quand le serveur ne s'arrête pas (revue finale M2) ----------


@pytest.fixture
def serveur_qui_ne_s_arrete_pas(faux_serveur, monkeypatch):
    """Le faux serveur ne s'arrête pas dans STOP_TIMEOUT : stop() renvoie False."""
    demarrer = launcher.start_server

    def demarrer_bloque(host, port):
        instance = demarrer(host, port)
        instance.arret_reussi = False
        return instance

    monkeypatch.setattr(launcher, "start_server", demarrer_bloque)
    return faux_serveur


def test_arret_force_si_le_serveur_ne_s_arrete_pas(serveur_qui_ne_s_arrete_pas, monkeypatch, sortie_forcee):
    """Fenêtre fermée, mais un module bloqué dans un thread : le processus est terminé de force."""
    monkeypatch.setattr(launcher, "open_window", lambda url: True)
    assert launcher.run("window") == 0
    assert serveur_qui_ne_s_arrete_pas["instances"][0].arretee is True
    assert sortie_forcee == [0]


@pytest.mark.parametrize("mode", ["window", "browser"])
def test_arret_propre_pas_d_arret_force(faux_serveur, monkeypatch, sortie_forcee, mode):
    monkeypatch.setattr(launcher, "open_window", lambda url: True)
    assert launcher.run(mode, open_browser=False) == 0
    assert faux_serveur["instances"][0].arret_reussi is True
    assert sortie_forcee == []


def test_arret_force_apres_la_boite_ok_sans_console(serveur_qui_ne_s_arrete_pas, sans_console, sortie_forcee):
    """Sans console : la boîte « OK pour arrêter » est fermée, le serveur ne s'arrête pas -> arrêt forcé."""
    assert launcher.run("browser", open_browser=False) == 0
    assert len(sans_console["boites"]) == 1
    assert sortie_forcee == [0]


def test_arret_force_garde_le_code_d_echec(serveur_qui_ne_s_arrete_pas, monkeypatch, sortie_forcee):
    """Le serveur n'a pas démarré et ne s'arrête pas : le code de sortie reste 1."""
    monkeypatch.setattr(launcher, "wait_until_healthy", lambda url, timeout=20.0, alive=None: False)
    assert launcher.run("browser") == 1
    assert sortie_forcee == [1]


def test_jamais_d_arret_force_en_mode_serveur(monkeypatch, sortie_forcee):
    monkeypatch.setattr(launcher, "serve_blocking", lambda host, port: None)
    assert launcher.run("server", port=8123) == 0
    assert sortie_forcee == []


def test_sortie_forcee_vide_les_flux_et_les_journaux(monkeypatch, caplog):
    """_hard_exit : avertissement, flux vidés, journaux fermés, puis os._exit(code)."""
    evenements = []

    class Flux:
        def __init__(self, nom):
            self.nom = nom

        def flush(self):
            evenements.append(f"flush {self.nom}")

    class FluxFerme:
        def flush(self):
            raise ValueError("I/O operation on closed file")

    monkeypatch.setattr(sys, "stdout", Flux("stdout"))
    monkeypatch.setattr(sys, "stderr", FluxFerme())  # un flux fermé n'empêche pas la sortie
    monkeypatch.setattr(launcher.logging, "shutdown", lambda: evenements.append("logging.shutdown"))
    monkeypatch.setattr(launcher.os, "_exit", lambda code: evenements.append(f"_exit {code}"))
    with caplog.at_level(logging.WARNING, logger=launcher.logger.name):
        _HARD_EXIT_REEL(3)
    assert evenements == ["flush stdout", "logging.shutdown", "_exit 3"]
    assert "Arrêt forcé du processus" in caplog.text


def test_icone_de_fenetre_absente_sous_windows(monkeypatch, tmp_path):
    # WinForms refuse un PNG comme icône de fenêtre (ArgumentException « picture »).
    (tmp_path / "desktop").mkdir()
    (tmp_path / "desktop" / "icon.png").write_bytes(b"fausse icone")
    monkeypatch.setattr(launcher.paths, "package_dir", lambda: tmp_path)
    monkeypatch.setattr(launcher.sys, "platform", "win32")
    assert launcher._icon_path() is None
    monkeypatch.setattr(launcher.sys, "platform", "linux")
    assert launcher._icon_path() == str(tmp_path / "desktop" / "icon.png")


# --- Arrêt automatique du mode navigateur (IdleWatchdog) -------------------------------


class Horloge:
    """Horloge monotone simulée."""

    def __init__(self) -> None:
        self.t = 1000.0

    def __call__(self) -> float:
        return self.t


class ServeurVivant:
    """Serveur simulé qui tourne jusqu'à stop() ; arret_reussi=False : thread encore vivant après STOP_TIMEOUT."""

    def __init__(self, arret_reussi: bool = True) -> None:
        self.vivant = True
        self.arrets = 0
        self.arret_reussi = arret_reussi

    def is_alive(self) -> bool:
        return self.vivant

    def stop(self) -> bool:
        self.arrets += 1
        self.vivant = not self.arret_reussi
        return self.arret_reussi


@pytest.fixture
def veille():
    """Chien de garde sur une horloge simulée ; `etat` : dernier battement, dernière requête de l'API, scan en cours."""
    horloge = Horloge()
    etat = {"battement": None, "activite": None, "scan": False}
    chien = launcher.IdleWatchdog(
        ServeurVivant(),
        lambda: etat["battement"],
        lambda: etat["scan"],
        clock=horloge,
        last_activity=lambda: etat["activite"],
    )

    def avancer(secondes: float) -> bool:
        """Une vérification toutes les IDLE_CHECK_INTERVAL s pendant `secondes` : True dès que l'arrêt est dû."""
        for _ in range(round(secondes / launcher.IDLE_CHECK_INTERVAL)):
            horloge.t += launcher.IDLE_CHECK_INTERVAL
            if chien.due():
                return True
        return False

    def battre() -> None:
        etat["battement"] = horloge.t

    def requete() -> None:
        etat["activite"] = horloge.t

    return types.SimpleNamespace(
        chien=chien, horloge=horloge, etat=etat, avancer=avancer, battre=battre, requete=requete
    )


def test_veille_arret_deux_minutes_apres_le_dernier_battement(veille):
    assert launcher.IDLE_SHUTDOWN == 120
    assert veille.avancer(30) is False
    veille.battre()
    assert veille.avancer(60) is False
    veille.battre()  # onglet toujours ouvert
    assert veille.avancer(115) is False
    assert veille.avancer(5) is True


def test_veille_pas_d_arret_pendant_un_scan(veille):
    veille.battre()
    veille.etat["scan"] = True
    assert veille.avancer(900) is False
    veille.etat["scan"] = False
    assert veille.avancer(5) is True


def test_veille_sans_aucun_battement_delai_initial(veille):
    """Navigateur qui ne s'est pas ouvert : pas d'arrêt avant IDLE_FIRST_HEARTBEAT, puis la même règle."""
    assert launcher.IDLE_FIRST_HEARTBEAT > launcher.IDLE_SHUTDOWN
    assert veille.avancer(launcher.IDLE_FIRST_HEARTBEAT - 5) is False
    veille.etat["scan"] = True
    assert veille.avancer(5) is False
    veille.etat["scan"] = False
    assert veille.avancer(5) is True


def test_veille_premier_battement_tardif(veille):
    assert veille.avancer(500) is False
    veille.battre()
    assert veille.avancer(115) is False
    assert veille.avancer(5) is True


def test_veille_sortie_de_veille_relance_le_delai(veille):
    """Machine en veille une heure : les onglets n'ont pas encore pu battre, pas d'arrêt au réveil."""
    veille.battre()
    veille.horloge.t += 3600
    assert veille.chien.due() is False
    assert veille.avancer(115) is False
    assert veille.avancer(5) is True


def test_veille_interface_sans_battement_jamais_d_arret(veille):
    """Revue : interface ancienne ou en cache (aucun battement) utilisée 10 min, arrêtée en pleine lecture.

    Des requêtes de l'API arrivent sans aucun battement : impossible de savoir
    quand cette interface se ferme, le serveur n'est jamais arrêté.
    """
    veille.requete()
    assert veille.avancer(launcher.IDLE_FIRST_HEARTBEAT * 3) is False
    # Un battement finit par arriver (interface rechargée) : la règle habituelle reprend.
    veille.battre()
    assert veille.avancer(115) is False
    assert veille.avancer(5) is True


def test_veille_requete_de_l_api_compte_comme_activite(veille):
    veille.battre()
    assert veille.avancer(100) is False
    veille.requete()  # client de l'API, ou onglet qui agit
    assert veille.avancer(115) is False
    assert veille.avancer(5) is True


@pytest.fixture
def durees_courtes(monkeypatch):
    monkeypatch.setattr(launcher, "IDLE_CHECK_INTERVAL", 0.01)
    monkeypatch.setattr(launcher, "IDLE_SHUTDOWN", 0.05)
    monkeypatch.setattr(launcher, "IDLE_FIRST_HEARTBEAT", 0.2)


def test_veille_arrete_le_serveur_apres_inactivite(durees_courtes, caplog, sortie_forcee):
    serveur = ServeurVivant()
    battement = time.monotonic()
    chien = launcher.IdleWatchdog(serveur, lambda: battement, lambda: False)
    with caplog.at_level(logging.INFO, logger=launcher.logger.name):
        chien.start()
        chien.thread.join(timeout=5)
    assert not chien.thread.is_alive()
    assert serveur.arrets == 1
    assert "Aucun onglet ouvert depuis" in caplog.text
    assert sortie_forcee == []


def test_veille_sans_battement_arrete_apres_le_delai_initial(durees_courtes):
    serveur = ServeurVivant()
    debut = time.monotonic()
    chien = launcher.IdleWatchdog(serveur, lambda: None, lambda: False)
    chien.start()
    chien.thread.join(timeout=5)
    assert serveur.arrets == 1
    assert time.monotonic() - debut >= launcher.IDLE_FIRST_HEARTBEAT


def test_veille_arret_force_si_le_serveur_ne_s_arrete_pas(durees_courtes, sortie_forcee):
    """Même chemin que Ctrl+C ou la boîte « OK » : stop(), puis _hard_exit s'il échoue."""
    serveur = ServeurVivant(arret_reussi=False)
    chien = launcher.IdleWatchdog(serveur, lambda: time.monotonic() - 1, lambda: False)
    chien.start()
    chien.thread.join(timeout=5)
    assert serveur.arrets == 1
    assert sortie_forcee == [0]


def test_veille_jamais_pendant_un_scan_ni_apres_annulation(durees_courtes):
    serveur = ServeurVivant()
    occupe = launcher.IdleWatchdog(serveur, lambda: time.monotonic() - 1, lambda: True)
    occupe.start()
    annule = launcher.IdleWatchdog(serveur, lambda: None, lambda: False)
    annule.start()
    annule.cancel()
    time.sleep(0.4)
    assert serveur.arrets == 0
    assert not annule.thread.is_alive()
    occupe.cancel()
    occupe.thread.join(timeout=5)
    assert not occupe.thread.is_alive()


def test_veille_s_arrete_avec_le_serveur(durees_courtes):
    serveur = ServeurVivant()
    serveur.vivant = False  # arrêté par un autre chemin (Ctrl+C, boîte « OK »)
    chien = launcher.IdleWatchdog(serveur, lambda: None, lambda: False)
    chien.start()
    chien.thread.join(timeout=5)
    assert not chien.thread.is_alive()
    assert serveur.arrets == 0


@pytest.mark.parametrize("console_absente", [True, False])
def test_veille_ferme_la_boite_ok_sans_console(durees_courtes, monkeypatch, console_absente):
    """Exécutable sans console : la boîte « OK » bloque le thread principal, elle est fermée comme par un clic."""
    fermetures = []
    monkeypatch.setattr(launcher.sys, "platform", "win32")
    monkeypatch.setattr(launcher, "_console_absent", console_absente)
    monkeypatch.setattr(launcher, "_box_thread", 4321)  # boîte affichée par ce thread
    monkeypatch.setattr(launcher, "close_message_box", lambda thread_id: fermetures.append(thread_id) or True)
    serveur = ServeurVivant()
    chien = launcher.IdleWatchdog(serveur, lambda: time.monotonic() - 1, lambda: False)
    chien.start()
    chien.thread.join(timeout=5)
    assert serveur.arrets == 1
    assert fermetures == ([4321] if console_absente else [])


def test_veille_boite_ok_impossible_a_fermer_fin_du_processus(
    durees_courtes, monkeypatch, sortie_forcee, caplog
):
    """Revue : boîte introuvable ou fermeture en échec, processus fantôme jusqu'au clic sur OK.

    Le serveur est déjà arrêté : il n'y a plus rien à perdre, le processus se termine.
    """
    monkeypatch.setattr(launcher.sys, "platform", "win32")
    monkeypatch.setattr(launcher, "_console_absent", True)
    monkeypatch.setattr(launcher, "_box_thread", 4321)
    monkeypatch.setattr(launcher, "close_message_box", lambda thread_id: False)
    serveur = ServeurVivant()
    chien = launcher.IdleWatchdog(serveur, lambda: time.monotonic() - 1, lambda: False)
    with caplog.at_level(logging.WARNING, logger=launcher.logger.name):
        chien.start()
        chien.thread.join(timeout=5)
    assert serveur.arrets == 1
    assert sortie_forcee == [0]
    assert "Boîte « OK » impossible à fermer" in caplog.text


def test_veille_boite_ok_pas_affichee_ni_fermeture_ni_sortie_forcee(
    durees_courtes, monkeypatch, sortie_forcee
):
    """Boîte indisponible (repli sur l'attente habituelle) : le thread principal s'arrête seul avec le serveur."""
    fermetures = []
    monkeypatch.setattr(launcher.sys, "platform", "win32")
    monkeypatch.setattr(launcher, "_console_absent", True)
    monkeypatch.setattr(launcher, "_box_thread", None)
    monkeypatch.setattr(
        launcher, "close_message_box", lambda thread_id: fermetures.append(thread_id) or False
    )
    serveur = ServeurVivant()
    chien = launcher.IdleWatchdog(serveur, lambda: time.monotonic() - 1, lambda: False)
    chien.start()
    chien.thread.join(timeout=5)
    assert serveur.arrets == 1
    assert fermetures == []
    assert sortie_forcee == []


def test_boite_ok_notee_le_temps_de_son_affichage(faux_serveur, sans_console, monkeypatch):
    """Le chien de garde ferme la boîte du thread qui l'affiche, et seulement pendant son affichage."""
    vus = []
    monkeypatch.setattr(
        launcher,
        "show_message_box",
        lambda texte, titre=launcher.WINDOW_TITLE, error=False: vus.append(launcher._box_thread) or True,
    )
    assert launcher.run("browser") == 0
    assert vus == [threading.get_native_id()]
    assert launcher._box_thread is None


def test_veille_etat_illisible_jamais_d_arret(durees_courtes, caplog):
    serveur = ServeurVivant()

    def illisible():
        raise RuntimeError("état indisponible")

    chien = launcher.IdleWatchdog(serveur, illisible, lambda: False)
    with caplog.at_level(logging.WARNING, logger=launcher.logger.name):
        chien.start()
        time.sleep(0.2)
        chien.cancel()
        chien.thread.join(timeout=5)
    assert serveur.arrets == 0
    assert caplog.text.count("vérification impossible") == 1  # signalé une fois, pas à chaque vérification


@pytest.fixture
def chiens_de_garde(monkeypatch):
    """Remplace start_idle_watchdog : liste des chiens de garde lancés par run()."""
    lances = []

    class FauxChien:
        def __init__(self, handle) -> None:
            self.handle = handle
            self.annule = False

        def cancel(self) -> None:
            self.annule = True

    def lancer(handle):
        lances.append(FauxChien(handle))
        return lances[-1]

    monkeypatch.setattr(launcher, "start_idle_watchdog", lancer)
    return lances


def test_arret_automatique_en_mode_navigateur(faux_serveur, chiens_de_garde, capsys):
    assert launcher.run("browser") == 0
    assert len(chiens_de_garde) == 1
    assert chiens_de_garde[0].handle is faux_serveur["instances"][0]
    assert chiens_de_garde[0].annule is True  # interface fermée : chien de garde arrêté
    sortie = capsys.readouterr().out
    assert "2 min après la fermeture du dernier onglet" in sortie
    # Limite annoncée : un onglet mis en veille par le navigateur ne bat plus.
    assert "veille" in sortie


def test_pas_d_arret_automatique_avec_no_open(faux_serveur, chiens_de_garde, capsys):
    """Revue : --browser --no-open (interface ouverte plus tard, ou usage par l'API) arrêté 10 min après le lancement."""
    assert launcher.run("browser", open_browser=False) == 0
    assert chiens_de_garde == []
    sortie = capsys.readouterr().out
    assert "dernier onglet" not in sortie
    assert "Fermez cette fenêtre pour arrêter DomainRecon" in sortie


def test_pas_d_arret_automatique_avec_no_open_sans_console(faux_serveur, chiens_de_garde, sans_console):
    assert launcher.run("browser", open_browser=False) == 0
    assert chiens_de_garde == []
    assert "dernier onglet" not in sans_console["boites"][0]
    assert "OK pour arrêter DomainRecon" in sans_console["boites"][0]


class ServeurQuiMeurt:
    """Serveur simulé pour run() : vivant jusqu'à stop(), qui réussit."""

    def __init__(self, url: str) -> None:
        self.url = url
        self.vivant = True
        self.arrets = 0

    def is_alive(self) -> bool:
        return self.vivant

    def stop(self) -> bool:
        self.arrets += 1
        self.vivant = False
        return True


@pytest.fixture
def chien_reel(monkeypatch):
    """run('browser') avec le vrai chien de garde, sur l'état réel de l'application, en durées courtes."""
    from domainrecon.api.app import app

    monkeypatch.setattr(launcher, "IDLE_CHECK_INTERVAL", 0.05)
    monkeypatch.setattr(launcher, "IDLE_SHUTDOWN", 1.0)
    monkeypatch.setattr(launcher, "IDLE_FIRST_HEARTBEAT", 5.0)
    monkeypatch.setattr(app.state, "last_heartbeat", time.monotonic())  # un onglet, fermé aussitôt
    monkeypatch.setattr(app.state, "last_api_activity", None)
    serveurs = []

    def demarrer(host, port):
        serveurs.append(ServeurQuiMeurt(launcher.browser_url(host, port)))
        return serveurs[-1]

    monkeypatch.setattr(launcher, "start_server", demarrer)
    monkeypatch.setattr(launcher, "wait_until_healthy", lambda url, timeout=20.0, alive=None: True)
    monkeypatch.setattr(launcher.webbrowser, "open", lambda url: True)
    monkeypatch.setattr(launcher, "_log_file", None)
    return serveurs


def test_arret_automatique_de_bout_en_bout_avec_console(chien_reel, monkeypatch, sortie_forcee):
    """Chien de garde réel → stop() → run() rend 0, sans arrêt forcé (Ctrl+C attendu, jamais reçu)."""
    monkeypatch.setattr(launcher, "_console_absent", False)
    debut = time.monotonic()
    assert launcher.run("browser") == 0
    assert time.monotonic() - debut < 10
    assert chien_reel[0].arrets >= 1
    assert sortie_forcee == []


@pytest.mark.skipif(sys.platform != "win32", reason="boîte de message Windows réelle")
def test_arret_automatique_ferme_la_vraie_boite_ok(chien_reel, monkeypatch, sortie_forcee):
    """Exécutable sans console : vraie boîte MessageBoxW, fermée par le chien de garde réel (classe, thread, ordre)."""
    monkeypatch.setattr(launcher, "_console_absent", True)
    affichages = []
    vraie_boite = launcher.show_message_box

    def boite(texte, titre=launcher.WINDOW_TITLE, error=False):
        affichages.append(vraie_boite(texte, f"{titre} (test automatique)", error))
        return affichages[-1]

    monkeypatch.setattr(launcher, "show_message_box", boite)
    resultat = []
    # Thread « principal » du lanceur : il crée le chien de garde et affiche la boîte.
    principal = threading.Thread(target=lambda: resultat.append(launcher.run("browser")), daemon=True)
    principal.start()
    principal.join(timeout=15)
    if principal.is_alive():
        _fermer_les_fenetres_du_thread(principal.native_id)
        principal.join(timeout=5)
        pytest.fail("la boîte « OK » n'a pas été fermée par le chien de garde")
    if affichages != [True]:
        pytest.skip("MessageBoxW n'a rien affiché (session sans bureau interactif)")
    assert resultat == [0]
    assert chien_reel[0].arrets >= 1
    assert sortie_forcee == []


def _fermer_les_fenetres_du_thread(thread_id: int) -> None:
    """Secours d'un test en échec : ferme (WM_CLOSE) toute fenêtre du thread, sans passer par le lanceur."""
    import ctypes
    from ctypes import wintypes

    user32 = ctypes.WinDLL("user32")
    rappel = ctypes.WINFUNCTYPE(wintypes.BOOL, wintypes.HWND, wintypes.LPARAM)
    user32.EnumThreadWindows.argtypes = (wintypes.DWORD, rappel, wintypes.LPARAM)
    user32.PostMessageW.argtypes = (wintypes.HWND, wintypes.UINT, wintypes.WPARAM, wintypes.LPARAM)
    user32.EnumThreadWindows(
        thread_id, rappel(lambda hwnd, _l: bool(user32.PostMessageW(hwnd, 0x0010, 0, 0)) or True), 0
    )


@pytest.mark.skipif(sys.platform != "win32", reason="boîte de message Windows réelle")
def test_fermeture_d_une_vraie_boite_de_message():
    """close_message_box sur une vraie MessageBoxW affichée par un autre thread : elle rend IDOK, comme un clic."""
    import ctypes

    resultat = {}
    pret = threading.Event()

    def afficher():
        resultat["thread"] = threading.get_native_id()
        pret.set()
        resultat["code"] = ctypes.windll.user32.MessageBoxW(
            None,
            "Fermeture automatique (test)",
            "DomainRecon (test automatique)",
            launcher._MB_ICONINFORMATION,
        )

    boite = threading.Thread(target=afficher, daemon=True)
    boite.start()
    assert pret.wait(5)
    limite = time.monotonic() + 5
    while not launcher.close_message_box(resultat["thread"]):
        if not boite.is_alive():
            pytest.skip("MessageBoxW n'a rien affiché (session sans bureau interactif)")
        if time.monotonic() > limite:
            _fermer_les_fenetres_du_thread(resultat["thread"])
            boite.join(timeout=5)
            pytest.fail("boîte de message introuvable par close_message_box")
        time.sleep(0.05)
    boite.join(timeout=5)
    assert not boite.is_alive()
    assert resultat["code"] == launcher._IDOK


def test_arret_automatique_dans_le_repli_navigateur(faux_serveur, chiens_de_garde, sans_console, monkeypatch):
    monkeypatch.setattr(launcher, "open_window", lambda url: False)
    assert launcher.run("window") == 0
    assert len(chiens_de_garde) == 1
    assert "2 min après la fermeture du dernier onglet" in sans_console["boites"][0]


def test_jamais_d_arret_automatique_en_mode_fenetre_ni_serveur(faux_serveur, chiens_de_garde, monkeypatch):
    monkeypatch.setattr(launcher, "open_window", lambda url: True)
    assert launcher.run("window") == 0
    monkeypatch.setattr(launcher, "serve_blocking", lambda host, port: None)
    assert launcher.run("server", port=8123) == 0
    monkeypatch.setattr(launcher, "wait_until_healthy", lambda url, timeout=20.0, alive=None: False)
    assert launcher.run("browser") == 1  # serveur qui n'a pas démarré : rien à surveiller
    assert chiens_de_garde == []


def test_chien_de_garde_lit_l_etat_de_l_application(monkeypatch):
    from domainrecon.api.app import app
    from domainrecon.api.routes import jobs as jobs_routes

    monkeypatch.setattr(launcher, "IDLE_CHECK_INTERVAL", 60.0)  # aucune vérification pendant le test
    monkeypatch.setattr(app.state, "last_heartbeat", 123.0)
    monkeypatch.setattr(app.state, "last_api_activity", 456.0)
    chien = launcher.start_idle_watchdog(FausseInstance("http://127.0.0.1:5123"))
    try:
        assert isinstance(chien, launcher.IdleWatchdog)
        assert chien._last_heartbeat() == 123.0
        assert chien._last_activity() == 456.0
        assert chien._busy == jobs_routes.manager.busy
        assert chien.thread.is_alive()
    finally:
        chien.cancel()
    chien.thread.join(timeout=5)
    assert not chien.thread.is_alive()


def test_chien_de_garde_indisponible_n_empeche_pas_le_lancement(monkeypatch, caplog):
    from domainrecon.api.app import app

    monkeypatch.delattr(app.state, "job_manager")
    with caplog.at_level(logging.WARNING, logger=launcher.logger.name):
        assert launcher.start_idle_watchdog(FausseInstance("http://127.0.0.1:5123")) is None
    assert "Arrêt automatique du mode navigateur indisponible" in caplog.text


def test_fermeture_de_la_boite_indisponible(monkeypatch):
    import ctypes

    monkeypatch.delattr(ctypes, "WinDLL", raising=False)  # hors Windows
    assert launcher.close_message_box(1234) is False


@pytest.mark.skipif(sys.platform != "win32", reason="API Windows (WINFUNCTYPE)")
def test_fermeture_de_la_boite_comme_un_clic_sur_ok(monkeypatch):
    import ctypes

    fenetres = {101: "#32770", 202: "Chrome_WidgetWin_1"}
    enumerations, messages = [], []

    def enum_thread_windows(thread_id, rappel, lparam):
        enumerations.append(thread_id)
        for hwnd in list(fenetres):
            rappel(hwnd, 0)
        return True

    def get_class_name(hwnd, tampon, taille):
        tampon.value = fenetres[hwnd]
        return len(fenetres[hwnd])

    def post_message(hwnd, message, wparam, lparam):
        messages.append((hwnd, message, wparam, lparam))
        return True

    faux = types.SimpleNamespace(
        EnumThreadWindows=enum_thread_windows, GetClassNameW=get_class_name, PostMessageW=post_message
    )
    monkeypatch.setattr(ctypes, "WinDLL", lambda nom: faux)
    assert launcher.close_message_box(4321) is True
    assert enumerations == [4321]
    # WM_CLOSE, seulement à la boîte : MessageBoxW rend IDOK, comme un clic sur OK.
    assert messages == [(101, launcher._WM_CLOSE, 0, 0)]
    del fenetres[101]
    messages.clear()
    assert launcher.close_message_box(4321) is False
    assert messages == []
