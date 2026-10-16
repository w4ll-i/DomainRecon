# =============================================================================
# DomainRecon - Lanceur : serveur local et fenêtre native ou navigateur
# =============================================================================
# Trois modes (commande `domainrecon`, voir __main__.py) :
#   - window  : serveur sur 127.0.0.1 (port PREFERRED_APP_PORT, sinon un port
#               libre) et fenêtre pywebview « DomainRecon » ; fermer la fenêtre
#               arrête le serveur. Sans moteur web (WebView2 sous Windows,
#               WebKitGTK ou Qt sous Linux), repli automatique sur le navigateur ;
#   - browser : serveur et navigateur par défaut (version portable) ; le
#               serveur s'arrête seul environ 2 minutes après la fermeture du
#               dernier onglet (IdleWatchdog), comme dans le repli navigateur,
#               sauf avec --no-open (interface ouverte plus tard, ou API seule) ;
#   - server  : serveur seul, au premier plan (usage avancé, sans interface).
# En modes window et browser, uvicorn tourne dans un thread : pywebview exige
# le thread principal. Le port préféré, quand il est libre, garde la même
# origine d'un lancement à l'autre : le localStorage (langue choisie) en dépend.
# =============================================================================

from __future__ import annotations

import ipaddress
import logging
import os
import socket
import sys
import threading
import time
import traceback
import urllib.error
import urllib.request
import webbrowser
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path

from .. import __version__
from ..core import paths

logger = logging.getLogger(__name__)

MODES = ("window", "browser", "server")
DEFAULT_SERVER_PORT = 8000
# Port essayé en premier par les modes window et browser (origine stable pour le
# stockage de la fenêtre ou du navigateur) ; un port libre quelconque sinon.
PREFERRED_APP_PORT = 47815
WINDOW_TITLE = "DomainRecon"
WINDOW_SIZE = (1280, 820)
WINDOW_MIN_SIZE = (960, 640)
# Attente du démarrage du serveur local, puis de son arrêt, en secondes.
HEALTH_TIMEOUT = 20.0
STOP_TIMEOUT = 10.0
# Délai laissé par uvicorn aux connexions encore ouvertes (flux SSE d'un scan en
# cours) avant de les interrompre : sans borne, un flux ouvert bloquerait l'arrêt.
# Inférieur à STOP_TIMEOUT pour que stop() voie le thread se terminer.
GRACEFUL_SHUTDOWN_TIMEOUT = 3
# Mode navigateur : arrêt automatique quand plus aucun onglet de l'interface
# n'envoie de battement (toutes les 30 s, POST /api/system/heartbeat), en
# secondes. Toute autre requête de l'API compte aussi comme activité. Tant
# qu'aucun battement n'est arrivé (navigateur qui ne s'est pas ouvert), délai
# plus long avant la même règle ; jamais d'arrêt si des requêtes arrivent sans
# aucun battement (interface ancienne ou en cache, client de l'API). Un écart
# anormal entre deux vérifications (sortie de veille de la machine) relance le
# délai : les onglets n'ont pas encore pu se manifester.
IDLE_SHUTDOWN = 120.0
IDLE_FIRST_HEARTBEAT = 600.0
IDLE_CHECK_INTERVAL = 5.0
IDLE_SUSPEND_GAP = 30.0
# Runtime WebView2 d'Edge (identifiant fixe de Microsoft).
_WEBVIEW2_RUNTIME = "{F3017226-FE2A-4295-8BDF-00C3A9A7E4C5}"
# Boîte de message Windows (MessageBoxW) : bouton OK, icône d'information.
_MB_OK = 0x0
_MB_ICONERROR = 0x10
_MB_ICONINFORMATION = 0x40
# Fermeture de cette boîte par le chien de garde : WM_CLOSE, comme la croix ou
# Échap. Le seul bouton d'une boîte MB_OK porte l'identifiant IDCANCEL : un
# WM_COMMAND IDOK y est ignoré. MessageBoxW rend alors IDOK, comme un clic sur OK.
_WM_CLOSE = 0x0010
_IDOK = 1  # valeur rendue par MessageBoxW après un clic sur OK (ou WM_CLOSE)
_DIALOG_CLASS = "#32770"  # classe Windows des boîtes de dialogue, MessageBoxW comprise
# Vrai quand ensure_std_streams a dû remplacer les flux absents : exécutable
# fenêtré, sans console pour l'utilisateur.
_console_absent = False
# Thread (identifiant natif) qui affiche la boîte « OK » du mode navigateur, le
# temps de son affichage ; None sinon. Le chien de garde ferme cette boîte.
_box_thread: int | None = None
# Journal où vont alors stdout et stderr (None : console présente, ou os.devnull).
_log_file: Path | None = None
# Requêtes vers le serveur local : jamais par un proxy (HTTP_PROXY d'entreprise).
_LOCAL_OPENER = urllib.request.build_opener(urllib.request.ProxyHandler({}))


# =============================================================================
# Adresses et console
# =============================================================================


def connect_host(host: str) -> str:
    """Adresse à utiliser pour joindre un serveur qui écoute sur `host`."""
    if host in ("", "0.0.0.0"):
        return "127.0.0.1"
    if host == "::":
        return "::1"
    return host


def browser_url(host: str, port: int) -> str:
    """URL de l'interface, telle que joignable depuis cette machine."""
    target = connect_host(host)
    if ":" in target:  # IPv6 littérale
        target = f"[{target}]"
    return f"http://{target}:{port}"


def is_loopback(host: str) -> bool:
    """Vrai si l'hôte n'est joignable que depuis cette machine."""
    if host.lower() == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def server_loop() -> str:
    """Boucle d'événements demandée à uvicorn.

    Sous Windows, « none » laisse asyncio choisir sa boucle par défaut
    (ProactorEventLoop), seule capable de lancer le pilote de Playwright :
    sinon chaque capture d'écran échoue.
    """
    return "none" if sys.platform == "win32" else "auto"


def make_console_safe() -> None:
    """Remplace les caractères non affichables au lieu de lever une exception.

    Sous Windows, une sortie redirigée (fichier, pipe, tâche planifiée) utilise
    l'encodage local (cp1252…) : un caractère hors de cet encodage lèverait
    UnicodeEncodeError avant même le démarrage du serveur.
    """
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if reconfigure is None:
            continue
        try:
            reconfigure(errors="replace")
        except (ValueError, OSError):  # flux fermé ou détaché
            pass


def ensure_std_streams() -> Path | None:
    """Exécutable fenêtré : flux standard absents redirigés vers un journal.

    DomainRecon.exe (sans console) démarre avec sys.stdout et sys.stderr à
    None : uvicorn (isatty) et logging échoueraient. Renvoie le journal
    ouvert (<données>/logs/domainrecon.log), ou None si rien n'a été fait.
    Dossier de données non inscriptible : les flux vont vers os.devnull (la
    fonction ne lève jamais d'exception, le démarrage doit rester possible).
    """
    global _console_absent, _log_file
    if sys.stdout is not None and sys.stderr is not None:
        return None
    _console_absent = True
    try:
        log_dir = paths.data_dir() / "logs"
        log_dir.mkdir(parents=True, exist_ok=True)
        log_file = log_dir / "domainrecon.log"
        stream = open(log_file, "a", encoding="utf-8", buffering=1)  # ouvert pour toute la vie du processus
    except Exception:  # quelle que soit la cause (droits, disque, chemin) : jamais d'échec ici
        log_file = Path(os.devnull)
        stream = open(log_file, "w", encoding="utf-8")
    if sys.stdout is None:
        sys.stdout = stream
    if sys.stderr is None:
        sys.stderr = stream
    _log_file = None if log_file == Path(os.devnull) else log_file
    return log_file


def _minutes(seconds: float) -> str:
    """Durée lisible : 120 -> « 2 min »."""
    return f"{seconds / 60:g} min"


def print_banner(url: str, mode: str, auto_stop: bool = True) -> None:
    """Affiche l'adresse de l'interface (cadre en ASCII, lisible dans toute console).

    `auto_stop` : l'arrêt automatique du mode navigateur est actif (pas avec --no-open).
    """
    line = "=" * 58
    if mode == "server":
        stop = "Ctrl+C pour arrêter le serveur."
    elif not auto_stop:
        stop = "Fermez cette fenêtre pour arrêter DomainRecon."
    else:
        stop = (
            "Fermez cette fenêtre pour arrêter DomainRecon (arrêt automatique\n"
            f"  {_minutes(IDLE_SHUTDOWN)} après la fermeture du dernier onglet ; un onglet mis\n"
            "  en veille par le navigateur peut compter comme fermé)."
        )
    print(
        f"\n  {line}\n"
        f"    DomainRecon {__version__}\n"
        f"  {'-' * 58}\n"
        f"    Adresse : {url}\n"
        f"    API     : {url}/api/docs\n"
        f"  {line}\n"
        f"  {stop}\n",
        flush=True,
    )


def warn_network_exposure(host: str, api_token: str | None, allowed_hosts: list[str]) -> None:
    """Rappelle les réglages de sécurité quand le serveur écoute sur le réseau."""
    err = sys.stderr
    print(f"[!] Le serveur écoute sur {host} : il est joignable depuis le réseau.", file=err)
    if not api_token:
        print(
            "    Aucun API_TOKEN défini : n'importe qui sur ce réseau peut lancer des scans,\n"
            "    lire et supprimer l'historique. Définissez API_TOKEN (voir .env.example).",
            file=err,
        )
    if "*" not in allowed_hosts:
        print(
            "    Ajoutez à ALLOWED_HOSTS le nom ou l'adresse utilisés pour joindre l'outil\n"
            f"    (actuellement : {', '.join(allowed_hosts)}).",
            file=err,
        )


def describe_error(exc: BaseException) -> str:
    """Cause d'une exception en une ligne : « PermissionError : [Errno 13] … »."""
    text = str(exc).strip()
    first_line = text.splitlines()[0] if text else ""
    return f"{type(exc).__name__} : {first_line}" if first_line else type(exc).__name__


def report_failure(message: str, exc: BaseException | None = None) -> None:
    """Signale un échec de démarrage : sur stderr ([!]) et, sans console, dans une boîte de message.

    Exécutable fenêtré (DomainRecon.exe) : stderr va dans un journal que
    personne ne lit, et sans boîte le double-clic ne produirait « rien ».
    L'exception, s'il y en a une, est écrite au journal (traceback).
    """
    print(f"[!] {message}", file=sys.stderr)
    if not _console_absent:
        return
    if exc is not None:
        traceback.print_exception(exc, file=sys.stderr)
    text = message if _log_file is None else f"{message}\n\nJournal : {_log_file}"
    show_message_box(text, error=True)


def allow_app_host(host: str) -> None:
    """Ajoute à ALLOWED_HOSTS l'adresse que l'application ouvre elle-même (modes window et browser).

    `--host 192.168.1.10` ouvre http://192.168.1.10:port : sans cela, le
    contrôle de l'en-tête Host (anti DNS rebinding) refuserait la fenêtre. Un
    ALLOWED_HOSTS personnalisé sans localhost refuserait de même 127.0.0.1.
    À appeler avant de démarrer le serveur : la liste est lue à son démarrage.
    """
    from ..core import config

    target = connect_host(host)
    known = {entry.strip().lower() for entry in config.ALLOWED_HOSTS}
    if "*" not in known and target.lower() not in known:
        config.ALLOWED_HOSTS = [*config.ALLOWED_HOSTS, target]


# =============================================================================
# Serveur
# =============================================================================


def find_free_port(host: str = "127.0.0.1") -> int:
    """Port TCP libre sur `host` (choisi par le système)."""
    family = socket.AF_INET6 if ":" in host else socket.AF_INET
    with socket.socket(family, socket.SOCK_STREAM) as sock:
        sock.bind((host, 0))
        return sock.getsockname()[1]


def is_port_free(host: str, port: int) -> bool:
    """Vrai si `port` peut être lié sur `host` (test de liaison, sans réutilisation d'adresse)."""
    family = socket.AF_INET6 if ":" in host else socket.AF_INET
    try:
        with socket.socket(family, socket.SOCK_STREAM) as sock:
            sock.bind((host, port))
    except OSError:
        return False
    return True


def choose_app_port(host: str) -> int:
    """Port des modes window et browser : PREFERRED_APP_PORT s'il est libre, sinon un port libre."""
    if is_port_free(host, PREFERRED_APP_PORT):
        return PREFERRED_APP_PORT
    return find_free_port(host)


def _uvicorn_config(host: str, port: int):
    """Configuration uvicorn de l'application (import tardif : base et journaux à la demande).

    Jamais de rechargement automatique. proxy_headers=False : l'adresse du client
    (request.client.host) est celle de la connexion TCP, que X-Forwarded-For ne
    peut pas falsifier (la route d'ouverture du dossier de données s'en sert pour
    reconnaître la machine locale). timeout_graceful_shutdown borne l'arrêt en
    présence d'un flux SSE ouvert.
    """
    import uvicorn

    from ..api.app import app

    return uvicorn.Config(
        app,
        host=host,
        port=port,
        loop=server_loop(),
        proxy_headers=False,
        timeout_graceful_shutdown=GRACEFUL_SHUTDOWN_TIMEOUT,
    )


@dataclass
class ServerHandle:
    """Serveur uvicorn lancé dans un thread (modes window et browser)."""

    url: str
    _server: object = field(repr=False)
    _thread: threading.Thread = field(repr=False)

    def is_alive(self) -> bool:
        return self._thread.is_alive()

    def stop(self) -> bool:
        """Demande l'arrêt du serveur et attend la fin du thread (au plus STOP_TIMEOUT).

        Renvoie False (et le journalise) si le thread tourne encore : un module
        de scan bloqué dans un thread (WHOIS, DNS…) retient alors le processus
        jusqu'à la fin de son délai.
        """
        self._server.should_exit = True
        self._thread.join(timeout=STOP_TIMEOUT)
        if self._thread.is_alive():
            logger.warning(
                "Le serveur ne s'est pas arrêté en %s s : le processus attend la fin de ses tâches en cours",
                STOP_TIMEOUT,
            )
            return False
        return True


def start_server(host: str, port: int) -> ServerHandle:
    """Démarre uvicorn dans un thread et rend la main aussitôt (voir wait_until_healthy)."""
    import uvicorn

    server = uvicorn.Server(_uvicorn_config(host, port))
    register_exit(server)
    thread = threading.Thread(target=server.run, name="domainrecon-serveur", daemon=True)
    thread.start()
    return ServerHandle(url=browser_url(host, port), _server=server, _thread=thread)


def exit_app(server) -> None:
    """Ferme DomainRecon comme le ferait l'utilisateur (fin d'une désinstallation complète).

    Fenêtre native : elle est détruite, run() reprend la main et arrête le serveur.
    Navigateur : le serveur s'arrête ; la boîte « OK » de l'exécutable sans console est
    fermée comme par un clic. Serveur seul : arrêt comme par Ctrl+C.
    """
    webview = sys.modules.get("webview")
    if webview is not None:
        for window in list(getattr(webview, "windows", ())):
            try:
                window.destroy()
            except Exception as e:  # fenêtre déjà fermée
                logger.warning("Fermeture de la fenêtre impossible : %s", e)
    server.should_exit = True
    box_thread = _box_thread
    if sys.platform == "win32" and box_thread is not None:
        close_message_box(box_thread)


def register_exit(server) -> None:
    """Donne à l'API le moyen de fermer l'application (app.state.exit_app, route de fin de désinstallation)."""
    from ..api.app import app

    app.state.exit_app = lambda: exit_app(server)


def serve_blocking(host: str, port: int) -> None:
    """Serveur au premier plan (mode server) : Ctrl+C l'arrête proprement.

    Après l'arrêt, uvicorn rejoue le signal reçu : SIGINT remonte ici en
    KeyboardInterrupt, avalée comme le fait uvicorn.run (sortie normale, code 0).
    """
    import uvicorn

    server = uvicorn.Server(_uvicorn_config(host, port))
    register_exit(server)
    try:
        server.run()
    except KeyboardInterrupt:
        pass


def wait_until_healthy(
    url: str, timeout: float = HEALTH_TIMEOUT, alive: Callable[[], bool] | None = None
) -> bool:
    """Attend que `url`/api/health réponde (200 ou 503 : le serveur tourne).

    `alive` (facultatif) dit si le serveur lancé tourne encore : une fois mort
    (port déjà occupé, erreur au démarrage), inutile d'attendre, et la réponse
    éventuelle d'un autre service sur ce port n'est pas la sienne. Toute autre
    réponse HTTP (400 « Host refusé », 404…) n'est pas celle de /api/health de
    DomainRecon : échec immédiat.
    """
    deadline = time.monotonic() + timeout
    while True:
        if alive is not None and not alive():
            return False
        try:
            with _LOCAL_OPENER.open(f"{url}/api/health", timeout=2):
                return True
        except urllib.error.HTTPError as e:
            if e.code == 503:  # base en lecture seule : le serveur tourne
                return True
            logger.warning("%s/api/health répond HTTP %s : ce n'est pas le serveur attendu", url, e.code)
            return False
        except (urllib.error.URLError, OSError):
            pass
        if time.monotonic() >= deadline:
            return False
        time.sleep(0.2)


# =============================================================================
# Fenêtre native (pywebview)
# =============================================================================


def _webview2_version() -> str | None:
    """Version du runtime WebView2 lue dans le registre Windows, ou None."""
    import winreg

    key = rf"Microsoft\EdgeUpdate\Clients\{_WEBVIEW2_RUNTIME}"
    candidates = (
        (winreg.HKEY_CURRENT_USER, rf"SOFTWARE\{key}"),
        (winreg.HKEY_LOCAL_MACHINE, rf"SOFTWARE\WOW6432Node\{key}"),
        (winreg.HKEY_LOCAL_MACHINE, rf"SOFTWARE\{key}"),
    )
    for root, path in candidates:
        try:
            with winreg.OpenKey(root, path) as handle:
                version, _ = winreg.QueryValueEx(handle, "pv")
        except OSError:
            continue
        if version and str(version) != "0.0.0.0":
            return str(version)
    return None


def webview2_available() -> bool:
    """Moteur de la fenêtre native présent ? Toujours vrai hors Windows (GTK/Qt testés au démarrage).

    Sans WebView2, pywebview se rabattrait sur MSHTML (Internet Explorer),
    incapable d'afficher l'interface : repli sur le navigateur à la place.
    """
    if sys.platform != "win32":
        return True
    try:
        return _webview2_version() is not None
    except Exception:
        return False


def _icon_path() -> str | None:
    # Icône PNG de la fenêtre pour GTK/Qt seulement : sous Windows, WinForms
    # exige un .ico et lève une ArgumentException (« picture ») sur un PNG ;
    # la fenêtre y reprend l'icône de l'exécutable.
    if sys.platform == "win32":
        return None
    icon = paths.package_dir() / "desktop" / "icon.png"
    return str(icon) if icon.is_file() else None


def open_window(url: str) -> bool:
    """Affiche l'interface dans une fenêtre native et attend sa fermeture.

    Renvoie False si la fenêtre ne peut pas s'ouvrir (moteur absent,
    pywebview non installé) : l'appelant se rabat sur le navigateur.
    Stockage persistant (private_mode=False) : la langue choisie
    (localStorage) survit au redémarrage. Téléchargements autorisés
    (ALLOW_DOWNLOADS, refusé par défaut) : exports PDF et JSON de l'interface.
    """
    if not webview2_available():
        logger.warning("WebView2 absent : fenêtre native indisponible")
        return False
    try:
        import webview
    except Exception as e:  # ImportError, ou chargement de pythonnet impossible
        logger.warning("pywebview indisponible : %s", e)
        return False
    storage = paths.data_dir() / "webview"
    try:
        storage.mkdir(parents=True, exist_ok=True)
        try:
            webview.settings["ALLOW_DOWNLOADS"] = True  # réglage global de pywebview (>= 5)
        except (AttributeError, TypeError):
            logger.warning("pywebview sans ALLOW_DOWNLOADS : exports PDF/JSON bloqués dans la fenêtre")
        webview.create_window(
            WINDOW_TITLE, url, width=WINDOW_SIZE[0], height=WINDOW_SIZE[1], min_size=WINDOW_MIN_SIZE
        )
        webview.start(private_mode=False, storage_path=str(storage), icon=_icon_path())
    except Exception as e:
        logger.warning("Fenêtre native indisponible : %s", e)
        return False
    return True


# =============================================================================
# Arrêt automatique du mode navigateur
# =============================================================================


def close_message_box(thread_id: int) -> bool:
    """Ferme les boîtes de message ouvertes par le thread `thread_id` (Windows), comme un clic sur OK.

    Renvoie False si aucune n'a été trouvée ou si l'API est indisponible.
    Instance propre de user32 : ses argtypes ne touchent pas ctypes.windll.
    WM_CLOSE (voir _WM_CLOSE) : MessageBoxW rend IDOK.
    """
    try:
        import ctypes
        from ctypes import wintypes

        user32 = ctypes.WinDLL("user32")
        enum_proc = ctypes.WINFUNCTYPE(wintypes.BOOL, wintypes.HWND, wintypes.LPARAM)
        user32.EnumThreadWindows.argtypes = (wintypes.DWORD, enum_proc, wintypes.LPARAM)
        user32.GetClassNameW.argtypes = (wintypes.HWND, wintypes.LPWSTR, ctypes.c_int)
        user32.PostMessageW.argtypes = (wintypes.HWND, wintypes.UINT, wintypes.WPARAM, wintypes.LPARAM)
        boxes = []

        def visit(hwnd, _lparam):
            name = ctypes.create_unicode_buffer(32)
            if user32.GetClassNameW(hwnd, name, len(name)) and name.value == _DIALOG_CLASS:
                boxes.append(hwnd)
            return True

        user32.EnumThreadWindows(thread_id, enum_proc(visit), 0)
        for hwnd in boxes:
            user32.PostMessageW(hwnd, _WM_CLOSE, 0, 0)
    except Exception as e:  # pas Windows, ou user32 inaccessible
        logger.warning("Fermeture de la boîte de message impossible : %s", e)
        return False
    return bool(boxes)


class IdleWatchdog:
    """Chien de garde du mode navigateur : arrête DomainRecon quand plus aucun onglet n'est ouvert.

    Chaque onglet de l'interface envoie un battement toutes les 30 s, même en
    arrière-plan ; toute autre requête de l'API (`last_activity`) compte aussi.
    Toutes les IDLE_CHECK_INTERVAL secondes : sans battement ni requête depuis
    IDLE_SHUTDOWN (IDLE_FIRST_HEARTBEAT tant que rien n'est arrivé) et sans
    scan en cours, arrêt par le même chemin que Ctrl+C ou la boîte « OK » :
    stop(), puis _hard_exit si le serveur ne s'arrête pas. Des requêtes sans
    aucun battement viennent d'une interface qui n'en envoie pas (ancienne, en
    cache) ou d'un client de l'API : impossible de savoir quand elle se ferme,
    jamais d'arrêt. Jamais en mode fenêtre (fermer la fenêtre suffit) ni en
    mode serveur. Durées relues à chaque vérification (les tests les remplacent).
    """

    def __init__(
        self,
        handle: ServerHandle,
        last_heartbeat: Callable[[], float | None],
        busy: Callable[[], bool],
        clock: Callable[[], float] = time.monotonic,
        last_activity: Callable[[], float | None] = lambda: None,
    ) -> None:
        self.handle = handle
        self._last_heartbeat = last_heartbeat
        self._last_activity = last_activity
        self._busy = busy
        self._clock = clock
        # Début du délai : lancement, puis chaque sortie de veille.
        self._since = clock()
        self._last_check = self._since
        self._cancelled = threading.Event()
        self._error_logged = False
        self._no_heartbeat_logged = False
        self.thread: threading.Thread | None = None

    def _limit(self, last: float | None) -> float:
        return IDLE_FIRST_HEARTBEAT if last is None else IDLE_SHUTDOWN

    def due(self) -> bool:
        """Vrai si l'arrêt est dû maintenant (voir la classe) ; appelée à chaque vérification."""
        now = self._clock()
        if now - self._last_check > IDLE_CHECK_INTERVAL + IDLE_SUSPEND_GAP:
            # Sortie de veille : l'horloge monotone a compté la veille, les
            # onglets ouverts n'ont pas encore pu envoyer leur battement.
            self._since = now
        self._last_check = now
        last = self._last_heartbeat()
        activity = self._last_activity()
        if last is None and activity is not None:
            if not self._no_heartbeat_logged:
                logger.info("Requêtes de l'API sans battement de l'interface : arrêt automatique suspendu")
                self._no_heartbeat_logged = True
            return False
        if activity is not None:
            last = max(last, activity)
        quiet = now - (self._since if last is None else max(last, self._since))
        return quiet >= self._limit(last) and not self._busy()

    def start(self) -> None:
        self.thread = threading.Thread(target=self._run, name="domainrecon-veille", daemon=True)
        self.thread.start()

    def cancel(self) -> None:
        """Met fin au chien de garde (DomainRecon arrêté par un autre chemin)."""
        self._cancelled.set()

    def _run(self) -> None:
        while not self._cancelled.wait(IDLE_CHECK_INTERVAL):
            if not self.handle.is_alive():
                return
            try:
                due = self.due()
            except Exception as e:  # état de l'application illisible : jamais d'arrêt sur une erreur
                if not self._error_logged:
                    logger.warning("Arrêt automatique : vérification impossible (%s)", describe_error(e))
                    self._error_logged = True
                continue
            if due and not self._cancelled.is_set():
                self._shutdown()
                return

    def _shutdown(self) -> None:
        logger.info("Aucun onglet ouvert depuis %s : arrêt", _minutes(self._limit(self._last_heartbeat())))
        if self.handle.stop() is False:
            _hard_exit(0)
            return
        # Exécutable sans console : la boîte « OK » bloque le thread principal,
        # fermée comme par un clic ; run() termine alors normalement. Boîte
        # introuvable ou fermeture impossible : le serveur est déjà arrêté, rien
        # à perdre, le processus se termine (sinon il resterait, avec une boîte
        # qui dit DomainRecon ouvert). Boîte pas affichée (repli sur l'attente
        # habituelle) : le thread principal s'arrête seul avec le serveur.
        box_thread = _box_thread
        if sys.platform == "win32" and _console_absent and box_thread is not None:
            if not close_message_box(box_thread):
                logger.warning("Boîte « OK » impossible à fermer : fin du processus")
                _hard_exit(0)


def start_idle_watchdog(handle: ServerHandle) -> IdleWatchdog | None:
    """Lance le chien de garde du mode navigateur ; None (journalisé) si l'état de l'application est illisible."""
    try:
        from ..api.app import app

        state = app.state
        busy = state.job_manager.busy
    except Exception as e:  # une fonction de confort n'empêche jamais le lancement
        logger.warning("Arrêt automatique du mode navigateur indisponible : %s", describe_error(e))
        return None
    watchdog = IdleWatchdog(
        handle,
        last_heartbeat=lambda: getattr(state, "last_heartbeat", None),
        busy=busy,
        last_activity=lambda: getattr(state, "last_api_activity", None),
    )
    watchdog.start()
    return watchdog


# =============================================================================
# Modes
# =============================================================================


def _wait_while_running(handle: ServerHandle) -> None:
    """Attend l'arrêt du serveur ; Ctrl+C (ou fermeture de la console) y met fin."""
    try:
        while handle.is_alive():
            time.sleep(0.5)
    except KeyboardInterrupt:
        pass


def show_message_box(text: str, title: str = WINDOW_TITLE, error: bool = False) -> bool:
    """Boîte de message native bloquante (Windows) ; False si elle n'a pas pu s'afficher."""
    icon = _MB_ICONERROR if error else _MB_ICONINFORMATION
    try:
        import ctypes

        shown = ctypes.windll.user32.MessageBoxW(None, text, title, _MB_OK | icon)
    except Exception as e:  # pas Windows, ou user32 inaccessible
        logger.warning("Boîte de message indisponible : %s", e)
        return False
    return bool(shown)


def _wait_for_stop(handle: ServerHandle, after_fallback: bool, auto_stop: bool = True) -> None:
    """Attend l'arrêt de DomainRecon pendant que l'interface est dans le navigateur.

    Exécutable sans console sous Windows : le serveur serait invisible et
    impossible à arrêter ; une boîte de message bloquante sert de « fenêtre » et
    sa fermeture arrête le serveur. Sinon (console, autre système, boîte
    indisponible) : attente de l'arrêt du serveur (Ctrl+C). `auto_stop` :
    arrêt automatique actif (chien de garde), annoncé dans la boîte.
    """
    global _box_thread
    if sys.platform == "win32" and _console_absent:
        if after_fallback:
            intro = (
                "La fenêtre native n'a pas pu s'ouvrir (WebView2 absent ?) : "
                "DomainRecon s'est ouvert dans votre navigateur."
            )
        else:
            intro = "DomainRecon est ouvert dans votre navigateur."
        text = f"{intro}\n\n{handle.url}\n\nCliquez sur OK pour arrêter DomainRecon."
        if auto_stop:
            text += (
                f" Il s'arrête aussi seul {_minutes(IDLE_SHUTDOWN)} après la fermeture du dernier onglet "
                "(un onglet mis en veille par le navigateur peut compter comme fermé)."
            )
        # Noté avant l'affichage : le chien de garde ferme la boîte de ce thread.
        _box_thread = threading.get_native_id()
        try:
            shown = show_message_box(text)
        finally:
            _box_thread = None
        if shown:
            return
    _wait_while_running(handle)


def _hard_exit(code: int) -> None:
    """Termine le processus sans attendre les threads restants (les tests remplacent cette fonction).

    Le serveur ne s'est pas arrêté à temps (voir ServerHandle.stop) : les threads
    de module encore en cours retiendraient l'interpréteur jusqu'à la fin de
    leur délai. Flux et journaux sont vidés avant ; SQLite reste cohérent
    (transactions journalisées).
    """
    logger.warning("Arrêt forcé du processus : des tâches de scan tournent encore dans leurs threads")
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.flush()
        except Exception:  # flux fermé ou détaché
            pass
    logging.shutdown()
    os._exit(code)


def _startup_failure_text() -> str:
    """Message d'un serveur local qui n'a pas démarré, avec la cause si l'application l'a notée."""
    try:
        from ..api.app import app

        error = getattr(app.state, "startup_error", None)
    except Exception:  # application impossible à importer : seule la cause d'import compte
        error = None
    if error is None:
        return "Le serveur local n'a pas démarré (voir les journaux)."
    return f"Le serveur local n'a pas démarré : {describe_error(error)}"


def run(mode: str = "window", host: str = "127.0.0.1", port: int = 0, open_browser: bool = True) -> int:
    """Lance DomainRecon dans le mode demandé ; renvoie le code de sortie."""
    if mode not in MODES:
        raise ValueError(f"Mode inconnu : {mode!r} (attendu : {', '.join(MODES)})")
    if mode == "server":
        port = port or DEFAULT_SERVER_PORT
        print_banner(browser_url(host, port), mode)
        try:
            serve_blocking(host, port)
        except Exception as exc:  # données inaccessibles, base illisible… : message, pas de traceback brut
            report_failure(f"Le serveur n'a pas pu démarrer : {describe_error(exc)}", exc)
            return 1
        return 0

    try:
        handle = start_server(host, port or choose_app_port(host))
    except Exception as exc:
        # Import de l'application (données en lecture seule…), adresse ou port impossibles.
        report_failure(f"Le serveur local n'a pas pu démarrer : {describe_error(exc)}", exc)
        return 1
    code = 1
    try:
        code = _run_interface(mode, handle, open_browser)
        return code
    finally:
        # Un module de scan bloqué dans un thread (WHOIS, DNS…) retiendrait le
        # processus après la fermeture de la fenêtre : on y met fin de force.
        if handle.stop() is False:
            _hard_exit(code)


def _run_interface(mode: str, handle: ServerHandle, open_browser: bool) -> int:
    """Interface des modes window et browser, jusqu'à sa fermeture ; renvoie le code de sortie."""
    if not wait_until_healthy(handle.url, alive=handle.is_alive):
        report_failure(_startup_failure_text())
        return 1
    after_fallback = False
    if mode == "window":
        if open_window(handle.url):
            return 0
        after_fallback = True
        print("[i] Fenêtre native indisponible : ouverture dans le navigateur.")
    # Navigateur (mode browser ou repli) : arrêt automatique après la fermeture
    # du dernier onglet. Pas avec --no-open : l'interface s'ouvrira plus tard
    # (autre poste avec --host), ou l'API sert seule.
    watchdog = start_idle_watchdog(handle) if open_browser else None
    try:
        print_banner(handle.url, "browser", auto_stop=watchdog is not None)
        if open_browser:
            webbrowser.open(handle.url)
        _wait_for_stop(handle, after_fallback, auto_stop=watchdog is not None)
    finally:
        if watchdog is not None:
            watchdog.cancel()
    return 0
