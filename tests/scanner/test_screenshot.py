# =============================================================================
# DomainRecon - Tests de la capture d'écran : garde réseau, proxy, Chromium absent
# =============================================================================
# Aucun trafic vers Internet : résolutions DNS simulées, serveurs locaux sur
# 127.0.0.1, connexions sortantes du proxy simulées et module Playwright simulé
# (sauf quelques tests qui lancent le vrai Playwright, sautés s'il manque :
# dossier de navigateurs vide, boucle sans sous-processus, et vrai Chromium
# face à un site injoignable).
# conftest.py fixe ALLOW_PRIVATE_TARGETS=0 : la politique par défaut s'applique.
# =============================================================================

import asyncio
import logging
import socket
import sys
import threading
import time
import types
from concurrent.futures import ThreadPoolExecutor
from types import SimpleNamespace

import pytest

from domainrecon.i18n import msg
from domainrecon.scanner import screenshot, targets
from domainrecon.scanner.errors import ModuleError
from rendu import fr

PUBLIC_IP = "93.184.216.34"


# =============================================================================
# Fixtures
# =============================================================================


@pytest.fixture
def page_dns(monkeypatch):
    """Résolveur système simulé : table nom -> adresses (IP publique par défaut).

    Les noms en « .trou-noir.test » bloquent jusqu'à `release` (DNS qui ne
    répond pas). `calls` : noms résolus ; `threads` : threads qui ont résolu.
    """
    state = SimpleNamespace(table={}, calls=[], threads=set(), release=threading.Event())

    def fake_getaddrinfo(host):
        state.calls.append(host)
        state.threads.add(threading.current_thread().name)
        if host.endswith(".trou-noir.test"):
            state.release.wait(10)
        return [
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", (address, 0))
            for address in state.table.get(host, [PUBLIC_IP])
        ]

    monkeypatch.setattr(targets, "_system_getaddrinfo", fake_getaddrinfo)
    try:
        yield state
    finally:
        state.release.set()


@pytest.fixture
def silent_server():
    """Serveur TCP local qui accepte les connexions et ne lit jamais rien."""
    listener = socket.socket()
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4096)
    listener.bind(("127.0.0.1", 0))
    listener.listen(5)
    held: list[socket.socket] = []

    def accept():
        while True:
            try:
                conn, _ = listener.accept()
            except OSError:
                return
            held.append(conn)

    thread = threading.Thread(target=accept, daemon=True)
    thread.start()
    try:
        yield listener.getsockname()[1]
    finally:
        listener.close()
        for conn in held:
            conn.close()
        thread.join(timeout=2)


def _fake_playwright(monkeypatch, launch_error: Exception) -> None:
    """Module playwright.async_api simulé dont le lancement de Chromium échoue."""

    class Chromium:
        async def launch(self, **kwargs):
            raise launch_error

    class Manager:
        async def __aenter__(self):
            return SimpleNamespace(chromium=Chromium())

        async def __aexit__(self, *exc_info):
            return False

    module = types.ModuleType("playwright.async_api")
    module.async_playwright = Manager
    monkeypatch.setitem(sys.modules, "playwright.async_api", module)


@pytest.fixture
def public_target(monkeypatch):
    """La cible de la capture passe pour publique (aucune résolution réelle)."""

    async def ensure(host):
        return [PUBLIC_IP]

    monkeypatch.setattr(screenshot, "ensure_target_allowed", ensure)


# =============================================================================
# Garde réseau : résolutions demandées par la page
# =============================================================================


def test_garde_resout_hors_de_l_executeur_par_defaut(page_dns):
    guard = screenshot._NetworkGuard()

    assert asyncio.run(guard.addresses_for("cdn.example.com")) == [PUBLIC_IP]
    assert page_dns.calls == ["cdn.example.com"]
    assert all(name.startswith("domainrecon-capture-dns") for name in page_dns.threads)


def test_garde_une_seule_resolution_pour_des_requetes_simultanees(page_dns):
    """Des requêtes simultanées vers un même hôte partagent la même résolution."""
    guard = screenshot._NetworkGuard()

    async def scenario():
        requests = [asyncio.ensure_future(guard.addresses_for("lent.trou-noir.test")) for _ in range(10)]
        await asyncio.sleep(0.2)
        page_dns.release.set()
        return await asyncio.gather(*requests)

    assert asyncio.run(scenario()) == [[PUBLIC_IP]] * 10
    assert page_dns.calls == ["lent.trou-noir.test"]


def test_garde_limite_le_nombre_d_hotes_distincts(monkeypatch, page_dns):
    monkeypatch.setattr(screenshot, "_GUARD_MAX_HOSTS", 5)
    guard = screenshot._NetworkGuard()
    guard.remember("example.com", [PUBLIC_IP])

    async def scenario():
        return [await guard.addresses_for(f"h{i}.example.net") for i in range(10)]

    results = asyncio.run(scenario())

    # La cible compte parmi les 5 hôtes : 4 nouveaux noms sont résolus, pas plus.
    assert results[:4] == [[PUBLIC_IP]] * 4
    assert results[4:] == [[]] * 6
    assert page_dns.calls == [f"h{i}.example.net" for i in range(4)]
    assert guard.blocked == [f"h{i}.example.net" for i in range(4, 9)]
    # Un hôte déjà validé reste utilisable au-delà de la limite.
    assert asyncio.run(guard.addresses_for("h0.example.net")) == [PUBLIC_IP]


@pytest.mark.parametrize("addresses", [["10.0.0.1"], [PUBLIC_IP, "127.0.0.1"], ["169.254.169.254"]])
def test_garde_applique_la_politique_aux_adresses_resolues(page_dns, addresses):
    page_dns.table["interne.example.com"] = addresses
    guard = screenshot._NetworkGuard()

    assert asyncio.run(guard.addresses_for("interne.example.com")) == []
    assert guard.blocked == ["interne.example.com"]


def test_garde_reseau_prive_sur_option(monkeypatch, page_dns):
    monkeypatch.setenv("ALLOW_PRIVATE_TARGETS", "1")
    page_dns.table["intranet.example.com"] = ["10.0.0.1"]
    guard = screenshot._NetworkGuard()

    assert asyncio.run(guard.addresses_for("intranet.example.com")) == ["10.0.0.1"]
    assert guard.blocked == []


def test_page_hostile_n_accapare_pas_l_executeur_par_defaut(page_dns):
    """Régression : des centaines de noms sans réponse DNS bloquaient les contrôles des autres scans."""

    async def scenario():
        loop = asyncio.get_running_loop()
        default_executor = ThreadPoolExecutor(max_workers=4)
        loop.set_default_executor(default_executor)
        guard = screenshot._NetworkGuard()
        hostile = [asyncio.ensure_future(guard.addresses_for(f"n{i}.trou-noir.test")) for i in range(20)]
        await asyncio.sleep(0.2)
        try:
            # Contrôle de cible d'un autre scan, sur l'exécuteur par défaut.
            return await asyncio.wait_for(targets.ensure_target_allowed("autre-scan.example"), timeout=2)
        finally:
            page_dns.release.set()
            guard.cancel_pending()
            await asyncio.gather(*hostile, return_exceptions=True)

    assert asyncio.run(scenario()) == [PUBLIC_IP]


# =============================================================================
# Proxy : fermeture bornée
# =============================================================================


class _StuckWriter:
    """StreamWriter dont le tampon ne se vide jamais (pair qui ne lit plus)."""

    def __init__(self) -> None:
        self.closed = False
        self.aborted = False
        self.transport = SimpleNamespace(abort=self._abort)

    def _abort(self) -> None:
        self.aborted = True

    def close(self) -> None:
        self.closed = True

    async def wait_closed(self) -> None:
        await asyncio.Event().wait()


def test_fermeture_abandonnee_si_le_pair_ne_lit_plus(monkeypatch):
    monkeypatch.setattr(screenshot, "_PROXY_CLOSE_TIMEOUT", 0.2)
    writer = _StuckWriter()

    asyncio.run(asyncio.wait_for(screenshot._close_writer(writer), timeout=5))

    assert writer.closed and writer.aborted


def test_fermeture_normale_sans_abandon(monkeypatch):
    writer = _StuckWriter()

    async def closed_at_once():
        return None

    writer.wait_closed = closed_at_once
    asyncio.run(screenshot._close_writer(writer))

    assert writer.closed and not writer.aborted


def test_arret_du_proxy_borne_si_la_cible_ne_lit_plus(monkeypatch, silent_server):
    """Régression : un envoi vers un serveur qui ne lit rien bloquait proxy.close() sans fin,
    donc le scan et son créneau (MAX_CONCURRENT_SCANS)."""
    monkeypatch.setattr(screenshot, "_PROXY_CLOSE_TIMEOUT", 0.3)

    async def scenario():
        guard = screenshot._NetworkGuard()
        guard.remember("muet.invalid", ["127.0.0.1"])
        proxy = screenshot._FilteringProxy(guard)
        port = int((await proxy.start()).rsplit(":", 1)[1])
        reader, writer = await asyncio.open_connection("127.0.0.1", port)
        writer.write(f"CONNECT muet.invalid:{silent_server} HTTP/1.1\r\n\r\n".encode())
        await writer.drain()
        response = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), timeout=5)
        assert response.startswith(b"HTTP/1.1 200")

        # Envoi massif jusqu'à saturation des tampons : la cible ne lit rien.
        chunk = b"x" * 65536
        try:
            for _ in range(4000):
                writer.write(chunk)
                await asyncio.wait_for(writer.drain(), timeout=0.5)
        except asyncio.TimeoutError:
            pass
        else:
            pytest.fail("les tampons ne se sont jamais remplis")
        writer.transport.abort()  # Chromium fermé (browser.close())
        await asyncio.sleep(0.2)

        start = time.monotonic()
        await asyncio.wait_for(proxy.close(), timeout=10)
        return time.monotonic() - start

    assert asyncio.run(scenario()) < 5


# =============================================================================
# Site autorisé mais injoignable : 502 du proxy et cause en français
# =============================================================================

# Port jamais contacté : asyncio.open_connection est simulé pour lui.
UNREACHABLE_PORT = 8765


@pytest.fixture
def unreachable_port(monkeypatch):
    """Les connexions du proxy vers UNREACHABLE_PORT n'aboutissent jamais (port filtré,
    comme le port 80 de testphp.vulnweb.com) ; délai de connexion du proxy ramené à 0,1 s."""
    monkeypatch.setattr(screenshot, "_PROXY_CONNECT_TIMEOUT", 0.1)
    real_open_connection = asyncio.open_connection

    async def open_connection(host=None, port=None, **kwargs):
        if port == UNREACHABLE_PORT:
            await asyncio.sleep(30)
        return await real_open_connection(host, port, **kwargs)

    monkeypatch.setattr(asyncio, "open_connection", open_connection)
    return UNREACHABLE_PORT


async def _via_proxy(proxy, raw_request: bytes) -> bytes:
    """Envoie une requête au proxy (démarré ici) ; renvoie l'en-tête de sa réponse, b"" si aucune."""
    port = int((await proxy.start()).rsplit(":", 1)[1])
    try:
        reader, writer = await asyncio.open_connection("127.0.0.1", port)
        writer.write(raw_request)
        await writer.drain()
        try:
            return await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), timeout=5)
        except asyncio.IncompleteReadError as e:
            return e.partial
        finally:
            writer.close()
    finally:
        await proxy.close()


@pytest.mark.parametrize("scheme", ["http", "https"])
def test_proxy_repond_502_marque_si_le_site_est_injoignable(unreachable_port, scheme):
    """Régression : en http, le proxy fermait la connexion sans réponse, et Chromium
    présentait « net::ERR_EMPTY_RESPONSE » comme une réponse vide du site."""
    guard = screenshot._NetworkGuard()
    guard.remember("injoignable.invalid", ["127.0.0.1"])
    proxy = screenshot._FilteringProxy(guard)
    host = f"injoignable.invalid:{unreachable_port}"
    if scheme == "https":
        request = f"CONNECT {host} HTTP/1.1\r\nHost: {host}\r\n\r\n"
    else:
        request = f"GET http://{host}/ HTTP/1.1\r\nHost: {host}\r\n\r\n"

    head = asyncio.run(_via_proxy(proxy, request.encode()))

    status_line, *lines = head.decode("latin-1").split("\r\n")
    assert status_line == "HTTP/1.1 502 Bad Gateway"
    headers = {name.lower(): value for name, _, value in (line.partition(": ") for line in lines if line)}
    assert proxy.is_own_error(headers)
    assert fr(proxy.upstream_error(f"{scheme}://{host}/")) == (
        f"connexion impossible au port {unreachable_port} (délai dépassé)"
    )


def test_502_d_un_site_distinct_de_celui_du_proxy():
    """Seul le jeton de la capture en cours désigne une réponse du proxy lui-même."""
    proxy = screenshot._FilteringProxy(screenshot._NetworkGuard())
    assert not proxy.is_own_error({})
    assert not proxy.is_own_error({screenshot._PROXY_ERROR_HEADER: "jeton-devine"})
    assert proxy.upstream_error("http://jamais-contacte.example/") is None


@pytest.mark.parametrize(
    "message, attendu",
    [
        (
            "Page.goto: net::ERR_EMPTY_RESPONSE at http://example.com/\nCall log:\n  - navigating",
            "connexion fermée sans réponse",
        ),
        ("Page.goto: net::ERR_CONNECTION_REFUSED at https://example.com/", "connexion refusée"),
        ("Page.goto: Timeout 15000ms exceeded.\nCall log:", "délai de navigation dépassé (15 s)"),
        (
            "Page.goto: net::ERR_TUNNEL_CONNECTION_FAILED at https://autre.example/",
            "connexion HTTPS refusée par le proxy de capture (hôte bloqué ou injoignable)",
        ),
        # Tunnel refusé par le proxy : sa cause exacte, pour l'hôte et le port concernés.
        (
            "Page.goto: net::ERR_TUNNEL_CONNECTION_FAILED at https://example.com/",
            "connexion impossible au port 443 (délai dépassé)",
        ),
        # Code inconnu : première ligne du message, telle quelle.
        (
            "Page.goto: net::ERR_INCONNU at https://example.com/\nCall log:",
            "Page.goto: net::ERR_INCONNU at https://example.com/",
        ),
    ],
)
def test_echecs_de_navigation_expliques_en_francais(message, attendu):
    proxy = screenshot._FilteringProxy(screenshot._NetworkGuard())
    proxy._upstream_errors[("example.com", 443)] = msg(
        "screenshot.connect_failed", port=443, error=msg("net.timeout")
    )
    assert fr(screenshot._navigation_failure(Exception(message), "https://example.com/", proxy)) == attendu


@pytest.mark.parametrize(
    "error, attendu",
    [
        (asyncio.TimeoutError(), "délai dépassé"),
        (TimeoutError("timed out"), "délai dépassé"),
        (ConnectionRefusedError(10061, "Connexion refusée par le système"), "connexion refusée"),
        (OSError(113, "No route to host"), "No route to host"),
    ],
)
def test_cause_d_une_connexion_impossible(error, attendu):
    assert fr(screenshot._connect_error_text(error)) == attendu


@pytest.fixture(scope="module")
def chromium():
    """Saute les tests avec un vrai Chromium si Playwright ou Chromium n'est pas installé."""
    playwright_api = pytest.importorskip("playwright.async_api")

    async def probe():
        async with playwright_api.async_playwright() as p:
            browser = await p.chromium.launch(headless=True)
            await browser.close()

    try:
        asyncio.run(probe())
    except Exception as e:
        pytest.skip(f"Chromium indisponible : {e}")


def test_capture_d_un_site_injoignable_avec_le_vrai_chromium(
    chromium, unreachable_port, monkeypatch, tmp_path
):
    """Régression (testphp.vulnweb.com) : « net::ERR_TUNNEL_CONNECTION_FAILED » et
    « net::ERR_EMPTY_RESPONSE » bruts. Chromium affiche le 502 du proxy en http :
    il ne doit pas être capturé comme la page du site."""

    async def ensure(host):
        return ["127.0.0.1"]

    monkeypatch.setattr(screenshot, "ensure_target_allowed", ensure)
    host = f"injoignable.invalid:{unreachable_port}"
    monkeypatch.setattr(screenshot, "_capture_urls", lambda domain: [f"https://{host}/", f"http://{host}/"])

    with pytest.raises(ModuleError) as excinfo:
        asyncio.run(screenshot.capture_screenshot("injoignable.invalid", str(tmp_path)))

    cause = f"connexion impossible au port {unreachable_port} (délai dépassé)"
    assert str(excinfo.value) == (
        f"Capture d'écran impossible : https://{host}/ : {cause} ; http://{host}/ : {cause}"
    )
    assert list(tmp_path.iterdir()) == []


# =============================================================================
# Chromium absent ou impossible à lancer
# =============================================================================

_MISSING_BROWSER = (
    "BrowserType.launch: Executable doesn't exist at "
    "C:\\Users\\alice\\AppData\\Local\\ms-playwright\\chromium_headless_shell-1187\\chrome-headless-shell.exe\n"
    "╔════════════════════════════════════════════════════════════╗\n"
    "║ Looks like Playwright was just installed or updated.       ║\n"
    "║ Please run the following command to download new browsers: ║\n"
    "║     playwright install                                     ║\n"
    "╚════════════════════════════════════════════════════════════╝"
)


def test_chromium_absent_capture_ignoree(monkeypatch, public_target, tmp_path, caplog):
    """Sans navigateur, la capture est ignorée (None → « skipped ») : le scan n'est pas partiel."""
    _fake_playwright(monkeypatch, Exception(_MISSING_BROWSER))

    with caplog.at_level(logging.WARNING, logger="domainrecon.scanner"):
        assert asyncio.run(screenshot.capture_screenshot("example.com", str(tmp_path))) is None

    assert list(tmp_path.iterdir()) == []
    # Chemin local et commande d'installation : dans les journaux du serveur seulement.
    assert "chrome-headless-shell.exe" in caplog.text
    assert "playwright install --only-shell chromium" in caplog.text


def test_chromium_impossible_a_lancer_sans_chemin_local(monkeypatch, public_target, tmp_path, caplog):
    _fake_playwright(
        monkeypatch,
        Exception(
            "BrowserType.launch: Host system is missing dependencies to run browsers.\n"
            "Missing libraries: libnss3.so (/home/domainrecon/.cache/ms-playwright/chromium-1187/chrome)"
        ),
    )

    with caplog.at_level(logging.WARNING, logger="domainrecon.scanner"):
        with pytest.raises(ModuleError) as excinfo:
            asyncio.run(screenshot.capture_screenshot("example.com", str(tmp_path)))

    message = str(excinfo.value)
    assert "Chromium" in message and "journaux" in message
    assert "/home/" not in message and "ms-playwright" not in message
    assert "missing dependencies" in caplog.text


def test_boucle_sans_sous_processus_message_explicite(monkeypatch, public_target, tmp_path):
    """uvicorn --reload sous Windows : le pilote ne démarre pas (NotImplementedError sans message)."""

    class Manager:
        async def __aenter__(self):
            raise NotImplementedError

        async def __aexit__(self, *exc_info):
            return False

    module = types.ModuleType("playwright.async_api")
    module.async_playwright = Manager
    monkeypatch.setitem(sys.modules, "playwright.async_api", module)

    with pytest.raises(ModuleError) as excinfo:
        asyncio.run(screenshot.capture_screenshot("example.com", str(tmp_path)))
    assert "sous-processus" in str(excinfo.value)
    assert "domainrecon --server" in str(excinfo.value)
    assert list(tmp_path.iterdir()) == []


@pytest.mark.skipif(
    sys.platform != "win32" or sys.version_info < (3, 11),
    reason="SelectorEventLoop sans sous-processus : Windows seulement (asyncio.Runner : Python 3.11+)",
)
def test_boucle_sans_sous_processus_avec_le_vrai_playwright(public_target, tmp_path):
    """La vraie SelectorEventLoop de Windows (celle d'uvicorn --reload) donne le message explicite."""
    pytest.importorskip("playwright.async_api")

    with pytest.raises(ModuleError, match="sous-processus"):
        with asyncio.Runner(loop_factory=asyncio.SelectorEventLoop) as runner:
            runner.run(screenshot.capture_screenshot("example.com", str(tmp_path)))


def test_chromium_absent_detecte_avec_le_vrai_playwright(monkeypatch, public_target, tmp_path):
    """Le message réel de Playwright (dossier de navigateurs vide) est bien reconnu."""
    pytest.importorskip("playwright.async_api")
    browsers = tmp_path / "navigateurs"
    browsers.mkdir()
    monkeypatch.setenv("PLAYWRIGHT_BROWSERS_PATH", str(browsers))
    captures = tmp_path / "captures"

    assert asyncio.run(screenshot.capture_screenshot("example.com", str(captures))) is None
    assert list(captures.iterdir()) == []
