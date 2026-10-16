# =============================================================================
# DomainRecon - Scanner : capture d'écran (Playwright)
# =============================================================================
# Chromium tourne côté serveur : il ne doit atteindre que des cibles
# autorisées par la politique de cibles (targets.py). Deux barrières :
#
# 1. `context.route("**/*")` interrompt tout de suite les requêtes vers un
#    hôte refusé et tout schéma autre que http, https, data ou blob.
# 2. Un proxy HTTP local, imposé à Chromium, porte TOUTES ses connexions
#    sortantes, y compris celles que `route` ne voit pas (cible d'une
#    redirection HTTP, préconnexions…). Il résout l'hôte, applique la
#    politique puis se connecte à l'adresse validée : Chromium ne fait aucune
#    résolution DNS lui-même, ce qui neutralise le DNS rebinding.
#
# Les hôtes demandés par la page sont résolus sur un pool dédié, en nombre
# limité : une page hostile ne peut pas accaparer l'exécuteur par défaut.
# Les service workers et les WebSockets, inutiles pour une capture, sont bloqués.
#
# Proxy sortant (Réglages, sinon variables HTTPS_PROXY… : voir proxy.py) : le
# proxy filtrant s'y connecte au lieu de joindre les sites directement, vers
# l'adresse qu'il a validée. Chromium garde le proxy filtrant pour seul proxy :
# les deux barrières restent entières.
# =============================================================================

import asyncio
import re
import secrets
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlsplit

from ..core import config
from ..core.settings_store import is_valid_proxy_url
from ..i18n import msg, render
from .common import current_scan_proxy, logger, url_host
from .errors import ModuleError, ProxyError, TargetNotAllowedError
from .proxy import get_proxy_url, open_tunnel
from .targets import RESOLVE_TIMEOUT, _lookup, ensure_ip_allowed, ensure_target_allowed

# Dossier des captures : fourni par la configuration centralisée (DATA_DIR).
SCREENSHOTS_DIR = config.SCREENSHOTS_DIR

# Noms produits par screenshot_filename() : slug, horodatage, suffixe aléatoire.
# Les captures antérieures (sans suffixe) restent reconnues.
SCREENSHOT_NAME_RE = re.compile(r"^[a-z0-9_-]{1,100}_\d+(?:_[0-9a-f]{8})?\.png\Z")
_SLUG_MAX_LENGTH = 100

# Délais de la capture, en millisecondes.
SCREENSHOT_NAV_TIMEOUT_MS = 15000
SCREENSHOT_SETTLE_MS = 2000

_NETWORK_SCHEMES = ("http", "https")
# Contenu local au navigateur, sans accès réseau.
_LOCAL_SCHEMES = ("data", "blob")

# Arguments Chromium :
# - aucune résolution DNS locale : tout nom passe par le proxy, qui l'épingle
#   (l'adresse du proxy lui-même doit être exclue de la règle) ;
# - pas d'UDP WebRTC hors proxy (il contournerait le filtre).
_PROXY_HOST = "127.0.0.1"
_CHROMIUM_ARGS = [
    f"--host-resolver-rules=MAP * ~NOTFOUND , EXCLUDE {_PROXY_HOST}",
    "--force-webrtc-ip-handling-policy=disable_non_proxied_udp",
]

# Proxy local : délais (s) et taille maximale d'un en-tête HTTP.
_PROXY_HEAD_TIMEOUT = 30.0
_PROXY_CONNECT_TIMEOUT = 10.0
# En-tête des réponses 502 du proxy lui-même (site injoignable), avec un jeton
# propre à chaque capture : une réponse du site ne peut pas l'imiter.
_PROXY_ERROR_HEADER = "x-domainrecon-proxy-error"
# Délai de fermeture d'une connexion : au-delà, elle est abandonnée (abort).
_PROXY_CLOSE_TIMEOUT = 2.0
_PROXY_HEAD_LIMIT = 64 * 1024
_PROXY_CHUNK_SIZE = 64 * 1024
# En-têtes propres au saut client <-> proxy, jamais retransmis.
_HOP_BY_HOP_HEADERS = {b"connection", b"proxy-connection", b"keep-alive", b"proxy-authorization"}

# Hôtes distincts qu'une page peut faire résoudre pendant une capture : au-delà,
# toute requête vers un nouvel hôte est bloquée.
_GUARD_MAX_HOSTS = 50
# Pool dédié aux résolutions demandées par la page, comme _RESOLVER_POOL
# (targets.py) : des centaines de noms dont le DNS ne répond pas ne doivent pas
# occuper l'exécuteur par défaut, partagé avec les contrôles de cible des
# autres scans, TLS, WHOIS et httpx.
_GUARD_DNS_POOL = ThreadPoolExecutor(max_workers=4, thread_name_prefix="domainrecon-capture-dns")

# Message de Playwright quand le navigateur n'a pas été téléchargé.
_BROWSER_MISSING_MARKER = "executable doesn't exist"

# Le pilote de Playwright est un sous-processus : la boucle asyncio doit savoir
# en lancer, ce que ne sait pas la SelectorEventLoop de Windows, choisie par
# uvicorn --reload (NotImplementedError sans message).
_NO_SUBPROCESS_MESSAGE = msg("screenshot.no_subprocess")


# =============================================================================
# Module 19 : Screenshot Capture (Playwright)
# =============================================================================


def screenshot_filename(domain: str) -> str:
    """Nom de fichier sûr et unique pour une capture (jamais de séparateur de chemin).

    Le suffixe aléatoire évite que deux scans lancés dans la même seconde
    partagent un fichier (supprimer l'un effacerait la capture de l'autre).
    """
    slug = re.sub(r"[^a-z0-9_-]", "_", domain.lower())[:_SLUG_MAX_LENGTH] or "capture"
    timestamp = int(datetime.now(timezone.utc).timestamp())
    return f"{slug}_{timestamp}_{secrets.token_hex(4)}.png"


def _capture_urls(domain: str) -> list[str]:
    """URL tentées, dans l'ordre (point d'injection pour les tests)."""
    host = url_host(domain)
    return [f"https://{host}/", f"http://{host}/"]


def _first_line(error: BaseException) -> str:
    text = str(error).strip()
    return text.splitlines()[0] if text else type(error).__name__


# Codes d'erreur réseau de Chromium (« net::ERR_… at URL ») les plus courants
# lors d'une capture.
_NET_ERROR_RE = re.compile(r"net::(ERR_[A-Z0-9_]+)(?: at (\S+))?")
_NAV_TIMEOUT_RE = re.compile(r"Timeout (\d+)ms exceeded")


def _net_error_reason(code: str) -> dict | None:
    """Raison traduisible d'un code d'erreur réseau de Chromium, ou None."""
    reasons = {
        "ERR_EMPTY_RESPONSE": msg("screenshot.net_empty_response"),
        "ERR_TUNNEL_CONNECTION_FAILED": msg("screenshot.net_tunnel_failed"),
        "ERR_CONNECTION_REFUSED": msg("net.connection_refused"),
        "ERR_CONNECTION_RESET": msg("screenshot.net_connection_reset"),
        "ERR_CONNECTION_CLOSED": msg("screenshot.net_connection_closed"),
        "ERR_CONNECTION_TIMED_OUT": msg("screenshot.net_connection_timed_out"),
        "ERR_TIMED_OUT": msg("net.timeout"),
        "ERR_NAME_NOT_RESOLVED": msg("screenshot.net_name_not_resolved"),
        "ERR_ADDRESS_UNREACHABLE": msg("screenshot.net_address_unreachable"),
        "ERR_BLOCKED_BY_CLIENT": msg("screenshot.net_blocked"),
        "ERR_ABORTED": msg("screenshot.net_aborted"),
        "ERR_TOO_MANY_REDIRECTS": msg("screenshot.net_too_many_redirects"),
        "ERR_INVALID_RESPONSE": msg("screenshot.net_invalid_response"),
        "ERR_SSL_PROTOCOL_ERROR": msg("screenshot.net_ssl_protocol"),
        "ERR_SSL_VERSION_OR_CIPHER_MISMATCH": msg("screenshot.net_ssl_mismatch"),
    }
    return reasons.get(code)


def _connect_error_text(error: BaseException | None) -> object:
    """Cause lisible (traduisible) de l'échec d'une connexion sortante du proxy."""
    # Avant OSError : TimeoutError en hérite (asyncio.TimeoutError aussi, en 3.11+).
    if isinstance(error, (asyncio.TimeoutError, TimeoutError)):
        return msg("net.timeout")
    if isinstance(error, ConnectionRefusedError):
        return msg("net.connection_refused")
    if isinstance(error, OSError) and error.strerror:
        return error.strerror
    return _first_line(error) if error is not None else msg("screenshot.no_address")


class _UpstreamUnreachable(ModuleError):
    """Réponse 502 du proxy de capture : le site n'a pas pu être joint."""


async def _page_host_addresses(host: str) -> list[str]:
    """Contrôle d'ensure_target_allowed() pour un hôte demandé par la page.

    La résolution passe par _GUARD_DNS_POOL ; chaque adresse est ensuite
    validée par ensure_ip_allowed() (même politique). Lève
    TargetNotAllowedError si l'une d'elles est refusée.
    """
    addresses = await _lookup(host, RESOLVE_TIMEOUT, _GUARD_DNS_POOL)
    return [ensure_ip_allowed(address) for address in addresses]


class _NetworkGuard:
    """Politique de cibles appliquée aux requêtes de Chromium.

    Chaque hôte est résolu et validé une seule fois par capture : le filtre
    `route` et le proxy utilisent les mêmes adresses, et des requêtes
    simultanées vers un même hôte attendent la même résolution. Au-delà de
    _GUARD_MAX_HOSTS hôtes distincts, tout nouvel hôte est bloqué.
    """

    def __init__(self) -> None:
        self._addresses: dict[str, list[str]] = {}
        self._pending: dict[str, asyncio.Task] = {}
        self._limit_reached = False
        self.blocked: list[str] = []

    def remember(self, host: str, addresses: list[str]) -> None:
        self._addresses[host] = list(addresses)

    def _block(self, host: str) -> None:
        # Liste bornée : elle ne sert qu'au message d'erreur de la capture.
        if len(self.blocked) < _GUARD_MAX_HOSTS and host not in self.blocked:
            self.blocked.append(host)

    async def addresses_for(self, host: str) -> list[str]:
        """Adresses validées de `host`, ou `[]` si l'hôte est refusé ou ne résout pas."""
        if host in self._addresses:
            return self._addresses[host]
        task = self._pending.get(host)
        if task is None:
            if len(self._addresses) + len(self._pending) >= _GUARD_MAX_HOSTS:
                if not self._limit_reached:
                    self._limit_reached = True
                    logger.info(
                        "Capture : plus de %d hôtes distincts, les suivants sont bloqués", _GUARD_MAX_HOSTS
                    )
                self._block(host)
                return []
            task = asyncio.ensure_future(self._resolve(host))
            self._pending[host] = task
        # shield : une requête annulée n'interrompt pas la résolution partagée.
        return await asyncio.shield(task)

    async def _resolve(self, host: str) -> list[str]:
        try:
            try:
                addresses = await _page_host_addresses(host)
            except TargetNotAllowedError:
                addresses = []
            if not addresses:
                self._block(host)
                logger.info("Capture : hôte bloqué ou non résolu : %s", host[:200])
            self._addresses[host] = addresses
            return addresses
        finally:
            self._pending.pop(host, None)

    def cancel_pending(self) -> None:
        """Annule les résolutions encore en cours (fin de la capture)."""
        for task in list(self._pending.values()):
            task.cancel()

    async def url_allowed(self, url: str) -> bool:
        try:
            parts = urlsplit(url)
            scheme = parts.scheme.lower()
            host = parts.hostname or ""
        except ValueError:
            return False
        if scheme in _LOCAL_SCHEMES:
            return True
        if scheme not in _NETWORK_SCHEMES or not host:
            return False
        return bool(await self.addresses_for(host))

    async def handle_route(self, route, request) -> None:
        """Handler `context.route("**/*")` : laisse passer ou interrompt la requête."""
        try:
            allowed = await self.url_allowed(request.url)
        except Exception as e:
            logger.debug("Capture : contrôle de %s impossible (%s)", request.url[:200], e)
            allowed = False
        try:
            if allowed:
                await route.continue_()
            else:
                await route.abort("blockedbyclient")
        except Exception as e:
            # Page ou contexte fermés entre-temps : rien à faire.
            logger.debug("Capture : routage de %s interrompu (%s)", request.url[:200], e)


class _ProxyRefused(Exception):
    """Requête refusée par le proxy (hôte non autorisé ou requête invalide)."""


def _rewrite_head(first_line: bytes, header_block: bytes) -> bytes:
    """En-tête HTTP sans les en-têtes de saut, avec `Connection: close`.

    Une requête par connexion : Chromium ne réutilise pas la connexion au
    proxy pour un autre hôte, qui échapperait sinon au contrôle.
    """
    lines = [first_line]
    for line in header_block.split(b"\r\n"):
        name = line.split(b":", 1)[0].strip().lower()
        if line and name not in _HOP_BY_HOP_HEADERS:
            lines.append(line)
    lines.append(b"Connection: close")
    return b"\r\n".join(lines) + b"\r\n\r\n"


async def _pipe(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
    while True:
        data = await reader.read(_PROXY_CHUNK_SIZE)
        if not data:
            return
        writer.write(data)
        await writer.drain()


async def _close_writer(writer: asyncio.StreamWriter | None) -> None:
    """Ferme une connexion du proxy en au plus _PROXY_CLOSE_TIMEOUT.

    Face à un pair qui ne lit plus (fenêtre TCP à zéro), le tampon d'écriture
    ne se vide jamais et wait_closed() ne rendrait pas la main : la fin de la
    capture, donc le scan, resterait bloquée. La connexion est alors abandonnée
    (abort). Pas d'abort d'emblée : il tronquerait la fin des réponses normales.
    """
    if writer is None:
        return
    writer.close()
    try:
        await asyncio.wait_for(writer.wait_closed(), timeout=_PROXY_CLOSE_TIMEOUT)
    except (asyncio.TimeoutError, TimeoutError):
        writer.transport.abort()
    except asyncio.CancelledError:
        writer.transport.abort()
        raise
    except Exception:
        pass


class _FilteringProxy:
    """Proxy HTTP local (CONNECT et requêtes absolues) imposé à Chromium.

    Chaque connexion vers l'extérieur est validée par `_NetworkGuard` puis
    ouverte vers l'adresse validée. Un site autorisé mais injoignable reçoit
    une réponse 502 marquée (_PROXY_ERROR_HEADER), jamais une connexion fermée
    sans réponse, que Chromium présenterait comme une réponse vide du site.

    Avec `upstream` (URL du proxy sortant), chaque connexion passe par lui :
    tunnel CONNECT ou SOCKS5 vers l'adresse validée, jamais vers le nom.
    """

    def __init__(self, guard: _NetworkGuard, upstream: str | None = None) -> None:
        self._guard = guard
        self._upstream = upstream
        self._server: asyncio.AbstractServer | None = None
        self._connections: set[asyncio.Task] = set()
        self._token = secrets.token_hex(8)
        # Cause de chaque connexion impossible, par (hôte, port).
        self._upstream_errors: dict[tuple[str, int], object] = {}

    def _bad_gateway(self) -> bytes:
        return (
            b"HTTP/1.1 502 Bad Gateway\r\n"
            + f"{_PROXY_ERROR_HEADER}: {self._token}\r\n".encode("ascii")
            + b"Content-Length: 0\r\nConnection: close\r\n\r\n"
        )

    def upstream_error(self, url: str) -> object | None:
        """Cause de l'échec de connexion du proxy vers l'hôte et le port de `url`, s'il y en a eu un."""
        try:
            parts = urlsplit(url)
            port = parts.port or (443 if parts.scheme.lower() == "https" else 80)
        except ValueError:
            return None
        return self._upstream_errors.get((parts.hostname or "", port))

    def is_own_error(self, headers: dict) -> bool:
        """Vrai si la réponse est le 502 du proxy lui-même, pas celle du site."""
        return headers.get(_PROXY_ERROR_HEADER) == self._token

    async def start(self) -> str:
        """Démarre le proxy sur un port libre de 127.0.0.1 et renvoie son URL."""
        self._server = await asyncio.start_server(self._handle, _PROXY_HOST, 0, limit=_PROXY_HEAD_LIMIT)
        port = self._server.sockets[0].getsockname()[1]
        return f"http://{_PROXY_HOST}:{port}"

    async def close(self) -> None:
        """Arrête le proxy et ses connexions, en temps borné."""
        if self._server is None:
            return
        self._server.close()
        connections = list(self._connections)
        for task in connections:
            task.cancel()
        if connections:
            # Une connexion annulée se ferme en au plus 2 × _PROXY_CLOSE_TIMEOUT
            # (voir _close_writer) ; au-delà, elle est annulée de nouveau, sans
            # être attendue davantage.
            _, pending = await asyncio.wait(connections, timeout=3 * _PROXY_CLOSE_TIMEOUT)
            for task in pending:
                task.cancel()
        try:
            await asyncio.wait_for(self._server.wait_closed(), timeout=_PROXY_CLOSE_TIMEOUT)
        except (asyncio.TimeoutError, TimeoutError):
            logger.debug("Proxy de capture : connexions encore ouvertes à l'arrêt")

    async def _connect(self, host: str, port: int):
        addresses = await self._guard.addresses_for(host)
        if not addresses:
            raise _ProxyRefused(host)
        last_error: BaseException | None = None
        # IPv4 d'abord (comme primary_address) : une IPv6 injoignable coûterait
        # jusqu'à _PROXY_CONNECT_TIMEOUT avant le repli.
        for address in sorted(addresses, key=lambda a: ":" in a):
            if self._upstream is None:
                connection = asyncio.open_connection(address, port, limit=_PROXY_HEAD_LIMIT)
            else:
                connection = open_tunnel(self._upstream, address, port, limit=_PROXY_HEAD_LIMIT)
            try:
                return await asyncio.wait_for(connection, timeout=_PROXY_CONNECT_TIMEOUT)
            except (OSError, asyncio.TimeoutError) as e:
                last_error = e
        if isinstance(last_error, ProxyError):
            # Le proxy sortant n'a pas joint le site : sa cause vaut mieux que « connexion impossible ».
            reason = last_error.message
        else:
            reason = msg("screenshot.connect_failed", port=port, error=_connect_error_text(last_error))
        self._upstream_errors[(host, port)] = reason
        raise OSError(f"{host} : {render(reason, 'fr')}")

    async def _handle(self, client_reader: asyncio.StreamReader, client_writer: asyncio.StreamWriter) -> None:
        task = asyncio.current_task()
        if task is not None:
            self._connections.add(task)
            task.add_done_callback(self._connections.discard)
        upstream_writer = None
        is_connect = False
        try:
            head = await asyncio.wait_for(client_reader.readuntil(b"\r\n\r\n"), timeout=_PROXY_HEAD_TIMEOUT)
            request_line, _, header_block = head[:-4].partition(b"\r\n")
            method, target, version = request_line.decode("latin-1").split(" ")
            is_connect = method.upper() == "CONNECT"

            if is_connect:
                # « CONNECT hôte:port » : tunnel TLS (https, wss).
                parts = urlsplit(f"//{target}")
                host, port = parts.hostname or "", parts.port or 443
            else:
                # « GET http://hôte:port/chemin » : requête http en clair.
                parts = urlsplit(target)
                if parts.scheme.lower() != "http" or not parts.hostname:
                    raise _ProxyRefused(target[:200])
                host, port = parts.hostname, parts.port or 80
                path = (parts.path or "/") + (f"?{parts.query}" if parts.query else "")
            try:
                upstream_reader, upstream_writer = await self._connect(host, port)
            except OSError:
                # Hôte autorisé mais injoignable : réponse explicite. Chromium
                # signale un échec de tunnel (https) ou reçoit ce 502 marqué
                # (http), au lieu d'une réponse vide attribuée au site.
                client_writer.write(self._bad_gateway())
                await client_writer.drain()
                raise
            if is_connect:
                client_writer.write(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                await client_writer.drain()
            else:
                upstream_writer.write(
                    _rewrite_head(f"{method} {path} {version}".encode("latin-1"), header_block)
                )
                await upstream_writer.drain()

            await self._relay(client_reader, client_writer, upstream_reader, upstream_writer, is_connect)
        except _ProxyRefused:
            if is_connect:
                client_writer.write(
                    b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                )
                try:
                    await client_writer.drain()
                except OSError:
                    pass
            # Requête http refusée : connexion fermée sans réponse (échec côté Chromium).
        except (
            OSError,
            EOFError,
            ValueError,
            UnicodeError,
            asyncio.TimeoutError,
            asyncio.LimitOverrunError,
        ) as e:
            logger.debug("Proxy de capture : connexion interrompue (%s)", e)
        finally:
            # Les deux connexions sont fermées, même si l'annulation (fin de la
            # capture) interrompt la première fermeture.
            try:
                await _close_writer(upstream_writer)
            finally:
                await _close_writer(client_writer)

    @staticmethod
    async def _relay(
        client_reader, client_writer, upstream_reader, upstream_writer, is_connect: bool
    ) -> None:
        """Relaie les deux sens jusqu'à la fermeture de l'un d'eux."""

        async def upstream_to_client() -> None:
            if not is_connect:
                head = await upstream_reader.readuntil(b"\r\n\r\n")
                status_line, _, header_block = head[:-4].partition(b"\r\n")
                client_writer.write(_rewrite_head(status_line, header_block))
                await client_writer.drain()
            await _pipe(upstream_reader, client_writer)

        tasks = [
            asyncio.ensure_future(_pipe(client_reader, upstream_writer)),
            asyncio.ensure_future(upstream_to_client()),
        ]
        try:
            done, _ = await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
            for finished in done:
                finished.result()
        finally:
            for pending in tasks:
                pending.cancel()
            await asyncio.gather(*tasks, return_exceptions=True)


def _navigation_failure(error: BaseException, url: str, proxy: _FilteringProxy) -> object:
    """Cause lisible de l'échec d'une tentative de capture de `url`."""
    if isinstance(error, _UpstreamUnreachable):
        return error.message
    text = str(error)
    match = _NET_ERROR_RE.search(text)
    if match:
        code = match.group(1)
        # Tunnel refusé par le proxy : il connaît la cause exacte.
        if code == "ERR_TUNNEL_CONNECTION_FAILED":
            reason = proxy.upstream_error(match.group(2) or url)
            if reason:
                return reason
        reason = _net_error_reason(code)
        if reason is not None:
            return reason
    timeout = _NAV_TIMEOUT_RE.search(text)
    if timeout:
        return msg("screenshot.nav_timeout", seconds=f"{int(timeout.group(1)) / 1000:g}")
    return _first_line(error)


async def _refuse_websocket(ws) -> None:
    """Handler `context.route_web_socket` : aucune WebSocket n'est ouverte."""
    try:
        await ws.close(code=1008, reason="Bloqué par DomainRecon")
    except Exception as e:
        logger.debug("Capture : fermeture de WebSocket interrompue (%s)", e)


async def capture_screenshot(domain: str, output_dir: str, outbound_proxy: str | None = None) -> str | None:
    """Capture un screenshot de la page d'accueil du domaine.

    Renvoie le nom du fichier, ou None si Playwright ou son navigateur
    Chromium n'est pas installé (capture ignorée). Lève
    `TargetNotAllowedError` si la cible n'est pas autorisée, et `ModuleError`
    si la capture a échoué.

    `outbound_proxy` : proxy sortant (http, https, socks5 ou socks5h) derrière lequel
    le proxy filtrant joint les sites ; None : pendant un scan, celui que
    l'orchestrateur a lu au départ (common.scan_proxy) ; hors scan, celui des
    Réglages ou de l'environnement (proxy.get_proxy_url) ; « » : aucun. Une URL
    de proxy invalide fait échouer la capture, sans repli vers une connexion directe.
    """
    try:
        from playwright.async_api import async_playwright
    except ImportError:
        logger.info("Playwright non installé — capture d'écran ignorée")
        return None

    guard = _NetworkGuard()
    # Refus immédiat d'une cible non autorisée, avant même de lancer Chromium.
    addresses = await ensure_target_allowed(domain)
    if not addresses:
        raise ModuleError(msg("screenshot.no_ip", domain=domain))
    guard.remember(domain, addresses)
    if outbound_proxy is not None:
        upstream = outbound_proxy
    elif (in_scan := current_scan_proxy()) is not None:
        # Pendant un scan : le proxy lu une seule fois par l'orchestrateur, le même pour tous les modules.
        upstream = in_scan.url
    else:
        # Lecture des Réglages hors de la boucle d'événements.
        upstream = await asyncio.to_thread(get_proxy_url)
    if upstream and not is_valid_proxy_url(upstream):
        raise ModuleError(msg("api.settings_invalid_proxy"))

    out = Path(output_dir)
    out.mkdir(parents=True, exist_ok=True)
    filename = screenshot_filename(domain)
    filepath = out / filename
    failures: list[object] = []

    proxy = _FilteringProxy(guard, upstream or None)
    proxy_url = await proxy.start()
    try:
        async with async_playwright() as p:
            try:
                browser = await p.chromium.launch(
                    headless=True,
                    # « <-loopback> » : même localhost passe par le proxy.
                    proxy={"server": proxy_url, "bypass": "<-loopback>"},
                    args=_CHROMIUM_ARGS,
                )
            except Exception as e:
                # Le message de Playwright contient le chemin local du
                # navigateur : il ne va que dans les journaux du serveur.
                if _BROWSER_MISSING_MARKER in str(e).lower():
                    logger.warning(
                        "Chromium (Playwright) n'est pas installé — capture d'écran ignorée. "
                        "Exécutez « python -m playwright install --only-shell chromium ». Détail : %s",
                        e,
                    )
                    return None
                logger.warning("Chromium n'a pas pu démarrer : %s", e)
                raise ModuleError(msg("screenshot.chromium_failed")) from e
            try:
                context = await browser.new_context(
                    viewport={"width": 1280, "height": 720},
                    # Cohérent avec VERIFY_TLS=False : un certificat invalide est
                    # mesuré par le module TLS, il ne doit pas empêcher la capture.
                    ignore_https_errors=True,
                    # Les requêtes d'un service worker échapperaient au routage.
                    service_workers="block",
                    accept_downloads=False,
                )
                await context.route("**/*", guard.handle_route)
                if hasattr(context, "route_web_socket"):  # Playwright >= 1.48
                    await context.route_web_socket("**/*", _refuse_websocket)
                for url in _capture_urls(domain):
                    # Page neuve à chaque tentative : après un échec, la page
                    # d'erreur de Chromium (chrome-error://) se charge encore et
                    # interromprait la navigation suivante (repli http d'un
                    # site sans HTTPS).
                    page = await context.new_page()
                    try:
                        response = await page.goto(
                            url, wait_until="domcontentloaded", timeout=SCREENSHOT_NAV_TIMEOUT_MS
                        )
                        # 502 du proxy (site injoignable) : rien à capturer.
                        if response is not None and proxy.is_own_error(response.headers):
                            reason = proxy.upstream_error(response.url) or msg("screenshot.site_unreachable")
                            raise _UpstreamUnreachable(reason)
                        await page.wait_for_timeout(SCREENSHOT_SETTLE_MS)
                        await page.screenshot(path=str(filepath), full_page=False)
                        return filename
                    except Exception as e:
                        logger.debug("Capture %s échouée: %s", url, e)
                        failures.append(
                            msg("screenshot.attempt", url=url, error=_navigation_failure(e, url, proxy))
                        )
                        try:
                            await page.close()
                        except Exception as close_error:
                            logger.debug("Capture : fermeture de page interrompue (%s)", close_error)
            finally:
                await browser.close()
    except NotImplementedError as e:
        logger.warning(
            "Playwright ne peut pas démarrer son pilote : boucle %s sans sous-processus",
            type(asyncio.get_running_loop()).__name__,
        )
        raise ModuleError(_NO_SUBPROCESS_MESSAGE) from e
    finally:
        try:
            await proxy.close()
        finally:
            guard.cancel_pending()

    logger.warning("Capture d'écran impossible pour %s", domain)
    if guard.blocked:
        hosts = ", ".join(guard.blocked[:5])
        raise ModuleError(msg("screenshot.failed_blocked", hosts=hosts, errors=failures))
    raise ModuleError(msg("screenshot.failed", errors=failures))
