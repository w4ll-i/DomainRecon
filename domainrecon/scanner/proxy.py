# =============================================================================
# DomainRecon - Scanner : proxy sortant (HTTP ou SOCKS)
# =============================================================================
# Un seul proxy pour tout le scanner :
#
#   - get_proxy_url()    : le proxy à utiliser, lu au moment de l'appel ;
#   - make_http_client() : client HTTP des modules, qui l'emprunte ;
#   - open_tunnel()      : connexion TCP à travers lui, pour le proxy filtrant
#                          local de la capture d'écran (screenshot.py).
#
# Schémas acceptés : http, https, socks5 et socks5h (voir
# settings_store.PROXY_SCHEMES). SOCKS demande le paquet socksio côté httpx.
# Les requêtes DNS directes (dnspython), WHOIS, le scan de ports et la sonde TLS
# n'y passent pas.
#
# Les identifiants d'un proxy (http://utilisateur:mot de passe@hôte) ne sont
# jamais écrits dans les journaux ni dans les messages.
# =============================================================================

import asyncio
import base64
import ipaddress
import ssl
from urllib.parse import unquote, urlsplit

import httpx
from sqlalchemy.exc import SQLAlchemyError

from ..core.database import SessionLocal
from ..core.models import Settings
from ..core.settings_store import SETTINGS_ID, read_secret
from ..i18n import msg
from .common import USER_AGENT, _environment_proxies, _guarded_client, logger
from .errors import ProxyError

# Délai par défaut d'une requête des clients de make_http_client, en secondes.
DEFAULT_TIMEOUT = 10.0

# Taille maximale (octets) d'une ligne lue sur une connexion ouverte par
# open_tunnel : celle du proxy filtrant de la capture d'écran.
STREAM_LIMIT = 64 * 1024

# Port d'un proxy dont l'URL n'en indique pas.
_DEFAULT_PORTS = {"http": 80, "https": 443, "socks5": 1080, "socks5h": 1080}


# =============================================================================
# Proxy à utiliser
# =============================================================================


def _stored_proxy_url() -> str | None:
    """Proxy des Réglages (colonne proxy_url), en clair ; None si aucun ou si la base est illisible."""
    try:
        with SessionLocal() as db:
            row = db.get(Settings, SETTINGS_ID)
            value = read_secret(row, "proxy_url") if row is not None else ""
    except SQLAlchemyError as e:
        # Une base indisponible ne doit pas empêcher de lire l'environnement :
        # le scan part alors avec celui-ci, ou sans proxy.
        logger.warning("Proxy des Réglages illisible (%s) : repli sur l'environnement", type(e).__name__)
        return None
    return value.strip() or None


def _environment_proxy_url() -> str | None:
    """Proxy de l'environnement (HTTPS_PROXY, puis HTTP_PROXY, puis ALL_PROXY) ; NO_PROXY=* le désactive.

    Même lecture que les clients HTTP du scanner (common._environment_proxies),
    schéma http:// ajouté à une valeur « hôte:port » comprise. Les exclusions
    par hôte de NO_PROXY ne s'appliquent pas : un seul proxy sert à tout.
    """
    proxies = _environment_proxies()
    if "*" in (name.strip() for name in proxies.get("no", "").split(",")):
        return None
    return proxies.get("https") or proxies.get("http") or proxies.get("all")


def get_proxy_url() -> str | None:
    """Proxy sortant à utiliser, ou None (connexion directe).

    Le réglage `proxy_url` des Réglages l'emporte (lu en base, déchiffré s'il
    l'était) ; à défaut, les variables HTTPS_PROXY, HTTP_PROXY ou ALL_PROXY.
    Lecture synchrone de la base : depuis une coroutine, passer par
    `asyncio.to_thread(get_proxy_url)`. Le résultat contient d'éventuels
    identifiants en clair : à ne jamais journaliser (settings_store.mask_proxy_url).
    """
    return _stored_proxy_url() or _environment_proxy_url()


# =============================================================================
# Client HTTP des modules
# =============================================================================


def make_http_client(
    proxy: str | None = None,
    *,
    verify: bool = True,
    transport: httpx.AsyncBaseTransport | None = None,
    **kwargs,
) -> httpx.AsyncClient:
    """Client HTTP asynchrone d'un module de scan, derrière `proxy` s'il est donné.

    - `proxy` : URL du proxy (voir get_proxy_url) appliquée à toutes les
      requêtes ; None : aucun proxy imposé (celui de l'environnement s'applique,
      comme aux clients des 18 premiers modules).
    - Comme tous les clients du scanner, il soumet chaque requête (redirections
      comprises) à la politique de cibles et épingle les connexions directes sur
      les adresses validées (common._guarded_client). Derrière un proxy, c'est
      lui qui résout le nom et s'y connecte : l'épinglage ne s'applique pas.
    - Par défaut : TLS vérifié, aucune redirection suivie, délai de 10 s,
      User-Agent de l'application ; `verify`, `timeout`, `follow_redirects`,
      `headers`… se règlent comme pour httpx.AsyncClient (sauf `event_hooks`,
      réservé à la politique de cibles). `transport` sert aux tests
      (httpx.MockTransport) : le proxy n'est alors pas utilisé.

    Une URL de proxy invalide, ou SOCKS sans le paquet socksio, lève une erreur
    à la création : jamais de repli silencieux vers une connexion directe.
    """
    kwargs.setdefault("timeout", DEFAULT_TIMEOUT)
    kwargs.setdefault("follow_redirects", False)
    headers = httpx.Headers({"User-Agent": USER_AGENT})
    headers.update(kwargs.pop("headers", None))
    return _guarded_client(
        transport,
        verify=verify,
        proxies={"all": proxy} if proxy else None,
        headers=headers,
        **kwargs,
    )


# =============================================================================
# Connexion à travers le proxy (capture d'écran)
# =============================================================================
# Chromium ne parle qu'au proxy filtrant local de screenshot.py, qui valide
# chaque hôte avant de s'y connecter. Avec un proxy sortant, il s'y connecte à
# travers lui : tunnel CONNECT (proxy HTTP) ou SOCKS5, vers l'adresse validée
# elle-même (jamais le nom : le proxy ne refait pas de résolution DNS).


def _os_error_text(error: OSError) -> object:
    """Cause lisible (traduisible) d'une connexion impossible au proxy."""
    if isinstance(error, ConnectionRefusedError):
        return msg("net.connection_refused")
    return error.strerror or type(error).__name__


async def _read_exactly(reader: asyncio.StreamReader, count: int) -> bytes:
    try:
        return await reader.readexactly(count)
    except asyncio.IncompleteReadError as e:
        raise ProxyError(msg("proxy.bad_reply")) from e


async def _http_connect(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
    host: str,
    port: int,
    credentials: tuple[str, str] | None,
) -> None:
    """Tunnel CONNECT : le proxy répond 2xx quand la connexion vers host:port est ouverte."""
    authority = f"[{host}]:{port}" if ":" in host else f"{host}:{port}"
    lines = [f"CONNECT {authority} HTTP/1.1", f"Host: {authority}"]
    if credentials is not None:
        token = base64.b64encode(":".join(credentials).encode("utf-8")).decode("ascii")
        lines.append(f"Proxy-Authorization: Basic {token}")
    writer.write(("\r\n".join(lines) + "\r\n\r\n").encode("ascii"))
    await writer.drain()
    try:
        head = await reader.readuntil(b"\r\n\r\n")
    except (asyncio.IncompleteReadError, asyncio.LimitOverrunError) as e:
        raise ProxyError(msg("proxy.bad_reply")) from e
    status_line = head.split(b"\r\n", 1)[0].decode("latin-1").split(" ", 2)
    if len(status_line) < 2 or not status_line[0].startswith("HTTP/") or not status_line[1].isdigit():
        raise ProxyError(msg("proxy.bad_reply"))
    status = int(status_line[1])
    if 200 <= status < 300:
        return
    if status == 407:
        raise ProxyError(msg("proxy.auth_failed"))
    raise ProxyError(msg("proxy.refused", detail=f"HTTP {status}"))


async def _socks5_connect(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
    host: str,
    port: int,
    credentials: tuple[str, str] | None,
) -> None:
    """Connexion SOCKS5 (RFC 1928), avec identifiant et mot de passe (RFC 1929) si l'URL en porte."""
    methods = b"\x00\x02" if credentials is not None else b"\x00"
    writer.write(b"\x05" + bytes([len(methods)]) + methods)
    await writer.drain()
    version, method = await _read_exactly(reader, 2)
    if version != 5:
        raise ProxyError(msg("proxy.bad_reply"))
    if method == 0x02 and credentials is not None:
        user, password = (value.encode("utf-8") for value in credentials)
        if len(user) > 255 or len(password) > 255:
            raise ProxyError(msg("proxy.auth_failed"))
        writer.write(b"\x01" + bytes([len(user)]) + user + bytes([len(password)]) + password)
        await writer.drain()
        _, status = await _read_exactly(reader, 2)
        if status != 0:
            raise ProxyError(msg("proxy.auth_failed"))
    elif method == 0xFF:
        # Aucune méthode acceptée : le proxy exige une authentification.
        raise ProxyError(msg("proxy.auth_failed"))
    elif method != 0x00:
        raise ProxyError(msg("proxy.bad_reply"))

    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        name = host.encode("idna")
        if len(name) > 255:
            raise ValueError(f"Nom d'hôte trop long pour SOCKS5 : {host[:50]!r}") from None
        destination = b"\x03" + bytes([len(name)]) + name
    else:
        destination = (b"\x01" if address.version == 4 else b"\x04") + address.packed
    writer.write(b"\x05\x01\x00" + destination + port.to_bytes(2, "big"))
    await writer.drain()

    version, reply, _, address_type = await _read_exactly(reader, 4)
    if version != 5:
        raise ProxyError(msg("proxy.bad_reply"))
    if reply != 0:
        raise ProxyError(msg("proxy.refused", detail=f"SOCKS5 {reply}"))
    # Adresse et port de liaison du proxy : lus pour les écarter du flux relayé.
    if address_type == 1:
        skipped = 4
    elif address_type == 4:
        skipped = 16
    elif address_type == 3:
        skipped = (await _read_exactly(reader, 1))[0]
    else:
        raise ProxyError(msg("proxy.bad_reply"))
    await _read_exactly(reader, skipped + 2)


async def open_tunnel(
    proxy_url: str, host: str, port: int, *, limit: int = STREAM_LIMIT
) -> tuple[asyncio.StreamReader, asyncio.StreamWriter]:
    """Connexion TCP vers host:port à travers le proxy `proxy_url` (HTTP CONNECT ou SOCKS5).

    Renvoie (lecteur, écrivain) prêts à relayer des octets, comme
    asyncio.open_connection ; `limit` est la taille maximale d'une ligne lue.
    Lève ProxyError (un OSError) si l'URL du proxy est invalide, si le proxy
    est injoignable ou refuse la connexion, et ValueError si `host` n'est pas
    un nom ou une adresse. Aucun délai ici : l'appelant l'impose
    (asyncio.wait_for), et une annulation ferme la connexion ouverte.
    """
    if not host or any(ch.isspace() or ord(ch) < 32 or ord(ch) == 127 for ch in host):
        raise ValueError(f"Hôte invalide pour le tunnel : {host[:50]!r}")
    try:
        parts = urlsplit(proxy_url)
        scheme = parts.scheme.lower()
        if scheme not in _DEFAULT_PORTS or not parts.hostname:
            raise ValueError(scheme)
        proxy_port = parts.port or _DEFAULT_PORTS[scheme]
    except ValueError as e:
        raise ProxyError(msg("api.settings_invalid_proxy")) from e
    credentials = None
    if parts.username is not None:
        credentials = (unquote(parts.username), unquote(parts.password or ""))
    options: dict = {"limit": limit}
    if scheme == "https":
        options.update(ssl=ssl.create_default_context(), server_hostname=parts.hostname)

    writer = None
    try:
        try:
            reader, writer = await asyncio.open_connection(parts.hostname, proxy_port, **options)
            if scheme.startswith("socks5"):
                await _socks5_connect(reader, writer, host, port, credentials)
            else:
                await _http_connect(reader, writer, host, port, credentials)
        except ProxyError:
            raise
        except OSError as e:
            raise ProxyError(msg("proxy.unreachable", error=_os_error_text(e))) from e
    except BaseException:
        # Échec ou annulation : la connexion au proxy ne reste jamais ouverte.
        if writer is not None:
            writer.close()
        raise
    return reader, writer
