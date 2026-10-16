# =============================================================================
# DomainRecon - Scanner : éléments partagés
# =============================================================================
# Logger, clients HTTP de collecte et petits utilitaires communs aux modules.
#
# Tous les clients HTTP appliquent la politique de cibles (targets.py) à
# CHAQUE requête, redirections comprises : les modules n'ont rien à faire pour
# en profiter. Les connexions directes sont en outre épinglées sur les
# adresses validées : httpx ne résout jamais le nom une seconde fois, ce qui
# ferme la porte au DNS rebinding.
# =============================================================================

import contextlib
import contextvars
import functools
import hashlib
import logging
import ssl
import typing
import urllib.request
from collections.abc import Iterator
from dataclasses import dataclass, field

import httpcore
import httpx

from .. import __version__
from ..core import config
from ..i18n import msg
from .errors import TargetNotAllowedError, message_exception
from .targets import ensure_target_allowed, is_public_address

# Logger commun à tout le package : nom « domainrecon.scanner ».
logger = logging.getLogger(__package__)


# Version reprise de domainrecon.__version__ (source unique).
USER_AGENT = f"DomainRecon/{__version__} (+https://github.com/w4ll-i/DomainRecon)"

# La collecte doit pouvoir interroger des sites dont le certificat est expiré ou
# auto-signé : la vérification TLS est donc volontairement désactivée pour les
# requêtes vers la CIBLE. La validité réelle du certificat n'est pas perdue
# pour autant — elle est mesurée à part par `check_tls_certificate()`, qui
# utilise un contexte SSL vérifiant et remonte l'erreur exacte.
# Les API tierces (crt.sh, ipinfo.io, HackerTarget) passent par `_api_client()`,
# qui vérifie TLS : leurs réponses ne doivent pas être falsifiables.
#
# Proxy sortant : l'orchestrateur lit le proxy des Réglages une fois par scan et
# le pose avec `scan_proxy()` ; `_http_client()` et `_api_client()` le lisent à
# la création du client, si bien que les modules n'ont rien à transmettre. Hors
# d'un scan (tests, sondes de clés API), c'est l'environnement qui décide.
VERIFY_TLS = False

# Nombre maximal de redirections suivies automatiquement (httpx : 20 par défaut).
MAX_REDIRECTS = 10

# Encodages de contenu annoncés à la cible : les seuls que
# `http_utils.read_body_limited()` sait décoder avec une sortie bornée.
ACCEPT_ENCODING = "gzip, deflate"

# Nombre maximal d'adresses essayées pour une connexion (borne la durée totale).
MAX_CONNECT_ADDRESSES = 3

_ALLOWED_SCHEMES = ("http", "https")


def url_host(host: str) -> str:
    """Hôte prêt à insérer dans une URL : une IPv6 littérale passe entre crochets."""
    return f"[{host}]" if ":" in host else host


# =============================================================================
# Proxy du scan en cours
# =============================================================================


@dataclass(frozen=True)
class ScanProxy:
    """Proxy sortant décidé au départ d'un scan ; `url` vaut None quand le scan n'en utilise aucun."""

    # Peut porter des identifiants (http://utilisateur:mdp@hôte) : absent de repr(), jamais journalisé.
    url: str | None = field(default=None, repr=False)


# Contextvar : copiée dans chaque tâche créée pendant le scan (modules, tâches du
# cache) et dans les threads lancés par asyncio.to_thread, jamais partagée avec
# un autre scan simultané. None : aucun scan en cours.
_scan_proxy: contextvars.ContextVar[ScanProxy | None] = contextvars.ContextVar(
    "domainrecon_scan_proxy", default=None
)


@contextlib.contextmanager
def scan_proxy(url: str | None) -> Iterator[ScanProxy]:
    """Le temps du bloc, les clients de collecte passent par le proxy `url` (None : aucun proxy imposé).

    Posé par l'orchestrateur autour de l'exécution des modules ; l'état est
    restauré à la sortie, même sur une annulation.
    """
    state = ScanProxy(url or None)
    token = _scan_proxy.set(state)
    try:
        yield state
    finally:
        _scan_proxy.reset(token)


def current_scan_proxy() -> ScanProxy | None:
    """Proxy du scan en cours, ou None hors d'un scan (le proxy est alors à lire dans les Réglages)."""
    return _scan_proxy.get()


def _scan_proxies() -> dict[str, str] | None:
    """Proxys imposés aux clients de collecte (même forme que `_environment_proxies`), ou None.

    Un proxy de scan s'applique à toutes les requêtes, comme dans
    proxy.make_http_client : « all », sans exclusion NO_PROXY. None : le client
    suit l'environnement (hors scan, ou scan sans proxy).
    """
    state = _scan_proxy.get()
    return {"all": state.url} if state is not None and state.url else None


def proxy_scope() -> str | None:
    """Empreinte du proxy du scan, pour la clé des caches (`cache.cached(scope=…)`).

    Une réponse n'est partagée qu'entre appels qui passent par le même proxy, et
    une requête en cours sans proxy n'est jamais reprise par un scan qui en
    exige un. Empreinte et non URL : la clé ne porte pas d'identifiants.
    """
    state = _scan_proxy.get()
    if state is None or not state.url:
        return None
    return hashlib.sha256(state.url.encode("utf-8")).hexdigest()[:16]


@functools.cache
def _verified_ssl_context() -> ssl.SSLContext:
    """Contexte TLS vérifiant des clients d'API tierces, construit une seule fois.

    Le construire charge le magasin de certificats (certifi) : environ une
    demi-seconde de calcul synchrone. Refait à chaque client, il bloquait la
    boucle d'événements au démarrage de chaque scan, au point de faire expirer
    les sondes du scan de ports (ports ouverts signalés filtrés). Réglages de
    httpx par défaut (certifi, ou SSL_CERT_FILE / SSL_CERT_DIR lus au premier
    appel) ; un SSLContext se partage sans risque entre clients et connexions.
    """
    return httpx.create_ssl_context()


def _environment_proxies() -> dict[str, str]:
    """Proxys de l'environnement, lus comme httpx (trust_env=True).

    Seules les clés http, https et all comptent : httpx ignore les autres
    variables *_PROXY (SOCKS_PROXY, FTP_PROXY…). « no » reprend NO_PROXY,
    utile seulement si un proxy est configuré. Comme pour httpx, getproxies()
    se rabat sur le registre Windows (ou la configuration macOS) si
    l'environnement n'en déclare aucun.
    """
    try:
        found = urllib.request.getproxies()
    except OSError:
        return {}
    proxies = {}
    for scheme in ("http", "https", "all"):
        url = found.get(scheme)
        if url:
            proxies[scheme] = url if "://" in url else f"http://{url}"
    if proxies and found.get("no"):
        proxies["no"] = found["no"]
    return proxies


def _proxy_for_url(url: httpx.URL, proxies: dict[str, str]) -> str | None:
    """Proxy emprunté par une requête vers `url`, ou None (connexion directe).

    Même décision que httpx, URL par URL : proxy du schéma, sinon « all »,
    sauf exclusion NO_PROXY (« * » exclut tout). Seul le NO_PROXY de
    l'environnement compte : la liste d'exclusion du registre Windows est
    ignorée, par httpx aussi.
    """
    proxy = proxies.get(url.scheme) or proxies.get("all")
    if not proxy:
        return None
    no_proxy = proxies.get("no", "")
    if "*" in (name.strip() for name in no_proxy.split(",")):
        return None
    host = url.host if url.port is None else f"{url.host}:{url.port}"
    if urllib.request.proxy_bypass_environment(host, proxies):
        return None
    return proxy


class _PinnedBackend(httpcore.AsyncNetworkBackend):
    """Backend réseau httpcore qui ne se connecte qu'à des adresses validées.

    Le nom est résolu et contrôlé (`ensure_target_allowed`) au moment même de
    la connexion, qui vise ensuite ces adresses et elles seules : httpx ne
    fait plus sa propre résolution, si bien qu'une autre réponse DNS (DNS
    rebinding) ne peut pas mener la requête vers un hôte interne. httpcore
    transmet toujours le nom d'origine à la poignée de main TLS (SNI inchangé).
    """

    def __init__(self) -> None:
        self._inner = httpcore.AnyIOBackend()

    async def connect_tcp(
        self,
        host: str,
        port: int,
        timeout: float | None = None,
        local_address: str | None = None,
        socket_options: typing.Iterable | None = None,
    ) -> httpcore.AsyncNetworkStream:
        if config.private_targets_allowed():
            # Aucune adresse n'est interdite : rien à épingler.
            addresses = [host]
        else:
            addresses = await ensure_target_allowed(host)
        if not addresses:
            raise message_exception(httpcore.ConnectError, msg("net.resolve_failed", host=host))
        last_error: Exception = message_exception(
            httpcore.ConnectError, msg("net.no_reachable_address", host=host)
        )
        # IPv4 d'abord (comme primary_address) : une IPv6 injoignable coûterait
        # tout le délai de connexion avant le repli.
        for address in sorted(addresses, key=lambda a: ":" in a)[:MAX_CONNECT_ADDRESSES]:
            try:
                return await self._inner.connect_tcp(
                    address,
                    port,
                    timeout=timeout,
                    local_address=local_address,
                    socket_options=socket_options,
                )
            except (httpcore.ConnectError, httpcore.ConnectTimeout) as e:
                last_error = e
        raise last_error

    async def sleep(self, seconds: float) -> None:
        await self._inner.sleep(seconds)


class _GuardedTransport(httpx.AsyncBaseTransport):
    """Transport des clients de collecte : connexions directes épinglées, proxys respectés.

    Fournir un transport à httpx.AsyncClient lui fait ignorer les proxys de
    l'environnement : ce transport reprend leur routage, URL par URL
    (`_proxy_for_url`), avec la décision qu'appliquent aussi les hooks.
    """

    def __init__(self, *, verify: bool, proxies: dict[str, str]) -> None:
        self._proxies = proxies
        # Contexte vérifiant partagé (coûteux à construire) ; sans vérification,
        # httpx en crée un en une fraction de milliseconde.
        tls = _verified_ssl_context() if verify else False
        self._direct = httpx.AsyncHTTPTransport(verify=tls)
        pool = getattr(self._direct, "_pool", None)
        if not isinstance(pool, httpcore.AsyncConnectionPool) or not hasattr(pool, "_network_backend"):
            # Garde-fou pour une future version de httpx/httpcore : sans
            # épinglage des connexions, pas de client du tout.
            raise RuntimeError("Version de httpx/httpcore non prise en charge : connexions non épinglables")
        pool._network_backend = _PinnedBackend()
        # Le proxy lui-même est une configuration de confiance : pas d'épinglage.
        self._via_proxy = {
            url: httpx.AsyncHTTPTransport(verify=tls, proxy=url)
            for key, url in proxies.items()
            if key != "no"
        }

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        proxy = _proxy_for_url(request.url, self._proxies)
        transport = self._direct if proxy is None else self._via_proxy[proxy]
        return await transport.handle_async_request(request)

    async def aclose(self) -> None:
        for transport in (self._direct, *self._via_proxy.values()):
            await transport.aclose()


def _target_guard_hooks(real_network: bool, proxies: dict[str, str] | None = None) -> dict:
    """Hooks httpx qui appliquent la politique de cibles à chaque requête.

    - `request` : schéma http/https uniquement, puis `ensure_target_allowed()`
      sur l'hôte de la requête — y compris chaque saut de redirection, que
      httpx fait repasser par les hooks.
    - `response` : l'adresse du pair réellement connecté doit être publique.
      C'est un second rempart : la connexion directe est déjà épinglée sur des
      adresses validées (`_PinnedBackend`). Il est sauté pour une requête qui
      passe par un proxy, dont l'adresse n'est pas celle de la cible.

    La présence d'un proxy est décidée URL par URL, comme le routage
    (`_proxy_for_url`). Derrière un proxy, un nom que seul le proxy sait
    résoudre n'est pas contrôlé localement : la politique dépend alors de lui.
    """
    proxies = proxies or {}

    def proxied(url: httpx.URL) -> bool:
        return real_network and _proxy_for_url(url, proxies) is not None

    async def check_request(request: httpx.Request) -> None:
        if request.url.scheme not in _ALLOWED_SCHEMES:
            raise TargetNotAllowedError(msg("target.scheme_not_allowed", scheme=request.url.scheme))
        if config.private_targets_allowed():
            return
        host = request.url.raw_host.decode("ascii", errors="replace")
        addresses = await ensure_target_allowed(host)
        if not addresses and real_network and not proxied(request.url):
            # Sans résolution, la connexion directe échouerait de toute façon
            # (elle ne vise que des adresses validées) : échec immédiat.
            raise message_exception(httpx.ConnectError, msg("net.resolve_failed", host=host), request=request)

    async def check_response(response: httpx.Response) -> None:
        if config.private_targets_allowed() or proxied(response.request.url):
            return
        stream = response.extensions.get("network_stream")
        peer = stream.get_extra_info("server_addr") if stream is not None else None
        if not peer:
            return
        peer_ip = str(peer[0]).split("%", 1)[0]
        if not is_public_address(peer_ip):
            logger.warning(
                "Réponse bloquée : %s servi par l'adresse non publique %s",
                response.request.url.host,
                peer_ip,
            )
            raise TargetNotAllowedError(msg("target.peer_not_public"))

    return {"request": [check_request], "response": [check_response]}


def _guarded_client(
    transport: httpx.AsyncBaseTransport | None,
    *,
    verify: bool,
    proxies: dict[str, str] | None = None,
    **kwargs,
) -> httpx.AsyncClient:
    """Client httpx soumis à la politique de cibles (hooks + connexions épinglées).

    `transport` (tests : httpx.MockTransport) remplace le réseau ; les hooks
    restent appliqués. Sinon, `_GuardedTransport` porte la vérification TLS :
    le `verify` du client serait ignoré. `proxies` (mêmes clés que
    _environment_proxies : http, https, all, no) impose le proxy ; à défaut,
    celui de l'environnement.
    """
    if transport is None:
        proxies = _environment_proxies() if proxies is None else proxies
        transport = _GuardedTransport(verify=verify, proxies=proxies)
        hooks = _target_guard_hooks(real_network=True, proxies=proxies)
    else:
        hooks = _target_guard_hooks(real_network=False)
    return httpx.AsyncClient(event_hooks=hooks, transport=transport, **kwargs)


def _http_client(
    timeout: float = 10.0,
    follow_redirects: bool = True,
    *,
    transport: httpx.AsyncBaseTransport | None = None,
) -> httpx.AsyncClient:
    """Client HTTP partagé par les modules de collecte (requêtes vers la cible).

    Pendant un scan, il passe par le proxy sortant du scan (`scan_proxy`) : le
    proxy résout alors le nom lui-même, mais la politique de cibles s'applique
    toujours avant la requête (voir `_target_guard_hooks`). `transport` sert aux
    tests (httpx.MockTransport) ; la politique de cibles reste appliquée.
    """
    return _guarded_client(
        transport,
        verify=VERIFY_TLS,
        proxies=_scan_proxies(),
        timeout=timeout,
        follow_redirects=follow_redirects,
        max_redirects=MAX_REDIRECTS,
        headers={"User-Agent": USER_AGENT, "Accept-Encoding": ACCEPT_ENCODING},
    )


def _api_client(
    timeout: float = 10.0,
    *,
    transport: httpx.AsyncBaseTransport | None = None,
) -> httpx.AsyncClient:
    """Client des API tierces (crt.sh, ipinfo.io, HackerTarget).

    TLS vérifié et aucune redirection suivie : une réponse falsifiée (proxy,
    Wi-Fi public) ne doit pas pouvoir injecter de faux résultats. Pendant un
    scan, il passe par le proxy sortant du scan, comme `_http_client` : sans
    cela, un proxy configuré laisserait fuir l'adresse réelle vers ces services.
    """
    return _guarded_client(
        transport,
        verify=True,
        proxies=_scan_proxies(),
        timeout=timeout,
        follow_redirects=False,
        headers={"User-Agent": USER_AGENT},
    )
