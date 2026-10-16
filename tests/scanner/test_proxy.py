# =============================================================================
# DomainRecon - Tests du proxy sortant (scanner/proxy.py) et de son usage par la capture d'écran
# =============================================================================
# - get_proxy_url : réglage en base (déchiffré), puis variables d'environnement ;
# - make_http_client : client des modules derrière le proxy (vrai proxy HTTP et
#   SOCKS5 locaux, politique de cibles conservée) ;
# - open_tunnel : CONNECT HTTP et SOCKS5, face à de faux proxys locaux ;
# - capture d'écran : le proxy filtrant s'enchaîne derrière le proxy sortant, y
#   compris avec un vrai Chromium (sauté s'il n'est pas installé).
# Aucun trafic vers Internet : tout se passe sur 127.0.0.1.
# =============================================================================

import asyncio
import base64
import ipaddress
import logging
import socket
import ssl
import sys
import types
from types import SimpleNamespace

import httpcore
import httpx
import pytest
from sqlalchemy.exc import OperationalError

from domainrecon.core import crypto
from domainrecon.core.database import Base, SessionLocal, engine
from domainrecon.core.models import Settings
from domainrecon.core.settings_store import get_settings, update_settings
from domainrecon.scanner import common, proxy, screenshot, targets
from domainrecon.scanner.errors import ModuleError, ProxyError, TargetNotAllowedError
from rendu import en, fr

PUBLIC_IP = "93.184.216.34"


# =============================================================================
# Outils : réglages, environnement, faux serveurs
# =============================================================================


@pytest.fixture(autouse=True)
def reglages_vierges():
    """Table des réglages vide avant et après chaque test."""
    Base.metadata.create_all(bind=engine)
    with SessionLocal() as db:
        db.query(Settings).delete()
        db.commit()
    yield
    with SessionLocal() as db:
        db.query(Settings).delete()
        db.commit()


def _enregistrer(**champs):
    """Réglages enregistrés comme par PUT /api/settings."""
    with SessionLocal() as db:
        update_settings(db, champs)


def _proxy_env(monkeypatch, **env):
    """Remplace les variables de proxy par `env`.

    `env` n'est jamais vide : sinon getproxies() lirait le registre Windows.
    """
    for name in ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY"):
        monkeypatch.delenv(name, raising=False)
        monkeypatch.delenv(name.lower(), raising=False)
    for name, value in env.items():
        monkeypatch.setenv(name, value)


@pytest.fixture
def sans_proxy_env(monkeypatch):
    """Aucun proxy dans l'environnement (NO_PROXY=* : ni proxy, ni repli sur le registre Windows)."""
    _proxy_env(monkeypatch, NO_PROXY="*")


@pytest.fixture
def dns_public(monkeypatch):
    """Tout nom résout vers une adresse publique (une adresse littérale reste elle-même) : aucun paquet DNS ne sort."""

    async def resoudre(host, timeout=targets.RESOLVE_TIMEOUT):
        try:
            return [str(ipaddress.ip_address(host))]
        except ValueError:
            return [PUBLIC_IP]

    monkeypatch.setattr(targets, "resolve_addresses", resoudre)


async def _pipe(reader, writer):
    try:
        while data := await reader.read(65536):
            writer.write(data)
            await writer.drain()
    except (ConnectionError, OSError):
        pass
    finally:
        writer.close()


async def _relay(reader, writer, upstream_reader, upstream_writer):
    """Relaie les deux sens jusqu'à la fermeture de l'un d'eux."""
    await asyncio.gather(_pipe(reader, upstream_writer), _pipe(upstream_reader, writer))


class _Server:
    """Serveur asyncio local : démarre sur un port libre de 127.0.0.1, ferme tout à l'arrêt."""

    def __init__(self):
        self.port = None
        self._server = None
        self._writers = set()

    async def __aenter__(self):
        self._server = await asyncio.start_server(self._accept, "127.0.0.1", 0)
        self.port = self._server.sockets[0].getsockname()[1]
        return self

    async def __aexit__(self, *exc_info):
        self._server.close()
        for writer in list(self._writers):
            writer.close()

    async def _accept(self, reader, writer):
        self._writers.add(writer)
        try:
            await self.handle(reader, writer)
        except (asyncio.IncompleteReadError, asyncio.LimitOverrunError, ConnectionError, OSError):
            pass
        finally:
            writer.close()

    async def handle(self, reader, writer):  # pragma: no cover - redéfini
        raise NotImplementedError


class Site(_Server):
    """Site HTTP local : répond 200 (page de test) ; requêtes reçues dans `requests`."""

    BODY = b"<html><body><h1>Page de test</h1></body></html>"

    def __init__(self):
        super().__init__()
        self.requests: list[tuple[str, dict]] = []

    async def handle(self, reader, writer):
        head = await reader.readuntil(b"\r\n\r\n")
        request_line, headers = _parse_head(head)
        self.requests.append((request_line, headers))
        writer.write(
            b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nConnection: close\r\n"
            + f"Content-Length: {len(self.BODY)}\r\n\r\n".encode()
            + self.BODY
        )
        await writer.drain()


class Banner(_Server):
    """Serveur TCP qui salue (« BANNER ») dès la connexion puis renvoie ce qu'il reçoit."""

    async def handle(self, reader, writer):
        writer.write(b"BANNER")
        await writer.drain()
        await _pipe(reader, writer)


def _parse_head(head: bytes) -> tuple[str, dict]:
    request_line, *lines = head[:-4].decode("latin-1").split("\r\n")
    headers = {name.lower(): value.strip() for name, _, value in (line.partition(":") for line in lines)}
    return request_line, headers


class FakeHttpProxy(_Server):
    """Proxy HTTP local. CONNECT : `status` (200 : tunnel relayé vers `target`) ; GET absolu : réponse directe.

    `raw_reply` remplace toute réponse (réponse invalide, connexion fermée sans réponse avec b"").
    `requests` : (ligne de requête, en-têtes) reçus.
    """

    def __init__(self, *, status=200, target=None, raw_reply=None):
        super().__init__()
        self.status = status
        self.target = target
        self.raw_reply = raw_reply
        self.requests: list[tuple[str, dict]] = []

    @property
    def url(self) -> str:
        return f"http://127.0.0.1:{self.port}"

    async def handle(self, reader, writer):
        request_line, headers = _parse_head(await reader.readuntil(b"\r\n\r\n"))
        self.requests.append((request_line, headers))
        if self.raw_reply is not None:
            writer.write(self.raw_reply)
        elif self.status != 200:
            writer.write(f"HTTP/1.1 {self.status} Refus\r\nContent-Length: 0\r\n\r\n".encode())
        elif request_line.startswith("CONNECT "):
            upstream_reader, upstream_writer = await asyncio.open_connection(*self.target)
            writer.write(b"HTTP/1.1 200 Connection Established\r\nProxy-Agent: faux\r\n\r\n")
            await writer.drain()
            await _relay(reader, writer, upstream_reader, upstream_writer)
            return
        else:
            writer.write(b"HTTP/1.1 200 OK\r\nContent-Length: 12\r\nConnection: close\r\n\r\nvia le proxy")
        await writer.drain()


class FakeSocks5(_Server):
    """Proxy SOCKS5 local, avec ou sans identifiant ; relaie vers `target` (sinon vers la destination demandée).

    `reply` : code de réponse (0 : succès) ; `bound` : type de l'adresse de liaison renvoyée (1, 3 ou 4).
    `requests` : (destination, port) demandés ; `address_types` : leur type (1 IPv4, 3 nom, 4 IPv6).
    """

    def __init__(self, *, credentials=None, reply=0, target=None, bound=1):
        super().__init__()
        self.credentials = credentials
        self.reply = reply
        self.target = target
        self.bound = bound
        self.requests: list[tuple[str, int]] = []
        self.address_types: list[int] = []
        self.credentials_seen: list[tuple[str, str]] = []

    @property
    def url(self) -> str:
        return f"socks5://127.0.0.1:{self.port}"

    async def handle(self, reader, writer):
        _, count = await reader.readexactly(2)
        methods = await reader.readexactly(count)
        if self.credentials is None:
            writer.write(b"\x05\x00")
        elif 2 in methods:
            writer.write(b"\x05\x02")
            await writer.drain()
            _, user_length = await reader.readexactly(2)
            user = (await reader.readexactly(user_length)).decode()
            password_length = (await reader.readexactly(1))[0]
            password = (await reader.readexactly(password_length)).decode()
            self.credentials_seen.append((user, password))
            accepted = (user, password) == self.credentials
            writer.write(b"\x01" + (b"\x00" if accepted else b"\x01"))
            await writer.drain()
            if not accepted:
                return
        else:
            writer.write(b"\x05\xff")  # aucune méthode acceptable
            await writer.drain()
            return
        await writer.drain()

        _, _, _, address_type = await reader.readexactly(4)
        if address_type == 1:
            destination = socket.inet_ntoa(await reader.readexactly(4))
        elif address_type == 4:
            destination = socket.inet_ntop(socket.AF_INET6, await reader.readexactly(16))
        else:
            destination = (await reader.readexactly((await reader.readexactly(1))[0])).decode()
        port = int.from_bytes(await reader.readexactly(2), "big")
        self.requests.append((destination, port))
        self.address_types.append(address_type)

        if self.reply != 0:
            writer.write(b"\x05" + bytes([self.reply]) + b"\x00\x01" + bytes(6))
            await writer.drain()
            return
        upstream_reader, upstream_writer = await asyncio.open_connection(
            *(self.target or (destination, port))
        )
        bound = {1: b"\x01" + bytes(4), 4: b"\x04" + bytes(16), 3: b"\x03\x0bbound.local"}[self.bound]
        writer.write(b"\x05\x00\x00" + bound + bytes(2))
        await writer.drain()
        await _relay(reader, writer, upstream_reader, upstream_writer)


def _unused_port() -> int:
    """Port libre, aussitôt refermé : une connexion y est refusée."""
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


# =============================================================================
# get_proxy_url : réglage en base, puis environnement
# =============================================================================


def test_proxy_lu_dans_les_reglages_en_clair(sans_proxy_env):
    _enregistrer(proxy_url="socks5h://alice:mdp@127.0.0.1:1080")
    # Le mot de passe n'est pas masqué : c'est l'URL à utiliser, pas celle à afficher.
    assert proxy.get_proxy_url() == "socks5h://alice:mdp@127.0.0.1:1080"


def test_valeur_chiffree_dechiffree(sans_proxy_env):
    with SessionLocal() as db:
        get_settings(db).proxy_url = crypto.encrypt("http://alice:mdp@proxy.local:3128")
        db.commit()

    assert proxy.get_proxy_url() == "http://alice:mdp@proxy.local:3128"


def test_valeur_chiffree_illisible_comptee_absente(monkeypatch, caplog):
    _proxy_env(monkeypatch, HTTPS_PROXY="http://env.example:3128")
    with SessionLocal() as db:
        get_settings(db).proxy_url = "enc:v1:pas-un-jeton"
        db.commit()

    with caplog.at_level(logging.WARNING):
        assert proxy.get_proxy_url() == "http://env.example:3128"
    assert "illisible" in caplog.text


def test_reglage_prioritaire_sur_l_environnement(monkeypatch):
    _proxy_env(monkeypatch, HTTPS_PROXY="http://env.example:3128", HTTP_PROXY="http://env.example:3128")
    _enregistrer(proxy_url="socks5://127.0.0.1:9050")
    assert proxy.get_proxy_url() == "socks5://127.0.0.1:9050"


@pytest.mark.parametrize(
    ("env", "attendu"),
    [
        ({"NO_PROXY": "localhost"}, None),
        ({"HTTPS_PROXY": "http://a.example:3128"}, "http://a.example:3128"),
        ({"HTTP_PROXY": "http://b.example:3128"}, "http://b.example:3128"),
        ({"ALL_PROXY": "socks5://127.0.0.1:9050"}, "socks5://127.0.0.1:9050"),
        # HTTPS_PROXY, puis HTTP_PROXY, puis ALL_PROXY.
        (
            {
                "HTTPS_PROXY": "http://a.example:1",
                "HTTP_PROXY": "http://b.example:2",
                "ALL_PROXY": "http://c.example:3",
            },
            "http://a.example:1",
        ),
        ({"HTTP_PROXY": "http://b.example:2", "ALL_PROXY": "http://c.example:3"}, "http://b.example:2"),
        # « hôte:port » sans schéma : http:// ajouté, comme pour les clients du scanner.
        ({"HTTPS_PROXY": "proxy.example:3128"}, "http://proxy.example:3128"),
        ({"https_proxy": "http://minuscules.example:3128"}, "http://minuscules.example:3128"),
        # NO_PROXY=* désactive tout proxy de l'environnement ; une exclusion par hôte, non.
        ({"HTTPS_PROXY": "http://a.example:3128", "NO_PROXY": "*"}, None),
        ({"HTTPS_PROXY": "http://a.example:3128", "NO_PROXY": "intranet.example, *"}, None),
        ({"HTTPS_PROXY": "http://a.example:3128", "NO_PROXY": "intranet.example"}, "http://a.example:3128"),
    ],
)
def test_repli_sur_l_environnement(monkeypatch, env, attendu):
    _proxy_env(monkeypatch, **env)
    assert proxy.get_proxy_url() == attendu


def test_lecture_sans_ecriture_ni_ligne_creee(sans_proxy_env):
    """Aucune ligne de réglages : pas de proxy, et la lecture n'en crée pas."""
    assert proxy.get_proxy_url() is None
    with SessionLocal() as db:
        assert db.query(Settings).count() == 0


def test_reglage_blanc_ignore(monkeypatch):
    _proxy_env(monkeypatch, HTTPS_PROXY="http://env.example:3128")
    with SessionLocal() as db:
        get_settings(db).proxy_url = "   "
        db.commit()
    assert proxy.get_proxy_url() == "http://env.example:3128"


def test_base_illisible_repli_sur_l_environnement(monkeypatch, caplog):
    _proxy_env(monkeypatch, HTTPS_PROXY="http://alice:mdp@env.example:3128")

    class Illisible:
        def __enter__(self):
            raise OperationalError("SELECT 1", {}, Exception("database is locked"))

        def __exit__(self, *exc_info):
            return False

    monkeypatch.setattr(proxy, "SessionLocal", Illisible)

    with caplog.at_level(logging.WARNING):
        assert proxy.get_proxy_url() == "http://alice:mdp@env.example:3128"
    assert "repli sur l'environnement" in caplog.text
    assert "mdp" not in caplog.text  # jamais d'identifiants dans les journaux


# =============================================================================
# make_http_client
# =============================================================================


def _fermer(client):
    asyncio.run(client.aclose())


def test_client_sans_proxy(sans_proxy_env):
    client = proxy.make_http_client()
    try:
        assert isinstance(client._transport, common._GuardedTransport)
        assert client._transport._via_proxy == {}
        # Valeurs par défaut : délai de 10 s, aucune redirection suivie, User-Agent de l'application.
        assert client.timeout == httpx.Timeout(10.0)
        assert client.follow_redirects is False
        assert client.headers["user-agent"] == common.USER_AGENT
        # TLS vérifié.
        assert client._transport._direct._pool._ssl_context.verify_mode == ssl.CERT_REQUIRED
    finally:
        _fermer(client)


def test_client_options_de_httpx(sans_proxy_env):
    client = proxy.make_http_client(
        timeout=3, follow_redirects=True, verify=False, headers={"X-Test": "1", "user-agent": "Autre/1"}
    )
    try:
        assert client.timeout == httpx.Timeout(3)
        assert client.follow_redirects is True
        assert client.headers["x-test"] == "1" and client.headers["user-agent"] == "Autre/1"
        assert client._transport._direct._pool._ssl_context.verify_mode == ssl.CERT_NONE
    finally:
        _fermer(client)


def test_client_sans_proxy_explicite_suit_l_environnement(monkeypatch):
    """None : aucun proxy imposé ; celui de l'environnement s'applique, comme aux clients des 18 modules."""
    _proxy_env(monkeypatch, HTTPS_PROXY="http://env.example:3128")
    client = proxy.make_http_client()
    try:
        assert client._transport._proxies == {"https": "http://env.example:3128"}
    finally:
        _fermer(client)


def test_client_avec_proxy_impose_a_toutes_les_requetes(monkeypatch):
    url = "http://alice:p%40ss@127.0.0.1:3128"
    _proxy_env(monkeypatch, HTTPS_PROXY="http://env.example:3128", NO_PROXY="api.example")
    client = proxy.make_http_client(url)
    try:
        transport = client._transport
        # Le proxy imposé remplace celui de l'environnement, exclusions NO_PROXY comprises.
        assert transport._proxies == {"all": url}
        assert list(transport._via_proxy) == [url]
        assert isinstance(transport._via_proxy[url]._pool, httpcore.AsyncHTTPProxy)
        for target in ("https://api.example/", "http://site.example/"):
            assert common._proxy_for_url(httpx.URL(target), transport._proxies) == url
    finally:
        _fermer(client)


def test_proxy_vide_equivaut_a_aucun_proxy(sans_proxy_env):
    client = proxy.make_http_client("")
    try:
        assert client._transport._via_proxy == {}
    finally:
        _fermer(client)


def test_transport_de_test_remplace_le_reseau(sans_proxy_env, dns_public):
    """Avec un transport simulé, le proxy n'est pas utilisé ; la politique de cibles reste appliquée."""
    seen = []

    def handler(request):
        seen.append(str(request.url))
        return httpx.Response(200, text="ok")

    async def go():
        async with proxy.make_http_client(
            "http://127.0.0.1:9", transport=httpx.MockTransport(handler)
        ) as client:
            assert (await client.get("http://site.example/")).text == "ok"
            with pytest.raises(TargetNotAllowedError):
                await client.get("http://127.0.0.1/")

    asyncio.run(go())
    assert seen == ["http://site.example/"]


def test_requete_http_a_travers_un_proxy_http_avec_identifiants(sans_proxy_env, dns_public):
    async def go():
        async with FakeHttpProxy() as fake:
            url = f"http://alice:p%40ss@127.0.0.1:{fake.port}"
            async with proxy.make_http_client(url) as client:
                response = await client.get("http://site.example/page?x=1")
            return response, fake.requests

    response, requests = asyncio.run(go())

    assert response.status_code == 200 and response.text == "via le proxy"
    ((request_line, headers),) = requests
    # Forme absolue : c'est bien un proxy qui a reçu la requête, identifiants décodés.
    assert request_line == "GET http://site.example/page?x=1 HTTP/1.1"
    assert headers["proxy-authorization"] == "Basic " + base64.b64encode(b"alice:p@ss").decode()
    assert headers["host"] == "site.example"
    assert headers["user-agent"] == common.USER_AGENT


def test_politique_de_cibles_appliquee_derriere_le_proxy(sans_proxy_env, dns_public):
    """Un hôte interne reste refusé avant d'atteindre le proxy."""

    async def go():
        async with FakeHttpProxy() as fake:
            async with proxy.make_http_client(fake.url) as client:
                with pytest.raises(TargetNotAllowedError):
                    await client.get("http://127.0.0.1:8080/admin")
                with pytest.raises(TargetNotAllowedError):
                    await client.get("ftp://site.example/")
            return fake.requests

    assert asyncio.run(go()) == []


@pytest.mark.parametrize("scheme", ["socks5", "socks5h"])
def test_requete_http_a_travers_un_proxy_socks5(sans_proxy_env, dns_public, scheme):
    pytest.importorskip("socksio")

    async def go():
        async with Site() as site:
            async with FakeSocks5(target=("127.0.0.1", site.port)) as fake:
                async with proxy.make_http_client(f"{scheme}://127.0.0.1:{fake.port}") as client:
                    response = await client.get("http://site.example/page")
                return response, fake.requests, fake.address_types, site.requests

    response, socks_requests, address_types, site_requests = asyncio.run(go())

    assert response.status_code == 200 and b"Page de test" in response.content
    assert socks_requests == [("site.example", 80)] and address_types == [3]
    assert site_requests[0][0] == "GET /page HTTP/1.1"


def test_proxy_invalide_leve_une_erreur_sans_repli_direct(sans_proxy_env):
    with pytest.raises(ValueError, match="(?i)proxy"):
        proxy.make_http_client("ftp://proxy.example:21")


def test_socks_sans_socksio_erreur_explicite(monkeypatch, sans_proxy_env):
    monkeypatch.setitem(sys.modules, "socksio", None)  # « import socksio » échoue
    with pytest.raises(ImportError, match="socksio"):
        proxy.make_http_client("socks5://127.0.0.1:1080")


# =============================================================================
# open_tunnel : CONNECT HTTP
# =============================================================================


async def _echange_via_tunnel(reader, writer):
    """Salutation du serveur puis aller-retour : prouve que le flux relayé est intact."""
    assert await asyncio.wait_for(reader.readexactly(6), 5) == b"BANNER"
    writer.write(b"ping")
    await writer.drain()
    assert await asyncio.wait_for(reader.readexactly(4), 5) == b"ping"


def test_tunnel_connect_http():
    async def go():
        async with Banner() as banner, FakeHttpProxy(target=("127.0.0.1", banner.port)) as fake:
            reader, writer = await proxy.open_tunnel(fake.url, "93.184.216.34", 443)
            try:
                await _echange_via_tunnel(reader, writer)
            finally:
                writer.close()
            return fake.requests

    ((request_line, headers),) = asyncio.run(go())

    assert request_line == "CONNECT 93.184.216.34:443 HTTP/1.1"
    assert headers["host"] == "93.184.216.34:443"
    assert "proxy-authorization" not in headers


def test_tunnel_connect_http_adresse_ipv6_entre_crochets():
    async def go():
        async with Banner() as banner, FakeHttpProxy(target=("127.0.0.1", banner.port)) as fake:
            _, writer = await proxy.open_tunnel(fake.url, "2606:4700::1111", 443)
            writer.close()
            return fake.requests

    ((request_line, headers),) = asyncio.run(go())
    assert request_line == "CONNECT [2606:4700::1111]:443 HTTP/1.1"
    assert headers["host"] == "[2606:4700::1111]:443"


def test_tunnel_connect_http_identifiants_decodes():
    async def go():
        async with Banner() as banner, FakeHttpProxy(target=("127.0.0.1", banner.port)) as fake:
            url = f"http://alice:p%40ss%3A%2F@127.0.0.1:{fake.port}"
            _, writer = await proxy.open_tunnel(url, "93.184.216.34", 443)
            writer.close()
            return fake.requests

    ((_, headers),) = asyncio.run(go())
    assert headers["proxy-authorization"] == "Basic " + base64.b64encode(b"alice:p@ss:/").decode()


@pytest.mark.parametrize(
    ("proxy_kwargs", "code", "params"),
    [
        ({"status": 403}, "proxy.refused", {"detail": "HTTP 403"}),
        ({"status": 502}, "proxy.refused", {"detail": "HTTP 502"}),
        ({"status": 407}, "proxy.auth_failed", {}),
        ({"raw_reply": b"SSH-2.0-OpenSSH\r\n\r\n"}, "proxy.bad_reply", {}),
        ({"raw_reply": b"HTTP/1.1 abc Oups\r\n\r\n"}, "proxy.bad_reply", {}),
        ({"raw_reply": b""}, "proxy.bad_reply", {}),
        ({"raw_reply": b"HTTP/1.1 200 Connection Established\r\n"}, "proxy.bad_reply", {}),
    ],
)
def test_tunnel_connect_http_refuse(proxy_kwargs, code, params):
    async def go():
        async with FakeHttpProxy(**proxy_kwargs) as fake:
            with pytest.raises(ProxyError) as excinfo:
                await proxy.open_tunnel(fake.url, "93.184.216.34", 443)
            return excinfo.value

    error = asyncio.run(go())

    assert isinstance(error, OSError) and error.message == {"$t": code, "p": params}


def test_proxy_injoignable():
    async def go():
        with pytest.raises(ProxyError) as excinfo:
            await proxy.open_tunnel(f"http://127.0.0.1:{_unused_port()}", "93.184.216.34", 443)
        return excinfo.value

    error = asyncio.run(go())

    assert error.message == {
        "$t": "proxy.unreachable",
        "p": {"error": {"$t": "net.connection_refused", "p": {}}},
    }
    assert fr(error.message) == "proxy sortant injoignable (connexion refusée)"
    assert en(error.message) == "outbound proxy unreachable (connection refused)"


def test_proxy_dont_le_nom_ne_se_resout_pas(monkeypatch):
    real_getaddrinfo = socket.getaddrinfo

    def getaddrinfo(host, *args, **kwargs):
        if host == "proxy-inexistant.invalid":  # aucune requête DNS réelle
            raise socket.gaierror(socket.EAI_NONAME, "Name or service not known")
        return real_getaddrinfo(host, *args, **kwargs)

    monkeypatch.setattr(socket, "getaddrinfo", getaddrinfo)

    async def go():
        with pytest.raises(ProxyError) as excinfo:
            await proxy.open_tunnel("http://proxy-inexistant.invalid:3128", "93.184.216.34", 443)
        return excinfo.value

    error = asyncio.run(go())
    assert error.message == {"$t": "proxy.unreachable", "p": {"error": "Name or service not known"}}


def test_connexion_au_proxy_fermee_si_la_reponse_ne_vient_pas(monkeypatch):
    """Annulation (délai de l'appelant) pendant la poignée de main : la connexion ne reste pas ouverte."""
    opened = []
    real_open_connection = asyncio.open_connection

    async def open_connection(*args, **kwargs):
        reader, writer = await real_open_connection(*args, **kwargs)
        opened.append(writer)  # tenue ici : seule une fermeture explicite la ferme
        return reader, writer

    monkeypatch.setattr(asyncio, "open_connection", open_connection)

    async def go():
        closed = asyncio.Event()

        class Muet(_Server):
            async def handle(self, reader, writer):
                await reader.readuntil(b"\r\n\r\n")
                await reader.read()  # rend la main seulement quand le client ferme
                closed.set()

        async with Muet() as muet:
            tunnel = proxy.open_tunnel(f"http://127.0.0.1:{muet.port}", "93.184.216.34", 443)
            with pytest.raises(asyncio.TimeoutError):
                await asyncio.wait_for(tunnel, 0.3)
            assert len(opened) == 1 and opened[0].is_closing()
            await asyncio.wait_for(closed.wait(), 5)

    asyncio.run(go())


@pytest.mark.parametrize(
    "url",
    [
        "ftp://proxy.example:21",
        "proxy.example:3128",
        "http://",
        "http://proxy.example:99999",
        "socks4://p:1080",
    ],
)
def test_url_de_proxy_invalide(url):
    async def go():
        with pytest.raises(ProxyError) as excinfo:
            await proxy.open_tunnel(url, "93.184.216.34", 443)
        return excinfo.value

    assert asyncio.run(go()).message == {"$t": "api.settings_invalid_proxy", "p": {}}


@pytest.mark.parametrize("host", ["", "bad host", "evil\r\nHost: x", "tab\tbed"])
def test_hote_invalide_refuse_avant_toute_connexion(host):
    async def go():
        await proxy.open_tunnel("http://127.0.0.1:1", host, 443)

    with pytest.raises(ValueError, match="Hôte invalide"):
        asyncio.run(go())


def test_proxy_https_ouvre_une_connexion_tls(monkeypatch):
    """Schéma https:// : TLS vers le proxy lui-même, nom du proxy vérifié."""
    seen = {}

    async def open_connection(host, port, **kwargs):
        seen.update(host=host, port=port, **kwargs)
        raise ConnectionRefusedError

    monkeypatch.setattr(asyncio, "open_connection", open_connection)

    async def go():
        with pytest.raises(ProxyError):
            await proxy.open_tunnel("https://proxy.example", "93.184.216.34", 443)

    asyncio.run(go())

    assert (seen["host"], seen["port"]) == ("proxy.example", 443)  # port par défaut du schéma
    assert isinstance(seen["ssl"], ssl.SSLContext) and seen["ssl"].check_hostname
    assert seen["server_hostname"] == "proxy.example"
    assert seen["limit"] == proxy.STREAM_LIMIT


def test_ports_par_defaut_des_proxys(monkeypatch):
    ports = {}

    async def open_connection(host, port, **kwargs):
        ports.setdefault(host, port)
        raise ConnectionRefusedError

    monkeypatch.setattr(asyncio, "open_connection", open_connection)

    async def go():
        for scheme in ("http", "socks5", "socks5h"):
            with pytest.raises(ProxyError):
                await proxy.open_tunnel(f"{scheme}://{scheme}.example", "93.184.216.34", 443)

    asyncio.run(go())
    assert ports == {"http.example": 80, "socks5.example": 1080, "socks5h.example": 1080}


# =============================================================================
# open_tunnel : SOCKS5
# =============================================================================


@pytest.mark.parametrize(
    ("host", "address_type", "destination"),
    [
        ("93.184.216.34", 1, "93.184.216.34"),
        ("2606:4700::1111", 4, "2606:4700::1111"),
        ("site.example", 3, "site.example"),
    ],
)
def test_tunnel_socks5(host, address_type, destination):
    async def go():
        async with Banner() as banner, FakeSocks5(target=("127.0.0.1", banner.port)) as fake:
            reader, writer = await proxy.open_tunnel(fake.url, host, 443)
            try:
                await _echange_via_tunnel(reader, writer)
            finally:
                writer.close()
            return fake.requests, fake.address_types

    requests, address_types = asyncio.run(go())

    assert requests == [(destination, 443)] and address_types == [address_type]


@pytest.mark.parametrize("bound", [1, 3, 4])
def test_adresse_de_liaison_ecartee_du_flux(bound):
    """Le proxy renvoie sa propre adresse (IPv4, nom, IPv6) : elle ne doit pas se mêler aux données."""

    async def go():
        async with Banner() as banner, FakeSocks5(target=("127.0.0.1", banner.port), bound=bound) as fake:
            reader, writer = await proxy.open_tunnel(fake.url, "93.184.216.34", 443)
            try:
                await _echange_via_tunnel(reader, writer)
            finally:
                writer.close()

    asyncio.run(go())


def test_tunnel_socks5_avec_identifiants():
    async def go():
        async with Banner() as banner:
            async with FakeSocks5(credentials=("alice", "p@ss:é"), target=("127.0.0.1", banner.port)) as fake:
                url = f"socks5h://alice:p%40ss%3A%C3%A9@127.0.0.1:{fake.port}"
                reader, writer = await proxy.open_tunnel(url, "93.184.216.34", 443)
                try:
                    await _echange_via_tunnel(reader, writer)
                finally:
                    writer.close()
                return fake.credentials_seen

    assert asyncio.run(go()) == [("alice", "p@ss:é")]


def test_tunnel_socks5_identifiants_refuses():
    async def go():
        async with FakeSocks5(credentials=("alice", "mdp")) as fake:
            with pytest.raises(ProxyError) as excinfo:
                await proxy.open_tunnel(f"socks5://alice:faux@127.0.0.1:{fake.port}", "93.184.216.34", 443)
            return excinfo.value

    error = asyncio.run(go())
    assert error.message == {"$t": "proxy.auth_failed", "p": {}}
    assert "identifiants" in fr(error.message) and "credentials" in en(error.message)


def test_tunnel_socks5_authentification_exigee_mais_absente():
    async def go():
        async with FakeSocks5(credentials=("alice", "mdp")) as fake:
            with pytest.raises(ProxyError) as excinfo:
                await proxy.open_tunnel(fake.url, "93.184.216.34", 443)  # aucun identifiant dans l'URL
            return excinfo.value, fake.requests

    error, requests = asyncio.run(go())
    assert error.message == {"$t": "proxy.auth_failed", "p": {}}
    assert requests == []


@pytest.mark.parametrize(
    "credentials",
    [("x" * 256, "mdp"), ("alice", "y" * 256)],
    ids=["identifiant-trop-long", "mot-de-passe-trop-long"],
)
def test_tunnel_socks5_identifiants_trop_longs(credentials):
    async def go():
        async with FakeSocks5(credentials=credentials) as fake:
            user, password = credentials
            with pytest.raises(ProxyError) as excinfo:
                await proxy.open_tunnel(
                    f"socks5://{user}:{password}@127.0.0.1:{fake.port}", "93.184.216.34", 443
                )
            return excinfo.value

    assert asyncio.run(go()).message == {"$t": "proxy.auth_failed", "p": {}}


@pytest.mark.parametrize("reply", [1, 2, 5])
def test_tunnel_socks5_refuse(reply):
    async def go():
        async with FakeSocks5(reply=reply) as fake:
            with pytest.raises(ProxyError) as excinfo:
                await proxy.open_tunnel(fake.url, "93.184.216.34", 443)
            return excinfo.value

    error = asyncio.run(go())
    assert error.message == {"$t": "proxy.refused", "p": {"detail": f"SOCKS5 {reply}"}}


def test_tunnel_socks5_reponse_inattendue():
    """Un serveur qui ne parle pas SOCKS5 (ici : HTTP) donne une erreur claire, pas un blocage."""

    class Http(_Server):
        async def handle(self, reader, writer):
            await reader.readexactly(3)
            writer.write(b"HTTP/1.1 400 Bad Request\r\n\r\n")
            await writer.drain()

    async def go():
        async with Http() as http:
            with pytest.raises(ProxyError) as excinfo:
                await asyncio.wait_for(
                    proxy.open_tunnel(f"socks5://127.0.0.1:{http.port}", "93.184.216.34", 443), 5
                )
            return excinfo.value

    assert asyncio.run(go()).message == {"$t": "proxy.bad_reply", "p": {}}


def test_tunnel_socks5_nom_trop_long():
    async def go():
        async with FakeSocks5() as fake:
            await proxy.open_tunnel(fake.url, ("a" * 63 + ".") * 5 + "com", 443)

    with pytest.raises(ValueError, match="trop long"):
        asyncio.run(go())


# =============================================================================
# Proxy filtrant de la capture d'écran, enchaîné derrière le proxy sortant
# =============================================================================


async def _via_filtre(filtre, raw_request: bytes, *, follow: bytes = b"") -> bytes:
    """Envoie `raw_request` au proxy filtrant (démarré ici) ; renvoie ce qu'il répond, `follow` envoyé ensuite."""
    port = int((await filtre.start()).rsplit(":", 1)[1])
    try:
        reader, writer = await asyncio.open_connection("127.0.0.1", port)
        writer.write(raw_request)
        await writer.drain()
        if follow:
            head = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), 5)
            writer.write(follow)
            await writer.drain()
            response = head + await asyncio.wait_for(reader.read(), 5)
        else:
            try:
                response = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), 5)
            except asyncio.IncompleteReadError as e:
                response = e.partial
        writer.close()
        return response
    finally:
        await filtre.close()


def _garde(*hotes: tuple[str, list[str]]) -> "screenshot._NetworkGuard":
    guard = screenshot._NetworkGuard()
    for nom, adresses in hotes:
        guard.remember(nom, adresses)
    return guard


def test_filtre_enchaine_connect_a_travers_un_proxy_http():
    async def go():
        async with Site() as site, FakeHttpProxy(target=("127.0.0.1", site.port)) as upstream:
            filtre = screenshot._FilteringProxy(_garde(("site.invalid", ["127.0.0.1"])), upstream.url)
            get = f"GET / HTTP/1.1\r\nHost: site.invalid:{site.port}\r\nConnection: close\r\n\r\n".encode()
            connect = f"CONNECT site.invalid:{site.port} HTTP/1.1\r\nHost: site.invalid:{site.port}\r\n\r\n".encode()
            response = await _via_filtre(filtre, connect, follow=get)
            return response, upstream.requests, site.requests

    response, upstream_requests, site_requests = asyncio.run(go())

    assert response.startswith(b"HTTP/1.1 200 Connection Established") and b"Page de test" in response
    # Le proxy sortant reçoit l'adresse validée, jamais le nom : pas de seconde résolution possible.
    ((request_line, _),) = upstream_requests
    assert request_line.startswith("CONNECT 127.0.0.1:") and "site.invalid" not in request_line
    assert site_requests[0][0] == "GET / HTTP/1.1"


def test_filtre_enchaine_requete_http_en_clair_a_travers_un_proxy_http():
    async def go():
        async with Site() as site, FakeHttpProxy(target=("127.0.0.1", site.port)) as upstream:
            filtre = screenshot._FilteringProxy(_garde(("site.invalid", ["127.0.0.1"])), upstream.url)
            request = (
                f"GET http://site.invalid:{site.port}/page HTTP/1.1\r\nHost: site.invalid:{site.port}\r\n"
                "Proxy-Connection: keep-alive\r\nProxy-Authorization: Basic Zm9vOmJhcg==\r\n\r\n"
            ).encode()
            port = int((await filtre.start()).rsplit(":", 1)[1])
            try:
                reader, writer = await asyncio.open_connection("127.0.0.1", port)
                writer.write(request)
                await writer.drain()
                response = await asyncio.wait_for(reader.read(), 5)
                writer.close()
            finally:
                await filtre.close()
            return response, upstream.requests, site.requests

    response, upstream_requests, site_requests = asyncio.run(go())

    assert response.startswith(b"HTTP/1.1 200 OK") and b"Page de test" in response
    assert upstream_requests[0][0].startswith("CONNECT 127.0.0.1:")
    # Le site reçoit la requête sous forme d'origine, sans les en-têtes propres au proxy local.
    request_line, headers = site_requests[0]
    assert request_line == "GET /page HTTP/1.1" and headers["host"].startswith("site.invalid:")
    assert "proxy-authorization" not in headers and "proxy-connection" not in headers


def test_filtre_enchaine_a_travers_un_proxy_socks5_adresse_ipv6_comprise():
    async def go():
        async with Site() as site, FakeSocks5(target=("127.0.0.1", site.port)) as upstream:
            guard = _garde(("v4.invalid", ["127.0.0.1"]), ("v6.invalid", ["2606:4700::1111"]))
            filtre = screenshot._FilteringProxy(guard, upstream.url)
            get = b"GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n"
            ok = await _via_filtre(
                filtre, f"CONNECT v4.invalid:{site.port} HTTP/1.1\r\n\r\n".encode(), follow=get
            )
            filtre = screenshot._FilteringProxy(guard, upstream.url)
            ok6 = await _via_filtre(
                filtre, f"CONNECT v6.invalid:{site.port} HTTP/1.1\r\n\r\n".encode(), follow=get
            )
            return ok, ok6, upstream.requests, upstream.address_types

    ok, ok6, requests, address_types = asyncio.run(go())

    assert b"Page de test" in ok and b"Page de test" in ok6
    assert [destination for destination, _ in requests] == ["127.0.0.1", "2606:4700::1111"]
    assert address_types == [1, 4]


def test_filtre_sans_proxy_sortant_connexion_directe():
    """Sans proxy sortant, rien ne change : connexion directe à l'adresse validée."""

    async def go():
        async with Site() as site:
            filtre = screenshot._FilteringProxy(_garde(("site.invalid", ["127.0.0.1"])))
            get = b"GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n"
            connect = f"CONNECT site.invalid:{site.port} HTTP/1.1\r\n\r\n".encode()
            return await _via_filtre(filtre, connect, follow=get)

    assert b"Page de test" in asyncio.run(go())


def test_filtre_politique_de_cibles_avant_le_proxy_sortant():
    """Un hôte refusé par la politique n'atteint jamais le proxy sortant."""

    async def go():
        async with FakeHttpProxy() as upstream:
            guard = screenshot._NetworkGuard()  # « interne.invalid » : refusé (aucune adresse validée)
            guard.remember("interne.invalid", [])
            filtre = screenshot._FilteringProxy(guard, upstream.url)
            connect = await _via_filtre(filtre, b"CONNECT interne.invalid:443 HTTP/1.1\r\n\r\n")
            filtre = screenshot._FilteringProxy(guard, upstream.url)
            plain = await _via_filtre(
                filtre, b"GET http://interne.invalid/ HTTP/1.1\r\nHost: interne.invalid\r\n\r\n"
            )
            return connect, plain, upstream.requests

    connect, plain, upstream_requests = asyncio.run(go())

    assert connect.startswith(b"HTTP/1.1 403") and plain == b""
    assert upstream_requests == []


@pytest.mark.parametrize(
    ("upstream", "attendu"),
    [
        (lambda: FakeHttpProxy(status=403), "le proxy sortant a refusé la connexion (HTTP 403)"),
        (
            lambda: FakeHttpProxy(status=407),
            "le proxy sortant a refusé les identifiants (authentification requise ou invalide)",
        ),
        (lambda: FakeSocks5(reply=5), "le proxy sortant a refusé la connexion (SOCKS5 5)"),
    ],
    ids=["http-403", "http-407", "socks5-refus"],
)
@pytest.mark.parametrize("scheme", ["http", "https"])
def test_filtre_refus_du_proxy_sortant_repond_502_avec_la_cause(upstream, attendu, scheme):
    async def go():
        async with upstream() as fake:
            filtre = screenshot._FilteringProxy(_garde(("site.invalid", ["127.0.0.1"])), fake.url)
            host = "site.invalid:8765"
            if scheme == "https":
                request = f"CONNECT {host} HTTP/1.1\r\nHost: {host}\r\n\r\n"
            else:
                request = f"GET http://{host}/ HTTP/1.1\r\nHost: {host}\r\n\r\n"
            head = await _via_filtre(filtre, request.encode())
            return head, filtre

    head, filtre = asyncio.run(go())

    status_line, *lines = head.decode("latin-1").split("\r\n")
    assert status_line == "HTTP/1.1 502 Bad Gateway"
    headers = {name.lower(): value for name, _, value in (line.partition(": ") for line in lines if line)}
    assert filtre.is_own_error(headers)
    # La cause exacte est celle du proxy sortant, pas un « connexion impossible » trompeur.
    assert fr(filtre.upstream_error(f"{scheme}://site.invalid:8765/")) == attendu


def test_filtre_proxy_sortant_injoignable():
    async def go():
        filtre = screenshot._FilteringProxy(
            _garde(("site.invalid", ["127.0.0.1"])), f"socks5://127.0.0.1:{_unused_port()}"
        )
        head = await _via_filtre(filtre, b"CONNECT site.invalid:8765 HTTP/1.1\r\n\r\n")
        return head, filtre

    head, filtre = asyncio.run(go())

    assert head.startswith(b"HTTP/1.1 502")
    assert (
        fr(filtre.upstream_error("https://site.invalid:8765/"))
        == "proxy sortant injoignable (connexion refusée)"
    )


# =============================================================================
# capture_screenshot : lecture du proxy sortant (Playwright simulé)
# =============================================================================


@pytest.fixture
def capture_simulee(monkeypatch, tmp_path):
    """Capture dont Chromium « n'est pas installé » : rend les arguments de lancement et les proxys filtrants créés."""
    launches: list[dict] = []
    filtres: list[screenshot._FilteringProxy] = []

    class Chromium:
        async def launch(self, **kwargs):
            launches.append(kwargs)
            raise Exception("BrowserType.launch: Executable doesn't exist at /absent/chrome")

    class Manager:
        async def __aenter__(self):
            return SimpleNamespace(chromium=Chromium())

        async def __aexit__(self, *exc_info):
            return False

    module = types.ModuleType("playwright.async_api")
    module.async_playwright = Manager
    monkeypatch.setitem(sys.modules, "playwright.async_api", module)

    async def ensure(host):
        return [PUBLIC_IP]

    monkeypatch.setattr(screenshot, "ensure_target_allowed", ensure)

    real = screenshot._FilteringProxy

    class Espion(real):
        def __init__(self, guard, upstream=None):
            super().__init__(guard, upstream)
            filtres.append(self)

    monkeypatch.setattr(screenshot, "_FilteringProxy", Espion)

    def capturer(*args):
        return asyncio.run(screenshot.capture_screenshot("example.com", str(tmp_path), *args))

    return SimpleNamespace(launches=launches, filtres=filtres, capturer=capturer, dossier=tmp_path)


def test_capture_proxy_sortant_passe_en_parametre(capture_simulee, sans_proxy_env):
    assert (
        capture_simulee.capturer("socks5://proxy.example:1080") is None
    )  # Chromium absent : capture ignorée

    (filtre,) = capture_simulee.filtres
    assert filtre._upstream == "socks5://proxy.example:1080"
    # Chromium ne parle qu'au proxy filtrant local, jamais au proxy sortant.
    (launch,) = capture_simulee.launches
    assert launch["proxy"]["server"].startswith("http://127.0.0.1:")
    assert launch["proxy"]["bypass"] == "<-loopback>"
    assert "proxy.example" not in str(launch)


def test_capture_proxy_sortant_des_reglages(capture_simulee, sans_proxy_env):
    _enregistrer(proxy_url="http://alice:mdp@proxy.example:3128")
    capture_simulee.capturer()
    assert [filtre._upstream for filtre in capture_simulee.filtres] == ["http://alice:mdp@proxy.example:3128"]


def test_capture_proxy_sortant_de_l_environnement(capture_simulee, monkeypatch):
    _proxy_env(monkeypatch, HTTPS_PROXY="http://env.example:3128")
    capture_simulee.capturer()
    assert [filtre._upstream for filtre in capture_simulee.filtres] == ["http://env.example:3128"]


def test_capture_reglage_prioritaire_sur_l_environnement(capture_simulee, monkeypatch):
    _proxy_env(monkeypatch, HTTPS_PROXY="http://env.example:3128")
    _enregistrer(proxy_url="http://reglage.example:3128")
    capture_simulee.capturer()
    assert [filtre._upstream for filtre in capture_simulee.filtres] == ["http://reglage.example:3128"]


def test_capture_sans_aucun_proxy(capture_simulee, sans_proxy_env):
    capture_simulee.capturer()
    assert [filtre._upstream for filtre in capture_simulee.filtres] == [None]


def test_capture_proxy_vide_force_la_connexion_directe(capture_simulee, monkeypatch):
    _proxy_env(monkeypatch, HTTPS_PROXY="http://env.example:3128")
    _enregistrer(proxy_url="http://reglage.example:3128")
    capture_simulee.capturer("")
    assert [filtre._upstream for filtre in capture_simulee.filtres] == [None]


def test_capture_pendant_un_scan_utilise_le_proxy_lu_par_l_orchestrateur(capture_simulee, monkeypatch):
    """Le proxy du scan (lu une fois au départ) prime sur les Réglages et l'environnement, sans nouvelle lecture."""
    _proxy_env(monkeypatch, HTTPS_PROXY="http://env.example:3128")
    _enregistrer(proxy_url="http://reglage.example:3128")

    def relecture(*args, **kwargs):
        raise AssertionError("les Réglages ne sont pas relus pendant un scan")

    monkeypatch.setattr(screenshot, "get_proxy_url", relecture)

    async def capturer():
        with common.scan_proxy("socks5://scan.example:1080"):
            return await screenshot.capture_screenshot("example.com", str(capture_simulee.dossier))

    asyncio.run(capturer())

    assert [filtre._upstream for filtre in capture_simulee.filtres] == ["socks5://scan.example:1080"]


def test_capture_pendant_un_scan_sans_proxy_reste_directe(capture_simulee, monkeypatch):
    """Scan sans proxy : la capture ne va pas en chercher un dans les Réglages ni l'environnement."""
    _proxy_env(monkeypatch, HTTPS_PROXY="http://env.example:3128")
    _enregistrer(proxy_url="http://reglage.example:3128")

    async def capturer():
        with common.scan_proxy(None):
            return await screenshot.capture_screenshot("example.com", str(capture_simulee.dossier))

    asyncio.run(capturer())

    assert [filtre._upstream for filtre in capture_simulee.filtres] == [None]


def test_capture_parametre_explicite_prime_sur_le_proxy_du_scan(capture_simulee, sans_proxy_env):
    async def capturer():
        with common.scan_proxy("http://scan.example:3128"):
            return await screenshot.capture_screenshot(
                "example.com", str(capture_simulee.dossier), "http://explicite.example:3128"
            )

    asyncio.run(capturer())

    assert [filtre._upstream for filtre in capture_simulee.filtres] == ["http://explicite.example:3128"]


@pytest.mark.parametrize(
    "invalide", ["ftp://proxy.example:21", "proxy.example:3128", "http://", "socks4://p:1080"]
)
def test_capture_proxy_invalide_echoue_sans_repli_direct(capture_simulee, sans_proxy_env, invalide):
    with pytest.raises(ModuleError) as excinfo:
        capture_simulee.capturer(invalide)

    assert fr(excinfo.value.message).startswith("URL de proxy invalide")
    assert capture_simulee.launches == [] and capture_simulee.filtres == []  # Chromium jamais lancé


def test_capture_proxy_invalide_dans_l_environnement(capture_simulee, monkeypatch):
    _proxy_env(monkeypatch, HTTPS_PROXY="ftp://proxy.example:21")
    with pytest.raises(ModuleError, match="URL de proxy invalide"):
        capture_simulee.capturer()
    assert capture_simulee.launches == []


def test_capture_identifiants_du_proxy_absents_des_journaux(capture_simulee, sans_proxy_env, caplog):
    with caplog.at_level(logging.DEBUG):
        capture_simulee.capturer("http://alice:motdepasse-secret@proxy.example:3128")
    assert "motdepasse-secret" not in caplog.text


def test_capture_cible_refusee_avant_la_lecture_du_proxy(monkeypatch, tmp_path, capture_simulee):
    """Une cible interdite est refusée tout de suite, sans lire les réglages ni lancer quoi que ce soit."""

    async def refuse(host):
        raise TargetNotAllowedError("cible interdite")

    monkeypatch.setattr(screenshot, "ensure_target_allowed", refuse)
    monkeypatch.setattr(proxy, "SessionLocal", lambda: pytest.fail("réglages lus pour une cible refusée"))

    with pytest.raises(TargetNotAllowedError):
        capture_simulee.capturer()


# =============================================================================
# Vrai Chromium derrière le proxy filtrant, lui-même derrière un proxy sortant
# =============================================================================


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


@pytest.fixture
def capture_reelle(monkeypatch, chromium):
    """Cible « site.invalid » (adresse validée : 127.0.0.1) servie par `Site`, capture rapide."""

    async def ensure(host):
        return ["127.0.0.1"]

    monkeypatch.setattr(screenshot, "ensure_target_allowed", ensure)
    monkeypatch.setattr(screenshot, "SCREENSHOT_SETTLE_MS", 200)

    def cible(site):
        monkeypatch.setattr(screenshot, "_capture_urls", lambda domain: [f"http://site.invalid:{site.port}/"])

    return cible


def test_capture_reelle_a_travers_un_proxy_http_des_reglages(capture_reelle, sans_proxy_env, tmp_path):
    async def go():
        async with Site() as site:
            async with FakeHttpProxy(target=("127.0.0.1", site.port)) as upstream:
                capture_reelle(site)
                _enregistrer(proxy_url=upstream.url)
                # Lecture des Réglages depuis un thread, comme en production.
                filename = await screenshot.capture_screenshot("site.invalid", str(tmp_path))
                return filename, upstream.requests, site.requests

    filename, upstream_requests, site_requests = asyncio.run(go())

    assert filename and (tmp_path / filename).is_file()
    # Toutes les connexions de Chromium sont passées par le proxy sortant, vers l'adresse validée.
    assert upstream_requests and all(line.startswith("CONNECT 127.0.0.1:") for line, _ in upstream_requests)
    request_line, headers = site_requests[0]
    assert request_line == "GET / HTTP/1.1" and headers["host"].startswith("site.invalid:")


def test_capture_reelle_a_travers_un_proxy_socks5(capture_reelle, sans_proxy_env, tmp_path):
    async def go():
        async with Site() as site:
            async with FakeSocks5(target=("127.0.0.1", site.port)) as upstream:
                capture_reelle(site)
                filename = await screenshot.capture_screenshot("site.invalid", str(tmp_path), upstream.url)
                return filename, upstream.requests, upstream.address_types

    filename, requests, address_types = asyncio.run(go())

    assert filename and (tmp_path / filename).is_file()
    assert requests and all(destination == "127.0.0.1" for destination, _ in requests)
    assert set(address_types) == {1}


def test_capture_reelle_refus_du_proxy_sortant_explique(capture_reelle, sans_proxy_env, tmp_path):
    async def go():
        async with Site() as site, FakeHttpProxy(status=403) as upstream:
            capture_reelle(site)
            with pytest.raises(ModuleError) as excinfo:
                await screenshot.capture_screenshot("site.invalid", str(tmp_path), upstream.url)
            return excinfo.value, site.requests

    error, site_requests = asyncio.run(go())

    assert "le proxy sortant a refusé la connexion (HTTP 403)" in fr(error.message)
    assert site_requests == []  # le site n'a jamais été joint
    assert list(tmp_path.iterdir()) == []


def test_capture_reelle_proxy_sortant_injoignable_explique(capture_reelle, sans_proxy_env, tmp_path):
    async def go():
        async with Site() as site:
            capture_reelle(site)
            with pytest.raises(ModuleError) as excinfo:
                await screenshot.capture_screenshot(
                    "site.invalid", str(tmp_path), f"socks5://127.0.0.1:{_unused_port()}"
                )
            return excinfo.value

    error = asyncio.run(go())
    assert "proxy sortant injoignable (connexion refusée)" in fr(error.message)
