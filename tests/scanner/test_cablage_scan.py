# =============================================================================
# DomainRecon - Tests du câblage du scan : proxy sortant des clients de collecte
# et caches des API tierces
# =============================================================================
# - le proxy posé pour un scan (common.scan_proxy) est monté par les clients des
#   modules (common._http_client, common._api_client), sans changer leur
#   signature ; sans proxy, ils restent directs (ou suivent l'environnement) ;
# - la politique de cibles (anti-SSRF) s'applique AVANT le proxy, qui résout le
#   nom lui-même : une cible interne est refusée même derrière un proxy ;
# - les appels aux API tierces (crt.sh, Cert Spotter, ipinfo.io, HackerTarget)
#   sont mis en cache (cache.cached), jamais d'un résultat en erreur, sans
#   collision entre domaines ni entre proxys.
# Aucun trafic vers Internet : tout se passe sur 127.0.0.1 ou en transport simulé.
# =============================================================================

import asyncio
import base64
import ipaddress

import httpcore
import httpx
import pytest

from domainrecon.scanner import cache, common, network, targets
from domainrecon.scanner import dns as scanner_dns
from domainrecon.scanner.errors import ModuleError, TargetNotAllowedError
from rendu import fr

# Comportement des 18 modules historiques : registre ramené à eux (tests/conftest.py).
pytestmark = pytest.mark.usefixtures("registre_historique")

PUBLIC_IP = "93.184.216.34"
PUBLIC_IP_2 = "93.184.216.35"
PROXY_URL = "http://alice:mdp@127.0.0.1:3128"
OTHER_PROXY_URL = "socks5://127.0.0.1:9050"

CLIENTS = [common._http_client, common._api_client]


# =============================================================================
# Outils
# =============================================================================


def _proxy_env(monkeypatch, **env):
    """Remplace les variables de proxy par `env` (jamais vide : sinon getproxies() lirait le registre Windows)."""
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
def dns_simule(monkeypatch):
    """Résolution simulée : `table` donne les adresses d'un nom ; un nom inconnu résout vers une adresse publique."""
    table: dict[str, list[str]] = {}

    async def resoudre(host, timeout=targets.RESOLVE_TIMEOUT):
        try:
            return [str(ipaddress.ip_address(host))]
        except ValueError:
            return list(table.get(host, [PUBLIC_IP]))

    monkeypatch.setattr(targets, "resolve_addresses", resoudre)
    return table


class FakeProxy:
    """Proxy HTTP local : note les connexions et les requêtes reçues, et répond `response` (statut, en-têtes, corps)."""

    def __init__(self, response=(200, {}, b"via le proxy")):
        self.response = response
        self.connections = 0
        self.requests: list[tuple[str, dict]] = []
        self._server = None
        self.port = 0

    async def __aenter__(self):
        self._server = await asyncio.start_server(self._handle, "127.0.0.1", 0)
        self.port = self._server.sockets[0].getsockname()[1]
        return self

    async def __aexit__(self, *exc_info):
        self._server.close()
        await self._server.wait_closed()

    @property
    def url(self) -> str:
        return f"http://127.0.0.1:{self.port}"

    async def _handle(self, reader, writer):
        self.connections += 1
        try:
            head = await reader.readuntil(b"\r\n\r\n")
            lines = head.decode("latin-1").split("\r\n")
            headers = dict(line.split(": ", 1) for line in lines[1:] if ": " in line)
            self.requests.append((lines[0], {name.lower(): value for name, value in headers.items()}))
            status, extra, body = self.response
            fields = {"Content-Length": str(len(body)), "Connection": "close", **extra}
            writer.write(
                f"HTTP/1.1 {status} X\r\n".encode()
                + "".join(f"{name}: {value}\r\n" for name, value in fields.items()).encode()
                + b"\r\n"
                + body
            )
            await writer.drain()
        except (asyncio.IncompleteReadError, ConnectionError):
            pass
        finally:
            writer.close()


def _close(client):
    asyncio.run(client.aclose())


# =============================================================================
# A1 : le proxy du scan est monté par les clients des modules
# =============================================================================


@pytest.mark.parametrize("make", CLIENTS)
def test_client_hors_scan_suit_l_environnement(make, monkeypatch):
    """Sans scan en cours (tests, sondes de clés API) : comportement inchangé, l'environnement décide."""
    _proxy_env(monkeypatch, HTTPS_PROXY="http://env.example:3128")
    assert common.current_scan_proxy() is None
    client = make()
    try:
        assert client._transport._proxies == {"https": "http://env.example:3128"}
    finally:
        _close(client)


@pytest.mark.parametrize("make", CLIENTS)
def test_client_du_scan_monte_le_proxy(make, monkeypatch):
    # Le proxy du scan remplace celui de l'environnement, exclusions NO_PROXY comprises.
    _proxy_env(monkeypatch, HTTPS_PROXY="http://env.example:3128", NO_PROXY="api.example")
    with common.scan_proxy(PROXY_URL):
        client = make()
    try:
        transport = client._transport
        assert transport._proxies == {"all": PROXY_URL}
        assert list(transport._via_proxy) == [PROXY_URL]
        assert isinstance(transport._via_proxy[PROXY_URL]._pool, httpcore.AsyncHTTPProxy)
        for target in ("https://api.example/", "http://site.example/"):
            assert common._proxy_for_url(httpx.URL(target), transport._proxies) == PROXY_URL
    finally:
        _close(client)


@pytest.mark.parametrize("make", CLIENTS)
def test_scan_sans_proxy_client_direct(make, sans_proxy_env):
    with common.scan_proxy(None):
        assert common.current_scan_proxy() == common.ScanProxy(None)
        client = make()
    try:
        assert client._transport._via_proxy == {}
        assert common._proxy_for_url(httpx.URL("https://site.example/"), client._transport._proxies) is None
    finally:
        _close(client)


@pytest.mark.parametrize("make", CLIENTS)
def test_scan_sans_proxy_garde_l_environnement(make, monkeypatch):
    """Un scan sans proxy des Réglages ne retire pas celui de l'environnement : les clients le suivent encore."""
    _proxy_env(monkeypatch, HTTPS_PROXY="http://env.example:3128")
    with common.scan_proxy(None):
        client = make()
    try:
        assert client._transport._proxies == {"https": "http://env.example:3128"}
    finally:
        _close(client)


def test_proxy_du_scan_restaure_a_la_sortie(sans_proxy_env):
    assert common.current_scan_proxy() is None
    with common.scan_proxy(PROXY_URL):
        assert common.current_scan_proxy().url == PROXY_URL
        with common.scan_proxy(OTHER_PROXY_URL):
            assert common.current_scan_proxy().url == OTHER_PROXY_URL
        assert common.current_scan_proxy().url == PROXY_URL
    assert common.current_scan_proxy() is None


def test_proxy_du_scan_restaure_apres_une_exception(sans_proxy_env):
    with pytest.raises(RuntimeError):
        with common.scan_proxy(PROXY_URL):
            raise RuntimeError("module en échec")
    assert common.current_scan_proxy() is None


def test_scans_simultanes_chacun_son_proxy(sans_proxy_env):
    """Deux scans dans la même boucle : le proxy de l'un n'est jamais vu par l'autre."""

    async def scan(proxy, pause):
        with common.scan_proxy(proxy):
            await asyncio.sleep(pause)
            # Une tâche créée pendant le scan (module) hérite du proxy de CE scan.
            seen_by_task = await asyncio.ensure_future(_proxy_seen())
            client = common._api_client()
            try:
                return common.current_scan_proxy().url, seen_by_task, dict(client._transport._proxies)
            finally:
                await client.aclose()

    async def _proxy_seen():
        await asyncio.sleep(0.01)
        return common.current_scan_proxy().url

    async def scenario():
        return await asyncio.gather(scan(PROXY_URL, 0.03), scan(OTHER_PROXY_URL, 0.0), scan(None, 0.01))

    first, second, third = asyncio.run(scenario())

    assert first == (PROXY_URL, PROXY_URL, {"all": PROXY_URL})
    assert second == (OTHER_PROXY_URL, OTHER_PROXY_URL, {"all": OTHER_PROXY_URL})
    assert third[:2] == (None, None) and "all" not in third[2]


def test_thread_lance_pendant_le_scan_voit_le_proxy(sans_proxy_env):
    async def scenario():
        with common.scan_proxy(PROXY_URL):
            return await asyncio.to_thread(common.current_scan_proxy)

    assert asyncio.run(scenario()).url == PROXY_URL


def test_proxy_du_scan_jamais_dans_repr(sans_proxy_env):
    with common.scan_proxy(PROXY_URL) as state:
        assert "mdp" not in repr(state) and "127.0.0.1" not in repr(state)


def test_empreinte_du_proxy_pour_les_caches(sans_proxy_env):
    assert common.proxy_scope() is None
    with common.scan_proxy(None):
        assert common.proxy_scope() is None
    with common.scan_proxy(PROXY_URL):
        first = common.proxy_scope()
        assert first and "mdp" not in first and PROXY_URL not in first
        with common.scan_proxy(OTHER_PROXY_URL):
            assert common.proxy_scope() not in (None, first)
        assert common.proxy_scope() == first


@pytest.mark.parametrize("make", CLIENTS)
def test_transport_de_test_ignore_le_proxy_mais_garde_la_politique_de_cibles(
    make, dns_simule, sans_proxy_env
):
    seen = []

    def handler(request):
        seen.append(str(request.url))
        return httpx.Response(200, text="ok")

    async def scenario():
        with common.scan_proxy(PROXY_URL):
            async with make(transport=httpx.MockTransport(handler)) as client:
                assert (await client.get("http://site.example/")).text == "ok"
                with pytest.raises(TargetNotAllowedError):
                    await client.get("http://127.0.0.1/")

    asyncio.run(scenario())
    assert seen == ["http://site.example/"]


@pytest.mark.parametrize("make", CLIENTS)
def test_requete_reelle_passe_par_le_proxy_du_scan(make, dns_simule, sans_proxy_env):
    async def scenario():
        async with FakeProxy() as proxy:
            url = f"http://alice:p%40ss@127.0.0.1:{proxy.port}"
            with common.scan_proxy(url):
                async with make() as client:
                    response = await client.get("http://site.example/page?x=1")
            return response, proxy.requests

    response, requests = asyncio.run(scenario())

    assert response.status_code == 200 and response.text == "via le proxy"
    ((request_line, headers),) = requests
    # Forme absolue : c'est bien un proxy qui a reçu la requête, identifiants décodés.
    assert request_line == "GET http://site.example/page?x=1 HTTP/1.1"
    assert headers["proxy-authorization"] == "Basic " + base64.b64encode(b"alice:p@ss").decode()
    assert headers["host"] == "site.example"
    assert headers["user-agent"] == common.USER_AGENT


# --- Anti-SSRF : la politique de cibles passe AVANT le proxy ---------------------


@pytest.mark.parametrize("make", CLIENTS)
@pytest.mark.parametrize(
    "target",
    [
        "http://127.0.0.1:8080/admin",
        "http://169.254.169.254/latest/meta-data/",
        "http://[::1]/",
        "http://interne.example/",  # nom qui résout vers une adresse privée
        "ftp://site.example/",
    ],
)
def test_cible_interne_refusee_meme_derriere_un_proxy(make, target, dns_simule, sans_proxy_env):
    dns_simule["interne.example"] = ["10.0.0.5"]

    async def scenario():
        async with FakeProxy() as proxy:
            with common.scan_proxy(proxy.url):
                async with make() as client:
                    with pytest.raises(TargetNotAllowedError):
                        await client.get(target)
            return proxy.connections

    # Le proxy ne reçoit rien : refus avant toute connexion.
    assert asyncio.run(scenario()) == 0


def test_redirection_vers_une_cible_interne_refusee_derriere_un_proxy(dns_simule, sans_proxy_env):
    async def scenario():
        async with FakeProxy(response=(302, {"Location": "http://169.254.169.254/latest"}, b"")) as proxy:
            with common.scan_proxy(proxy.url):
                async with common._http_client(follow_redirects=True) as client:
                    with pytest.raises(TargetNotAllowedError):
                        await client.get("http://site.example/")
            return proxy.requests

    # Seule la première requête (cible publique) est partie ; le saut interne est refusé.
    ((request_line, _),) = asyncio.run(scenario())
    assert request_line == "GET http://site.example/ HTTP/1.1"


def test_cible_privee_autorisee_par_le_reglage_reste_possible_derriere_un_proxy(
    dns_simule, sans_proxy_env, monkeypatch
):
    """ALLOW_PRIVATE_TARGETS=1 (réseau local) : même politique avec ou sans proxy."""
    monkeypatch.setenv("ALLOW_PRIVATE_TARGETS", "1")

    async def scenario():
        async with FakeProxy() as proxy:
            with common.scan_proxy(proxy.url):
                async with common._http_client() as client:
                    response = await client.get("http://10.0.0.7/")
            return response.status_code, proxy.requests

    status, requests = asyncio.run(scenario())
    assert status == 200 and requests[0][0] == "GET http://10.0.0.7/ HTTP/1.1"


# =============================================================================
# A1 : les appels aux API tierces des modules passent par le client du scan
# =============================================================================


def _spy_factory(monkeypatch, module, handler):
    """Remplace `module._api_client` par un client simulé qui note le proxy du scan visible à sa création."""
    created: list[dict | None] = []

    def factory(timeout=10.0):
        created.append(common._scan_proxies())
        return common._api_client(timeout, transport=httpx.MockTransport(handler))

    monkeypatch.setattr(module, "_api_client", factory)
    return created


def test_ipinfo_ouvre_son_client_avec_le_proxy_du_scan(monkeypatch, dns_simule):
    created = _spy_factory(monkeypatch, network, lambda request: httpx.Response(200, json={"country": "FR"}))

    async def scenario():
        with common.scan_proxy(PROXY_URL):
            return await network.get_geo_data(PUBLIC_IP)

    assert asyncio.run(scenario())["measured"] is True
    assert created == [{"all": PROXY_URL}]


def test_crtsh_ouvre_son_client_avec_le_proxy_du_scan(monkeypatch, dns_simule):
    created = _spy_factory(
        monkeypatch,
        scanner_dns,
        lambda request: httpx.Response(200, json=[{"name_value": "www.example.com"}]),
    )

    async def no_resolution(host):
        return None

    async def no_addresses(host, timeout=targets.RESOLVE_TIMEOUT):
        return []

    monkeypatch.setattr(scanner_dns, "resolve_ip", no_resolution)
    monkeypatch.setattr(scanner_dns, "resolve_addresses", no_addresses)

    async def scenario():
        with common.scan_proxy(PROXY_URL):
            return await scanner_dns.find_subdomains("example.com")

    assert [entry["subdomain"] for entry in asyncio.run(scenario())] == ["www.example.com"]
    assert created == [{"all": PROXY_URL}]


# =============================================================================
# A3 : cache des API tierces
# =============================================================================


class Clock:
    """Horloge du cache simulée, avancée à la main."""

    def __init__(self):
        self.now = 1000.0

    def __call__(self):
        return self.now

    def advance(self, seconds):
        self.now += seconds


@pytest.fixture
def clock(monkeypatch):
    fake = Clock()
    monkeypatch.setattr(cache, "_clock", fake)
    return fake


def _serve(monkeypatch, handler):
    """Services tiers simulés (`network._api_client`) ; renvoie la liste des requêtes reçues."""
    requests: list[httpx.Request] = []

    def recording(request):
        requests.append(request)
        return handler(request)

    monkeypatch.setattr(
        network,
        "_api_client",
        lambda timeout=10.0: common._api_client(timeout, transport=httpx.MockTransport(recording)),
    )
    return requests


def _hosts(requests, host):
    return [request for request in requests if request.url.host == host]


def test_durees_de_cache_des_api_tierces():
    # ipinfo.io : position et propriétaire d'une IP, qui changent rarement ; reverse-IP : déduit du DNS.
    assert network.IPINFO_CACHE_TTL == cache.LONG_TTL == 86400
    assert network.REVERSE_IP_CACHE_TTL == cache.MEDIUM_TTL == 3600
    # crt.sh : sous-domaines, une heure ; la source de secours, partielle, moins longtemps.
    assert scanner_dns.CT_CACHE_TTL == cache.MEDIUM_TTL
    assert scanner_dns.CT_FALLBACK_CACHE_TTL == cache.SHORT_TTL < scanner_dns.CT_CACHE_TTL


def test_ipinfo_deuxieme_appel_sans_requete(monkeypatch, dns_simule, clock):
    requests = _serve(
        monkeypatch, lambda request: httpx.Response(200, json={"country": "FR", "org": "AS1 A"})
    )

    async def scenario():
        return [await network.get_geo_data(PUBLIC_IP) for _ in range(3)]

    first, second, third = asyncio.run(scenario())

    assert len(requests) == 1
    assert first == second == third and first["country_code"] == "FR"


def test_ipinfo_deux_adresses_sans_collision(monkeypatch, dns_simule, clock):
    def handler(request):
        country = "FR" if PUBLIC_IP in str(request.url) else "US"
        return httpx.Response(200, json={"country": country})

    requests = _serve(monkeypatch, handler)

    async def scenario():
        return (
            await network.get_geo_data(PUBLIC_IP),
            await network.get_geo_data(PUBLIC_IP_2),
            await network.get_geo_data(PUBLIC_IP),
        )

    first, other, again = asyncio.run(scenario())

    assert len(requests) == 2
    assert (first["country_code"], other["country_code"], again["country_code"]) == ("FR", "US", "FR")


def test_ipinfo_expire_apres_vingt_quatre_heures(monkeypatch, dns_simule, clock):
    requests = _serve(monkeypatch, lambda request: httpx.Response(200, json={"country": "FR"}))

    async def scenario():
        await network.get_geo_data(PUBLIC_IP)
        clock.advance(network.IPINFO_CACHE_TTL - 1)
        await network.get_geo_data(PUBLIC_IP)
        assert len(requests) == 1
        clock.advance(2)
        await network.get_geo_data(PUBLIC_IP)

    asyncio.run(scenario())
    assert len(requests) == 2


def test_ipinfo_echec_jamais_garde(monkeypatch, dns_simule, clock):
    statuses = [429, 500, 200]
    requests = _serve(monkeypatch, lambda request: httpx.Response(statuses.pop(0), json={"country": "FR"}))

    async def scenario():
        return [await network.get_geo_data(PUBLIC_IP) for _ in range(4)]

    results = asyncio.run(scenario())

    assert [r["measured"] for r in results] == [False, False, True, True]
    assert len(requests) == 3  # le quatrième appel vient du cache


def test_ipinfo_dans_un_scan_et_hors_scan_ne_se_melangent_pas(monkeypatch, dns_simule, clock):
    """Une réponse (ou une requête en cours) obtenue sans proxy n'est jamais reprise par un scan qui en exige un."""
    created = _spy_factory(monkeypatch, network, lambda request: httpx.Response(200, json={"country": "FR"}))

    async def hors_scan():
        return await network.get_geo_data(PUBLIC_IP)

    async def avec_proxy(url):
        with common.scan_proxy(url):
            return await network.get_geo_data(PUBLIC_IP)

    async def scenario():
        # Simultanés : le calcul en cours sans proxy n'est pas repris par le scan avec proxy.
        await asyncio.gather(hors_scan(), avec_proxy(PROXY_URL), avec_proxy(OTHER_PROXY_URL))
        # Ensuite chacun retrouve sa propre entrée.
        await asyncio.gather(hors_scan(), avec_proxy(PROXY_URL), avec_proxy(OTHER_PROXY_URL))

    asyncio.run(scenario())

    assert sorted(created, key=str) == sorted([None, {"all": PROXY_URL}, {"all": OTHER_PROXY_URL}], key=str)


def _hackertarget_text(request):
    if request.url.host == "ipinfo.io":
        return httpx.Response(200, json={"org": "AS15133 Edgecast Inc."})
    return httpx.Response(200, text="a.example\nb.example\nc.example\n")


def test_hackertarget_cache_par_ip_sans_collision_entre_domaines(monkeypatch, dns_simule, clock):
    requests = _serve(monkeypatch, _hackertarget_text)

    async def scenario():
        return (
            await network.extended_network_scan(PUBLIC_IP, "a.example"),
            await network.extended_network_scan(PUBLIC_IP, "b.example"),
            await network.extended_network_scan(PUBLIC_IP, "a.example"),
        )

    for_a, for_b, for_a_again = asyncio.run(scenario())

    # Une seule requête HackerTarget (et une ipinfo) pour la même IP...
    assert len(_hosts(requests, "api.hackertarget.com")) == 1
    assert len(_hosts(requests, "ipinfo.io")) == 1
    # ... mais chaque domaine s'exclut lui-même de ses voisins, sans emprunter ceux d'un autre.
    assert for_a["reverse_ip_neighbors"] == ["b.example", "c.example"]
    assert for_b["reverse_ip_neighbors"] == ["a.example", "c.example"]
    assert for_a_again == for_a


def test_hackertarget_autre_adresse_nouvelle_requete(monkeypatch, dns_simule, clock):
    requests = _serve(monkeypatch, _hackertarget_text)

    async def scenario():
        await network.extended_network_scan(PUBLIC_IP, "a.example")
        await network.extended_network_scan(PUBLIC_IP_2, "a.example")

    asyncio.run(scenario())

    assert len(_hosts(requests, "api.hackertarget.com")) == 2


def test_hackertarget_quota_jamais_garde_puis_expiration(monkeypatch, dns_simule, clock):
    texts = ["API count exceeded - Increase Quota with Membership", "a.example\nb.example\n"]

    reverse_ip_calls = []

    def handler(request):
        if request.url.host == "ipinfo.io":
            return httpx.Response(200, json={"org": "AS1 A"})
        reverse_ip_calls.append(request)
        return httpx.Response(200, text=texts[0] if len(reverse_ip_calls) == 1 else texts[1])

    requests = _serve(monkeypatch, handler)

    async def scenario():
        quota = await network.extended_network_scan(PUBLIC_IP, "x.example")
        ok = await network.extended_network_scan(PUBLIC_IP, "x.example")
        again = await network.extended_network_scan(PUBLIC_IP, "x.example")
        return quota, ok, again

    quota, ok, again = asyncio.run(scenario())

    assert fr(quota["neighbors_error"]) == "Quota de l'API HackerTarget dépassé"
    assert ok["reverse_ip_neighbors"] == again["reverse_ip_neighbors"] == ["a.example", "b.example"]
    assert len(_hosts(requests, "api.hackertarget.com")) == 2  # l'échec n'est pas gardé, le succès l'est


def test_hackertarget_expire_apres_une_heure(monkeypatch, dns_simule, clock):
    requests = _serve(monkeypatch, _hackertarget_text)

    async def scenario():
        await network.extended_network_scan(PUBLIC_IP, "a.example")
        clock.advance(network.REVERSE_IP_CACHE_TTL - 1)
        await network.extended_network_scan(PUBLIC_IP, "a.example")
        assert len(_hosts(requests, "api.hackertarget.com")) == 1
        clock.advance(2)
        await network.extended_network_scan(PUBLIC_IP, "a.example")

    asyncio.run(scenario())

    assert len(_hosts(requests, "api.hackertarget.com")) == 2
    # ipinfo.io (24 h) est, lui, toujours en cache.
    assert len(_hosts(requests, "ipinfo.io")) == 1


def test_hackertarget_reponse_inexploitable_jamais_gardee(monkeypatch, dns_simule, clock):
    bodies = ["<html>erreur</html>", "a.example\n"]

    def handler(request):
        if request.url.host == "ipinfo.io":
            return httpx.Response(200, json={"org": "AS1 A"})
        return httpx.Response(200, text=bodies.pop(0))

    _serve(monkeypatch, handler)

    async def scenario():
        with pytest.raises(ModuleError):
            await network._reverse_ip_neighbors(PUBLIC_IP, "x.example")
        return await network._reverse_ip_neighbors(PUBLIC_IP, "x.example")

    assert asyncio.run(scenario()) == ["a.example"]


# --- Journaux CT (crt.sh, Cert Spotter) ------------------------------------------


def _serve_ct(monkeypatch, handler):
    requests: list[httpx.Request] = []

    def recording(request):
        requests.append(request)
        return handler(request)

    monkeypatch.setattr(
        scanner_dns,
        "_api_client",
        lambda timeout=10.0: common._api_client(timeout, transport=httpx.MockTransport(recording)),
    )

    async def no_resolution(host):
        return None

    async def no_addresses(host, timeout=targets.RESOLVE_TIMEOUT):
        return []

    monkeypatch.setattr(scanner_dns, "resolve_ip", no_resolution)
    # Sonde du joker DNS : aucun paquet DNS ne sort.
    monkeypatch.setattr(scanner_dns, "resolve_addresses", no_addresses)
    return requests


def test_crtsh_deux_domaines_sans_collision_deuxieme_appel_sans_requete(monkeypatch, dns_simule, clock):
    def handler(request):
        domain = request.url.params["q"].removeprefix("%.")
        return httpx.Response(200, json=[{"name_value": f"www.{domain}"}])

    requests = _serve_ct(monkeypatch, handler)

    async def scenario():
        return (
            await scanner_dns.find_subdomains("example.com"),
            await scanner_dns.find_subdomains("example.org"),
            await scanner_dns.find_subdomains("example.com"),
            await scanner_dns.find_subdomains("example.org"),
        )

    com, org, com_again, org_again = asyncio.run(scenario())

    assert len(requests) == 2  # un par domaine : les deux appels suivants viennent du cache
    assert [e["subdomain"] for e in com] == ["www.example.com"] == [e["subdomain"] for e in com_again]
    assert [e["subdomain"] for e in org] == ["www.example.org"] == [e["subdomain"] for e in org_again]


def test_crtsh_scan_avec_proxy_ne_reprend_pas_la_reponse_sans_proxy(monkeypatch, dns_simule, clock):
    requests = _serve_ct(
        monkeypatch, lambda request: httpx.Response(200, json=[{"name_value": "www.example.com"}])
    )

    async def scenario():
        await scanner_dns.find_subdomains("example.com")
        with common.scan_proxy(PROXY_URL):
            await scanner_dns.find_subdomains("example.com")
            await scanner_dns.find_subdomains("example.com")

    asyncio.run(scenario())

    assert len(requests) == 2  # sans proxy, puis avec proxy (une fois : le suivant vient du cache)
