# =============================================================================
# DomainRecon - Tests de la politique de cibles (anti-SSRF)
# =============================================================================
# Aucun trafic vers des domaines tiers : résolutions DNS simulées,
# httpx.MockTransport et serveurs HTTP locaux sur 127.0.0.1 uniquement.
# conftest.py fixe ALLOW_PRIVATE_TARGETS=0 : la politique par défaut s'applique.
# =============================================================================

import asyncio
import http.server
import re
import socket
import ssl
import threading
import time
from pathlib import Path
from types import SimpleNamespace

import httpcore
import httpx
import pytest

from domainrecon.i18n import msg
from domainrecon.scanner import common, network, screenshot, targets
from domainrecon.scanner.errors import ModuleError, TargetNotAllowedError, message_of
from domainrecon.scanner.targets import (
    ensure_ip_allowed,
    ensure_target_allowed,
    is_ip_literal,
    is_public_address,
    is_valid_target,
    normalize_target,
    primary_address,
    resolve_addresses,
    resolve_ip,
)
from rendu import fr

PUBLIC_IP = "93.184.216.34"


# =============================================================================
# Fixtures
# =============================================================================


@pytest.fixture
def private_allowed(monkeypatch):
    """Active ALLOW_PRIVATE_TARGETS (usage volontaire sur son propre réseau)."""
    monkeypatch.setenv("ALLOW_PRIVATE_TARGETS", "1")


@pytest.fixture
def fake_dns(monkeypatch):
    """Résolveur simulé : table nom -> adresses. Aucun paquet DNS ne sort."""
    table: dict[str, list[str]] = {}

    async def fake_resolve(host, timeout=targets.RESOLVE_TIMEOUT):
        literal = targets._parse_ip(host)
        if literal is not None:
            return [str(literal)]
        return list(table.get(host, []))

    monkeypatch.setattr(targets, "resolve_addresses", fake_resolve)
    return table


@pytest.fixture
def no_proxy(monkeypatch):
    """Aucun proxy système : les requêtes locales vont bien au serveur de test.

    NO_PROXY=* suffit (httpx n'emprunte alors aucun proxy) et évite que
    getproxies() ne se rabatte sur le registre Windows.
    """
    for name in ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "http_proxy", "https_proxy", "all_proxy"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("NO_PROXY", "*")


def _proxy_env(monkeypatch, **env):
    """Remplace les variables de proxy lues par httpx (http, https, all, no) par `env`."""
    for name in ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY"):
        monkeypatch.delenv(name, raising=False)
        monkeypatch.delenv(name.lower(), raising=False)
    for name, value in env.items():
        monkeypatch.setenv(name, value)


@pytest.fixture
def connections(monkeypatch):
    """Espionne les connexions TCP de httpcore : aucune ne sort de la machine.

    `hosts` reçoit chaque adresse (ou nom) à laquelle httpcore se connecte.
    Une connexion vers PUBLIC_IP est refusée, sauf avec
    `public_served_locally=True` : elle aboutit alors sur 127.0.0.1, comme si
    le serveur de test était cette adresse publique. Seules les connexions
    locales partent réellement.
    """
    spy = SimpleNamespace(hosts=[], public_served_locally=False)
    real_connect = httpcore.AnyIOBackend.connect_tcp

    async def connect_tcp(self, host, port, timeout=None, local_address=None, socket_options=None):
        spy.hosts.append(host)
        if host == PUBLIC_IP and spy.public_served_locally:
            host = "127.0.0.1"
        elif host not in ("127.0.0.1", "localhost"):
            raise httpcore.ConnectError(f"Connexion vers {host} interdite pendant les tests")
        return await real_connect(
            self, host, port, timeout=timeout, local_address=local_address, socket_options=socket_options
        )

    monkeypatch.setattr(httpcore.AnyIOBackend, "connect_tcp", connect_tcp)
    return spy


@pytest.fixture
def local_server(no_proxy):
    """Serveur HTTP sur 127.0.0.1 : routes configurables, chemins reçus enregistrés."""
    hits: list[str] = []
    routes: dict[str, tuple[int, dict, bytes]] = {}

    class Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            hits.append(self.path)
            status, headers, body = routes.get(
                self.path, (200, {"Content-Type": "text/html"}, b"<h1>ok</h1>")
            )
            self.send_response(status)
            for name, value in headers.items():
                self.send_header(name, value)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *args):
            pass

    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True)
    thread.start()
    try:
        yield SimpleNamespace(port=server.server_address[1], hits=hits, routes=routes)
    finally:
        server.shutdown()
        server.server_close()


def _numeric_only_getaddrinfo(host):
    """Résolveur système limité aux formes numériques (AI_NUMERICHOST : jamais de DNS)."""
    return socket.getaddrinfo(host, None, 0, socket.SOCK_STREAM, 0, socket.AI_NUMERICHOST)


# =============================================================================
# normalize_target
# =============================================================================


@pytest.mark.parametrize(
    "raw, expected",
    [
        # IPv6 : crochets retirés, forme canonique
        ("[::1]", "::1"),
        ("http://[::1]:8000/", "::1"),
        ("[2001:db8::1]:443", "2001:db8::1"),
        ("2001:DB8:0:0::1", "2001:db8::1"),
        ("https://user:pw@[2001:db8::1]:8443/x", "2001:db8::1"),
        # IDN converti en punycode
        ("café.fr", "xn--caf-dma.fr"),
        ("https://bücher.de/", "xn--bcher-kva.de"),
        ("CAFÉ.FR", "xn--caf-dma.fr"),
        ("café。fr", "xn--caf-dma.fr"),
        ("ｅｘａｍｐｌｅ.com", "example.com"),
        # Hôte réel d'une URL avec userinfo
        ("http://evil.example@93.184.216.34/", "93.184.216.34"),
        ("HTTP://Example.COM.:443/", "example.com"),
    ],
)
def test_normalize_target_formes(raw, expected):
    assert normalize_target(raw) == expected


@pytest.mark.parametrize(
    "raw",
    [
        # IPv4 + blanc + HTML : acceptée par socket.inet_aton, d'où un XSS stocké
        "127.0.0.1 <img src=x onerror=alert(1)>",
        "127.0.0.1\t<svg onload=alert(1)>",
        "127.0.0.1\n<script>alert(1)</script>",
        "exa mple.com",
        "exa\tmple.com",
        "example.com\x00",
        "exam​ple.com",
        # Barre oblique inverse : lue « / » par un navigateur, pas par urlsplit
        "http://example.com\\@127.0.0.1/",
        # Port invalide, crochets mal formés, zone IPv6
        "example.com:abc",
        "example.com:99999",
        "[example.com]",
        "[1.2.3.4]",
        "http://[::1",
        "fe80::1%eth0",
        # IDN invalide
        "café..fr",
        "http:///chemin",
        "",
        "   ",
    ],
)
def test_normalize_target_saisie_inexploitable(raw):
    assert normalize_target(raw) == ""


def test_normalize_target_type_invalide():
    assert normalize_target(None) == ""
    assert normalize_target(123) == ""


def test_normalize_puis_validation_ipv4_mappee():
    """La forme canonique d'une IPv4 mappée dépend de la version de Python : cohérente."""
    host = normalize_target("::FFFF:127.0.0.1")
    assert is_valid_target(host)
    assert is_ip_literal(host)


# =============================================================================
# is_valid_target / is_ip_literal
# =============================================================================


@pytest.mark.parametrize(
    "host, valid",
    [
        ("example.com", True),
        ("xn--caf-dma.fr", True),
        ("a" * 63 + ".com", True),
        ("93.184.216.34", True),
        ("2001:db8::1", True),
        ("::1", True),
        # Entrées piégées
        ("127.0.0.1 <img src=x onerror=alert(1)>", False),
        ("127.0.0.1\t<svg onload=alert(1)>", False),
        ("example.com\n", False),
        ("example.com ", False),
        ("exam​ple.com", False),
        # IPv4 non canoniques (acceptées par inet_aton, interprétées par les résolveurs)
        ("127.1", False),
        ("0177.0.0.1", False),
        ("0x7f000001", False),
        ("0x7f.1", False),
        ("2130706433", False),
        ("1.2.3", False),
        ("1.2.3.4.5", False),
        ("999.1.1.1", False),
        ("01.2.3.4", False),
        ("0", False),
        # IPv6 non canonique, entre crochets ou avec zone
        ("2001:DB8::1", False),
        ("2001:0db8::1", False),
        ("[::1]", False),
        ("fe80::1%eth0", False),
        # IDN non converti, syntaxe invalide
        ("café.fr", False),
        ("a" * 64 + ".com", False),
        ("a" * 254, False),
        ("exa_mple.com", False),
        ("-example.com", False),
        ("example-.com", False),
        ("a..b.com", False),
        ("", False),
        (None, False),
    ],
)
def test_is_valid_target_strict(host, valid):
    assert is_valid_target(host) is valid


@pytest.mark.parametrize(
    "host, literal",
    [
        ("127.0.0.1", True),
        ("::1", True),
        ("2001:db8::1", True),
        ("example.com", False),
        ("127.1", False),
        ("[::1]", False),
        ("fe80::1%eth0", False),
        ("", False),
    ],
)
def test_is_ip_literal(host, literal):
    assert is_ip_literal(host) is literal


# =============================================================================
# is_public_address
# =============================================================================


@pytest.mark.parametrize(
    "ip, public",
    [
        (PUBLIC_IP, True),
        ("8.8.8.8", True),
        ("2606:4700:4700::1111", True),
        ("::ffff:8.8.8.8", True),
        ("64:ff9b::808:808", True),  # NAT64 vers une IPv4 publique
        # Loopback
        ("127.0.0.1", False),
        ("127.8.9.10", False),
        ("::1", False),
        # RFC 1918, ULA
        ("10.0.0.1", False),
        ("172.16.5.4", False),
        ("192.168.1.1", False),
        ("fd00::1", False),
        # Link-local, métadonnées cloud
        ("169.254.169.254", False),
        ("fe80::1", False),
        # Plages partagées, non spécifiées, multicast, réservées, documentation
        ("100.64.0.1", False),
        ("0.0.0.0", False),
        ("::", False),
        ("224.0.0.1", False),
        ("ff02::1", False),
        ("255.255.255.255", False),
        ("240.0.0.1", False),
        ("192.0.2.1", False),
        ("198.18.0.1", False),
        ("2001:db8::1", False),
        ("fec0::1", False),
        # IPv6 qui embarquent une IPv4 interne
        ("::ffff:127.0.0.1", False),
        ("::ffff:169.254.169.254", False),
        ("::ffff:10.0.0.1", False),
        ("2002:7f00:1::1", False),
        ("2002:a00:1::1", False),
        ("64:ff9b::7f00:1", False),
        ("64:ff9b::a9fe:a9fe", False),
        ("::127.0.0.1", False),
        # Pas une IP
        ("example.com", False),
        ("127.1", False),
        ("", False),
    ],
)
def test_is_public_address(ip, public):
    assert is_public_address(ip) is public


def test_primary_address_prefere_ipv4():
    assert primary_address(["2001:db8::1", "192.0.2.1"]) == "192.0.2.1"
    assert primary_address(["2001:db8::1"]) == "2001:db8::1"
    assert primary_address([]) is None


# =============================================================================
# Résolution DNS
# =============================================================================


def _addrinfo(*addresses):
    infos = []
    for address in addresses:
        if ":" in address:
            infos.append((socket.AF_INET6, socket.SOCK_STREAM, 6, "", (address, 0, 0, 0)))
        else:
            infos.append((socket.AF_INET, socket.SOCK_STREAM, 6, "", (address, 0)))
    return infos


def test_resolve_addresses_litteral_sans_resolution(monkeypatch):
    def interdit(host):
        raise AssertionError("aucune résolution attendue pour une IP littérale")

    monkeypatch.setattr(targets, "_system_getaddrinfo", interdit)
    assert asyncio.run(resolve_addresses(PUBLIC_IP)) == [PUBLIC_IP]
    assert asyncio.run(resolve_addresses("2001:DB8::1")) == ["2001:db8::1"]


def test_resolve_addresses_a_et_aaaa_dedoublonnees(monkeypatch):
    monkeypatch.setattr(
        targets,
        "_system_getaddrinfo",
        lambda host: _addrinfo("fe80::1%eth0", PUBLIC_IP, PUBLIC_IP, "2606:4700::1"),
    )
    assert asyncio.run(resolve_addresses("site.example")) == ["fe80::1", PUBLIC_IP, "2606:4700::1"]


@pytest.mark.parametrize(
    "error",
    [
        socket.gaierror(socket.EAI_NONAME, "inconnu"),
        UnicodeError("label vide"),
        OSError("réseau"),
    ],
)
def test_resolve_addresses_erreurs_capturees(monkeypatch, error):
    def echoue(host):
        raise error

    monkeypatch.setattr(targets, "_system_getaddrinfo", echoue)
    assert asyncio.run(resolve_addresses("site.example")) == []
    assert asyncio.run(resolve_ip("site.example")) is None


def test_resolve_ip_label_invalide_ne_leve_pas():
    """SCAN-13 : l'encodeur IDNA lève UnicodeError (pas gaierror) avant toute requête."""
    assert asyncio.run(resolve_ip("a..example.com")) is None
    assert asyncio.run(resolve_ip("x" * 70 + ".example.com")) is None


def test_resolution_bornee_dans_le_temps(monkeypatch):
    def lent(host):
        time.sleep(0.8)
        return _addrinfo(PUBLIC_IP)

    monkeypatch.setattr(targets, "_system_getaddrinfo", lent)

    async def go():
        # Chronométré dans la boucle : asyncio.run() attend ensuite la fin du thread.
        started = time.monotonic()
        addresses = await resolve_addresses("lent.example", timeout=0.1)
        ip = await resolve_ip("lent.example", timeout=0.1)
        return addresses, ip, time.monotonic() - started

    addresses, ip, elapsed = asyncio.run(go())
    assert addresses == [] and ip is None
    assert elapsed < 0.6


def test_resolve_ip_ipv4_puis_ipv6_dans_un_pool_dedie(monkeypatch):
    threads = []

    def resolver(host):
        threads.append(threading.current_thread().name)
        return _addrinfo("2606:4700::1", PUBLIC_IP) if host == "double.example" else _addrinfo("2606:4700::1")

    monkeypatch.setattr(targets, "_system_getaddrinfo", resolver)
    assert asyncio.run(resolve_ip("double.example")) == PUBLIC_IP
    # IPv6 seule : n'est plus déclarée « non résolue »
    assert asyncio.run(resolve_ip("v6.example")) == "2606:4700::1"
    # Les résolutions en masse ne passent pas par l'exécuteur par défaut.
    assert threads and all(name.startswith("domainrecon-dns") for name in threads)


# =============================================================================
# ensure_target_allowed / ensure_ip_allowed
# =============================================================================


@pytest.mark.parametrize(
    "host",
    [
        "127.0.0.1",
        "10.0.0.1",
        "172.16.0.1",
        "192.168.1.1",
        "169.254.169.254",
        "100.64.0.1",
        "0.0.0.0",
        "::1",
        "fd00::1",
        "fe80::1",
        "::ffff:127.0.0.1",
        "::ffff:169.254.169.254",
    ],
)
def test_litteraux_internes_refuses(host):
    with pytest.raises(TargetNotAllowedError):
        asyncio.run(ensure_target_allowed(host))


@pytest.mark.parametrize("host", ["2130706433", "0x7f000001", "127.1"])
def test_formes_numeriques_resolues_puis_refusees(monkeypatch, host):
    """Si une forme non canonique atteint le résolveur, c'est l'adresse obtenue qui est jugée."""
    monkeypatch.setattr(targets, "_system_getaddrinfo", _numeric_only_getaddrinfo)
    with pytest.raises(TargetNotAllowedError) as excinfo:
        asyncio.run(ensure_target_allowed(host))
    # Une forme numérique n'est pas une cible valide : le message ne reprend pas la saisie.
    assert excinfo.value.message == msg("target.not_allowed")


def test_cible_publique_acceptee():
    assert asyncio.run(ensure_target_allowed(PUBLIC_IP)) == [PUBLIC_IP]


def test_nom_resolu_vers_adresse_interne_refuse(fake_dns):
    fake_dns["metadata.google.internal"] = ["169.254.169.254"]
    fake_dns["mixte.example"] = [PUBLIC_IP, "10.0.0.5"]
    fake_dns["public.example"] = [PUBLIC_IP]

    with pytest.raises(TargetNotAllowedError):
        asyncio.run(ensure_target_allowed("metadata.google.internal"))
    # Une seule adresse interne suffit à refuser.
    with pytest.raises(TargetNotAllowedError):
        asyncio.run(ensure_target_allowed("mixte.example"))
    assert asyncio.run(ensure_target_allowed("public.example")) == [PUBLIC_IP]


def test_cible_non_resolue_n_est_pas_un_refus(fake_dns):
    assert asyncio.run(ensure_target_allowed("introuvable.example")) == []


def test_message_de_refus_sans_adresse_interne(fake_dns):
    fake_dns["intranet.example"] = ["10.1.2.3"]
    with pytest.raises(TargetNotAllowedError) as excinfo:
        asyncio.run(ensure_target_allowed("intranet.example"))
    message = str(excinfo.value)
    assert "10.1.2.3" not in message
    assert "ALLOW_PRIVATE_TARGETS" in message
    # Message traduisible : le nom saisi est repris, jamais l'adresse résolue ; str() en français.
    assert excinfo.value.message == msg("target.not_allowed_host", host="intranet.example")
    assert fr(excinfo.value.message) == message
    assert message == (
        "Cible non autorisée : « intranet.example » correspond à une adresse privée, locale ou réservée. "
        "Pour analyser votre propre réseau, définissez ALLOW_PRIVATE_TARGETS=1."
    )
    # Erreur de validation : l'API la transforme en 400.
    assert isinstance(excinfo.value, ValueError)


def test_localhost_refuse_par_defaut_et_autorise_sur_option(monkeypatch):
    with pytest.raises(TargetNotAllowedError):
        asyncio.run(ensure_target_allowed("localhost"))
    monkeypatch.setenv("ALLOW_PRIVATE_TARGETS", "1")
    addresses = asyncio.run(ensure_target_allowed("localhost"))
    assert addresses and not any(is_public_address(address) for address in addresses)


def test_ensure_ip_allowed():
    assert ensure_ip_allowed(PUBLIC_IP) == PUBLIC_IP
    with pytest.raises(TargetNotAllowedError) as excinfo:
        ensure_ip_allowed("127.0.0.1")
    assert fr(excinfo.value.message) == (
        "Adresse non autorisée : adresse privée, locale ou réservée. "
        "Pour analyser votre propre réseau, définissez ALLOW_PRIVATE_TARGETS=1."
    )
    with pytest.raises(TargetNotAllowedError):
        ensure_ip_allowed("::ffff:10.0.0.1")
    with pytest.raises(ValueError) as excinfo:
        ensure_ip_allowed("example.com")
    assert not isinstance(excinfo.value, TargetNotAllowedError)
    # Message traduisible ; str() reste en français pour les journaux.
    assert message_of(excinfo.value) == msg("target.invalid_ip", ip="'example.com'")
    assert str(excinfo.value) == "Adresse IP invalide : 'example.com'"


def test_ensure_ip_allowed_reseau_local_sur_option(private_allowed):
    assert ensure_ip_allowed("192.168.1.10") == "192.168.1.10"


# =============================================================================
# Client HTTP : politique appliquée à chaque requête et redirection
# =============================================================================


def _mock_client(handler, **kwargs):
    return common._http_client(transport=httpx.MockTransport(handler), **kwargs)


@pytest.mark.parametrize(
    "location",
    [
        "http://interne.example/admin",
        "http://169.254.169.254/latest/meta-data/iam/",
        "http://127.0.0.1:9123/",
        "http://[::ffff:127.0.0.1]:8080/",
        "http://[::1]/",
        "http://10.0.0.5/",
    ],
)
def test_redirection_vers_hote_interne_bloquee(fake_dns, location):
    fake_dns["public.example"] = [PUBLIC_IP]
    fake_dns["interne.example"] = ["10.0.0.5"]
    seen = []

    def handler(request):
        seen.append(str(request.url))
        if request.url.host == "public.example":
            return httpx.Response(302, headers={"Location": location})
        return httpx.Response(200, text="SECRET INTERNE")

    async def go():
        async with _mock_client(handler) as client:
            await client.get("http://public.example/")

    with pytest.raises(TargetNotAllowedError):
        asyncio.run(go())
    assert seen == ["http://public.example/"]


def test_redirection_vers_hote_public_suivie(fake_dns):
    fake_dns["public.example"] = [PUBLIC_IP]
    fake_dns["www.public.example"] = ["93.184.216.35"]

    def handler(request):
        if request.url.host == "public.example":
            return httpx.Response(301, headers={"Location": "https://www.public.example/"})
        return httpx.Response(200, text="bienvenue")

    async def go():
        async with _mock_client(handler) as client:
            return await client.get("http://public.example/")

    response = asyncio.run(go())
    assert response.status_code == 200
    assert str(response.url) == "https://www.public.example/"


def test_redirections_bornees(fake_dns):
    fake_dns["boucle.example"] = [PUBLIC_IP]

    def handler(request):
        return httpx.Response(302, headers={"Location": "http://boucle.example/"})

    async def go():
        async with _mock_client(handler) as client:
            await client.get("http://boucle.example/")

    with pytest.raises(httpx.TooManyRedirects):
        asyncio.run(go())


def test_schema_non_http_refuse(fake_dns):
    def handler(request):
        raise AssertionError("aucune requête attendue")

    async def go():
        async with _mock_client(handler) as client:
            await client.get("ftp://public.example/")

    with pytest.raises(TargetNotAllowedError) as excinfo:
        asyncio.run(go())
    assert fr(excinfo.value.message) == "Schéma non autorisé : ftp"


def test_hote_non_resolu_ne_part_pas_sur_le_reseau(fake_dns, no_proxy):
    """Sans résolution contrôlée, httpx ne doit pas obtenir une autre réponse DNS."""

    async def go():
        async with common._http_client() as client:
            await client.get("http://introuvable.example/")

    with pytest.raises(httpx.ConnectError) as excinfo:
        asyncio.run(go())
    assert message_of(excinfo.value) == msg("net.resolve_failed", host="introuvable.example")
    assert str(excinfo.value) == "Résolution DNS impossible pour introuvable.example"


def test_client_api_tierces_verifie_tls(monkeypatch):
    """La vérification TLS est portée par les transports (le `verify` du client serait ignoré)."""
    _proxy_env(monkeypatch, HTTPS_PROXY="http://127.0.0.1:9")
    api = common._api_client()
    target = common._http_client()
    try:
        assert api.follow_redirects is False
        for client in (api, target):
            assert client.event_hooks["request"] and client.event_hooks["response"]
            # Connexions directes épinglées sur les adresses validées.
            assert isinstance(client._transport._direct._pool._network_backend, common._PinnedBackend)
        api_pools = [api._transport._direct._pool, *(t._pool for t in api._transport._via_proxy.values())]
        target_pools = [
            target._transport._direct._pool,
            *(t._pool for t in target._transport._via_proxy.values()),
        ]
        assert len(api_pools) == len(target_pools) == 2
        assert all(pool._ssl_context.verify_mode == ssl.CERT_REQUIRED for pool in api_pools)
        target_mode = ssl.CERT_REQUIRED if common.VERIFY_TLS else ssl.CERT_NONE
        assert all(pool._ssl_context.verify_mode == target_mode for pool in target_pools)
    finally:
        asyncio.run(api.aclose())
        asyncio.run(target.aclose())


def test_client_refuse_le_loopback_par_defaut(local_server):
    async def go():
        async with common._http_client() as client:
            await client.get(f"http://127.0.0.1:{local_server.port}/")

    with pytest.raises(TargetNotAllowedError):
        asyncio.run(go())
    assert local_server.hits == []


def test_client_autorise_le_loopback_sur_option(local_server, private_allowed):
    async def go():
        async with common._http_client() as client:
            return await client.get(f"http://127.0.0.1:{local_server.port}/")

    assert asyncio.run(go()).status_code == 200
    assert local_server.hits == ["/"]


def _pretend_public(monkeypatch, *names):
    """Fait passer des noms (servis en réalité par 127.0.0.1) pour publics au contrôle DNS."""
    real_resolve = targets.resolve_addresses

    async def resolve(host, timeout=targets.RESOLVE_TIMEOUT):
        if host in names:
            return [PUBLIC_IP]
        return await real_resolve(host, timeout)

    monkeypatch.setattr(targets, "resolve_addresses", resolve)


def _rebinding_dns(monkeypatch, name):
    """DNS rebinding (TTL 0) : `name` résout vers PUBLIC_IP une fois, puis vers 127.0.0.1."""
    answers = [[PUBLIC_IP]]
    real_resolve = targets.resolve_addresses

    async def resolve(host, timeout=targets.RESOLVE_TIMEOUT):
        if host == name:
            return answers.pop(0) if answers else ["127.0.0.1"]
        return await real_resolve(host, timeout)

    monkeypatch.setattr(targets, "resolve_addresses", resolve)


def test_redirection_reelle_vers_le_loopback_bloquee(local_server, monkeypatch, connections):
    port = local_server.port
    local_server.routes["/"] = (302, {"Location": f"http://127.0.0.1:{port}/secret"}, b"")
    _pretend_public(monkeypatch, "localhost")
    connections.public_served_locally = True
    # Isole le contrôle du saut de redirection de celui du pair (voir plus bas).
    monkeypatch.setattr(common, "is_public_address", lambda ip: True)

    async def go():
        async with common._http_client() as client:
            await client.get(f"http://localhost:{port}/")

    with pytest.raises(TargetNotAllowedError):
        asyncio.run(go())
    assert local_server.hits == ["/"]
    # Connexion à l'adresse validée ; le saut vers 127.0.0.1 n'a rien ouvert.
    assert connections.hosts == [PUBLIC_IP]


def test_rebinding_dns_connexion_epinglee_sur_l_adresse_validee(local_server, monkeypatch, connections):
    """Le contrôle DNS voit une IP publique, le résolveur système 127.0.0.1 : httpx ne résout plus."""
    local_server.routes["/"] = (200, {"Content-Type": "text/plain"}, b"SECRET INTERNE")
    _pretend_public(monkeypatch, "localhost")

    async def go():
        async with common._http_client() as client:
            await client.get(f"http://localhost:{local_server.port}/admin?confirm=1")

    # PUBLIC_IP est injoignable pendant les tests (voir la fixture connections).
    with pytest.raises(httpx.ConnectError):
        asyncio.run(go())
    assert connections.hosts == [PUBLIC_IP]
    assert local_server.hits == []


def test_rebinding_dns_requete_jamais_livree(local_server, monkeypatch, connections):
    """TTL 0 : le hook voit l'IP publique, la résolution de la connexion 127.0.0.1."""
    local_server.routes["/"] = (200, {"Content-Type": "text/plain"}, b"SECRET INTERNE")
    _rebinding_dns(monkeypatch, "localhost")

    async def go():
        async with common._http_client() as client:
            await client.get(f"http://localhost:{local_server.port}/")

    with pytest.raises(TargetNotAllowedError):
        asyncio.run(go())
    assert connections.hosts == []
    assert local_server.hits == []


def test_pair_non_public_bloque_en_second_rempart(local_server, monkeypatch, connections):
    """Si une connexion aboutissait malgré tout sur 127.0.0.1, la réponse serait refusée."""
    local_server.routes["/"] = (200, {"Content-Type": "text/plain"}, b"SECRET INTERNE")
    _pretend_public(monkeypatch, "localhost")
    connections.public_served_locally = True

    async def go():
        async with common._http_client() as client:
            await client.get(f"http://localhost:{local_server.port}/")

    with pytest.raises(TargetNotAllowedError) as excinfo:
        asyncio.run(go())
    assert excinfo.value.message == msg("target.peer_not_public")
    assert connections.hosts == [PUBLIC_IP]


def test_connexion_epinglee_ipv4_d_abord_et_bornee(fake_dns, no_proxy, connections):
    fake_dns["multi.example"] = ["2606:4700::1", "93.184.216.35", "93.184.216.36", "93.184.216.37", PUBLIC_IP]

    async def go():
        async with common._http_client() as client:
            await client.get("http://multi.example/")

    with pytest.raises(httpx.ConnectError):
        asyncio.run(go())
    assert connections.hosts == ["93.184.216.35", "93.184.216.36", "93.184.216.37"]
    assert len(connections.hosts) == common.MAX_CONNECT_ADDRESSES


# Environnements où httpx n'emprunte AUCUN proxy pour une URL http:// : les
# contrôles ne doivent pas y être désactivés.
_DIRECT_PROXY_ENVS = [
    pytest.param({"NO_PROXY": "localhost,127.0.0.1"}, id="no_proxy-seul"),
    pytest.param({"HTTPS_PROXY": "http://127.0.0.1:9"}, id="https_proxy-seul-url-http"),
    pytest.param({"NO_PROXY": "intranet.example", "SOCKS_PROXY": "socks5://127.0.0.1:9"}, id="socks_proxy"),
]


@pytest.mark.parametrize("env", _DIRECT_PROXY_ENVS)
def test_sans_proxy_emprunte_le_controle_du_pair_reste_actif(local_server, monkeypatch, connections, env):
    local_server.routes["/"] = (200, {"Content-Type": "text/plain"}, b"SECRET INTERNE")
    _proxy_env(monkeypatch, **env)
    _pretend_public(monkeypatch, "localhost")
    connections.public_served_locally = True

    async def go():
        async with common._http_client() as client:
            return await client.get(f"http://localhost:{local_server.port}/")

    with pytest.raises(TargetNotAllowedError):
        asyncio.run(go())
    # Connexion directe, épinglée : pas de passage par un proxy.
    assert connections.hosts == [PUBLIC_IP]
    assert local_server.hits == ["/"]


@pytest.mark.parametrize("env", _DIRECT_PROXY_ENVS)
def test_sans_proxy_emprunte_hote_non_resolu_ne_part_pas(fake_dns, monkeypatch, connections, env):
    _proxy_env(monkeypatch, **env)

    async def go():
        async with common._http_client() as client:
            await client.get("http://introuvable.example/")

    with pytest.raises(httpx.ConnectError):
        asyncio.run(go())
    assert connections.hosts == []


def test_rebinding_dns_bloque_avec_no_proxy_seul(local_server, monkeypatch, connections):
    local_server.routes["/"] = (200, {"Content-Type": "text/plain"}, b"SECRET INTERNE")
    _proxy_env(monkeypatch, NO_PROXY="localhost,127.0.0.1")
    _rebinding_dns(monkeypatch, "localhost")

    async def go():
        async with common._http_client() as client:
            await client.get(f"http://localhost:{local_server.port}/")

    with pytest.raises(TargetNotAllowedError):
        asyncio.run(go())
    assert local_server.hits == []


def test_proxy_http_reel_toujours_emprunte(local_server, fake_dns, monkeypatch, connections):
    """HTTP_PROXY défini : la requête passe par le proxy (ici le serveur local), sans épinglage."""
    fake_dns["site.example"] = [PUBLIC_IP]
    _proxy_env(monkeypatch, HTTP_PROXY=f"http://127.0.0.1:{local_server.port}")
    local_server.routes["http://site.example/page"] = (200, {"Content-Type": "text/plain"}, b"via le proxy")

    async def go():
        async with common._http_client() as client:
            return await client.get("http://site.example/page")

    response = asyncio.run(go())
    assert response.status_code == 200 and response.text == "via le proxy"
    # Requête en forme absolue : c'est bien un proxy qui l'a reçue.
    assert local_server.hits == ["http://site.example/page"]
    assert connections.hosts == ["127.0.0.1"]


def test_proxy_reel_mais_hote_exclu_par_no_proxy(local_server, monkeypatch, connections):
    """Hôte exclu par NO_PROXY : connexion directe, épinglée, et contrôle du pair actif."""
    local_server.routes["/"] = (200, {"Content-Type": "text/plain"}, b"SECRET INTERNE")
    _proxy_env(monkeypatch, HTTP_PROXY=f"http://127.0.0.1:{local_server.port}", NO_PROXY="localhost")
    _pretend_public(monkeypatch, "localhost")
    connections.public_served_locally = True

    async def go():
        async with common._http_client() as client:
            await client.get(f"http://localhost:{local_server.port}/")

    with pytest.raises(TargetNotAllowedError):
        asyncio.run(go())
    assert connections.hosts == [PUBLIC_IP]
    assert local_server.hits == ["/"]


# =============================================================================
# network.py : ports et services tiers
# =============================================================================


def test_scan_ports_refuse_une_ip_interne():
    with pytest.raises(TargetNotAllowedError) as excinfo:
        asyncio.run(network.scan_ports("127.0.0.1"))
    assert excinfo.value.message == msg("target.ip_not_allowed")


def test_scan_ports_refuse_un_nom_d_hote():
    with pytest.raises(ValueError) as excinfo:
        asyncio.run(network.scan_ports("example.com"))
    assert not isinstance(excinfo.value, TargetNotAllowedError)
    assert message_of(excinfo.value) == msg("target.invalid_ip", ip="'example.com'")


def test_scan_ports_sans_ip():
    assert asyncio.run(network.scan_ports(None)) == []


def test_scan_ports_detecte_un_port_ouvert(monkeypatch, private_allowed):
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.bind(("127.0.0.1", 0))
    listener.listen()
    port = listener.getsockname()[1]
    monkeypatch.setattr(network, "COMMON_PORTS", {port: "Test"})
    try:
        result = asyncio.run(network.scan_ports("127.0.0.1"))
    finally:
        listener.close()
    assert result == [{"port": port, "state": "open", "service": "Test"}]


def test_scan_ports_hote_injoignable_leve_module_error(monkeypatch):
    async def injoignable(host, port, **kwargs):
        raise OSError("Réseau injoignable")

    monkeypatch.setattr(asyncio, "open_connection", injoignable)
    with pytest.raises(ModuleError):
        asyncio.run(network.scan_ports(PUBLIC_IP))


def _api_factory(monkeypatch, handler):
    """Remplace le client des API tierces de network.py par un MockTransport."""

    def factory(timeout=10.0):
        return common._api_client(timeout, transport=httpx.MockTransport(handler))

    monkeypatch.setattr(network, "_api_client", factory)


def _no_api(monkeypatch):
    def factory(timeout=10.0):
        raise AssertionError("aucun service tiers ne doit être interrogé")

    monkeypatch.setattr(network, "_api_client", factory)


@pytest.mark.parametrize("ip", ["10.0.0.1", "127.0.0.1", "169.254.169.254", "fd00::1"])
def test_geo_et_reseau_etendu_sans_tiers_pour_une_ip_interne(monkeypatch, private_allowed, ip):
    _no_api(monkeypatch)
    geo = asyncio.run(network.get_geo_data(ip))
    assert geo["measured"] is False and geo["skipped"] is True
    assert "non publique" in fr(geo["error"])
    extended = asyncio.run(network.extended_network_scan(ip, "intranet"))
    assert extended["measured"] is False and extended["skipped"] is True


def test_geo_ip_invalide(monkeypatch):
    _no_api(monkeypatch)
    geo = asyncio.run(network.get_geo_data("pas-une-ip"))
    assert geo["measured"] is False
    assert fr(geo["error"]) == "Adresse IP invalide : géolocalisation impossible"


def test_geolocalisation_https_ipinfo(monkeypatch, fake_dns):
    fake_dns["ipinfo.io"] = ["34.117.59.81"]
    seen = []

    def handler(request):
        seen.append(str(request.url))
        return httpx.Response(
            200,
            json={
                "ip": PUBLIC_IP,
                "city": "Norwell",
                "region": "Massachusetts",
                "country": "US",
                "loc": "42.1508,-70.8228",
                "org": "AS15133 Edgecast Inc.",
                "postal": "02061",
                "timezone": "America/New_York",
            },
        )

    _api_factory(monkeypatch, handler)
    geo = asyncio.run(network.get_geo_data(PUBLIC_IP))
    assert seen == [f"https://ipinfo.io/{PUBLIC_IP}/json"]
    assert geo["measured"] is True and geo["error"] is None
    assert geo["country_code"] == "US" and geo["city"] == "Norwell"
    assert (geo["lat"], geo["lon"]) == (42.1508, -70.8228)
    assert geo["as_info"] == "AS15133 Edgecast Inc." and geo["isp"] == "Edgecast Inc."


def test_geolocalisation_quota_depasse(monkeypatch, fake_dns):
    fake_dns["ipinfo.io"] = ["34.117.59.81"]
    _api_factory(monkeypatch, lambda request: httpx.Response(429, text="Too Many Requests"))
    geo = asyncio.run(network.get_geo_data(PUBLIC_IP))
    assert geo["measured"] is False
    assert "429" in fr(geo["error"])


def _extended_handler(ipinfo_json, hackertarget_text, ipinfo_status=200):
    def handler(request):
        if request.url.host == "ipinfo.io":
            return httpx.Response(ipinfo_status, json=ipinfo_json)
        assert str(request.url).startswith("https://api.hackertarget.com/")
        return httpx.Response(200, text=hackertarget_text)

    return handler


@pytest.fixture
def api_dns(fake_dns):
    fake_dns["ipinfo.io"] = ["34.117.59.81"]
    fake_dns["api.hackertarget.com"] = ["172.67.75.1"]
    return fake_dns


def test_reseau_etendu_quota_hackertarget(monkeypatch, api_dns):
    _api_factory(
        monkeypatch,
        _extended_handler(
            {"org": "AS15133 Edgecast Inc.", "hostname": "<script>alert(1)</script>"},
            "API count exceeded - Increase Quota with Membership",
        ),
    )
    result = asyncio.run(network.extended_network_scan(PUBLIC_IP, "example.com"))
    assert result["reverse_ip_neighbors"] == []
    assert "Quota" in fr(result["neighbors_error"])
    assert result["asn_info"]["asn"] == "AS15133"
    assert result["asn_info"]["org"] == "Edgecast Inc."
    # PTR choisi par le propriétaire de l'IP : invalide, donc écarté
    assert result["asn_info"]["hostname"] is None
    assert result["measured"] is True
    assert "ip_range" not in result


def test_reseau_etendu_filtre_les_voisins(monkeypatch, api_dns):
    _api_factory(
        monkeypatch,
        _extended_handler(
            {"org": "AS15133 Edgecast Inc.", "hostname": "host.example.net"},
            "errorpage.example.com\nwww.example.com\nexample.com\n<img src=x onerror=alert(1)>\n"
            "errorpage.example.com\n",
        ),
    )
    result = asyncio.run(network.extended_network_scan(PUBLIC_IP, "example.com"))
    assert result["reverse_ip_neighbors"] == ["errorpage.example.com", "www.example.com"]
    assert result["neighbors_error"] is None
    assert result["asn_info"]["hostname"] == "host.example.net"


def test_reseau_etendu_aucun_voisin(monkeypatch, api_dns):
    _api_factory(monkeypatch, _extended_handler({"org": "AS1 X"}, f"No DNS A records found for {PUBLIC_IP}"))
    result = asyncio.run(network.extended_network_scan(PUBLIC_IP, "example.com"))
    assert result["reverse_ip_neighbors"] == [] and result["neighbors_error"] is None


def test_reseau_etendu_reponse_inattendue(monkeypatch, api_dns):
    _api_factory(monkeypatch, _extended_handler({"org": "AS1 X"}, "error check your search parameter"))
    result = asyncio.run(network.extended_network_scan(PUBLIC_IP, "example.com"))
    assert result["reverse_ip_neighbors"] == []
    assert result["neighbors_error"]


def test_reseau_etendu_deux_sources_en_echec(monkeypatch, api_dns):
    _api_factory(monkeypatch, _extended_handler({}, "API count exceeded", ipinfo_status=503))
    result = asyncio.run(network.extended_network_scan(PUBLIC_IP, "example.com"))
    assert result["measured"] is False
    assert "503" in fr(result["error"]) and "Quota" in fr(result["error"])


# =============================================================================
# Capture d'écran : nom de fichier, proxy filtrant, Chromium
# =============================================================================


def test_nom_de_capture_unique_et_compatible():
    names = {screenshot.screenshot_filename("example.com") for _ in range(20)}
    assert len(names) == 20
    for name in names:
        assert screenshot.SCREENSHOT_NAME_RE.match(name)
        # Motif accepté par main.py pour servir les captures
        assert re.match(r"^[a-z0-9_-]+\.png$", name)
    assert screenshot.SCREENSHOT_NAME_RE.match("example_com_1790371130.png")  # ancien format
    assert not screenshot.SCREENSHOT_NAME_RE.match("../x_1_abcdef12.png")


def test_nom_de_capture_borne_en_longueur():
    name = screenshot.screenshot_filename(("a" * 63 + ".") * 3 + "com")
    assert len(name) < 150
    assert screenshot.SCREENSHOT_NAME_RE.match(name)


def test_capture_refuse_une_cible_interne(tmp_path):
    pytest.importorskip("playwright.async_api")
    with pytest.raises(TargetNotAllowedError):
        asyncio.run(screenshot.capture_screenshot("127.0.0.1", str(tmp_path)))
    assert list(tmp_path.iterdir()) == []


async def _read_http_response(reader: asyncio.StreamReader) -> bytes:
    """Lit une réponse (en-tête + Content-Length) ; b"" si la connexion est fermée sans réponse."""
    try:
        head = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), timeout=5)
    except asyncio.IncompleteReadError as e:
        return e.partial
    length = 0
    for line in head.split(b"\r\n"):
        name, _, value = line.partition(b":")
        if name.strip().lower() == b"content-length":
            length = int(value)
    return head + await asyncio.wait_for(reader.readexactly(length), timeout=5)


async def _proxy_exchange(guard: screenshot._NetworkGuard, raw_request: bytes) -> bytes:
    proxy = screenshot._FilteringProxy(guard)
    url = await proxy.start()
    port = int(url.rsplit(":", 1)[1])
    try:
        reader, writer = await asyncio.open_connection("127.0.0.1", port)
        writer.write(raw_request)
        await writer.drain()
        response = await _read_http_response(reader)
        writer.close()
        return response
    finally:
        await proxy.close()


def test_proxy_refuse_connect_vers_hote_interne(local_server):
    guard = screenshot._NetworkGuard()
    request = f"CONNECT 127.0.0.1:{local_server.port} HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n".encode()
    response = asyncio.run(_proxy_exchange(guard, request))
    assert response.startswith(b"HTTP/1.1 403")
    assert guard.blocked == ["127.0.0.1"]


def test_proxy_refuse_requete_http_vers_hote_interne(local_server):
    guard = screenshot._NetworkGuard()
    port = local_server.port
    request = f"GET http://127.0.0.1:{port}/secret HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\n\r\n".encode()
    assert asyncio.run(_proxy_exchange(guard, request)) == b""
    assert local_server.hits == []


def test_proxy_relaie_vers_l_adresse_validee(local_server):
    """Le proxy se connecte à l'adresse validée, sans nouvelle résolution du nom."""
    guard = screenshot._NetworkGuard()
    guard.remember("site.invalid", ["127.0.0.1"])
    port = local_server.port
    local_server.routes["/page"] = (
        200,
        {"Content-Type": "text/plain", "Connection": "keep-alive"},
        b"contenu",
    )
    request = (
        f"GET http://site.invalid:{port}/page HTTP/1.1\r\nHost: site.invalid:{port}\r\n"
        "Proxy-Connection: keep-alive\r\n\r\n"
    ).encode()
    response = asyncio.run(_proxy_exchange(guard, request))
    head, _, body = response.partition(b"\r\n\r\n")
    assert head.startswith(b"HTTP/1.")
    assert b"Connection: close" in head and b"keep-alive" not in head.lower()
    assert body == b"contenu"
    assert local_server.hits == ["/page"]


def test_proxy_refuse_schema_non_http(local_server):
    guard = screenshot._NetworkGuard()
    guard.remember("site.invalid", ["127.0.0.1"])
    request = b"GET ftp://site.invalid/fichier HTTP/1.1\r\nHost: site.invalid\r\n\r\n"
    assert asyncio.run(_proxy_exchange(guard, request)) == b""


@pytest.fixture(scope="module")
def chromium():
    """Saute les tests de capture si Chromium (Playwright) n'est pas installé."""
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
def capture_env(monkeypatch, local_server, chromium):
    """Capture vers le serveur local : « localhost » et les noms en .invalid passent
    pour publics et sont épinglés sur 127.0.0.1.

    Toute autre cible, dont 127.0.0.1 écrit en clair, reste soumise à la vraie politique.
    """
    real_ensure = targets.ensure_target_allowed

    async def ensure(host):
        if host == "localhost" or host.endswith(".invalid"):
            return ["127.0.0.1"]
        return await real_ensure(host)

    monkeypatch.setattr(screenshot, "ensure_target_allowed", ensure)
    monkeypatch.setattr(screenshot, "SCREENSHOT_SETTLE_MS", 600)

    def target(path, host="localhost"):
        monkeypatch.setattr(
            screenshot, "_capture_urls", lambda domain: [f"http://{host}:{local_server.port}{path}"]
        )

    return SimpleNamespace(server=local_server, target=target)


def test_capture_bloque_sous_ressources_internes_et_websockets(capture_env, tmp_path):
    port = capture_env.server.port
    page = f"""<html><body><h1>Accueil</h1>
        <img src="/autorise.png">
        <img src="http://127.0.0.1:{port}/sonde-img">
        <iframe src="http://127.0.0.1:{port}/sonde-iframe"></iframe>
        <script>
          fetch("/autorise-fetch").catch(() => {{}});
          fetch("http://127.0.0.1:{port}/sonde-fetch").catch(() => {{}});
          try {{ new WebSocket("ws://localhost:{port}/sonde-ws"); }} catch (e) {{}}
        </script></body></html>"""
    capture_env.server.routes["/"] = (200, {"Content-Type": "text/html"}, page.encode())
    capture_env.target("/")

    filename = asyncio.run(screenshot.capture_screenshot("localhost", str(tmp_path)))

    assert filename and (tmp_path / filename).is_file()
    hits = capture_env.server.hits
    # Témoins : la page a bien été chargée et son JavaScript exécuté.
    assert "/" in hits and "/autorise.png" in hits and "/autorise-fetch" in hits
    assert not [hit for hit in hits if hit.startswith("/sonde")]


def test_capture_bloque_une_redirection_vers_le_reseau_interne(capture_env, tmp_path):
    port = capture_env.server.port
    capture_env.server.routes["/redir"] = (302, {"Location": f"http://127.0.0.1:{port}/secret"}, b"")
    capture_env.target("/redir")

    with pytest.raises(ModuleError) as excinfo:
        asyncio.run(screenshot.capture_screenshot("localhost", str(tmp_path)))

    assert "127.0.0.1" in str(excinfo.value)
    assert capture_env.server.hits == ["/redir"]
    assert list(tmp_path.iterdir()) == []


def test_capture_resolution_epinglee_par_le_proxy(capture_env, tmp_path):
    """Chromium ne résout aucun nom lui-même : seul le proxy connaît l'adresse validée.

    « epingle.invalid » n'existe dans aucun DNS (TLD réservé) : la page ne peut
    s'afficher que via l'adresse épinglée par le proxy.
    """
    capture_env.target("/", host="epingle.invalid")
    filename = asyncio.run(screenshot.capture_screenshot("epingle.invalid", str(tmp_path)))
    assert filename and Path(tmp_path, filename).is_file()
    assert capture_env.server.hits[:1] == ["/"]


def test_capture_repli_apres_un_echec_de_navigation(capture_env, monkeypatch, tmp_path):
    """Site sans HTTPS : l'échec de la première URL n'empêche pas la capture de la suivante.

    Sur une page unique, la page d'erreur de Chromium (chrome-error://) interrompait
    la navigation de repli : aucun site servi seulement en HTTP n'était capturé.
    """
    with socket.socket() as sock:  # port libre, aussitôt refermé : connexion refusée
        sock.bind(("127.0.0.1", 0))
        closed_port = sock.getsockname()[1]
    port = capture_env.server.port
    monkeypatch.setattr(
        screenshot,
        "_capture_urls",
        lambda domain: [f"https://localhost:{closed_port}/", f"http://localhost:{port}/"],
    )

    filename = asyncio.run(screenshot.capture_screenshot("localhost", str(tmp_path)))

    assert filename and (tmp_path / filename).is_file()
    assert capture_env.server.hits[:1] == ["/"]


def test_proxy_connect_vers_hote_injoignable_repond_502():
    guard = screenshot._NetworkGuard()
    guard.remember("injoignable.invalid", ["127.0.0.1"])
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        closed_port = sock.getsockname()[1]
    request = (
        f"CONNECT injoignable.invalid:{closed_port} HTTP/1.1\r\nHost: injoignable.invalid\r\n\r\n".encode()
    )
    assert asyncio.run(_proxy_exchange(guard, request)).startswith(b"HTTP/1.1 502")


def test_capture_reseau_local_sur_option(monkeypatch, local_server, chromium, private_allowed, tmp_path):
    port = local_server.port
    local_server.routes["/redir"] = (302, {"Location": f"http://127.0.0.1:{port}/final"}, b"")
    monkeypatch.setattr(screenshot, "SCREENSHOT_SETTLE_MS", 200)
    monkeypatch.setattr(screenshot, "_capture_urls", lambda domain: [f"http://localhost:{port}/redir"])

    filename = asyncio.run(screenshot.capture_screenshot("localhost", str(tmp_path)))

    assert filename and (tmp_path / filename).is_file()
    assert local_server.hits[:2] == ["/redir", "/final"]
