# =============================================================================
# DomainRecon - Tests des garde-fous HTTP : décodage borné, choix du proxy,
# contexte TLS des API tierces
# =============================================================================
# Aucun trafic réseau réel : httpx.MockTransport, flux simulés, et un serveur
# local 127.0.0.1 pour la lecture de bout en bout.
# =============================================================================

import asyncio
import functools
import gzip
import ssl
import tracemalloc
import zlib

import httpx
import pytest

import domainrecon
from domainrecon.i18n import msg
from domainrecon.scanner import common, http_utils
from domainrecon.scanner.errors import message_of
from domainrecon.scanner.http_utils import FETCH_ERRORS, fetch, read_body_limited
from rendu import en, fr

# Corps de test varié : texte, toutes les valeurs d'octet, zéros (très compressibles).
PLAIN = b"".join(
    [b"<html><body>", bytes(range(256)) * 40, b"\0" * 5000, b"DomainRecon " * 300, b"</body></html>"]
)


@functools.cache
def _zeros_bomb(mib: int, layers: int = 1) -> bytes:
    """`mib` Mio de zéros compressés `layers` fois en gzip (quelques Ko sur le réseau)."""
    data = bytes(mib << 20)
    for _ in range(layers):
        data = gzip.compress(data)
    return data


def _raw_deflate(data: bytes) -> bytes:
    compressor = zlib.compressobj(wbits=-zlib.MAX_WBITS)
    return compressor.compress(data) + compressor.flush()


class _Chunks(httpx.AsyncByteStream):
    """Corps brut livré par morceaux de `size` octets."""

    def __init__(self, data: bytes, size: int) -> None:
        self._data = data
        self._size = size

    async def __aiter__(self):
        for start in range(0, len(self._data), self._size):
            yield self._data[start : start + self._size]


def _read(data: bytes, encoding: str | None, max_bytes: int, size: int = 65536) -> tuple[bytes, bool]:
    headers = {"Content-Encoding": encoding} if encoding else {}
    response = httpx.Response(
        200, headers=headers, stream=_Chunks(data, size), request=httpx.Request("GET", "http://x.example/")
    )
    return asyncio.run(read_body_limited(response, max_bytes))


def _fetch(headers, body: bytes, max_bytes: int):
    """fetch() sur un transport simulé dont le corps arrive en streaming (non lu d'avance)."""

    def handler(request):
        return httpx.Response(200, headers=headers, stream=_Chunks(body, 65536))

    async def go():
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
            return await fetch(client, "http://x.example/", max_bytes=max_bytes)

    return asyncio.run(go())


def _peak_mib(func):
    """(résultat, pic d'allocation en Mio) d'un appel."""
    tracemalloc.start()
    try:
        result = func()
        peak = tracemalloc.get_traced_memory()[1]
    finally:
        tracemalloc.stop()
    return result, peak / (1024 * 1024)


# =============================================================================
# read_body_limited : décodage borné
# =============================================================================


@pytest.mark.parametrize(
    "encoding, data",
    [
        pytest.param("gzip", gzip.compress(PLAIN), id="gzip"),
        pytest.param("x-gzip", gzip.compress(PLAIN), id="x-gzip"),
        pytest.param("GZIP", gzip.compress(PLAIN), id="GZIP"),
        pytest.param("deflate", zlib.compress(PLAIN), id="deflate"),
        # deflate brut (sans en-tête zlib) : envoyé par certains serveurs
        pytest.param("deflate", _raw_deflate(PLAIN), id="deflate-brut"),
        pytest.param("identity, gzip", gzip.compress(PLAIN), id="identity-gzip"),
        pytest.param("identity", PLAIN, id="identity"),
        pytest.param(None, PLAIN, id="aucun"),
    ],
)
@pytest.mark.parametrize("size", [1, 7, 4096, 1 << 20])
def test_decodage_complet_quel_que_soit_le_decoupage(encoding, data, size):
    assert _read(data, encoding, 1 << 20, size) == (PLAIN, False)


@pytest.mark.parametrize(
    "encoding, encode",
    [
        pytest.param("gzip", gzip.compress, id="gzip"),
        pytest.param("deflate", zlib.compress, id="deflate"),
        pytest.param(None, bytes, id="aucun"),
    ],
)
@pytest.mark.parametrize("max_bytes", [1, 100, len(PLAIN) - 1, len(PLAIN), len(PLAIN) + 1])
@pytest.mark.parametrize("size", [3, 65536])
def test_limite_appliquee_au_corps_decode(encoding, encode, max_bytes, size):
    body, truncated = _read(encode(PLAIN), encoding, max_bytes, size)
    assert body == PLAIN[:max_bytes]
    assert truncated is (len(PLAIN) > max_bytes)


def test_sans_limite_le_corps_n_est_pas_lu():
    assert _read(gzip.compress(PLAIN), "gzip", 0) == (b"", False)


def test_encodage_inconnu_rendu_brut_comme_httpx():
    assert _read(b"octets-brotli", "br", 1024) == (b"octets-brotli", False)


def test_bombe_gzip_simple_bornee():
    """64 Mio de zéros en ~64 Ko : seule la part demandée est décompressée."""
    bomb = _zeros_bomb(64)
    (body, truncated), peak = _peak_mib(lambda: _read(bomb, "gzip", 64 * 1024, len(bomb)))
    assert len(body) == 64 * 1024 and truncated is True
    assert peak < 8


@pytest.mark.parametrize("encoding", ["gzip, gzip", "gzip,deflate", "deflate, gzip, identity"])
def test_encodages_empiles_refuses(encoding):
    """« gzip, gzip » : quelques centaines d'octets pour 64 Mio ; corps non décodé."""
    bomb = _zeros_bomb(64, layers=2)
    assert len(bomb) < 2048
    (body, truncated), peak = _peak_mib(lambda: _read(bomb, encoding, 1 << 20))
    assert (body, truncated) == (b"", True)
    assert peak < 4


def test_en_tetes_content_encoding_multiples_refuses():
    result = _fetch(
        [("Content-Encoding", "gzip"), ("Content-Encoding", "gzip")], _zeros_bomb(64, layers=2), 1 << 20
    )
    assert (result.body, result.truncated) == (b"", True)
    # Statut et en-têtes restent exploitables.
    assert result.status_code == 200


@pytest.mark.parametrize("encoding", ["gzip", "deflate"])
def test_corps_compresse_invalide_leve_decoding_error(encoding):
    with pytest.raises(httpx.DecodingError) as excinfo:
        _fetch({"Content-Encoding": encoding}, b"pas du tout compresse " * 20, 1 << 20)
    # Erreur ordinaire d'une requête : les modules la traitent déjà.
    assert isinstance(excinfo.value, FETCH_ERRORS)
    # Message traduisible (texte de zlib repris tel quel) ; str() reste en français pour les journaux.
    message = message_of(excinfo.value)
    assert message["$t"] == "http.bad_compressed_body"
    assert str(excinfo.value).startswith("Corps compressé invalide : ")
    assert fr(message) == str(excinfo.value)
    assert en(message) == f"Invalid compressed body: {message['p']['detail']}"


def test_decodeur_bloque_leve_decoding_error_traduisible(monkeypatch):
    """Garde-fou : un décodeur qui n'avance plus ne fait jamais boucler la lecture."""
    monkeypatch.setattr(http_utils._BoundedDecoder, "decode", lambda self, data, room: (b"", data))
    with pytest.raises(httpx.DecodingError) as excinfo:
        _read(gzip.compress(PLAIN), "gzip", 1 << 20)
    assert str(excinfo.value) == "Corps compressé invalide : décompression bloquée"  # journaux : français
    assert fr(message_of(excinfo.value)) == "Corps compressé invalide : décompression bloquée"
    assert en(message_of(excinfo.value)) == "Invalid compressed body: decompression stalled"
    # La cause (erreur de zlib) porte aussi son message.
    assert isinstance(excinfo.value.__cause__, zlib.error)
    assert message_of(excinfo.value.__cause__) == msg("http.decompression_stuck")


@pytest.mark.parametrize("max_bytes, expected", [(10, (PLAIN[:10], True)), (1 << 20, (PLAIN, False))])
def test_corps_deja_lu_seulement_borne(max_bytes, expected):
    """httpx.Response(content=…) (transports simulés) : corps déjà lu et décodé par httpx."""
    response = httpx.Response(200, headers={"Content-Encoding": "gzip"}, content=gzip.compress(PLAIN))
    assert asyncio.run(read_body_limited(response, max_bytes)) == expected


def test_flux_gzip_incomplet_rendu_partiellement():
    """Connexion coupée en cours de flux : ce qui a été reçu est rendu, comme httpx."""
    body, truncated = _read(gzip.compress(PLAIN)[:-200], "gzip", 1 << 20)
    assert PLAIN.startswith(body) and 0 < len(body) < len(PLAIN)
    assert truncated is False


def test_bombe_empilee_sur_un_vrai_serveur(monkeypatch):
    """Bout en bout avec le vrai client HTTP : le corps « gzip, gzip » n'est pas développé."""
    monkeypatch.setenv("ALLOW_PRIVATE_TARGETS", "1")
    bomb = _zeros_bomb(64, layers=2)

    async def handle(reader, writer):
        try:
            await reader.readuntil(b"\r\n\r\n")
            writer.write(
                b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Encoding: gzip, gzip\r\n"
                + f"Content-Length: {len(bomb)}\r\nConnection: close\r\n\r\n".encode()
                + bomb
            )
            await writer.drain()
        finally:
            writer.close()

    async def scenario():
        server = await asyncio.start_server(handle, "127.0.0.1", 0)
        port = server.sockets[0].getsockname()[1]
        try:
            async with common._http_client(timeout=5.0) as client:
                return await fetch(client, f"http://127.0.0.1:{port}/", max_bytes=1 << 20)
        finally:
            server.close()

    result, peak = _peak_mib(lambda: asyncio.run(scenario()))
    assert (result.body, result.truncated) == (b"", True)
    assert peak < 16


def test_client_n_annonce_que_les_encodages_bornes():
    seen = []

    def handler(request):
        seen.append(request.headers.get("accept-encoding"))
        return httpx.Response(200)

    async def go():
        async with common._http_client(transport=httpx.MockTransport(handler)) as client:
            await client.get("http://93.184.216.34/")

    asyncio.run(go())
    assert seen == [common.ACCEPT_ENCODING] == ["gzip, deflate"]


def test_user_agent_reprend_la_version_de_l_application():
    """Le User-Agent annonce la version du package (domainrecon.__version__), pas un numéro figé."""
    assert domainrecon.__version__ in common.USER_AGENT
    assert common.USER_AGENT == (
        f"DomainRecon/{domainrecon.__version__} (+https://github.com/w4ll-i/DomainRecon)"
    )
    seen = []

    def handler(request):
        seen.append(request.headers.get("user-agent"))
        return httpx.Response(200)

    async def go():
        # Clients de la cible et des API tierces : le même User-Agent.
        for client in (
            common._http_client(transport=httpx.MockTransport(handler)),
            common._api_client(transport=httpx.MockTransport(handler)),
        ):
            async with client:
                await client.get("http://93.184.216.34/")

    asyncio.run(go())
    assert seen == [common.USER_AGENT, common.USER_AGENT]


# =============================================================================
# Choix du proxy : même décision que httpx, URL par URL
# =============================================================================


def _proxy_env(monkeypatch, **env):
    """Remplace les variables de proxy de l'environnement par `env`.

    `env` n'est jamais vide : sinon getproxies() lirait le registre Windows.
    """
    for name in ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY", "SOCKS_PROXY", "FTP_PROXY"):
        monkeypatch.delenv(name, raising=False)
        monkeypatch.delenv(name.lower(), raising=False)
    for name, value in env.items():
        monkeypatch.setenv(name, value)


@pytest.mark.parametrize(
    "env, expected",
    [
        # NO_PROXY seul, SOCKS_PROXY, FTP_PROXY : httpx n'emprunte aucun proxy.
        ({"NO_PROXY": "localhost,127.0.0.1"}, {}),
        ({"NO_PROXY": "*"}, {}),
        ({"SOCKS_PROXY": "socks5://127.0.0.1:1080", "FTP_PROXY": "http://127.0.0.1:21"}, {}),
        ({"HTTPS_PROXY": "proxy.example:3128"}, {"https": "http://proxy.example:3128"}),
        (
            {
                "HTTP_PROXY": "http://proxy.example:3128",
                "ALL_PROXY": "http://all.example:8080",
                "NO_PROXY": "intra",
            },
            {"http": "http://proxy.example:3128", "all": "http://all.example:8080", "no": "intra"},
        ),
    ],
)
def test_proxys_de_l_environnement_lus_comme_httpx(monkeypatch, env, expected):
    _proxy_env(monkeypatch, **env)
    assert common._environment_proxies() == expected


P = "http://proxy.example:3128"


@pytest.mark.parametrize(
    "proxies, url, expected",
    [
        ({}, "http://site.example/", None),
        # Proxy HTTPS seul : une URL en http:// part en direct.
        ({"https": P}, "http://site.example/", None),
        ({"https": P}, "https://site.example/", P),
        ({"all": P}, "http://site.example/", P),
        ({"http": P, "all": "http://autre.example:1"}, "http://site.example/", P),
        # Exclusions NO_PROXY
        ({"http": P, "no": "*"}, "http://site.example/", None),
        ({"http": P, "no": "intranet.example, *"}, "http://site.example/", None),
        ({"http": P, "no": "site.example"}, "http://site.example/", None),
        ({"http": P, "no": "site.example"}, "http://www.site.example/", None),
        ({"http": P, "no": ".site.example"}, "http://www.site.example/", None),
        ({"http": P, "no": "site.example"}, "http://autresite.example/", P),
        ({"http": P, "no": "site.example:8080"}, "http://site.example:8080/", None),
        ({"http": P, "no": "site.example:8080"}, "http://site.example/", P),
        ({"http": P, "no": "localhost,127.0.0.1"}, "http://127.0.0.1:8000/", None),
        ({"http": P, "no": "::1"}, "http://[::1]:8000/", None),
        ({"http": P, "no": "::1"}, "http://[::2]/", P),
    ],
)
def test_proxy_decide_url_par_url(proxies, url, expected):
    assert common._proxy_for_url(httpx.URL(url), proxies) == expected


# =============================================================================
# Clients des API tierces : contexte TLS vérifiant construit une seule fois
# =============================================================================


def test_contexte_tls_des_api_construit_une_seule_fois(monkeypatch):
    """Régression : chaque client d'API reconstruisait son contexte TLS (~0,5 s de calcul
    synchrone), ce qui bloquait la boucle d'événements au démarrage des scans."""
    built = []
    real = httpx.create_ssl_context

    def counting(*args, **kwargs):
        built.append(1)
        return real(*args, **kwargs)

    monkeypatch.setattr(httpx, "create_ssl_context", counting)
    _proxy_env(monkeypatch, HTTPS_PROXY="http://127.0.0.1:9")
    common._verified_ssl_context.cache_clear()
    clients = [common._api_client() for _ in range(3)]
    try:
        contexts = {
            id(pool._ssl_context)
            for client in clients
            for pool in (
                client._transport._direct._pool,
                *(t._pool for t in client._transport._via_proxy.values()),
            )
        }
        context = clients[0]._transport._direct._pool._ssl_context
        assert len(built) == 1
        assert len(contexts) == 1  # connexions directes et via le proxy
        assert context.verify_mode == ssl.CERT_REQUIRED and context.check_hostname is True
    finally:
        for client in clients:
            asyncio.run(client.aclose())
        common._verified_ssl_context.cache_clear()
