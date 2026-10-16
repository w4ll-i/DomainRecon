# =============================================================================
# DomainRecon - Outils des tests de modules (tests/scanner/modules/)
# =============================================================================
# Fichier PARTAGÉ (docs/contrat-modules.md) : un module se teste dans
# tests/scanner/modules/test_<clé>.py avec ces fixtures, sans réseau réel.
#
#   - reseau_coupe (automatique) : toute connexion ou résolution réelle échoue
#     (OSError) et fait échouer le test ; la politique de cibles accepte les
#     hôtes simulés ;
#   - http_simule(routes) : simule TOUTES les requêtes HTTP du scanner (cible,
#     API tierces, ScanContext.http). `routes` : {« https://hôte/chemin » :
#     réponse} où la réponse est (statut, en-têtes, corps), un dict ou une liste
#     (réponse JSON 200), une exception (levée) ou une fonction (requête) ->
#     httpx.Response. Route absente : connexion refusée. Rend la liste des
#     requêtes reçues (httpx.Request) ;
#   - dns_simule(zone) : résolveur simulé de scanner.dns (DnsQuerier) :
#     {(nom, type): [rdata ou texte TXT] | classe d'exception}, nom absent :
#     NXDOMAIN ;
#   - contexte(**champs) : ScanContext prêt (example.com, 93.184.216.34,
#     client HTTP simulé, `secrets`) ;
#   - executer(spec, contexte) : lance spec.run(contexte) (asyncio.run) ;
#   - verifier_sortie(valeur, secrets) : sortie conforme (types JSON, measured
#     et error pour un dict, aucune clé API recopiée).
# =============================================================================

import asyncio
import asyncio.base_events
import asyncio.proactor_events
import asyncio.selector_events
import json
import socket
from types import MappingProxyType

import dns.rdata
import dns.rdataclass
import dns.rdatatype
import dns.resolver
import httpx
import pytest

from domainrecon.i18n import is_msg, render
from domainrecon.scanner import common, proxy, targets
from domainrecon.scanner import dns as scanner_dns
from domainrecon.scanner.registry import ScanContext

# Cible et adresse publique des tests (example.com, réservé par l'IANA).
DOMAINE = "example.com"
ADRESSE = "93.184.216.34"
_ROUTES_VIDES: dict = {}


class AccesReseauInterdit(OSError):
    """Accès réseau réel pendant un test de module."""


@pytest.fixture(autouse=True)
def reseau_coupe(monkeypatch):
    """Coupe le réseau réel ; un accès tenté fait échouer le test à la fin, même si le module l'a avalé."""
    tentatives: list[str] = []

    def refuse(*args, **kwargs):
        tentatives.append(repr(args[:2]))
        raise AccesReseauInterdit("Accès réseau réel interdit dans les tests de modules")

    async def refuse_async(*args, **kwargs):
        refuse(*args[1:], **kwargs)

    def local(address) -> bool:
        # La boucle d'événements se parle à elle-même en local (socketpair sous Windows) : permis.
        host = address[0] if isinstance(address, tuple) and address else address
        return host in ("127.0.0.1", "::1", "localhost")

    def guard(name):
        original = getattr(socket.socket, name)

        def method(self, *args, **kwargs):
            address = args[-1] if args else None
            if local(address):
                return original(self, *args, **kwargs)
            return refuse(address)

        return method

    for name in ("getaddrinfo", "gethostbyname", "gethostbyname_ex", "gethostbyaddr", "create_connection"):
        monkeypatch.setattr(socket, name, refuse)
    # Connexions directes à une adresse IP (TCP, UDP : DNS de dnspython, sondes) : refusées aussi.
    for name in ("connect", "connect_ex", "sendto"):
        monkeypatch.setattr(socket.socket, name, guard(name))
    for name in ("create_connection", "create_datagram_endpoint"):
        monkeypatch.setattr(asyncio.base_events.BaseEventLoop, name, refuse_async)
    for loop_class in (
        asyncio.proactor_events.BaseProactorEventLoop,
        asyncio.selector_events.BaseSelectorEventLoop,
    ):
        if loop_class:
            original_connect = loop_class.sock_connect

            async def sock_connect(self, sock, address, _original=original_connect):
                if local(address):
                    return await _original(self, sock, address)
                return refuse(address)

            monkeypatch.setattr(loop_class, "sock_connect", sock_connect)

    async def allowed(host: str) -> list[str]:
        # Politique de cibles : l'hôte simulé est public (adresse de test).
        return [ADRESSE]

    monkeypatch.setattr(common, "ensure_target_allowed", allowed)
    monkeypatch.setattr(targets, "ensure_target_allowed", allowed)
    yield tentatives
    assert not tentatives, f"Accès réseau réel tenté : {tentatives}"


def make_handler(routes: dict, requetes: list):
    """Transport simulé à partir d'une table de routes (voir l'en-tête)."""

    def handler(request: httpx.Request) -> httpx.Response:
        requetes.append(request)
        key = f"{request.url.scheme}://{request.url.host}{request.url.path}"
        action = routes.get(key)
        if action is None:
            raise httpx.ConnectError("Connexion refusée (route non simulée)", request=request)
        if isinstance(action, BaseException):
            raise action
        if callable(action):
            return action(request)
        if isinstance(action, (dict, list)):
            return httpx.Response(200, json=action)
        status, headers, body = action
        if isinstance(body, str):
            body = body.encode("utf-8")
        return httpx.Response(status, headers=headers, content=body)

    return handler


@pytest.fixture
def http_simule(monkeypatch):
    """Installe des routes simulées pour tous les clients HTTP du scanner ; rend les requêtes reçues."""
    state: dict = {"handler": make_handler(_ROUTES_VIDES, [])}
    original = common._guarded_client

    def guarded(transport, **kwargs):
        # Toujours le transport simulé : jamais le réseau, hooks de la politique de cibles conservés.
        return original(httpx.MockTransport(lambda request: state["handler"](request)), **kwargs)

    monkeypatch.setattr(common, "_guarded_client", guarded)
    monkeypatch.setattr(proxy, "_guarded_client", guarded)

    def install(routes: dict) -> list[httpx.Request]:
        requetes: list[httpx.Request] = []
        state["handler"] = make_handler(routes, requetes)
        return requetes

    install.state = state
    return install


def txt(*strings: str):
    """Enregistrement TXT dnspython."""
    text = " ".join('"' + s.replace('"', '\\"') + '"' for s in strings)
    return dns.rdata.from_text(dns.rdataclass.IN, dns.rdatatype.TXT, text)


def rdata(rtype: str, text: str):
    """Enregistrement dnspython d'un type quelconque (« A », « 93.184.216.34 »)."""
    return dns.rdata.from_text(dns.rdataclass.IN, dns.rdatatype.from_text(rtype), text)


class FakeResolver:
    """Résolveur simulé : zone {(nom, type): [rdata ou texte TXT] | classe d'exception} ; nom absent : NXDOMAIN."""

    def __init__(self, zone: dict):
        self.zone = {(name.lower().rstrip("."), rtype): value for (name, rtype), value in zone.items()}
        self.queries: list[tuple[str, str]] = []
        self.timeout = None
        self.lifetime = None

    def resolve(self, qname, rdtype, lifetime=None, **kwargs):
        key = (str(qname).rstrip(".").lower(), rdtype)
        self.queries.append(key)
        value = self.zone.get(key, dns.resolver.NXDOMAIN)
        if isinstance(value, type) and issubclass(value, Exception):
            raise value()
        return [txt(v) if isinstance(v, str) else v for v in value]


@pytest.fixture
def dns_simule(monkeypatch):
    """Installe un résolveur simulé pour scanner.dns (DnsQuerier) ; rend le résolveur."""

    def install(zone: dict) -> FakeResolver:
        resolver = FakeResolver(zone)
        monkeypatch.setattr(scanner_dns, "_make_resolver", lambda: resolver)
        return resolver

    return install


@pytest.fixture
def contexte(http_simule):
    """Fabrique de ScanContext : cible example.com résolue, client des API tierces simulé."""
    clients: list[httpx.AsyncClient] = []

    def make(**fields) -> ScanContext:
        secrets = fields.pop("secrets", {})
        client = proxy.make_http_client(
            transport=httpx.MockTransport(lambda r: http_simule.state["handler"](r))
        )
        clients.append(client)
        values = {"domain": DOMAINE, "addresses": [ADRESSE], "http": client, **fields}
        return ScanContext(secrets=MappingProxyType(dict(secrets)), **values)

    yield make

    async def close_all() -> None:
        for client in clients:
            await client.aclose()

    asyncio.run(close_all())


def executer(spec, context: ScanContext, timeout: float = 30):
    """Lance le module comme l'orchestrateur (sous délai), en dehors de toute boucle."""
    return asyncio.run(asyncio.wait_for(spec.run(context), timeout=timeout))


def verifier_sortie(valeur: object, secrets=()) -> None:
    """Sortie conforme au contrat : types JSON ; dict avec measured (bool) et error ; aucune clé recopiée."""
    texte = json.dumps(valeur, ensure_ascii=False)
    for secret in secrets:
        assert secret not in texte, "une clé API apparaît dans le résultat"
    if isinstance(valeur, dict):
        assert isinstance(valeur.get("measured"), bool), "measured (booléen) manquant"
        assert "error" in valeur, "error manquant"
        error = valeur["error"]
        assert error is None or isinstance(error, str) or is_msg(error), "error : texte ou msg()"
        for secret in secrets:
            assert secret not in json.dumps(render(valeur, "fr"), ensure_ascii=False)


@pytest.fixture
def outils():
    """Accès aux aides sans import : outils.executer, outils.verifier_sortie, outils.txt, outils.rdata."""

    class Outils:
        pass

    tools = Outils()
    tools.executer = executer
    tools.verifier_sortie = verifier_sortie
    tools.txt = txt
    tools.rdata = rdata
    tools.DOMAINE = DOMAINE
    tools.ADRESSE = ADRESSE
    return tools
