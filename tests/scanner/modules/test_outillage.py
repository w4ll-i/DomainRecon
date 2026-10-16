# =============================================================================
# DomainRecon - Tests de l'outillage des tests de modules (conftest.py voisin)
# =============================================================================

import asyncio
import socket

import pytest

from domainrecon.i18n import msg
from domainrecon.scanner import common, dns, http_utils
from domainrecon.scanner.errors import ModuleError
from domainrecon.scanner.registry import ModuleSpec


def test_http_simule_couvre_api_cible_et_contexte(http_simule, contexte):
    requetes = http_simule(
        {
            "https://api.example.org/v1/info": {"ok": True},
            "https://example.com/": (200, {"X-Test": "1"}, "<html>accueil</html>"),
        }
    )
    context = contexte(secrets={"demo_key": "valeur"})

    async def scenario():
        api = await context.http.get("https://api.example.org/v1/info")
        async with common._http_client() as client:
            fetched = await http_utils.fetch(client, "https://example.com/", site="example.com")
        home = await context.homepage()
        return api.json(), fetched.text, home

    api, page, home = asyncio.run(scenario())

    assert api == {"ok": True} and page == "<html>accueil</html>"
    assert home.status_code == 200 and home.headers["x-test"] == "1"
    assert [str(r.url) for r in requetes][:2] == ["https://api.example.org/v1/info", "https://example.com/"]
    assert dict(context.secrets) == {"demo_key": "valeur"}


def test_route_absente_connexion_refusee(http_simule, contexte):
    http_simule({})
    context = contexte()

    async def scenario():
        await context.http.get("https://inconnu.example/")

    with pytest.raises(Exception, match="route non simulée"):
        asyncio.run(scenario())


def test_dns_simule(dns_simule, outils):
    resolver = dns_simule(
        {("example.com", "TXT"): ["v=spf1 -all"], ("example.com", "A"): [outils.rdata("A", "93.184.216.34")]}
    )
    querier = dns.DnsQuerier(query_timeout=1, budget=5)

    assert querier.lookup("example.com", "TXT").status == "ok"
    assert [str(a) for a in querier.lookup("example.com", "A").answers] == ["93.184.216.34"]
    assert querier.lookup("absent.example.com", "A").status == "nxdomain"
    assert ("example.com", "TXT") in resolver.queries


def test_reseau_reel_coupe(reseau_coupe):
    with pytest.raises(OSError):
        socket.create_connection(("93.184.216.34", 443))
    with pytest.raises(OSError):
        socket.getaddrinfo("example.com", 443)
    # La tentative est notée : vidée ici, sinon le test échouerait à la fin.
    assert len(reseau_coupe) == 2
    reseau_coupe.clear()


def test_verifier_sortie(outils):
    outils.verifier_sortie({"measured": True, "error": None, "x": [1]})
    outils.verifier_sortie({"measured": False, "error": msg("orchestrator.skip_generic")})
    with pytest.raises(AssertionError):
        outils.verifier_sortie({"error": None})
    with pytest.raises(AssertionError):
        outils.verifier_sortie({"measured": True, "error": None, "fuite": "cle-123"}, secrets=["cle-123"])
    with pytest.raises(TypeError):
        outils.verifier_sortie({"measured": True, "error": None, "ensemble": {1}})


def test_executer_un_module(contexte, outils):
    async def run(context):
        if not context.secrets:
            raise ModuleError(msg("orchestrator.module_failed"))
        return {"measured": True, "error": None}

    spec = ModuleSpec(name="demo_outillage", family="leaks", category="passif", run=run)

    assert outils.executer(spec, contexte(secrets={"k": "v"})) == {"measured": True, "error": None}
    with pytest.raises(ModuleError):
        outils.executer(spec, contexte())
