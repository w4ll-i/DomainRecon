# =============================================================================
# DomainRecon - Tests du module « api_endpoints » (sans réseau)
# =============================================================================

import json

import httpx

from domainrecon.scanner.errors import ModuleError
from domainrecon.scanner.modules.api_endpoints import SPEC
from domainrecon.scanner.rules import FindingInput

ACCUEIL = "<html><head><title>Accueil</title></head><body>" + "Contenu. " * 50 + "</body></html>"


def _entree(data):
    return FindingInput(
        {"api_endpoints": data}, "api_endpoints", lambda scan, m: scan.get(m), lambda s, m: True
    )


def _serveur(routes=None, defaut=404):
    routes = routes or {}

    def repondre(requete: httpx.Request) -> httpx.Response:
        chemin = requete.url.path
        if chemin == "/":
            return httpx.Response(200, headers={"Content-Type": "text/html"}, content=ACCUEIL)
        if chemin in routes:
            action = routes[chemin]
            if callable(action):
                return action(requete)
            statut, headers, corps = action
            return httpx.Response(statut, headers=headers, content=corps)
        return httpx.Response(defaut, content="Not Found")

    return repondre


def _lancer(http_simule, contexte, outils, serveur):
    http_simule({})
    http_simule.state["handler"] = serveur
    valeur = outils.executer(SPEC, contexte())
    outils.verifier_sortie(valeur)
    return valeur


def test_openapi_detecte_par_contenu(http_simule, contexte, outils):
    body = json.dumps({"openapi": "3.0.0", "paths": {}})
    routes = {"/openapi.json": (200, {"Content-Type": "application/json"}, body)}
    valeur = _lancer(http_simule, contexte, outils, _serveur(routes))
    e = next(x for x in valeur["endpoints"] if x["path"] == "/openapi.json")
    assert e["type"] == "openapi" and e["severity"] == "high"


def test_json_sans_forme_openapi_non_retenu(http_simule, contexte, outils):
    """Un /openapi.json qui n'est pas du JSON OpenAPI (page HTML) est écarté."""
    routes = {"/openapi.json": (200, {"Content-Type": "text/html"}, "<html>404-like</html>")}
    valeur = _lancer(http_simule, contexte, outils, _serveur(routes))
    assert all(x["path"] != "/openapi.json" for x in valeur["endpoints"])


def test_actuator_par_links(http_simule, contexte, outils):
    body = json.dumps({"_links": {"self": {"href": "/actuator"}}})
    routes = {"/actuator": (200, {"Content-Type": "application/json"}, body)}
    valeur = _lancer(http_simule, contexte, outils, _serveur(routes))
    assert any(x["type"] == "actuator" for x in valeur["endpoints"])


def test_prometheus_par_corps(http_simule, contexte, outils):
    body = "# HELP http_requests_total Total\n# TYPE http_requests_total counter\nhttp_requests_total 5\n"
    routes = {"/metrics": (200, {"Content-Type": "text/plain"}, body)}
    valeur = _lancer(http_simule, contexte, outils, _serveur(routes))
    assert any(x["type"] == "metrics" for x in valeur["endpoints"])


def test_graphql_introspection_confirmee(http_simule, contexte, outils):
    def graphql(requete):
        if requete.method == "POST":
            return httpx.Response(200, json={"data": {"__schema": {"types": []}}})
        return httpx.Response(200, json={"data": None})

    valeur = _lancer(http_simule, contexte, outils, _serveur({"/graphql": graphql}))
    e = next(x for x in valeur["endpoints"] if x["path"] == "/graphql")
    assert e.get("introspection") is True and e["severity"] == "high"


def test_401_partout_non_retenu(http_simule, contexte, outils):
    valeur = _lancer(http_simule, contexte, outils, _serveur(defaut=401))
    assert valeur["endpoints"] == []


def test_rien_trouve(http_simule, contexte, outils):
    valeur = _lancer(http_simule, contexte, outils, _serveur())
    assert valeur["count"] == 0
    assert not any(r.check(_entree(valeur)) for r in SPEC.findings)


def test_site_injoignable(http_simule, contexte, outils):
    http_simule({})
    try:
        outils.executer(SPEC, contexte())
    except ModuleError:
        return
    raise AssertionError("ModuleError attendu")
