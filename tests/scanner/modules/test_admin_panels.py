# =============================================================================
# DomainRecon - Tests du module « admin_panels » (sans réseau)
# =============================================================================

import httpx

from domainrecon.scanner.errors import ModuleError
from domainrecon.scanner.modules.admin_panels import SPEC
from domainrecon.scanner.rules import FindingInput

ACCUEIL = "<html><head><title>Accueil</title></head><body>" + "Contenu. " * 50 + "</body></html>"


def _entree(data):
    return FindingInput(
        {"admin_panels": data}, "admin_panels", lambda scan, m: scan.get(m), lambda s, m: True
    )


def _serveur(routes=None, accueil=ACCUEIL, defaut=404):
    routes = routes or {}

    def repondre(requete: httpx.Request) -> httpx.Response:
        chemin = requete.url.path
        if chemin == "/":
            return httpx.Response(200, headers={"Content-Type": "text/html"}, content=accueil)
        if chemin in routes:
            statut, headers, corps = routes[chemin]
            return httpx.Response(statut, headers=headers, content=corps)
        return httpx.Response(defaut, content="Not Found")

    return repondre


def _lancer(http_simule, contexte, outils, serveur):
    http_simule({})
    http_simule.state["handler"] = serveur
    valeur = outils.executer(SPEC, contexte())
    outils.verifier_sortie(valeur)
    return valeur


def test_panneau_par_signature_de_produit(http_simule, contexte, outils):
    page = "<html><body><h1>phpMyAdmin</h1>" + "Welcome to phpMyAdmin, please login. " * 5 + "</body></html>"
    valeur = _lancer(http_simule, contexte, outils, _serveur({"/phpmyadmin/": (200, {}, page)}))
    pma = next(p for p in valeur["panels"] if p["path"] == "/phpmyadmin/")
    assert pma["confidence"] == "high" and pma["product"] == "phpMyAdmin"


def test_401_retenu_si_pas_la_norme(http_simule, contexte, outils):
    valeur = _lancer(http_simule, contexte, outils, _serveur({"/admin": (401, {}, "Denied")}))
    assert any(p["path"] == "/admin" and p["reason"] == "access_denied" for p in valeur["panels"])


def test_401_partout_non_retenu(http_simule, contexte, outils):
    """Un serveur qui répond 401 à toute URL (dont la ligne de base) ne donne aucun panneau."""
    valeur = _lancer(http_simule, contexte, outils, _serveur(defaut=401))
    assert valeur["panels"] == []


def test_redirection_barre_oblique_ignoree(http_simule, contexte, outils):
    routes = {"/admin": (301, {"Location": "https://example.com/admin/"}, "")}
    valeur = _lancer(http_simule, contexte, outils, _serveur(routes))
    assert all(p["path"] != "/admin" for p in valeur["panels"])


def test_redirection_vers_login_confiance_haute(http_simule, contexte, outils):
    routes = {"/dashboard": (302, {"Location": "https://example.com/auth/login"}, "")}
    valeur = _lancer(http_simule, contexte, outils, _serveur(routes))
    panel = next(p for p in valeur["panels"] if p["path"] == "/dashboard")
    assert panel["confidence"] == "high" and panel["reason"] == "redirect"


def test_serveur_fourre_tout_aucun_faux_positif(http_simule, contexte, outils):
    def serveur(requete):
        return httpx.Response(200, headers={"Content-Type": "text/html"}, content=ACCUEIL)

    valeur = _lancer(http_simule, contexte, outils, serveur)
    assert valeur["panels"] == [] and valeur["catch_all"] is True


def test_rien_trouve_et_constat(http_simule, contexte, outils):
    valeur = _lancer(http_simule, contexte, outils, _serveur())
    assert valeur["count"] == 0
    assert SPEC.findings[0].check(_entree(valeur)) is None


def test_site_injoignable(http_simule, contexte, outils):
    http_simule({})
    try:
        outils.executer(SPEC, contexte())
    except ModuleError:
        return
    raise AssertionError("ModuleError attendu")
