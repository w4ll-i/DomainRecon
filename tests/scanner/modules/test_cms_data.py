# =============================================================================
# DomainRecon - Tests du module « cms_data » (sans réseau)
# =============================================================================

import httpx

from domainrecon.scanner.errors import ModuleError
from domainrecon.scanner.modules.cms_data import SPEC
from domainrecon.scanner.rules import FindingInput

ACCUEIL = "<html><head><title>Accueil</title></head><body>" + "Contenu. " * 50 + "</body></html>"


def _entree(data):
    return FindingInput({"cms_data": data}, "cms_data", lambda scan, m: scan.get(m), lambda s, m: True)


def _serveur(routes=None, accueil=ACCUEIL, defaut=404):
    routes = routes or {}

    def repondre(requete: httpx.Request) -> httpx.Response:
        chemin = requete.url.path
        if chemin == "/":
            return httpx.Response(200, headers={"Content-Type": "text/html"}, content=accueil)
        if chemin in routes:
            statut, corps = routes[chemin]
            return httpx.Response(statut, content=corps)
        return httpx.Response(defaut, content="Not Found")

    return repondre


def _lancer(http_simule, contexte, outils, serveur, accueil=None):
    http_simule({})
    http_simule.state["handler"] = serveur
    valeur = outils.executer(SPEC, contexte())
    outils.verifier_sortie(valeur)
    return valeur


def test_wordpress_par_generator(http_simule, contexte, outils):
    accueil = '<html><head><meta name="generator" content="WordPress 6.4.2"></head><body>x</body></html>'
    routes = {"/wp-json/wp/v2/users": (200, '[{"id":1,"name":"admin"}]')}
    valeur = _lancer(http_simule, contexte, outils, _serveur(routes, accueil=accueil))
    assert valeur["cms"] == "WordPress" and valeur["version"] == "6.4.2"
    assert any(i["key"] == "user_enum" for i in valeur["issues"])
    assert SPEC.findings[0].check(_entree(valeur)) is not None


def test_pas_de_cms(http_simule, contexte, outils):
    valeur = _lancer(http_simule, contexte, outils, _serveur())
    assert valeur["cms"] is None and valeur["issues"] == []
    assert not any(r.check(_entree(valeur)) for r in SPEC.findings)


def test_chemin_seul_sans_contenu_non_detecte(http_simule, contexte, outils):
    """Un /README.txt sans mention Joomla ne fait pas conclure à Joomla."""
    routes = {"/README.txt": (200, "Readme générique du site, rien de spécifique.")}
    valeur = _lancer(http_simule, contexte, outils, _serveur(routes))
    assert valeur["cms"] is None


def test_drupal_par_changelog(http_simule, contexte, outils):
    routes = {"/CHANGELOG.txt": (200, "Drupal 9.5.0, 2023-01-05\n- Correctifs divers")}
    valeur = _lancer(http_simule, contexte, outils, _serveur(routes))
    assert valeur["cms"] == "Drupal" and valeur["version"] == "9.5.0"


def test_site_injoignable(http_simule, contexte, outils):
    http_simule({})
    try:
        outils.executer(SPEC, contexte())
    except ModuleError:
        return
    raise AssertionError("ModuleError attendu")
