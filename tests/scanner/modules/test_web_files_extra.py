# =============================================================================
# DomainRecon - Tests du module « web_files_extra » (sans réseau)
# =============================================================================

import json

import httpx
import pytest

from domainrecon.scanner.errors import ModuleError
from domainrecon.scanner.impl import web_files_extra as logic
from domainrecon.scanner.modules.web_files_extra import SPEC
from domainrecon.scanner.rules import FindingInput

ACCUEIL = "<html><head><title>Accueil</title></head><body>" + "Contenu. " * 50 + "</body></html>"
CROSSDOMAIN = '<?xml version="1.0"?><cross-domain-policy><allow-access-from domain="*" secure="false"/></cross-domain-policy>'
ADS = "# ads.txt\nexample.com, pub-1234, DIRECT, f08c47fec0942fa0\nadnetwork.com, 9876, RESELLER\nOWNERDOMAIN=example.com\n"
OIDC = {
    "issuer": "https://example.com",
    "authorization_endpoint": "https://example.com/auth",
    "token_endpoint": "https://example.com/token",
    "jwks_uri": "https://example.com/jwks",
    "response_types_supported": ["code"],
    "id_token_signing_alg_values_supported": ["RS256", "none"],
}


def _entree(data):
    return FindingInput(
        {"web_files_extra": data}, "web_files_extra", lambda scan, m: scan.get(m), lambda s, m: True
    )


def _serveur(fichiers=None, accueil=ACCUEIL, fourre_tout=False):
    """Serveur simulé : `fichiers` {chemin: (statut, type, corps)} ; le reste donne 404 (ou l'accueil en 200)."""
    fichiers = fichiers or {}

    def repondre(requete: httpx.Request) -> httpx.Response:
        chemin = requete.url.path
        if chemin == "/":
            return httpx.Response(200, headers={"Content-Type": "text/html"}, content=accueil)
        if chemin in fichiers:
            statut, type_, corps = fichiers[chemin]
            en_tetes = {"Content-Type": type_}
            if statut in (301, 302):
                en_tetes["Location"] = "/compte/mot-de-passe"
            return httpx.Response(statut, headers=en_tetes, content=corps)
        if fourre_tout:
            return httpx.Response(200, headers={"Content-Type": "text/html"}, content=accueil)
        return httpx.Response(404, content="Not Found")

    return repondre


def _lancer(http_simule, contexte, outils, serveur):
    requetes = http_simule({})
    http_simule.state["handler"] = lambda requete: (requetes.append(requete), serveur(requete))[1]
    valeur = outils.executer(SPEC, contexte())
    outils.verifier_sortie(valeur)
    return valeur, requetes


# --- Validateurs --------------------------------------------------------------------------


def test_ads_txt():
    details = logic.validate("ads", ADS, "text/plain")
    assert details["records"] == 2 and details["direct"] == 1 and details["reseller"] == 1
    assert details["ownerdomain"] == "example.com" and details["sellers"] == ["example.com", "adnetwork.com"]
    assert logic.validate("ads", "rien d'utile ici", "text/plain") is None


def test_html_est_refuse_pour_un_fichier_de_donnees():
    assert logic.validate("text", ACCUEIL, "text/html") is None
    assert logic.validate("manifest", "<!DOCTYPE html><html>", "text/plain") is None
    assert logic.validate("text", "", "text/plain") is None


def test_manifeste():
    texte = json.dumps(
        {"name": "App", "short_name": "A", "start_url": "/", "icons": [{}, {}], "display": "standalone"}
    )
    details = logic.validate("manifest", texte, "application/manifest+json")
    assert details["name"] == "App" and details["icons"] == 2
    assert logic.validate("manifest", json.dumps({"autre": 1}), "application/json") is None
    assert logic.validate("manifest", "pas du JSON", "text/plain") is None


def test_crossdomain_joker_et_clientaccess():
    assert logic.validate("crossdomain", CROSSDOMAIN, "text/xml") == {
        "domains": ["*"],
        "wildcard": True,
        "insecure": True,
    }
    sain = '<cross-domain-policy><allow-access-from domain="*.example.com"/></cross-domain-policy>'
    assert logic.validate("crossdomain", sain, "text/xml")["wildcard"] is False
    silverlight = '<access-policy><cross-domain-access><policy><allow-from><domain uri="*"/></allow-from></policy></cross-domain-access></access-policy>'
    assert logic.validate("clientaccess", silverlight, "text/xml")["wildcard"] is True
    assert logic.validate("crossdomain", "<root/>", "text/xml") is None


def test_lien_du_manifeste_dans_la_page():
    html = '<head><link rel="stylesheet" href="/a.css"><link rel="manifest" href="/static/app.webmanifest?v=2"></head>'
    assert logic.manifest_path(html, "https://example.com/", "example.com") == "/static/app.webmanifest?v=2"
    externe = '<link rel="manifest" href="https://cdn.autre.net/m.json">'
    assert logic.manifest_path(externe, "https://example.com/", "example.com") is None
    assert logic.manifest_path("", "https://example.com/", "example.com") is None


# --- Module -----------------------------------------------------------------------------------


def test_succes_plusieurs_fichiers(http_simule, contexte, outils):
    serveur = _serveur(
        {
            "/humans.txt": (200, "text/plain", "/* TEAM */\nChef: Alice\n"),
            "/ads.txt": (200, "text/plain", ADS),
            "/.well-known/openid-configuration": (200, "application/json", json.dumps(OIDC)),
            "/crossdomain.xml": (200, "text/xml", CROSSDOMAIN),
            "/.well-known/change-password": (302, "text/plain", ""),
        }
    )
    valeur, requetes = _lancer(http_simule, contexte, outils, serveur)
    assert set(valeur["found"]) == {"humans", "ads", "openid_configuration", "crossdomain", "change_password"}
    assert valeur["files"]["ads"]["details"]["records"] == 2
    assert valeur["files"]["change_password"]["details"] == {"redirect": True}
    assert valeur["files"]["app_ads"]["found"] is False and valeur["found_count"] == 5
    assert valeur["permissive"] == ["crossdomain"] and valeur["catch_all"] is False
    assert {r.method for r in requetes} == {"GET"}
    constats = {r.code: r.check(_entree(valeur)) for r in SPEC.findings}
    assert constats["finding.web_files_extra.permissive_policy"] == {"files": "crossdomain"}
    assert constats["finding.web_files_extra.oidc_alg_none"] is True


def test_rien_trouve(http_simule, contexte, outils):
    valeur, _ = _lancer(http_simule, contexte, outils, _serveur())
    assert valeur["found"] == [] and valeur["found_count"] == 0 and valeur["unverified"] == 0
    assert not any(r.check(_entree(valeur)) for r in SPEC.findings)


def test_serveur_fourre_tout_aucun_faux_positif(http_simule, contexte, outils):
    """Une page d'accueil servie en 200 à toute URL ne fait trouver aucun fichier."""
    valeur, _ = _lancer(http_simule, contexte, outils, _serveur(fourre_tout=True))
    assert valeur["found"] == [] and valeur["catch_all"] is True


def test_change_password_exige_un_404_sur_une_url_inconnue(http_simule, contexte, outils):
    """Même un 200 sur change-password ne compte pas si une URL inventée répond aussi 200."""
    valeur, _ = _lancer(http_simule, contexte, outils, _serveur(fourre_tout=True))
    assert valeur["files"]["change_password"]["found"] is False


def test_fichier_texte_identique_a_la_page_introuvable_ecarte(http_simule, contexte, outils):
    serveur = _serveur(fourre_tout=False)

    def repondre(requete):
        if requete.url.path.endswith(".txt") or requete.url.path.endswith("/humans.txt"):
            return httpx.Response(
                200, headers={"Content-Type": "text/plain"}, content="Page introuvable, désolé."
            )
        return serveur(requete)

    valeur, _ = _lancer(http_simule, contexte, outils, repondre)
    assert "humans" not in valeur["found"]


def test_manifeste_declare_par_la_page(http_simule, contexte, outils):
    accueil = (
        '<html><head><link rel="manifest" href="/static/app.webmanifest"></head><body>'
        + "x" * 300
        + "</body></html>"
    )
    serveur = _serveur(
        {
            "/static/app.webmanifest": (
                200,
                "application/manifest+json",
                json.dumps({"name": "App", "start_url": "/"}),
            )
        },
        accueil=accueil,
    )
    valeur, _ = _lancer(http_simule, contexte, outils, serveur)
    assert valeur["files"]["manifest"]["found"] is True
    assert valeur["files"]["manifest"]["path"] == "/static/app.webmanifest"


def test_delai_sur_un_fichier_n_empeche_pas_les_autres(http_simule, contexte, outils):
    base = _serveur({"/humans.txt": (200, "text/plain", "/* TEAM */\nAlice\n")})

    def repondre(requete):
        if requete.url.path == "/ads.txt":
            raise httpx.ReadTimeout("délai", request=requete)
        return base(requete)

    valeur, _ = _lancer(http_simule, contexte, outils, repondre)
    assert valeur["files"]["ads"]["found"] is None and valeur["unverified"] == 1
    assert valeur["files"]["humans"]["found"] is True


def test_cible_injoignable_est_un_echec(http_simule, contexte, outils):
    http_simule({})
    with pytest.raises(ModuleError):
        outils.executer(SPEC, contexte())


def test_donnees_inattendues_ne_levent_pas():
    for donnees in (None, [], {"permissive": 3, "files": "x"}, {"files": {"openid_configuration": 5}}):
        for regle in SPEC.findings:
            regle.check(_entree(donnees))
    assert SPEC.score_rules == () and SPEC.category == "passif"
