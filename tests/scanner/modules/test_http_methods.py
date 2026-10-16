# =============================================================================
# DomainRecon - Tests du module « http_methods » (sans réseau)
# =============================================================================

import httpx
import pytest

from domainrecon.i18n import render
from domainrecon.scanner.errors import ModuleError
from domainrecon.scanner.modules.http_methods import SPEC, parse_allow
from domainrecon.scanner.rules import FindingInput, Hit

URL = "https://example.com/"


def _entree(data):
    return FindingInput(
        {"http_methods": data}, "http_methods", lambda scan, m: scan.get(m), lambda s, m: True
    )


def _constat(code, data):
    return next(r for r in SPEC.findings if r.code == code).check(_entree(data))


def _serveur(allow=None, trace="refuse", options=200):
    """Route simulée de la racine : OPTIONS, TRACE et TRACK selon le scénario."""

    def repondre(requete: httpx.Request) -> httpx.Response:
        if requete.method == "OPTIONS":
            return httpx.Response(options, headers={"Allow": allow} if allow else {})
        if requete.method in ("TRACE", "TRACK") and trace == "echo":
            corps = f"{requete.method} / HTTP/1.1\r\nhost: example.com\r\nx-domainrecon-trace: {requete.headers['x-domainrecon-trace']}\r\n"
            return httpx.Response(200, headers={"Content-Type": "message/http"}, content=corps)
        if requete.method in ("TRACE", "TRACK") and trace == "fourre-tout":
            return httpx.Response(200, headers={"Content-Type": "text/html"}, content="<html>accueil</html>")
        return httpx.Response(405, content="refusé")

    return repondre


def _lancer(http_simule, contexte, outils, serveur):
    requetes = http_simule({URL: serveur})
    valeur = outils.executer(SPEC, contexte())
    outils.verifier_sortie(valeur)
    return valeur, requetes


def test_parse_allow():
    assert parse_allow("get, HEAD,options , GET, 12, x-y") == ["GET", "HEAD", "OPTIONS"]
    assert parse_allow(None) == []


def test_serveur_sain(http_simule, contexte, outils):
    valeur, requetes = _lancer(http_simule, contexte, outils, _serveur("GET, HEAD, OPTIONS"))
    assert valeur["trace_enabled"] is False and valeur["advertised_dangerous"] == []
    assert valeur["allow_header_present"] is True and valeur["trace"]["status_code"] == 405
    assert not any(_constat(r.code, valeur) for r in SPEC.findings)
    assert SPEC.score_rules[0].evaluate({"http_methods": valeur}).points == 3
    # Jamais de méthode d'écriture envoyée.
    assert {r.method for r in requetes} == {"OPTIONS", "TRACE", "TRACK"}


def test_trace_reellement_active(http_simule, contexte, outils):
    valeur, _ = _lancer(http_simule, contexte, outils, _serveur("GET, TRACE", trace="echo"))
    assert valeur["trace_enabled"] is True and valeur["trace"]["enabled"] is True
    constat = _constat("finding.http_methods.trace_enabled", valeur)
    assert isinstance(constat, Hit) and constat.params["methods"] == "TRACE, TRACK"
    assert SPEC.score_rules[0].evaluate({"http_methods": valeur}).points == 0


def test_serveur_fourre_tout_200_n_est_pas_trace(http_simule, contexte, outils):
    """Faux positif évité : un 200 HTML qui ne renvoie pas le marqueur n'est pas un TRACE actif."""
    valeur, _ = _lancer(http_simule, contexte, outils, _serveur("GET", trace="fourre-tout"))
    assert valeur["trace_enabled"] is False and valeur["trace"]["status_code"] == 200


def test_allow_absent_n_est_pas_un_feu_vert(http_simule, contexte, outils):
    """Allow absent : pas de conclusion « aucune méthode dangereuse »."""
    valeur, _ = _lancer(http_simule, contexte, outils, _serveur(None))
    assert valeur["allow_header_present"] is False
    resultat = SPEC.score_rules[0].evaluate({"http_methods": valeur})
    assert resultat.points == 3 and "Allow absent" in render(resultat.detail, "fr")


def test_methodes_d_ecriture_annoncees(http_simule, contexte, outils):
    valeur, _ = _lancer(http_simule, contexte, outils, _serveur("GET, PUT, DELETE, PROPFIND"))
    assert valeur["advertised_dangerous"] == ["PUT", "DELETE", "PROPFIND"] and valeur["webdav"] is True
    assert _constat("finding.http_methods.dangerous_advertised", valeur) == {
        "methods": "PUT, DELETE, PROPFIND"
    }
    assert SPEC.score_rules[0].evaluate({"http_methods": valeur}).points == 2


def test_repli_http_si_https_injoignable(http_simule, contexte, outils):
    requetes = http_simule({"http://example.com/": _serveur("GET")})
    valeur = outils.executer(SPEC, contexte())
    assert valeur["url"] == "http://example.com/" and len(requetes) >= 2


def test_delai_sur_trace_ne_fait_pas_echouer_le_module(http_simule, contexte, outils):
    def serveur(requete):
        if requete.method == "OPTIONS":
            return httpx.Response(200, headers={"Allow": "GET"})
        raise httpx.ReadTimeout("délai", request=requete)

    valeur, _ = _lancer(http_simule, contexte, outils, serveur)
    assert valeur["trace"]["tested"] is False and valeur["trace_enabled"] is False


def test_cible_injoignable_est_un_echec(http_simule, contexte, outils):
    http_simule({})
    with pytest.raises(ModuleError):
        outils.executer(SPEC, contexte())


def test_categorie_active_et_sans_cle():
    assert SPEC.category == "actif" and SPEC.requires_authorization and SPEC.keys == ()


def test_donnees_inattendues_ne_levent_pas():
    for donnees in (
        None,
        [],
        {"advertised_dangerous": 5, "trace": "x"},
        {"trace_enabled": True, "trace": []},
    ):
        for regle in SPEC.findings:
            regle.check(_entree(donnees))
    assert SPEC.score_rules[0].evaluate({"http_methods": None}).points == 2


def test_trace_non_testable_n_est_pas_presente_comme_refusee(http_simule, contexte, outils):
    def serveur(requete):
        if requete.method == "OPTIONS":
            return httpx.Response(200, headers={"Allow": "GET"})
        raise httpx.ReadTimeout("délai", request=requete)

    valeur, _ = _lancer(http_simule, contexte, outils, serveur)
    resultat = SPEC.score_rules[0].evaluate({"http_methods": valeur})
    assert resultat.points == 2 and "non testables" in render(resultat.detail, "fr")
