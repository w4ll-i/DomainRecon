# =============================================================================
# DomainRecon - Tests du module « headers_extra » (sans réseau)
# =============================================================================

import pytest

from domainrecon.scanner.errors import ModuleError
from domainrecon.scanner.modules.headers_extra import SPEC
from domainrecon.scanner.rules import FindingInput, Hit

URL = "https://example.com/"


def _entree(data):
    return FindingInput(
        {"headers_extra": data}, "headers_extra", lambda scan, m: scan.get(m), lambda scan, m: True
    )


def _constats(data):
    resultats = {}
    for regle in SPEC.findings:
        resultats[regle.code] = regle.check(_entree(data))
    return resultats


def _lancer(http_simule, contexte, outils, en_tetes, statut=200):
    http_simule({URL: (statut, en_tetes, "<html></html>")})
    valeur = outils.executer(SPEC, contexte())
    outils.verifier_sortie(valeur)
    return valeur


def test_isolation_complete(http_simule, contexte, outils):
    valeur = _lancer(
        http_simule,
        contexte,
        outils,
        {
            "Cross-Origin-Opener-Policy": 'same-origin; report-to="coop"',
            "Cross-Origin-Embedder-Policy": "require-corp",
            "Cross-Origin-Resource-Policy": "same-site",
        },
    )
    assert valeur["measured"] is True and valeur["https"] is True
    assert valeur["cross_origin_isolated"] is True
    assert {k: v["status"] for k, v in valeur["checks"].items()} == {"coop": "ok", "coep": "ok", "corp": "ok"}
    assert valeur["obsolete"] == []
    resultat = SPEC.score_rules[0].evaluate({"headers_extra": valeur})
    assert resultat.points == 5 and resultat.measured


def test_rien_trouve_en_tetes_absents(http_simule, contexte, outils):
    valeur = _lancer(http_simule, contexte, outils, {"Server": "x"})
    assert {v["status"] for v in valeur["checks"].values()} == {"missing"}
    assert valeur["cross_origin_isolated"] is False
    constats = _constats(valeur)
    assert constats["finding.headers_extra.coop_missing"] is True
    assert not constats["finding.headers_extra.obsolete"]
    # Pas d'en-tête obsolète : 1 point sur 5 seulement.
    assert SPEC.score_rules[0].evaluate({"headers_extra": valeur}).points == 1


def test_valeurs_partielles_faibles_et_invalides(http_simule, contexte, outils):
    valeur = _lancer(
        http_simule,
        contexte,
        outils,
        {
            "Cross-Origin-Opener-Policy": "same-origin-allow-popups",
            "Cross-Origin-Embedder-Policy": "unsafe-none",
            "Cross-Origin-Resource-Policy": "n'importe quoi",
        },
    )
    assert valeur["checks"]["coop"]["status"] == "partial"
    assert valeur["checks"]["coep"]["status"] == "weak"
    assert valeur["checks"]["corp"]["status"] == "invalid"
    assert valeur["cross_origin_isolated"] is False


def test_corp_cross_origin_est_partiel(http_simule, contexte, outils):
    valeur = _lancer(http_simule, contexte, outils, {"Cross-Origin-Resource-Policy": "cross-origin"})
    assert valeur["checks"]["corp"]["status"] == "partial"


def test_en_tetes_obsoletes_signales(http_simule, contexte, outils):
    valeur = _lancer(
        http_simule,
        contexte,
        outils,
        {
            "Public-Key-Pins": 'pin-sha256="abc"; max-age=5184000',
            "Expect-CT": "max-age=86400, enforce",
            "X-XSS-Protection": "1; mode=block",
            "Feature-Policy": "camera 'none'",
        },
    )
    assert [o["header"] for o in valeur["obsolete"]] == [
        "expect-ct",
        "feature-policy",
        "public-key-pins",
        "x-xss-protection",
    ]
    constat = _constats(valeur)["finding.headers_extra.obsolete"]
    assert isinstance(constat, Hit) and constat.severity == "medium"
    assert "public-key-pins" in constat.params["headers"]


def test_faux_positif_evite_xss_protection_zero(http_simule, contexte, outils):
    """X-XSS-Protection: 0 est la valeur recommandée : pas d'en-tête « obsolète » à retirer."""
    valeur = _lancer(http_simule, contexte, outils, {"X-XSS-Protection": "0"})
    assert valeur["obsolete"] == []
    assert not _constats(valeur)["finding.headers_extra.obsolete"]


def test_obsolete_sans_hpkp_gravite_faible(http_simule, contexte, outils):
    valeur = _lancer(http_simule, contexte, outils, {"Expect-CT": "max-age=0"})
    assert _constats(valeur)["finding.headers_extra.obsolete"].severity == "low"


def test_coop_non_reproche_en_http(http_simule, contexte, outils):
    """COOP n'a d'effet qu'en contexte sécurisé : un site servi seulement en HTTP n'est pas accusé."""
    # https:// n'est pas simulé (connexion refusée) : le site n'est joignable qu'en HTTP.
    http_simule({"http://example.com/": (200, {}, "ok")})
    valeur = outils.executer(SPEC, contexte())
    assert valeur["https"] is False
    assert not _constats(valeur)["finding.headers_extra.coop_missing"]


def test_cible_injoignable_est_un_echec(http_simule, contexte, outils):
    http_simule({})
    with pytest.raises(ModuleError):
        outils.executer(SPEC, contexte())


def test_donnees_inattendues_ne_levent_pas():
    for donnees in (None, [], {"checks": "x", "obsolete": 3}, {"https": True}):
        for regle in SPEC.findings:
            regle.check(_entree(donnees))


def test_aucune_cle_requise():
    assert SPEC.keys == () and SPEC.category == "passif"
