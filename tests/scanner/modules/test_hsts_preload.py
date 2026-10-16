# =============================================================================
# DomainRecon - Tests du module « hsts_preload » (sans réseau)
# =============================================================================

import httpx
import pytest

from domainrecon.i18n import render
from domainrecon.scanner.errors import ModuleError
from domainrecon.scanner.impl import hsts_preload as logic
from domainrecon.scanner.modules.hsts_preload import SPEC
from domainrecon.scanner.rules import FindingInput

STATUS = "https://hstspreload.org/api/v2/status"
PRELOADABLE = "https://hstspreload.org/api/v2/preloadable"
FORT = "max-age=63072000; includeSubDomains; preload"


def _entree(data):
    return FindingInput(
        {"hsts_preload": data}, "hsts_preload", lambda scan, m: scan.get(m), lambda s, m: True
    )


def _constat(code, data):
    regle = next(r for r in SPEC.findings if r.code == code)
    return regle.check(_entree(data))


def _routes(hsts=None, statut="unknown", **plus):
    en_tetes = {"Strict-Transport-Security": hsts} if hsts else {}
    routes = {
        "https://example.com/": (200, en_tetes, ""),
        STATUS: {"name": "example.com", "status": statut, "bulk": False, "preloadedDomain": ""},
        PRELOADABLE: {
            "errors": [{"code": "response.no_header", "summary": "x", "message": "y"}],
            "warnings": [],
        },
    }
    routes.update(plus)
    return routes


def _lancer(http_simule, contexte, outils, routes, **champs):
    requetes = http_simule(routes)
    valeur = outils.executer(SPEC, contexte(**champs))
    outils.verifier_sortie(valeur)
    return valeur, requetes


# --- Analyse de l'en-tête ----------------------------------------------------


@pytest.mark.parametrize(
    ("valeur", "note", "eligible"),
    [
        (FORT, "A", True),
        ("max-age=31536000; includeSubDomains", "B", False),
        ("max-age=15552000", "C", False),
        ("max-age=3600", "D", False),
        ("max-age=0", "F", False),
        ("includeSubDomains", "F", False),
        ("", "F", False),
        ('max-age="31536000"; includesubdomains; PRELOAD', "A", True),
        ("max-age=31536000; preload", "B", False),
    ],
)
def test_note_et_eligibilite(valeur, note, eligible):
    hsts = logic.parse_hsts(valeur)
    assert hsts["grade"] == note and hsts["preload_eligible"] is eligible


def test_seul_le_premier_en_tete_compte():
    assert logic.parse_hsts("max-age=0, max-age=63072000; includeSubDomains; preload")["grade"] == "F"


# --- Module -------------------------------------------------------------------


def test_succes_domaine_precharge(http_simule, contexte, outils):
    valeur, requetes = _lancer(http_simule, contexte, outils, _routes(FORT, "preloaded"))
    assert valeur["grade"] == "A" and valeur["preloaded"] is True and valeur["https"] is True
    assert valeur["hsts"]["max_age_days"] == 730
    assert valeur["preload"]["status"] == "preloaded"
    # Déjà inscrit : aucun besoin de chercher les obstacles à la soumission.
    assert not any(str(r.url).startswith(PRELOADABLE) for r in requetes)
    assert SPEC.score_rules[0].evaluate({"hsts_preload": valeur}).points == 5


def test_eligible_mais_non_inscrit(http_simule, contexte, outils):
    valeur, _ = _lancer(http_simule, contexte, outils, _routes(FORT, "unknown"))
    assert valeur["preloaded"] is False and valeur["hsts"]["preload_eligible"] is True
    assert valeur["preload"]["blockers"] == {"errors": ["response.no_header"], "warnings": []}
    assert _constat("finding.hsts_preload.not_preloaded", valeur) is True
    assert not _constat("finding.hsts_preload.preload_unready", valeur)


def test_hsts_absent(http_simule, contexte, outils):
    valeur, _ = _lancer(http_simule, contexte, outils, _routes(None, "unknown"))
    assert valeur["hsts"]["present"] is False and valeur["grade"] == "F"
    assert SPEC.score_rules[0].evaluate({"hsts_preload": valeur}).points == 0
    assert not any(_constat(r.code, valeur) for r in SPEC.findings)


def test_preload_sans_conditions_de_la_liste(http_simule, contexte, outils):
    valeur, _ = _lancer(http_simule, contexte, outils, _routes("max-age=300; preload", "unknown"))
    assert _constat("finding.hsts_preload.preload_unready", valeur) is True
    assert _constat("finding.hsts_preload.no_subdomains", valeur) is True


def test_sous_domaine_interroge_le_domaine_enregistrable(http_simule, contexte, outils):
    routes = _routes(None, "preloaded")
    routes["https://www.example.com/"] = (200, {"Strict-Transport-Security": "max-age=31536000"}, "")
    requetes = http_simule(routes)
    valeur = outils.executer(SPEC, contexte(domain="www.example.com", apex="example.com", site="example.com"))
    assert valeur["preload_domain"] == "example.com" and valeur["domain"] == "www.example.com"
    assert valeur["hsts"]["grade"] == "B" and valeur["apex_hsts"]["present"] is False
    api = [r for r in requetes if r.url.path == "/api/v2/status"]
    assert api and api[0].url.params["domain"] == "example.com"
    # Le domaine enregistrable est précâblé : le constat « non inscrit » ne vise que lui.
    assert not _constat("finding.hsts_preload.not_preloaded", valeur)


def test_site_sans_https_mesure_mais_sans_objet_pour_le_score(http_simule, contexte, outils):
    routes = _routes(None, "unknown")
    del routes["https://example.com/"]
    valeur, _ = _lancer(http_simule, contexte, outils, routes)
    assert valeur["https"] is False and valeur["https_error"]
    resultat = SPEC.score_rules[0].evaluate({"hsts_preload": valeur})
    assert resultat.applicable is False


def test_service_en_quota_degrade_sans_echec(http_simule, contexte, outils):
    routes = _routes(FORT)
    routes[STATUS] = (429, {}, "")
    valeur, _ = _lancer(http_simule, contexte, outils, routes)
    assert valeur["preload"]["measured"] is False
    assert render(valeur["preload"]["error"], "fr")
    assert valeur["preloaded"] is False


def test_service_et_cible_injoignables_sont_un_echec(http_simule, contexte, outils):
    http_simule({})
    with pytest.raises(ModuleError):
        outils.executer(SPEC, contexte())


def test_reponse_illisible_du_service(http_simule, contexte, outils):
    routes = _routes(FORT)
    routes[STATUS] = (200, {}, "<html>pas du JSON</html>")
    valeur, _ = _lancer(http_simule, contexte, outils, routes)
    assert valeur["preload"]["measured"] is False


def test_erreur_reseau_du_service_ne_cite_pas_l_url(http_simule, contexte, outils):
    routes = _routes(FORT)

    def casse(requete):
        raise httpx.ReadTimeout("délai", request=requete)

    routes[STATUS] = casse
    valeur, _ = _lancer(http_simule, contexte, outils, routes)
    assert valeur["preload"]["measured"] is False
    assert "hstspreload.org/api" not in str(render(valeur["preload"]["error"], "fr"))


def test_cible_ip_sans_objet(contexte):
    assert SPEC.skip_reason(contexte(domain="93.184.216.34"))


def test_donnees_inattendues_ne_levent_pas():
    for donnees in (None, [], {"https": True, "hsts": "x", "preload": 3}):
        for regle in SPEC.findings:
            regle.check(_entree(donnees))
    assert SPEC.score_rules[0].evaluate({"hsts_preload": []}).applicable is False
