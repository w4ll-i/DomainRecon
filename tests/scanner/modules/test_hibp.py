# =============================================================================
# DomainRecon - Tests du module « hibp » (sans réseau : réponses simulées conformes à
# https://haveibeenpwned.com/API/v3)
# =============================================================================

import httpx
import pytest

from domainrecon.i18n import render
from domainrecon.scanner.errors import ModuleError
from domainrecon.scanner.modules.hibp import SPEC
from domainrecon.scanner.rules import FindingInput

CATALOGUE = "https://haveibeenpwned.com/api/v3/breaches"
COMPTES = "https://haveibeenpwned.com/api/v3/breacheddomain/adobe.com"
CLE = "cle-hibp-secrete-0123456789abcdef"

ADOBE = {
    "Name": "Adobe",
    "Title": "Adobe",
    "Domain": "adobe.com",
    "BreachDate": "2013-10-04",
    "AddedDate": "2013-12-04T00:00:00Z",
    "PwnCount": 152445165,
    "Description": 'En 2013, <em>153 millions</em> de comptes ont fuité, <a href="http://x">détails</a>.',
    "DataClasses": ["Email addresses", "Password hints", "Passwords", "Usernames"],
    "IsVerified": True,
    "IsFabricated": False,
    "IsSensitive": False,
    "IsRetired": False,
    "IsSpamList": False,
    "IsMalware": False,
}


def _constats(data):
    """Résultats des règles de constats du module sur `data`."""
    entree = FindingInput({}, "hibp", lambda scan, module: data, lambda scan, module: True)
    return {rule.code: rule.check(entree) for rule in SPEC.findings}


def _score(data):
    return SPEC.score_rules[0].evaluate({"hibp": data})


def test_declaration():
    assert SPEC.category == "sensible" and SPEC.family == "leaks"
    assert [(k.name, k.required) for k in SPEC.keys] == [("hibp_key", False)]
    assert "haveibeenpwned" in SPEC.key_tests


def test_succes_catalogue_gratuit(http_simule, contexte, outils):
    requetes = http_simule({CATALOGUE: [ADOBE]})
    contexte_ = contexte(domain="www.adobe.com", apex="adobe.com")
    resultat = outils.executer(SPEC, contexte_)
    outils.verifier_sortie(resultat)
    assert resultat["measured"] is True and resultat["source"] == "catalog"
    assert resultat["breach_count"] == 1 and resultat["total_pwned"] == 152445165
    assert resultat["passwords_exposed"] is True and resultat["domain_search"] == "not_requested"
    assert resultat["breaches"][0]["name"] == "Adobe"
    assert "<" not in resultat["breaches"][0]["description"]
    # « www. » et le domaine enregistrable n'ouvrent qu'une seule requête ; aucune clé envoyée.
    assert len(requetes) == 1 and requetes[0].url.params["Domain"] == "adobe.com"
    assert "hibp-api-key" not in requetes[0].headers


def test_rien_trouve(http_simule, contexte, outils):
    http_simule({CATALOGUE: []})
    resultat = outils.executer(SPEC, contexte())
    outils.verifier_sortie(resultat)
    assert resultat["breach_count"] == 0 and resultat["breaches"] == []
    assert _constats(resultat) == {"finding.hibp.breaches": None, "finding.hibp.accounts": None}
    assert _score(resultat).points == 5


def test_faux_positif_autre_domaine_ecarte(http_simule, contexte, outils):
    # Un service qui ignorerait ?Domain= rendrait tout le catalogue : seul le domaine exact compte.
    autre = {**ADOBE, "Name": "NotAdobe", "Domain": "notadobe.com"}
    sous_domaine = {**ADOBE, "Name": "Forum", "Domain": "forum.adobe.com"}
    http_simule({CATALOGUE: [autre, sous_domaine, ADOBE]})
    resultat = outils.executer(SPEC, contexte(domain="adobe.com"))
    assert [b["name"] for b in resultat["breaches"]] == ["Adobe"]


def test_cle_comptes_masques(http_simule, contexte, outils):
    requetes = http_simule({CATALOGUE: [ADOBE], COMPTES: {"alice": ["Adobe"], "bob": ["Adobe", "Autre"]}})
    resultat = outils.executer(SPEC, contexte(domain="adobe.com", secrets={"hibp_key": CLE}))
    outils.verifier_sortie(resultat, [CLE])
    assert resultat["source"] == "catalog+key" and resultat["domain_search"] == "ok"
    assert resultat["accounts"] == 2 and resultat["accounts_breaches"] == ["Adobe", "Autre"]
    assert resultat["accounts_sample"] == ["a***@adobe.com", "b***@adobe.com"]
    assert "alice" not in str(resultat)
    assert requetes[1].headers["hibp-api-key"] == CLE
    assert _constats(resultat)["finding.hibp.accounts"] == {"count": 2, "breaches": 2}
    assert _score(resultat).points == 0


@pytest.mark.parametrize(
    ("reponse", "etat"),
    [
        ((401, {}, ""), "rejected"),
        ((403, {}, ""), "not_verified"),
        ((429, {}, ""), "quota"),
        ((500, {}, ""), "error"),
    ],
)
def test_cle_refusee_ou_domaine_non_verifie_ne_fait_pas_echouer(http_simule, contexte, outils, reponse, etat):
    http_simule({CATALOGUE: [ADOBE], COMPTES: reponse})
    resultat = outils.executer(SPEC, contexte(domain="adobe.com", secrets={"hibp_key": CLE}))
    outils.verifier_sortie(resultat, [CLE])
    assert resultat["domain_search"] == etat and resultat["breach_count"] == 1
    assert resultat["accounts"] is None


def test_cle_aucun_compte(http_simule, contexte, outils):
    http_simule({CATALOGUE: [], COMPTES: (404, {}, "")})
    resultat = outils.executer(SPEC, contexte(domain="adobe.com", secrets={"hibp_key": CLE}))
    assert resultat["domain_search"] == "ok" and resultat["accounts"] == 0


@pytest.mark.parametrize(
    ("route", "attendu"),
    [
        ((429, {"Retry-After": "2"}, ""), "Quota"),
        ((503, {}, ""), "503"),
        ((200, {}, "<html>pas du JSON</html>"), "illisible"),
        ((200, {}, '{"pas": "une liste"}'), "illisible"),
        (httpx.ReadTimeout("lent"), "délai"),
        (httpx.ConnectError("refusé"), "ConnectError"),
    ],
)
def test_echecs(http_simule, contexte, outils, route, attendu):
    http_simule({CATALOGUE: route})
    with pytest.raises(ModuleError) as erreur:
        outils.executer(SPEC, contexte(secrets={"hibp_key": CLE}))
    texte = render(erreur.value.message, "fr")
    assert attendu in texte and CLE not in texte


def test_catalogue_garde_24_h(http_simule, contexte, outils):
    requetes = http_simule({CATALOGUE: [ADOBE]})
    outils.executer(SPEC, contexte(domain="adobe.com"))
    outils.executer(SPEC, contexte(domain="adobe.com"))
    assert len(requetes) == 1


def test_adresse_ip_sans_objet(contexte):
    raison = SPEC.skip_reason(contexte(domain="93.184.216.34"))
    assert raison is not None
    assert SPEC.skip_reason(contexte()) is None


def test_constats_et_score_brèche_avec_mots_de_passe(http_simule, contexte, outils):
    http_simule({CATALOGUE: [ADOBE]})
    resultat = outils.executer(SPEC, contexte(domain="adobe.com"))
    constat = _constats(resultat)["finding.hibp.breaches"]
    assert constat.severity == "high" and constat.params == {"count": 1, "names": "Adobe"}
    assert _score(resultat).points == 0


def test_score_breche_sans_mot_de_passe():
    donnees = {
        "measured": True,
        "breaches": [{"name": "Liste"}],
        "passwords_exposed": False,
        "accounts": None,
    }
    assert _score(donnees).points == 2
    assert _constats(donnees)["finding.hibp.breaches"].severity == "medium"


def test_lecture_defensive_des_anciennes_donnees():
    for donnees in (None, [], "x", {"breaches": "pas une liste", "accounts": "?"}):
        assert _constats(donnees)["finding.hibp.accounts"] is None
        _score(donnees if isinstance(donnees, dict) else {})


def test_test_de_cle_interroge_le_statut_d_abonnement():
    sondes = SPEC.key_tests["haveibeenpwned"].probes({"hibp_key": CLE})
    assert sondes[0].url == "https://haveibeenpwned.com/api/v3/subscription/status"
    assert sondes[0].headers == {"hibp-api-key": CLE}
