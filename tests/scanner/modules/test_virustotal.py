# =============================================================================
# DomainRecon - Tests du module « virustotal » (sans réseau)
# =============================================================================

import httpx
import pytest

from domainrecon.i18n import render
from domainrecon.scanner.errors import ModuleError
from domainrecon.scanner.modules import virustotal
from domainrecon.scanner.rules import FindingInput

CLE = "vt-cle-secrete-0123456789abcdef"
SPEC = virustotal.SPEC
DOMAINE = "https://www.virustotal.com/api/v3/domains/example.com"
ADRESSE = "https://www.virustotal.com/api/v3/ip_addresses/93.184.216.34"


def _rapport(malicious=0, suspicious=0, engines=(), **extra):
    """Réponse conforme à la documentation VirusTotal v3 (objet « data.attributes »)."""
    results = {name: {"category": "malicious", "result": "phishing"} for name in engines}
    results["Autre"] = {"category": "harmless", "result": "clean"}
    attributes = {
        "last_analysis_stats": {
            "malicious": malicious,
            "suspicious": suspicious,
            "harmless": 60,
            "undetected": 25,
            "timeout": 0,
        },
        "last_analysis_results": results,
        "reputation": -3,
        "categories": {"Forcepoint": "information technology", "Sophos": "information technology"},
        "last_analysis_date": 1760000000,
        "total_votes": {"harmless": 4, "malicious": 1},
        **extra,
    }
    return {"data": {"id": "x", "type": "domain", "attributes": attributes}}


def _lancer(contexte, outils, http_simule, routes, **champs):
    requetes = http_simule(routes)
    context = contexte(secrets={"virustotal_key": CLE}, **champs)
    return outils.executer(SPEC, context), requetes


def test_succes(contexte, outils, http_simule):
    sortie, requetes = _lancer(
        contexte,
        outils,
        http_simule,
        {
            DOMAINE: _rapport(2, 1, ["Alpha", "Beta"]),
            ADRESSE: _rapport(0, 0, country="US", as_owner="EDGECAST"),
        },
    )
    outils.verifier_sortie(sortie, [CLE])
    assert sortie["domain"]["malicious"] == 2 and sortie["domain"]["suspicious"] == 1
    assert sortie["domain"]["flagged_engines"] == ["Alpha", "Beta"]
    assert sortie["domain"]["categories"] == ["information technology"]
    assert sortie["ip"]["country"] == "US" and sortie["ip"]["as_owner"] == "EDGECAST"
    # La clé voyage en en-tête, jamais dans l'URL.
    assert all(r.headers["x-apikey"] == CLE and CLE not in str(r.url) for r in requetes)


def test_rien_trouve_objet_inconnu(contexte, outils, http_simule):
    sortie, _ = _lancer(contexte, outils, http_simule, {DOMAINE: (404, {}, "{}"), ADRESSE: (404, {}, "{}")})
    outils.verifier_sortie(sortie, [CLE])
    assert sortie["domain"] == {"found": False} and sortie["ip"] == {"found": False}
    assert SPEC.score_rules[0].evaluate({"virustotal": sortie}).measured is False


@pytest.mark.parametrize(
    ("statut", "code"),
    [
        (401, "network.http_status"),
        (403, "network.http_status"),
        (429, "network.quota"),
        (500, "network.http_status"),
    ],
)
def test_echecs_http(contexte, outils, http_simule, statut, code):
    with pytest.raises(ModuleError) as erreur:
        _lancer(contexte, outils, http_simule, {DOMAINE: (statut, {}, "{}")})
    assert erreur.value.message["$t"] == code
    assert CLE not in str(erreur.value)


def test_reponse_illisible(contexte, outils, http_simule):
    with pytest.raises(ModuleError) as erreur:
        _lancer(contexte, outils, http_simule, {DOMAINE: (200, {}, "pas du json")})
    assert erreur.value.message["$t"] == "virustotal.unreadable"
    with pytest.raises(ModuleError):
        _lancer(contexte, outils, http_simule, {DOMAINE: {"data": {}}})


def test_delai_depasse_et_connexion(contexte, outils, http_simule):
    with pytest.raises(ModuleError) as erreur:
        _lancer(contexte, outils, http_simule, {DOMAINE: httpx.ReadTimeout("délai https://x/?key=" + CLE)})
    texte = str(render(erreur.value.message, "fr"))
    assert "délai dépassé" in texte and CLE not in texte
    with pytest.raises(ModuleError):
        _lancer(contexte, outils, http_simule, {DOMAINE: httpx.ConnectError("refusé")})


def test_cible_ip_sans_requete_domaine(contexte, outils, http_simule):
    sortie, requetes = _lancer(
        contexte, outils, http_simule, {ADRESSE: _rapport(0, 0)}, domain="93.184.216.34"
    )
    assert sortie["domain"] is None and sortie["ip"]["found"] is True
    assert [r.url.path for r in requetes] == ["/api/v3/ip_addresses/93.184.216.34"]


def test_cle_declaree_et_requise():
    assert SPEC.required_keys == ("virustotal_key",) and SPEC.category == "cle_api"


def _constats(donnees):
    scan = {"modules": {"virustotal": {"data": donnees}}}
    entree = FindingInput(scan, "virustotal", lambda s, m: s["modules"][m]["data"], lambda s, m: True)
    return {rule.code: rule.check(entree) for rule in SPEC.findings}


def test_constats_et_score():
    propre = {"domain": {"found": True, "malicious": 0, "suspicious": 0}, "ip": None}
    assert not any(_constats(propre).values())
    assert SPEC.score_rules[0].evaluate({"virustotal": propre}).points == 5

    faible = {"domain": {"found": True, "malicious": 1, "suspicious": 0}, "ip": None}
    assert _constats(faible)["finding.virustotal.domain_flagged"].severity == "low"
    assert SPEC.score_rules[0].evaluate({"virustotal": faible}).points == 3

    fort = {"domain": {"found": True, "malicious": 7, "flagged_engines": ["A"]}, "ip": None}
    assert _constats(fort)["finding.virustotal.domain_flagged"].severity == "high"
    assert SPEC.score_rules[0].evaluate({"virustotal": fort}).points == 0


def test_ip_mutualisee_ne_double_pas_le_domaine():
    seule = {"domain": {"found": True, "malicious": 0}, "ip": {"found": True, "malicious": 4}}
    assert _constats(seule)["finding.virustotal.ip_flagged"].severity == "low"
    deux = {"domain": {"found": True, "malicious": 2}, "ip": {"found": True, "malicious": 4}}
    assert _constats(deux)["finding.virustotal.ip_flagged"] is None
    assert _constats("n'importe quoi") == {
        "finding.virustotal.domain_flagged": None,
        "finding.virustotal.ip_flagged": None,
    }
