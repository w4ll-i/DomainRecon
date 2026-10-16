# =============================================================================
# DomainRecon - Tests du module « abuseipdb » (sans réseau)
# =============================================================================

import httpx
import pytest

from domainrecon.i18n import render
from domainrecon.scanner.errors import ModuleError
from domainrecon.scanner.modules import abuseipdb
from domainrecon.scanner.rules import FindingInput

CLE = "abuse-cle-secrete-0123456789abcdef"
SPEC = abuseipdb.SPEC
URL = "https://api.abuseipdb.com/api/v2/check"


def _reponse(score=0, **extra):
    """Réponse conforme à la documentation AbuseIPDB v2 (check)."""
    data = {
        "ipAddress": "93.184.216.34",
        "isPublic": True,
        "ipVersion": 4,
        "isWhitelisted": False,
        "abuseConfidenceScore": score,
        "countryCode": "US",
        "usageType": "Content Delivery Network",
        "isp": "Edgecast",
        "domain": "edgecast.com",
        "hostnames": [],
        "isTor": False,
        "totalReports": 12,
        "numDistinctUsers": 5,
        "lastReportedAt": "2026-10-10T08:00:00+00:00",
        **extra,
    }
    return {"data": data}


def _lancer(contexte, outils, http_simule, route, **champs):
    requetes = http_simule({URL: route})
    context = contexte(secrets={"abuseipdb_key": CLE}, **champs)
    return outils.executer(SPEC, context), requetes


def test_succes(contexte, outils, http_simule):
    sortie, requetes = _lancer(contexte, outils, http_simule, _reponse(80))
    outils.verifier_sortie(sortie, [CLE])
    assert sortie["abuse_confidence_score"] == 80 and sortie["risk_level"] == "high"
    assert sortie["total_reports"] == 12 and sortie["isp"] == "Edgecast"
    assert requetes[0].headers["Key"] == CLE and CLE not in str(requetes[0].url)
    assert requetes[0].url.params["ipAddress"] == "93.184.216.34"


def test_rien_trouve(contexte, outils, http_simule):
    sortie, _ = _lancer(contexte, outils, http_simule, _reponse(0, totalReports=0, numDistinctUsers=0))
    assert sortie["risk_level"] == "low" and sortie["total_reports"] == 0
    assert SPEC.score_rules[0].evaluate({"abuseipdb": sortie}).points == 5


@pytest.mark.parametrize(
    ("statut", "code"),
    [(401, "network.http_status"), (422, "network.http_status"), (429, "network.quota")],
)
def test_echecs_http(contexte, outils, http_simule, statut, code):
    with pytest.raises(ModuleError) as erreur:
        _lancer(contexte, outils, http_simule, (statut, {}, "{}"))
    assert erreur.value.message["$t"] == code and CLE not in str(erreur.value)


def test_reponse_illisible(contexte, outils, http_simule):
    with pytest.raises(ModuleError):
        _lancer(contexte, outils, http_simule, (200, {}, "<html>"))
    with pytest.raises(ModuleError):
        _lancer(contexte, outils, http_simule, {"data": {}})


def test_delai_depasse(contexte, outils, http_simule):
    with pytest.raises(ModuleError) as erreur:
        _lancer(contexte, outils, http_simule, httpx.ReadTimeout("trop long " + CLE))
    texte = str(render(erreur.value.message, "fr"))
    assert "délai dépassé" in texte and CLE not in texte


def test_sans_adresse_sans_objet(contexte):
    assert SPEC.skip_reason(contexte(addresses=[])) is not None
    assert SPEC.skip_reason(contexte()) is None


def test_cle_absente_ou_refusee(contexte, outils, http_simule):
    # Sans clé, le service répond 401 : échec propre, jamais de résultat vide trompeur.
    http_simule({URL: (401, {}, '{"errors":[{"detail":"Authentication failed"}]}')})
    with pytest.raises(ModuleError):
        outils.executer(SPEC, contexte(secrets={}))
    assert SPEC.required_keys == ("abuseipdb_key",)


def _entree(donnees):
    scan = {"modules": {"abuseipdb": {"data": donnees}}}
    return FindingInput(scan, "abuseipdb", lambda s, m: s["modules"][m]["data"], lambda s, m: True)


def test_constats_et_score():
    regle = SPEC.findings[0]
    base = {"abuse_confidence_score": 60, "total_reports": 9, "num_distinct_users": 4}
    assert regle.check(_entree(base)).severity == "medium"
    assert regle.check(_entree({**base, "abuse_confidence_score": 90})).severity == "high"
    assert regle.check(_entree({**base, "abuse_confidence_score": 30})).severity == "low"
    assert regle.check(_entree({**base, "abuse_confidence_score": 10})) is None
    assert regle.check(_entree("illisible")) is None
    assert SPEC.score_rules[0].evaluate({"abuseipdb": base}).points == 1


def test_liste_blanche_evite_le_faux_positif():
    donnees = {"abuse_confidence_score": 95, "is_whitelisted": True, "total_reports": 40}
    assert SPEC.findings[0].check(_entree(donnees)) is None
    assert SPEC.score_rules[0].evaluate({"abuseipdb": donnees}).points == 5
