# =============================================================================
# DomainRecon - Tests du module « observatory » (sans réseau)
# =============================================================================

import httpx
import pytest

from domainrecon.i18n import render
from domainrecon.scanner.errors import ModuleError
from domainrecon.scanner.modules.observatory import SPEC
from domainrecon.scanner.rules import FindingInput, Hit

API = "https://observatory-api.mdn.mozilla.net/api/v2/scan"

# Réponse conforme à la documentation officielle (relevée le 15/10/2026 pour example.com).
REPONSE = {
    "id": 128279039,
    "details_url": "https://developer.mozilla.org/en-US/observatory/analyze?host=example.com",
    "algorithm_version": 6,
    "scanned_at": "2026-10-15T12:19:22.806Z",
    "error": None,
    "grade": "F",
    "score": 10,
    "status_code": 200,
    "tests_failed": 5,
    "tests_passed": 7,
    "tests_quantity": 12,
}


def _entree(data):
    return FindingInput({"observatory": data}, "observatory", lambda scan, m: scan.get(m), lambda s, m: True)


def _lancer(http_simule, contexte, outils, route, **champs):
    requetes = http_simule({API: route})
    valeur = outils.executer(SPEC, contexte(**champs))
    outils.verifier_sortie(valeur)
    return valeur, requetes


def test_succes(http_simule, contexte, outils):
    valeur, requetes = _lancer(http_simule, contexte, outils, REPONSE)
    assert valeur["grade"] == "F" and valeur["score"] == 10 and valeur["tests_quantity"] == 12
    assert valeur["details_url"].startswith("https://developer.mozilla.org/")
    assert requetes[0].method == "POST" and requetes[0].url.params["host"] == "example.com"
    assert SPEC.score_rules[0].evaluate({"observatory": valeur}).points == 0


def test_bonne_note_sans_constat(http_simule, contexte, outils):
    valeur, _ = _lancer(http_simule, contexte, outils, {**REPONSE, "grade": "A+", "score": 130})
    assert SPEC.findings[0].check(_entree(valeur)) is None
    assert SPEC.score_rules[0].evaluate({"observatory": valeur}).points == 5


def test_constat_gravite_selon_la_note(http_simule, contexte, outils):
    constat_f = SPEC.findings[0].check(_entree({"grade": "F"}))
    constat_d = SPEC.findings[0].check(_entree({"grade": "D-"}))
    assert isinstance(constat_f, Hit) and constat_f.severity == "medium" and constat_f.params["grade"] == "F"
    assert constat_d.severity == "low"


def test_site_injoignable_signale_par_le_service(http_simule, contexte, outils):
    http_simule({API: {**REPONSE, "error": "site-down", "grade": None}})
    with pytest.raises(ModuleError) as erreur:
        outils.executer(SPEC, contexte())
    assert "site-down" in render(erreur.value.message, "fr")


def test_nom_d_hote_refuse_422(http_simule, contexte, outils):
    http_simule({API: (422, {}, '{"error":"invalid-hostname","message":"Invalid hostname"}')})
    with pytest.raises(ModuleError) as erreur:
        outils.executer(SPEC, contexte())
    assert "invalid-hostname" in render(erreur.value.message, "fr")


def test_quota_429(http_simule, contexte, outils):
    http_simule({API: (429, {}, "")})
    with pytest.raises(ModuleError) as erreur:
        outils.executer(SPEC, contexte())
    assert "MDN Observatory" in render(erreur.value.message, "fr")


def test_ancienne_api_502(http_simule, contexte, outils):
    http_simule({API: (502, {}, "Bad Gateway")})
    with pytest.raises(ModuleError) as erreur:
        outils.executer(SPEC, contexte())
    assert "502" in render(erreur.value.message, "fr")


def test_reponse_illisible(http_simule, contexte, outils):
    http_simule({API: (200, {}, "<html>pas du JSON</html>")})
    with pytest.raises(ModuleError):
        outils.executer(SPEC, contexte())


def test_note_hors_format(http_simule, contexte, outils):
    http_simule({API: {**REPONSE, "grade": "Z9"}})
    with pytest.raises(ModuleError):
        outils.executer(SPEC, contexte())


def test_echec_reseau_ne_cite_pas_l_url(http_simule, contexte, outils):
    def casse(requete):
        raise httpx.ConnectTimeout(
            "délai sur https://observatory-api.mdn.mozilla.net/?secret", request=requete
        )

    http_simule({API: casse})
    with pytest.raises(ModuleError) as erreur:
        outils.executer(SPEC, contexte())
    assert "secret" not in str(erreur.value) and "ConnectTimeout" in str(erreur.value)


def test_lien_de_rapport_hors_mdn_ecarte(http_simule, contexte, outils):
    valeur, _ = _lancer(http_simule, contexte, outils, {**REPONSE, "details_url": "https://evil.example/x"})
    assert valeur["details_url"] is None


def test_cible_ip_sans_objet(contexte):
    assert SPEC.skip_reason(contexte(domain="93.184.216.34"))


def test_donnees_inattendues_ne_levent_pas():
    for donnees in (None, [], {"grade": 5}, {"grade": ""}):
        SPEC.findings[0].check(_entree(donnees))
    assert SPEC.score_rules[0].evaluate({"observatory": None}).measured is False
