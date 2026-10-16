# =============================================================================
# DomainRecon - Tests du module « leakix » (sans réseau : réponses simulées au format
# actuel de l'API, https://leakix.net/api-documentation : {"Services": [...], "Leaks": [...]})
# =============================================================================

import httpx
import pytest

from domainrecon.i18n import render
from domainrecon.scanner.errors import ModuleError
from domainrecon.scanner.impl import leakix as impl
from domainrecon.scanner.modules.leakix import SPEC
from domainrecon.scanner.rules import FindingInput

URL = "https://leakix.net/domain/example.com"
CLE = "cle-leakix-secrete-0123456789"

FUITE = {
    "event_type": "leak",
    "event_source": "ElasticSearchOpenPlugin",
    "ip": "93.184.216.34",
    "host": "db.example.com",
    "port": "9200",
    "protocol": "elasticsearch",
    "summary": "Elasticsearch ouvert, index users contenant admin@example.com et password=hunter2secret",
    "time": "2026-09-30T10:00:00Z",
    "leak": {
        "stage": "open",
        "type": "elasticsearch",
        "severity": "critical",
        "dataset": {"rows": 120000, "files": 0, "size": 52428800, "collections": 3, "infected": False},
    },
    "service": {
        "credentials": {"noauth": True, "username": "svc-es-admin", "password": "mot-de-passe-secret"}
    },
}
SERVICE = {
    "event_type": "service",
    "event_source": "HttpPlugin",
    "ip": "93.184.216.34",
    "host": "www.example.com",
    "port": "8080",
    "protocol": "http",
    "summary": "Panneau ouvert",
    "time": "2026-09-29T08:00:00Z",
    "service": {"credentials": {"noauth": True}, "software": {"name": "Jenkins", "version": "2.4"}},
}
REPONSE = {"Services": [SERVICE], "Leaks": [FUITE]}


def _constats(data):
    entree = FindingInput({}, "leakix", lambda scan, module: data, lambda scan, module: True)
    return {rule.code: rule.check(entree) for rule in SPEC.findings}


def _score(data):
    return SPEC.score_rules[0].evaluate({"leakix": data})


def test_declaration():
    assert SPEC.category == "sensible" and SPEC.family == "leaks"
    assert [(k.name, k.required) for k in SPEC.keys] == [("leakix_key", True)]


def test_succes_format_actuel(http_simule, contexte, outils):
    requetes = http_simule({URL: REPONSE})
    resultat = outils.executer(SPEC, contexte(secrets={"leakix_key": CLE}))
    outils.verifier_sortie(resultat, [CLE])
    assert resultat["query"] == "domain" and resultat["leak_count"] == 1 and resultat["service_count"] == 1
    assert resultat["critical_count"] == 1 and resultat["noauth_count"] == 1
    fuite = resultat["leaks"][0]
    assert fuite["severity"] == "critical" and fuite["port"] == 9200 and fuite["dataset_rows"] == 120000
    # Identifiants et adresses jamais recopiés.
    texte = str(resultat)
    for secret in ("mot-de-passe-secret", "hunter2secret", "admin@example.com", "svc-es-admin"):
        assert secret not in texte
    assert requetes[0].headers["api-key"] == CLE and requetes[0].headers["accept"] == "application/json"


def test_services_et_fuites_nulls(http_simule, contexte, outils):
    http_simule({URL: {"Services": None, "Leaks": None}})
    resultat = outils.executer(SPEC, contexte(secrets={"leakix_key": CLE}))
    assert resultat["leak_count"] == 0 and resultat["service_count"] == 0
    assert _score(resultat).points == 5


def test_ancien_format_liste_plate_encore_lu(http_simule, contexte, outils):
    http_simule({URL: [FUITE, SERVICE]})
    resultat = outils.executer(SPEC, contexte(secrets={"leakix_key": CLE}))
    assert resultat["leak_count"] == 1 and resultat["service_count"] == 1


@pytest.mark.parametrize("statut", [204, 404])
def test_aucun_resultat(http_simule, contexte, outils, statut):
    http_simule({URL: (statut, {}, "")})
    resultat = outils.executer(SPEC, contexte(secrets={"leakix_key": CLE}))
    outils.verifier_sortie(resultat, [CLE])
    assert resultat["leak_count"] == 0 and resultat["leaks"] == []


def test_faux_positif_hote_d_un_autre_domaine_ecarte(http_simule, contexte, outils):
    etranger = {**FUITE, "host": "db.notexample.com"}
    http_simule({URL: {"Leaks": [etranger, FUITE], "Services": [{**SERVICE, "host": ""}]}})
    resultat = outils.executer(SPEC, contexte(secrets={"leakix_key": CLE}))
    assert resultat["leak_count"] == 1 and resultat["ignored"] == 1
    assert resultat["service_count"] == 1  # hôte absent : gardé


def test_cible_ip_utilise_la_route_hote(http_simule, contexte, outils):
    requetes = http_simule({"https://leakix.net/host/93.184.216.34": {"Services": [SERVICE], "Leaks": None}})
    resultat = outils.executer(SPEC, contexte(domain="93.184.216.34", secrets={"leakix_key": CLE}))
    assert resultat["query"] == "host" and resultat["service_count"] == 1
    assert requetes[0].url.path == "/host/93.184.216.34"


@pytest.mark.parametrize(
    ("route", "attendu"),
    [
        ((401, {}, '"Invalid API key"'), "LeakIX refusée"),
        ((429, {}, ""), "Quota"),
        ((500, {}, ""), "500"),
        ((200, {}, "<html>"), "illisible"),
        ((200, {}, '"texte"'), "illisible"),
        (httpx.ReadTimeout("lent"), "délai"),
    ],
)
def test_echecs(http_simule, contexte, outils, route, attendu):
    http_simule({URL: route})
    with pytest.raises(ModuleError) as erreur:
        outils.executer(SPEC, contexte(secrets={"leakix_key": CLE}))
    texte = render(erreur.value.message, "fr")
    assert attendu in texte and CLE not in texte


def test_cle_absente_signalee_par_le_contexte(contexte, outils):
    # Le module exige sa clé : l'orchestrateur ne le lance pas sans elle (clé requise).
    assert SPEC.required_keys == ("leakix_key",)
    with pytest.raises(ModuleError) as erreur:
        outils.executer(SPEC, contexte())
    assert "non renseignée" in render(erreur.value.message, "fr")


def test_constats_et_score(http_simule, contexte, outils):
    http_simule({URL: REPONSE})
    resultat = outils.executer(SPEC, contexte(secrets={"leakix_key": CLE}))
    constats = _constats(resultat)
    assert constats["finding.leakix.leaks"].severity == "critical"
    assert constats["finding.leakix.leaks"].params == {"count": 1, "critical": 1}
    assert constats["finding.leakix.exposed"] == {"count": 1}
    assert _score(resultat).points == 0


def test_score_services_ouverts_seulement():
    donnees = impl.parse_response({"Services": [SERVICE]}, "example.com", by_domain=True)
    assert _score(donnees).points == 2
    assert _constats(donnees)["finding.leakix.leaks"] is None


def test_lecture_defensive():
    for donnees in (None, [], {"leak_count": "x", "noauth_count": None}):
        assert _constats(donnees) == {"finding.leakix.leaks": None, "finding.leakix.exposed": None}
        _score(donnees if isinstance(donnees, dict) else {})


def test_test_de_cle():
    sonde = SPEC.key_tests["leakix"].probes({"leakix_key": CLE})[0]
    assert sonde.url.startswith("https://leakix.net/") and sonde.headers["api-key"] == CLE
    assert 404 in sonde.accepted
