# =============================================================================
# DomainRecon - Tests du module « urlscan » (sans réseau)
# =============================================================================

import httpx
import pytest

from domainrecon.scanner import cache
from domainrecon.scanner.errors import ModuleError
from domainrecon.scanner.modules import urlscan
from domainrecon.scanner.rules import FindingInput

CLE = "urlscan-cle-secrete-0123456789abcdef"
SPEC = urlscan.SPEC
RECHERCHE = "https://urlscan.io/api/v1/search/"
U1 = "01a13f6c-b63f-73fd-8ee3-7ed9f02fe8e9"
U2 = "01a13f80-0390-716c-9949-e2f9ac097921"
RESULTAT = "https://urlscan.io/api/v1/result/{}/"


def _scan(uuid, ip="93.184.216.34", country="US", when="2026-10-10T10:00:00.000Z"):
    """Entrée de recherche conforme à la documentation (verdicts toujours null dans la recherche)."""
    return {
        "task": {"uuid": uuid, "time": when, "domain": "example.com", "apexDomain": "example.com"},
        "page": {
            "ip": ip,
            "country": country,
            "server": "ECS",
            "title": "Example Domain",
            "domain": "example.com",
        },
        "result": f"https://urlscan.io/api/v1/result/{uuid}/",
        "screenshot": f"https://urlscan.io/screenshots/{uuid}.png",
        "verdicts": None,
    }


def _detail(malicious=False, categories=()):
    return {
        "verdicts": {
            "overall": {
                "hasVerdicts": 1 if malicious else 0,
                "score": 100 if malicious else 0,
                "malicious": malicious,
                "categories": list(categories),
                "brands": [],
            }
        }
    }


def _lancer(contexte, outils, http_simule, routes, secrets=None, **champs):
    requetes = http_simule(routes)
    context = contexte(secrets=secrets if secrets is not None else {"urlscan_key": CLE}, **champs)
    return outils.executer(SPEC, context), requetes


def test_requete_de_recherche():
    assert urlscan.build_query("example.com", "example.com", False, False) == (
        "task.apexDomain:example.com AND page.apexDomain:example.com"
    )
    assert urlscan.build_query("blog.example.com", "example.com", False, False) == (
        "task.domain:blog.example.com AND page.domain:blog.example.com"
    )
    assert urlscan.build_query("user.github.io", "github.io", False, True).startswith(
        "task.domain:user.github.io"
    )
    assert urlscan.build_query("93.184.216.34", "93.184.216.34", True, False) == 'page.ip:"93.184.216.34"'


def test_succes_avec_verdicts(contexte, outils, http_simule):
    routes = {
        RECHERCHE: {
            "total": 1341,
            "has_more": True,
            "results": [_scan(U1), _scan(U2, "93.184.215.14", "FR")],
        },
        RESULTAT.format(U1): _detail(True, ["phishing"]),
        RESULTAT.format(U2): _detail(False),
    }
    sortie, requetes = _lancer(contexte, outils, http_simule, routes)
    outils.verifier_sortie(sortie, [CLE])
    assert sortie["total_scans"] == 1341 and sortie["analyzed_scans"] == 2
    assert sortie["ips_seen"] == ["93.184.215.14", "93.184.216.34"]
    assert sortie["countries_seen"] == ["FR", "US"]
    assert sortie["malicious_scans"] == 1 and sortie["verdicts"][0]["categories"] == ["phishing"]
    assert (
        sortie["report_url"] == f"https://urlscan.io/result/{U1}/"
        and sortie["page_title"] == "Example Domain"
    )
    assert all(r.headers["API-Key"] == CLE and CLE not in str(r.url) for r in requetes)
    assert requetes[0].url.params["q"].startswith("task.apexDomain:example.com")


def test_sans_cle_et_rien_trouve(contexte, outils, http_simule):
    sortie, requetes = _lancer(
        contexte, outils, http_simule, {RECHERCHE: {"total": 0, "results": []}}, secrets={}
    )
    outils.verifier_sortie(sortie)
    assert sortie["total_scans"] == 0 and sortie["verdicts"] == [] and sortie["authenticated"] is False
    assert "API-Key" not in requetes[0].headers
    assert SPEC.score_rules[0].evaluate({"urlscan": sortie}).measured is False


def test_limite_sur_les_verdicts_non_fatale(contexte, outils, http_simule):
    routes = {RECHERCHE: {"total": 1, "results": [_scan(U1)]}, RESULTAT.format(U1): (429, {}, "{}")}
    sortie, _ = _lancer(contexte, outils, http_simule, routes)
    assert sortie["total_scans"] == 1 and sortie["verdicts"] == []


def test_cible_ip_sans_verdict(contexte, outils, http_simule):
    routes = {RECHERCHE: {"total": 9, "results": [_scan(U1)]}}
    sortie, requetes = _lancer(contexte, outils, http_simule, routes, domain="93.184.216.34")
    assert sortie["verdicts"] == [] and len(requetes) == 1


@pytest.mark.parametrize(
    ("statut", "code"), [(429, "network.quota"), (400, "network.http_status"), (500, "network.http_status")]
)
def test_echecs_http(contexte, outils, http_simule, statut, code):
    with pytest.raises(ModuleError) as erreur:
        _lancer(contexte, outils, http_simule, {RECHERCHE: (statut, {}, "{}")})
    assert erreur.value.message["$t"] == code and CLE not in str(erreur.value)


def test_illisible_delai_connexion(contexte, outils, http_simule):
    with pytest.raises(ModuleError) as erreur:
        _lancer(contexte, outils, http_simule, {RECHERCHE: (200, {}, "<html>")})
    assert erreur.value.message["$t"] == "urlscan.unreadable"
    with pytest.raises(ModuleError):
        _lancer(contexte, outils, http_simule, {RECHERCHE: {"results": "non"}})
    cache.clear_cache()
    with pytest.raises(ModuleError):
        _lancer(contexte, outils, http_simule, {RECHERCHE: httpx.ReadTimeout("long")})
    cache.clear_cache()
    with pytest.raises(ModuleError):
        _lancer(contexte, outils, http_simule, {})


def test_cle_facultative():
    assert SPEC.required_keys == () and SPEC.optional_keys == ("urlscan_key",)


def _entree(donnees):
    scan = {"modules": {"urlscan": {"data": donnees}}}
    return FindingInput(scan, "urlscan", lambda s, m: s["modules"][m]["data"], lambda s, m: True)


def test_constats_et_score():
    malveillant = {
        "total_scans": 4,
        "verdicts": [
            {
                "malicious": True,
                "has_verdicts": True,
                "categories": ["phishing"],
                "report_url": "https://urlscan.io/result/x/",
            }
        ],
    }
    propre = {"total_scans": 4, "verdicts": [{"malicious": False, "has_verdicts": True}]}
    assert SPEC.findings[0].check(_entree(malveillant)).severity == "high"
    assert SPEC.findings[0].check(_entree(propre)) is None
    assert SPEC.findings[0].check(_entree("illisible")) is None
    assert SPEC.score_rules[0].evaluate({"urlscan": malveillant}).points == 0
    assert SPEC.score_rules[0].evaluate({"urlscan": propre}).points == 3
    sans = {"verdicts": [{"malicious": False, "has_verdicts": False}]}
    assert SPEC.score_rules[0].evaluate({"urlscan": sans}).measured is False
