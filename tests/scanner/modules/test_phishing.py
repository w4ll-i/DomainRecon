# =============================================================================
# DomainRecon - Tests du module « phishing » (sans réseau)
# =============================================================================

import gzip

import httpx
import pytest

from domainrecon.scanner.errors import ModuleError
from domainrecon.scanner.modules import phishing
from domainrecon.scanner.rules import FindingInput

SPEC = phishing.SPEC
FLUX_PT = "https://data.phishtank.com/data/online-valid.csv"
CDN_PT = "https://cdn.phishtank.com/datadumps/verified_online.csv"
FLUX_OP = "https://openphish.com/feed.txt"
RAW_OP = "https://raw.githubusercontent.com/openphish/public_feed/refs/heads/main/feed.txt"
API_PT = "https://checkurl.phishtank.com/checkurl/"

ENTETE = "phish_id,url,phish_detail_url,submission_time,verified,verification_time,online,target\n"


@pytest.fixture(autouse=True)
def _index_vides():
    phishing.clear_indexes()
    yield
    phishing.clear_indexes()


def _csv(*lignes):
    corps = ENTETE
    for numero, url in lignes:
        corps += f"{numero},{url},http://www.phishtank.com/phish_detail.php?phish_id={numero},2026-10-15T05:54:20+00:00,yes,2026-10-15T06:02:17+00:00,yes,Other\n"
    return corps


def _routes(csv_texte=None, openphish="http://autre.test/\n", **extra):
    """Flux avec les redirections réelles : PhishTank vers son CDN, OpenPhish vers GitHub."""
    routes = {
        FLUX_PT: (302, {"location": CDN_PT + "?Expires=1&Signature=abc"}, ""),
        CDN_PT: (
            200,
            {"content-type": "text/csv"},
            csv_texte if csv_texte is not None else _csv((1, "https://x.test/a")),
        ),
        FLUX_OP: (302, {"location": RAW_OP}, ""),
        RAW_OP: (200, {"content-type": "text/plain"}, openphish),
    }
    routes.update(extra)
    return routes


def _lancer(contexte, outils, http_simule, routes, **champs):
    requetes = http_simule(routes)
    return outils.executer(SPEC, contexte(**champs)), requetes


def test_succes_page_d_accueil_listee(contexte, outils, http_simule):
    csv_texte = _csv(
        (11, "http://example.com/"),
        (12, "https://login.example.com/mot-de-passe"),
        (13, "https://autre.test/"),
    )
    sortie, requetes = _lancer(
        contexte,
        outils,
        http_simule,
        _routes(csv_texte, "https://example.com.evil.test/\nhttp://www.example.com/x\n"),
    )
    outils.verifier_sortie(sortie)
    assert sortie["listed"] is True and sortie["root_hits"] == 1 and sortie["page_hits"] == 2
    assert (
        sortie["sources"]["phishtank"]["status"] == "ok" and sortie["sources"]["phishtank"]["mode"] == "feed"
    )
    assert sortie["sources"]["openphish"]["pages"] == 1
    # example.com.evil.test n'est PAS un sous-domaine d'example.com.
    assert {h["host"] for h in sortie["hits"]} == {"example.com", "login.example.com", "www.example.com"}
    assert next(h for h in sortie["hits"] if h["phish_id"] == "11")["detail_url"].endswith("phish_id=11")
    # Redirections suivies à la main, User-Agent demandé par PhishTank, aucune URL de la cible envoyée.
    assert requetes[0].headers["user-agent"] == "phishtank/domainrecon"
    assert not any("example.com" in str(r.url) for r in requetes)


def test_rien_trouve(contexte, outils, http_simule):
    sortie, _ = _lancer(contexte, outils, http_simule, _routes())
    assert sortie["listed"] is False and sortie["hits"] == [] and sortie["failed_sources"] == []
    assert SPEC.score_rules[0].evaluate({"phishing": sortie}).points == 5


def test_flux_compresse_en_gzip(contexte, outils, http_simule):
    routes = _routes()
    routes[RAW_OP] = (200, {"content-encoding": "gzip"}, gzip.compress(b"https://example.com/p\n"))
    sortie, _ = _lancer(contexte, outils, http_simule, routes)
    assert sortie["sources"]["openphish"]["pages"] == 1


def test_grande_plateforme_abusee_n_est_pas_un_site_pirate(contexte, outils, http_simule):
    lignes = [(i, f"https://docs.example.com/form/{i}") for i in range(60)]
    sortie, _ = _lancer(contexte, outils, http_simule, _routes(_csv(*lignes)))
    assert sortie["root_hits"] == 0 and sortie["page_hits"] == 60 and sortie["abused_platform"] is True
    assert SPEC.findings[1].check(_entree(sortie)).severity == "low"
    assert SPEC.score_rules[0].evaluate({"phishing": sortie}).points == 4


def test_entrees_non_verifiees_ecartees(contexte, outils, http_simule):
    csv_texte = (
        ENTETE + "5,http://example.com/,u,t,no,t,yes,Other\n6,http://example.com/b,u,t,yes,t,no,Other\n"
    )
    sortie, _ = _lancer(contexte, outils, http_simule, _routes(csv_texte))
    assert sortie["listed"] is False


def test_repli_api_phishtank_exige_verifie_et_valide(contexte, outils, http_simule):
    """example.com est connu de PhishTank mais non vérifié et non valide : pas un positif."""

    def api(requete):
        return httpx.Response(
            200,
            json={"results": {"in_database": True, "phish_id": 4866807, "verified": False, "valid": False}},
        )

    routes = _routes(**{FLUX_PT: (503, {}, "")})
    routes[API_PT] = api
    sortie, requetes = _lancer(contexte, outils, http_simule, routes)
    assert sortie["sources"]["phishtank"]["mode"] == "api" and sortie["listed"] is False
    assert any(r.method == "POST" for r in requetes)

    def api_vrai(requete):
        return httpx.Response(
            200, json={"results": {"in_database": True, "phish_id": 9, "verified": True, "valid": True}}
        )

    phishing.clear_indexes()
    routes[API_PT] = api_vrai
    sortie, _ = _lancer(contexte, outils, http_simule, routes)
    assert sortie["root_hits"] >= 1


def test_une_source_en_echec_garde_l_autre(contexte, outils, http_simule):
    routes = _routes(openphish="rien d'utile\n")
    sortie, _ = _lancer(contexte, outils, http_simule, routes)
    assert sortie["failed_sources"] == ["openphish"] and sortie["sources"]["openphish"]["status"] == "failed"
    assert sortie["measured"] is True


def test_toutes_les_sources_en_echec(contexte, outils, http_simule):
    with pytest.raises(ModuleError) as erreur:
        _lancer(contexte, outils, http_simule, {})
    assert erreur.value.message["$t"] == "phishing.no_source"


def test_delai_depasse_et_quota(contexte, outils, http_simule):
    routes = _routes(**{CDN_PT: httpx.ReadTimeout("lent"), RAW_OP: (429, {}, "")})
    routes[API_PT] = httpx.ReadTimeout("lent")
    with pytest.raises(ModuleError):
        _lancer(contexte, outils, http_simule, routes)


def test_redirection_non_securisee_refusee(contexte, outils, http_simule):
    routes = _routes(**{FLUX_OP: (302, {"location": "http://openphish.example/feed.txt"}, "")})
    sortie, _ = _lancer(contexte, outils, http_simule, routes)
    assert sortie["sources"]["openphish"]["status"] == "failed"


def test_plateforme_mutualisee_limitee_au_sous_domaine(contexte, outils, http_simule):
    csv_texte = _csv((1, "https://alice.github.io/x"), (2, "https://bob.github.io/y"))
    sortie, _ = _lancer(
        contexte,
        outils,
        http_simule,
        _routes(csv_texte),
        domain="alice.github.io",
        apex="github.io",
        site="alice.github.io",
    )
    assert sortie["scope"] == "alice.github.io" and sortie["page_hits"] == 1


def test_cible_ip(contexte, outils, http_simule):
    sortie, _ = _lancer(
        contexte,
        outils,
        http_simule,
        _routes(_csv((1, "http://93.184.216.34/login"))),
        domain="93.184.216.34",
    )
    assert sortie["scope"] == "93.184.216.34" and sortie["page_hits"] == 1


def _entree(donnees):
    scan = {"modules": {"phishing": {"data": donnees}}}
    return FindingInput(scan, "phishing", lambda s, m: s["modules"][m]["data"], lambda s, m: True)


def test_constats_et_score():
    racine = {
        "root_hits": 1,
        "page_hits": 0,
        "scope": "example.com",
        "hits": [{"source": "phishtank", "url": "http://example.com/"}],
    }
    pages = {"root_hits": 0, "page_hits": 3, "scope": "example.com", "hits": []}
    assert SPEC.findings[0].check(_entree(racine))["count"] == 1
    assert SPEC.findings[0].check(_entree(pages)) is None
    assert SPEC.findings[1].check(_entree(pages)).severity == "medium"
    assert SPEC.findings[1].check(_entree("illisible")) is None
    assert SPEC.score_rules[0].evaluate({"phishing": racine}).points == 0
    assert SPEC.score_rules[0].evaluate({"phishing": pages}).points == 2


def test_declaration():
    assert SPEC.keys == () and SPEC.category == "passif" and SPEC.verdict is True
