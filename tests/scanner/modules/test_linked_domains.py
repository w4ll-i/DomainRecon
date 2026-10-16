# =============================================================================
# DomainRecon - Tests du module « linked_domains » (sans réseau)
# =============================================================================

import asyncio

import pytest

from domainrecon.i18n import render
from domainrecon.scanner.errors import ModuleError
from domainrecon.scanner.impl import wc_linked as logic
from domainrecon.scanner.modules.linked_domains import SPEC
from domainrecon.scanner.rules import FindingInput

HOME = "https://example.com/"

PAGE = """<html><head>
<script src="//CDN.JSDelivr.net/npm/jquery@3.7.1/dist/jquery.min.js"></script>
<script src="https://www.google-analytics.com/analytics.js"></script>
<script src="https://evilexample.com/pixel.js"></script>
<script src="https://example.com.attaquant.net/x.js"></script>
<link rel="stylesheet" href="https://fonts.googleapis.com/css2?family=Roboto">
<link rel="stylesheet" href="http://ancien.exemple.net/style.css">
<script src="https://cdn.example.com/app.js"></script>
<script src="/local.js"></script>
</head><body>
<a href="https://twitter.com/exemple">X</a><a href="https://www.netflix.com/">Netflix</a>
<iframe src="https://www.youtube-nocookie.com/embed/abc"></iframe>
<img src="https://static.autre-site.org/logo.png">
<form action="https://js.stripe.com/pay"></form>
</body></html>"""


def _par_domaine(liens):
    return {d["domain"]: d for d in liens["external_domains"]}


def _constat(code, data):
    regle = next(r for r in SPEC.findings if r.code == code)
    entree = FindingInput({SPEC.name: data}, SPEC.name, lambda scan, m: scan.get(m), lambda s, m: True)
    return regle.check(entree)


# --- Filtre corrigé ------------------------------------------------------------------


def test_domaine_ressemblant_est_bien_externe():
    """L'ancien `endswith(example.com)` excluait « evilexample.com » ; `domain in ref`, « example.com.attaquant.net »."""
    liens = _par_domaine(logic.analyze(PAGE, HOME, "example.com"))
    assert "evilexample.com" in liens
    assert "attaquant.net" in liens
    assert "example.com" not in liens


def test_sous_domaine_du_site_est_interne():
    liens = logic.analyze(PAGE, HOME, "example.com")
    assert "cdn.example.com" in liens["own_hosts"]
    assert all(d["domain"] != "example.com" for d in liens["external_domains"])


def test_classification_par_suffixe_entier():
    """« x.com » ne doit pas reconnaître netflix.com (sous-chaîne) ; « cdn » exact seulement en premier libellé."""
    assert logic.classify("netflix.com") is None
    assert logic.classify("twitter.com") == "social"
    assert logic.classify("syndication.twitter.com") == "social"
    assert logic.classify("cdnexample.org") is None
    assert logic.classify("cdn.exemple.net") == "cdn"
    assert logic.classify("www.google-analytics.com") == "analytics"
    assert logic.classify("fonts.gstatic.com") == "font"


def test_protocole_relatif_et_majuscules():
    liens = _par_domaine(logic.analyze(PAGE, HOME, "example.com"))
    assert liens["jsdelivr.net"]["category"] == "cdn"


def test_categories_et_groupes():
    liens = logic.analyze(PAGE, HOME, "example.com")
    assert "jsdelivr.net" in liens["cdn_domains"]
    assert "twitter.com" in liens["social_media"]
    assert "google-analytics.com" in liens["analytics_trackers"]
    assert "stripe.com" in liens["payment_domains"]
    assert "netflix.com" not in liens["social_media"]
    assert "evilexample.com" in liens["third_party_scripts"]


def test_contenu_mixte_seulement_sur_page_https():
    liens = logic.analyze(PAGE, HOME, "example.com")
    assert [m["kind"] for m in liens["mixed_content"]] == ["style"]
    assert logic.analyze(PAGE, "http://example.com/", "example.com")["mixed_content"] == []


def test_domaine_a_risque_marque():
    html = '<script src="https://cdn.polyfill.io/v3/polyfill.min.js"></script>'
    liens = logic.analyze(html, HOME, "example.com")
    assert liens["risky_domains"] == ["polyfill.io"]


def test_page_sans_lien_externe():
    liens = logic.analyze('<a href="/a">a</a><script src="/b.js"></script>', HOME, "example.com")
    assert liens["external_count"] == 0 and liens["external_domains"] == []


# --- Module ----------------------------------------------------------------------------


def test_succes(http_simule, contexte, outils):
    http_simule({HOME: (200, {}, PAGE)})
    valeur = outils.executer(SPEC, contexte())
    outils.verifier_sortie(valeur)
    categories = {d["domain"]: d["category"] for d in valeur["external_domains"]}
    assert render(categories["twitter.com"], "fr") == "Réseaux sociaux"
    assert categories["evilexample.com"] is None
    assert valeur["external_count"] == len(valeur["external_domains"])


def test_site_injoignable(http_simule, contexte):
    http_simule({})
    with pytest.raises(ModuleError):
        asyncio.run(SPEC.run(contexte()))


# --- Constats ----------------------------------------------------------------------------


def test_constat_contenu_mixte(http_simule, contexte, outils):
    http_simule({HOME: (200, {}, PAGE)})
    donnees = outils.executer(SPEC, contexte())
    constat = _constat("finding.linked_domains.mixed_content", donnees)
    assert constat["count"] == 1 and constat["example"].startswith("http://ancien.exemple.net")


def test_constat_traceurs_au_dela_du_seuil():
    assert _constat("finding.linked_domains.trackers", {"analytics_trackers": ["a.com"] * 4}) is None
    assert _constat("finding.linked_domains.trackers", {"analytics_trackers": ["a.com"] * 5}) == {"count": 5}


def test_donnee_inattendue_ne_leve_pas():
    for code in (r.code for r in SPEC.findings):
        for donnees in (None, 3, [], {"mixed_content": "x", "analytics_trackers": 4}):
            _constat(code, donnees)


def test_declaration():
    assert SPEC.family == "web" and SPEC.category == "passif" and not SPEC.score_rules
