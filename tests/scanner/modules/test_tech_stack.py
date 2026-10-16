# =============================================================================
# DomainRecon - Tests du module « tech_stack » (sans réseau)
# =============================================================================

import pytest

from domainrecon.i18n import render
from domainrecon.scanner.errors import ModuleError
from domainrecon.scanner.impl import wc_tech_catalog as catalog
from domainrecon.scanner.modules.tech_stack import SPEC
from domainrecon.scanner.rules import FindingInput

HOME = "https://example.com/"

PAGE_WORDPRESS = """<html><head><meta name="generator" content="WordPress 6.4.2">
<script src="/wp-includes/js/jquery/jquery.min.js?ver=3.7.1"></script>
<link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap@4.3.1/dist/css/bootstrap.min.css">
</head><body class="woocommerce"><p>Nous parlons de magento, shopify et sentry dans cet article.</p></body></html>"""


def _par_nom(technologies):
    return {t["name"]: t for t in technologies}


def _constat(code, data):
    regle = next(r for r in SPEC.findings if r.code == code)
    entree = FindingInput({SPEC.name: data}, SPEC.name, lambda scan, m: scan.get(m), lambda s, m: True)
    return regle.check(entree)


def _lancer(http_simule, contexte, outils, en_tetes, corps, statut=200):
    http_simule({HOME: (statut, en_tetes, corps)})
    valeur = outils.executer(SPEC, contexte())
    outils.verifier_sortie(valeur)
    return valeur


# --- Catalogue (sans réseau) --------------------------------------------------


def test_detection_avec_version_et_confiance():
    detectees = _par_nom(
        catalog.analyze(
            {"server": "nginx/1.18.0", "x-powered-by": "PHP/7.4.3", "set-cookie": "PHPSESSID=abc; path=/"},
            PAGE_WORDPRESS,
            HOME,
        )
    )
    assert detectees["Nginx"]["version"] == "1.18.0" and detectees["Nginx"]["confidence"] == "medium"
    assert detectees["PHP"]["version"] == "7.4.3" and detectees["PHP"]["confidence"] == "high"
    assert detectees["WordPress"]["version"] == "6.4.2" and detectees["WordPress"]["confidence"] == "high"
    assert detectees["jQuery"]["version"] == "3.7.1"
    assert detectees["Bootstrap"]["version"] == "4.3.1"
    assert detectees["jsDelivr"]["category_key"] == "cdn"


def test_faux_positifs_du_texte_evites():
    """Magento, Shopify, Sentry cités dans le TEXTE ne sont pas des technologies de la page."""
    noms = {t["name"] for t in catalog.analyze({}, PAGE_WORDPRESS, HOME)}
    assert not noms & {"Magento", "Shopify", "Sentry", "Cloudflare"}


def test_cdnjs_n_est_pas_cloudflare():
    html = '<script src="https://cdnjs.cloudflare.com/ajax/libs/jquery/3.3.1/jquery.min.js"></script>'
    noms = {t["name"] for t in catalog.analyze({}, html, HOME)}
    assert "cdnjs" in noms and "jQuery" in noms and "Cloudflare" not in noms


def test_cloudflare_par_en_tetes_seulement():
    detectees = _par_nom(catalog.analyze({"server": "cloudflare", "cf-ray": "abc-CDG"}, "", HOME))
    assert (
        detectees["Cloudflare"]["category_key"] == "cdn" and detectees["Cloudflare"]["confidence"] == "high"
    )


def test_technologie_deduite_en_confiance_faible():
    detectees = _par_nom(catalog.analyze({}, '<script src="/_next/static/chunks/main.js"></script>', HOME))
    assert detectees["Next.js"]["confidence"] == "medium"
    assert detectees["React"]["implied"] is True and detectees["React"]["confidence"] == "low"


def test_github_pages_exige_fastly():
    assert "GitHub Pages" not in {t["name"] for t in catalog.analyze({"server": "GitHub.com"}, "", HOME)}
    avec_fastly = catalog.analyze({"server": "GitHub.com", "x-fastly-request-id": "abc"}, "", HOME)
    assert "GitHub Pages" in {t["name"] for t in avec_fastly}


def test_serveur_et_generateur_inconnus_releves_tels_quels():
    detectees = _par_nom(
        catalog.analyze({"server": "MonServeur/9"}, '<meta name="generator" content="SuperSite 2.1">', HOME)
    )
    assert detectees["MonServeur/9"]["category_key"] == "web_server"
    assert (
        detectees["SuperSite"]["category_key"] == "generator" and detectees["SuperSite"]["version"] == "2.1"
    )


def test_apache_coyote_est_tomcat_pas_apache():
    noms = {t["name"] for t in catalog.analyze({"server": "Apache-Coyote/1.1"}, "", HOME)}
    assert "Apache Tomcat" in noms and "Apache HTTP Server" not in noms


def test_niveaux_de_confiance():
    assert [catalog.confidence_of(n) for n in (2, 3, 4, 5, 9)] == ["low", "medium", "medium", "high", "high"]


def test_categories_du_catalogue_toutes_declarees():
    for _name, category, *_ in catalog.SIGNATURES:
        assert category in catalog.CATEGORIES


def test_signatures_aucune_expression_invalide():
    # La compilation a lieu à l'import ; chaque signature a un nom unique.
    noms = [s[0] for s in catalog.SIGNATURES]
    assert len(noms) == len(set(noms)) and len(noms) >= 180


# --- Module ----------------------------------------------------------------------


def test_succes(http_simule, contexte, outils):
    valeur = _lancer(
        http_simule,
        contexte,
        outils,
        {"Server": "nginx/1.18.0", "X-Powered-By": "PHP/7.4.3"},
        PAGE_WORDPRESS,
    )
    noms = _par_nom(valeur["technologies"])
    assert valeur["measured"] is True and valeur["count"] == len(valeur["technologies"])
    assert noms["WordPress"]["category"]["$t"] == "tech_stack.cat_cms"
    assert render(noms["Nginx"]["category"], "fr") == "Serveur web"
    assert valeur["with_version"] >= 4


def test_page_sans_technologie(http_simule, contexte, outils):
    valeur = _lancer(http_simule, contexte, outils, {}, "<html><body>Bonjour</body></html>")
    assert valeur["technologies"] == [] and valeur["count"] == 0


def test_page_en_erreur_http_est_analysee(http_simule, contexte, outils):
    valeur = _lancer(http_simule, contexte, outils, {"Server": "nginx"}, "Not found", statut=404)
    assert "Nginx" in _par_nom(valeur["technologies"])


def test_site_injoignable(http_simule, contexte):
    import asyncio

    http_simule({})
    with pytest.raises(ModuleError) as erreur:
        asyncio.run(SPEC.run(contexte()))
    assert "injoignable" in render(erreur.value.message, "fr")


def test_delai_depasse(http_simule, contexte):
    import asyncio

    import httpx

    http_simule({HOME: httpx.ReadTimeout("délai"), "http://example.com/": httpx.ReadTimeout("délai")})
    with pytest.raises(ModuleError):
        asyncio.run(SPEC.run(contexte()))


# --- Constats et score ------------------------------------------------------------


def _donnees(**plus):
    return {
        "measured": True,
        "error": None,
        "technologies": [
            {
                "name": "Nginx",
                "version": "1.18.0",
                "confidence": "medium",
                "evidence": ["h:server"],
                "implied": False,
            },
            {
                "name": "PHP",
                "version": "7.4.3",
                "confidence": "high",
                "evidence": ["h:x-powered-by"],
                "implied": False,
            },
            {
                "name": "jQuery",
                "version": "3.7.1",
                "confidence": "medium",
                "evidence": ["url"],
                "implied": False,
            },
        ],
        **plus,
    }


def test_constat_version_exposee():
    constat = _constat("finding.tech_stack.version_disclosed", _donnees())
    assert constat["count"] == 2 and constat["items"] == ["Nginx 1.18.0", "PHP 7.4.3"]


def test_constat_version_exposee_pas_pour_une_bibliotheque_de_page():
    donnees = {
        "technologies": [{"name": "jQuery", "version": "3.7.1", "evidence": ["url"], "implied": False}]
    }
    assert _constat("finding.tech_stack.version_disclosed", donnees) is None


def test_constat_fin_de_vie():
    constats = _constat("finding.tech_stack.end_of_life", _donnees())
    assert [c.params["name"] for c in constats] == ["PHP"]
    assert constats[0].params["supported"] == "8.2"


def test_php_pris_en_charge_pas_en_fin_de_vie():
    donnees = {"technologies": [{"name": "PHP", "version": "8.3.1", "confidence": "high", "evidence": []}]}
    assert _constat("finding.tech_stack.end_of_life", donnees) is None


def test_donnee_inattendue_ne_leve_pas():
    for donnees in (None, [], {"technologies": "x"}, {"technologies": [None, 3]}):
        assert _constat("finding.tech_stack.version_disclosed", donnees) is None
        assert _constat("finding.tech_stack.end_of_life", donnees) is None


@pytest.mark.parametrize(
    ("technologies", "points"),
    [
        ([{"name": "PHP", "version": "5.6.0", "confidence": "high", "evidence": []}], 0),
        ([{"name": "Nginx", "version": "1.2", "confidence": "high", "evidence": ["h:server"]}], 2),
        ([{"name": "WordPress", "version": None, "confidence": "high", "evidence": ["url"]}], 3),
    ],
)
def test_score(technologies, points):
    sortie = SPEC.score_rules[0].evaluate({"tech_stack": {"technologies": technologies}})
    assert sortie.points == points and sortie.measured is True


def test_declaration():
    assert SPEC.family == "web" and SPEC.category == "passif" and SPEC.quick is True
