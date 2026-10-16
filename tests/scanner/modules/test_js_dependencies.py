# =============================================================================
# DomainRecon - Tests du module « js_dependencies » (OSV.dev simulé, sans réseau)
# =============================================================================

import asyncio
import json

import httpx
import pytest

from domainrecon.i18n import render
from domainrecon.scanner.errors import ModuleError
from domainrecon.scanner.impl import wc_js_libs as libs
from domainrecon.scanner.impl import wc_versions as versions
from domainrecon.scanner.modules.js_dependencies import SPEC
from domainrecon.scanner.rules import FindingInput

HOME = "https://example.com/"
OSV = "https://api.osv.dev/v1/query"

PAGE = """<html><head>
<script src="https://cdnjs.cloudflare.com/ajax/libs/jquery/3.3.1/jquery.min.js"></script>
<script src="https://cdn.jsdelivr.net/npm/bootstrap@4.3.1/dist/js/bootstrap.bundle.min.js"
        integrity="sha384-abc" crossorigin="anonymous"></script>
<link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap@4.3.1/dist/css/bootstrap.min.css">
<script src="/assets/lodash.4.17.4.js"></script>
<script src="https://www.googletagmanager.com/gtag/js?id=G-XXXX"></script>
<script src="https://evil-example.com/lib.js"></script>
<script src="//cdn.polyfill.io/v3/polyfill.min.js"></script>
</head><body></body></html>"""


def _avis(identifiant, cve, severite="MEDIUM", corrige="3.4.0"):
    return {
        "id": identifiant,
        "summary": "Pollution de prototype",
        "aliases": [cve],
        "database_specific": {"severity": severite},
        "affected": [
            {
                "package": {"name": "jquery", "ecosystem": "npm"},
                "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": corrige}]}],
            }
        ],
    }


def _osv(table):
    """Route OSV : avis par nom de paquet puis version (corps JSON de la requête)."""

    def repondre(requete):
        corps = json.loads(requete.content)
        cle = (corps["package"]["name"], corps["version"])
        return httpx.Response(200, json={"vulns": table.get(cle, [])})

    return repondre


def _lancer(http_simule, contexte, outils, page=PAGE, osv=None):
    routes = {HOME: (200, {}, page)}
    if osv is not None:
        routes[OSV] = osv
    http_simule(routes)
    valeur = outils.executer(SPEC, contexte())
    outils.verifier_sortie(valeur)
    return valeur


def _par_nom(valeur):
    return {(lib["name"], lib["version"]): lib for lib in valeur["libraries"]}


def _constat(code, data):
    regle = next(r for r in SPEC.findings if r.code == code)
    entree = FindingInput({SPEC.name: data}, SPEC.name, lambda scan, m: scan.get(m), lambda s, m: True)
    return regle.check(entree)


# --- Comparaison de versions ---------------------------------------------------------------


@pytest.mark.parametrize(
    ("version", "introduite", "corrigee", "attendu"),
    [
        ("3.5.0", None, "3.5.0", False),  # la version corrigée n'est PAS vulnérable
        ("3.4.9", None, "3.5.0", True),
        ("4.3.1", "4.0.0", "4.3.1", False),
        ("4.3.0", "4.0.0", "4.3.1", True),
        ("3.9.9", "4.0.0", "4.3.1", False),  # avant l'introduction
        ("3.5.0-beta1", None, "3.5.0", True),  # une avant-version précède la version finale
        ("3.5", None, "3.5.0", False),
        ("1.12.4", None, "1.9.0", False),
        ("latest", None, "3.5.0", None),  # illisible : ni vulnérable ni sûre
        ("3.x", None, "3.5.0", None),
        ("", None, "3.5.0", None),
        ("2.0.0", None, None, True),  # jamais corrigée
    ],
)
def test_plage_de_versions(version, introduite, corrigee, attendu):
    assert versions.is_affected(version, introduite, corrigee) is attendu


def test_comparaison():
    assert versions.compare_versions("1.10.0", "1.9.0") == 1
    assert versions.compare_versions("1.0", "1.0.0") == 0
    assert versions.compare_versions("1.0.0-rc1", "1.0.0") == -1
    assert versions.compare_versions("abc", "1.0.0") is None


def test_table_locale_ne_signale_pas_les_versions_corrigees():
    assert libs.local_vulnerabilities("jquery", "3.5.0") == []
    assert libs.local_vulnerabilities("jquery", "3.7.1") == []
    assert libs.local_vulnerabilities("bootstrap", "4.3.1") == []
    assert libs.local_vulnerabilities("jquery", "latest") == []
    assert {v["cve"] for v in libs.local_vulnerabilities("jquery", "3.3.1")} == {
        "CVE-2019-11358",
        "CVE-2020-11022",
        "CVE-2020-11023",
    }
    assert libs.local_vulnerabilities("lodash", "4.17.4")[0]["severity"] == "critical"


def test_table_locale_coherente():
    for paquet, introduite, corrigee, cve, gravite, nature in libs.LOCAL_VULNS:
        assert paquet in libs.KNOWN_PACKAGES, paquet
        assert versions.parse_version(corrigee) and (introduite == "0" or versions.parse_version(introduite))
        assert cve.startswith("CVE-") and gravite in ("critical", "high", "medium", "low")
        assert nature in libs.KINDS


# --- Identification d'une bibliothèque -------------------------------------------------------


@pytest.mark.parametrize(
    ("url", "nom", "version"),
    [
        ("https://cdnjs.cloudflare.com/ajax/libs/jquery/3.3.1/jquery.min.js", "jquery", "3.3.1"),
        ("https://cdn.jsdelivr.net/npm/bootstrap@4.3.1/dist/js/bootstrap.min.js", "bootstrap", "4.3.1"),
        ("https://unpkg.com/@popperjs/core@2.9.2/dist/umd/popper.min.js", "@popperjs/core", "2.9.2"),
        ("https://ajax.googleapis.com/ajax/libs/angularjs/1.5.0/angular.min.js", "angular", "1.5.0"),
        ("https://code.jquery.com/jquery-3.5.0.min.js", "jquery", "3.5.0"),
        ("https://code.jquery.com/ui/1.12.1/jquery-ui.min.js", "jquery-ui", "1.12.1"),
        ("https://maxcdn.bootstrapcdn.com/bootstrap/3.3.7/js/bootstrap.min.js", "bootstrap", "3.3.7"),
        ("https://example.com/assets/lodash.4.17.4.js", "lodash", "4.17.4"),
        ("https://example.com/wp-includes/js/jquery/jquery.min.js?ver=3.7.1", "jquery", "3.7.1"),
        ("https://example.com/libs/moment/2.29.1/moment.min.js", "moment", "2.29.1"),
    ],
)
def test_identification(url, nom, version):
    trouve = libs.identify(url)
    assert trouve["name"] == nom and trouve["version"] == version


@pytest.mark.parametrize(
    "url",
    [
        "https://x.com/main-1.2.js",
        "https://x.com/app.min.js",
        "https://x.com/vendor/chunk.3f2a.js",
        "https://x.com/",
    ],
)
def test_fichier_quelconque_non_identifie(url):
    """Un nom de fichier versionné n'est pas un nom de paquet : l'ancien repli interrogeait OSV avec « main »."""
    assert libs.identify(url) is None


def test_version_non_fixee():
    assert libs.identify("https://cdn.jsdelivr.net/npm/jquery@latest/dist/jquery.min.js")["version"] is None


# --- Module ---------------------------------------------------------------------------------


def test_succes_avec_osv(http_simule, contexte, outils):
    osv = _osv(
        {
            ("jquery", "3.3.1"): [
                _avis("GHSA-a", "CVE-2019-11358"),
                _avis("GHSA-b", "CVE-2020-11022", corrige="3.5.0"),
            ]
        }
    )
    valeur = _lancer(http_simule, contexte, outils, osv=osv)
    jquery = _par_nom(valeur)[("jquery", "3.3.1")]
    assert jquery["checked"] is True and jquery["severity"] == "medium"
    cves = {v["cve"] for v in jquery["vulnerabilities"]}
    assert {"CVE-2019-11358", "CVE-2020-11022", "CVE-2020-11023"} <= cves  # OSV + table locale, sans doublon
    assert len(cves) == len(jquery["vulnerabilities"])
    assert _par_nom(valeur)[("bootstrap", "4.3.1")]["vulnerabilities"] == []  # version corrigée
    assert valeur["osv"]["available"] is True and valeur["osv"]["queried"] >= 3
    assert valeur["vulnerable_count"] == 2  # jQuery 3.3.1 et lodash 4.17.4 (table locale)


def test_hors_ligne_la_table_locale_repond(http_simule, contexte, outils):
    """OSV.dev injoignable : le résultat reste utile (table locale) et le dit."""
    valeur = _lancer(http_simule, contexte, outils)  # aucune route OSV : connexion refusée
    assert valeur["osv"]["available"] is False and valeur["osv"]["failed"] == valeur["osv"]["queried"]
    assert render(valeur["osv"]["error"], "fr").startswith("OSV.dev")
    jquery = _par_nom(valeur)[("jquery", "3.3.1")]
    assert jquery["checked"] is False and jquery["vulnerabilities"]
    assert all(v["source"] == "local" for v in jquery["vulnerabilities"])


@pytest.mark.parametrize("reponse", [httpx.Response(500), httpx.Response(429), httpx.Response(200, text="x")])
def test_erreurs_osv_n_annulent_pas_le_module(http_simule, contexte, outils, reponse):
    valeur = _lancer(http_simule, contexte, outils, osv=lambda requete: reponse)
    assert valeur["osv"]["available"] is False and valeur["library_count"] >= 3


def test_cdn_compromis_et_polyfill(http_simule, contexte, outils):
    valeur = _lancer(http_simule, contexte, outils, osv=_osv({}))
    assert valeur["polyfill_detected"] is True
    assert (
        valeur["risky_cdns"][0]["host"] == "cdn.polyfill.io"
        and valeur["risky_cdns"][0]["severity"] == "critical"
    )


def test_miroir_sur_polyfill_fastly_non_accuse(http_simule, contexte, outils):
    page = '<script src="https://polyfill-fastly.io/v3/polyfill.min.js"></script>'
    assert _lancer(http_simule, contexte, outils, page=page, osv=_osv({}))["risky_cdns"] == []


def test_sri_manquant_reconnu_par_domaine_enregistrable(http_simule, contexte, outils):
    """« evil-example.com » contient « example.com » : il n'est pas exempté de SRI."""
    valeur = _lancer(http_simule, contexte, outils, osv=_osv({}))
    manquants = {m["host"] for m in valeur["sri_missing"]}
    assert "evil-example.com" in manquants and "cdnjs.cloudflare.com" in manquants
    assert "cdn.polyfill.io" in manquants  # URL protocole-relative, ignorée avant
    # Intégrité présente, ressource du site, service dynamique : pas de reproche.
    assert "www.googletagmanager.com" not in manquants and "example.com" not in manquants
    assert not any(m["url"].endswith("bootstrap.bundle.min.js") for m in valeur["sri_missing"])
    # Les feuilles de style tierces comptent aussi.
    assert any(m["kind"] == "style" for m in valeur["sri_missing"])


def test_fichiers_du_site_analyses(http_simule, contexte, outils):
    valeur = _lancer(http_simule, contexte, outils, osv=_osv({}))
    lodash = _par_nom(valeur)[("lodash", "4.17.4")]
    assert lodash["first_party"] is True and lodash["severity"] == "critical"


def test_version_non_fixee_n_est_pas_vulnerable(http_simule, contexte, outils):
    page = (
        '<script src="https://cdn.jsdelivr.net/npm/jquery@latest/dist/jquery.min.js" integrity="x"></script>'
    )
    valeur = _lancer(http_simule, contexte, outils, page=page, osv=_osv({}))
    jquery = valeur["libraries"][0]
    assert jquery["pinned"] is False and jquery["vulnerabilities"] == [] and valeur["osv"]["queried"] == 0


def test_page_sans_bibliotheque(http_simule, contexte, outils):
    valeur = _lancer(http_simule, contexte, outils, page="<html><body>Bonjour</body></html>", osv=_osv({}))
    assert valeur["libraries"] == [] and valeur["highest_severity"] == "ok" and valeur["sri_missing"] == []


def test_site_injoignable(http_simule, contexte):
    http_simule({})
    with pytest.raises(ModuleError):
        asyncio.run(SPEC.run(contexte()))


def test_delai_depasse(http_simule, contexte):
    http_simule({HOME: httpx.ReadTimeout("délai"), "http://example.com/": httpx.ReadTimeout("délai")})
    with pytest.raises(ModuleError):
        asyncio.run(SPEC.run(contexte()))


# --- Constats et score -------------------------------------------------------------------------


def _resultat(http_simule, contexte, outils):
    return _lancer(http_simule, contexte, outils, osv=_osv({}))


def test_constats(http_simule, contexte, outils):
    donnees = _resultat(http_simule, contexte, outils)
    vulnerables = _constat("finding.js_dependencies.vulnerable", donnees)
    par_nom = {h.params["name"]: h for h in vulnerables}
    assert par_nom["lodash"].severity == "critical" and par_nom["lodash"].params["fixed"] == "4.17.21"
    assert par_nom["jquery"].severity == "medium"
    cdn = _constat("finding.js_dependencies.risky_cdn", donnees)
    assert cdn[0].params["host"] == "cdn.polyfill.io" and cdn[0].severity == "critical"
    sri = _constat("finding.js_dependencies.sri_missing", donnees)
    assert sri.severity == "medium" and sri.params["scripts"] >= 3


def test_sri_style_seul_est_de_faible_gravite():
    donnees = {"sri_missing": [{"kind": "style", "host": "cdn.example.net", "url": "x"}]}
    assert _constat("finding.js_dependencies.sri_missing", donnees).severity == "low"


def test_constats_rien_a_signaler():
    for code in (r.code for r in SPEC.findings):
        assert _constat(code, {"libraries": [], "risky_cdns": [], "sri_missing": []}) is None


def test_donnee_inattendue_ne_leve_pas():
    for code in (r.code for r in SPEC.findings):
        for donnees in (None, 3, [], {"libraries": "x", "risky_cdns": [None], "sri_missing": [3]}):
            _constat(code, donnees)


@pytest.mark.parametrize(
    ("donnees", "points"),
    [
        ({"highest_severity": "critical"}, 0),
        ({"highest_severity": "ok", "risky_cdns": [{"host": "x"}]}, 0),
        ({"highest_severity": "high"}, 1),
        ({"highest_severity": "medium", "sri_missing_count": 2}, 2),
        ({"highest_severity": "ok", "sri_missing_count": 2}, 4),
        ({"highest_severity": "ok"}, 5),
    ],
)
def test_score(donnees, points):
    assert SPEC.score_rules[0].evaluate({"js_dependencies": donnees}).points == points


def test_declaration():
    assert SPEC.family == "web" and SPEC.category == "passif" and SPEC.optional is True
