# =============================================================================
# DomainRecon - Tests du module « dast_data » (sans réseau)
# =============================================================================

import httpx
import pytest

from domainrecon.scanner.errors import ModuleError
from domainrecon.scanner.impl import dast_data as logic
from domainrecon.scanner.modules.dast_data import SPEC
from domainrecon.scanner.rules import FindingInput, Hit

ACCUEIL = "<html><body>" + "Bienvenue sur le site. " * 40 + "</body></html>"


def _entree(data):
    return FindingInput({"dast_data": data}, "dast_data", lambda scan, m: scan.get(m), lambda s, m: True)


def _constat(code, data):
    return next(r for r in SPEC.findings if r.code == code).check(_entree(data))


def _serveur(en_tetes=None, statut_404=404, corps_404="Not Found", accueil=ACCUEIL):
    def repondre(requete: httpx.Request) -> httpx.Response:
        if requete.url.path == "/":
            return httpx.Response(200, headers=en_tetes or {}, content=accueil)
        return httpx.Response(statut_404, content=corps_404)

    return repondre


def _lancer(http_simule, contexte, outils, serveur):
    # Le chemin inexistant est aléatoire : un seul serveur simulé répond à toutes les URL.
    requetes = http_simule({})
    http_simule.state["handler"] = _handler_global(serveur, requetes)
    valeur = outils.executer(SPEC, contexte())
    outils.verifier_sortie(valeur)
    return valeur, requetes


def _handler_global(serveur, requetes):
    def handler(requete: httpx.Request) -> httpx.Response:
        requetes.append(requete)
        return serveur(requete)

    return handler


# --- Analyse des en-têtes ---------------------------------------------------------


def test_version_divulguee_et_banniere_sans_version():
    analyse = logic.analyze_headers({"server": "nginx/1.10.3 (Ubuntu)", "x-powered-by": "Express"})
    assert [f["header"] for f in analyse["findings"]] == ["Server"]
    assert {b["header"]: b["version"] for b in analyse["banners"]} == {"Server": True, "X-Powered-By": False}


def test_cdn_sans_version_n_est_pas_un_constat():
    assert logic.analyze_headers({"server": "cloudflare"})["findings"] == []


def test_en_tetes_de_debogage():
    analyse = logic.analyze_headers({"x-debug-token": "abc", "x-debug-token-link": "/_profiler/abc"})
    assert {f["header"]: f["severity"] for f in analyse["findings"]} == {
        "x-debug-token": "medium",
        "x-debug-token-link": "high",
    }


# --- Analyse de la page 404 ---------------------------------------------------------


@pytest.mark.parametrize(
    ("corps", "framework"),
    [
        ("<title>Whoops! There was an error.</title>", "laravel"),
        ("Using the URLconf defined in mysite.urls, Django tried these URL patterns", "django"),
        ("<h1>Whitelabel Error Page</h1>", "spring"),
        ("<pre>Cannot GET /xyz</pre>", "express"),
        (
            "<b>Warning</b>:  include(x.php): failed to open stream in <b>/var/www/a.php</b> on line <b>3</b>",
            "php",
        ),
        ("Fatal error: Uncaught Error in /var/www/html/index.php on line 12", "php"),
        ("Server Error in '/' Application.", "aspnet"),
        ("Traceback (most recent call last):\n  File", "python"),
        ("<address>Apache/2.4.29 (Ubuntu) Server at example.com Port 80</address>", "server_signature"),
        ("The Werkzeug interactive debugger", "werkzeug"),
    ],
)
def test_empreintes_de_pages_d_erreur(corps, framework):
    analyse = logic.analyze_not_found(404, corps, ACCUEIL)
    assert framework in {f["framework"] for f in analyse["findings"]}


@pytest.mark.parametrize(
    "corps",
    [
        "Page introuvable. Cet article parle de Laravel et de Django.",
        "Attention : Warning: ce produit est fragile.",
        "Not Found",
    ],
)
def test_faux_positifs_evites_sur_de_simples_mots(corps):
    """L'ancienne empreinte se déclenchait sur le mot « laravel », « Django » ou « Warning: »."""
    assert logic.analyze_not_found(404, corps, ACCUEIL)["findings"] == []


def test_serveur_fourre_tout_non_analyse():
    analyse = logic.analyze_not_found(200, ACCUEIL + "<!-- Whoops! There was an error -->", ACCUEIL)
    assert analyse == {"catch_all": True, "analyzed": False, "findings": []}


def test_page_200_differente_est_analysee():
    analyse = logic.analyze_not_found(200, "Traceback (most recent call last): boom", ACCUEIL)
    assert analyse["analyzed"] is True and analyse["findings"][0]["framework"] == "python"


# --- Module ---------------------------------------------------------------------------


def test_succes_site_propre(http_simule, contexte, outils):
    valeur, requetes = _lancer(http_simule, contexte, outils, _serveur({"Server": "cloudflare"}))
    assert valeur["findings"] == [] and valeur["finding_count"] == 0
    assert valeur["not_found"]["tested"] is True and valeur["not_found"]["status_code"] == 404
    assert requetes[-1].url.path.startswith("/dr404-")
    assert SPEC.score_rules[0].evaluate({"dast_data": valeur}).points == 3
    assert not any(r.check(_entree(valeur)) for r in SPEC.findings)


def test_site_bavard(http_simule, contexte, outils):
    valeur, _ = _lancer(
        http_simule,
        contexte,
        outils,
        _serveur(
            {"Server": "Apache/2.4.29", "X-Debug-Token-Link": "/_profiler/1"},
            500,
            "Traceback (most recent call last):",
        ),
    )
    assert {f["type"] for f in valeur["findings"]} == {"version_disclosure", "debug_header", "verbose_404"}
    assert valeur["findings"][0]["severity"] == "high"
    assert valeur["severity_summary"]["high"] == 1 and valeur["severity_summary"]["medium"] == 1
    debug = _constat("finding.dast_data.debug_header", valeur)
    assert isinstance(debug, Hit) and debug.severity == "high"
    assert _constat("finding.dast_data.version_disclosure", valeur) == {"headers": "Server: Apache/2.4.29"}
    assert _constat("finding.dast_data.verbose_404", valeur).params["frameworks"] == "python"
    assert SPEC.score_rules[0].evaluate({"dast_data": valeur}).points == 0


def test_serveur_fourre_tout_aucun_constat(http_simule, contexte, outils):
    valeur, _ = _lancer(http_simule, contexte, outils, _serveur(statut_404=200, corps_404=ACCUEIL))
    assert valeur["not_found"]["catch_all"] is True and valeur["findings"] == []


def test_echec_de_la_requete_404_garde_les_en_tetes(http_simule, contexte, outils):
    def serveur(requete):
        if requete.url.path == "/":
            return httpx.Response(200, headers={"Server": "nginx/1.10.3"}, content=ACCUEIL)
        raise httpx.ReadTimeout("délai", request=requete)

    valeur, _ = _lancer(http_simule, contexte, outils, serveur)
    assert valeur["not_found"]["tested"] is False and valeur["not_found"]["error"]
    assert valeur["finding_count"] == 1


def test_cible_injoignable_est_un_echec(http_simule, contexte, outils):
    http_simule({})
    with pytest.raises(ModuleError):
        outils.executer(SPEC, contexte())


def test_categorie_active():
    assert SPEC.category == "actif" and SPEC.requires_authorization and SPEC.keys == ()


def test_donnees_inattendues_ne_levent_pas():
    for donnees in (None, [], {"findings": "x"}, {"findings": [3, None, {"type": "debug_header"}]}):
        for regle in SPEC.findings:
            regle.check(_entree(donnees))
    assert SPEC.score_rules[0].evaluate({"dast_data": None}).points == 3
