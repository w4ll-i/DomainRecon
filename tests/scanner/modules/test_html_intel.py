# =============================================================================
# DomainRecon - Tests du module « html_intel » (sans réseau)
# =============================================================================

import asyncio

import httpx
import pytest

from domainrecon.i18n import render
from domainrecon.scanner.errors import ModuleError
from domainrecon.scanner.impl import wc_html_intel as logic
from domainrecon.scanner.modules.html_intel import SPEC
from domainrecon.scanner.rules import FindingInput

HOME = "https://example.com/"

PAGE = """<!DOCTYPE html><html><head><title>Accueil</title>
<meta name="generator" content="WordPress 6.4.2">
<!--[if lt IE 9]><script src="html5shiv.js"></script><![endif]-->
<!-- TODO: retirer le mot de passe admin avant la mise en production -->
<!-- Serveur de test : 192.168.1.15, déployé depuis /var/www/html/site -->
<!-- Start of footer -->
</head><body>
<img src="/img/logo@2x.png" alt="logo@2x.png">
<p>Écrivez à contact@example.com ou à jean.dupont@autre-societe.org. Fichier sprite@3x.webp.</p>
<a href="mailto:support@example.com?subject=Aide">Support</a>
<form action="http://example.com/login" method="post">
  <input type="text" name="user"><input type="password" name="pass">
  <input type="hidden" name="csrf_token" value="abc"><input type="hidden" name="admin_role" value="1">
</form>
<form action="https://paiement.autre.net/pay"><input name="q"></form>
<pre>Warning: mysqli_connect(): Access denied in /var/www/html/db.php on line 12</pre>
</body></html>"""


def _constat(code, data):
    regle = next(r for r in SPEC.findings if r.code == code)
    entree = FindingInput({SPEC.name: data}, SPEC.name, lambda scan, m: scan.get(m), lambda s, m: True)
    return regle.check(entree)


def _lancer(http_simule, contexte, outils, corps, statut=200):
    http_simule({HOME: (statut, {}, corps)})
    valeur = outils.executer(SPEC, contexte())
    outils.verifier_sortie(valeur)
    return valeur


# --- Analyse ---------------------------------------------------------------------


def test_generateur_et_titre():
    intel = logic.analyze(PAGE, HOME, "example.com")
    assert intel["title"] == "Accueil"
    assert intel["generator"] == "WordPress 6.4.2" and intel["generator_has_version"] is True


def test_emails_pas_de_fichiers_et_rgpd():
    emails = logic.analyze(PAGE, HOME, "example.com")["emails"]
    assert sorted(emails["own"]) == ["contact@example.com", "support@example.com"]
    # Un tiers est masqué ; « logo@2x.png » et « sprite@3x.webp » ne sont pas des adresses.
    assert emails["third_party_masked"] == ["j***@autre-societe.org"]
    assert emails["total"] == 3


def test_commentaires_suspects_d_abord_et_bruit_ecarte():
    intel = logic.analyze(PAGE, HOME, "example.com")
    textes = [c["text"] for c in intel["comments"]]
    assert not any("html5shiv" in t or "Start of footer" in t for t in textes)
    assert "credential" in intel["comments"][0]["flags"] or "todo" in intel["comments"][0]["flags"]
    assert intel["suspicious_comments"] == 2


def test_ip_interne_et_chemins_de_serveur():
    intel = logic.analyze(PAGE, HOME, "example.com")
    assert intel["internal_ips"] == ["192.168.1.15"]
    assert "/var/www/html/site" in intel["server_paths"]


def test_ip_publique_et_numero_de_version_ne_sont_pas_des_ip_internes():
    intel = logic.analyze("<p>93.184.216.34 ; version 10.0.0.1.2 ; 999.168.1.1</p>", HOME, "example.com")
    assert intel["internal_ips"] == []


def test_formulaires():
    formulaires = logic.analyze(PAGE, HOME, "example.com")["forms"]
    connexion, paiement = formulaires
    assert connexion["has_password"] and connexion["insecure"] and not connexion["third_party"]
    assert paiement["third_party"] and not paiement["insecure"]
    assert connexion["hidden_fields"] == 2


def test_page_http_rend_les_formulaires_non_chiffres():
    html = '<form action="/login"><input type="password" name="p"></form>'
    assert logic.analyze(html, "http://example.com/", "example.com")["forms"][0]["insecure"] is True
    assert logic.analyze(html, HOME, "example.com")["forms"][0]["insecure"] is False


def test_champs_caches_sensibles_sans_jeton_csrf():
    assert logic.analyze(PAGE, HOME, "example.com")["sensitive_hidden_fields"] == ["admin_role"]


@pytest.mark.parametrize(
    ("extrait", "nature"),
    [
        ("<b>Warning</b>: include(x) in <b>/var/www/a.php</b> on line <b>3</b>", "php_error"),
        ("Fatal error: Uncaught Exception in /var/www/a.php:3", "php_error"),
        ("Traceback (most recent call last):\n  File x", "python_traceback"),
        ("at com.example.app.Main.run(Main.java:42)", "java_stacktrace"),
        ("System.NullReferenceException: Object reference", "dotnet_error"),
        ("You have an error in your SQL syntax near", "sql_error"),
    ],
)
def test_messages_d_erreur_techniques(extrait, nature):
    assert nature in logic.analyze(f"<body>{extrait}</body>", HOME, "example.com")["error_disclosures"]


def test_page_propre():
    intel = logic.analyze("<html><body><h1>Bonjour</h1></body></html>", HOME, "example.com")
    assert intel["error_disclosures"] == [] and intel["internal_ips"] == [] and intel["forms"] == []


# --- Module ------------------------------------------------------------------------


def test_succes(http_simule, contexte, outils):
    valeur = _lancer(http_simule, contexte, outils, PAGE)
    assert valeur["measured"] is True and valeur["generator"] == "WordPress 6.4.2"
    assert valeur["url"].rstrip("/") == "https://example.com" and valeur["html_length"] == len(PAGE)


def test_site_injoignable(http_simule, contexte):
    http_simule({})
    with pytest.raises(ModuleError) as erreur:
        asyncio.run(SPEC.run(contexte()))
    assert "injoignable" in render(erreur.value.message, "fr")


def test_delai_depasse(http_simule, contexte):
    http_simule({HOME: httpx.ReadTimeout("délai"), "http://example.com/": httpx.ReadTimeout("délai")})
    with pytest.raises(ModuleError):
        asyncio.run(SPEC.run(contexte()))


def test_corps_vide(http_simule, contexte, outils):
    valeur = _lancer(http_simule, contexte, outils, "")
    assert valeur["comments"] == [] and valeur["forms"] == [] and valeur["title"] is None


# --- Constats et score ----------------------------------------------------------------


def test_constats_sur_la_page_d_exemple(http_simule, contexte, outils):
    donnees = _lancer(http_simule, contexte, outils, PAGE)
    assert _constat("finding.html_intel.password_in_clear", donnees) == {"count": 1}
    assert (
        _constat("finding.html_intel.form_in_clear", donnees) is None
    )  # le formulaire non chiffré a un mot de passe
    assert _constat("finding.html_intel.internal_ip", donnees) == {"count": 1, "example": "192.168.1.15"}
    assert _constat("finding.html_intel.sensitive_comments", donnees) == {"count": 2}
    assert _constat("finding.html_intel.generator_version", donnees) == {"generator": "WordPress 6.4.2"}
    kinds = _constat("finding.html_intel.error_disclosure", donnees)["kinds"]
    assert render(kinds[0], "fr") == "erreur PHP"
    assert _constat("finding.html_intel.server_paths", donnees)["count"] >= 1


def test_formulaire_sans_mot_de_passe_en_clair():
    donnees = {"forms": [{"has_password": False, "insecure": True}]}
    assert _constat("finding.html_intel.form_in_clear", donnees) == {"count": 1}
    assert _constat("finding.html_intel.password_in_clear", donnees) is None


def test_donnee_inattendue_ne_leve_pas():
    for code in (r.code for r in SPEC.findings):
        for donnees in (
            None,
            3,
            [],
            {"forms": "x", "internal_ips": 4, "suspicious_comments": "a", "generator": 5},
        ):
            _constat(code, donnees)


@pytest.mark.parametrize(
    ("donnees", "points"),
    [
        ({"forms": [{"has_password": True, "insecure": True}]}, 0),
        ({"error_disclosures": ["php_error"]}, 1),
        ({"internal_ips": ["10.0.0.1"]}, 2),
        ({"forms": [{"has_password": False, "insecure": True}]}, 2),
        ({}, 3),
    ],
)
def test_score(donnees, points):
    assert SPEC.score_rules[0].evaluate({"html_intel": donnees}).points == points


def test_declaration():
    assert SPEC.family == "web" and SPEC.category == "passif"


def test_commentaires_dedoubles_et_marqueurs_de_gabarit_ecartes():
    html = "<!-- astro:end --><!-- astro:end --><!-- Un vrai commentaire --><!-- Un vrai commentaire -->"
    intel = logic.analyze(html, HOME, "example.com")
    assert [c["text"] for c in intel["comments"]] == ["Un vrai commentaire"] and intel["comments_total"] == 1
