# =============================================================================
# DomainRecon - Tests du module « sensitive_files » (sans réseau)
# =============================================================================

import httpx

from domainrecon.scanner.errors import ModuleError
from domainrecon.scanner.modules.sensitive_files import SPEC
from domainrecon.scanner.rules import FindingInput

ACCUEIL = "<html><head><title>Accueil</title></head><body>" + "Contenu. " * 50 + "</body></html>"
ENV = "APP_KEY=base64:abcd\nDB_PASSWORD=secret\nDB_HOST=localhost\n"
GIT = "ref: refs/heads/main\n"


def _entree(data):
    return FindingInput(
        {"sensitive_files": data}, "sensitive_files", lambda scan, m: scan.get(m), lambda s, m: True
    )


def _serveur(fichiers=None, accueil=ACCUEIL, fourre_tout=False):
    fichiers = fichiers or {}

    def repondre(requete: httpx.Request) -> httpx.Response:
        chemin = requete.url.path
        if chemin == "/":
            return httpx.Response(200, headers={"Content-Type": "text/html"}, content=accueil)
        if chemin in fichiers:
            statut, corps = fichiers[chemin]
            return httpx.Response(statut, content=corps)
        if fourre_tout:
            return httpx.Response(200, headers={"Content-Type": "text/html"}, content=accueil)
        return httpx.Response(404, content="Not Found")

    return repondre


def _lancer(http_simule, contexte, outils, serveur):
    http_simule({})
    http_simule.state["handler"] = serveur
    valeur = outils.executer(SPEC, contexte())
    outils.verifier_sortie(valeur)
    return valeur


def test_env_et_git_exposes(http_simule, contexte, outils):
    valeur = _lancer(http_simule, contexte, outils, _serveur({"/.env": (200, ENV), "/.git/HEAD": (200, GIT)}))
    cles = {e["key"] for e in valeur["exposed"]}
    assert {"env", "git_head"} <= cles
    assert valeur["has_critical"] is True and valeur["catch_all"] is False
    constats = {r.code: r.check(_entree(valeur)) for r in SPEC.findings}
    assert constats["finding.sensitive_files.critical"] is not None
    # Le contenu du secret n'apparaît jamais dans le résultat.
    assert "secret" not in str(valeur)


def test_rien_expose(http_simule, contexte, outils):
    valeur = _lancer(http_simule, contexte, outils, _serveur())
    assert valeur["exposed"] == [] and valeur["exposed_count"] == 0
    assert not any(r.check(_entree(valeur)) for r in SPEC.findings)


def test_serveur_fourre_tout_aucun_faux_positif(http_simule, contexte, outils):
    """Un 200 avec la page d'accueil pour toute URL ne révèle aucun fichier."""
    valeur = _lancer(http_simule, contexte, outils, _serveur(fourre_tout=True))
    assert valeur["exposed"] == [] and valeur["catch_all"] is True


def test_contenu_invalide_ecarte(http_simule, contexte, outils):
    """Un .env qui ne contient pas d'affectations VAR= n'est pas retenu."""
    valeur = _lancer(http_simule, contexte, outils, _serveur({"/.env": (200, "<html>page</html>")}))
    assert all(e["key"] != "env" or e["found"] is False for e in valeur["exposed"] + [])
    assert "env" not in {e["key"] for e in valeur["exposed"]}


def test_delai_sur_un_chemin(http_simule, contexte, outils):
    base = _serveur({"/.git/HEAD": (200, GIT)})

    def repondre(requete):
        if requete.url.path == "/.env":
            raise httpx.ReadTimeout("délai", request=requete)
        return base(requete)

    valeur = _lancer(http_simule, contexte, outils, repondre)
    assert valeur["unverified"] >= 1
    assert "git_head" in {e["key"] for e in valeur["exposed"]}


def test_site_injoignable(http_simule, contexte, outils):
    http_simule({})
    try:
        outils.executer(SPEC, contexte())
    except ModuleError:
        return
    raise AssertionError("un site injoignable doit lever ModuleError")


def test_score_et_plafond(http_simule, contexte, outils):
    valeur = _lancer(http_simule, contexte, outils, _serveur({"/.env": (200, ENV)}))
    (rule,) = SPEC.score_rules
    outcome = rule.evaluate({"sensitive_files": valeur})
    assert outcome.points == 0 and outcome.cap_reason is not None
    propre = _lancer(http_simule, contexte, outils, _serveur())
    assert rule.evaluate({"sensitive_files": propre}).points == 8
