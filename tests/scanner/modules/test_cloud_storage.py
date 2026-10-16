# =============================================================================
# DomainRecon - Tests du module « cloud_storage » (sans réseau)
# =============================================================================

import httpx

from domainrecon.scanner.modules import cloud_storage
from domainrecon.scanner.modules.cloud_storage import SPEC
from domainrecon.scanner.rules import FindingInput

LISTING = '<?xml version="1.0"?><ListBucketResult><Name>b</Name></ListBucketResult>'


def _entree(data):
    return FindingInput(
        {"cloud_storage": data}, "cloud_storage", lambda scan, m: scan.get(m), lambda s, m: True
    )


def test_references_extraites_de_la_page():
    html = 'img src="https://assets-example.s3.amazonaws.com/logo.png" et https://storage.googleapis.com/exbucket/x'
    refs = cloud_storage._referenced_buckets(html)
    assert "assets-example" in refs and "exbucket" in refs


def test_candidats_depuis_le_domaine():
    cands = cloud_storage._candidates("example.com")
    assert "example" in cands and "example-backup" in cands
    assert len(cands) <= cloud_storage._MAX_CANDIDATES


def _serveur(accueil, routes):
    def repondre(requete: httpx.Request) -> httpx.Response:
        url = str(requete.url)
        if requete.url.host == "example.com":
            return httpx.Response(200, headers={"Content-Type": "text/html"}, content=accueil)
        for frag, (statut, corps) in routes.items():
            if frag in url:
                return httpx.Response(statut, content=corps)
        return httpx.Response(404, content="")

    return repondre


def test_bucket_cite_et_ouvert(http_simule, contexte, outils):
    accueil = '<html><body><img src="https://assets-example.s3.amazonaws.com/l.png"></body></html>'
    routes = {"assets-example.s3.amazonaws.com": (200, LISTING)}
    http_simule({})
    http_simule.state["handler"] = _serveur(accueil, routes)
    valeur = outils.executer(SPEC, contexte())
    outils.verifier_sortie(valeur)
    exposed = [b for b in valeur["buckets"] if b["status"] == "exposed"]
    assert any(b["bucket"] == "assets-example" and b["confidence"] == "referenced" for b in exposed)
    assert SPEC.findings[0].check(_entree(valeur)) is not None


def test_bucket_devine_sans_listing_ignore(http_simule, contexte, outils):
    """Un bucket deviné qui répond 200 sans listing XML n'est pas retenu (page tierce)."""
    accueil = "<html><body>rien</body></html>"
    routes = {"s3.amazonaws.com": (200, "<html>page d'accueil tierce</html>")}
    http_simule({})
    http_simule.state["handler"] = _serveur(accueil, routes)
    valeur = outils.executer(SPEC, contexte())
    outils.verifier_sortie(valeur)
    assert valeur["exposed_count"] == 0


def test_rien_trouve(http_simule, contexte, outils):
    http_simule({})
    http_simule.state["handler"] = _serveur("<html>rien</html>", {})
    valeur = outils.executer(SPEC, contexte())
    outils.verifier_sortie(valeur)
    assert valeur["buckets"] == []
    assert SPEC.findings[0].check(_entree(valeur)) is None
