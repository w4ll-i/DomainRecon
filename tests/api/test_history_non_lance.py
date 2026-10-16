# =============================================================================
# DomainRecon - Tests de l'historique et de la timeline : module non lancé
# =============================================================================
# Un module que le scan n'a pas lancé (profil rapide, sélection personnalisée)
# n'a rien mesuré : son compteur est null, pas 0. Un module lancé qui ne trouve
# rien reste à 0. Un scan d'avant les profils (modules_launched NULL) est compté
# comme avant. Les scans sont enregistrés directement en base.
# =============================================================================

import pytest
from fastapi.testclient import TestClient

from domainrecon.api.app import app
from domainrecon.core import database
from domainrecon.core.models import Scan

# Comportement des 18 modules historiques : registre ramené à eux (tests/conftest.py).
pytestmark = pytest.mark.usefixtures("registre_historique")

OK = {"status": "ok", "error": None}


@pytest.fixture
def client():
    with TestClient(app) as c:
        yield c


def _enregistrer(domain: str, **colonnes) -> None:
    with database.SessionLocal() as db:
        db.add(Scan(domain=domain, status="success", **colonnes))
        db.commit()


def _compteurs(client, domain: str) -> tuple[tuple, tuple]:
    """((sous-domaines, ports) de l'historique, (sous-domaines, ports) de la timeline)."""
    (entree,) = client.get(f"/api/history?domain={domain}").json()["scans"]
    (point,) = client.get(f"/api/dns-timeline/{domain}").json()["timeline"]
    return (
        (entree["subdomains_count"], entree["open_ports_count"]),
        (point["subdomains_count"], point["open_ports_count"]),
    )


def test_scan_rapide_module_non_lance_compte_null(client):
    """Profil rapide : subdomains et open_ports ne sont pas dans le plan, ils s'affichent « non mesuré »."""
    _enregistrer(
        "rapide.non-lance.example",
        profile="rapide",
        modules_launched=["dns_records", "waf"],
        module_status={"dns_records": OK, "waf": OK},
        subdomains=[],
        open_ports=[],
    )
    assert _compteurs(client, "rapide.non-lance.example") == ((None, None), (None, None))


def test_scan_complet_zero_trouve_reste_zero(client):
    """Modules lancés qui ne trouvent rien : 0, pas null."""
    _enregistrer(
        "complet.non-lance.example",
        profile="complet",
        modules_launched=["subdomains", "open_ports"],
        module_status={"subdomains": OK, "open_ports": OK},
        subdomains=[],
        open_ports=[],
    )
    assert _compteurs(client, "complet.non-lance.example") == ((0, 0), (0, 0))


def test_module_lance_sans_statut_est_compte(client):
    """Déclaré dans modules_launched sans statut : lancé, sa liste est comptée."""
    _enregistrer(
        "declare.non-lance.example",
        modules_launched=["subdomains"],
        module_status={},
        subdomains=[{"subdomain": "www.declare.non-lance.example"}],
        open_ports=[],
    )
    assert _compteurs(client, "declare.non-lance.example") == ((1, None), (1, None))


def test_statut_prouve_que_le_module_a_tourne(client):
    """Un statut de module le compte comme lancé même s'il manque à modules_launched."""
    _enregistrer(
        "statut.non-lance.example",
        modules_launched=["waf"],
        module_status={"waf": OK, "open_ports": OK},
        subdomains=[],
        open_ports=[{"port": 443}],
    )
    assert _compteurs(client, "statut.non-lance.example") == ((None, 1), (None, 1))


def test_aucun_module_lance_compte_null(client):
    """Liste vide (connue) : rien n'a tourné, donc rien n'a été mesuré."""
    _enregistrer("vide.non-lance.example", modules_launched=[], subdomains=[], open_ports=[])
    assert _compteurs(client, "vide.non-lance.example") == ((None, None), (None, None))


@pytest.mark.parametrize("inconnu", [None, "subdomains", {"subdomains": True}, 3])
def test_ancien_scan_modules_launched_inconnu_inchange(client, inconnu):
    """modules_launched absent ou illisible (scan d'avant la v2) : listes comptées telles quelles."""
    domaine = f"ancien-{type(inconnu).__name__.lower()}.non-lance.example"
    _enregistrer(
        domaine,
        modules_launched=inconnu,
        subdomains=[{"subdomain": f"www.{domaine}"}],
        open_ports=[],
    )
    assert _compteurs(client, domaine) == ((1, 0), (1, 0))


def test_module_lance_en_echec_reste_null(client):
    """Lancé mais en échec : toujours null (règle d'avant), pas 0."""
    _enregistrer(
        "echec.non-lance.example",
        modules_launched=["subdomains", "open_ports"],
        module_status={"subdomains": {"status": "failed", "error": "délai"}, "open_ports": OK},
        subdomains=[],
        open_ports=[],
    )
    assert _compteurs(client, "echec.non-lance.example") == ((None, 0), (None, 0))
