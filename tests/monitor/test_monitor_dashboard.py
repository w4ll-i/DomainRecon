# =============================================================================
# DomainRecon - Tests du tableau de bord (GET /api/dashboard)
# =============================================================================

import pytest
from fastapi.testclient import TestClient
from surveillance import add_scan

from domainrecon.api.app import app
from domainrecon.core import database
from domainrecon.core.models import utcnow
from domainrecon.monitor.models import Watch


@pytest.fixture
def client():
    with TestClient(app) as c:
        yield c


def test_tableau_de_bord_vide(client):
    body = client.get("/api/dashboard").json()
    assert body["domains"] == []
    assert body["totals"]["domains"] == 0
    assert body["totals"]["average_score"] is None
    assert body["totals"]["findings"]["total"] == 0


def test_un_element_par_domaine_avec_dernier_scan_et_tendance(client):
    add_scan("a.test", minutes=0, grade="A", score=95)
    add_scan("a.test", minutes=10, grade="B", score=80)
    last = add_scan("a.test", minutes=20, grade="C", score=65)
    add_scan("b.test", minutes=5, grade="A", score=90, ports=(3306,))
    body = client.get("/api/dashboard").json()
    by_domain = {d["domain"]: d for d in body["domains"]}
    assert set(by_domain) == {"a.test", "b.test"}
    a = by_domain["a.test"]
    assert a["scan_id"] == last
    assert a["grade"] == "C" and a["score"] == 65
    assert a["scans_count"] == 3
    assert [point["score"] for point in a["trend"]] == [95, 80, 65]
    assert a["scan_timestamp"].endswith("Z")
    # Tri : dernier scan en premier.
    assert [d["domain"] for d in body["domains"]] == ["a.test", "b.test"]


def test_constats_ouverts_par_gravite_et_totaux(client):
    add_scan("sain.test", minutes=0, grade="A", score=95)
    add_scan("expose.test", minutes=1, grade="D", score=50, ports=(3306,))
    body = client.get("/api/dashboard").json()
    by_domain = {d["domain"]: d for d in body["domains"]}
    assert by_domain["sain.test"]["findings"]["total"] == 0
    exposed = by_domain["expose.test"]["findings"]
    assert exposed["total"] >= 1 and exposed["critical"] + exposed["high"] >= 1
    totals = body["totals"]
    assert totals["domains"] == 2
    assert totals["grades"]["A"] == 1 and totals["grades"]["D"] == 1
    assert totals["average_score"] == 72.5
    assert totals["with_critical_or_high"] == 1
    assert totals["findings"]["total"] == exposed["total"]


def test_note_non_mesuree_affichee_na(client):
    add_scan("na.test", grade="B", score=70, coverage=0)
    (item,) = client.get("/api/dashboard").json()["domains"]
    assert item["grade"] == "N/A" and item["score"] is None
    assert item["status"] == "success"


def test_surveillance_associee_au_domaine(client):
    add_scan("suivi.test")
    with database.SessionLocal() as db:
        db.add(Watch(domain="suivi.test", frequency="weekly", next_run_at=utcnow(), rules={}, channels=[]))
        db.commit()
    body = client.get("/api/dashboard").json()
    (item,) = body["domains"]
    assert item["watch"]["frequency"] == "weekly" and item["watch"]["enabled"] is True
    assert body["totals"]["watched"] == 1


def test_limite_de_domaines(client):
    for i in range(3):
        add_scan(f"d{i}.test", minutes=i)
    body = client.get("/api/dashboard?limit=2").json()
    assert len(body["domains"]) == 2
    assert body["totals"]["domains"] == 3 and body["totals"]["shown"] == 2
    assert client.get("/api/dashboard?limit=0").status_code == 422
