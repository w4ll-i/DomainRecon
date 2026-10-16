# =============================================================================
# DomainRecon - Tests des scans en lot (POST /api/batches)
# =============================================================================
# Le scanner et l'enregistrement sont simulés (JobManager.runner et saver) ; aucune
# résolution DNS (ensure_target_allowed est remplacé).
# =============================================================================

import asyncio
import time

import pytest
from fastapi.testclient import TestClient
from surveillance import add_scan

from domainrecon.api.app import app
from domainrecon.api.jobs import JobManager
from domainrecon.api.routes import jobs as jobs_routes
from domainrecon.monitor import batches as batches_module
from domainrecon.monitor import routes as monitor_routes
from domainrecon.monitor.batches import MAX_BATCH_DOMAINS, BatchManager, clean_domains
from domainrecon.scanner.errors import TargetNotAllowedError


def test_nettoyage_de_la_liste():
    accepted, rejected, duplicates = clean_domains(
        [
            "Exemple.COM",
            "https://exemple.com/page",
            "  autre.test , troisieme.test;quatrieme.test\nexemple.com ",
            "!!",
            "",
            "bücher.example",
        ]
    )
    assert accepted == [
        "exemple.com",
        "autre.test",
        "troisieme.test",
        "quatrieme.test",
        "xn--bcher-kva.example",
    ]
    assert duplicates == 2
    assert [r["input"] for r in rejected] == ["!!"]
    assert rejected[0]["reason"]["$t"] == "target.invalid"


class Etat:
    """Suivi des scans simulés : domaines lancés, simultanéité maximale."""

    def __init__(self) -> None:
        self.started: list[str] = []
        self.running = 0
        self.peak = 0
        self.fail: set[str] = set()
        self.block = False


@pytest.fixture
def etat():
    return Etat()


@pytest.fixture
def banc(monkeypatch, etat):
    """Fabrique (client, gestionnaires) avec un scanner simulé, des lots neufs et des attentes courtes."""
    monkeypatch.setattr(batches_module, "SLOT_RETRY_DELAY", 0.02)

    async def resoudre(host):
        if host == "interdit.test":
            raise TargetNotAllowedError({"$t": "target.ip_not_allowed", "p": {}})
        return ["93.184.216.34"]

    monkeypatch.setattr(jobs_routes, "ensure_target_allowed", resoudre)

    async def scanner(domain, on_module, **plan):
        etat.started.append(domain)
        etat.running += 1
        etat.peak = max(etat.peak, etat.running)
        try:
            if etat.block:
                await asyncio.Event().wait()
            await asyncio.sleep(0.05)
            if domain in etat.fail:
                raise RuntimeError("panne")
            on_module("dns_records", "ok", 0.01)
            return {"domain": domain}
        finally:
            etat.running -= 1

    def enregistrer(result: dict) -> int:
        return add_scan(result["domain"], grade="B", score=82)

    def fabriquer(max_concurrent: int = 2):
        jobs = JobManager(max_concurrent, runner=scanner, saver=enregistrer)
        batches = BatchManager()
        app.dependency_overrides[jobs_routes.get_job_manager] = lambda: jobs
        app.dependency_overrides[monitor_routes.get_batch_manager] = lambda: batches
        return TestClient(app), jobs, batches

    yield fabriquer
    app.dependency_overrides.pop(jobs_routes.get_job_manager, None)
    app.dependency_overrides.pop(monitor_routes.get_batch_manager, None)


def _attendre(client, batch_id: str, statut: str = "done", delai: float = 10.0) -> dict:
    fin = time.monotonic() + delai
    while time.monotonic() < fin:
        body = client.get(f"/api/batches/{batch_id}").json()
        if body["status"] == statut:
            return body
        time.sleep(0.05)
    raise AssertionError(f"lot toujours « {body['status']} » : {body}")


def test_lot_complet(banc, etat):
    client, _, _ = banc()
    with client:
        response = client.post(
            "/api/batches",
            json={"domains": ["Un.test", "https://deux.test/x", "un.test", "!!", "trois.test"]},
        )
        assert response.status_code == 202
        start = response.json()
        assert start["total"] == 3 and start["duplicates"] == 1
        assert [r["input"] for r in start["rejected"]] == ["!!"]
        assert start["status"] == "running" and len(start["id"]) == 32
        body = _attendre(client, start["id"])
    assert body["counts"] == {"queued": 0, "running": 0, "done": 3, "failed": 0, "cancelled": 0}
    assert body["finished"] == 3 and body["profile"] == "complet"
    items = {i["domain"]: i for i in body["items"]}
    assert set(items) == {"un.test", "deux.test", "trois.test"}
    assert all(i["status"] == "done" and i["scan_id"] and i["error"] is None for i in items.values())
    assert items["un.test"]["grade"] == "B" and items["un.test"]["score"] == 82
    assert sorted(etat.started) == ["deux.test", "trois.test", "un.test"]


def test_concurrence_limitee_du_lot(banc, etat):
    client, _, _ = banc(max_concurrent=2)
    with client:
        batch_id = client.post("/api/batches", json={"domains": [f"d{i}.test" for i in range(6)]}).json()[
            "id"
        ]
        body = _attendre(client, batch_id)
    assert body["counts"]["done"] == 6
    assert etat.peak == 2


def test_un_seul_emplacement_le_lot_reste_sequentiel(banc, etat):
    client, _, _ = banc(max_concurrent=1)
    with client:
        batch_id = client.post("/api/batches", json={"domains": [f"d{i}.test" for i in range(3)]}).json()[
            "id"
        ]
        body = _attendre(client, batch_id)
    assert body["counts"]["done"] == 3 and etat.peak == 1


def test_un_domaine_en_echec_ne_bloque_pas_les_autres(banc, etat):
    etat.fail.add("casse.test")
    client, _, _ = banc()
    with client:
        batch_id = client.post(
            "/api/batches", json={"domains": ["casse.test", "interdit.test", "bon.test"], "profile": "rapide"}
        ).json()["id"]
        body = _attendre(client, batch_id)
    items = {i["domain"]: i for i in body["items"]}
    assert body["counts"]["done"] == 1 and body["counts"]["failed"] == 2
    assert items["bon.test"]["status"] == "done"
    assert items["casse.test"]["status"] == "failed" and isinstance(items["casse.test"]["error"], str)
    assert items["interdit.test"]["status"] == "failed" and items["interdit.test"]["scan_id"] is None


def test_liste_invalide_ou_trop_longue(banc):
    client, _, _ = banc()
    with client:
        vide = client.post("/api/batches", json={"domains": ["!!", "  "]})
        assert vide.status_code == 400 and vide.json()["code"] == "batch.empty"
        trop = client.post(
            "/api/batches", json={"domains": [f"d{i}.test" for i in range(MAX_BATCH_DOMAINS + 1)]}
        )
        assert trop.status_code == 400 and trop.json()["code"] == "batch.too_many"
        assert client.post("/api/batches", json={"domains": []}).status_code == 422
        assert client.post("/api/batches", json={}).status_code == 422
        assert (
            client.post("/api/batches", content="x", headers={"content-type": "text/plain"}).status_code
            == 415
        )


def test_autorisation_exigee_cote_serveur(banc):
    client, _, _ = banc()
    with client:
        sans = client.post(
            "/api/batches",
            json={"domains": ["a.test"], "profile": "personnalise", "selected": ["open_ports"]},
        )
        assert sans.status_code == 400 and sans.json()["code"] == "api.authorization_required"
        avec = client.post(
            "/api/batches",
            json={
                "domains": ["a.test"],
                "profile": "personnalise",
                "selected": ["open_ports"],
                "authorized_target": True,
            },
        )
        assert avec.status_code == 202
        _attendre(client, avec.json()["id"])


def test_annulation_du_lot(banc, etat):
    etat.block = True
    client, jobs, _ = banc(max_concurrent=1)
    with client:
        batch_id = client.post("/api/batches", json={"domains": [f"d{i}.test" for i in range(4)]}).json()[
            "id"
        ]
        for _ in range(100):
            if etat.running:
                break
            time.sleep(0.05)
        assert etat.running == 1
        cancel = client.post(f"/api/batches/{batch_id}/cancel", json={})
        assert cancel.status_code == 202 and cancel.json()["status"] == "cancelled"
        body = _attendre(client, batch_id, "cancelled")
        assert body["counts"]["cancelled"] == 4 and body["counts"]["done"] == 0
        assert client.post(f"/api/batches/{batch_id}/cancel", json={}).status_code == 409
        assert not jobs.busy()
    assert etat.started == ["d0.test"]


def test_lot_inconnu_et_liste(banc):
    client, _, _ = banc()
    with client:
        assert client.get("/api/batches/" + "0" * 32).status_code == 404
        assert client.get("/api/batches/pas-un-identifiant").status_code == 422
        assert client.post("/api/batches/" + "0" * 32 + "/cancel", json={}).status_code == 404
        batch_id = client.post("/api/batches", json={"domains": ["a.test"]}).json()["id"]
        _attendre(client, batch_id)
        listing = client.get("/api/batches").json()["batches"]
        assert [b["id"] for b in listing] == [batch_id]
        assert "items" not in listing[0]


def test_lots_anciens_oublies():
    manager = BatchManager()
    old = batches_module.Batch(id="a" * 32, plan=None, items=[], finished_at=time.monotonic() - 7200)
    recent = batches_module.Batch(id="b" * 32, plan=None, items=[], finished_at=time.monotonic())
    manager._batches = {old.id: old, recent.id: recent}
    assert manager.get(old.id) is None and manager.get(recent.id) is recent
