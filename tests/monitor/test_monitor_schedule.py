# =============================================================================
# DomainRecon - Tests des échéances, de run_due et du planificateur (horloge simulée)
# =============================================================================
# Le scanner est remplacé par un « runner » qui enregistre un scan de test ; les
# canaux externes par un transport httpx simulé. Aucune requête réseau.
# =============================================================================

import asyncio
import json
from datetime import datetime, timedelta

import httpx
import pytest
from surveillance import BASE_TIME, add_scan, add_watch, asynchrone, read_watch

from domainrecon.api.jobs import JobManager, TooManyScans
from domainrecon.core import database
from domainrecon.monitor import schedule, service
from domainrecon.monitor.scheduler import Scheduler, create_scheduler
from domainrecon.monitor.service import WatchScanError
from domainrecon.notify import store
from domainrecon.notify.models import Notification

NOW = BASE_TIME + timedelta(hours=1)


class Horloge:
    """Horloge simulée : l'heure ne bouge que si le test la déplace."""

    def __init__(self, now: datetime = NOW) -> None:
        self.now = now

    def __call__(self) -> datetime:
        return self.now

    def advance(self, **delta) -> None:
        self.now += timedelta(**delta)


class FauxRunner:
    """Runner de test : enregistre un scan par appel (le suivant de `scans`) et note les domaines lancés."""

    def __init__(self, *scans: dict) -> None:
        self.scans = list(scans)
        self.calls: list[str] = []

    async def __call__(self, spec) -> int:
        self.calls.append(spec.domain)
        options = self.scans.pop(0) if self.scans else {}
        return add_scan(spec.domain, **options)


# --- Échéances ------------------------------------------------------------------


def test_prochaine_echeance_selon_la_frequence():
    start = datetime(2026, 1, 31, 8, 30)
    assert schedule.next_run("daily", start) == datetime(2026, 2, 1, 8, 30)
    assert schedule.next_run("weekly", start) == datetime(2026, 2, 7, 8, 30)
    # 31 janvier + 1 mois : fin février (année non bissextile).
    assert schedule.next_run("monthly", start) == datetime(2026, 2, 28, 8, 30)
    with pytest.raises(ValueError):
        schedule.next_run("hourly", start)


def test_ajout_de_mois_passe_l_annee_et_les_bissextiles():
    assert schedule.add_months(datetime(2026, 12, 15), 1) == datetime(2027, 1, 15)
    assert schedule.add_months(datetime(2028, 1, 31), 1) == datetime(2028, 2, 29)
    assert schedule.add_months(datetime(2026, 3, 31), 12) == datetime(2027, 3, 31)


def test_surveillances_echues_triees_et_actives_seulement():
    late = add_watch("tard.test", next_run_at=NOW - timedelta(days=2))
    soon = add_watch("recent.test", next_run_at=NOW - timedelta(minutes=5))
    add_watch("futur.test", next_run_at=NOW + timedelta(minutes=1))
    add_watch("off.test", next_run_at=NOW - timedelta(days=9), enabled=False)
    with database.SessionLocal() as db:
        assert [watch_id for watch_id, _ in schedule.list_due(db, NOW)] == [late, soon]


def test_la_reservation_d_une_echeance_n_est_possible_qu_une_fois():
    watch_id = add_watch(next_run_at=NOW)
    new = NOW + timedelta(days=1)
    with database.SessionLocal() as db:
        assert schedule.claim(db, watch_id, NOW, new) is True
        assert schedule.claim(db, watch_id, NOW, new) is False
    assert read_watch(watch_id).next_run_at == new


# --- run_due --------------------------------------------------------------------


@asynchrone
async def test_run_due_lance_la_surveillance_echue_et_avance_l_echeance():
    watch_id = add_watch("a.test", frequency="weekly", next_run_at=NOW - timedelta(minutes=1))
    other = add_watch("b.test", next_run_at=NOW + timedelta(hours=2))
    runner = FauxRunner()
    results = await service.run_due(runner, clock=Horloge())
    assert runner.calls == ["a.test"]
    (result,) = results
    assert result.status == "done" and result.alerts == []
    watch = read_watch(watch_id)
    assert watch.next_run_at == NOW + timedelta(days=7)
    assert watch.last_status == "done" and watch.last_scan_id == result.scan_id
    assert watch.last_run_at == NOW and watch.last_error is None
    assert read_watch(other).next_run_at == NOW + timedelta(hours=2)
    # Rien n'est plus échu : le passage suivant ne relance rien.
    assert await service.run_due(runner, clock=Horloge()) == []
    assert runner.calls == ["a.test"]


@asynchrone
async def test_run_due_avec_horloge_qui_avance():
    watch_id = add_watch("a.test", frequency="daily", next_run_at=NOW)
    clock = Horloge()
    runner = FauxRunner()
    await service.run_due(runner, clock=clock)
    assert read_watch(watch_id).next_run_at == NOW + timedelta(days=1)
    clock.advance(hours=23)
    assert await service.run_due(runner, clock=clock) == []
    clock.advance(hours=1, minutes=1)
    (result,) = await service.run_due(runner, clock=clock)
    assert result.status == "done"
    assert runner.calls == ["a.test", "a.test"]
    assert read_watch(watch_id).next_run_at == clock.now + timedelta(days=1)


@asynchrone
async def test_deux_passages_simultanes_ne_lancent_qu_un_scan():
    add_watch("a.test", next_run_at=NOW - timedelta(minutes=1))
    runner = FauxRunner()
    first, second = await asyncio.gather(
        service.run_due(runner, clock=Horloge()), service.run_due(runner, clock=Horloge())
    )
    assert runner.calls == ["a.test"]
    assert len(first) + len(second) == 1


@asynchrone
async def test_echec_d_un_scan_n_arrete_pas_les_autres_et_reprogramme_dans_une_heure():
    failing = add_watch("echec.test", frequency="monthly", next_run_at=NOW - timedelta(minutes=2))
    healthy = add_watch("ok.test", next_run_at=NOW - timedelta(minutes=1))

    async def runner(spec):
        if spec.domain == "echec.test":
            raise WatchScanError({"$t": "api.scan_failed", "p": {}})
        return add_scan(spec.domain)

    results = {r.domain: r for r in await service.run_due(runner, clock=Horloge())}
    assert results["echec.test"].status == "failed" and results["ok.test"].status == "done"
    watch = read_watch(failing)
    assert watch.last_status == "failed" and watch.last_error["$t"] == "api.scan_failed"
    assert watch.next_run_at == NOW + timedelta(hours=1)
    assert read_watch(healthy).last_status == "done"


@asynchrone
async def test_exception_inattendue_enregistree_sans_detail():
    watch_id = add_watch("bug.test", next_run_at=NOW)

    async def runner(spec):
        raise RuntimeError("secret-interne")

    (result,) = await service.run_due(runner, clock=Horloge())
    assert result.status == "failed"
    assert "secret-interne" not in json.dumps(read_watch(watch_id).last_error)


@asynchrone
async def test_aucun_emplacement_libre_reporte_la_surveillance():
    watch_id = add_watch("a.test", next_run_at=NOW - timedelta(minutes=1))

    async def runner(spec):
        raise TooManyScans()

    (result,) = await service.run_due(runner, clock=Horloge())
    assert result.status == "deferred"
    watch = read_watch(watch_id)
    assert watch.next_run_at == NOW - timedelta(minutes=1) and watch.last_status is None


@asynchrone
async def test_annulation_rend_l_echeance():
    watch_id = add_watch("a.test", next_run_at=NOW)

    async def runner(spec):
        await asyncio.Event().wait()

    task = asyncio.ensure_future(service.run_due(runner, clock=Horloge()))
    await asyncio.sleep(0.2)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    assert read_watch(watch_id).next_run_at == NOW


@asynchrone
async def test_scan_en_erreur_compte_comme_echec():
    watch_id = add_watch("a.test", next_run_at=NOW)
    runner = FauxRunner({"status": "error", "measured": ()})
    (result,) = await service.run_due(runner, clock=Horloge())
    assert result.status == "failed"
    assert read_watch(watch_id).last_status == "failed"


@asynchrone
async def test_concurrence_limitee():
    for i in range(4):
        add_watch(f"d{i}.test", next_run_at=NOW)
    running = peak = 0

    async def runner(spec):
        nonlocal running, peak
        running += 1
        peak = max(peak, running)
        await asyncio.sleep(0.05)
        running -= 1
        return add_scan(spec.domain)

    results = await service.run_due(runner, clock=Horloge(), concurrency=2)
    assert len(results) == 4 and peak == 2


# --- Alertes ----------------------------------------------------------------------


@asynchrone
async def test_baisse_de_note_alerte_le_centre_puis_se_tait():
    watch_id = add_watch("a.test", next_run_at=NOW, rules={})
    runner = FauxRunner({"grade": "A", "score": 95}, {"grade": "D", "score": 50}, {"grade": "D", "score": 50})
    clock = Horloge()
    (first,) = await service.run_due(runner, clock=clock)
    assert first.alerts == []  # premier scan : simple référence
    clock.advance(days=1, minutes=1)
    (second,) = await service.run_due(runner, clock=clock)
    assert "grade_drop" in [a.rule for a in second.alerts]
    clock.advance(days=1, minutes=1)
    (third,) = await service.run_due(runner, clock=clock)
    assert third.alerts == []  # la note reste basse : aucun changement d'état
    with database.SessionLocal() as db:
        rows = db.query(Notification).filter(Notification.watch_id == watch_id).all()
    assert [r.rule for r in rows] == ["grade_drop"]
    assert rows[0].message["$t"] == "alert.grade_drop" and rows[0].is_read is False
    assert rows[0].scan_id == second.scan_id


@asynchrone
async def test_alerte_envoyee_aux_canaux_de_la_surveillance():
    add_watch("a.test", next_run_at=NOW, channels=["discord", "slack"])
    with database.SessionLocal() as db:
        store.save_channel(db, "discord", True, {"url": "https://discord.com/api/webhooks/1/secret-token"})
        # Slack désactivé : l'envoi est refusé proprement, sans bloquer Discord.
        store.save_channel(db, "slack", False, {"url": "https://hooks.slack.com/services/T/B/secret"})
    requests: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        return httpx.Response(204)

    runner = FauxRunner({"cert_days": 5})
    (result,) = await service.run_due(runner, clock=Horloge(), transport=httpx.MockTransport(handler))
    assert [a.rule for a in result.alerts] == ["cert_expiry"]
    assert len(requests) == 1 and requests[0].url.host == "discord.com"
    assert json.loads(requests[0].content)["username"] == "DomainRecon"
    assert result.delivery["discord"]["ok"] is True
    assert result.delivery["slack"]["ok"] is False
    with database.SessionLocal() as db:
        (row,) = db.query(Notification).all()
    assert row.delivery["discord"]["ok"] is True
    assert row.delivery["slack"]["error"]["$t"] == "notify.error_disabled"


@asynchrone
async def test_une_panne_des_canaux_ne_fait_pas_echouer_la_surveillance(monkeypatch):
    watch_id = add_watch("a.test", next_run_at=NOW)

    async def broken(*args, **kwargs):
        raise RuntimeError("canal en panne")

    monkeypatch.setattr(service.dispatch, "dispatch_alerts", broken)
    runner = FauxRunner({"cert_days": 3})
    (result,) = await service.run_due(runner, clock=Horloge())
    assert result.status == "done" and len(result.alerts) == 1
    assert read_watch(watch_id).last_status == "done"


# --- Planificateur ---------------------------------------------------------------


@asynchrone
async def test_planificateur_tick_avec_horloge_simulee():
    add_watch("a.test", next_run_at=NOW - timedelta(minutes=1))
    clock = Horloge()
    runner = FauxRunner()
    scheduler = Scheduler(runner, clock=clock, concurrency=1)
    assert [r.domain for r in await scheduler.tick()] == ["a.test"]
    assert scheduler.last_tick_at == NOW
    assert await scheduler.tick() == []
    clock.advance(days=1, minutes=5)
    assert [r.status for r in await scheduler.tick()] == ["done"]


@asynchrone
async def test_planificateur_boucle_reveil_et_arret():
    add_watch("a.test", next_run_at=NOW - timedelta(minutes=1))
    runner = FauxRunner()
    scheduler = Scheduler(runner, clock=Horloge(), interval=3600, initial_delay=3600)
    scheduler.start()
    scheduler.start()  # sans effet : une seule boucle
    assert scheduler.running
    await asyncio.sleep(0.05)
    assert runner.calls == []  # le premier passage est différé
    scheduler.wake()
    for _ in range(100):
        if runner.calls:
            break
        await asyncio.sleep(0.05)
    assert runner.calls == ["a.test"]
    await scheduler.stop()
    assert not scheduler.running
    await scheduler.stop()  # idempotent


@asynchrone
async def test_planificateur_survit_a_un_passage_en_echec(monkeypatch):
    calls = 0

    async def boom(*args, **kwargs):
        nonlocal calls
        calls += 1
        raise RuntimeError("base verrouillée")

    monkeypatch.setattr("domainrecon.monitor.scheduler.run_due", boom)
    scheduler = Scheduler(FauxRunner(), interval=0.05, initial_delay=0)
    scheduler.start()
    for _ in range(100):
        if calls >= 2:
            break
        await asyncio.sleep(0.05)
    await scheduler.stop()
    assert calls >= 2


# --- Runner du gestionnaire de tâches -------------------------------------------------


def _gestionnaire(max_concurrent: int = 2, runner=None) -> JobManager:
    async def scanner(domain, on_module, **plan):
        on_module("dns_records", "ok", 0.01)
        return {"domain": domain}

    def enregistrer(result: dict) -> int:
        return add_scan(result["domain"])

    return JobManager(max_concurrent, runner=runner or scanner, saver=enregistrer)


async def _cible(domain: str) -> str:
    return domain


@asynchrone
async def test_runner_du_gestionnaire_de_taches():
    manager = _gestionnaire()
    run = service.job_manager_runner(manager, _cible)
    spec = service.WatchSpec(1, "a.test", "rapide", (), False, "daily", (), "fr")
    scan_id = await run(spec)
    assert isinstance(scan_id, int)
    # L'emplacement est rendu après le scan.
    assert manager.busy() is False


@asynchrone
async def test_runner_du_gestionnaire_scan_en_echec():
    async def echoue(domain, on_module, **plan):
        raise RuntimeError("panne")

    run = service.job_manager_runner(_gestionnaire(runner=echoue), _cible)
    spec = service.WatchSpec(1, "a.test", "rapide", (), False, "daily", (), "fr")
    with pytest.raises(WatchScanError) as error:
        await run(spec)
    assert error.value.message["$t"] == "api.scan_failed"


@asynchrone
async def test_runner_du_gestionnaire_autorisation_manquante():
    run = service.job_manager_runner(_gestionnaire(), _cible)
    spec = service.WatchSpec(1, "a.test", "personnalise", ("open_ports",), False, "daily", (), "fr")
    with pytest.raises(WatchScanError) as error:
        await run(spec)
    assert error.value.message["$t"] == "api.authorization_required"


@asynchrone
async def test_runner_du_gestionnaire_sans_emplacement_libre():
    async def bloque(domain, on_module, **plan):
        await asyncio.Event().wait()

    manager = _gestionnaire(max_concurrent=1, runner=bloque)
    run = service.job_manager_runner(manager, _cible)
    spec = service.WatchSpec(1, "a.test", "rapide", (), False, "daily", (), "fr")
    first = asyncio.ensure_future(run(spec))
    await asyncio.sleep(0.2)
    with pytest.raises(TooManyScans):
        await run(spec)
    await manager.cancel_all()
    with pytest.raises(WatchScanError):
        await first


@asynchrone
async def test_runner_du_gestionnaire_cible_refusee_rend_l_emplacement():
    async def refuse(domain: str) -> str:
        raise ValueError("cible refusée")

    manager = _gestionnaire(max_concurrent=1)
    run = service.job_manager_runner(manager, refuse)
    spec = service.WatchSpec(1, "a.test", "rapide", (), False, "daily", (), "fr")
    with pytest.raises(WatchScanError):
        await run(spec)
    assert manager.busy() is False


def test_create_scheduler_laisse_un_emplacement_a_l_interface():
    assert create_scheduler(JobManager(3)).concurrency == 2
    assert create_scheduler(JobManager(1)).concurrency == 1
