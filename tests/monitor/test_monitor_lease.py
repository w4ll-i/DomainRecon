# =============================================================================
# DomainRecon - Tests du bail d'exécution des surveillances (monitor/lease.py)
# =============================================================================
# Prise atomique, expiration et reprise, renouvellement, libération ; exclusion
# mutuelle entre deux exécutions concurrentes de run_due : deux passages d'une
# même boucle, deux boucles d'événements dans deux fils (planificateur intégré
# et commande `monitor run-due`), puis deux vrais processus sur la même base
# SQLite. Aucun réseau : le scanner est remplacé par un « runner » de test.
# =============================================================================

import asyncio
import logging
import os
import subprocess
import sys
import textwrap
import threading
import time
from datetime import timedelta
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.exc import OperationalError
from surveillance import BASE_TIME, add_scan, add_watch, asynchrone, read_watch

from domainrecon.api.app import app
from domainrecon.cli import run as run_cli
from domainrecon.core import database
from domainrecon.core.models import utcnow
from domainrecon.monitor import lease, service
from domainrecon.monitor.models import Watch, WatchLease
from domainrecon.monitor.scheduler import Scheduler
from domainrecon.monitor.service import WatchScanError

ROOT = Path(__file__).resolve().parents[2]
NOW = BASE_TIME + timedelta(hours=1)
TTL = timedelta(minutes=5)


class Horloge:
    """Horloge simulée figée (celle de run_due) ; `advance` la déplace."""

    def __init__(self, now=NOW) -> None:
        self.now = now

    def __call__(self):
        return self.now

    def advance(self, **delta) -> None:
        self.now += timedelta(**delta)


def _prendre(watch_id: int, holder: str, now=NOW, ttl=TTL) -> bool:
    with database.SessionLocal() as db:
        return lease.acquire(db, watch_id, holder, now, ttl)


def _renouveler(watch_id: int, holder: str, now=NOW, ttl=TTL) -> bool:
    with database.SessionLocal() as db:
        return lease.renew(db, watch_id, holder, now, ttl)


def _liberer(watch_id: int, holder: str) -> bool:
    with database.SessionLocal() as db:
        return lease.release(db, watch_id, holder)


def _baux() -> dict[int, WatchLease]:
    """Baux présents en base, par surveillance."""
    with database.SessionLocal() as db:
        rows = db.query(WatchLease).all()
        db.expunge_all()
        return {row.watch_id: row for row in rows}


def _poser_bail(watch_id: int, holder: str, expires_at, acquired_at=None) -> None:
    """Pose directement un bail (celui d'un autre processus)."""
    with database.SessionLocal() as db:
        db.add(
            WatchLease(
                watch_id=watch_id,
                holder=holder,
                acquired_at=acquired_at or expires_at - TTL,
                expires_at=expires_at,
            )
        )
        db.commit()


class Bloque:
    """Runner de test qui reste dans le scan tant que `liberer` n'est pas levé ; compte les scans simultanés."""

    def __init__(self) -> None:
        self.entree = asyncio.Event()
        self.liberer = asyncio.Event()
        self.appels: list[str] = []
        self.en_cours = 0
        self.pic = 0

    async def __call__(self, spec) -> int:
        self.appels.append(spec.domain)
        self.en_cours += 1
        self.pic = max(self.pic, self.en_cours)
        self.entree.set()
        try:
            await self.liberer.wait()
        finally:
            self.en_cours -= 1
        return add_scan(spec.domain)


class Enregistre:
    """Runner de test immédiat : enregistre un scan par appel."""

    def __init__(self) -> None:
        self.appels: list[str] = []

    async def __call__(self, spec) -> int:
        self.appels.append(spec.domain)
        return add_scan(spec.domain)


def _redevenir_echue(watch_id: int, quand=BASE_TIME) -> None:
    """Ce que fait « Lancer maintenant » (POST /api/watches/{id}/run) : la surveillance est de nouveau échue."""
    with database.SessionLocal() as db:
        db.query(Watch).filter(Watch.id == watch_id).update({Watch.next_run_at: quand})
        db.commit()


# --- Prise, expiration, renouvellement, libération -----------------------------------


def test_prise_d_un_bail_libre():
    watch_id = add_watch()
    assert _prendre(watch_id, "a") is True
    row = _baux()[watch_id]
    assert (row.holder, row.acquired_at, row.expires_at) == ("a", NOW, NOW + TTL)


def test_un_bail_tenu_ne_se_prend_pas_deux_fois():
    one, two = add_watch("a.test"), add_watch("b.test")
    assert _prendre(one, "a") is True
    assert _prendre(one, "b") is False
    # Même à une seconde de l'expiration, et par le même détenteur : le bail n'est pas encore libre.
    assert _prendre(one, "b", now=NOW + TTL - timedelta(seconds=1)) is False
    assert _prendre(one, "a") is False
    row = _baux()[one]
    assert (row.holder, row.acquired_at, row.expires_at) == ("a", NOW, NOW + TTL)
    # Un bail par surveillance.
    assert _prendre(two, "b") is True


def test_un_bail_expire_est_repris():
    watch_id = add_watch()
    assert _prendre(watch_id, "a") is True
    reprise = NOW + TTL
    assert _prendre(watch_id, "b", now=reprise) is True
    row = _baux()[watch_id]
    assert (row.holder, row.acquired_at, row.expires_at) == ("b", reprise, reprise + TTL)
    # L'ancien détenteur n'a plus de droit : ni renouveler, ni libérer le bail de l'autre.
    assert _renouveler(watch_id, "a", now=reprise) is False
    assert _liberer(watch_id, "a") is False
    assert _baux()[watch_id].holder == "b"


def test_une_reprise_est_prise_une_seule_fois():
    watch_id = add_watch()
    _poser_bail(watch_id, "mort", NOW - timedelta(seconds=1))
    assert _prendre(watch_id, "a") is True
    assert _prendre(watch_id, "b") is False
    assert _baux()[watch_id].holder == "a"


def test_renouvellement_reserve_au_detenteur():
    watch_id = add_watch()
    assert _prendre(watch_id, "a") is True
    plus_tard = NOW + timedelta(minutes=2)
    assert _renouveler(watch_id, "b", now=plus_tard) is False
    assert _baux()[watch_id].expires_at == NOW + TTL
    assert _renouveler(watch_id, "a", now=plus_tard) is True
    assert _baux()[watch_id].expires_at == plus_tard + TTL
    # Un bail expiré que personne n'a repris peut encore être renouvelé par son détenteur.
    apres_expiration = NOW + timedelta(hours=1)
    assert _renouveler(watch_id, "a", now=apres_expiration) is True
    assert _baux()[watch_id].expires_at == apres_expiration + TTL
    assert _renouveler(999, "a") is False


def test_liberation_reservee_au_detenteur():
    watch_id = add_watch()
    assert _prendre(watch_id, "a") is True
    assert _liberer(watch_id, "b") is False
    assert watch_id in _baux()
    assert _liberer(watch_id, "a") is True
    assert _baux() == {}
    assert _liberer(watch_id, "a") is False  # déjà libre
    assert _prendre(watch_id, "b") is True


def test_identifiants_d_execution_uniques():
    assert len({lease.new_holder() for _ in range(100)}) == 100
    assert all(len(lease.new_holder()) <= 64 for _ in range(10))


# --- Atomicité : plusieurs fils, plusieurs processus ---------------------------------


def _course(fonction, participants: int) -> list:
    """Lance `participants` fils qui appellent `fonction(rang)` en même temps ; renvoie leurs résultats."""
    barriere = threading.Barrier(participants)
    resultats: list = [None] * participants

    def travail(rang: int) -> None:
        barriere.wait(timeout=30)
        try:
            resultats[rang] = fonction(rang)
        except Exception as exc:  # une erreur de base doit faire échouer le test, pas se perdre dans le fil
            resultats[rang] = exc

    fils = [threading.Thread(target=travail, args=(rang,)) for rang in range(participants)]
    for fil in fils:
        fil.start()
    for fil in fils:
        fil.join(timeout=60)
    return resultats


@pytest.mark.parametrize("expire", [False, True], ids=["bail-libre", "bail-expire"])
def test_prise_concurrente_un_seul_gagnant(expire):
    """Huit fils (huit connexions SQLite) prennent le même bail en même temps : un seul l'obtient."""
    for tour in range(5):
        watch_id = add_watch(f"course{tour}-{int(expire)}.test")
        if expire:
            _poser_bail(watch_id, "mort", NOW - timedelta(seconds=1))
        resultats = _course(lambda rang, watch_id=watch_id: _prendre(watch_id, f"fil-{rang}"), participants=8)
        assert all(r in (True, False) for r in resultats), resultats
        assert resultats.count(True) == 1, resultats
        assert _baux()[watch_id].holder == f"fil-{resultats.index(True)}"


CHILD_COURSE = textwrap.dedent(
    """
    import sys
    import time
    from datetime import datetime
    from pathlib import Path

    pret, depart, watch_id, holder = Path(sys.argv[1]), Path(sys.argv[2]), int(sys.argv[3]), sys.argv[4]
    from domainrecon.core import database
    from domainrecon.monitor import lease

    pret.write_text("1")
    while not depart.exists():
        time.sleep(0.001)
    with database.SessionLocal() as db:
        print("GAGNE" if lease.acquire(db, watch_id, holder, datetime(2026, 3, 1, 13, 0), lease.LEASE_TTL) else "PERDU")
    """
)


def _python(script: str, *args, timeout: float = 120) -> subprocess.CompletedProcess:
    """Exécute un script dans un autre processus Python (même base : DATABASE_URL est héritée)."""
    return subprocess.run(
        [sys.executable, "-c", script, *map(str, args)],
        cwd=ROOT,
        capture_output=True,
        encoding="utf-8",
        timeout=timeout,
        check=False,
    )


def test_prise_concurrente_par_plusieurs_processus(tmp_path):
    """Quatre processus Python prennent le même bail au même instant : un seul l'obtient."""
    watch_id = add_watch("processus.test")
    depart = tmp_path / "depart"
    enfants = []
    for rang in range(4):
        pret = tmp_path / f"pret-{rang}"
        processus = subprocess.Popen(
            [sys.executable, "-c", CHILD_COURSE, str(pret), str(depart), str(watch_id), f"processus-{rang}"],
            cwd=ROOT,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            encoding="utf-8",
        )
        enfants.append((pret, processus))
    try:
        limite = time.monotonic() + 90
        while not all(pret.exists() for pret, _ in enfants):
            assert time.monotonic() < limite, "les processus ne sont pas prêts"
            assert all(p.poll() is None for _, p in enfants), [p.communicate()[1] for _, p in enfants]
            time.sleep(0.05)
        depart.write_text("1")
        sorties = [p.communicate(timeout=60) for _, p in enfants]
    finally:
        for _, processus in enfants:
            if processus.poll() is None:
                processus.kill()
    assert all(p.returncode == 0 for _, p in enfants), sorties
    verdicts = [out.strip() for out, _ in sorties]
    assert sorted(verdicts) == ["GAGNE", "PERDU", "PERDU", "PERDU"], sorties
    assert _baux()[watch_id].holder == f"processus-{verdicts.index('GAGNE')}"


# --- hold : prise, renouvellement et libération autour d'une exécution --------------------


@asynchrone
async def test_hold_prend_puis_libere_le_bail():
    watch_id = add_watch()
    clock = Horloge()
    async with lease.hold(watch_id, clock) as acquired:
        assert acquired is True
        row = _baux()[watch_id]
        assert row.acquired_at == NOW and row.expires_at == NOW + lease.LEASE_TTL
        assert row.holder.startswith(f"{os.getpid()}-")
    assert _baux() == {}


@asynchrone
async def test_hold_libere_le_bail_apres_une_exception():
    watch_id = add_watch()
    with pytest.raises(RuntimeError, match="boum"):
        async with lease.hold(watch_id, Horloge()) as acquired:
            assert acquired
            raise RuntimeError("boum")
    assert _baux() == {}


@asynchrone
async def test_hold_libere_le_bail_apres_une_annulation():
    watch_id = add_watch()
    dedans = asyncio.Event()

    async def tenir():
        async with lease.hold(watch_id, Horloge()):
            dedans.set()
            await asyncio.Event().wait()

    task = asyncio.ensure_future(tenir())
    await dedans.wait()
    assert watch_id in _baux()
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    assert _baux() == {}


@asynchrone
async def test_hold_annule_pendant_la_prise_ne_laisse_pas_de_bail(monkeypatch):
    """Annulation à l'instant même de la prise : le fil va au bout, et le bail pris malgré tout est rendu."""
    watch_id = add_watch()
    prise_reelle = lease._acquire
    entree, fin = threading.Event(), threading.Event()

    def lente(*args):
        entree.set()
        time.sleep(0.3)
        try:
            return prise_reelle(*args)
        finally:
            fin.set()

    monkeypatch.setattr(lease, "_acquire", lente)

    async def tenir():
        async with lease.hold(watch_id, Horloge()):
            pytest.fail("le bloc ne doit pas s'exécuter : la tâche est annulée avant")

    tache = asyncio.ensure_future(tenir())
    assert await asyncio.to_thread(entree.wait, 10)
    tache.cancel()
    with pytest.raises(asyncio.CancelledError):
        await tache
    # La prise est allée au bout dans son fil : le bail qu'elle a pris a été rendu, pas abandonné.
    assert await asyncio.to_thread(fin.wait, 10)
    assert _baux() == {}


@asynchrone
async def test_hold_refuse_un_bail_deja_tenu():
    watch_id = add_watch()
    async with lease.hold(watch_id, Horloge()) as premier:
        assert premier is True
        holder = _baux()[watch_id].holder
        async with lease.hold(watch_id, Horloge()) as second:
            assert second is False
        # Le refus ne touche pas au bail du premier.
        assert _baux()[watch_id].holder == holder
    assert _baux() == {}
    async with lease.hold(watch_id, Horloge()) as troisieme:
        assert troisieme is True


@asynchrone
async def test_hold_reprend_un_bail_expire_et_laisse_celui_d_un_autre(monkeypatch):
    watch_id = add_watch()
    _poser_bail(watch_id, "mort", NOW - timedelta(seconds=1))
    async with lease.hold(watch_id, Horloge()) as acquired:
        assert acquired is True
        assert _baux()[watch_id].holder != "mort"
    assert _baux() == {}
    # Bail encore valide d'un autre processus : pas de reprise, et il reste en place à la sortie.
    _poser_bail(watch_id, "vivant", NOW + timedelta(minutes=1))
    async with lease.hold(watch_id, Horloge()) as acquired:
        assert acquired is False
    assert _baux()[watch_id].holder == "vivant"


@asynchrone
async def test_hold_renouvelle_le_bail_tant_que_le_bloc_dure():
    watch_id = add_watch()
    horloge = Horloge()
    ttl = timedelta(seconds=30)
    async with lease.hold(watch_id, horloge, ttl=ttl, renew_every=0.01) as acquired:
        assert acquired
        assert _baux()[watch_id].expires_at == NOW + ttl
        horloge.advance(seconds=20)
        for _ in range(200):
            if _baux()[watch_id].expires_at == NOW + timedelta(seconds=20) + ttl:
                break
            await asyncio.sleep(0.01)
        assert _baux()[watch_id].expires_at == NOW + timedelta(seconds=20) + ttl
    assert _baux() == {}


@asynchrone
async def test_hold_perte_du_bail_signalee_sans_toucher_celui_de_l_autre(caplog):
    """Bail repris par un autre après une expiration : le renouvellement s'arrête et la sortie le laisse intact."""
    watch_id = add_watch()
    with caplog.at_level(logging.WARNING, logger="domainrecon.monitor.lease"):
        async with lease.hold(watch_id, Horloge(), renew_every=0.01) as acquired:
            assert acquired
            with database.SessionLocal() as db:
                db.query(WatchLease).filter(WatchLease.watch_id == watch_id).update(
                    {WatchLease.holder: "repreneur"}
                )
                db.commit()
            for _ in range(200):
                if "perdu" in caplog.text:
                    break
                await asyncio.sleep(0.01)
    assert f"Bail de la surveillance {watch_id} perdu" in caplog.text
    assert _baux()[watch_id].holder == "repreneur"


@asynchrone
async def test_hold_base_inaccessible_ne_lance_rien(monkeypatch, caplog):
    def occupee(*args):
        raise OperationalError("INSERT", {}, Exception("database is locked"))

    monkeypatch.setattr(lease, "_acquire", occupee)
    with caplog.at_level(logging.WARNING, logger="domainrecon.monitor.lease"):
        async with lease.hold(1, Horloge()) as acquired:
            assert acquired is False
    assert "prise impossible (OperationalError)" in caplog.text


@asynchrone
async def test_hold_liberation_en_echec_n_empeche_pas_la_sortie(monkeypatch, caplog):
    watch_id = add_watch()

    def occupee(*args):
        raise OperationalError("DELETE", {}, Exception("database is locked"))

    with caplog.at_level(logging.WARNING, logger="domainrecon.monitor.lease"):
        async with lease.hold(watch_id, Horloge()) as acquired:
            assert acquired
            monkeypatch.setattr(lease, "_release", occupee)
    assert "libération impossible" in caplog.text
    # Le bail restant expirera de lui-même.
    assert watch_id in _baux()


# --- run_due : une surveillance n'est jamais exécutée deux fois en même temps --------------


@asynchrone
async def test_surveillance_en_cours_non_relancee_meme_redevenue_echue():
    """« Lancer maintenant » pendant un scan : la réservation de l'échéance seule laissait un second scan partir."""
    watch_id = add_watch("a.test", next_run_at=NOW - timedelta(minutes=1))
    runner = Bloque()
    premier = asyncio.ensure_future(service.run_due(runner, clock=Horloge()))
    await runner.entree.wait()
    assert watch_id in _baux()

    _redevenir_echue(watch_id)
    second = await service.run_due(runner, clock=Horloge())
    assert second == []
    assert runner.appels == ["a.test"] and runner.pic == 1
    # La surveillance écartée reste échue et intacte.
    watch = read_watch(watch_id)
    assert watch.next_run_at == BASE_TIME and watch.last_status is None

    runner.liberer.set()
    (resultat,) = await premier
    assert resultat.status == "done"
    assert _baux() == {}
    # Bail rendu, surveillance toujours échue : elle repart au passage suivant, toujours seule.
    (suivant,) = await service.run_due(runner, clock=Horloge())
    assert suivant.status == "done"
    assert runner.appels == ["a.test", "a.test"] and runner.pic == 1


@asynchrone
async def test_les_autres_surveillances_ne_sont_pas_bloquees_par_un_bail():
    occupee = add_watch("occupee.test", next_run_at=NOW - timedelta(minutes=2))
    libre = add_watch("libre.test", next_run_at=NOW - timedelta(minutes=1))
    _poser_bail(occupee, "autre", NOW + timedelta(minutes=1))
    runner = Enregistre()
    (resultat,) = await service.run_due(runner, clock=Horloge())
    assert resultat.domain == "libre.test" and resultat.status == "done"
    assert runner.appels == ["libre.test"]
    assert read_watch(occupee).next_run_at == NOW - timedelta(minutes=2)
    assert read_watch(libre).last_status == "done"
    assert set(_baux()) == {occupee}


@asynchrone
async def test_bail_valide_d_un_autre_processus_ecarte_la_surveillance():
    watch_id = add_watch("a.test", next_run_at=NOW - timedelta(minutes=1))
    _poser_bail(watch_id, "autre-processus", NOW + timedelta(minutes=3))
    runner = Enregistre()
    assert await service.run_due(runner, clock=Horloge()) == []
    assert runner.appels == []
    watch = read_watch(watch_id)
    assert watch.next_run_at == NOW - timedelta(minutes=1) and watch.last_status is None
    assert _baux()[watch_id].holder == "autre-processus"


@asynchrone
async def test_bail_expire_d_un_processus_arrete_est_repris():
    watch_id = add_watch("a.test", next_run_at=NOW - timedelta(minutes=1))
    _poser_bail(watch_id, "processus-arrete", NOW - timedelta(seconds=1))
    runner = Enregistre()
    (resultat,) = await service.run_due(runner, clock=Horloge())
    assert resultat.status == "done" and runner.appels == ["a.test"]
    assert _baux() == {}


@asynchrone
async def test_bail_non_renouvele_expire_puis_une_autre_execution_le_reprend():
    """Un processus figé ne renouvelle plus son bail : à l'expiration, une autre exécution prend la relève."""
    watch_id = add_watch("a.test", next_run_at=NOW - timedelta(minutes=1))
    horloge = Horloge()
    runner = Bloque()
    premier = asyncio.ensure_future(service.run_due(runner, clock=horloge))
    await runner.entree.wait()
    _redevenir_echue(watch_id)
    # Le temps passe plus vite que le renouvellement (une minute réelle) : le bail est expiré.
    horloge.advance(seconds=lease.LEASE_TTL.total_seconds() + 1)
    autre = Enregistre()
    (repris,) = await service.run_due(autre, clock=horloge)
    assert repris.status == "done" and autre.appels == ["a.test"]
    # La première exécution finit après coup : elle ne libère pas ce qui n'est plus à elle.
    runner.liberer.set()
    (fini,) = await premier
    assert fini.status == "done"
    assert _baux() == {}


@pytest.mark.parametrize("issue", ["echec", "exception", "report", "annulation"])
@asynchrone
async def test_bail_libere_quelle_que_soit_l_issue(issue):
    watch_id = add_watch("a.test", next_run_at=NOW - timedelta(minutes=1))
    dedans = asyncio.Event()

    async def runner(spec):
        dedans.set()
        if issue == "echec":
            raise WatchScanError({"$t": "api.scan_failed", "p": {}})
        if issue == "exception":
            raise RuntimeError("secret-interne")
        if issue == "report":
            raise service.TooManyScans()
        await asyncio.Event().wait()

    tache = asyncio.ensure_future(service.run_due(runner, clock=Horloge()))
    if issue == "annulation":
        await dedans.wait()
        assert watch_id in _baux()
        tache.cancel()
        with pytest.raises(asyncio.CancelledError):
            await tache
    else:
        (resultat,) = await tache
        assert resultat.status == {"echec": "failed", "exception": "failed", "report": "deferred"}[issue]
    assert _baux() == {}


@asynchrone
async def test_deux_passages_simultanes_dans_la_meme_boucle():
    for i in range(3):
        add_watch(f"d{i}.test", next_run_at=NOW - timedelta(minutes=1))
    runner = Enregistre()
    premier, second = await asyncio.gather(
        service.run_due(runner, clock=Horloge()), service.run_due(runner, clock=Horloge())
    )
    assert sorted(runner.appels) == ["d0.test", "d1.test", "d2.test"]
    assert len(premier) + len(second) == 3
    assert _baux() == {}


@asynchrone
async def test_deux_boucles_d_evenements_dans_deux_fils_ne_lancent_qu_un_scan():
    """Deux passages réellement parallèles (deux boucles, deux connexions SQLite) : un seul scan, jamais deux à la fois."""
    watch_id = add_watch("a.test", next_run_at=NOW - timedelta(minutes=1))
    runner = Bloque()
    premier = asyncio.ensure_future(service.run_due(runner, clock=Horloge()))
    await runner.entree.wait()
    _redevenir_echue(watch_id)

    autre = Enregistre()
    resultats: list = []

    def autre_processus():
        resultats.append(asyncio.run(service.run_due(autre, clock=Horloge())))

    fil = threading.Thread(target=autre_processus)
    fil.start()
    await asyncio.to_thread(fil.join, 60)
    assert resultats == [[]] and autre.appels == []
    assert runner.appels == ["a.test"]

    runner.liberer.set()
    await premier
    assert _baux() == {}


@asynchrone
async def test_planificateur_integre_et_commande_run_due_ne_se_marchent_pas_dessus(monkeypatch, capsys):
    """Le scénario du chantier : le planificateur du serveur scanne, `domainrecon monitor run-due` passe en même temps."""
    watch_id = add_watch("a.test", next_run_at=BASE_TIME)
    runner = Bloque()
    cli = Enregistre()
    monkeypatch.setattr(service, "direct_runner", lambda: cli)
    planificateur = Scheduler(runner, concurrency=1)  # horloge réelle, comme la commande
    tick = asyncio.ensure_future(planificateur.tick())
    await runner.entree.wait()

    _redevenir_echue(watch_id)
    code = await asyncio.to_thread(run_cli, ["monitor", "run-due"])
    assert code == 0
    assert "Aucune surveillance échue." in capsys.readouterr().out
    assert cli.appels == [] and runner.appels == ["a.test"]
    assert read_watch(watch_id).next_run_at == BASE_TIME

    runner.liberer.set()
    (resultat,) = await tick
    assert resultat.status == "done"
    assert _baux() == {}

    # Le scan terminé, la commande peut lancer la surveillance restée échue.
    code = await asyncio.to_thread(run_cli, ["monitor", "run-due"])
    assert code == 0 and cli.appels == ["a.test"]
    assert "[ok] a.test" in capsys.readouterr().out


def test_la_commande_laisse_de_cote_une_surveillance_dont_le_bail_est_tenu(monkeypatch, capsys):
    watch_id = add_watch("a.test", next_run_at=BASE_TIME)
    cli = Enregistre()
    monkeypatch.setattr(service, "direct_runner", lambda: cli)
    _poser_bail(watch_id, "serveur", utcnow() + timedelta(minutes=10))
    assert run_cli(["monitor", "run-due"]) == 0
    assert "Aucune surveillance échue." in capsys.readouterr().out
    assert cli.appels == []
    assert _baux()[watch_id].holder == "serveur"
    assert read_watch(watch_id).next_run_at == BASE_TIME


CHILD_RUN_DUE = textwrap.dedent(
    """
    import sys
    from pathlib import Path

    marqueur, scan_id = Path(sys.argv[1]), int(sys.argv[2])
    from domainrecon import cli
    from domainrecon.monitor import service

    def faux_runner():
        async def run(spec):
            marqueur.write_text(spec.domain, encoding="utf-8")
            return scan_id

        return run

    service.direct_runner = faux_runner
    sys.exit(cli.run(["monitor", "run-due"]))
    """
)


def test_run_due_d_un_autre_processus_respecte_le_bail(tmp_path):
    """`domainrecon monitor run-due` dans un vrai second processus : bail valide = rien lancé ; bail expiré = repris."""
    watch_id = add_watch("a.test", next_run_at=BASE_TIME)
    scan_id = add_scan("a.test")
    marqueur = tmp_path / "lance"

    _poser_bail(watch_id, "serveur", utcnow() + timedelta(minutes=10))
    sortie = _python(CHILD_RUN_DUE, marqueur, scan_id)
    assert sortie.returncode == 0, sortie.stderr
    assert "Aucune surveillance échue." in sortie.stdout
    assert not marqueur.exists()
    assert read_watch(watch_id).next_run_at == BASE_TIME

    with database.SessionLocal() as db:
        db.query(WatchLease).delete()
        db.commit()
    _poser_bail(watch_id, "serveur-arrete", utcnow() - timedelta(minutes=1))
    sortie = _python(CHILD_RUN_DUE, marqueur, scan_id)
    assert sortie.returncode == 0, sortie.stderr
    assert marqueur.read_text(encoding="utf-8") == "a.test"
    assert "[ok] a.test" in sortie.stdout
    assert _baux() == {}
    assert read_watch(watch_id).last_status == "done"


# --- Suppression d'une surveillance ----------------------------------------------------


def test_supprimer_une_surveillance_supprime_son_bail(monkeypatch):
    monkeypatch.setenv("SCHEDULER", "0")
    one, two = add_watch("a.test"), add_watch("b.test")
    _poser_bail(one, "serveur", NOW + TTL)
    _poser_bail(two, "serveur", NOW + TTL)
    with TestClient(app) as client:
        assert client.delete(f"/api/watches/{one}").json() == {"id": one}
    assert set(_baux()) == {two}
