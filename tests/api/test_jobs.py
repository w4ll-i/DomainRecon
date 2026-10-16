# =============================================================================
# DomainRecon - Tests du gestionnaire de tâches de scan (api/jobs.py)
# =============================================================================
# Le scanner et l'enregistrement sont remplacés par des faux : aucun réseau.
# =============================================================================

import asyncio
import logging
import threading
import time
import warnings

import pytest

from domainrecon.api.jobs import JOB_MAX_AGE, JobManager, ScanJob, TooManyScans, format_sse
from domainrecon.api.storage import ScanSaveError
from domainrecon.i18n import msg
from domainrecon.scanner import MODULE_NAMES
from domainrecon.scanner.errors import TargetNotAllowedError
from rendu import en

# Comportement des 18 modules historiques : registre ramené à eux (tests/conftest.py).
pytestmark = pytest.mark.usefixtures("registre_historique")


async def _evenements(manager: JobManager, job_id: str) -> list[dict]:
    return [event async for event in manager.subscribe(job_id)]


# Les faux scanners ont la forme de perform_full_scan : le gestionnaire leur transmet
# aussi le plan du scan (profile, authorized_target, selected, available_keys).
async def _scan_rapide(domain, on_module, **plan):
    on_module("dns_records", "ok", 0.5)
    on_module("screenshot", "skipped", 0.0)
    return {"domain": domain}


async def _scan_bloque(domain, on_module, **plan):
    on_module("dns_records", "ok", 0.1)
    await asyncio.Event().wait()  # jusqu'à l'annulation


def _enregistrer(result):
    return 42


def test_scan_termine_evenements_dans_l_ordre():
    enregistres = []

    def enregistrer(result):
        enregistres.append(result)
        return 42

    async def scenario():
        manager = JobManager(2, runner=_scan_rapide, saver=enregistrer)
        job = manager.start("Example.COM")
        assert isinstance(job, ScanJob) and job.status == "running" and len(job.id) == 32
        return job, await _evenements(manager, job.id)

    job, evenements = asyncio.run(scenario())
    assert (job.domain, job.status, job.scan_id, job.done, job.total) == ("example.com", "done", 42, 2, 16)
    assert job.finished_at is not None
    assert [e["event"] for e in evenements] == ["module", "progress", "module", "progress", "done"]
    assert evenements[0]["data"] == {"name": "dns_records", "family": "dns", "status": "ok", "duration": 0.5}
    assert evenements[1]["data"] == {"done": 1, "total": 16}
    assert evenements[2]["data"] == {
        "name": "screenshot",
        "family": "identity",
        "status": "skipped",
        "duration": 0.0,
    }
    assert evenements[-1] == {"event": "done", "data": {"scan_id": 42}}
    # Le gestionnaire ajoute au résultat le profil et les modules lancés (ici, ceux du plan par défaut).
    modules_complet = [name for name in MODULE_NAMES if name not in ("open_ports", "subdomain_takeover")]
    assert enregistres == [
        {"profile": "complet", "modules_launched": modules_complet, "domain": "example.com"}
    ]


def test_evenements_rejoues_et_abonnes_multiples():
    async def scenario():
        manager = JobManager(2, runner=_scan_rapide, saver=_enregistrer)
        job = manager.start("example.com")
        premier, second = await asyncio.gather(_evenements(manager, job.id), _evenements(manager, job.id))
        rejoue = await _evenements(manager, job.id)  # après la fin
        return premier, second, rejoue

    premier, second, rejoue = asyncio.run(scenario())
    assert premier == second == rejoue
    assert premier[-1]["event"] == "done"


def test_abonne_deconnecte_n_affecte_pas_les_autres():
    async def scenario():
        manager = JobManager(1, runner=_scan_bloque, saver=_enregistrer)
        job = manager.start("example.com")
        abandonne = asyncio.ensure_future(_evenements(manager, job.id))
        fidele = asyncio.ensure_future(_evenements(manager, job.id))
        await asyncio.sleep(0.05)
        abandonne.cancel()
        await asyncio.sleep(0.01)
        assert manager.cancel(job.id) is True
        return await asyncio.wait_for(fidele, timeout=5)

    evenements = asyncio.run(scenario())
    assert [e["event"] for e in evenements] == ["module", "progress", "cancelled"]


def test_echecs_cible_interne_enregistrement():
    async def refuse(domain, on_module, **plan):
        raise TargetNotAllowedError(msg("target.ip_not_allowed"))

    async def plante(domain, on_module, **plan):
        raise RuntimeError("détail interne")

    def enregistrement_impossible(result):
        raise ScanSaveError("x")

    async def scenario(runner, saver=_enregistrer):
        manager = JobManager(1, runner=runner, saver=saver)
        job = manager.start("example.com")
        return job, await _evenements(manager, job.id)

    job, evenements = asyncio.run(scenario(refuse))
    assert job.status == "failed"
    ((nom, donnees),) = [(e["event"], e["data"]) for e in evenements]
    assert nom == "failed"
    assert (donnees["code"], donnees["params"]) == ("target.ip_not_allowed", {})
    assert en(donnees["detail"]).startswith("Address not allowed")

    _, evenements = asyncio.run(scenario(plante))
    assert evenements[-1]["data"]["code"] == "api.scan_failed"
    assert "détail interne" not in str(evenements)

    _, evenements = asyncio.run(scenario(_scan_rapide, enregistrement_impossible))
    assert evenements[-1]["data"]["code"] == "api.save_failed"


def test_annulation_libere_l_emplacement():
    async def scenario():
        manager = JobManager(1, runner=_scan_bloque, saver=_enregistrer)
        job = manager.start("example.com")
        with pytest.raises(TooManyScans):
            manager.start("example.org")
        await asyncio.sleep(0.01)
        assert manager.cancel(job.id) is True
        await manager.wait(job.id, timeout=5)
        assert job.status == "cancelled" and job.finished_at is not None
        assert manager.cancel(job.id) is False  # déjà terminée
        evenements = await _evenements(manager, job.id)
        suivant = manager.start("example.org")  # emplacement libéré
        manager.cancel(suivant.id)
        await manager.wait(suivant.id, timeout=5)
        return evenements

    evenements = asyncio.run(scenario())
    assert [e["event"] for e in evenements] == ["module", "progress", "cancelled"]


def test_annulation_avant_le_demarrage_de_la_tache():
    async def scenario():
        manager = JobManager(1, runner=_scan_bloque, saver=_enregistrer)
        job = manager.start("example.com")
        assert manager.cancel(job.id) is True  # avant le premier pas de la tâche
        await manager.wait(job.id, timeout=5)
        evenements = await _evenements(manager, job.id)
        second = manager.start("example.org")  # l'emplacement a bien été libéré
        manager.cancel(second.id)
        await manager.wait(second.id, timeout=5)
        return job, evenements

    job, evenements = asyncio.run(scenario())
    assert job.status == "cancelled"
    assert [e["event"] for e in evenements] == ["cancelled"]


def test_cible_invalide_ou_refusee_avant_la_tache(monkeypatch):
    monkeypatch.setenv("ALLOW_PRIVATE_TARGETS", "0")

    async def scenario():
        manager = JobManager(1, runner=_scan_rapide, saver=_enregistrer)
        with pytest.raises(ValueError) as invalide:
            manager.start("pas une cible")
        with pytest.raises(TargetNotAllowedError):
            manager.start("10.0.0.1")
        assert manager.slots.acquire(blocking=False)  # aucun emplacement consommé
        manager.slots.release()
        return invalide.value

    erreur = asyncio.run(scenario())
    assert en(erreur.message) == "Invalid target: 'pas une cible'"


def test_purge_des_taches_terminees():
    async def scenario():
        manager = JobManager(2, runner=_scan_rapide, saver=_enregistrer)
        job = manager.start("example.com")
        await manager.wait(job.id, timeout=5)
        assert manager.purge_finished() == 0
        job.finished_at = time.monotonic() - JOB_MAX_AGE - 1
        assert manager.purge_finished() == 1
        return manager.get(job.id)

    assert asyncio.run(scenario()) is None


def test_scan_en_cours_lu_par_le_lanceur():
    """busy() : vrai tant qu'une tâche tourne (chien de garde du mode navigateur), lisible d'un autre thread."""

    async def scenario():
        manager = JobManager(1, runner=_scan_bloque, saver=_enregistrer)
        assert manager.busy() is False
        job = manager.start("example.com")
        await asyncio.sleep(0.01)
        pendant = await asyncio.to_thread(manager.busy)
        manager.cancel(job.id)
        await manager.wait(job.id, timeout=5)
        return pendant, manager.busy()

    assert asyncio.run(scenario()) == (True, False)


def test_emplacement_reserve_compte_comme_scan_en_cours():
    """Revue : le scan synchrone (POST /api/scan) et la résolution qui précède une tâche, ignorés par busy()."""
    manager = JobManager(2)
    manager.reserve_slot()
    assert manager.busy() is True
    manager.reserve_slot()
    with pytest.raises(TooManyScans):
        manager.reserve_slot()  # refus : le compte ne bouge pas
    manager.release_slot()
    assert manager.busy() is True
    manager.release_slot()
    assert manager.busy() is False


def test_tache_inconnue():
    manager = JobManager(1)
    assert manager.get("0" * 32) is None
    assert manager.cancel("0" * 32) is False


def test_format_sse():
    assert format_sse({"event": "progress", "data": {"done": 1, "total": 18}}) == (
        'event: progress\ndata: {"done":1,"total":18}\n\n'
    )
    assert format_sse({"event": "failed", "data": {"detail": "délai dépassé"}}) == (
        'event: failed\ndata: {"detail":"délai dépassé"}\n\n'
    )


# --- Arrêt, emplacements réservés, clôture (revue finale) ----------------------------


def test_cancel_all_annule_les_taches_en_cours():
    """Arrêt du serveur : toutes les tâches en cours sont closes, emplacements rendus."""

    async def scenario():
        manager = JobManager(2, runner=_scan_bloque, saver=_enregistrer)
        premier, second = manager.start("example.com"), manager.start("example.org")
        fini = JobManager(1, runner=_scan_rapide, saver=_enregistrer)
        termine = fini.start("example.net")
        await fini.wait(termine.id, timeout=5)
        await asyncio.sleep(0.01)
        assert await manager.cancel_all(timeout=5) == 2
        assert await fini.cancel_all(timeout=5) == 0  # rien à annuler
        assert (premier.status, second.status, termine.status) == ("cancelled", "cancelled", "done")
        assert premier.finished_at is not None
        # Les deux emplacements sont libres.
        assert manager.slots.acquire(blocking=False) and manager.slots.acquire(blocking=False)
        assert [e["event"] for e in await _evenements(manager, premier.id)] == [
            "module",
            "progress",
            "cancelled",
        ]

    asyncio.run(scenario())


def test_cancel_all_sans_tache():
    assert asyncio.run(JobManager(1).cancel_all()) == 0


def test_reservation_d_un_emplacement():
    async def scenario():
        manager = JobManager(1, runner=_scan_bloque, saver=_enregistrer)
        manager.reserve_slot()
        with pytest.raises(TooManyScans):
            manager.reserve_slot()
        with pytest.raises(TooManyScans):
            manager.start("example.com")  # emplacement pris par la réservation
        manager.release_slot()
        job = manager.start("example.com")
        manager.cancel(job.id)
        await manager.wait(job.id, timeout=5)

    asyncio.run(scenario())


def test_start_reserve_rend_l_emplacement_s_il_echoue(monkeypatch):
    """start(reserved=True) devient responsable de l'emplacement : cible refusée ou tâche impossible."""
    monkeypatch.setenv("ALLOW_PRIVATE_TARGETS", "0")

    async def scenario():
        manager = JobManager(1, runner=_scan_rapide, saver=_enregistrer)
        for cible, erreur in (("pas une cible", ValueError), ("10.0.0.1", TargetNotAllowedError)):
            manager.reserve_slot()
            with pytest.raises(erreur):
                manager.start(cible, reserved=True)
            manager.reserve_slot()  # rendu par start() : la réservation suivante réussit
            manager.release_slot()
        manager.reserve_slot()
        job = manager.start("example.com", reserved=True)
        await manager.wait(job.id, timeout=5)
        assert job.status == "done"
        manager.reserve_slot()  # la tâche terminée a rendu son emplacement
        manager.release_slot()

    asyncio.run(scenario())


def test_creation_de_tache_impossible_rend_l_emplacement(monkeypatch):
    """create_task qui lève après l'acquisition : pas d'emplacement perdu, pas de tâche fantôme."""

    async def scenario():
        manager = JobManager(1, runner=_scan_rapide, saver=_enregistrer)
        vraie = asyncio.get_running_loop()

        class BoucleSansTache:
            def create_future(self):
                return vraie.create_future()

            def create_task(self, coroutine):
                raise RuntimeError("boucle fermée")

        with monkeypatch.context() as m, warnings.catch_warnings():
            warnings.simplefilter("error")  # « coroutine never awaited » ferait échouer le test
            m.setattr(asyncio, "get_running_loop", lambda: BoucleSansTache())
            with pytest.raises(RuntimeError, match="boucle fermée"):
                manager.start("example.com")
        assert manager._jobs == {}
        assert manager.slots.acquire(blocking=False)  # l'emplacement a bien été rendu

    asyncio.run(scenario())


async def _scan_plante(domain, on_module, **plan):
    raise RuntimeError("panne du scan")


def test_exception_inattendue_de_la_tache_n_est_pas_une_annulation(caplog):
    """Une exception échappée de _run (bogue) : tâche en échec et journalisée, jamais « cancelled »."""

    async def scenario():
        manager = JobManager(1, runner=_scan_plante, saver=_enregistrer)
        vraie_fail = manager._fail
        appels = []

        def fail_une_fois(job, message):
            appels.append(message)
            if len(appels) == 1:
                raise RuntimeError("bogue dans la clôture")
            vraie_fail(job, message)

        manager._fail = fail_une_fois
        job = manager.start("example.com")
        await manager.wait(job.id, timeout=5)
        await asyncio.sleep(0)  # laisse passer le rappel de fin de tâche
        evenements = await _evenements(manager, job.id)
        assert manager.slots.acquire(blocking=False)  # emplacement rendu
        return job, evenements

    with caplog.at_level(logging.ERROR, logger="domainrecon.api.jobs"):
        job, evenements = asyncio.run(scenario())
    assert job.status == "failed"
    assert [e["event"] for e in evenements] == ["failed"]
    assert evenements[0]["data"]["code"] == "api.scan_failed"
    assert "terminée sur une exception" in caplog.text
    assert "bogue dans la clôture" in caplog.text  # l'exception est journalisée avec sa trace


def test_emplacement_rendu_meme_si_la_cloture_echoue():
    """_task_done : release() dans un finally, même quand la clôture de la tâche lève."""

    async def scenario():
        manager = JobManager(1, runner=_scan_bloque, saver=_enregistrer)

        def finish_en_panne(*args, **kwargs):
            raise RuntimeError("clôture impossible")

        manager._finish = finish_en_panne
        job = manager.start("example.com")
        assert manager.cancel(job.id) is True  # avant le premier pas : _run ne clôt rien, _task_done oui
        await manager.wait(job.id, timeout=5)
        await asyncio.sleep(0.01)
        assert manager.slots.acquire(blocking=False)

    erreurs_de_boucle = []
    loop = asyncio.new_event_loop()
    loop.set_exception_handler(lambda _loop, context: erreurs_de_boucle.append(context))
    try:
        loop.run_until_complete(scenario())
    finally:
        loop.close()
    assert erreurs_de_boucle  # l'erreur du rappel est signalée par la boucle, pas perdue


def test_erreur_d_enregistrement_apres_annulation_journalisee(caplog):
    """Le thread d'enregistrement échoue après l'annulation : plus personne n'attend, l'erreur est journalisée."""
    liberer = threading.Event()

    def enregistrer(result):
        liberer.wait(5)
        raise ScanSaveError("disque plein")

    async def scenario():
        manager = JobManager(1, runner=_scan_rapide, saver=enregistrer)
        job = manager.start("example.com")
        await asyncio.sleep(0.1)  # scan terminé, enregistrement en attente dans son thread
        assert manager.cancel(job.id) is True
        await manager.wait(job.id, timeout=5)
        assert job.status == "cancelled"
        liberer.set()
        for _ in range(250):
            if "échoué après la fin de la tâche" in caplog.text:
                break
            await asyncio.sleep(0.02)

    with caplog.at_level(logging.ERROR, logger="domainrecon.api.jobs"):
        asyncio.run(scenario())
    assert "Enregistrement du scan de example.com" in caplog.text
    assert "ScanSaveError" in caplog.text


def test_echec_d_enregistrement_en_cours_de_tache_non_journalise_apres_coup(caplog):
    """Tâche encore en cours : l'échec est traité par _run (événement « failed »), pas par le journal d'après-coup."""

    def enregistrement_impossible(result):
        raise ScanSaveError("x")

    async def scenario():
        manager = JobManager(1, runner=_scan_rapide, saver=enregistrement_impossible)
        job = manager.start("example.com")
        return await _evenements(manager, job.id)

    with caplog.at_level(logging.ERROR, logger="domainrecon.api.jobs"):
        evenements = asyncio.run(scenario())
    assert evenements[-1]["data"]["code"] == "api.save_failed"
    assert "après la fin de la tâche" not in caplog.text
