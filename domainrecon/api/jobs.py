# =============================================================================
# DomainRecon - API : tâches de scan en mémoire et leurs événements
# =============================================================================
# Un scan lancé par POST /api/scans devient une tâche asyncio. Son plan (ScanPlan :
# profil, modules à lancer) est arrêté avant sa création, par plan_scan. Chaque
# module terminé produit deux événements (module, progress : le total de la
# progression est le nombre de modules du plan), puis un événement final (done,
# failed ou cancelled). Les événements sont conservés pour être rejoués à chaque
# abonné (reconnexion possible). Les tâches vivent en mémoire (perdues au
# redémarrage : acceptable pour une application de bureau) et sont purgées
# JOB_MAX_AGE secondes après leur fin. Un seul sémaphore (`slots`) borne les
# scans simultanés, synchrones (POST /api/scan) comme en tâche (POST /api/scans).
# =============================================================================

import asyncio
import functools
import json
import logging
import threading
import time
import uuid
from collections.abc import AsyncIterator, Awaitable, Callable, Iterable
from dataclasses import dataclass, field

from ..core import config
from ..i18n import is_msg, msg
from ..scanner import (
    is_ip_literal,
    is_public_address,
    is_valid_target,
    normalize_target,
    perform_full_scan,
    registry,
)
from ..scanner.errors import TargetNotAllowedError, message_exception, message_of
from ..scanner.registry import PROFILE_CUSTOM, PROFILE_FULL
from . import storage

logger = logging.getLogger(__name__)

# Âge maximal d'une tâche terminée avant sa purge, en secondes.
JOB_MAX_AGE = 600.0

# Même forme que perform_full_scan : (domaine, on_module=…, profile=…,
# authorized_target=…, selected=…, available_keys=…) -> résultat.
Runner = Callable[..., Awaitable[dict]]


class TooManyScans(Exception):
    """Aucun emplacement de scan libre (MAX_CONCURRENT_SCANS atteint)."""


@dataclass(frozen=True)
class ScanPlan:
    """Ce qu'un scan lance, arrêté avant la création de la tâche (voir plan_scan).

    `profile`, `selected` (profil « personnalise » seulement), `authorized_target`
    et `available_keys` (noms des clés API renseignées, jamais leurs valeurs) sont
    transmis tels quels au scanner ; `modules` donne les noms des modules qu'il
    lancera, dans l'ordre d'exécution (registry.get_modules).
    """

    profile: str
    selected: tuple[str, ...]
    authorized_target: bool
    available_keys: frozenset[str]
    modules: tuple[str, ...]


def _modules_needing_authorization(profile: str, selected: tuple[str, ...]) -> list[str]:
    """Modules actifs ou sensibles du plan (dépendances comprises), pour une cible dont le test est autorisé.

    Calculé comme si toutes les clés API étaient renseignées : ce que le profil
    réserve aux cibles autorisées, que la clé du module soit là ou non.
    """
    every_key = {name for spec in registry.MODULES.values() for name in spec.required_keys}
    chosen = registry.get_modules(profile, every_key, True, selected)
    return [spec.name for spec in chosen if spec.requires_authorization]


def plan_scan(
    profile: str = PROFILE_FULL,
    selected: Iterable[str] | None = None,
    authorized_target: bool = False,
    available_keys: Iterable[str] = (),
) -> ScanPlan:
    """Plan d'un scan : les modules que le profil, la sélection, l'autorisation et les clés API permettent de lancer.

    `selected` ne compte que pour le profil « personnalise » ; ses noms inconnus
    du registre sont ignorés. Lève ValueError, porteuse d'un message traduisible
    (scanner.errors.message_of), quand :
    - un module actif ou sensible est choisi (ou requis par un module choisi)
      sans `authorized_target` : api.authorization_required. C'est ici que
      l'autorisation est exigée, côté serveur, et non seulement par l'interface ;
    - aucun module ne peut être lancé : api.no_modules (sélection vide ou sans
      module valide, modules à clé API dont la clé manque).
    Un profil inconnu lève aussi ValueError (registry.get_modules).
    """
    keys = frozenset(available_keys or ())
    authorized = bool(authorized_target)
    if profile == PROFILE_CUSTOM:
        chosen = tuple(dict.fromkeys(name for name in selected or () if name in registry.MODULES))
    else:
        chosen = ()
    if not authorized and (needing := _modules_needing_authorization(profile, chosen)):
        raise message_exception(ValueError, msg("api.authorization_required", modules=needing, sep=", "))
    specs = registry.get_modules(profile, keys, authorized, chosen)
    if not specs:
        raise message_exception(ValueError, msg("api.no_modules"))
    return ScanPlan(profile, chosen, authorized, keys, tuple(spec.name for spec in specs))


@dataclass(eq=False)
class ScanJob:
    """Tâche de scan : plan, état, compteurs et événements déjà émis."""

    id: str
    domain: str
    plan: ScanPlan
    status: str = "running"  # running | done | failed | cancelled
    events: list[dict] = field(default_factory=list)
    scan_id: int | None = None
    done: int = 0
    # Nombre de modules du plan : la progression annonce « done sur total ».
    total: int = 0
    finished_at: float | None = None  # horloge monotone (time.monotonic)
    _task: asyncio.Task | None = field(default=None, repr=False)
    _waiter: asyncio.Future | None = field(default=None, repr=False)


def format_sse(event: dict) -> str:
    """Bloc Server-Sent Events d'un événement (données en JSON compact, UTF-8)."""
    data = json.dumps(event["data"], ensure_ascii=False, separators=(",", ":"))
    return f"event: {event['event']}\ndata: {data}\n\n"


class JobManager:
    """Tâches de scan du processus : lancement, suivi, annulation, purge."""

    def __init__(
        self,
        max_concurrent: int,
        *,
        runner: Runner | None = None,
        saver: Callable[[dict], int] | None = None,
    ) -> None:
        self.max_concurrent = max_concurrent
        self.slots = threading.BoundedSemaphore(max_concurrent)
        # Remplaçables (tests, serveur E2E) ; None : scanner et base réels.
        self.runner = runner
        self.saver = saver
        self._jobs: dict[str, ScanJob] = {}
        # Emplacements pris par reserve_slot() et pas encore rendus : scans
        # synchrones, tâches, et résolution qui précède une tâche (busy()).
        self._held = 0
        self._held_lock = threading.Lock()

    def get(self, job_id: str) -> ScanJob | None:
        self.purge_finished()
        return self._jobs.get(job_id)

    def busy(self) -> bool:
        """Vrai si un scan est en cours : emplacement pris (POST /api/scan compris) ou tâche active.

        Lu depuis un autre thread (chien de garde du mode navigateur,
        desktop/launcher.py) : copie des tâches d'abord ; un dictionnaire
        modifié pendant la copie compte comme « en cours » (prudence).
        """
        if self._held > 0:
            return True
        try:
            jobs = list(self._jobs.values())
        except RuntimeError:
            return True
        return any(job.status == "running" for job in jobs)

    def reserve_slot(self) -> None:
        """Réserve un emplacement de scan ; TooManyScans s'il n'y en a plus.

        Pour un scan synchrone (rendu par release_slot() après l'enregistrement),
        ou pour contrôler la disponibilité avant un travail coûteux (résolution
        DNS) : l'emplacement se passe ensuite à start(reserved=True), ou se
        rend par release_slot() si le travail échoue.
        """
        self.purge_finished()
        if not self.slots.acquire(blocking=False):
            raise TooManyScans()
        with self._held_lock:
            self._held += 1

    def release_slot(self) -> None:
        """Rend un emplacement réservé par reserve_slot() et non confié à start()."""
        with self._held_lock:
            self._held -= 1
        self.slots.release()

    def start(self, domain: str, *, reserved: bool = False, plan: ScanPlan | None = None) -> ScanJob:
        """Crée et lance la tâche (dans la boucle d'événements en cours).

        Lève ValueError (cible invalide) ou TargetNotAllowedError (IP non
        publique) avant toute création, TooManyScans sans emplacement libre.
        `plan` : les modules à lancer (voir plan_scan) ; à défaut, ceux du profil
        « complet » (sans clé API ni autorisation). `reserved` : l'appelant a
        déjà pris un emplacement (reserve_slot) ; start() en devient responsable
        et le rend s'il échoue.
        """
        try:
            target = normalize_target(domain)
            if not is_valid_target(target):
                raise message_exception(ValueError, msg("target.invalid", target=repr(domain)))
            if (
                is_ip_literal(target)
                and not config.private_targets_allowed()
                and not is_public_address(target)
            ):
                raise TargetNotAllowedError(msg("target.ip_not_allowed"))
            if plan is None:
                plan = plan_scan()
            loop = asyncio.get_running_loop()
            if not reserved:
                self.reserve_slot()
                reserved = True
            job = ScanJob(id=uuid.uuid4().hex, domain=target, plan=plan, total=len(plan.modules))
            job._waiter = loop.create_future()
            coroutine = self._run(job)
            try:
                job._task = loop.create_task(coroutine)
            except BaseException:
                coroutine.close()  # jamais attendue : évite l'avertissement « never awaited »
                raise
        except BaseException:
            # Seul un emplacement détenu est rendu : TooManyScans n'en a pris aucun.
            if reserved:
                self.release_slot()
            raise
        self._jobs[job.id] = job
        # Fin de la tâche, quelle qu'elle soit (même annulée avant d'avoir démarré).
        job._task.add_done_callback(functools.partial(self._task_done, job))
        return job

    def cancel(self, job_id: str) -> bool:
        """Demande l'annulation d'une tâche en cours ; False si inconnue ou terminée."""
        job = self._jobs.get(job_id)
        if job is None or job.status != "running" or job._task is None:
            return False
        return job._task.cancel()

    async def wait(self, job_id: str, timeout: float) -> None:
        """Attend (au plus `timeout` secondes) la fin de la tâche."""
        job = self._jobs.get(job_id)
        if job is not None and job._task is not None and not job._task.done():
            await asyncio.wait({job._task}, timeout=timeout)

    async def cancel_all(self, timeout: float = 5.0) -> int:
        """Annule toutes les tâches en cours et attend (au plus `timeout` s) leur clôture.

        Appelé à l'arrêt du serveur ; renvoie le nombre de tâches annulées.
        Un module qui tourne dans un thread (WHOIS, DNS…) ne s'interrompt pas :
        la tâche est close, le thread finit seul.
        """
        tasks = {
            job._task
            for job in self._jobs.values()
            if job.status == "running" and job._task is not None and not job._task.done()
        }
        for task in tasks:
            task.cancel()
        if tasks:
            await asyncio.wait(tasks, timeout=timeout)
        return len(tasks)

    async def subscribe(self, job_id: str) -> AsyncIterator[dict]:
        """Événements de la tâche : ceux déjà émis, puis les suivants jusqu'au dernier."""
        job = self._jobs.get(job_id)
        if job is None:
            return
        index = 0
        while True:
            while index < len(job.events):
                index += 1
                yield job.events[index - 1]
            if job.status != "running" or job._waiter is None:
                return
            # shield : un abonné qui se déconnecte n'annule pas l'attente des autres.
            await asyncio.shield(job._waiter)

    def purge_finished(self, max_age: float = JOB_MAX_AGE) -> int:
        """Oublie les tâches terminées depuis plus de `max_age` secondes ; renvoie leur nombre."""
        now = time.monotonic()
        expired = [
            job_id
            for job_id, job in self._jobs.items()
            if job.finished_at is not None and now - job.finished_at > max_age
        ]
        for job_id in expired:
            del self._jobs[job_id]
        return len(expired)

    # --- Déroulement d'une tâche (toujours dans la boucle d'événements) ------

    def _emit(self, job: ScanJob, event: str, data: dict) -> None:
        job.events.append({"event": event, "data": data})
        waiter, job._waiter = job._waiter, asyncio.get_running_loop().create_future()
        if waiter is not None and not waiter.done():
            waiter.set_result(None)

    def _on_module(self, job: ScanJob, name: str, status: str, duration: float) -> None:
        if job.status != "running":
            return
        job.done += 1
        module = {
            "name": name,
            "family": spec.family if (spec := registry.MODULES.get(name)) is not None else None,
            "status": status,
            "duration": round(float(duration), 3),
        }
        self._emit(job, "module", module)
        self._emit(job, "progress", {"done": job.done, "total": job.total})

    def _finish(self, job: ScanJob, status: str, event: str, data: dict) -> None:
        job.status = status
        job.finished_at = time.monotonic()
        self._emit(job, event, data)

    def _fail(self, job: ScanJob, message: object) -> None:
        code = message["$t"] if is_msg(message) else None
        params = message["p"] if is_msg(message) else {}
        self._finish(job, "failed", "failed", {"code": code, "params": params, "detail": message})

    async def _run(self, job: ScanJob) -> None:
        # Lus à l'exécution : un faux posé après la création du gestionnaire compte.
        runner = self.runner or perform_full_scan
        saver = self.saver or storage.save_scan
        plan = job.plan
        try:
            result = await runner(
                job.domain,
                on_module=functools.partial(self._on_module, job),
                profile=plan.profile,
                authorized_target=plan.authorized_target,
                selected=plan.selected,
                available_keys=plan.available_keys,
            )
            # Profil et modules lancés sont enregistrés avec le scan (ceux du résultat priment, s'il en porte).
            result = {"profile": plan.profile, "modules_launched": list(plan.modules), **result}
            scan_id = await asyncio.to_thread(self._save, job, saver, result)
        except asyncio.CancelledError:
            self._finish(job, "cancelled", "cancelled", {})
        except storage.ScanSaveError:
            self._fail(job, msg("api.save_failed"))
        except ValueError as e:
            # Cible refusée en cours de scan (TargetNotAllowedError) ou invalide.
            self._fail(job, message_of(e) or str(e))
        except Exception:
            logger.exception("Scan de %s (tâche %s) échoué", job.domain, job.id)
            self._fail(job, msg("api.scan_failed"))
        else:
            job.scan_id = scan_id
            self._finish(job, "done", "done", {"scan_id": scan_id})

    def _save(self, job: ScanJob, saver: Callable[[dict], int], result: dict) -> int:
        """Enregistre le résultat (dans un thread) ; journalise l'échec que plus personne n'attend.

        Une tâche annulée pendant l'enregistrement laisse le thread aller au
        bout : son erreur éventuelle n'arriverait nulle part.
        """
        try:
            return saver(result)
        except Exception:
            if job.status != "running":
                logger.exception(
                    "Enregistrement du scan de %s (tâche %s) échoué après la fin de la tâche",
                    job.domain,
                    job.id,
                )
            raise

    def _task_done(self, job: ScanJob, task: asyncio.Task) -> None:
        """Rappel de fin de la tâche asyncio : clôt une tâche que _run n'a pas pu clore, puis libère l'emplacement."""
        try:
            if job.status == "running":
                if task.cancelled():
                    # Annulée avant d'avoir démarré : _run n'a jamais tourné.
                    self._finish(job, "cancelled", "cancelled", {})
                else:
                    # _run a levé une exception qu'il n'a pas gérée (bogue) : jamais « annulée ».
                    logger.error(
                        "Tâche %s (scan de %s) terminée sur une exception",
                        job.id,
                        job.domain,
                        exc_info=task.exception(),
                    )
                    self._fail(job, msg("api.scan_failed"))
        finally:
            self.release_slot()
