# =============================================================================
# DomainRecon - Surveillance : scans en lot
# =============================================================================
# Un lot = une liste de domaines scannés avec le même plan (profil, autorisation).
# Les domaines attendent dans une file ; au plus `concurrency` scans du lot
# tournent en même temps, et chacun prend un emplacement du gestionnaire de
# tâches existant (api/jobs.py, MAX_CONCURRENT_SCANS) : un lot ne prive donc pas
# l'interface de scans. Les lots vivent en mémoire (comme les tâches) et sont
# oubliés une heure après leur fin.
# =============================================================================

import asyncio
import logging
import re
import time
import uuid
from collections import deque
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from datetime import datetime

from ..api.jobs import JobManager, ScanPlan, TooManyScans
from ..core.models import utcnow
from ..i18n import msg
from ..scanner import is_valid_target, normalize_target
from ..scanner.errors import message_of

logger = logging.getLogger(__name__)

# Plafond de domaines d'un lot, et de lots conservés en mémoire.
MAX_BATCH_DOMAINS = 100
MAX_KEPT_BATCHES = 50
BATCH_MAX_AGE = 3600.0
# Scans simultanés d'un lot (borné aussi par les emplacements du gestionnaire).
DEFAULT_BATCH_CONCURRENCY = 2
# Attente avant de réessayer de prendre un emplacement, en secondes.
SLOT_RETRY_DELAY = 1.0

_SPLIT_RE = re.compile(r"[\s,;]+")

Precheck = Callable[[str], Awaitable[str]]


def clean_domains(raw: list[str]) -> tuple[list[str], list[dict], int]:
    """(domaines normalisés sans doublon, entrées refusées, nombre de doublons).

    Chaque entrée peut regrouper plusieurs domaines séparés par des espaces, des
    virgules, des points-virgules ou des sauts de ligne (liste collée).
    """
    accepted: list[str] = []
    rejected: list[dict] = []
    seen: set[str] = set()
    duplicates = 0
    for entry in raw:
        for token in _SPLIT_RE.split(entry.strip()):
            if not token:
                continue
            target = normalize_target(token)
            if not is_valid_target(target):
                rejected.append(
                    {"input": token[:255], "reason": msg("target.invalid", target=repr(token[:255]))}
                )
            elif target in seen:
                duplicates += 1
            else:
                seen.add(target)
                accepted.append(target)
    return accepted, rejected, duplicates


@dataclass
class BatchItem:
    domain: str
    status: str = "queued"  # queued | running | done | failed | cancelled
    job_id: str | None = None
    scan_id: int | None = None
    error: object = None


@dataclass(eq=False)
class Batch:
    id: str
    plan: ScanPlan
    items: list[BatchItem]
    created_at: datetime = field(default_factory=utcnow)
    cancelled: bool = False
    concurrency: int = DEFAULT_BATCH_CONCURRENCY
    finished_at: float | None = None  # horloge monotone
    _tasks: list[asyncio.Task] = field(default_factory=list, repr=False)
    _watcher: asyncio.Task | None = field(default=None, repr=False)

    @property
    def status(self) -> str:
        if self.finished_at is None:
            return "running"
        return "cancelled" if self.cancelled else "done"

    def counts(self) -> dict[str, int]:
        counts = dict.fromkeys(("queued", "running", "done", "failed", "cancelled"), 0)
        for item in self.items:
            counts[item.status] += 1
        return counts


class BatchManager:
    """Lots du processus : création, suivi, annulation, purge."""

    def __init__(self) -> None:
        self._batches: dict[str, Batch] = {}

    def get(self, batch_id: str) -> Batch | None:
        self.purge()
        return self._batches.get(batch_id)

    def all(self) -> list[Batch]:
        self.purge()
        return sorted(self._batches.values(), key=lambda b: b.created_at, reverse=True)

    def purge(self) -> None:
        """Oublie les lots terminés depuis plus d'une heure, puis les plus anciens au-delà du plafond."""
        now = time.monotonic()
        for batch_id in [
            b.id
            for b in self._batches.values()
            if b.finished_at is not None and now - b.finished_at > BATCH_MAX_AGE
        ]:
            del self._batches[batch_id]
        finished = sorted(
            (b for b in self._batches.values() if b.finished_at is not None), key=lambda b: b.finished_at
        )
        while len(self._batches) > MAX_KEPT_BATCHES and finished:
            del self._batches[finished.pop(0).id]

    def busy(self) -> bool:
        return any(b.finished_at is None for b in self._batches.values())

    def start(
        self,
        manager: JobManager,
        domains: list[str],
        plan: ScanPlan,
        precheck: Precheck,
        *,
        concurrency: int = DEFAULT_BATCH_CONCURRENCY,
    ) -> Batch:
        """Crée le lot et lance ses travailleurs (dans la boucle d'événements en cours)."""
        self.purge()
        batch = Batch(
            id=uuid.uuid4().hex,
            plan=plan,
            items=[BatchItem(domain) for domain in domains],
            concurrency=max(1, min(concurrency, manager.max_concurrent)),
        )
        self._batches[batch.id] = batch
        queue = deque(batch.items)
        loop = asyncio.get_running_loop()
        batch._tasks = [
            loop.create_task(self._worker(batch, queue, manager, precheck), name=f"batch-{batch.id[:8]}")
            for _ in range(min(batch.concurrency, len(batch.items)))
        ]
        batch._watcher = loop.create_task(self._watch(batch))
        return batch

    def cancel(self, batch_id: str, manager: JobManager) -> bool:
        """Annule un lot en cours : les domaines en attente sont abandonnés, les scans en cours annulés."""
        batch = self._batches.get(batch_id)
        if batch is None or batch.finished_at is not None:
            return False
        batch.cancelled = True
        for item in batch.items:
            if item.status == "queued":
                item.status = "cancelled"
            elif item.status == "running" and item.job_id is not None:
                manager.cancel(item.job_id)
        return True

    async def cancel_all(self, timeout: float = 5.0) -> int:
        """Arrêt de l'application : abandonne les lots en cours (les tâches de scan sont annulées par le gestionnaire)."""
        tasks = []
        for batch in self._batches.values():
            if batch.finished_at is None:
                batch.cancelled = True
                tasks.extend(t for t in batch._tasks if not t.done())
        for task in tasks:
            task.cancel()
        if tasks:
            await asyncio.wait(tasks, timeout=timeout)
        return len(tasks)

    # --- Déroulement -----------------------------------------------------------

    async def _watch(self, batch: Batch) -> None:
        """Marque le lot terminé quand tous ses travailleurs ont fini."""
        await asyncio.gather(*batch._tasks, return_exceptions=True)
        for item in batch.items:
            if item.status in ("queued", "running"):
                item.status = "cancelled"
        batch.finished_at = time.monotonic()

    async def _worker(self, batch: Batch, queue: deque, manager: JobManager, precheck: Precheck) -> None:
        while not batch.cancelled:
            try:
                item = queue.popleft()
            except IndexError:
                return
            if item.status != "queued":
                continue
            await self._run_item(batch, item, manager, precheck)

    async def _run_item(self, batch: Batch, item: BatchItem, manager: JobManager, precheck: Precheck) -> None:
        item.status = "running"
        try:
            while True:
                if batch.cancelled:
                    item.status = "cancelled"
                    return
                try:
                    manager.reserve_slot()
                    break
                except TooManyScans:
                    await asyncio.sleep(SLOT_RETRY_DELAY)
            try:
                target = await precheck(item.domain)
            except BaseException:
                manager.release_slot()
                raise
            job = manager.start(target, reserved=True, plan=batch.plan)
            item.job_id = job.id
            while job.status == "running":
                await manager.wait(job.id, timeout=1.0)
            item.scan_id = job.scan_id
            item.status = job.status if job.status in ("done", "cancelled") else "failed"
            if job.status == "failed":
                item.error = job.events[-1]["data"].get("detail") if job.events else msg("api.scan_failed")
        except ValueError as e:
            item.status = "failed"
            item.error = message_of(e) or msg("api.scan_failed")
        except asyncio.CancelledError:
            item.status = "cancelled"
            raise
        except Exception:
            logger.exception("Lot %s : scan de %s en échec", batch.id, item.domain)
            item.status = "failed"
            item.error = msg("api.scan_failed")
