# =============================================================================
# DomainRecon - Surveillance : planificateur intégré
# =============================================================================
# Tâche asyncio démarrée avec l'application (api/app.py, lifespan) : toutes les
# `interval` secondes, elle lance les surveillances échues (service.run_due). Elle
# ne tourne que tant que l'application est ouverte ; la tâche système
# (systask.py) prend le relais application fermée. SCHEDULER=0 (environnement ou
# .env) la désactive. L'horloge est injectable (tests).
# =============================================================================

import asyncio
import contextlib
import logging

import httpx

from ..core import config
from ..core.models import utcnow
from .service import Clock, RunResult, ScanRunner, run_due

logger = logging.getLogger(__name__)

# Période de réveil (secondes) et attente avant le premier passage, pour ne pas
# concurrencer le démarrage de l'application.
DEFAULT_INTERVAL = 60.0
DEFAULT_INITIAL_DELAY = 20.0


def scheduler_enabled() -> bool:
    """Planificateur actif ? (SCHEDULER, vrai par défaut)."""
    return config.env_bool("SCHEDULER", True)


class Scheduler:
    """Passe périodiquement les surveillances échues."""

    def __init__(
        self,
        runner: ScanRunner,
        *,
        clock: Clock = utcnow,
        interval: float = DEFAULT_INTERVAL,
        initial_delay: float = DEFAULT_INITIAL_DELAY,
        concurrency: int = 1,
        transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        self.runner = runner
        self.clock = clock
        self.interval = interval
        self.initial_delay = initial_delay
        self.concurrency = concurrency
        self.transport = transport
        self.last_tick_at = None
        self.last_results: list[RunResult] = []
        self._task: asyncio.Task | None = None
        self._wake = asyncio.Event()

    @property
    def running(self) -> bool:
        return self._task is not None and not self._task.done()

    async def tick(self) -> list[RunResult]:
        """Un passage : lance les surveillances échues à l'heure de l'horloge."""
        self.last_tick_at = self.clock()
        self.last_results = await run_due(
            self.runner, clock=self.clock, concurrency=self.concurrency, transport=self.transport
        )
        return self.last_results

    def wake(self) -> None:
        """Déclenche un passage sans attendre la prochaine période."""
        self._wake.set()

    async def _loop(self) -> None:
        delay = self.initial_delay
        while True:
            with contextlib.suppress(asyncio.TimeoutError):
                await asyncio.wait_for(self._wake.wait(), timeout=delay)
            self._wake.clear()
            delay = self.interval
            try:
                await self.tick()
            except asyncio.CancelledError:
                raise
            except Exception:
                logger.exception("Planificateur : passage en échec")

    def start(self) -> None:
        """Démarre la boucle (dans la boucle d'événements en cours) ; sans effet si elle tourne."""
        if not self.running:
            self._task = asyncio.get_running_loop().create_task(self._loop(), name="domainrecon-scheduler")

    async def stop(self) -> None:
        """Arrête la boucle ; un scan en cours est interrompu et son échéance rendue."""
        task, self._task = self._task, None
        if task is None:
            return
        task.cancel()
        with contextlib.suppress(asyncio.CancelledError, Exception):
            await task


def create_scheduler(manager) -> Scheduler:
    """Planificateur de l'application : les scans passent par le gestionnaire de tâches `manager`.

    Un emplacement reste libre pour l'interface quand le gestionnaire en a plusieurs.
    """
    from ..api.routes.jobs import precheck_target
    from .service import job_manager_runner

    return Scheduler(
        job_manager_runner(manager, precheck_target), concurrency=max(1, manager.max_concurrent - 1)
    )
