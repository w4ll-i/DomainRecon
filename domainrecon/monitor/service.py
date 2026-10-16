# =============================================================================
# DomainRecon - Surveillance : exécution des surveillances échues
# =============================================================================
# `run_due()` est le point d'entrée commun du planificateur intégré
# (scheduler.py) et de la commande `domainrecon monitor run-due`. Pour chaque
# surveillance échue : bail d'exécution (lease.py : une même surveillance n'est
# jamais scannée deux fois en même temps, même par deux processus), réservation
# de l'échéance, scan (par un « runner » : le gestionnaire de tâches de
# l'application, ou le scanner en direct pour la ligne de commande),
# comparaison avec le scan précédent, règles d'alerte, envoi aux canaux. Une
# surveillance en échec n'empêche pas les autres et sera retentée dans une heure.
# =============================================================================

import asyncio
import logging
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from datetime import datetime

import httpx

from ..api import storage
from ..api.jobs import JobManager, TooManyScans, plan_scan
from ..core.database import SessionLocal
from ..core.models import Scan, utcnow
from ..core.settings_store import load_secrets
from ..i18n import loads_message, msg
from ..notify import dispatch
from ..notify.channels import Alert
from ..scanner import perform_full_scan
from ..scanner.errors import message_of
from . import lease, schedule
from .alerts import evaluate, rules_of
from .compare import diff_scans, scan_view
from .models import Watch

logger = logging.getLogger(__name__)

Clock = Callable[[], datetime]


class WatchScanError(Exception):
    """Scan d'une surveillance en échec ; `message` est traduisible."""

    def __init__(self, message: object) -> None:
        super().__init__(str(message))
        self.message = message


@dataclass(frozen=True)
class WatchSpec:
    """Ce que le runner a besoin de connaître d'une surveillance."""

    id: int
    domain: str
    profile: str
    selected: tuple[str, ...]
    authorized_target: bool
    frequency: str
    channels: tuple[str, ...]
    lang: str


# Un runner lance le scan d'une surveillance et renvoie l'identifiant du scan enregistré.
ScanRunner = Callable[[WatchSpec], Awaitable[int]]


@dataclass
class RunResult:
    """Issue d'une surveillance dans un passage de run_due."""

    watch_id: int
    domain: str
    status: str  # done | failed | skipped | deferred
    scan_id: int | None = None
    alerts: list[Alert] = field(default_factory=list)
    delivery: dict = field(default_factory=dict)
    error: object = None


def spec_of(watch: Watch) -> WatchSpec:
    return WatchSpec(
        id=watch.id,
        domain=watch.domain,
        profile=watch.profile,
        selected=tuple(watch.selected or ()),
        authorized_target=bool(watch.authorized_target),
        frequency=watch.frequency,
        channels=tuple(watch.channels or ()),
        lang=watch.lang or "fr",
    )


# =============================================================================
# Runners
# =============================================================================


async def _plan(spec: WatchSpec):
    """Plan du scan (ValueError traduisible si l'autorisation ou les modules manquent)."""
    secrets = await asyncio.to_thread(load_secrets)
    return plan_scan(spec.profile, spec.selected, spec.authorized_target, secrets)


def job_manager_runner(manager: JobManager, precheck_target: Callable[[str], Awaitable[str]]) -> ScanRunner:
    """Runner de l'application : le scan passe par le gestionnaire de tâches (emplacements partagés).

    Sans emplacement libre, lève TooManyScans : la surveillance est reportée.
    """

    async def run(spec: WatchSpec) -> int:
        try:
            plan = await _plan(spec)
            manager.reserve_slot()
            try:
                target = await precheck_target(spec.domain)
            except BaseException:
                manager.release_slot()
                raise
            job = manager.start(target, reserved=True, plan=plan)
        except ValueError as e:
            raise WatchScanError(message_of(e) or msg("api.scan_failed")) from e
        while job.status == "running":
            await manager.wait(job.id, timeout=1.0)
        if job.status == "done" and job.scan_id is not None:
            return job.scan_id
        if job.status == "cancelled":
            raise WatchScanError(msg("monitor.scan_cancelled"))
        detail = job.events[-1]["data"].get("detail") if job.events else None
        raise WatchScanError(detail or msg("api.scan_failed"))

    return run


def direct_runner() -> ScanRunner:
    """Runner de la ligne de commande : le scanner directement, sans serveur."""

    async def run(spec: WatchSpec) -> int:
        try:
            plan = await _plan(spec)
            result = await perform_full_scan(
                spec.domain,
                profile=plan.profile,
                authorized_target=plan.authorized_target,
                selected=plan.selected,
                available_keys=plan.available_keys,
            )
            result = {"profile": plan.profile, "modules_launched": list(plan.modules), **result}
            return await asyncio.to_thread(storage.save_scan, result)
        except storage.ScanSaveError as e:
            raise WatchScanError(msg("api.save_failed")) from e
        except ValueError as e:
            raise WatchScanError(message_of(e) or msg("api.scan_failed")) from e

    return run


# =============================================================================
# Accès base (exécutés dans un fil)
# =============================================================================


def _restore(watch_id: int, claimed_next: datetime, expected: datetime) -> None:
    """Rend l'échéance (scan reporté ou interrompu)."""
    with SessionLocal() as db:
        db.query(Watch).filter(Watch.id == watch_id, Watch.next_run_at == claimed_next).update(
            {Watch.next_run_at: expected}, synchronize_session=False
        )
        db.commit()


def _due(now: datetime) -> list[tuple[int, datetime]]:
    with SessionLocal() as db:
        return schedule.list_due(db, now)


def _record_failure(watch_id: int, error: object, now: datetime, claimed_next: datetime) -> None:
    with SessionLocal() as db:
        watch = db.get(Watch, watch_id)
        if watch is None:
            return
        watch.last_run_at = now
        watch.last_status = "failed"
        watch.last_error = error if isinstance(error, (dict, str)) else msg("api.scan_failed")
        retry = now + schedule.RETRY_DELAY
        # Nouvelle tentative plus tôt que l'échéance normale, sans la repousser si elle est plus proche.
        if watch.next_run_at == claimed_next:
            watch.next_run_at = min(retry, claimed_next)
        db.commit()


def _previous_scan(db, domain: str, scan_id: int) -> Scan | None:
    return (
        db.query(Scan)
        .filter(Scan.domain == domain, Scan.id < scan_id, Scan.status != "error")
        .order_by(Scan.id.desc())
        .first()
    )


def _evaluate_and_record(watch_id: int, scan_id: int, now: datetime) -> tuple[list[Alert], str | None]:
    """Compare le scan au précédent, applique les règles et enregistre l'issue.

    Renvoie (alertes, None) ou ([], message d'erreur) si le scan lui-même est en erreur.
    """
    with SessionLocal() as db:
        watch = db.get(Watch, watch_id)
        scan = db.get(Scan, scan_id)
        if watch is None or scan is None:
            return [], None
        watch.last_run_at = now
        watch.last_scan_id = scan_id
        if scan.status == "error":
            watch.last_status = "failed"
            error = loads_message(scan.error_message) or msg("api.scan_failed")
            watch.last_error = error if isinstance(error, (dict, str)) else msg("api.scan_failed")
            db.commit()
            return [], error
        watch.last_status = "done"
        watch.last_error = None
        view = scan_view(scan)
        previous = _previous_scan(db, watch.domain, scan_id)
        diff = diff_scans(previous, scan, view_b=view) if previous is not None else None
        alerts, state = evaluate(rules_of(watch.rules), watch.alert_state or {}, watch.domain, view, diff)
        watch.alert_state = state
        db.commit()
        return alerts, None


# =============================================================================
# Exécution
# =============================================================================


async def _run_one(
    watch_id: int,
    expected: datetime,
    runner: ScanRunner,
    clock: Clock,
    transport: httpx.AsyncBaseTransport | None,
) -> RunResult:
    # Le bail d'abord : une surveillance déjà en cours d'exécution (ici ou dans un autre
    # processus) n'est pas touchée et reste échue pour le prochain passage.
    async with lease.hold(watch_id, clock) as acquired:
        if not acquired:
            logger.debug("Surveillance %s déjà en cours d'exécution : laissée de côté", watch_id)
            return RunResult(watch_id, "", "skipped")
        return await _run_leased(watch_id, expected, runner, clock, transport)


async def _run_leased(
    watch_id: int,
    expected: datetime,
    runner: ScanRunner,
    clock: Clock,
    transport: httpx.AsyncBaseTransport | None,
) -> RunResult:
    """Exécution d'une surveillance dont le bail est tenu : réservation de l'échéance, scan, alertes."""
    now = clock()
    spec = await asyncio.to_thread(_claim_with_frequency, watch_id, expected, now)
    if spec is None:
        return RunResult(watch_id, "", "skipped")
    claimed_next = schedule.next_run(spec.frequency, now)
    try:
        scan_id = await runner(spec)
    except TooManyScans:
        await asyncio.to_thread(_restore, watch_id, claimed_next, expected)
        return RunResult(watch_id, spec.domain, "deferred")
    except asyncio.CancelledError:
        await asyncio.shield(asyncio.to_thread(_restore, watch_id, claimed_next, expected))
        raise
    except WatchScanError as e:
        await asyncio.to_thread(_record_failure, watch_id, e.message, clock(), claimed_next)
        return RunResult(watch_id, spec.domain, "failed", error=e.message)
    except Exception:
        logger.exception("Surveillance de %s : scan en échec", spec.domain)
        error = msg("api.scan_failed")
        await asyncio.to_thread(_record_failure, watch_id, error, clock(), claimed_next)
        return RunResult(watch_id, spec.domain, "failed", error=error)

    alerts, error = await asyncio.to_thread(_evaluate_and_record, watch_id, scan_id, clock())
    if error is not None:
        await asyncio.to_thread(_record_failure, watch_id, error, clock(), claimed_next)
        return RunResult(watch_id, spec.domain, "failed", scan_id=scan_id, error=error)
    delivery = {}
    if alerts:
        try:
            delivery = await dispatch.dispatch_alerts(
                spec.domain, scan_id, watch_id, alerts, list(spec.channels), spec.lang, transport=transport
            )
        except Exception:
            logger.exception("Surveillance de %s : envoi des alertes en échec", spec.domain)
    return RunResult(watch_id, spec.domain, "done", scan_id=scan_id, alerts=alerts, delivery=delivery)


def _claim_with_frequency(watch_id: int, expected: datetime, now: datetime) -> WatchSpec | None:
    """Réserve l'échéance : prochaine échéance calculée depuis `now` selon la fréquence de la surveillance."""
    with SessionLocal() as db:
        watch = db.get(Watch, watch_id)
        if watch is None:
            return None
        new_next = schedule.next_run(watch.frequency, now)
        if not schedule.claim(db, watch_id, expected, new_next):
            return None
        db.refresh(watch)
        return spec_of(watch)


async def run_due(
    runner: ScanRunner,
    *,
    clock: Clock = utcnow,
    concurrency: int = 2,
    transport: httpx.AsyncBaseTransport | None = None,
) -> list[RunResult]:
    """Lance les surveillances échues à l'heure de `clock()` ; une issue par surveillance réservée.

    `concurrency` borne les scans simultanés de ce passage. Les surveillances
    déjà prises par un autre processus (bail tenu, ou échéance réservée) sont
    écartées (statut « skipped ») : elles restent échues si leur bail l'empêche.
    """
    due = await asyncio.to_thread(_due, clock())
    gate = asyncio.Semaphore(max(1, concurrency))

    async def one(watch_id: int, expected: datetime) -> RunResult:
        async with gate:
            return await _run_one(watch_id, expected, runner, clock, transport)

    results = await asyncio.gather(*(one(watch_id, expected) for watch_id, expected in due))
    return [r for r in results if r.status != "skipped"]
