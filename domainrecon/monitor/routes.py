# =============================================================================
# DomainRecon - API : tableau de bord, comparaison, lots et surveillances
# =============================================================================
# GET    /api/dashboard               un élément par domaine (note, score, tendance, constats, surveillance) et totaux
# GET    /api/compare?a=&b=           différences entre deux scans du même domaine (a : référence, b : plus récent)
# POST   /api/batches                 lance un lot {domains[], profile, selected, authorized_target} (202)
# GET    /api/batches                 lots en mémoire, du plus récent au plus ancien
# GET    /api/batches/{id}            progression et résultat par domaine
# POST   /api/batches/{id}/cancel     annule le lot (corps : {} en JSON)
# GET    /api/watches                 surveillances
# POST   /api/watches                 crée une surveillance
# GET    /api/watches/{id}            une surveillance
# PATCH  /api/watches/{id}            modifie une surveillance (champs présents seulement)
# DELETE /api/watches/{id}            supprime une surveillance
# POST   /api/watches/{id}/run        planifie le scan tout de suite (corps : {} en JSON)
# GET    /api/monitor/task            état de la tâche système (schtasks / systemd --user)
# POST   /api/monitor/task/install    installe la tâche système (requête locale seulement, sinon 403)
# POST   /api/monitor/task/uninstall  la désinstalle (requête locale seulement, sinon 403)
# Les alertes sont envoyées au centre de notifications (domainrecon/notify) et aux canaux de la surveillance.
# =============================================================================

from datetime import datetime
from typing import Annotated, Literal

from fastapi import APIRouter, Depends, Query, Request
from fastapi import Path as PathParam
from fastapi.concurrency import run_in_threadpool
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict, Field, StrictBool
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from ..api.errors import ApiError, request_lang
from ..api.jobs import JobManager, plan_scan
from ..api.routes.jobs import get_job_manager, precheck_target
from ..api.schemas import (
    MAX_MODULE_NAME_LENGTH,
    MAX_SCAN_ID,
    MAX_SELECTED_MODULES,
    LangQuery,
    ScanProfile,
    UtcDatetime,
    as_utc,
    iso_utc,
)
from ..api.security import require_json_body, require_local_client
from ..core import config
from ..core.database import get_db
from ..core.models import Scan, utcnow
from ..core.settings_store import load_secrets
from ..i18n import msg, render
from ..scanner import is_ip_literal, is_public_address, is_valid_target, normalize_target
from ..scanner.errors import message_of
from . import systask
from .alerts import AlertRules, rules_of
from .batches import MAX_BATCH_DOMAINS, Batch, BatchManager, clean_domains
from .compare import diff_scans
from .dashboard import MAX_DOMAINS, build_dashboard
from .models import Watch, WatchLease
from .scorefmt import display_score

router = APIRouter(prefix="/api", tags=["Surveillance"])

# Gestionnaire unique des lots du processus.
batch_manager = BatchManager()

ExternalChannel = Literal["discord", "slack", "teams", "webhook", "email", "desktop", "center"]
Frequency = Literal["daily", "weekly", "monthly"]
BatchId = Annotated[str, PathParam(pattern=r"^[0-9a-f]{32}$", description="Identifiant du lot")]
WatchId = Annotated[int, PathParam(ge=1, le=MAX_SCAN_ID, description="Identifiant de la surveillance")]
Selected = Annotated[
    list[Annotated[str, Field(max_length=MAX_MODULE_NAME_LENGTH)]], Field(max_length=MAX_SELECTED_MODULES)
]


def get_batch_manager() -> BatchManager:
    """Dépendance FastAPI : le gestionnaire de lots (remplacé dans les tests)."""
    return batch_manager


# =============================================================================
# Tableau de bord et comparaison
# =============================================================================


@router.get("/dashboard")
def get_dashboard(
    request: Request,
    limit: int = Query(MAX_DOMAINS, ge=1, le=MAX_DOMAINS),
    lang: LangQuery = None,
    db: Session = Depends(get_db),
):
    """Un élément par domaine scanné (dernier scan, note, tendance, constats ouverts) et les totaux."""
    return JSONResponse(render(build_dashboard(db, limit), request_lang(request)))


@router.get("/compare")
def compare_scans(
    request: Request,
    a: Annotated[int, Query(ge=1, le=MAX_SCAN_ID, description="Scan de référence")],
    b: Annotated[int, Query(ge=1, le=MAX_SCAN_ID, description="Scan à comparer (le plus récent)")],
    lang: LangQuery = None,
    db: Session = Depends(get_db),
):
    """Différences entre deux scans du même domaine : note, constats, DNS, ports, sous-domaines, certificat, technologies."""
    scan_a, scan_b = db.get(Scan, a), db.get(Scan, b)
    if scan_a is None or scan_b is None:
        raise ApiError(404, msg("api.scan_not_found"))
    if scan_a.domain != scan_b.domain:
        raise ApiError(400, msg("compare.different_domains"))
    return JSONResponse(render(diff_scans(scan_a, scan_b), request_lang(request)))


# =============================================================================
# Lots
# =============================================================================


class BatchRequest(BaseModel):
    """Corps de POST /api/batches."""

    domains: list[Annotated[str, Field(max_length=5000)]] = Field(..., min_length=1, max_length=1000)
    profile: ScanProfile = "complet"
    selected: Selected | None = None
    authorized_target: StrictBool = Field(
        False, description="Déclare avoir l'autorisation de tester TOUTES les cibles du lot"
    )


def batch_view(batch: Batch, db: Session | None = None, *, with_items: bool = True) -> dict:
    """État public d'un lot ; avec `db`, note et score des domaines terminés."""
    counts = batch.counts()
    view: dict = {
        "id": batch.id,
        "status": batch.status,
        "profile": batch.plan.profile,
        "created_at": iso_utc(batch.created_at),
        "total": len(batch.items),
        "counts": counts,
        "finished": counts["done"] + counts["failed"] + counts["cancelled"],
    }
    if not with_items:
        return view
    scores = {}
    scan_ids = [i.scan_id for i in batch.items if i.scan_id is not None]
    if db is not None and scan_ids:
        for scan_id, security_score in db.query(Scan.id, Scan.security_score).filter(Scan.id.in_(scan_ids)):
            scores[scan_id] = display_score(security_score)
    view["items"] = [
        {
            "domain": item.domain,
            "status": item.status,
            "scan_id": item.scan_id,
            "job_id": item.job_id,
            "error": item.error,
            "grade": scores[item.scan_id]["grade"] if item.scan_id in scores else None,
            "score": scores[item.scan_id]["score"] if item.scan_id in scores else None,
        }
        for item in batch.items
    ]
    return view


def _batch_or_404(batches: BatchManager, batch_id: str) -> Batch:
    batch = batches.get(batch_id)
    if batch is None:
        raise ApiError(404, msg("batch.not_found"))
    return batch


@router.post(
    "/batches",
    status_code=202,
    dependencies=[Depends(require_json_body)],
    responses={
        400: {"description": "Liste vide ou trop longue, autorisation manquante, aucun module à lancer"}
    },
)
async def start_batch(
    body: BatchRequest,
    request: Request,
    lang: LangQuery = None,
    jobs: JobManager = Depends(get_job_manager),
    batches: BatchManager = Depends(get_batch_manager),
):
    """Lance un lot : liste nettoyée et dédoublonnée, scans en file avec concurrence limitée.

    Les entrées sont normalisées (URL, majuscules, IDN) ; les entrées invalides sont renvoyées dans
    `rejected`. Plafond : 100 domaines. Un module actif ou sensible exige `authorized_target: true`
    (400 sinon), pour tous les domaines du lot.
    """
    accepted, rejected, duplicates = clean_domains(body.domains)
    if not accepted:
        raise ApiError(400, msg("batch.empty"))
    if len(accepted) > MAX_BATCH_DOMAINS:
        raise ApiError(400, msg("batch.too_many", max=MAX_BATCH_DOMAINS, count=len(accepted)))
    secrets = await run_in_threadpool(load_secrets)
    try:
        plan = plan_scan(body.profile, body.selected, body.authorized_target, secrets)
    except ValueError as e:
        raise ApiError(400, message_of(e) or str(e)) from e
    batch = batches.start(jobs, accepted, plan, precheck_target)
    view = batch_view(batch, with_items=False)
    view.update(rejected=rejected, duplicates=duplicates)
    return JSONResponse(render(view, request_lang(request)), status_code=202)


@router.get("/batches")
def list_batches(
    request: Request, lang: LangQuery = None, batches: BatchManager = Depends(get_batch_manager)
):
    """Lots en mémoire (sans le détail des domaines), du plus récent au plus ancien."""
    return {"batches": [batch_view(b, with_items=False) for b in batches.all()]}


@router.get("/batches/{batch_id}")
def get_batch(
    batch_id: BatchId,
    request: Request,
    lang: LangQuery = None,
    db: Session = Depends(get_db),
    batches: BatchManager = Depends(get_batch_manager),
):
    """Progression du lot et résultat par domaine (statut, scan, note, erreur)."""
    return JSONResponse(render(batch_view(_batch_or_404(batches, batch_id), db), request_lang(request)))


@router.post(
    "/batches/{batch_id}/cancel",
    status_code=202,
    dependencies=[Depends(require_json_body)],
    responses={404: {"description": "Lot inconnu"}, 409: {"description": "Lot déjà terminé"}},
)
async def cancel_batch(
    batch_id: BatchId,
    jobs: JobManager = Depends(get_job_manager),
    batches: BatchManager = Depends(get_batch_manager),
):
    """Annule le lot : domaines en attente abandonnés, scans en cours annulés."""
    batch = _batch_or_404(batches, batch_id)
    if not batches.cancel(batch_id, jobs):
        raise ApiError(409, msg("batch.not_running"))
    return JSONResponse({"id": batch.id, "status": "cancelled"}, status_code=202)


# =============================================================================
# Surveillances
# =============================================================================


class WatchCreate(BaseModel):
    """Corps de POST /api/watches."""

    model_config = ConfigDict(extra="forbid")

    domain: str = Field(..., min_length=3, max_length=255)
    profile: ScanProfile = "complet"
    selected: Selected | None = None
    authorized_target: StrictBool = False
    frequency: Frequency = "daily"
    enabled: bool = True
    rules: AlertRules = Field(default_factory=AlertRules)
    channels: list[ExternalChannel] = Field(default_factory=list, max_length=7)
    lang: Literal["fr", "en"] = "fr"
    next_run_at: UtcDatetime | None = Field(None, description="Première échéance (défaut : maintenant)")


class WatchUpdate(BaseModel):
    """Corps de PATCH /api/watches/{id} : un champ absent n'est pas modifié."""

    model_config = ConfigDict(extra="forbid")

    profile: ScanProfile | None = None
    selected: Selected | None = None
    authorized_target: StrictBool | None = None
    frequency: Frequency | None = None
    enabled: bool | None = None
    rules: AlertRules | None = None
    channels: list[ExternalChannel] | None = Field(None, max_length=7)
    lang: Literal["fr", "en"] | None = None
    next_run_at: UtcDatetime | None = None


def _naive_utc(value: datetime) -> datetime:
    return as_utc(value).replace(tzinfo=None)


def watch_view(watch: Watch) -> dict:
    return {
        "id": watch.id,
        "domain": watch.domain,
        "profile": watch.profile,
        "selected": watch.selected,
        "authorized_target": bool(watch.authorized_target),
        "frequency": watch.frequency,
        "enabled": bool(watch.enabled),
        "next_run_at": iso_utc(watch.next_run_at),
        "last_run_at": iso_utc(watch.last_run_at) if watch.last_run_at else None,
        "last_scan_id": watch.last_scan_id,
        "last_status": watch.last_status,
        "last_error": watch.last_error,
        "rules": rules_of(watch.rules).model_dump(),
        "channels": list(watch.channels or []),
        "lang": watch.lang,
        "created_at": iso_utc(watch.created_at),
    }


def _watch_or_404(db: Session, watch_id: int) -> Watch:
    watch = db.get(Watch, watch_id)
    if watch is None:
        raise ApiError(404, msg("monitor.watch_not_found"))
    return watch


def _check_plan(profile: str, selected: list[str] | None, authorized: bool) -> None:
    """Le plan de scan doit être valide dès la création (autorisation, modules) : 400 sinon."""
    try:
        plan_scan(profile, selected, authorized, load_secrets())
    except ValueError as e:
        raise ApiError(400, message_of(e) or str(e)) from e


@router.get("/watches")
def list_watches(request: Request, lang: LangQuery = None, db: Session = Depends(get_db)):
    watches = db.query(Watch).order_by(Watch.domain).all()
    return JSONResponse(render({"watches": [watch_view(w) for w in watches]}, request_lang(request)))


@router.post("/watches", status_code=201, dependencies=[Depends(require_json_body)])
def create_watch(body: WatchCreate, request: Request, lang: LangQuery = None, db: Session = Depends(get_db)):
    """Crée une surveillance : le domaine est scanné à chaque échéance et comparé au scan précédent."""
    target = normalize_target(body.domain)
    if not is_valid_target(target):
        raise ApiError(400, msg("api.invalid_domain"))
    if is_ip_literal(target) and not config.private_targets_allowed() and not is_public_address(target):
        raise ApiError(400, msg("target.ip_not_allowed"))
    _check_plan(body.profile, body.selected, body.authorized_target)
    if db.query(Watch.id).filter(Watch.domain == target).first() is not None:
        raise ApiError(409, msg("monitor.watch_exists"))
    watch = Watch(
        domain=target,
        profile=body.profile,
        selected=body.selected if body.profile == "personnalise" else None,
        authorized_target=body.authorized_target,
        frequency=body.frequency,
        enabled=body.enabled,
        next_run_at=_naive_utc(body.next_run_at) if body.next_run_at else utcnow(),
        rules=body.rules.model_dump(),
        channels=list(dict.fromkeys(body.channels)),
        lang=body.lang,
        alert_state={},
    )
    db.add(watch)
    try:
        db.commit()
    except IntegrityError as e:
        db.rollback()
        raise ApiError(409, msg("monitor.watch_exists")) from e
    return JSONResponse(render(watch_view(watch), request_lang(request)), status_code=201)


@router.get("/watches/{watch_id}")
def get_watch(watch_id: WatchId, request: Request, lang: LangQuery = None, db: Session = Depends(get_db)):
    return JSONResponse(render(watch_view(_watch_or_404(db, watch_id)), request_lang(request)))


@router.patch("/watches/{watch_id}", dependencies=[Depends(require_json_body)])
def update_watch(
    watch_id: WatchId,
    body: WatchUpdate,
    request: Request,
    lang: LangQuery = None,
    db: Session = Depends(get_db),
):
    watch = _watch_or_404(db, watch_id)
    changes = body.model_dump(exclude_unset=True)
    profile = changes.get("profile", watch.profile)
    selected = changes.get("selected", watch.selected)
    authorized = changes.get("authorized_target", watch.authorized_target)
    if {"profile", "selected", "authorized_target"} & changes.keys():
        _check_plan(profile, selected, bool(authorized))
    for key in ("profile", "authorized_target", "frequency", "enabled", "lang"):
        if changes.get(key) is not None:
            setattr(watch, key, changes[key])
    watch.selected = selected if profile == "personnalise" else None
    if body.rules is not None:
        watch.rules = body.rules.model_dump()
    if body.channels is not None:
        watch.channels = list(dict.fromkeys(body.channels))
    if body.next_run_at is not None:
        watch.next_run_at = _naive_utc(body.next_run_at)
    db.commit()
    return JSONResponse(render(watch_view(watch), request_lang(request)))


@router.delete("/watches/{watch_id}")
def delete_watch(watch_id: WatchId, db: Session = Depends(get_db)):
    watch = _watch_or_404(db, watch_id)
    db.delete(watch)
    # Pas de clé étrangère : le bail d'exécution part avec la surveillance (son numéro peut être réattribué).
    db.query(WatchLease).filter(WatchLease.watch_id == watch_id).delete(synchronize_session=False)
    db.commit()
    return {"id": watch_id}


@router.post(
    "/watches/{watch_id}/run",
    status_code=202,
    dependencies=[Depends(require_json_body)],
    responses={409: {"description": "Surveillance désactivée ou planificateur arrêté"}},
)
def run_watch_now(watch_id: WatchId, request: Request, db: Session = Depends(get_db)):
    """Rend la surveillance échue tout de suite et réveille le planificateur intégré."""
    watch = _watch_or_404(db, watch_id)
    scheduler = getattr(request.app.state, "scheduler", None)
    if not watch.enabled:
        raise ApiError(409, msg("monitor.watch_disabled"))
    if scheduler is None or not scheduler.running:
        raise ApiError(409, msg("monitor.scheduler_off"))
    watch.next_run_at = utcnow()
    db.commit()
    scheduler.wake()
    return JSONResponse({"id": watch.id, "next_run_at": iso_utc(watch.next_run_at)}, status_code=202)


# =============================================================================
# Tâche système
# =============================================================================


@router.get("/monitor/task")
async def task_status():
    """Tâche système qui exécute `domainrecon monitor run-due` : prise en charge, installée ou non."""
    return await run_in_threadpool(systask.status)


# Ces deux routes modifient le système de la machine du serveur : réservées aux requêtes
# locales, comme POST /api/system/open-data-dir (le corps JSON est vérifié d'abord : 415, puis 403).
_TASK_RESPONSES = {
    400: {"description": "Système non pris en charge ou refus du système (systask.*)"},
    403: {"description": "Requête venue d'une autre machine (api.local_only)"},
    415: {"description": "Corps non JSON"},
}


@router.post(
    "/monitor/task/install",
    dependencies=[Depends(require_json_body), Depends(require_local_client)],
    responses=_TASK_RESPONSES,
)
async def task_install(request: Request, lang: LangQuery = None):
    """Installe la tâche système (Planificateur de tâches Windows, minuteur systemd --user), sans droits administrateur."""
    try:
        return await run_in_threadpool(systask.install)
    except ValueError as e:
        raise ApiError(400, message_of(e) or str(e)) from e


@router.post(
    "/monitor/task/uninstall",
    dependencies=[Depends(require_json_body), Depends(require_local_client)],
    responses=_TASK_RESPONSES,
)
async def task_uninstall(request: Request, lang: LangQuery = None):
    """Retire la tâche système (sans erreur si elle n'existe pas)."""
    try:
        return await run_in_threadpool(systask.uninstall)
    except ValueError as e:
        raise ApiError(400, message_of(e) or str(e)) from e
