# =============================================================================
# DomainRecon - API : scans en tâche de fond et avancement en direct (SSE)
# =============================================================================
# POST /api/scans lance un scan et répond aussitôt (202). L'avancement se lit
# sur GET /api/scans/{id}/events (text/event-stream, événements rejoués depuis
# le début à chaque connexion), l'état sur GET /api/scans/{id}. Voir
# api/jobs.py. Le corps du POST choisit le profil de scan (rapide, complet,
# personnalise) ; un module actif ou sensible exige authorized_target, vérifié
# côté serveur (jobs.plan_scan). Si API_TOKEN est défini, le flux exige
# l'en-tête du jeton : le lire avec fetch() plutôt qu'EventSource, qui ne sait
# pas l'envoyer.
# =============================================================================

import asyncio
from typing import Annotated

from fastapi import APIRouter, Depends, Request
from fastapi import Path as PathParam
from fastapi.concurrency import run_in_threadpool
from fastapi.responses import JSONResponse, StreamingResponse

from ...core import config
from ...core.settings_store import load_secrets
from ...i18n import msg, render
from ...scanner import TARGET_RESOLVE_TIMEOUT, ensure_target_allowed, is_valid_target, normalize_target
from ...scanner.errors import message_exception, message_of
from ..errors import ApiError, request_lang
from ..jobs import JobManager, ScanJob, ScanPlan, TooManyScans, format_sse, plan_scan
from ..schemas import LangQuery, ScanJobRequest
from ..security import require_json_body

router = APIRouter(prefix="/api", tags=["Tâches de scan"])

# Gestionnaire unique du processus : ses emplacements bornent aussi POST /api/scan.
manager = JobManager(config.MAX_CONCURRENT_SCANS)

# Attente maximale de la fin d'une tâche annulée avant de répondre, en secondes.
CANCEL_WAIT = 2.0

JobId = Annotated[str, PathParam(pattern=r"^[0-9a-f]{32}$", description="Identifiant de la tâche")]


def get_job_manager() -> JobManager:
    """Dépendance FastAPI : le gestionnaire de tâches (remplacé dans les tests)."""
    return manager


async def precheck_target(domain: str) -> str:
    """Cible normalisée, validée et contrôlée (anti-SSRF) avant la création de la tâche.

    Lève ValueError (cible invalide) ou TargetNotAllowedError (adresse
    refusée). Une résolution trop lente n'empêche pas le scan : l'orchestrateur
    la refait et signale une cible injoignable.
    """
    target = normalize_target(domain)
    if not is_valid_target(target):
        raise message_exception(ValueError, msg("target.invalid", target=repr(domain)))
    try:
        await asyncio.wait_for(ensure_target_allowed(target), timeout=TARGET_RESOLVE_TIMEOUT)
    except (asyncio.TimeoutError, TimeoutError):
        pass
    return target


async def precheck_plan(body: ScanJobRequest) -> ScanPlan:
    """Plan du scan : les modules que le profil demandé permet de lancer, avec les clés API renseignées.

    Les clés sont lues dans les réglages au lancement du scan (leurs noms seuls
    entrent dans le plan). Lève ValueError, porteuse d'un message traduisible,
    si un module actif ou sensible est choisi sans `authorized_target`
    (api.authorization_required) ou si aucun module ne peut être lancé
    (api.no_modules) : voir jobs.plan_scan.
    """
    # Lecture de la base hors de la boucle d'événements.
    secrets = await run_in_threadpool(load_secrets)
    return plan_scan(body.profile, body.selected, body.authorized_target, secrets)


def _job_or_404(jobs: JobManager, job_id: str) -> ScanJob:
    job = jobs.get(job_id)
    if job is None:
        raise ApiError(404, msg("api.job_not_found"))
    return job


def job_status(job: ScanJob) -> dict:
    """État public d'une tâche."""
    return {
        "id": job.id,
        "domain": job.domain,
        "status": job.status,
        "scan_id": job.scan_id,
        "done": job.done,
        "total": job.total,
    }


@router.post(
    "/scans",
    status_code=202,
    dependencies=[Depends(require_json_body)],
    responses={
        400: {
            "description": (
                "Cible invalide ou non autorisée, autorisation de tester la cible manquante "
                "(module actif ou sensible), aucun module à lancer"
            )
        },
        415: {"description": "Corps non JSON"},
        429: {"description": "Trop de scans simultanés"},
    },
)
async def start_scan(body: ScanJobRequest, jobs: JobManager = Depends(get_job_manager)):
    """Lance un scan en tâche de fond ; avancement sur /api/scans/{id}/events.

    `profile` choisit les modules lancés : « rapide », « complet » (défaut) ou
    « personnalise » (ceux de `selected`). Les clés API renseignées dans les
    réglages ouvrent les modules qui en ont besoin. Un module actif ou sensible
    exige `authorized_target: true` (400 sinon) ; un plan sans aucun module est
    refusé (400).
    """
    try:
        # Emplacement d'abord (429 sans attendre), résolution DNS ensuite : une
        # rafale de requêtes ne monopolise pas l'exécuteur par défaut, que les
        # résolutions des scans en cours partagent.
        jobs.reserve_slot()
        try:
            target = await precheck_target(body.domain)
            plan = await precheck_plan(body)
        except BaseException:
            # cible ou plan refusés, résolution interrompue : la place n'est pas gardée
            jobs.release_slot()
            raise
        job = jobs.start(target, reserved=True, plan=plan)
    except TooManyScans as e:
        raise ApiError(
            429, msg("api.too_many_scans", max=jobs.max_concurrent), headers={"Retry-After": "30"}
        ) from e
    except ValueError as e:
        raise ApiError(400, message_of(e) or str(e)) from e
    return JSONResponse({"id": job.id, "status": job.status}, status_code=202)


# async : lu dans la boucle d'événements, comme les tâches qu'il décrit.
@router.get("/scans/{job_id}")
async def get_job(job_id: JobId, jobs: JobManager = Depends(get_job_manager)):
    """État d'une tâche de scan."""
    return job_status(_job_or_404(jobs, job_id))


@router.get("/scans/{job_id}/events", response_class=StreamingResponse)
async def job_events(
    job_id: JobId, request: Request, lang: LangQuery = None, jobs: JobManager = Depends(get_job_manager)
):
    """Événements de la tâche (text/event-stream), rejoués depuis le début."""
    _job_or_404(jobs, job_id)
    language = request_lang(request)

    async def stream():
        async for event in jobs.subscribe(job_id):
            yield format_sse(render(event, language))

    return StreamingResponse(
        stream(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


@router.post(
    "/scans/{job_id}/cancel",
    status_code=202,
    dependencies=[Depends(require_json_body)],
    responses={404: {"description": "Tâche inconnue"}, 409: {"description": "Tâche déjà terminée"}},
)
async def cancel_scan(job_id: JobId, jobs: JobManager = Depends(get_job_manager)):
    """Annule une tâche en cours (corps : {} en JSON)."""
    job = _job_or_404(jobs, job_id)
    if not jobs.cancel(job_id):
        raise ApiError(409, msg("api.job_not_running"))
    await jobs.wait(job_id, timeout=CANCEL_WAIT)
    return JSONResponse({"id": job.id, "status": job.status}, status_code=202)
