# =============================================================================
# DomainRecon - API : scan synchrone, lecture, suppression, tags et notes
# =============================================================================

import logging

from fastapi import APIRouter, Depends, Request
from fastapi.concurrency import run_in_threadpool
from fastapi.responses import JSONResponse
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from ...core.database import get_db
from ...core.models import Scan
from ...i18n import msg, render
from ...scanner import perform_full_scan
from ...scanner.errors import message_of
from ...scanner.families import compute_families
from ...scanner.findings import compute_findings
from .. import storage
from ..errors import ApiError, request_lang
from ..jobs import JobManager, TooManyScans
from ..schemas import LangQuery, ScanId, ScanMetaUpdate, ScanRequest, ScanResponse
from ..security import require_json_body
from .jobs import get_job_manager

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api", tags=["API"])


def _get_scan_or_404(db: Session, scan_id: int) -> Scan:
    scan = db.get(Scan, scan_id)
    if scan is None:
        raise ApiError(404, msg("api.scan_not_found"))
    return scan


def scan_payload(scan: Scan) -> dict:
    """Scan tel que renvoyé par l'API (messages non rendus), familles et points à corriger compris."""
    payload = ScanResponse.model_validate(scan).model_dump(mode="json")
    payload["families"] = compute_families(payload)
    payload["findings"] = compute_findings(payload)
    return payload


def _stored_payload(scan_id: int) -> dict:
    """Scan tout juste enregistré, relu dans sa propre session."""
    with storage.SessionLocal() as db:
        return scan_payload(db.get(Scan, scan_id))


@router.post(
    "/scan",
    response_model=ScanResponse,
    dependencies=[Depends(require_json_body)],
    responses={
        400: {"description": "Cible invalide ou non autorisée"},
        415: {"description": "Corps non JSON"},
        429: {"description": "Trop de scans simultanés"},
    },
)
async def scan_domain(
    body: ScanRequest,
    request: Request,
    lang: LangQuery = None,
    jobs: JobManager = Depends(get_job_manager),
):
    """Lance un scan complet d'un domaine (synchrone ; voir aussi POST /api/scans).

    Seule la cible se règle ici : le profil de scan, le choix des modules et l'autorisation
    des modules actifs ou sensibles sont réservés à POST /api/scans.
    """
    # Mêmes emplacements que les tâches : MAX_CONCURRENT_SCANS au total. Pris
    # par le gestionnaire, il compte comme scan en cours (busy() : le mode
    # navigateur ne s'arrête pas), jusqu'à la fin de l'enregistrement.
    try:
        jobs.reserve_slot()
    except TooManyScans as e:
        raise ApiError(
            429, msg("api.too_many_scans", max=jobs.max_concurrent), headers={"Retry-After": "30"}
        ) from e
    try:
        try:
            result = await perform_full_scan(body.domain)
        except ValueError as e:
            # Cible invalide, ou refusée par la politique de cibles
            # (TargetNotAllowedError hérite de ValueError) : message destiné à l'utilisateur.
            raise ApiError(400, message_of(e) or str(e)) from e
        except Exception as e:
            logger.exception("Scan de %r échoué", body.domain)
            raise ApiError(500, msg("api.scan_failed")) from e

        # Écriture synchrone hors de la boucle d'événements.
        try:
            scan_id = await run_in_threadpool(storage.save_scan, result)
        except storage.ScanSaveError as e:
            raise ApiError(500, msg("api.save_failed")) from e
    finally:
        jobs.release_slot()
    payload = await run_in_threadpool(_stored_payload, scan_id)
    return JSONResponse(render(payload, request_lang(request)))


@router.get("/scan/{scan_id}", response_model=ScanResponse)
def get_scan_by_id(scan_id: ScanId, request: Request, lang: LangQuery = None, db: Session = Depends(get_db)):
    """Récupère un scan par son ID, messages rendus dans la langue demandée."""
    return JSONResponse(render(scan_payload(_get_scan_or_404(db, scan_id)), request_lang(request)))


@router.delete("/scan/{scan_id}")
def delete_scan(scan_id: ScanId, request: Request, lang: LangQuery = None, db: Session = Depends(get_db)):
    """Supprime un scan et sa capture d'écran."""
    scan = _get_scan_or_404(db, scan_id)
    domain, screenshot = scan.domain, scan.screenshot_path
    db.delete(scan)
    db.commit()
    # Après le commit seulement : si la suppression échoue, la capture reste
    # utilisable. Et jamais si un autre scan référence le même fichier.
    try:
        if screenshot and not storage._screenshot_in_use(db, screenshot):
            storage._delete_screenshot_file(screenshot)
    except SQLAlchemyError as e:
        # Le scan est bien supprimé ; la capture sera reprise par le nettoyage
        # des orphelines au prochain démarrage.
        logger.warning("Capture %s conservée : vérification impossible (%s)", screenshot, e)
    logger.info("Scan %s (%s) supprimé", scan_id, domain)
    return {"message": render(msg("api.scan_deleted"), request_lang(request)), "id": scan_id}


@router.patch(
    "/scan/{scan_id}/meta",
    response_model=ScanResponse,
    dependencies=[Depends(require_json_body)],
)
def update_scan_meta(
    scan_id: ScanId,
    body: ScanMetaUpdate,
    request: Request,
    lang: LangQuery = None,
    db: Session = Depends(get_db),
):
    """Met à jour les tags et/ou les notes d'un scan."""
    scan = _get_scan_or_404(db, scan_id)
    if body.tags is not None:
        scan.tags = body.tags
    if body.notes is not None:
        scan.notes = body.notes
    db.commit()
    db.refresh(scan)
    return JSONResponse(render(scan_payload(scan), request_lang(request)))
