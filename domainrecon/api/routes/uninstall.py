# =============================================================================
# DomainRecon - API : sauvegarde de la base et désinstallation complète
# =============================================================================
# POST /api/system/backup              {}  -> copie cohérente de la base SQLite (.db),
#                                      réimportable par POST /api/import
#   409 api.backup_unavailable (base PostgreSQL, ou absente)
# POST /api/system/uninstall           {"dry_run": true} -> ce qui serait supprimé, sans rien toucher
#                                      {"confirm": "SUPPRIMER", "remove_program": false} -> désinstalle
#   400 api.uninstall_confirm (mot de confirmation absent ou faux)
#   409 api.uninstall_running (désinstallation déjà en cours)
# POST /api/system/uninstall/finish    {}  -> ferme l'application (après une désinstallation)
#   409 api.uninstall_not_done
# Toutes : corps JSON (415 sinon), requête locale seulement (403 api.local_only).
#
# Après une vraie désinstallation, l'API ne répond plus que 410 (api.uninstalled),
# sauf battement et fermeture : une requête qui rouvrirait la base la recréerait
# vide dans le dossier qui vient d'être supprimé (UninstalledGuardMiddleware).
# =============================================================================

import asyncio
import logging
import os
import sqlite3
import tempfile
import threading
from datetime import datetime
from pathlib import Path

from fastapi import APIRouter, Depends, Request
from fastapi.concurrency import run_in_threadpool
from fastapi.responses import FileResponse
from pydantic import BaseModel, Field
from starlette.background import BackgroundTask
from starlette.types import ASGIApp, Receive, Scope, Send

from ...core import config
from ...desktop import uninstall
from ...i18n import msg
from ..errors import ApiError, error_response, scope_lang
from ..schemas import LangQuery
from ..security import _route_path, is_api_path, require_json_body, require_local_client

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api", tags=["API"])

# Routes encore servies après la désinstallation.
AFTER_UNINSTALL_PATHS = frozenset({"/api/system/uninstall/finish", "/api/system/heartbeat"})
# Délai avant la fermeture demandée (secondes) : la réponse part d'abord.
EXIT_DELAY = 0.5
BACKUP_PREFIX = "domainrecon-backup-"

_lock = threading.Lock()

_LOCAL_JSON = [Depends(require_json_body), Depends(require_local_client)]
_LOCAL_RESPONSES = {
    403: {"description": "Requête venue d'une autre machine (api.local_only)"},
    415: {"description": "Corps non JSON"},
}


class UninstallRequest(BaseModel):
    """Corps de POST /api/system/uninstall."""

    dry_run: bool = Field(False, description="Lister seulement ce qui serait supprimé")
    confirm: str | None = Field(
        None, max_length=32, description="Mot de confirmation : SUPPRIMER (ou DELETE)"
    )
    remove_program: bool = Field(
        False, description="Versions portables : supprimer aussi le programme après la fermeture"
    )


class UninstalledGuardMiddleware:
    """Après la désinstallation, refuse (410) toute requête /api hors AFTER_UNINSTALL_PATHS."""

    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] == "http" and "app" in scope and getattr(scope["app"].state, "uninstalled", False):
            path = _route_path(scope)
            if is_api_path(path) and path not in AFTER_UNINSTALL_PATHS:
                response = error_response(410, msg("api.uninstalled"), scope_lang(scope))
                await response(scope, receive, send)
                return
        await self.app(scope, receive, send)


# =============================================================================
# Sauvegarde
# =============================================================================


def _backup_source() -> Path | None:
    database = uninstall._sqlite_path(config.DATABASE_URL)
    return database if database is not None and database.is_file() else None


def _make_backup(source: Path) -> Path:
    """Copie cohérente de la base (API de sauvegarde de SQLite, même pendant une écriture)."""
    fd, name = tempfile.mkstemp(prefix=BACKUP_PREFIX, suffix=".db")
    target = Path(name)
    os.close(fd)
    try:
        src = sqlite3.connect(f"file:{source.as_posix()}?mode=ro", uri=True)
        try:
            dst = sqlite3.connect(target)
            try:
                src.backup(dst)
            finally:
                dst.close()
        finally:
            src.close()
    except BaseException:
        target.unlink(missing_ok=True)
        raise
    return target


@router.post(
    "/system/backup",
    dependencies=_LOCAL_JSON,
    response_class=FileResponse,
    responses={
        **_LOCAL_RESPONSES,
        200: {"content": {"application/vnd.sqlite3": {}}, "description": "Base SQLite"},
        409: {"description": "Pas de base SQLite à sauvegarder (api.backup_unavailable)"},
    },
)
async def backup(lang: LangQuery = None):
    """Télécharge une copie de la base (historique, surveillances, réglages), réimportable par POST /api/import."""
    source = _backup_source()
    if source is None:
        raise ApiError(409, msg("api.backup_unavailable"))
    try:
        copy = await run_in_threadpool(_make_backup, source)
    except (OSError, sqlite3.Error) as e:
        logger.error("Sauvegarde de %s impossible : %s", source, e)
        raise ApiError(500, msg("api.backup_failed")) from e
    filename = f"domainrecon-sauvegarde-{datetime.now():%Y%m%d-%H%M%S}.db"
    return FileResponse(
        copy,
        media_type="application/vnd.sqlite3",
        filename=filename,
        background=BackgroundTask(copy.unlink, missing_ok=True),
    )


# =============================================================================
# Désinstallation
# =============================================================================


async def _stop_activity(request: Request) -> None:
    """Arrête la surveillance, les lots et les scans, puis ferme la base (connexions du pool)."""
    from ...core.database import engine
    from ...monitor import routes as monitor_routes
    from . import jobs

    state = request.app.state
    scheduler = getattr(state, "scheduler", None)
    if scheduler is not None:
        await scheduler.stop()
        state.scheduler = None
    await monitor_routes.batch_manager.cancel_all()
    await jobs.manager.cancel_all()
    await run_in_threadpool(engine.dispose)


@router.post(
    "/system/uninstall",
    dependencies=_LOCAL_JSON,
    responses={
        **_LOCAL_RESPONSES,
        400: {"description": "Mot de confirmation absent ou faux (api.uninstall_confirm)"},
        409: {"description": "Désinstallation déjà en cours (api.uninstall_running)"},
    },
)
async def uninstall_app(body: UninstallRequest, request: Request, lang: LangQuery = None):
    """Désinstallation complète (ou, avec dry_run, la liste de ce qui serait supprimé).

    Arrête la surveillance et retire la tâche système, ferme la base, supprime données,
    clés, réglages, caches et temporaires de DomainRecon, puis prépare ce qui ne peut se
    faire qu'après la fermeture (désinstalleur Windows, programme portable, fichiers
    verrouillés). La réponse détaille chaque élément et les étapes restantes.
    """
    ctx = uninstall.context_factory()
    if body.dry_run:
        report = await run_in_threadpool(uninstall.plan, ctx)
        report["can_exit"] = callable(getattr(request.app.state, "exit_app", None))
        return report
    if (body.confirm or "").strip().upper() not in uninstall.CONFIRM_WORDS:
        raise ApiError(400, msg("api.uninstall_confirm"))
    if not _lock.acquire(blocking=False):
        raise ApiError(409, msg("api.uninstall_running"))
    try:
        logger.warning("Désinstallation complète demandée (mode %s, données %s)", ctx.mode, ctx.data_dir)
        if not ctx.isolated:
            await _stop_activity(request)
        report = await run_in_threadpool(uninstall.execute, ctx, remove_program=body.remove_program)
        if not ctx.isolated:
            request.app.state.uninstalled = True
            from ...core import crypto

            crypto._fernet_for.cache_clear()
        request.app.state.uninstall_done = True
    finally:
        _lock.release()
    report["can_exit"] = callable(getattr(request.app.state, "exit_app", None))
    return report


@router.post(
    "/system/uninstall/finish",
    dependencies=_LOCAL_JSON,
    responses={
        **_LOCAL_RESPONSES,
        409: {"description": "Aucune désinstallation faite (api.uninstall_not_done)"},
    },
)
async def finish(request: Request, lang: LangQuery = None):
    """Ferme l'application après la désinstallation ; {"exiting": false} si elle ne sait pas se fermer seule."""
    state = request.app.state
    if not getattr(state, "uninstall_done", False):
        raise ApiError(409, msg("api.uninstall_not_done"))
    exit_app = getattr(state, "exit_app", None)
    if not callable(exit_app):
        return {"exiting": False}

    async def later() -> None:
        await asyncio.sleep(EXIT_DELAY)
        try:
            exit_app()
        except Exception as e:  # fermeture impossible : l'utilisateur fermera la fenêtre
            logger.warning("Fermeture de l'application impossible : %s", e)

    task = asyncio.get_running_loop().create_task(later())
    state.exit_task = task  # référence gardée : la tâche n'est pas ramassée avant son exécution
    return {"exiting": True}
