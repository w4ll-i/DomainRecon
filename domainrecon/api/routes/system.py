# =============================================================================
# DomainRecon - API : état du service, captures d'écran et statut du VPN
# =============================================================================

import logging
import os
import subprocess
import sys
import time
from pathlib import Path

from fastapi import APIRouter, Depends, Request, Response
from fastapi.responses import FileResponse, JSONResponse
from pydantic import BaseModel
from sqlalchemy import text
from sqlalchemy.orm import Session

from ...core import config, paths
from ...core.config import APP_VERSION
from ...core.database import get_db
from ...i18n import msg, render
from ...scanner import vpn
from .. import storage
from ..errors import ApiError, request_lang
from ..schemas import LangQuery
from ..security import require_json_body, require_local_client

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api", tags=["API"])


# Sans jeton (PUBLIC_PATHS) : `security` vide dans le schéma OpenAPI.
@router.get("/health", openapi_extra={"security": []})
def health_check(db: Session = Depends(get_db)):
    """État de l'API et de la base : 503 si la base est inaccessible."""
    try:
        db.execute(text("SELECT 1"))
    except Exception as e:
        logger.error("Base de données injoignable : %s", e)
        return JSONResponse({"api": "degraded", "database": "error", "version": APP_VERSION}, status_code=503)
    # Appel par le module : les tests remplacent storage._database_writable.
    if not storage._database_writable():
        logger.error("Base de données en lecture seule : les scans ne pourront pas être enregistrés")
        return JSONResponse(
            {"api": "degraded", "database": "read-only", "version": APP_VERSION}, status_code=503
        )
    return {"api": "healthy", "database": "connected", "version": APP_VERSION}


@router.get("/screenshot/{filename}")
def serve_screenshot(filename: str):
    """Sert une capture d'écran.

    Le nom de fichier vient de l'URL : il est validé puis confiné au dossier
    des captures avant toute lecture, sinon un nom comme `..\\..\\.env`
    sortirait du dossier (les séparateurs Windows ne sont pas normalisés par
    le routeur).
    """
    filepath = storage._screenshot_file(filename)
    if filepath is None or not filepath.is_file():
        raise ApiError(404, msg("api.screenshot_not_found"))
    return FileResponse(str(filepath), media_type="image/png")


def _open_folder(path: Path) -> None:
    """Ouvre un dossier dans le gestionnaire de fichiers du système."""
    path.mkdir(parents=True, exist_ok=True)
    if sys.platform == "win32":
        os.startfile(path)
    elif sys.platform == "darwin":
        subprocess.Popen(["open", str(path)])
    else:
        subprocess.Popen(["xdg-open", str(path)])


@router.get("/system/info")
def system_info():
    """Version et emplacement des données (écran Réglages)."""
    return {
        "version": APP_VERSION,
        "data_dir": str(config.DATA_DIR),
        "portable": paths.is_portable(),
        "frozen": paths.is_frozen(),
        # Documentation interactive active (API_DOCS) : l'interface n'affiche son lien que dans ce cas.
        "docs_enabled": config.API_DOCS_ENABLED,
    }


class VpnStatusResponse(BaseModel):
    """Statut du VPN Mullvad ; `connected` vaut null si le statut n'a pas pu être lu."""

    connected: bool | None
    ip: str | None
    country: str | None
    provider: str | None
    mullvad_cli: bool
    # Phrase dans la langue de la requête (?lang= ou Accept-Language).
    message: str


# def : le CLI Mullvad et am.i.mullvad.net sont interrogés dans le pool de threads.
@router.get("/system/vpn", response_model=VpnStatusResponse)
def vpn_status(request: Request, lang: LangQuery = None):
    """Statut du VPN Mullvad, en lecture seule (aucune connexion ni déconnexion).

    Avec le CLI Mullvad installé, la réponse vient de « mullvad status » ; sinon,
    de am.i.mullvad.net, interrogé sans proxy. Répond toujours 200 : un statut
    illisible donne `connected: null` et la cause dans `message`.
    """
    # Appel par le module : les tests remplacent vpn.get_vpn_status.
    status = vpn.get_vpn_status()
    error = status.pop("error")
    if status["connected"] is None:
        message = msg("api.vpn_unknown", reason=error)
    elif status["connected"]:
        message = msg("api.vpn_connected")
    else:
        message = msg("api.vpn_disconnected")
    return {**status, "message": render(message, request_lang(request))}


@router.post(
    "/system/open-data-dir",
    status_code=204,
    # Le corps JSON est vérifié d'abord (415), puis la provenance de la requête (403).
    dependencies=[Depends(require_json_body), Depends(require_local_client)],
    responses={
        403: {"description": "Requête venue d'une autre machine"},
        415: {"description": "Corps non JSON"},
        500: {"description": "Gestionnaire de fichiers indisponible (api.open_failed)"},
    },
)
def open_data_dir(lang: LangQuery = None):
    """Ouvre le dossier des données sur la machine du serveur (bouton « Ouvrir » des Réglages)."""
    # Appel par le module : les tests remplacent _open_folder.
    try:
        _open_folder(config.DATA_DIR)
    except Exception as e:
        # xdg-open absent, accès refusé, dossier impossible à créer… : une erreur
        # explicite (avec le chemin à ouvrir à la main), jamais un 500 générique.
        logger.error("Ouverture du dossier %s impossible : %s", config.DATA_DIR, e)
        raise ApiError(500, msg("api.open_failed", path=str(config.DATA_DIR))) from e
    return Response(status_code=204)


# async : une simple écriture, sans passer par le pool de threads.
@router.post(
    "/system/heartbeat",
    status_code=204,
    dependencies=[Depends(require_json_body)],
    responses={415: {"description": "Corps non JSON"}},
)
async def heartbeat(request: Request):
    """Battement de l'interface (corps : {} en JSON), envoyé toutes les 30 s par chaque onglet ouvert.

    En mode navigateur, le lanceur arrête le serveur environ 2 minutes après le
    dernier battement (desktop/launcher.py, IdleWatchdog) : l'horodatage, en
    horloge monotone, est rangé dans app.state.last_heartbeat.
    """
    request.app.state.last_heartbeat = time.monotonic()
    return Response(status_code=204)
