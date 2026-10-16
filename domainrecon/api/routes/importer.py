# =============================================================================
# DomainRecon - API : import d'une ancienne base DomainRecon
# =============================================================================
# POST /api/import   multipart/form-data, un seul champ « file » : l'ancienne base SQLite (.db)
#   200  {"read", "imported", "ignored", "duplicates", "unusable", "unknown_columns"}
#   400  api.import_no_file, api.multipart_invalid, api.import_not_sqlite, api.import_not_domainrecon
#   403  api.local_only (autre machine), api.cross_origin (autre origine)
#   409  api.import_running      413  api.import_too_large
#   415  api.multipart_required  500  api.import_failed
#
# Réservée aux requêtes locales (comme POST /api/system/open-data-dir) et à l'interface de
# l'application (même origine : un formulaire d'un site tiers peut envoyer du multipart sans
# préflight, contrairement au JSON). Le fichier est lu en flux dans un dossier temporaire
# (api/multipart.py : Starlette lirait le formulaire avec python-multipart, absent des
# dépendances), vérifié (en-tête SQLite, table « scans »), puis importé par la logique de
# `domainrecon import` (cli/importer.py : doublons ignorés, l'import peut être relancé). Le
# dossier temporaire est supprimé dans tous les cas. Un import à la fois.
# =============================================================================

import logging
import math
import shutil
import tempfile
import threading
from pathlib import Path

from fastapi import APIRouter, Depends, Request
from fastapi.concurrency import run_in_threadpool
from pydantic import BaseModel, Field
from sqlalchemy.exc import SQLAlchemyError
from starlette.requests import ClientDisconnect

from ...cli import importer as cli_importer
from ...i18n import msg
from ..errors import ApiError
from ..multipart import MultipartError, MultipartParser, PartData, PartEnd, PartStart, boundary_of
from ..schemas import LangQuery
from ..security import require_local_client, require_same_origin

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api", tags=["API"])

# Chemin de la route (la limite du corps de la requête est propre à ce chemin : api/app.py).
IMPORT_PATH = "/api/import"
# Nom du champ du formulaire qui porte la base.
FORM_FIELD = "file"
# Taille maximale de la base envoyée, et marge pour l'enveloppe du formulaire (frontières, en-têtes).
MAX_IMPORT_BYTES = 512 * 1024 * 1024
FORM_OVERHEAD_BYTES = 64 * 1024
# Colonnes inconnues rapportées dans la réponse : nombre et longueur (leurs noms viennent du fichier envoyé).
MAX_UNKNOWN_COLUMNS = 50
MAX_COLUMN_NAME_LENGTH = 64
TEMP_PREFIX = "domainrecon-import-"

# Un seul import à la fois : deux imports simultanés du même fichier se croiseraient (doublons).
_import_lock = threading.Lock()


class ImportResult(BaseModel):
    """Bilan d'un import : `read` = `imported` + `ignored`, et `ignored` = `duplicates` + `unusable`."""

    read: int = Field(description="Scans lus dans la base envoyée")
    imported: int = Field(description="Scans ajoutés à l'historique")
    ignored: int = Field(description="Scans non importés : doublons et lignes inexploitables")
    duplicates: int = Field(description="Scans déjà présents (même domaine, même horodatage)")
    unusable: int = Field(description="Lignes sans domaine ni horodatage lisible")
    unknown_columns: list[str] = Field(
        description="Colonnes de l'ancienne base sans équivalent, non reprises"
    )


def _too_large() -> dict:
    return msg("api.import_too_large", max=max(1, math.ceil(MAX_IMPORT_BYTES / (1024 * 1024))))


def upload_limit() -> tuple[int, object]:
    """Limite du corps de POST /api/import (BodySizeLimitMiddleware) : la base et l'enveloppe du formulaire."""
    return MAX_IMPORT_BYTES + FORM_OVERHEAD_BYTES, _too_large()


async def _receive_file(request: Request, boundary: bytes, target: Path) -> None:
    """Écrit dans `target` la partie « file » du formulaire reçu en flux ; une erreur de l'API sinon.

    Les autres parties sont lues pour rien (jetées). Le formulaire doit être complet : un envoi coupé
    est refusé, jamais importé à moitié.
    """
    parser = MultipartParser(boundary)
    found = False
    receiving = False  # la partie en cours est le fichier
    written = 0
    try:
        with target.open("wb") as sink:
            async for chunk in request.stream():
                for event in parser.feed(chunk):
                    if isinstance(event, PartStart):
                        receiving = event.name == FORM_FIELD
                        if receiving and found:
                            raise MultipartError("fichier envoyé deux fois")
                        found = found or receiving
                    elif isinstance(event, PartData) and receiving:
                        written += len(event.data)
                        if written > MAX_IMPORT_BYTES:
                            raise ApiError(413, _too_large())
                        await run_in_threadpool(sink.write, event.data)
                    elif isinstance(event, PartEnd):
                        receiving = False
            parser.finish()
    except (MultipartError, ClientDisconnect) as exc:
        raise ApiError(400, msg("api.multipart_invalid")) from exc
    except OSError as exc:
        logger.error("Import : écriture du fichier temporaire impossible (%s)", exc)
        raise ApiError(500, msg("api.import_failed")) from exc
    if not found:
        raise ApiError(400, msg("api.import_no_file"))


async def _import(target: Path) -> cli_importer.ImportStats:
    """Importe la base reçue dans un fil (lecture et écritures SQLite) ; les refus deviennent des erreurs de l'API."""
    try:
        return await run_in_threadpool(cli_importer.import_scans, target)
    except cli_importer.ImportSourceError as exc:
        if exc.reason == cli_importer.REASON_NOT_SQLITE:
            raise ApiError(400, msg("api.import_not_sqlite")) from exc
        raise ApiError(400, msg("api.import_not_domainrecon")) from exc
    except SQLAlchemyError:
        raise  # base occupée ou en erreur : gestionnaire commun (503 ou 500), sans détail pour le client
    except Exception as exc:
        logger.exception("Import d'une ancienne base : échec")
        raise ApiError(500, msg("api.import_failed")) from exc


@router.post(
    "/import",
    response_model=ImportResult,
    dependencies=[Depends(require_local_client), Depends(require_same_origin)],
    openapi_extra={
        "requestBody": {
            "required": True,
            "content": {
                "multipart/form-data": {
                    "schema": {
                        "type": "object",
                        "properties": {
                            FORM_FIELD: {
                                "type": "string",
                                "format": "binary",
                                "description": "Ancienne base DomainRecon (fichier SQLite .db)",
                            }
                        },
                        "required": [FORM_FIELD],
                    }
                }
            },
        }
    },
    responses={
        400: {
            "description": "Aucun fichier, formulaire illisible, ou fichier qui n'est pas une base DomainRecon"
        },
        403: {
            "description": "Requête venue d'une autre machine (api.local_only) ou d'une autre origine (api.cross_origin)"
        },
        409: {"description": "Un import est déjà en cours (api.import_running)"},
        413: {"description": "Fichier trop volumineux (api.import_too_large)"},
        415: {"description": "Corps qui n'est pas du multipart/form-data (api.multipart_required)"},
        500: {"description": "Import échoué (api.import_failed)"},
    },
)
async def import_database(request: Request, lang: LangQuery = None):
    """Importe les scans d'une ancienne base DomainRecon envoyée en `multipart/form-data` (champ `file`).

    La base est copiée dans un fichier temporaire, vérifiée (fichier SQLite avec une table `scans`),
    puis ses scans sont ajoutés à l'historique : un scan déjà présent (même domaine, même horodatage)
    est ignoré, l'import peut donc être relancé. Les captures d'écran ne sont pas importées.
    Réservé aux requêtes locales, issues de l'interface de l'application.
    """
    boundary = boundary_of(request.headers.get("content-type"))
    if boundary is None:
        raise ApiError(415, msg("api.multipart_required"))
    if not _import_lock.acquire(blocking=False):
        raise ApiError(409, msg("api.import_running"))
    try:
        try:
            folder = Path(tempfile.mkdtemp(prefix=TEMP_PREFIX))
        except OSError as exc:
            logger.error("Import : dossier temporaire impossible à créer (%s)", exc)
            raise ApiError(500, msg("api.import_failed")) from exc
        try:
            target = folder / "import.db"
            await _receive_file(request, boundary, target)
            stats = await _import(target)
        finally:
            # Le fichier reçu, quelle que soit l'issue (la base source est fermée avant : Windows).
            shutil.rmtree(folder, ignore_errors=True)
    finally:
        _import_lock.release()
    logger.info(
        "Import d'une ancienne base : %s scan(s) lu(s), %s importé(s), %s ignoré(s)",
        stats.read,
        stats.imported,
        stats.duplicates + stats.ignored,
    )
    return ImportResult(
        read=stats.read,
        imported=stats.imported,
        ignored=stats.duplicates + stats.ignored,
        duplicates=stats.duplicates,
        unusable=stats.ignored,
        unknown_columns=[name[:MAX_COLUMN_NAME_LENGTH] for name in stats.unknown[:MAX_UNKNOWN_COLUMNS]],
    )
