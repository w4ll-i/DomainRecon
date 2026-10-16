# =============================================================================
# DomainRecon - API : export du rapport d'un scan
# =============================================================================
# GET /api/scan/{id}/export?format=json|csv|md|html|pdf|sarif|junit&lang=fr|en
# renvoie le rapport en pièce jointe (type MIME et nom de fichier adaptés).
# Générateur : domainrecon/reports. Le PDF exige le Chromium de Playwright (503
# s'il manque). Voir aussi la commande `domainrecon export`.
# =============================================================================

from typing import Literal

from fastapi import APIRouter, Query, Request
from fastapi.concurrency import run_in_threadpool
from fastapi.responses import Response

from ... import reports
from ...i18n import msg
from ..errors import ApiError, request_lang
from ..schemas import LangQuery, ScanId

router = APIRouter(prefix="/api", tags=["API"])

ExportFormat = Literal["json", "csv", "md", "html", "pdf", "sarif", "junit"]


@router.get(
    "/scan/{scan_id}/export",
    response_class=Response,
    responses={
        200: {"description": "Rapport en pièce jointe", "content": {"application/octet-stream": {}}},
        404: {"description": "Scan introuvable"},
        503: {"description": "PDF indisponible : Chromium (Playwright) n'est pas installé"},
    },
)
async def export_scan(
    scan_id: ScanId,
    request: Request,
    format: ExportFormat = Query(..., description="Format du rapport"),
    lang: LangQuery = None,
):
    """Rapport d'un scan enregistré dans le format demandé, textes dans la langue demandée."""
    language = request_lang(request)
    payload = await run_in_threadpool(reports.load_payload, scan_id)
    if payload is None:
        raise ApiError(404, msg("api.scan_not_found"))
    try:
        if format == "pdf":
            report = await reports.generate_async(payload, format, language)
        else:
            report = await run_in_threadpool(reports.generate, payload, format, language)
    except reports.PdfUnavailableError as e:
        raise ApiError(503, msg("api.export_pdf_unavailable")) from e
    filename = reports.export_filename(payload, format)
    return Response(
        content=report.content,
        media_type=report.mime,
        headers={
            "Content-Disposition": f'attachment; filename="{filename}"',
            "Cache-Control": "no-store",
        },
    )
