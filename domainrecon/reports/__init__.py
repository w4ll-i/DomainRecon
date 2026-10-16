# =============================================================================
# DomainRecon - Rapports d'un scan enregistré
# =============================================================================
# generate(payload, format, lang) produit le rapport d'un scan dans l'un des
# formats de FORMATS (export de l'API, commande `domainrecon export`) ; « text »
# est un rendu de terminal réservé à la ligne de commande. `payload` est celui de
# l'API (api.routes.scans.scan_payload, messages non rendus) : load_payload(id)
# le lit en base. Le PDF passe par Chromium (asynchrone : generate_async) et lève
# PdfUnavailableError si le navigateur manque.
# =============================================================================

from __future__ import annotations

import asyncio
import base64
import re
from typing import NamedTuple

from .labels import norm_lang
from .markdown import to_markdown, to_text
from .model import build_report_data
from .pdf import PdfUnavailableError, html_to_pdf
from .structured import to_csv, to_json, to_junit, to_sarif
from .webpage import to_html

__all__ = [
    "CLI_FORMATS",
    "FORMATS",
    "PdfUnavailableError",
    "Report",
    "export_filename",
    "generate",
    "generate_async",
    "generate_sync",
    "load_payload",
]

FORMATS = ("json", "csv", "md", "html", "pdf", "sarif", "junit")
CLI_FORMATS = ("text", *FORMATS)

# Taille maximale d'une capture d'écran incluse dans la page.
MAX_SCREENSHOT_BYTES = 3 * 1024 * 1024

_SPECS: dict[str, tuple[str, str]] = {
    # format: (type MIME, extension)
    "json": ("application/json; charset=utf-8", "json"),
    "csv": ("text/csv; charset=utf-8", "csv"),
    "md": ("text/markdown; charset=utf-8", "md"),
    "html": ("text/html; charset=utf-8", "html"),
    "pdf": ("application/pdf", "pdf"),
    "sarif": ("application/sarif+json", "sarif"),
    "junit": ("application/xml; charset=utf-8", "xml"),
    "text": ("text/plain; charset=utf-8", "txt"),
}


class Report(NamedTuple):
    content: bytes
    mime: str
    extension: str
    format: str


def _check_format(fmt: str) -> None:
    if fmt not in CLI_FORMATS:
        raise ValueError(f"Format inconnu : {fmt!r} ({', '.join(CLI_FORMATS)})")


def load_payload(scan_id: int) -> dict | None:
    """Charge utile d'un scan enregistré (None s'il n'existe pas)."""
    # Import local : les routes importent ce paquet.
    from ..api.routes.scans import scan_payload
    from ..core.database import SessionLocal
    from ..core.models import Scan

    with SessionLocal() as db:
        scan = db.get(Scan, scan_id)
        return scan_payload(scan) if scan is not None else None


def screenshot_data_uri(payload: dict) -> str | None:
    """Capture d'écran du scan en data: URI PNG, si le fichier existe et reste raisonnable."""
    from ..api.storage import _screenshot_file

    path = _screenshot_file(payload.get("screenshot_path"))
    try:
        if path is None or not path.is_file() or path.stat().st_size > MAX_SCREENSHOT_BYTES:
            return None
        return "data:image/png;base64," + base64.b64encode(path.read_bytes()).decode("ascii")
    except OSError:
        return None


def _text_report(payload: dict, fmt: str, lang: str, with_screenshot: bool) -> str:
    data = build_report_data(payload, lang, screenshot_data_uri(payload) if with_screenshot else None)
    if fmt == "json":
        return to_json(payload, data)
    if fmt == "csv":
        return to_csv(data)
    if fmt == "md":
        return to_markdown(data)
    if fmt in ("html", "pdf"):
        return to_html(data)
    if fmt == "sarif":
        return to_sarif(data)
    if fmt == "junit":
        return to_junit(data)
    return to_text(data)


def _report(text: str, fmt: str) -> Report:
    mime, extension = _SPECS[fmt]
    # CSV avec BOM : Excel lit alors correctement les accents.
    encoding = "utf-8-sig" if fmt == "csv" else "utf-8"
    return Report(text.encode(encoding), mime, extension, fmt)


def generate(payload: dict, fmt: str, lang: str = "fr") -> Report:
    """Rapport d'un scan dans le format demandé (tous sauf le PDF ; voir generate_async)."""
    _check_format(fmt)
    if fmt == "pdf":
        raise ValueError("Le PDF est asynchrone : utiliser generate_async()")
    return _report(_text_report(payload, fmt, norm_lang(lang), fmt == "html"), fmt)


async def generate_async(payload: dict, fmt: str, lang: str = "fr") -> Report:
    """Comme generate(), PDF compris (PdfUnavailableError si Chromium manque)."""
    _check_format(fmt)
    if fmt != "pdf":
        return generate(payload, fmt, lang)
    html = _text_report(payload, "pdf", norm_lang(lang), True)
    mime, extension = _SPECS["pdf"]
    return Report(await html_to_pdf(html), mime, extension, "pdf")


def generate_sync(payload: dict, fmt: str, lang: str = "fr") -> Report:
    """Version synchrone pour la ligne de commande."""
    if fmt == "pdf":
        return asyncio.run(generate_async(payload, fmt, lang))
    return generate(payload, fmt, lang)


def export_filename(payload: dict, fmt: str) -> str:
    """Nom de fichier de l'export : domainrecon-<domaine>-<id>.<extension>."""
    _check_format(fmt)
    domain = re.sub(r"[^A-Za-z0-9._-]", "_", str(payload.get("domain") or "scan"))[:100]
    return f"domainrecon-{domain}-{payload.get('id')}.{_SPECS[fmt][1]}"
