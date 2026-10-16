# =============================================================================
# DomainRecon - API : service de l'interface construite (application monopage)
# =============================================================================
# Le frontend (React + Vite) est construit dans domainrecon/web : index.html,
# assets/ (fichiers à empreinte, en cache sans limite) et les fichiers publics
# à la racine (favicon…). Toute route GET hors /api rend index.html (routage
# côté navigateur) ; un chemin /api inconnu reste un 404 JSON ; un asset
# absent est un 404, jamais index.html. Sans build, « / » renvoie une
# indication en JSON.
#
# Types MIME fixés ici, jamais demandés à `mimetypes` : sous Windows, il lit
# le registre et peut annoncer text/plain pour .js, ce qui, avec
# X-Content-Type-Options: nosniff, bloque le script (écran blanc).
# =============================================================================

import re
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.responses import FileResponse, JSONResponse, Response

from ..core import paths
from ..i18n import msg, render
from .errors import ApiError, request_lang
from .security import _route_path, is_api_path

# Commande qui construit l'interface (indiquée quand elle manque).
FRONTEND_HINT = "cd frontend && npm run build"
# Fichiers à empreinte (Vite) : jamais modifiés, cache d'un an.
IMMUTABLE_CACHE = "public, max-age=31536000, immutable"
# index.html, fichiers publics et assets sans empreinte : toujours revalidés.
REVALIDATE_CACHE = "no-cache"
# Nom haché par Vite : « index-CvILnM5j.js », « inter-latin-400-normal-C38fXH4l.woff2 »
# (empreinte de 8 caractères avant l'extension).
_HASHED_NAME = re.compile(r"-[A-Za-z0-9_-]{8}\.[A-Za-z0-9]+")

MEDIA_TYPES = {
    ".html": "text/html",
    ".js": "text/javascript",
    ".mjs": "text/javascript",
    ".css": "text/css",
    ".json": "application/json",
    ".map": "application/json",
    ".webmanifest": "application/manifest+json",
    ".svg": "image/svg+xml",
    ".png": "image/png",
    ".jpg": "image/jpeg",
    ".jpeg": "image/jpeg",
    ".gif": "image/gif",
    ".webp": "image/webp",
    ".ico": "image/x-icon",
    ".woff": "font/woff",
    ".woff2": "font/woff2",
    ".ttf": "font/ttf",
    ".txt": "text/plain",
}
_DEFAULT_MEDIA_TYPE = "application/octet-stream"


def _confined_file(base: Path, relative: str) -> Path | None:
    """Fichier `relative` de `base` ; None s'il sort du dossier, est caché ou n'existe pas."""
    if not relative or "\\" in relative or "\0" in relative:
        return None
    if any(part in ("", ".", "..") or part.startswith(".") for part in relative.split("/")):
        return None
    root = base.resolve()
    candidate = (root / relative).resolve()
    if not candidate.is_relative_to(root) or not candidate.is_file():
        return None
    return candidate


def _file_response(path: Path, cache_control: str) -> FileResponse:
    media_type = MEDIA_TYPES.get(path.suffix.lower(), _DEFAULT_MEDIA_TYPE)
    return FileResponse(path, media_type=media_type, headers={"Cache-Control": cache_control})


def _asset_cache_control(path: Path) -> str:
    """Cache d'un an pour un fichier haché (contenu figé par son nom), revalidation sinon."""
    return IMMUTABLE_CACHE if _HASHED_NAME.search(path.name) else REVALIDATE_CACHE


def index_response(request: Request) -> Response:
    """index.html de l'interface, ou une indication JSON si elle n'est pas construite."""
    index = paths.web_dir() / "index.html"
    if index.is_file():
        return _file_response(index, REVALIDATE_CACHE)
    message = render(msg("api.frontend_missing"), request_lang(request))
    return JSONResponse({"message": message, "hint": FRONTEND_HINT})


def spa_fallback(request: Request) -> Response | None:
    """Route GET inconnue hors /api : fichier public s'il existe, sinon index.html ; None pour /api."""
    path = _route_path(request.scope)
    if request.method not in ("GET", "HEAD") or is_api_path(path):
        return None
    public_file = _confined_file(paths.web_dir(), path.lstrip("/"))
    if public_file is not None:
        return _file_response(public_file, REVALIDATE_CACHE)
    return index_response(request)


def register_spa(app: FastAPI) -> None:
    """Routes de l'interface ; le repli SPA passe par le gestionnaire 404 (api/errors.py)."""

    @app.api_route("/", methods=["GET", "HEAD"], include_in_schema=False)
    async def serve_index(request: Request):
        return index_response(request)

    @app.api_route("/assets/{name:path}", methods=["GET", "HEAD"], include_in_schema=False)
    async def serve_asset(name: str):
        asset = _confined_file(paths.web_dir() / "assets", name)
        if asset is None:
            # Jamais index.html à la place d'un script : type MIME faux, écran blanc.
            raise ApiError(404, msg("api.not_found"))
        return _file_response(asset, _asset_cache_control(asset))

    app.state.spa_fallback = spa_fallback
