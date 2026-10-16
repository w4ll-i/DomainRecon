# =============================================================================
# DomainRecon - API FastAPI
# =============================================================================
# Sert l'API sous /api et l'interface à la racine /. Routes : routes/ ;
# middlewares : security.py ; erreurs : errors.py ; stockage : storage.py ; interface : spa.py.
# =============================================================================

import logging
import time
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.concurrency import run_in_threadpool
from starlette.types import ASGIApp, Receive, Scope, Send

from ..core import config
from ..core.config import APP_VERSION
from ..monitor import routes as monitor_routes
from ..monitor.scheduler import create_scheduler, scheduler_enabled
from ..notify import routes as notify_routes
from . import storage
from .errors import install_error_handlers
from .routes import export, history, importer, jobs, modules, scans, settings, system, uninstall
from .security import (
    MAX_REQUEST_BODY_BYTES,
    ApiTokenMiddleware,
    BodySizeLimitMiddleware,
    ConfiguredCORSMiddleware,
    ConfiguredTrustedHostMiddleware,
    SecurityHeadersMiddleware,
    _route_path,
    is_api_path,
)
from .spa import register_spa

config.configure_logging()
logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Prépare la base et le stockage au démarrage (hors boucle d'événements) ; annule les scans à l'arrêt."""
    # Cause d'un échec du démarrage, lue par le lanceur (desktop/launcher.py) :
    # uvicorn arrête alors son thread sans lever d'exception.
    app.state.startup_error = None
    # Chaque démarrage du serveur repart sans battement de l'interface ni requête.
    app.state.last_heartbeat = None
    app.state.last_api_activity = None
    app.state.scheduler = None
    try:
        await run_in_threadpool(storage.prepare_storage)
    except Exception as exc:
        app.state.startup_error = exc
        raise
    logger.info("DomainRecon %s prêt", APP_VERSION)
    # Planificateur de la surveillance : lance les scans échus tant que l'application est ouverte.
    if scheduler_enabled():
        app.state.scheduler = create_scheduler(jobs.manager)
        app.state.scheduler.start()
    try:
        yield
    finally:
        if app.state.scheduler is not None:
            await app.state.scheduler.stop()
        await monitor_routes.batch_manager.cancel_all()
        # Fermeture de la fenêtre ou Ctrl+C en plein scan : les tâches sont
        # annulées au lieu de poursuivre leurs modules pendant l'arrêt.
        cancelled = await jobs.manager.cancel_all()
        if cancelled:
            logger.info("%s scan(s) en cours annulé(s) à l'arrêt", cancelled)


app = FastAPI(
    title="DomainRecon API",
    description="API OSINT pour la reconnaissance de domaines",
    version=APP_VERSION,
    lifespan=lifespan,
    docs_url="/api/docs" if config.API_DOCS_ENABLED else None,
    redoc_url="/api/redoc" if config.API_DOCS_ENABLED else None,
    openapi_url="/api/openapi.json" if config.API_DOCS_ENABLED else None,
)

# État lu par le lanceur pour l'arrêt automatique du mode navigateur
# (desktop/launcher.py, IdleWatchdog) : dernier battement de l'interface
# (horloge monotone, None avant le premier ; POST /api/system/heartbeat),
# dernière requête de l'API (ApiActivityMiddleware) et gestionnaire des scans
# en cours.
app.state.last_heartbeat = None
app.state.last_api_activity = None
app.state.job_manager = jobs.manager


class ApiActivityMiddleware:
    """Note l'heure (horloge monotone) de chaque requête /api acceptée dans app.state.last_api_activity.

    Le lanceur la compte comme activité : une interface qui n'envoie pas de
    battement (ancienne, ou gardée en cache par le navigateur) ou un client de
    l'API n'est jamais pris pour un onglet fermé. Placé après le contrôle du
    jeton : une requête refusée ne compte pas. La sonde de santé est exclue :
    le lanceur l'appelle lui-même au démarrage, l'interface toutes les 30 s.
    """

    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] == "http":
            path = _route_path(scope)
            if is_api_path(path) and path != "/api/health" and "app" in scope:
                scope["app"].state.last_api_activity = time.monotonic()
        await self.app(scope, receive, send)


# Chemins accessibles sans jeton, même si API_TOKEN est défini : le frontend
# (page statique, sans donnée), la supervision et, si elle est activée, la
# documentation interactive (aucune donnée de scan ; le schéma de l'API est
# public, comme le code du projet). Tout le reste exige le jeton.
_DOCS_PATHS = (
    app.docs_url,
    app.redoc_url,
    app.openapi_url,
    app.swagger_ui_oauth2_redirect_url if app.docs_url else None,
)
PUBLIC_PATHS = frozenset({"/", "/api/health", *(path for path in _DOCS_PATHS if path)})
# Pages HTML de la documentation (DOCS_CSP) ; le schéma, du JSON, relève d'API_CSP.
DOCS_PAGES = frozenset(path for path in _DOCS_PATHS if path and path != app.openapi_url)

# Authentification déclarée dans le schéma OpenAPI, sous les deux formes
# acceptées par ApiTokenMiddleware (au choix) : le bouton « Authorize » de
# /api/docs ajoute alors le jeton aux requêtes d'essai.
OPENAPI_SECURITY_SCHEMES = {
    "ApiToken": {
        "type": "apiKey",
        "in": "header",
        "name": "X-API-Token",
        "description": "Jeton d'API (API_TOKEN). Exigé seulement si API_TOKEN est défini sur le serveur.",
    },
    "Bearer": {
        "type": "http",
        "scheme": "bearer",
        "description": "Le même jeton, dans l'en-tête Authorization: Bearer <jeton>.",
    },
}


def openapi_with_token_auth() -> dict:
    """Schéma OpenAPI de l'application, authentification par jeton comprise."""
    schema = FastAPI.openapi(app)
    # FastAPI met le schéma en cache et le régénère si les routes changent.
    if "securitySchemes" not in schema.setdefault("components", {}):
        schema["components"]["securitySchemes"] = OPENAPI_SECURITY_SCHEMES
        schema["security"] = [{name: []} for name in OPENAPI_SECURITY_SCHEMES]
    return schema


app.openapi = openapi_with_token_auth

# Ordre d'exécution (le dernier ajouté est le plus externe) : en-têtes de
# sécurité → contrôle de Host → CORS → jeton → taille du corps → activité →
# garde de la désinstallation (410 une fois DomainRecon désinstallé) → routes.
app.add_middleware(uninstall.UninstalledGuardMiddleware)
app.add_middleware(ApiActivityMiddleware)
# Corps limité à 1 Mio, sauf l'envoi d'une ancienne base (POST /api/import) qui a sa propre limite.
app.add_middleware(
    BodySizeLimitMiddleware,
    max_bytes=MAX_REQUEST_BODY_BYTES,
    path_limits={importer.IMPORT_PATH: importer.upload_limit},
)
app.add_middleware(ApiTokenMiddleware, public_paths=PUBLIC_PATHS)
# Le frontend est servi par cette même application : aucune origine tierce n'a
# besoin de l'API. CORS_ORIGINS (config.py, vide par défaut) s'élargit si le
# frontend est ailleurs.
app.add_middleware(ConfiguredCORSMiddleware)
app.add_middleware(ConfiguredTrustedHostMiddleware)
app.add_middleware(SecurityHeadersMiddleware, docs_paths=DOCS_PAGES)

install_error_handlers(app)

app.include_router(system.router)
app.include_router(uninstall.router)
app.include_router(scans.router)
app.include_router(export.router)
app.include_router(history.router)
app.include_router(importer.router)
app.include_router(jobs.router)
app.include_router(settings.router)
app.include_router(modules.router)
app.include_router(monitor_routes.router)
app.include_router(notify_routes.router)
register_spa(app)
