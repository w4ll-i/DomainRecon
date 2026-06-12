# backend/app/main.py
"""
DomainRecon - FastAPI application bootstrap.

Application concerns (middleware, routing, lifespan) live here.
Business logic lives in:
  * routers/     - HTTP endpoints (scans, settings, vpn, misc)
  * schemas.py   - Pydantic models
  * helpers.py   - shared helpers (key masking, scan serialization)
  * migrations.py - legacy idempotent ALTER TABLE logic
  * scanner.py   - scan orchestrator
"""
import logging
import os
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from .auth import ApiKeyAuthMiddleware
from .database import Base, engine
from .migrations import apply_legacy_migrations
from .routers import misc, scans, settings, vpn

logger = logging.getLogger("domainrecon")


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Create tables and apply catch-up migrations on startup."""
    Base.metadata.create_all(bind=engine)
    apply_legacy_migrations(engine)
    yield


app = FastAPI(
    title="DomainRecon API",
    description="API OSINT pour la reconnaissance de domaines",
    version="1.0.0",
    lifespan=lifespan,
    docs_url="/api/docs",
    redoc_url="/api/redoc",
    openapi_url="/api/openapi.json",
)

# CORS origins are configurable via CORS_ORIGINS (comma-separated). Default to
# same-origin only; "*" is allowed but credentials stay disabled because the
# browser forbids the wildcard+credentials combination and the API is keyed via
# headers, not cookies.
_origins_env = os.getenv("CORS_ORIGINS", "").strip()
_allow_origins = [o.strip() for o in _origins_env.split(",") if o.strip()] or ["*"]

app.add_middleware(
    CORSMiddleware,
    allow_origins=_allow_origins,
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Optional API-key gate (no-op unless DOMAINRECON_API_KEY is set).
app.add_middleware(ApiKeyAuthMiddleware)

app.include_router(misc.router)
app.include_router(scans.router)
app.include_router(settings.router)
app.include_router(vpn.router)

# WebSocket routes can't be attached through APIRouter.websocket in some
# FastAPI versions - mount directly on the app.
app.add_api_websocket_route("/api/ws/scan", scans.websocket_scan)
