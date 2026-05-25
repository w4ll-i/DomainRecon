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
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

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

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(misc.router)
app.include_router(scans.router)
app.include_router(settings.router)
app.include_router(vpn.router)

# WebSocket routes can't be attached through APIRouter.websocket in some
# FastAPI versions - mount directly on the app.
app.add_api_websocket_route("/api/ws/scan", scans.websocket_scan)
