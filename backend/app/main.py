# =============================================================================
# DomainRecon - API FastAPI v5.0
# =============================================================================
# Sert l'API sous /api et le frontend à la racine /
# =============================================================================

from datetime import datetime, timezone
from typing import Optional
from contextlib import asynccontextmanager
from pathlib import Path

import httpx
from fastapi import FastAPI, Depends, HTTPException, APIRouter
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session
from sqlalchemy import text

from .database import engine, get_db, Base
from .models import Scan, Settings
from .scanner import run_scan

# Chemin vers le frontend
FRONTEND_DIR = Path(__file__).resolve().parent.parent.parent / "frontend"


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Crée les tables au démarrage + migrations douces v4.0 / v5.0."""
    Base.metadata.create_all(bind=engine)

    from sqlalchemy import inspect
    inspector = inspect(engine)

    # Migration v4.0 — colonnes scans
    v4_columns = [
        "urlscan_data", "wayback_data", "threat_intel",
        "js_analysis", "favicon_hash", "linked_domains",
        "email_blacklist", "hsts_preload",
    ]
    # Migration v5.0 — nouvelle colonne vuln_data
    v5_columns = ["vuln_data"]
    # Migration v6.0 — nouvelles colonnes
    v6_scan_columns = [
        ("zone_transfer", "JSON"), ("wildcard_dns", "JSON"), ("dns_rebinding", "JSON"),
        ("tls_deep", "JSON"), ("csp_grade", "JSON"), ("hsts_deep", "JSON"),
        ("admin_panels", "JSON"), ("html_intelligence", "JSON"), ("http_methods", "JSON"),
        ("smtp_security", "JSON"), ("banners", "JSON"), ("typosquatting", "JSON"),
        ("scan_profile", "VARCHAR(10) DEFAULT 'full'"), ("robtex", "JSON"),
        ("shodan_data", "JSON"),
    ]
    v6_settings_columns = [
        ("quick_timeout", "INTEGER DEFAULT 30"),
        ("full_timeout", "INTEGER DEFAULT 180"),
    ]

    existing_scan_cols = {col["name"] for col in inspector.get_columns("scans")}
    existing_settings_cols = {col["name"] for col in inspector.get_columns("settings")}
    with engine.connect() as conn:
        for col in v4_columns + v5_columns:
            if col not in existing_scan_cols:
                conn.execute(text(f"ALTER TABLE scans ADD COLUMN {col} JSON"))
        for col, dtype in v6_scan_columns:
            if col not in existing_scan_cols:
                conn.execute(text(f"ALTER TABLE scans ADD COLUMN {col} {dtype}"))
        for col, dtype in v6_settings_columns:
            if col not in existing_settings_cols:
                conn.execute(text(f"ALTER TABLE settings ADD COLUMN {col} {dtype}"))
        conn.commit()

    yield


app = FastAPI(
    title="DomainRecon API",
    description="API OSINT pour la reconnaissance de domaines",
    version="6.0.0",
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


# =============================================================================
# Helpers
# =============================================================================

def _mask_key(key: Optional[str]) -> Optional[str]:
    """Masque une clé API — retourne les 4 derniers caractères visibles."""
    if not key:
        return None
    if len(key) <= 4:
        return "••••"
    return "••••••••" + key[-4:]


def _get_or_create_settings(db: Session) -> Settings:
    """Retourne les settings existants ou crée une row singleton."""
    s = db.query(Settings).filter(Settings.id == 1).first()
    if not s:
        s = Settings(id=1)
        db.add(s)
        db.commit()
        db.refresh(s)
    return s


# =============================================================================
# Schémas Pydantic
# =============================================================================

class ScanRequest(BaseModel):
    domain: str = Field(..., min_length=1, max_length=255)
    profile: str = Field(default="full", pattern="^(quick|full)$")


class ScanResponse(BaseModel):
    id: int
    domain: str
    ip_address: Optional[str] = None
    dns_records: dict = Field(default_factory=dict)
    subdomains: list = Field(default_factory=list)
    security_headers: dict = Field(default_factory=dict)
    whois_data: dict = Field(default_factory=dict)
    geo_data: dict = Field(default_factory=dict)
    tls_certificate: dict = Field(default_factory=dict)
    open_ports: list = Field(default_factory=list)
    technologies: list = Field(default_factory=list)
    email_security: dict = Field(default_factory=dict)
    waf: dict = Field(default_factory=dict)
    redirect_chain: dict = Field(default_factory=dict)
    web_files: dict = Field(default_factory=dict)
    cookie_security: dict = Field(default_factory=dict)
    cors: dict = Field(default_factory=dict)
    reverse_dns: dict = Field(default_factory=dict)
    subdomain_takeover: list = Field(default_factory=list)
    network_extended: dict = Field(default_factory=dict)
    security_score: dict = Field(default_factory=dict)
    screenshot_path: Optional[str] = None
    tags: list = Field(default_factory=list)
    notes: Optional[str] = None
    # v4.0
    urlscan_data: dict = Field(default_factory=dict)
    wayback_data: dict = Field(default_factory=dict)
    threat_intel: dict = Field(default_factory=dict)
    js_analysis: dict = Field(default_factory=dict)
    favicon_hash: dict = Field(default_factory=dict)
    linked_domains: dict = Field(default_factory=dict)
    email_blacklist: dict = Field(default_factory=dict)
    hsts_preload: dict = Field(default_factory=dict)
    # v6.0
    zone_transfer:      Optional[dict] = None
    wildcard_dns:       Optional[dict] = None
    dns_rebinding:      Optional[dict] = None
    tls_deep:           Optional[dict] = None
    csp_grade:          Optional[dict] = None
    hsts_deep:          Optional[dict] = None
    admin_panels:       Optional[dict] = None
    html_intelligence:  Optional[dict] = None
    http_methods:       Optional[dict] = None
    smtp_security:      Optional[dict] = None
    banners:            Optional[dict] = None
    typosquatting:      Optional[dict] = None
    scan_profile:       Optional[str]  = None
    robtex:             Optional[dict] = None
    shodan_data:        Optional[dict] = None
    scan_timestamp: datetime
    status: str
    error_message: Optional[str] = None

    class Config:
        from_attributes = True


class HistoryResponse(BaseModel):
    total: int
    scans: list[ScanResponse]


class SettingsRequest(BaseModel):
    shodan_key: Optional[str] = None
    securitytrails_key: Optional[str] = None
    censys_id: Optional[str] = None
    censys_secret: Optional[str] = None
    urlscan_key: Optional[str] = None
    virustotal_key: Optional[str] = None
    screenshot_enabled: bool = False
    scan_timeout: int = Field(default=60, ge=10, le=300)
    quick_timeout: Optional[int] = 30
    full_timeout:  Optional[int] = 180


class SettingsResponse(BaseModel):
    shodan_key: Optional[str] = None
    virustotal_key: Optional[str] = None
    securitytrails_key: Optional[str] = None
    censys_id: Optional[str] = None
    censys_secret: Optional[str] = None
    urlscan_key: Optional[str] = None
    screenshot_enabled: bool = False
    scan_timeout: int = 60
    # Flags de validité (non stockés, renvoyés après test)
    shodan_valid: Optional[bool] = None
    securitytrails_valid: Optional[bool] = None
    censys_valid: Optional[bool] = None
    urlscan_valid: Optional[bool] = None

    class Config:
        from_attributes = True


# =============================================================================
# Helper — Scan → Response
# =============================================================================

def _extract_list(val, key: str) -> list:
    """Extrait une liste depuis un dict {key: [...]} ou retourne la valeur directement."""
    if isinstance(val, dict):
        return val.get(key, [])
    return val or []


def _scan_to_response(scan: Scan) -> ScanResponse:
    """Convertit un objet Scan SQLAlchemy en ScanResponse Pydantic."""
    return ScanResponse(
        id=scan.id,
        domain=scan.domain,
        ip_address=scan.ip_address,
        dns_records=scan.dns_records or {},
        subdomains=_extract_list(scan.subdomains, "subdomains"),
        security_headers=scan.security_headers or {},
        whois_data=scan.whois_data or {},
        geo_data=scan.geo_data or {},
        tls_certificate=scan.tls_certificate or {},
        open_ports=scan.open_ports if isinstance(scan.open_ports, list) else _extract_list(scan.open_ports, "open_ports"),
        technologies=scan.technologies if isinstance(scan.technologies, list) else _extract_list(scan.technologies, "technologies"),
        email_security=scan.email_security or {},
        waf=scan.waf or {},
        redirect_chain=scan.redirect_chain or {},
        web_files=scan.web_files or {},
        cookie_security=scan.cookie_security or {},
        cors=scan.cors or {},
        reverse_dns=scan.reverse_dns_data or {},
        subdomain_takeover=_extract_list(scan.subdomain_takeover, "vulnerable"),
        network_extended=scan.network_extended or {},
        security_score=scan.security_score or {},
        screenshot_path=scan.screenshot_path,
        tags=scan.tags or [],
        notes=scan.notes,
        urlscan_data=scan.urlscan_data or {},
        wayback_data=scan.wayback_data or {},
        threat_intel=scan.threat_intel or {},
        js_analysis=scan.js_analysis or {},
        favicon_hash=scan.favicon_hash or {},
        linked_domains=scan.linked_domains or {},
        email_blacklist=scan.email_blacklist or {},
        hsts_preload=scan.hsts_preload or {},
        zone_transfer=scan.zone_transfer,
        wildcard_dns=scan.wildcard_dns,
        dns_rebinding=scan.dns_rebinding,
        tls_deep=scan.tls_deep,
        csp_grade=scan.csp_grade,
        hsts_deep=scan.hsts_deep,
        admin_panels=scan.admin_panels,
        html_intelligence=scan.html_intelligence,
        http_methods=scan.http_methods,
        smtp_security=scan.smtp_security,
        banners=scan.banners,
        typosquatting=scan.typosquatting,
        scan_profile=scan.scan_profile,
        robtex=scan.robtex,
        shodan_data=getattr(scan, "shodan_data", None),
        scan_timestamp=scan.scan_timestamp,
        status=scan.status,
        error_message=scan.error_message,
    )


# =============================================================================
# API Router (/api)
# =============================================================================

api = APIRouter(prefix="/api", tags=["API"])


@api.get("/health")
async def health_check(db: Session = Depends(get_db)):
    """Vérifie l'état de l'API et de la base de données."""
    try:
        db.execute(text("SELECT 1"))
        return {"api": "healthy", "database": "connected"}
    except Exception as e:
        return {"api": "healthy", "database": f"error: {e}"}


# =============================================================================
# Scan
# =============================================================================

@api.post("/scan", response_model=ScanResponse)
async def scan_domain(request: ScanRequest, db: Session = Depends(get_db)):
    """Lance un scan d'un domaine (Quick ~20s ou Full ~3min)."""
    try:
        settings_row = _get_or_create_settings(db)
        settings = {
            "urlscan_key": settings_row.urlscan_key,
            "virustotal_key": getattr(settings_row, "virustotal_key", None),
            "shodan_key": getattr(settings_row, "shodan_key", None),
            "screenshot_enabled": settings_row.screenshot_enabled,
        }
        timeout = (
            (getattr(settings_row, "quick_timeout", None) or 30)
            if request.profile == "quick"
            else (getattr(settings_row, "full_timeout", None) or 180)
        )

        result = await run_scan(request.domain, request.profile, settings, timeout)

        db_scan = Scan(
            domain=request.domain,
            scan_profile=request.profile,
            ip_address=result.get("ip_address"),
            dns_records=result.get("dns_records"),
            subdomains=result.get("subdomains"),
            security_headers=result.get("security_headers"),
            whois_data=result.get("whois_data"),
            geo_data=result.get("geo_data"),
            tls_certificate=result.get("tls_certificate"),
            open_ports=result.get("open_ports"),
            technologies=result.get("technologies"),
            email_security=result.get("email_security"),
            waf=result.get("waf"),
            redirect_chain=result.get("redirect_chain"),
            web_files=result.get("web_files"),
            cookie_security=result.get("cookie_security"),
            cors=result.get("cors"),
            reverse_dns_data=result.get("reverse_dns_data"),
            subdomain_takeover=result.get("subdomain_takeover"),
            network_extended=result.get("network_extended"),
            security_score=result.get("security_score"),
            screenshot_path=result.get("screenshot_path"),
            urlscan_data=result.get("urlscan_data"),
            wayback_data=result.get("wayback_data"),
            threat_intel=result.get("threat_intel"),
            js_analysis=result.get("js_analysis"),
            favicon_hash=result.get("favicon_hash"),
            linked_domains=result.get("linked_domains"),
            hsts_preload=result.get("hsts_preload"),
            zone_transfer=result.get("zone_transfer"),
            wildcard_dns=result.get("wildcard_dns"),
            dns_rebinding=result.get("dns_rebinding"),
            tls_deep=result.get("tls_deep"),
            csp_grade=result.get("csp_grade"),
            hsts_deep=result.get("hsts_deep"),
            admin_panels=result.get("admin_panels"),
            html_intelligence=result.get("html_intelligence"),
            http_methods=result.get("http_methods"),
            smtp_security=result.get("smtp_security"),
            banners=result.get("banners"),
            typosquatting=result.get("typosquatting"),
            robtex=result.get("robtex"),
            shodan_data=result.get("shodan_data"),
            email_blacklist=result.get("email_blacklist"),
            scan_timestamp=datetime.now(timezone.utc),
            status="success",
        )

        db.add(db_scan)
        db.commit()
        db.refresh(db_scan)

        return _scan_to_response(db_scan)

    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=500, detail=str(e))


@api.get("/history", response_model=HistoryResponse)
async def get_scan_history(
    limit: int = 10,
    offset: int = 0,
    domain: Optional[str] = None,
    db: Session = Depends(get_db),
):
    """Récupère l'historique des scans avec pagination et filtre optionnel."""
    query = db.query(Scan)

    if domain:
        query = query.filter(Scan.domain.contains(domain))

    total = query.count()
    scans = query.order_by(Scan.scan_timestamp.desc()).offset(offset).limit(limit).all()

    return HistoryResponse(
        total=total,
        scans=[_scan_to_response(s) for s in scans],
    )


@api.get("/scan/{scan_id}", response_model=ScanResponse)
async def get_scan_by_id(scan_id: int, db: Session = Depends(get_db)):
    """Récupère un scan par son ID."""
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan non trouvé")
    return _scan_to_response(scan)


@api.delete("/scan/{scan_id}")
async def delete_scan(scan_id: int, db: Session = Depends(get_db)):
    """Supprime un scan par son ID."""
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan non trouvé")
    db.delete(scan)
    db.commit()
    return {"message": "Scan supprimé", "id": scan_id}


# =============================================================================
# Tags & Notes
# =============================================================================

class TagsNotesRequest(BaseModel):
    tags: Optional[list] = None
    notes: Optional[str] = None


@api.patch("/scan/{scan_id}/meta")
async def update_scan_meta(scan_id: int, request: TagsNotesRequest, db: Session = Depends(get_db)):
    """Met à jour les tags et notes d'un scan."""
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan non trouvé")
    if request.tags is not None:
        scan.tags = request.tags
    if request.notes is not None:
        scan.notes = request.notes
    db.commit()
    db.refresh(scan)
    return _scan_to_response(scan)


# =============================================================================
# Settings
# =============================================================================

@api.get("/settings", response_model=SettingsResponse)
async def get_settings(db: Session = Depends(get_db)):
    """Retourne les paramètres avec les clés masquées."""
    s = _get_or_create_settings(db)
    return SettingsResponse(
        shodan_key=_mask_key(s.shodan_key),
        virustotal_key=_mask_key(getattr(s, "virustotal_key", None)),
        securitytrails_key=_mask_key(s.securitytrails_key),
        censys_id=_mask_key(s.censys_id),
        censys_secret=_mask_key(s.censys_secret),
        urlscan_key=_mask_key(s.urlscan_key),
        screenshot_enabled=s.screenshot_enabled or False,
        scan_timeout=s.scan_timeout or 60,
    )


@api.put("/settings")
async def update_settings(request: SettingsRequest, db: Session = Depends(get_db)):
    """Sauvegarde les paramètres. Envoyer une chaîne vide pour effacer une clé."""
    s = _get_or_create_settings(db)

    # Ne mettre à jour que les champs explicitement fournis (None = non touché)
    # Chaîne vide "" = effacer la clé
    if request.shodan_key is not None:
        s.shodan_key = request.shodan_key or None
    if request.virustotal_key is not None:
        s.virustotal_key = request.virustotal_key or None
    if request.securitytrails_key is not None:
        s.securitytrails_key = request.securitytrails_key or None
    if request.censys_id is not None:
        s.censys_id = request.censys_id or None
    if request.censys_secret is not None:
        s.censys_secret = request.censys_secret or None
    if request.urlscan_key is not None:
        s.urlscan_key = request.urlscan_key or None

    s.screenshot_enabled = request.screenshot_enabled
    s.scan_timeout = request.scan_timeout
    if request.quick_timeout is not None:
        s.quick_timeout = request.quick_timeout
    if request.full_timeout is not None:
        s.full_timeout = request.full_timeout
    s.updated_at = datetime.now(timezone.utc)

    db.commit()
    db.refresh(s)

    return SettingsResponse(
        shodan_key=_mask_key(s.shodan_key),
        virustotal_key=_mask_key(getattr(s, "virustotal_key", None)),
        securitytrails_key=_mask_key(s.securitytrails_key),
        censys_id=_mask_key(s.censys_id),
        censys_secret=_mask_key(s.censys_secret),
        urlscan_key=_mask_key(s.urlscan_key),
        screenshot_enabled=s.screenshot_enabled or False,
        scan_timeout=s.scan_timeout or 60,
    )


@api.post("/settings/test/{service}")
async def test_api_key(service: str, db: Session = Depends(get_db)):
    """Teste la validité d'une clé API pour un service donné."""
    s = _get_or_create_settings(db)
    valid = False
    detail = ""

    try:
        async with httpx.AsyncClient(timeout=8.0) as client:
            if service == "shodan":
                if not s.shodan_key:
                    return {"valid": False, "detail": "Clé non configurée"}
                r = await client.get(
                    "https://api.shodan.io/api-info",
                    params={"key": s.shodan_key},
                )
                valid = r.status_code == 200
                if valid:
                    info = r.json()
                    credits = info.get("query_credits", "?")
                    detail = f"OK — {credits} crédits restants"
                else:
                    detail = f"Erreur {r.status_code}"

            elif service == "virustotal":
                if not getattr(s, "virustotal_key", None):
                    return {"valid": False, "detail": "Clé non configurée"}
                r = await client.get(
                    "https://www.virustotal.com/api/v3/users/me",
                    headers={"x-apikey": s.virustotal_key},
                )
                valid = r.status_code == 200
                detail = "OK" if valid else f"Erreur {r.status_code}"

            elif service == "securitytrails":
                if not s.securitytrails_key:
                    return {"valid": False, "detail": "Clé non configurée"}
                r = await client.get(
                    "https://api.securitytrails.com/v1/ping",
                    headers={"APIKEY": s.securitytrails_key},
                )
                valid = r.status_code == 200
                detail = "OK" if valid else f"Erreur {r.status_code}"

            elif service == "censys":
                if not s.censys_id or not s.censys_secret:
                    return {"valid": False, "detail": "ID ou Secret non configuré"}
                r = await client.get(
                    "https://search.censys.io/api/v2/account",
                    auth=(s.censys_id, s.censys_secret),
                )
                valid = r.status_code == 200
                detail = "OK" if valid else f"Erreur {r.status_code}"

            elif service == "urlscan":
                if not s.urlscan_key:
                    return {"valid": False, "detail": "Clé non configurée"}
                r = await client.get(
                    "https://urlscan.io/user/",
                    headers={"API-Key": s.urlscan_key},
                )
                valid = r.status_code == 200
                detail = "OK" if valid else f"Erreur {r.status_code}"

            else:
                raise HTTPException(status_code=400, detail=f"Service inconnu: {service}")

    except httpx.RequestError as e:
        detail = f"Erreur réseau: {str(e)[:80]}"

    return {"valid": valid, "service": service, "detail": detail}


# =============================================================================
# Screenshot Endpoint
# =============================================================================

@api.get("/screenshot/{filename}")
async def serve_screenshot(filename: str):
    """Sert une image screenshot capturée."""
    screenshots_dir = Path(__file__).resolve().parent.parent.parent / "data" / "screenshots"
    filepath = screenshots_dir / filename
    if not filepath.exists():
        raise HTTPException(status_code=404, detail="Screenshot non trouvé")
    return FileResponse(str(filepath), media_type="image/png")


# =============================================================================
# DNS Timeline
# =============================================================================

@api.get("/dns-timeline/{domain}")
async def get_dns_timeline(domain: str, db: Session = Depends(get_db)):
    """Récupère l'historique DNS d'un domaine à travers ses scans."""
    scans = (
        db.query(Scan)
        .filter(Scan.domain == domain)
        .order_by(Scan.scan_timestamp.asc())
        .all()
    )
    if not scans:
        raise HTTPException(status_code=404, detail="Aucun scan trouvé pour ce domaine")

    timeline = []
    for s in scans:
        timeline.append({
            "scan_id": s.id,
            "timestamp": s.scan_timestamp.isoformat(),
            "ip_address": s.ip_address,
            "dns_records": s.dns_records or {},
            "subdomains_count": len(_extract_list(s.subdomains, "subdomains")),
            "open_ports_count": len(_extract_list(s.open_ports, "open_ports")),
            "security_score": (s.security_score or {}).get("score"),
        })
    return {"domain": domain, "total_scans": len(timeline), "timeline": timeline}


# Inclure le router API
app.include_router(api)


# =============================================================================
# Frontend (servi par FastAPI)
# =============================================================================

@app.get("/", include_in_schema=False)
async def serve_frontend():
    """Sert la page HTML du frontend."""
    html_path = FRONTEND_DIR / "index.html"
    if html_path.exists():
        return FileResponse(str(html_path), media_type="text/html")
    return {"message": "Frontend non trouvé", "api_docs": "/api/docs"}
