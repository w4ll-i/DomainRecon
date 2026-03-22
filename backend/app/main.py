# =============================================================================
# DomainRecon - API
# =============================================================================

import logging
import traceback
import asyncio
from datetime import datetime, timezone
from typing import Optional
from contextlib import asynccontextmanager
from pathlib import Path

logger = logging.getLogger("domainrecon")

import json
import httpx
from fastapi import FastAPI, Depends, HTTPException, APIRouter, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session
from sqlalchemy import text

from .database import engine, get_db, Base
from .models import Scan, Settings
from .scanner import run_scan
from .vpn_manager import get_status as vpn_get_status, connect as vpn_connect, disconnect as vpn_disconnect, list_locations as vpn_list_locations, set_location as vpn_set_location

# Chemin vers le frontend
FRONTEND_DIR = Path(__file__).resolve().parent.parent.parent / "frontend"


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Crée les tables au démarrage et applique les migrations idempotentes."""
    Base.metadata.create_all(bind=engine)

    from sqlalchemy import inspect
    inspector = inspect(engine)

    legacy_columns = [
        "urlscan_data", "wayback_data", "threat_intel",
        "js_analysis", "favicon_hash", "linked_domains",
        "email_blacklist", "hsts_preload", "vuln_data",
    ]
    scan_columns = [
        ("zone_transfer", "JSON"), ("wildcard_dns", "JSON"), ("dns_rebinding", "JSON"),
        ("tls_deep", "JSON"), ("csp_grade", "JSON"), ("hsts_deep", "JSON"),
        ("admin_panels", "JSON"), ("html_intelligence", "JSON"), ("http_methods", "JSON"),
        ("smtp_security", "JSON"), ("banners", "JSON"), ("typosquatting", "JSON"),
        ("scan_profile", "VARCHAR(10) DEFAULT 'full'"), ("robtex", "JSON"),
        ("shodan_data", "JSON"),
    ]
    settings_columns = [
        ("quick_timeout",    "INTEGER DEFAULT 30"),
        ("full_timeout",     "INTEGER DEFAULT 180"),
        ("builtwith_key",    "VARCHAR(100)"),
        ("circl_user",       "VARCHAR(100)"),
        ("circl_password",   "VARCHAR(200)"),
        ("abuseipdb_key",    "VARCHAR(100)"),
        ("intelx_key",       "VARCHAR(100)"),
        ("safebrowsing_key", "VARCHAR(100)"),
        ("phishtank_key",    "VARCHAR(100)"),
        ("leakix_key",       "VARCHAR(100)"),
        ("github_token",     "VARCHAR(200)"),
    ]
    scan_columns += [
        ("bgpview_data",     "JSON"),
        ("certsh_data",      "JSON"),
        ("builtwith_data",   "JSON"),
        ("dast_data",        "JSON"),
        ("pdns_data",        "JSON"),
        ("emailrep_data",    "JSON"),
        ("abuseipdb_data",   "JSON"),
        ("observatory_data", "JSON"),
        ("cert_pinning",     "JSON"),
        ("crypto_audit",     "JSON"),
        ("intelx_data",      "JSON"),
        ("dnssec_data",      "JSON"),
        ("http_versions",    "JSON"),
        ("safebrowsing_data","JSON"),
        ("phishtank_data",   "JSON"),
        ("doh_comparison",   "JSON"),
        ("cloud_storage",    "JSON"),
        ("api_endpoints",    "JSON"),
        ("cms_data",         "JSON"),
        ("subdomain_bruteforce", "JSON"),
        ("leakix_data",      "JSON"),
        ("github_dork",      "JSON"),
        ("hibp_data",        "JSON"),
        ("js_deps_data",     "JSON"),
        ("censys_data",      "JSON"),
        ("nuclei_data",      "JSON"),
    ]
    scan_columns += [
        ("js_secrets_data", "JSON"),
        ("dnsbl_data",      "JSON"),
        ("paste_data",      "JSON"),
    ]
    settings_columns += [
        ("google_cse_key", "VARCHAR(100)"),
    ]

    existing_scan_cols = {col["name"] for col in inspector.get_columns("scans")}
    existing_settings_cols = {col["name"] for col in inspector.get_columns("settings")}
    with engine.connect() as conn:
        for col in legacy_columns:
            if col not in existing_scan_cols:
                conn.execute(text(f"ALTER TABLE scans ADD COLUMN {col} JSON"))
        for col, dtype in scan_columns:
            if col not in existing_scan_cols:
                conn.execute(text(f"ALTER TABLE scans ADD COLUMN {col} {dtype}"))
        for col, dtype in settings_columns:
            if col not in existing_settings_cols:
                conn.execute(text(f"ALTER TABLE settings ADD COLUMN {col} {dtype}"))
        conn.commit()

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

class VpnLocationRequest(BaseModel):
    code: str = Field(..., pattern=r"^[a-z]{2}(-[a-z0-9]+)?$")


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
    urlscan_data: dict = Field(default_factory=dict)
    wayback_data: dict = Field(default_factory=dict)
    threat_intel: dict = Field(default_factory=dict)
    js_analysis: dict = Field(default_factory=dict)
    favicon_hash: dict = Field(default_factory=dict)
    linked_domains: dict = Field(default_factory=dict)
    email_blacklist: dict = Field(default_factory=dict)
    hsts_preload: dict = Field(default_factory=dict)
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
    bgpview_data:       Optional[dict] = None
    certsh_data:        Optional[dict] = None
    builtwith_data:     Optional[dict] = None
    dast_data:          Optional[dict] = None
    pdns_data:          Optional[dict] = None
    emailrep_data:      Optional[dict] = None
    abuseipdb_data:     Optional[dict] = None
    observatory_data:   Optional[dict] = None
    cert_pinning:       Optional[dict] = None
    crypto_audit:       Optional[dict] = None
    intelx_data:        Optional[dict] = None
    dnssec_data:        Optional[dict] = None
    http_versions:      Optional[dict] = None
    safebrowsing_data:  Optional[dict] = None
    phishtank_data:     Optional[dict] = None
    doh_comparison:     Optional[dict] = None
    cloud_storage:      Optional[dict] = None
    api_endpoints:      Optional[dict] = None
    cms_data:           Optional[dict] = None
    subdomain_bruteforce: Optional[dict] = None
    leakix_data:        Optional[dict] = None
    github_dork:        Optional[dict] = None
    hibp_data:          Optional[dict] = None
    js_deps_data:       Optional[dict] = None
    censys_data:        Optional[dict] = None
    nuclei_data:        Optional[dict] = None
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
    builtwith_key:  Optional[str] = None
    circl_user:     Optional[str] = None
    circl_password: Optional[str] = None
    abuseipdb_key:  Optional[str] = None
    intelx_key:     Optional[str] = None
    safebrowsing_key: Optional[str] = None
    phishtank_key:    Optional[str] = None
    leakix_key:     Optional[str] = None
    github_token:   Optional[str] = None
    google_cse_key: Optional[str] = None


class SettingsResponse(BaseModel):
    shodan_key: Optional[str] = None
    virustotal_key: Optional[str] = None
    securitytrails_key: Optional[str] = None
    censys_id: Optional[str] = None
    censys_secret: Optional[str] = None
    urlscan_key: Optional[str] = None
    screenshot_enabled: bool = False
    scan_timeout: int = 60
    builtwith_key:  Optional[str] = None
    circl_user:     Optional[str] = None
    abuseipdb_key:  Optional[str] = None
    intelx_key:     Optional[str] = None
    safebrowsing_key: Optional[str] = None
    phishtank_key:    Optional[str] = None
    leakix_key:     Optional[str] = None
    github_token:   Optional[str] = None
    google_cse_key: Optional[str] = None
    # circl_password intentionally omitted (never return passwords)
    # Flags de validité (non stockés, renvoyés après test)
    shodan_valid: Optional[bool] = None
    securitytrails_valid: Optional[bool] = None
    censys_valid: Optional[bool] = None
    urlscan_valid: Optional[bool] = None
    builtwith_valid: Optional[bool] = None

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
        bgpview_data=getattr(scan, "bgpview_data", None),
        certsh_data=getattr(scan, "certsh_data", None),
        builtwith_data=getattr(scan, "builtwith_data", None),
        dast_data=getattr(scan, "dast_data", None),
        pdns_data=getattr(scan, "pdns_data", None),
        emailrep_data=getattr(scan, "emailrep_data", None),
        abuseipdb_data=getattr(scan, "abuseipdb_data", None),
        observatory_data=getattr(scan, "observatory_data", None),
        cert_pinning=getattr(scan, "cert_pinning", None),
        crypto_audit=getattr(scan, "crypto_audit", None),
        intelx_data=getattr(scan, "intelx_data", None),
        dnssec_data=getattr(scan, "dnssec_data", None),
        http_versions=getattr(scan, "http_versions", None),
        safebrowsing_data=getattr(scan, "safebrowsing_data", None),
        phishtank_data=getattr(scan, "phishtank_data", None),
        doh_comparison=getattr(scan, "doh_comparison", None),
        cloud_storage=getattr(scan, "cloud_storage", None),
        api_endpoints=getattr(scan, "api_endpoints", None),
        cms_data=getattr(scan, "cms_data", None),
        subdomain_bruteforce=getattr(scan, "subdomain_bruteforce", None),
        leakix_data=getattr(scan, "leakix_data", None),
        github_dork=getattr(scan, "github_dork", None),
        hibp_data=getattr(scan, "hibp_data", None),
        js_deps_data=getattr(scan, "js_deps_data", None),
        censys_data=getattr(scan, "censys_data", None),
        nuclei_data=getattr(scan, "nuclei_data", None),
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
            "builtwith_key":  getattr(settings_row, "builtwith_key", None),
            "circl_user":     getattr(settings_row, "circl_user", None),
            "circl_password": getattr(settings_row, "circl_password", None),
            "abuseipdb_key":  getattr(settings_row, "abuseipdb_key", None),
            "intelx_key":     getattr(settings_row, "intelx_key", None),
            "safebrowsing_key": getattr(settings_row, "safebrowsing_key", None),
            "phishtank_key":    getattr(settings_row, "phishtank_key", None),
            "leakix_key":     getattr(settings_row, "leakix_key", None),
            "github_token":   getattr(settings_row, "github_token", None),
            "google_cse_key": getattr(settings_row, "google_cse_key", None),
        }
        timeout = (
            (getattr(settings_row, "quick_timeout", None) or 30)
            if request.profile == "quick"
            else (getattr(settings_row, "full_timeout", None) or 180)
        )

        try:
            result = await run_scan(request.domain, request.profile, settings, timeout)
        except asyncio.TimeoutError:
            raise HTTPException(status_code=504, detail="Le scan a pris trop de temps et a dépassé le délai autorisé.")

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
            bgpview_data=result.get("bgpview_data"),
            certsh_data=result.get("certsh_data"),
            builtwith_data=result.get("builtwith_data"),
            dast_data=result.get("dast_data"),
            pdns_data=result.get("pdns_data"),
            emailrep_data=result.get("emailrep_data"),
            abuseipdb_data=result.get("abuseipdb_data"),
            observatory_data=result.get("observatory_data"),
            cert_pinning=result.get("cert_pinning"),
            crypto_audit=result.get("crypto_audit"),
            intelx_data=result.get("intelx_data"),
            dnssec_data=result.get("dnssec_data"),
            http_versions=result.get("http_versions"),
            safebrowsing_data=result.get("safebrowsing_data"),
            phishtank_data=result.get("phishtank_data"),
            doh_comparison=result.get("doh_comparison"),
            cloud_storage=result.get("cloud_storage"),
            api_endpoints=result.get("api_endpoints"),
            cms_data=result.get("cms_data"),
            subdomain_bruteforce=result.get("subdomain_bruteforce"),
            leakix_data=result.get("leakix_data"),
            github_dork=result.get("github_dork"),
            hibp_data=result.get("hibp_data"),
            js_deps_data=result.get("js_deps_data"),
            censys_data=result.get("censys_data"),
            nuclei_data=result.get("nuclei_data"),
            js_secrets_data=result.get("js_secrets_data"),
            dnsbl_data=result.get("dnsbl_data"),
            paste_data=result.get("paste_data"),
            email_blacklist=result.get("email_blacklist"),
            scan_timestamp=datetime.now(timezone.utc),
            status="success",
        )

        db.add(db_scan)
        db.commit()
        db.refresh(db_scan)

        return _scan_to_response(db_scan)

    except HTTPException:
        db.rollback()
        raise
    except Exception as e:
        db.rollback()
        logger.error("SCAN ERROR [%s]: %s\n%s", request.domain, e, traceback.format_exc())
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
        builtwith_key=_mask_key(getattr(s, "builtwith_key", None)),
        circl_user=getattr(s, "circl_user", None) or None,
        abuseipdb_key=_mask_key(getattr(s, "abuseipdb_key", None)),
        intelx_key=_mask_key(getattr(s, "intelx_key", None)),
        safebrowsing_key=_mask_key(getattr(s, "safebrowsing_key", None)),
        phishtank_key=_mask_key(getattr(s, "phishtank_key", None)),
        leakix_key=_mask_key(getattr(s, "leakix_key", None)),
        github_token=_mask_key(getattr(s, "github_token", None)),
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
    if request.builtwith_key is not None:
        s.builtwith_key = request.builtwith_key or None
    if request.circl_user is not None:
        s.circl_user = request.circl_user or None
    if request.circl_password is not None:
        s.circl_password = request.circl_password or None
    if request.abuseipdb_key is not None:
        s.abuseipdb_key = request.abuseipdb_key or None
    if request.intelx_key is not None:
        s.intelx_key = request.intelx_key or None
    if request.safebrowsing_key is not None:
        s.safebrowsing_key = request.safebrowsing_key or None
    if request.phishtank_key is not None:
        s.phishtank_key = request.phishtank_key or None
    if request.leakix_key is not None:
        s.leakix_key = request.leakix_key or None
    if request.github_token is not None:
        s.github_token = request.github_token or None
    if request.google_cse_key is not None:
        s.google_cse_key = request.google_cse_key or None

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
        builtwith_key=_mask_key(getattr(s, "builtwith_key", None)),
        circl_user=getattr(s, "circl_user", None) or None,
        abuseipdb_key=_mask_key(getattr(s, "abuseipdb_key", None)),
        intelx_key=_mask_key(getattr(s, "intelx_key", None)),
        safebrowsing_key=_mask_key(getattr(s, "safebrowsing_key", None)),
        phishtank_key=_mask_key(getattr(s, "phishtank_key", None)),
        leakix_key=_mask_key(getattr(s, "leakix_key", None)),
        github_token=_mask_key(getattr(s, "github_token", None)),
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

            elif service == "builtwith":
                if not getattr(s, "builtwith_key", None):
                    return {"valid": False, "detail": "Clé non configurée"}
                r = await client.get(
                    "https://api.builtwith.com/v21/api.json",
                    params={"KEY": s.builtwith_key, "LOOKUP": "builtwith.com"},
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

            elif service == "abuseipdb":
                if not getattr(s, "abuseipdb_key", None):
                    return {"valid": False, "detail": "Clé non configurée"}
                r = await client.get(
                    "https://api.abuseipdb.com/api/v2/check",
                    params={"ipAddress": "8.8.8.8", "maxAgeInDays": 1},
                    headers={"Key": s.abuseipdb_key, "Accept": "application/json"},
                )
                valid = r.status_code == 200
                if valid:
                    data = r.json().get("data", {})
                    detail = f"OK — score: {data.get('abuseConfidenceScore', '?')}%"
                else:
                    detail = f"Erreur {r.status_code}"

            elif service == "intelx":
                if not getattr(s, "intelx_key", None):
                    return {"valid": False, "detail": "Clé non configurée"}
                r = await client.post(
                    "https://2.intelx.io/authenticate/info",
                    headers={"x-key": s.intelx_key},
                )
                valid = r.status_code == 200
                if valid:
                    info = r.json()
                    level = info.get("accounts", [{}])[0].get("level", "?") if info.get("accounts") else "?"
                    detail = f"OK — niveau de compte: {level}"
                else:
                    detail = f"Erreur {r.status_code}"

            elif service == "safebrowsing":
                if not getattr(s, "safebrowsing_key", None):
                    return {"valid": False, "detail": "Clé non configurée"}
                r = await client.post(
                    f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={s.safebrowsing_key}",
                    json={"client": {"clientId": "test", "clientVersion": "1"}, "threatInfo": {"threatTypes": ["MALWARE"], "platformTypes": ["ANY_PLATFORM"], "threatEntryTypes": ["URL"], "threatEntries": [{"url": "http://example.com"}]}},
                )
                valid = r.status_code == 200
                detail = "OK — API opérationnelle" if valid else f"Erreur {r.status_code}"

            elif service == "leakix":
                key = getattr(s, "leakix_key", None)
                headers = {"Accept": "application/json"}
                if key:
                    headers["api-key"] = key
                r = await client.get("https://leakix.net/api/domain/example.com", headers=headers)
                valid = r.status_code in (200, 404)
                detail = "OK — API accessible" if valid else f"Erreur {r.status_code}"

            elif service == "github":
                token = getattr(s, "github_token", None)
                if not token:
                    return {"valid": False, "detail": "Token non configuré"}
                r = await client.get(
                    "https://api.github.com/user",
                    headers={"Authorization": f"Bearer {token}", "Accept": "application/vnd.github.v3+json"},
                )
                valid = r.status_code == 200
                if valid:
                    detail = f"OK — connecté en tant que {r.json().get('login', '?')}"
                else:
                    detail = f"Erreur {r.status_code}"

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


# =============================================================================
# Bulk Scan
# =============================================================================

class BulkScanRequest(BaseModel):
    domains: list[str] = Field(..., min_length=1, max_length=20)
    profile: str = Field(default="quick", pattern="^(quick|full)$")


@api.post("/scan/bulk")
async def bulk_scan(request: BulkScanRequest, db: Session = Depends(get_db)):
    """Lance un scan séquentiel sur plusieurs domaines (max 20)."""
    settings_row = _get_or_create_settings(db)
    settings = {
        "urlscan_key": settings_row.urlscan_key,
        "virustotal_key": getattr(settings_row, "virustotal_key", None),
        "shodan_key": getattr(settings_row, "shodan_key", None),
        "screenshot_enabled": False,
        "builtwith_key":  getattr(settings_row, "builtwith_key", None),
        "circl_user":     getattr(settings_row, "circl_user", None),
        "circl_password": getattr(settings_row, "circl_password", None),
        "abuseipdb_key":  getattr(settings_row, "abuseipdb_key", None),
        "intelx_key":     getattr(settings_row, "intelx_key", None),
        "safebrowsing_key": getattr(settings_row, "safebrowsing_key", None),
        "phishtank_key":    getattr(settings_row, "phishtank_key", None),
        "leakix_key":     getattr(settings_row, "leakix_key", None),
        "github_token":   getattr(settings_row, "github_token", None),
    }
    timeout = getattr(settings_row, "quick_timeout", None) or 60

    results = []
    for domain in request.domains:
        domain = domain.strip().lower().lstrip("https://").lstrip("http://").split("/")[0]
        if not domain:
            continue
        try:
            result = await run_scan(domain, request.profile, settings, timeout)
            db_scan = Scan(
                domain=domain,
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
                screenshot_path=None,
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
                bgpview_data=result.get("bgpview_data"),
                certsh_data=result.get("certsh_data"),
                builtwith_data=result.get("builtwith_data"),
                dast_data=result.get("dast_data"),
                pdns_data=result.get("pdns_data"),
                emailrep_data=result.get("emailrep_data"),
                abuseipdb_data=result.get("abuseipdb_data"),
                observatory_data=result.get("observatory_data"),
                cert_pinning=result.get("cert_pinning"),
                crypto_audit=result.get("crypto_audit"),
                intelx_data=result.get("intelx_data"),
                dnssec_data=result.get("dnssec_data"),
                http_versions=result.get("http_versions"),
                safebrowsing_data=result.get("safebrowsing_data"),
                phishtank_data=result.get("phishtank_data"),
                doh_comparison=result.get("doh_comparison"),
                cloud_storage=result.get("cloud_storage"),
                api_endpoints=result.get("api_endpoints"),
                cms_data=result.get("cms_data"),
                subdomain_bruteforce=result.get("subdomain_bruteforce"),
                leakix_data=result.get("leakix_data"),
                github_dork=result.get("github_dork"),
                hibp_data=result.get("hibp_data"),
                js_deps_data=result.get("js_deps_data"),
                censys_data=result.get("censys_data"),
                nuclei_data=result.get("nuclei_data"),
                email_blacklist=result.get("email_blacklist"),
                scan_timestamp=datetime.now(timezone.utc),
                status="success",
            )
            db.add(db_scan)
            db.commit()
            db.refresh(db_scan)
            results.append({"domain": domain, "scan_id": db_scan.id, "status": "success",
                            "score": (result.get("security_score") or {}).get("score"),
                            "ip": result.get("ip_address")})
        except Exception as e:
            db.rollback()
            logger.error("BULK SCAN ERROR [%s]: %s", domain, e)
            results.append({"domain": domain, "scan_id": None, "status": "error", "error": str(e)[:200]})

    return {"total": len(results), "results": results}


# =============================================================================
# Change Detection / Diff
# =============================================================================

@api.get("/scan/{scan_id}/diff/{other_id}")
async def diff_scans(scan_id: int, other_id: int, db: Session = Depends(get_db)):
    """Compare deux scans du même domaine et retourne les changements."""
    s1 = db.query(Scan).filter(Scan.id == scan_id).first()
    s2 = db.query(Scan).filter(Scan.id == other_id).first()
    if not s1 or not s2:
        raise HTTPException(status_code=404, detail="Scan non trouvé")

    def _set(val, key):
        v = val or {}
        if isinstance(v, dict):
            return set(v.get(key, []))
        return set()

    def _list_diff(a, b):
        sa, sb = set(a or []), set(b or [])
        return {"added": sorted(sb - sa), "removed": sorted(sa - sb), "unchanged": len(sa & sb)}

    # Subdomains
    subs1 = set(_extract_list(s1.subdomains, "subdomains"))
    subs2 = set(_extract_list(s2.subdomains, "subdomains"))

    # Ports
    ports1 = {p["port"] for p in (s1.open_ports or []) if isinstance(p, dict)} if isinstance(s1.open_ports, list) else set()
    ports2 = {p["port"] for p in (s2.open_ports or []) if isinstance(p, dict)} if isinstance(s2.open_ports, list) else set()

    # Security headers
    sh1 = set((s1.security_headers or {}).get("headers_found", {}).keys())
    sh2 = set((s2.security_headers or {}).get("headers_found", {}).keys())

    # Score
    score1 = (s1.security_score or {}).get("score")
    score2 = (s2.security_score or {}).get("score")
    score_delta = (score2 - score1) if (score1 is not None and score2 is not None) else None

    changes = []
    if s1.ip_address != s2.ip_address:
        changes.append({"type": "ip_change", "severity": "high",
                        "old": s1.ip_address, "new": s2.ip_address,
                        "message": f"IP changed: {s1.ip_address} → {s2.ip_address}"})
    if subs2 - subs1:
        changes.append({"type": "new_subdomains", "severity": "medium",
                        "items": sorted(subs2 - subs1),
                        "message": f"{len(subs2 - subs1)} new subdomain(s) discovered"})
    if subs1 - subs2:
        changes.append({"type": "removed_subdomains", "severity": "low",
                        "items": sorted(subs1 - subs2),
                        "message": f"{len(subs1 - subs2)} subdomain(s) no longer found"})
    if ports2 - ports1:
        changes.append({"type": "new_ports", "severity": "high",
                        "items": sorted(ports2 - ports1),
                        "message": f"New open port(s): {sorted(ports2 - ports1)}"})
    if ports1 - ports2:
        changes.append({"type": "closed_ports", "severity": "info",
                        "items": sorted(ports1 - ports2),
                        "message": f"Port(s) no longer open: {sorted(ports1 - ports2)}"})
    if sh1 - sh2:
        changes.append({"type": "headers_removed", "severity": "medium",
                        "items": sorted(sh1 - sh2),
                        "message": f"Security header(s) removed: {', '.join(sorted(sh1 - sh2))}"})
    if sh2 - sh1:
        changes.append({"type": "headers_added", "severity": "info",
                        "items": sorted(sh2 - sh1),
                        "message": f"Security header(s) added: {', '.join(sorted(sh2 - sh1))}"})
    if score_delta is not None and abs(score_delta) >= 5:
        sev = "high" if score_delta < -10 else "medium" if score_delta < 0 else "info"
        changes.append({"type": "score_change", "severity": sev,
                        "old": score1, "new": score2, "delta": score_delta,
                        "message": f"Security score: {score1} → {score2} ({score_delta:+d})"})

    tls1 = s1.tls_certificate or {}
    tls2 = s2.tls_certificate or {}
    if tls1.get("issuer_org") != tls2.get("issuer_org") and tls2.get("issuer_org"):
        changes.append({"type": "cert_issuer_change", "severity": "medium",
                        "old": tls1.get("issuer_org"), "new": tls2.get("issuer_org"),
                        "message": f"TLS cert issuer changed: {tls1.get('issuer_org')} → {tls2.get('issuer_org')}"})

    return {
        "scan_a": {"id": s1.id, "domain": s1.domain, "timestamp": s1.scan_timestamp.isoformat()},
        "scan_b": {"id": s2.id, "domain": s2.domain, "timestamp": s2.scan_timestamp.isoformat()},
        "changes": changes,
        "change_count": len(changes),
        "critical_changes": sum(1 for c in changes if c["severity"] in ("high", "critical")),
        "summary": {
            "ip": {"a": s1.ip_address, "b": s2.ip_address},
            "subdomains": {"a": len(subs1), "b": len(subs2), "diff": _list_diff(subs1, subs2)},
            "ports": {"a": sorted(ports1), "b": sorted(ports2)},
            "score": {"a": score1, "b": score2, "delta": score_delta},
        },
    }


# =============================================================================
# WebSocket — Scan avec progression en temps réel
# =============================================================================

@app.websocket("/api/ws/scan")
async def websocket_scan(ws: WebSocket):
    """WebSocket endpoint — le client envoie {domain, profile}, reçoit des events de progression."""
    await ws.accept()
    try:
        data = await asyncio.wait_for(ws.receive_json(), timeout=30)
        domain = (data.get("domain") or "").strip().lower()
        profile = data.get("profile", "full")
        if not domain or profile not in ("quick", "full"):
            await ws.send_json({"type": "error", "message": "Paramètres invalides (domain + profile requis)"})
            return

        # Load settings from DB (sync in thread)
        from .database import SessionLocal
        db = SessionLocal()
        try:
            settings_row = _get_or_create_settings(db)
            settings = {
                "urlscan_key": settings_row.urlscan_key,
                "virustotal_key": getattr(settings_row, "virustotal_key", None),
                "shodan_key": getattr(settings_row, "shodan_key", None),
                "screenshot_enabled": settings_row.screenshot_enabled,
                "builtwith_key":  getattr(settings_row, "builtwith_key", None),
                "circl_user":     getattr(settings_row, "circl_user", None),
                "circl_password": getattr(settings_row, "circl_password", None),
                "abuseipdb_key":  getattr(settings_row, "abuseipdb_key", None),
                "intelx_key":     getattr(settings_row, "intelx_key", None),
                "safebrowsing_key": getattr(settings_row, "safebrowsing_key", None),
                "phishtank_key":    getattr(settings_row, "phishtank_key", None),
                "leakix_key":     getattr(settings_row, "leakix_key", None),
                "github_token":   getattr(settings_row, "github_token", None),
            }
            timeout = (
                (getattr(settings_row, "quick_timeout", None) or 60)
                if profile == "quick"
                else (getattr(settings_row, "full_timeout", None) or 180)
            )
        finally:
            db.close()

        await ws.send_json({"type": "started", "domain": domain, "profile": profile})

        # Progress callback — sends events to WebSocket as modules complete
        async def progress_cb(event: dict):
            try:
                await ws.send_json({"type": "progress", **event})
            except Exception:
                pass

        result = await run_scan(domain, profile, settings, timeout, progress_cb=progress_cb)

        # Save to DB
        db2 = SessionLocal()
        try:
            db_scan = Scan(
                domain=domain, scan_profile=profile,
                ip_address=result.get("ip_address"),
                dns_records=result.get("dns_records"), subdomains=result.get("subdomains"),
                security_headers=result.get("security_headers"), whois_data=result.get("whois_data"),
                geo_data=result.get("geo_data"), tls_certificate=result.get("tls_certificate"),
                open_ports=result.get("open_ports"), technologies=result.get("technologies"),
                email_security=result.get("email_security"), waf=result.get("waf"),
                redirect_chain=result.get("redirect_chain"), web_files=result.get("web_files"),
                cookie_security=result.get("cookie_security"), cors=result.get("cors"),
                reverse_dns_data=result.get("reverse_dns_data"),
                subdomain_takeover=result.get("subdomain_takeover"),
                network_extended=result.get("network_extended"),
                security_score=result.get("security_score"), screenshot_path=result.get("screenshot_path"),
                urlscan_data=result.get("urlscan_data"), wayback_data=result.get("wayback_data"),
                threat_intel=result.get("threat_intel"), js_analysis=result.get("js_analysis"),
                favicon_hash=result.get("favicon_hash"), linked_domains=result.get("linked_domains"),
                hsts_preload=result.get("hsts_preload"), zone_transfer=result.get("zone_transfer"),
                wildcard_dns=result.get("wildcard_dns"), dns_rebinding=result.get("dns_rebinding"),
                tls_deep=result.get("tls_deep"), csp_grade=result.get("csp_grade"),
                hsts_deep=result.get("hsts_deep"), admin_panels=result.get("admin_panels"),
                html_intelligence=result.get("html_intelligence"), http_methods=result.get("http_methods"),
                smtp_security=result.get("smtp_security"), banners=result.get("banners"),
                typosquatting=result.get("typosquatting"), robtex=result.get("robtex"),
                shodan_data=result.get("shodan_data"), bgpview_data=result.get("bgpview_data"),
                certsh_data=result.get("certsh_data"), builtwith_data=result.get("builtwith_data"),
                dast_data=result.get("dast_data"), pdns_data=result.get("pdns_data"),
                emailrep_data=result.get("emailrep_data"), abuseipdb_data=result.get("abuseipdb_data"),
                observatory_data=result.get("observatory_data"), cert_pinning=result.get("cert_pinning"),
                crypto_audit=result.get("crypto_audit"), intelx_data=result.get("intelx_data"),
                dnssec_data=result.get("dnssec_data"), http_versions=result.get("http_versions"),
                safebrowsing_data=result.get("safebrowsing_data"), phishtank_data=result.get("phishtank_data"),
                doh_comparison=result.get("doh_comparison"), cloud_storage=result.get("cloud_storage"),
                api_endpoints=result.get("api_endpoints"), cms_data=result.get("cms_data"),
                subdomain_bruteforce=result.get("subdomain_bruteforce"),
                leakix_data=result.get("leakix_data"), github_dork=result.get("github_dork"),
                hibp_data=result.get("hibp_data"), js_deps_data=result.get("js_deps_data"),
                censys_data=result.get("censys_data"), nuclei_data=result.get("nuclei_data"),
                email_blacklist=result.get("email_blacklist"),
                scan_timestamp=datetime.now(timezone.utc), status="success",
            )
            db2.add(db_scan)
            db2.commit()
            db2.refresh(db_scan)
            scan_id = db_scan.id
        except Exception as e:
            db2.rollback()
            scan_id = None
            logger.error("WS SCAN DB ERROR: %s", e)
        finally:
            db2.close()

        await ws.send_json({"type": "complete", "scan_id": scan_id, "domain": domain})

    except asyncio.TimeoutError:
        await ws.send_json({"type": "error", "message": "Timeout — aucune donnée reçue"})
    except WebSocketDisconnect:
        pass
    except Exception as e:
        logger.error("WS SCAN ERROR: %s\n%s", e, traceback.format_exc())
        try:
            await ws.send_json({"type": "error", "message": str(e)[:200]})
        except Exception:
            pass


@api.get("/vpn/status")
async def vpn_status_endpoint():
    """Statut du VPN Mullvad (disponible uniquement si Mullvad est installé)."""
    return await vpn_get_status()

@api.post("/vpn/connect")
async def vpn_connect_endpoint():
    """Connecte au VPN Mullvad."""
    return await vpn_connect()

@api.post("/vpn/disconnect")
async def vpn_disconnect_endpoint():
    """Déconnecte du VPN Mullvad."""
    return await vpn_disconnect()

@api.get("/vpn/locations")
async def vpn_locations_endpoint():
    """Liste les pays/villes disponibles (relay list)."""
    return await vpn_list_locations()

@api.post("/vpn/location")
async def vpn_set_location_endpoint(request: VpnLocationRequest):
    """Définit le pays/ville de sortie du VPN."""
    return await vpn_set_location(request.code)


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
