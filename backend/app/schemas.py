# backend/app/schemas.py
"""Pydantic schemas - request/response models for the DomainRecon API."""

from datetime import datetime
from typing import Optional

from pydantic import BaseModel, Field


class VpnLocationRequest(BaseModel):
    code: str = Field(..., pattern=r"^[a-z]{2}(-[a-z0-9]+)?$")


class ScanRequest(BaseModel):
    domain: str = Field(..., min_length=1, max_length=255)
    profile: str = Field(default="full", pattern="^(quick|full)$")


class BulkScanRequest(BaseModel):
    domains: list[str] = Field(..., min_length=1, max_length=20)
    profile: str = Field(default="quick", pattern="^(quick|full)$")


class TagsNotesRequest(BaseModel):
    tags: Optional[list] = None
    notes: Optional[str] = None


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
    js_secrets_data:    Optional[dict] = None
    dnsbl_data:         Optional[dict] = None
    paste_data:         Optional[dict] = None
    mta_sts:            Optional[dict] = None
    bimi:               Optional[dict] = None
    reverse_ip:         Optional[dict] = None
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
    quick_timeout: Optional[int] = 60
    full_timeout:  Optional[int] = 300
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
    shodan_valid: Optional[bool] = None
    securitytrails_valid: Optional[bool] = None
    censys_valid: Optional[bool] = None
    urlscan_valid: Optional[bool] = None
    builtwith_valid: Optional[bool] = None

    class Config:
        from_attributes = True
