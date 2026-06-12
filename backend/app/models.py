# =============================================================================
# DomainRecon - Models
# =============================================================================

from datetime import datetime
from sqlalchemy import Column, Integer, String, DateTime, Text, JSON, Boolean
from .crypto import EncryptedString
from .database import Base


class Settings(Base):
    """Table singleton pour les clés API et préférences du scanner."""

    __tablename__ = "settings"

    id                  = Column(Integer, primary_key=True, default=1)
    shodan_key          = Column(EncryptedString(500), nullable=True)
    virustotal_key      = Column(EncryptedString(500), nullable=True)
    securitytrails_key  = Column(EncryptedString(500), nullable=True)
    censys_id           = Column(EncryptedString(500), nullable=True)
    censys_secret       = Column(EncryptedString(500), nullable=True)
    urlscan_key         = Column(EncryptedString(500), nullable=True)
    screenshot_enabled  = Column(Boolean, default=False)
    scan_timeout        = Column(Integer, default=60)
    updated_at          = Column(DateTime, nullable=True)
    quick_timeout       = Column(Integer, default=30)
    full_timeout        = Column(Integer, default=180)
    builtwith_key       = Column(EncryptedString(500), nullable=True)
    circl_user          = Column(EncryptedString(500), nullable=True)
    circl_password      = Column(EncryptedString(500), nullable=True)
    abuseipdb_key       = Column(EncryptedString(500), nullable=True)
    intelx_key          = Column(EncryptedString(500), nullable=True)
    safebrowsing_key    = Column(EncryptedString(500), nullable=True)
    phishtank_key       = Column(EncryptedString(500), nullable=True)
    leakix_key          = Column(EncryptedString(500), nullable=True)
    github_token        = Column(EncryptedString(500), nullable=True)
    google_cse_key      = Column(EncryptedString(500), nullable=True)

    def __repr__(self):
        return "<Settings>"


class Scan(Base):
    """Table des scans de domaines."""

    __tablename__ = "scans"

    id = Column(Integer, primary_key=True, index=True)
    domain = Column(String(255), nullable=False, index=True)
    ip_address = Column(String(45), nullable=True)
    dns_records = Column(JSON, nullable=True)
    subdomains = Column(JSON, nullable=True)
    security_headers = Column(JSON, nullable=True)
    whois_data = Column(JSON, nullable=True)
    geo_data = Column(JSON, nullable=True)
    tls_certificate = Column(JSON, nullable=True)
    open_ports = Column(JSON, nullable=True)
    technologies = Column(JSON, nullable=True)
    email_security = Column(JSON, nullable=True)
    waf = Column(JSON, nullable=True)
    redirect_chain = Column(JSON, nullable=True)
    web_files = Column(JSON, nullable=True)
    cookie_security = Column(JSON, nullable=True)
    cors = Column(JSON, nullable=True)
    reverse_dns_data = Column(JSON, nullable=True)
    subdomain_takeover = Column(JSON, nullable=True)
    network_extended = Column(JSON, nullable=True)
    security_score = Column(JSON, nullable=True)
    screenshot_path = Column(String(500), nullable=True)
    tags = Column(JSON, nullable=True)
    notes = Column(Text, nullable=True)
    urlscan_data = Column(JSON, nullable=True)
    wayback_data = Column(JSON, nullable=True)
    threat_intel = Column(JSON, nullable=True)
    js_analysis = Column(JSON, nullable=True)
    favicon_hash = Column(JSON, nullable=True)
    linked_domains = Column(JSON, nullable=True)
    email_blacklist = Column(JSON, nullable=True)
    hsts_preload = Column(JSON, nullable=True)
    zone_transfer       = Column(JSON, nullable=True)
    wildcard_dns        = Column(JSON, nullable=True)
    dns_rebinding       = Column(JSON, nullable=True)
    tls_deep            = Column(JSON, nullable=True)
    csp_grade           = Column(JSON, nullable=True)
    hsts_deep           = Column(JSON, nullable=True)
    admin_panels        = Column(JSON, nullable=True)
    html_intelligence   = Column(JSON, nullable=True)
    http_methods        = Column(JSON, nullable=True)
    smtp_security       = Column(JSON, nullable=True)
    banners             = Column(JSON, nullable=True)
    typosquatting       = Column(JSON, nullable=True)
    scan_profile        = Column(String(10), nullable=True)
    robtex              = Column(JSON, nullable=True)
    shodan_data         = Column(JSON, nullable=True)
    bgpview_data        = Column(JSON, nullable=True)
    certsh_data         = Column(JSON, nullable=True)
    builtwith_data      = Column(JSON, nullable=True)
    dast_data           = Column(JSON, nullable=True)
    pdns_data           = Column(JSON, nullable=True)
    emailrep_data       = Column(JSON, nullable=True)
    abuseipdb_data      = Column(JSON, nullable=True)
    observatory_data    = Column(JSON, nullable=True)
    cert_pinning        = Column(JSON, nullable=True)
    crypto_audit        = Column(JSON, nullable=True)
    intelx_data         = Column(JSON, nullable=True)
    dnssec_data         = Column(JSON, nullable=True)
    http_versions       = Column(JSON, nullable=True)
    safebrowsing_data   = Column(JSON, nullable=True)
    phishtank_data      = Column(JSON, nullable=True)
    doh_comparison      = Column(JSON, nullable=True)
    cloud_storage       = Column(JSON, nullable=True)
    api_endpoints       = Column(JSON, nullable=True)
    cms_data            = Column(JSON, nullable=True)
    subdomain_bruteforce = Column(JSON, nullable=True)
    leakix_data         = Column(JSON, nullable=True)
    github_dork         = Column(JSON, nullable=True)
    hibp_data           = Column(JSON, nullable=True)
    js_deps_data        = Column(JSON, nullable=True)
    censys_data         = Column(JSON, nullable=True)
    nuclei_data         = Column(JSON, nullable=True)
    js_secrets_data     = Column(JSON, nullable=True)
    dnsbl_data          = Column(JSON, nullable=True)
    paste_data          = Column(JSON, nullable=True)
    mta_sts             = Column(JSON, nullable=True)
    bimi                = Column(JSON, nullable=True)
    reverse_ip          = Column(JSON, nullable=True)
    scan_timestamp = Column(DateTime, default=datetime.utcnow, nullable=False)
    status = Column(String(50), default="success", nullable=False)
    error_message = Column(Text, nullable=True)

    def __repr__(self):
        return f"<Scan(id={self.id}, domain='{self.domain}')>"
