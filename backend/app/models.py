# =============================================================================
# DomainRecon - Modèles SQLAlchemy
# =============================================================================

from datetime import datetime
from sqlalchemy import Column, Integer, String, DateTime, Text, JSON, Boolean
from .database import Base


class Settings(Base):
    """Table singleton pour les clés API et préférences du scanner."""

    __tablename__ = "settings"

    id                  = Column(Integer, primary_key=True, default=1)
    shodan_key          = Column(String(100), nullable=True)
    virustotal_key      = Column(String(100), nullable=True)
    securitytrails_key  = Column(String(100), nullable=True)
    censys_id           = Column(String(100), nullable=True)
    censys_secret       = Column(String(100), nullable=True)
    urlscan_key         = Column(String(100), nullable=True)
    screenshot_enabled  = Column(Boolean, default=False)
    scan_timeout        = Column(Integer, default=60)
    updated_at          = Column(DateTime, nullable=True)

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
    # v3.1 — Extended
    network_extended = Column(JSON, nullable=True)
    security_score = Column(JSON, nullable=True)
    screenshot_path = Column(String(500), nullable=True)
    tags = Column(JSON, nullable=True)
    notes = Column(Text, nullable=True)
    # v4.0 — OSINT Enhanced
    urlscan_data = Column(JSON, nullable=True)
    wayback_data = Column(JSON, nullable=True)
    threat_intel = Column(JSON, nullable=True)
    js_analysis = Column(JSON, nullable=True)
    favicon_hash = Column(JSON, nullable=True)
    linked_domains = Column(JSON, nullable=True)
    email_blacklist = Column(JSON, nullable=True)
    hsts_preload = Column(JSON, nullable=True)
    # v5.0 — Vulnerability Scan
    vuln_data = Column(JSON, nullable=True)
    scan_timestamp = Column(DateTime, default=datetime.utcnow, nullable=False)
    status = Column(String(50), default="success", nullable=False)
    error_message = Column(Text, nullable=True)

    def __repr__(self):
        return f"<Scan(id={self.id}, domain='{self.domain}')>"
