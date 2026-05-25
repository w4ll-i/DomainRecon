# backend/app/helpers.py
"""Common helpers - key masking, settings access, scan serialization."""

from typing import Optional

from sqlalchemy.orm import Session

from .models import Scan, Settings
from .schemas import ScanResponse, SettingsResponse


# ─── Keys / settings ─────────────────────────────────────────────────────────

def mask_key(key: Optional[str]) -> Optional[str]:
    """Mask an API key - return only the last 4 characters, prefixed with bullets."""
    if not key:
        return None
    if len(key) <= 4:
        return "••••"
    return "••••••••" + key[-4:]


def get_or_create_settings(db: Session) -> Settings:
    """Return the singleton settings row, creating it if missing."""
    s = db.query(Settings).filter(Settings.id == 1).first()
    if not s:
        s = Settings(id=1)
        db.add(s)
        db.commit()
        db.refresh(s)
    return s


def settings_to_scan_config(s: Settings, *, include_password: bool = True) -> dict:
    """Build the settings dict consumed by `run_scan()`."""
    cfg = {
        "urlscan_key":       s.urlscan_key,
        "virustotal_key":    getattr(s, "virustotal_key", None),
        "shodan_key":        getattr(s, "shodan_key", None),
        "screenshot_enabled": s.screenshot_enabled,
        "builtwith_key":     getattr(s, "builtwith_key", None),
        "circl_user":        getattr(s, "circl_user", None),
        "abuseipdb_key":     getattr(s, "abuseipdb_key", None),
        "intelx_key":        getattr(s, "intelx_key", None),
        "safebrowsing_key":  getattr(s, "safebrowsing_key", None),
        "phishtank_key":     getattr(s, "phishtank_key", None),
        "leakix_key":        getattr(s, "leakix_key", None),
        "github_token":      getattr(s, "github_token", None),
        "google_cse_key":    getattr(s, "google_cse_key", None),
        "censys_id":         getattr(s, "censys_id", None),
        "censys_secret":     getattr(s, "censys_secret", None),
    }
    if include_password:
        cfg["circl_password"] = getattr(s, "circl_password", None)
    return cfg


def timeout_for_profile(s: Settings, profile: str) -> int:
    """Pick the configured timeout for a scan profile."""
    if profile == "quick":
        return getattr(s, "quick_timeout", None) or 60
    return getattr(s, "full_timeout", None) or 300


def settings_response(s: Settings) -> SettingsResponse:
    """Build the public (masked) settings response."""
    return SettingsResponse(
        shodan_key=mask_key(s.shodan_key),
        virustotal_key=mask_key(getattr(s, "virustotal_key", None)),
        securitytrails_key=mask_key(s.securitytrails_key),
        censys_id=mask_key(s.censys_id),
        censys_secret=mask_key(s.censys_secret),
        urlscan_key=mask_key(s.urlscan_key),
        builtwith_key=mask_key(getattr(s, "builtwith_key", None)),
        circl_user=getattr(s, "circl_user", None) or None,
        abuseipdb_key=mask_key(getattr(s, "abuseipdb_key", None)),
        intelx_key=mask_key(getattr(s, "intelx_key", None)),
        safebrowsing_key=mask_key(getattr(s, "safebrowsing_key", None)),
        phishtank_key=mask_key(getattr(s, "phishtank_key", None)),
        leakix_key=mask_key(getattr(s, "leakix_key", None)),
        github_token=mask_key(getattr(s, "github_token", None)),
        screenshot_enabled=s.screenshot_enabled or False,
        scan_timeout=s.scan_timeout or 60,
    )


# ─── Scan serialization ──────────────────────────────────────────────────────

def extract_list(val, key: str) -> list:
    """Extract a list from a {key: [...]} wrapper, or return the value directly."""
    if isinstance(val, dict):
        return val.get(key, [])
    return val or []


def scan_to_response(scan: Scan) -> ScanResponse:
    """Convert a Scan ORM row into a ScanResponse payload."""
    return ScanResponse(
        id=scan.id,
        domain=scan.domain,
        ip_address=scan.ip_address,
        dns_records=scan.dns_records or {},
        subdomains=extract_list(scan.subdomains, "subdomains"),
        security_headers=scan.security_headers or {},
        whois_data=scan.whois_data or {},
        geo_data=scan.geo_data or {},
        tls_certificate=scan.tls_certificate or {},
        open_ports=scan.open_ports if isinstance(scan.open_ports, list) else extract_list(scan.open_ports, "open_ports"),
        technologies=scan.technologies if isinstance(scan.technologies, list) else extract_list(scan.technologies, "technologies"),
        email_security=scan.email_security or {},
        waf=scan.waf or {},
        redirect_chain=scan.redirect_chain or {},
        web_files=scan.web_files or {},
        cookie_security=scan.cookie_security or {},
        cors=scan.cors or {},
        reverse_dns=scan.reverse_dns_data or {},
        subdomain_takeover=extract_list(scan.subdomain_takeover, "vulnerable"),
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
        js_secrets_data=getattr(scan, "js_secrets_data", None),
        dnsbl_data=getattr(scan, "dnsbl_data", None),
        paste_data=getattr(scan, "paste_data", None),
        mta_sts=getattr(scan, "mta_sts", None),
        bimi=getattr(scan, "bimi", None),
        reverse_ip=getattr(scan, "reverse_ip", None),
        scan_timestamp=scan.scan_timestamp,
        status=scan.status,
        error_message=scan.error_message,
    )


# Columns of `Scan` that come from a scan `result` dict. Used by
# both POST /scan and the WebSocket to build ORM rows without repeating
# 70 `key=result.get("key")` lines.
_SCAN_RESULT_COLUMNS = (
    "ip_address", "dns_records", "subdomains", "security_headers",
    "whois_data", "geo_data", "tls_certificate", "open_ports",
    "technologies", "email_security", "waf", "redirect_chain",
    "web_files", "cookie_security", "cors",
    "subdomain_takeover", "network_extended", "security_score",
    "screenshot_path", "urlscan_data", "wayback_data", "threat_intel",
    "js_analysis", "favicon_hash", "linked_domains", "hsts_preload",
    "zone_transfer", "wildcard_dns", "dns_rebinding", "tls_deep",
    "csp_grade", "hsts_deep", "admin_panels", "html_intelligence",
    "http_methods", "smtp_security", "banners", "typosquatting",
    "robtex", "shodan_data", "bgpview_data", "certsh_data",
    "builtwith_data", "dast_data", "pdns_data", "emailrep_data",
    "abuseipdb_data", "observatory_data", "cert_pinning", "crypto_audit",
    "intelx_data", "dnssec_data", "http_versions", "safebrowsing_data",
    "phishtank_data", "doh_comparison", "cloud_storage", "api_endpoints",
    "cms_data", "subdomain_bruteforce", "leakix_data", "github_dork",
    "hibp_data", "js_deps_data", "censys_data", "nuclei_data",
    "js_secrets_data", "dnsbl_data", "paste_data", "email_blacklist",
    "mta_sts", "bimi", "reverse_ip",
)


def build_scan_kwargs(result: dict) -> dict:
    """Translate a `run_scan()` result dict into Scan(**kwargs) arguments."""
    kwargs = {col: result.get(col) for col in _SCAN_RESULT_COLUMNS}
    # reverse_dns_data comes under the same name from result
    kwargs["reverse_dns_data"] = result.get("reverse_dns_data")
    return kwargs
