# =============================================================================
# DomainRecon - Scanner
# =============================================================================
# Les modules de scan sont découverts dans scanner/modules/ (un fichier par
# module, voir registry.py et docs/contrat-modules.md). Les 18 premiers
# (DNS, sous-domaines, en-têtes, TLS, ports, géolocalisation, WHOIS,
# technologies, e-mail, WAF, redirections, fichiers web, cookies, CORS,
# takeover, DNS inverse, réseau étendu, capture) gardent leur colonne dédiée
# (liste de référence : orchestrator.MODULE_NAMES).
#
# Ce package réexporte l'API du scanner (`from domainrecon.scanner import X`
# pour les noms qu'utilisent l'API et les tests), ainsi que la politique de
# cibles. Les critères du score (score.CRITERIA_WEIGHTS…) se lisent dans
# score.py : ils sont calculés à partir du registre à chaque lecture.
# =============================================================================

from .common import USER_AGENT, VERIFY_TLS, _api_client, _http_client, logger, url_host
from .cookies import analyze_cookies
from .cors import check_cors
from .dns import (
    DNS_RECORD_TYPES,
    SUBDOMAIN_MAX_RESULTS,
    SUBDOMAIN_RESOLVE_LIMIT,
    DnsLookup,
    DnsQuerier,
    _scan_dns_sync,
    find_dmarc,
    find_subdomains,
    is_dmarc_record,
    reverse_dns,
    scan_dns_records,
    txt_record_text,
)
from .email_security import (
    DKIM_SELECTORS,
    SPF_MAX_DNS_LOOKUPS,
    _analyze_email_security_sync,
    analyze_email_security,
    parse_spf,
    parse_tags,
)
from .errors import ModuleError, TargetNotAllowedError
from .headers import (
    HSTS_MIN_MAX_AGE,
    INFORMATIONAL_HEADERS,
    SECURITY_HEADERS,
    check_security_headers,
    empty_headers_result,
    evaluate_security_headers,
)
from .network import (
    COMMON_PORTS,
    PORT_SCAN_CONCURRENCY,
    PORT_TIMEOUT,
    _check_port,
    extended_network_scan,
    get_geo_data,
    scan_ports,
)
from .orchestrator import (
    MODULE_NAMES,
    MODULE_TIMEOUT,
    TAKEOVER_TIMEOUT,
    TARGET_RESOLVE_TIMEOUT,
    perform_full_scan,
)
from .redirects import trace_redirects
from .score import (
    GRADE_THRESHOLDS,
    PORT_PENALTY_POINTS,
    SCORE_VERSION,
    SENSITIVE_PORTS,
    compute_security_score,
    grade_for_score,
)
from .screenshot import SCREENSHOT_NAME_RE, SCREENSHOTS_DIR, capture_screenshot, screenshot_filename
from .takeover import TAKEOVER_FINGERPRINTS, TAKEOVER_MAX_SUBDOMAINS, check_subdomain_takeover
from .targets import (
    _HOSTNAME_RE,
    _TLD_EXTRACT,
    ensure_ip_allowed,
    ensure_target_allowed,
    extract_domain,
    is_ip_literal,
    is_public_address,
    is_valid_target,
    normalize_target,
    primary_address,
    registrable_domain,
    resolve_addresses,
    resolve_ip,
    site_domain,
)
from .technologies import TECH_BODY_SIGS, TECH_HEADER_SIGS, detect_technologies
from .tls import TLS_PORT, TLS_TIMEOUT, _check_tls_sync, check_tls_certificate
from .waf import WAF_SIGNATURES, detect_waf
from .web_files import check_web_files
from .whois_lookup import WHOIS_TIMEOUT, _get_whois_sync, get_whois_data

__all__ = [
    # common
    "logger",
    "USER_AGENT",
    "VERIFY_TLS",
    "_http_client",
    "_api_client",
    "url_host",
    # errors
    "ModuleError",
    "TargetNotAllowedError",
    # targets
    "_TLD_EXTRACT",
    "_HOSTNAME_RE",
    "normalize_target",
    "registrable_domain",
    "site_domain",
    "is_valid_target",
    "extract_domain",
    "resolve_ip",
    "is_ip_literal",
    "is_public_address",
    "primary_address",
    "resolve_addresses",
    "ensure_target_allowed",
    "ensure_ip_allowed",
    # dns
    "DNS_RECORD_TYPES",
    "SUBDOMAIN_RESOLVE_LIMIT",
    "SUBDOMAIN_MAX_RESULTS",
    "DnsLookup",
    "DnsQuerier",
    "find_dmarc",
    "txt_record_text",
    "is_dmarc_record",
    "_scan_dns_sync",
    "scan_dns_records",
    "find_subdomains",
    "reverse_dns",
    # headers
    "SECURITY_HEADERS",
    "INFORMATIONAL_HEADERS",
    "HSTS_MIN_MAX_AGE",
    "evaluate_security_headers",
    "empty_headers_result",
    "check_security_headers",
    # tls
    "TLS_PORT",
    "TLS_TIMEOUT",
    "_check_tls_sync",
    "check_tls_certificate",
    # network
    "COMMON_PORTS",
    "PORT_TIMEOUT",
    "PORT_SCAN_CONCURRENCY",
    "_check_port",
    "scan_ports",
    "get_geo_data",
    "extended_network_scan",
    # whois_lookup
    "WHOIS_TIMEOUT",
    "_get_whois_sync",
    "get_whois_data",
    # technologies
    "TECH_HEADER_SIGS",
    "TECH_BODY_SIGS",
    "detect_technologies",
    # waf
    "WAF_SIGNATURES",
    "detect_waf",
    # redirects
    "trace_redirects",
    # web_files
    "check_web_files",
    # cookies
    "analyze_cookies",
    # cors
    "check_cors",
    # email_security
    "DKIM_SELECTORS",
    "SPF_MAX_DNS_LOOKUPS",
    "parse_spf",
    "parse_tags",
    "_analyze_email_security_sync",
    "analyze_email_security",
    # takeover
    "TAKEOVER_FINGERPRINTS",
    "TAKEOVER_MAX_SUBDOMAINS",
    "check_subdomain_takeover",
    # score
    "SCORE_VERSION",
    "GRADE_THRESHOLDS",
    "SENSITIVE_PORTS",
    "PORT_PENALTY_POINTS",
    "grade_for_score",
    "compute_security_score",
    # screenshot
    "SCREENSHOTS_DIR",
    "SCREENSHOT_NAME_RE",
    "screenshot_filename",
    "capture_screenshot",
    # orchestrator
    "MODULE_NAMES",
    "MODULE_TIMEOUT",
    "TAKEOVER_TIMEOUT",
    "TARGET_RESOLVE_TIMEOUT",
    "perform_full_scan",
]
