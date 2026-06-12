# backend/app/scanner.py
"""
DomainRecon - Scan Orchestrator.

Execution flow:
  1. Resolve IP
  2. Wave 1: all independent async tasks (dict-based, per-module timeouts)
  3. Post-Wave-1: pure calculations (grade_csp, compute_spoofability)
  4. Wave 2: tasks that depend on Wave 1 output
  5. Post-Wave-2: assemble smtp_security + compute score

Design notes:
  * Tasks are registered by name in dicts - no positional coupling. Adding
    a module = one entry; removing = delete one line.
  * Each task has its own timeout (`TASK_TIMEOUTS`). A single slow module
    no longer blocks the whole batch via a shared global deadline.
  * The outer `timeout` parameter still acts as a hard ceiling for the
    entire Wave 1 to cap worst case.
"""
import asyncio
import logging
import re
from datetime import datetime
from typing import Awaitable, Callable, Optional

logger = logging.getLogger("domainrecon")

# ─── Normalization constants ───────────────────────────────────────────────────
_SH_KEYS = [
    "Strict-Transport-Security", "X-Frame-Options", "X-Content-Type-Options",
    "Content-Security-Policy", "X-XSS-Protection", "Referrer-Policy", "Permissions-Policy",
]
_PORTS_SVC = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS", 80: "HTTP",
    110: "POP3", 143: "IMAP", 443: "HTTPS", 445: "SMB", 587: "SMTP/TLS",
    993: "IMAPS", 995: "POP3S", 3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL",
    5900: "VNC", 6379: "Redis", 8080: "HTTP-Proxy", 8443: "HTTPS-Alt",
    8888: "HTTP-Alt", 27017: "MongoDB",
}
_GRADE_PTS = {"A": 4, "B": 3, "C": 2, "D": 1, "F": 0}

from .scanners.dns import (
    resolve_ip, scan_dns_records, find_subdomains,
    check_zone_transfer, check_wildcard, check_dns_rebinding,
    check_subdomain_takeover, reverse_dns,
)
from .scanners.tls import check_tls_certificate, scan_tls_deep, check_ocsp_stapling
from .scanners.web import (
    check_security_headers, grade_csp, analyze_hsts_deep,
    check_web_files, analyze_cookies, check_cors, trace_redirects,
    discover_admin_panels, extract_html_intelligence, check_http_methods,
)
from .scanners.email import (
    analyze_email_security, check_smtp_security, check_catch_all,
    compute_spoofability, check_email_blacklists,
    check_mta_sts, check_bimi,
)
from .scanners.ports import scan_ports, grab_banners
from .scanners.network import get_geo_data, extended_network_scan, robtex_lookup, reverse_ip_lookup
from .scanners.osint import (
    get_whois_data, check_wayback_machine, urlscan_lookup,
    check_threat_intelligence, analyze_js_files, compute_favicon_hash,
    extract_linked_domains, check_hsts_preload, capture_screenshot,
)
from .scanners.tech import detect_technologies, detect_waf
from .scanners.scoring import compute_security_score
from .scanners.shodan_scanner import shodan_lookup
from .scanners.pdns_scanner import pdns_lookup
from .scanners.certsh_scanner import certsh_lookup
from .scanners.builtwith_scanner import builtwith_lookup
from .scanners.bgpview_scanner import bgpview_lookup
from .scanners.dast_scanner import dast_scan
from .scanners.emailrep_scanner import emailrep_lookup
from .scanners.abuseipdb_scanner import abuseipdb_lookup
from .scanners.observatory_scanner import observatory_scan
from .scanners.cert_pinning_scanner import check_cert_pinning
from .scanners.crypto_scanner import crypto_audit
from .scanners.intelx_scanner import intelx_search
from .scanners.dnssec_scanner import check_dnssec
from .scanners.http_version_scanner import check_http_versions
from .scanners.safebrowsing_scanner import safebrowsing_check
from .scanners.phishtank_scanner import phishtank_check
from .scanners.doh_scanner import doh_comparison
from .scanners.cloud_storage_scanner import cloud_storage_scan
from .scanners.api_endpoints_scanner import scan_api_endpoints
from .scanners.cms_scanner import scan_cms
from .scanners.subdomain_bruteforce import bruteforce_subdomains
from .scanners.leakix_scanner import leakix_lookup
from .scanners.github_dork_scanner import github_dork
from .scanners.hibp_scanner import hibp_check
from .scanners.js_dependency_scanner import scan_js_dependencies
from .scanners.censys_scanner import censys_lookup
from .scanners.nuclei_scanner import nuclei_scan
from .scanners.js_secrets_scanner import scan_js_secrets
from .scanners.typosquatting_scanner import scan_typosquatting
from .scanners.dnsbl_scanner import scan_dnsbl
from .scanners.paste_scanner import scan_paste


# Per-module timeout (seconds). Modules not listed use DEFAULT_TIMEOUT.
DEFAULT_TIMEOUT = 25.0
TASK_TIMEOUTS: dict[str, float] = {
    # Fast DNS / passive
    "dns_records":           8.0,
    "zone_transfer":         8.0,
    "wildcard":              8.0,
    "dns_rebinding":         8.0,
    "reverse_dns":           5.0,
    "dnssec":                10.0,
    "mta_sts":               8.0,
    "bimi":                  5.0,
    "doh_comparison":        10.0,
    "email_security":        15.0,
    "email_blacklist":       15.0,
    # TLS / HTTP
    "tls_certificate":       15.0,
    "security_headers":      15.0,
    "hsts_preload":          10.0,
    "hsts_deep":             15.0,
    "cookies":               15.0,
    "cors":                  15.0,
    "redirects":             15.0,
    "http_methods":          15.0,
    "http_versions":         15.0,
    "cert_pinning":          15.0,
    "favicon_hash":          10.0,
    # Tech detection
    "technologies":          15.0,
    "waf":                   15.0,
    "web_files":             30.0,
    "html_intel":            15.0,
    # External OSINT (slower)
    "subdomains":            45.0,
    "whois":                 15.0,
    "wayback":               20.0,
    "urlscan":               20.0,
    "threat_intel":          25.0,
    "robtex":                15.0,
    "network_ext":           15.0,
    "reverse_ip":            15.0,
    "catch_all":             15.0,
    "geo":                   10.0,
    "ports":                 30.0,
    "linked_domains":        20.0,
    "js_analysis":           30.0,
    "certsh":                25.0,
    "pdns":                  20.0,
    "builtwith":             20.0,
    "bgpview":               15.0,
    # Heavier / optional
    "dast":                  60.0,
    "observatory":           45.0,
    "crypto_audit":          30.0,
    "safebrowsing":          10.0,
    "phishtank":             10.0,
    "cloud_storage":         30.0,
    "api_endpoints":         40.0,
    "cms":                   30.0,
    "subdomain_bruteforce":  60.0,
    "hibp":                  15.0,
    "js_dependencies":       30.0,
    "censys":                15.0,
    "js_secrets_data":       30.0,
    "typosquatting":         30.0,
    "paste_data":            20.0,
    # Wave 2
    "subdomain_takeover":    60.0,
    "emailrep_data":         15.0,
    "abuseipdb_data":        10.0,
    "shodan_data":           15.0,
    "banners":               30.0,
    "tls_deep":              45.0,
    "admin_panels":          45.0,
    "smtp_raw":              30.0,
    "screenshot":            40.0,
    "leakix_data":           15.0,
    "github_dork":           20.0,
    "nuclei_data":          120.0,
    "dnsbl_data":            20.0,
}


def _timeout_for(name: str) -> float:
    return TASK_TIMEOUTS.get(name, DEFAULT_TIMEOUT)


async def _noop() -> dict:
    return {}


async def _tracked(
    name: str,
    coro: Awaitable,
    total: int,
    progress_cb: Optional[Callable] = None,
    wave: int = 1,
) -> dict:
    """Wrap a coroutine with its own timeout and emit a progress event on completion."""
    try:
        result = await asyncio.wait_for(coro, timeout=_timeout_for(name))
        status = "done"
    except asyncio.TimeoutError:
        logger.debug("module '%s' timed out after %ss", name, _timeout_for(name))
        result = {"error": f"module timeout after {_timeout_for(name)}s"}
        status = "error"
    except Exception as e:
        logger.debug("module '%s' failed: %s", name, e, exc_info=True)
        result = {"error": str(e)[:200]}
        status = "error"
    if progress_cb:
        try:
            await progress_cb({"module": name, "total": total, "status": status, "wave": wave})
        except Exception:
            pass
    return result


async def _run_wave(
    tasks: dict[str, Awaitable],
    progress_cb: Optional[Callable] = None,
    wave_deadline: Optional[float] = None,
    wave: int = 1,
) -> dict[str, dict]:
    """Run a dict of {name: coroutine} in parallel, each with its own timeout.

    Returns a dict {name: result_or_error_dict}. Missing/failed modules resolve to {}.
    """
    total = len(tasks)
    names = list(tasks.keys())
    coros = [_tracked(name, tasks[name], total, progress_cb, wave) for name in names]

    try:
        if wave_deadline:
            results = await asyncio.wait_for(
                asyncio.gather(*coros, return_exceptions=True),
                timeout=wave_deadline,
            )
        else:
            results = await asyncio.gather(*coros, return_exceptions=True)
    except asyncio.TimeoutError:
        # Global wave deadline hit - return whatever didn't finish as empty.
        return {n: {} for n in names}

    def _safe(v):
        return v if isinstance(v, dict) else ({} if isinstance(v, BaseException) else (v or {}))

    return {n: _safe(r) for n, r in zip(names, results)}


async def run_scan(
    domain: str,
    scan_profile: str = "full",
    settings: Optional[dict] = None,
    timeout: int = 300,
    progress_cb=None,
) -> dict:
    if settings is None:
        settings = {}
    is_full = scan_profile == "full"

    ip = await resolve_ip(domain)

    # ─── Wave 1 - all independent tasks ─────────────────────────────────────
    w1: dict[str, Awaitable] = {
        "dns_records":      scan_dns_records(domain),
        "subdomains":       find_subdomains(domain, scan_profile),
        "tls_certificate":  check_tls_certificate(domain),
        "security_headers": check_security_headers(domain),
        "web_files":        check_web_files(domain),
        "cookies":          analyze_cookies(domain),
        "cors":             check_cors(domain),
        "redirects":        trace_redirects(domain),
        "technologies":     detect_technologies(domain),
        "waf":              detect_waf(domain),
        "whois":            get_whois_data(domain),
        "wayback":          check_wayback_machine(domain),
        "email_security":   analyze_email_security(domain),
        "hsts_preload":     check_hsts_preload(domain),
        "linked_domains":   extract_linked_domains(domain),
        "js_analysis":      analyze_js_files(domain),
        "favicon_hash":     compute_favicon_hash(domain),
        "geo":              get_geo_data(ip) if ip else _noop(),
        "ports":            scan_ports(ip) if ip else _noop(),
        "zone_transfer":    check_zone_transfer(domain),
        "wildcard":         check_wildcard(domain),
        "dns_rebinding":    check_dns_rebinding(domain),
        "email_blacklist":  check_email_blacklists(ip) if ip else _noop(),
        "html_intel":       extract_html_intelligence(domain),
        "http_methods":     check_http_methods(domain),
        "hsts_deep":        analyze_hsts_deep(domain),
        "reverse_dns":      reverse_dns(ip) if ip else _noop(),
        "network_ext":      extended_network_scan(ip) if ip else _noop(),
        "robtex":           robtex_lookup(domain),
        "urlscan":          urlscan_lookup(domain, settings.get("urlscan_key")),
        "threat_intel":     check_threat_intelligence(domain, ip or "", settings.get("virustotal_key")),
        "catch_all":        check_catch_all(domain),
        "certsh":           certsh_lookup(domain),
        "pdns":             pdns_lookup(
                                domain,
                                settings.get("circl_user", "") or "",
                                settings.get("circl_password", "") or "",
                            ),
        "builtwith":        builtwith_lookup(domain, settings.get("builtwith_key", "") or ""),
        "bgpview":          bgpview_lookup(ip) if (is_full and ip) else _noop(),
        "dast":             dast_scan(domain) if is_full else _noop(),
        "observatory":      observatory_scan(domain) if is_full else _noop(),
        "cert_pinning":     check_cert_pinning(domain),
        "crypto_audit":     crypto_audit(domain),
        "dnssec":           check_dnssec(domain),
        "http_versions":    check_http_versions(domain),
        "safebrowsing":     safebrowsing_check(domain, settings.get("safebrowsing_key")),
        "phishtank":        phishtank_check(domain, settings.get("phishtank_key")),
        "doh_comparison":   doh_comparison(domain),
        "cloud_storage":    cloud_storage_scan(domain),
        "api_endpoints":    scan_api_endpoints(domain),
        "cms":              scan_cms(domain),
        "subdomain_bruteforce": bruteforce_subdomains(domain),
        "hibp":             hibp_check(domain),
        "js_dependencies":  scan_js_dependencies(domain),
        "censys":           censys_lookup(
                                domain,
                                settings.get("censys_id", "") or "",
                                settings.get("censys_secret", "") or "",
                            ),
        "js_secrets_data":  scan_js_secrets(domain, settings),
        "typosquatting":    scan_typosquatting(domain, settings),
        "paste_data":       scan_paste(domain, settings),
        "mta_sts":          check_mta_sts(domain),
        "bimi":             check_bimi(domain),
        "reverse_ip":       reverse_ip_lookup(ip) if ip else _noop(),
    }

    r1 = await _run_wave(w1, progress_cb, wave_deadline=timeout, wave=1)

    # ─── Extract wave 1 results ─────────────────────────────────────────────
    dns_records       = r1["dns_records"]
    subdomains        = r1["subdomains"]
    tls_cert          = r1["tls_certificate"]
    security_headers  = r1["security_headers"]
    web_files         = r1["web_files"]
    cookies           = r1["cookies"]
    cors              = r1["cors"]
    redirects         = r1["redirects"]
    technologies      = r1["technologies"]
    waf               = r1["waf"]
    whois             = r1["whois"]
    wayback           = r1["wayback"]
    email_security    = r1["email_security"]
    hsts_preload      = r1["hsts_preload"]
    linked_domains    = r1["linked_domains"]
    js_analysis       = r1["js_analysis"]
    favicon_hash      = r1["favicon_hash"]
    geo               = r1["geo"]
    ports             = r1["ports"]
    zone_transfer     = r1["zone_transfer"]
    wildcard          = r1["wildcard"]
    dns_rebinding     = r1["dns_rebinding"]
    email_blacklist   = r1["email_blacklist"]
    html_intel        = r1["html_intel"]
    http_methods      = r1["http_methods"]
    hsts_deep         = r1["hsts_deep"]
    rev_dns           = r1["reverse_dns"]
    network_ext       = r1["network_ext"]
    robtex            = r1["robtex"]
    urlscan           = r1["urlscan"]
    threat_intel      = r1["threat_intel"]
    catch_all         = r1["catch_all"]
    certsh_data       = r1["certsh"]
    pdns_data         = r1["pdns"]
    builtwith_data    = r1["builtwith"]
    bgpview_data      = r1["bgpview"]
    dast_data         = r1["dast"]
    observatory_data  = r1["observatory"]
    cert_pinning      = r1["cert_pinning"]
    crypto_audit_data = r1["crypto_audit"]
    dnssec_data       = r1["dnssec"]
    http_versions     = r1["http_versions"]
    safebrowsing_data = r1["safebrowsing"]
    phishtank_data    = r1["phishtank"]
    doh_comp          = r1["doh_comparison"]
    cloud_storage_data   = r1["cloud_storage"]
    api_endpoints_data   = r1["api_endpoints"]
    cms_data_result      = r1["cms"]
    subdomain_bf_data    = r1["subdomain_bruteforce"]
    hibp_data_result     = r1["hibp"]
    js_deps_data         = r1["js_dependencies"]
    censys_data          = r1["censys"]
    js_secrets_data_result = r1["js_secrets_data"]
    typosquatting_data     = r1["typosquatting"]
    paste_data_result      = r1["paste_data"]
    mta_sts_data           = r1["mta_sts"]
    bimi_data              = r1["bimi"]
    reverse_ip_data        = r1["reverse_ip"]

    # ─── Post-Wave-1: pure calculations ─────────────────────────────────────
    csp_value = (security_headers or {}).get("Content-Security-Policy")
    csp_grade = grade_csp(csp_value)
    spoofability = compute_spoofability(email_security, catch_all)

    # Post-Wave-1: crt.sh - find subdomains seen only via CT logs
    if certsh_data and certsh_data.get("enriched"):
        subdomains_known = set((subdomains or {}).get("subdomains", []))
        ct_subs = set()
        for cert in certsh_data.get("certs", []):
            for san in cert.get("san", []):
                san_clean = san.lstrip("*.")
                if san_clean.endswith(f".{domain}") and san_clean not in subdomains_known:
                    ct_subs.add(san_clean)
        certsh_data["ct_only_subdomains"] = sorted(ct_subs)
        certsh_data["ct_only_count"] = len(ct_subs)

    # ─── Wave 2 - tasks that depend on Wave 1 output ────────────────────────
    subdomains_list = (subdomains or {}).get("subdomains", [])
    ports_open = (ports or {}).get("open_ports", [])
    _html_emails = (html_intel or {}).get("emails", [])

    w2: dict[str, Awaitable] = {
        "subdomain_takeover": check_subdomain_takeover(subdomains_list),
    }

    if _html_emails:
        w2["emailrep_data"] = emailrep_lookup(_html_emails)

    abuseipdb_key = settings.get("abuseipdb_key")
    if ip and abuseipdb_key:
        w2["abuseipdb_data"] = abuseipdb_lookup(ip, abuseipdb_key)

    shodan_key = settings.get("shodan_key")
    if ip and shodan_key:
        w2["shodan_data"] = shodan_lookup(ip, shodan_key)

    if ip and ports_open:
        w2["banners"] = grab_banners(ip, ports_open)

    if is_full:
        w2["tls_deep"]     = scan_tls_deep(domain)
        w2["admin_panels"] = discover_admin_panels(domain)
        w2["smtp_raw"]     = check_smtp_security(domain)
        if settings.get("screenshot_enabled"):
            w2["screenshot"] = capture_screenshot(domain)
    else:
        # Quick scan still discovers admin panels (lighter)
        w2["admin_panels"] = discover_admin_panels(domain)

    w2["leakix_data"] = leakix_lookup(domain, settings.get("leakix_key"))
    w2["github_dork"] = github_dork(domain, settings.get("github_token"))

    if is_full:
        w2["nuclei_data"] = nuclei_scan(domain)

    if ip:
        w2["dnsbl_data"] = scan_dnsbl(ip, settings)

    r2 = await _run_wave(w2, progress_cb, wave_deadline=timeout, wave=2)

    # ─── Wave 3 - IntelX (conditional on Wave 2 output) ─────────────────────
    intelx_data: dict = {}
    intelx_key = settings.get("intelx_key")
    if intelx_key:
        panels = r2.get("admin_panels", {}) or {}
        panels_found = panels.get("panels_found", []) or []
        confident_panels = [p for p in panels_found if p.get("confidence") in ("high", "medium")]
        if confident_panels:
            try:
                intelx_data = await asyncio.wait_for(
                    intelx_search(domain, intelx_key),
                    timeout=_timeout_for("intelx_data"),
                )
            except Exception:
                intelx_data = {}

    # ─── Post-Wave-2: assemble smtp_security ────────────────────────────────
    smtp_raw = r2.get("smtp_raw", {}) or {}
    smtp_security = {
        **email_security,
        "smtp": smtp_raw,
        "spoofability_score": spoofability.get("spoofability_score"),
        "risk_level": spoofability.get("risk_level"),
        "catch_all": catch_all.get("catch_all"),
    }

    security_score = compute_security_score({
        "tls_certificate": tls_cert,
        "tls_deep":        r2.get("tls_deep"),
        "security_headers": security_headers,
        "csp_grade":       csp_grade,
        "hsts_deep":       hsts_deep,
        "email_security":  email_security,
        "smtp_security":   smtp_security,
        "email_blacklist": email_blacklist,
        "threat_intel":    threat_intel,
        "open_ports":      ports,
        "cors":            cors,
        "zone_transfer":   zone_transfer,
        "js_analysis":     js_analysis,
        "admin_panels":    r2.get("admin_panels"),
        "http_methods":    http_methods,
    }, scan_profile)

    # ─── Output normalization ───────────────────────────────────────────────
    # security_headers: flat dict → {headers_found, headers_missing, score}
    _sh = security_headers or {}
    _sh_found = {h: _sh[h] for h in _SH_KEYS if _sh.get(h)}
    security_headers_out = {
        "headers_found": _sh_found,
        "headers_missing": [h for h in _SH_KEYS if not _sh.get(h)],
        "score": f"{len(_sh_found)}/{len(_SH_KEYS)}",
    }

    # email_security: raw strings → structured with grades
    _spf = (email_security or {}).get("spf")
    _dmarc = (email_security or {}).get("dmarc")
    _dkim = (email_security or {}).get("dkim") or {}
    if not _spf:
        _spf_g, _spf_iss = "F", ["Missing SPF record"]
    elif "-all" in _spf:
        _spf_g, _spf_iss = "A", []
    elif "~all" in _spf:
        _spf_g, _spf_iss = "B", ["Soft fail (~all) - use -all for strict enforcement"]
    else:
        _spf_g, _spf_iss = "C", []
    if not _dmarc:
        _dm_g, _dm_pol, _dm_iss = "F", None, ["Missing DMARC record"]
    else:
        _pm = re.search(r"p=(reject|quarantine|none)", _dmarc, re.IGNORECASE)
        _dm_pol = _pm.group(1) if _pm else "none"
        _dm_g = "A" if _dm_pol == "reject" else "B" if _dm_pol == "quarantine" else "D"
        _dm_iss = ["DMARC policy is 'none' (monitoring only)"] if _dm_pol == "none" else []
    _email_avg = (_GRADE_PTS.get(_spf_g, 0) + _GRADE_PTS.get(_dm_g, 0) + (3 if _dkim else 0)) / 3
    _email_ovr = "A" if _email_avg >= 3.5 else "B" if _email_avg >= 2.5 else "C" if _email_avg >= 1.5 else "D" if _email_avg >= 0.5 else "F"
    _email_recs = ([] if _spf else ["Ajouter un enregistrement SPF"]) + \
                  ([] if _dmarc else ["Ajouter un enregistrement DMARC"]) + \
                  (["Passer la politique DMARC à quarantine/reject"] if _dmarc and _dm_pol == "none" else []) + \
                  ([] if _dkim else ["Configurer DKIM pour signer les emails"])
    email_security_out = {
        "spf":   {"found": bool(_spf),   "record": _spf or "",   "grade": _spf_g, "issues": _spf_iss},
        "dkim":  {"found": bool(_dkim),  "selectors_found": list(_dkim.keys())},
        "dmarc": {"found": bool(_dmarc), "record": _dmarc or "", "policy": _dm_pol, "grade": _dm_g, "issues": _dm_iss},
        "overall_grade": _email_ovr,
        "recommendations": _email_recs,
    }

    # waf
    _waf_list = (waf or {}).get("waf_detected", [])
    waf_out = {
        "detected": bool(_waf_list),
        "waf_name": _waf_list[0] if _waf_list else None,
        "confidence": "medium" if _waf_list else None,
        "evidence": [f"Detected: {', '.join(_waf_list)}"] if _waf_list else [],
    }

    # geo_data
    _g = geo or {}
    geo_out = {
        "country_code": _g.get("countryCode", _g.get("country_code", "")),
        "country":      _g.get("country", ""),
        "region":       _g.get("regionName", _g.get("region", "")),
        "city":         _g.get("city", ""),
        "lat":          _g.get("lat", 0),
        "lon":          _g.get("lon", 0),
        "timezone":     _g.get("timezone", ""),
        "isp":          _g.get("isp", ""),
        "as_info":      _g.get("as", _g.get("as_info", "")),
    } if _g else {}

    # technologies - flatten {name, confidence, score} entries to a stable shape
    # ({"name": <str>, ...}); detect_technologies may yield dicts or bare strings.
    _tech = technologies or {}
    def _tech_entry(t):
        if isinstance(t, dict):
            return {"name": t.get("name", ""), "category": "Technologie",
                    "confidence": t.get("confidence"), "score": t.get("score")}
        return {"name": t, "category": "Technologie"}
    techs_out = (
        [_tech_entry(t) for t in _tech.get("technologies", [])]
        if isinstance(_tech, dict) else _tech
    )

    # open_ports
    _p = ports or {}
    ports_out = (
        [{"port": p, "service": _PORTS_SVC.get(p, "unknown"), "state": "open"}
         for p in _p.get("open_ports", [])]
        if isinstance(_p, dict) else _p
    )

    # tls_certificate
    _tls = tls_cert or {}
    if _tls and not _tls.get("error"):
        _subj = _tls.get("subject", {})
        _iss  = _tls.get("issuer", {})
        _na   = _tls.get("notAfter", _tls.get("not_after", ""))
        _days = None
        if _na:
            try:
                _days = (datetime.strptime(_na, "%b %d %H:%M:%S %Y %Z") - datetime.utcnow()).days
            except Exception:
                pass
        tls_out = {
            "subject":        _subj.get("commonName", "") if isinstance(_subj, dict) else _subj,
            "issuer_org":     _iss.get("organizationName", "") if isinstance(_iss, dict) else "",
            "issuer_cn":      _iss.get("commonName", "") if isinstance(_iss, dict) else "",
            "serial_number":  _tls.get("serialNumber", _tls.get("serial_number", "")),
            "not_before":     _tls.get("notBefore", _tls.get("not_before", "")),
            "not_after":      _na,
            "days_remaining": _days,
            "san":            _tls.get("subjectAltName", _tls.get("san", [])),
            "protocol":       _tls.get("protocol"),
            "cipher":         _tls.get("cipher"),
            "cipher_bits":    _tls.get("cipher_bits"),
            "valid":          _tls.get("valid", False),
            "error":          None,
        }
    else:
        tls_out = _tls

    return {
        "ip_address":      ip,
        "dns_records":     dns_records,
        "subdomains":      subdomains,
        "tls_certificate": tls_out,
        "security_headers": security_headers_out,
        "web_files":       web_files,
        "cookie_security": cookies,
        "cors":            cors,
        "redirect_chain":  redirects,
        "technologies":    techs_out,
        "waf":             waf_out,
        "whois_data":      whois,
        "wayback_data":    wayback,
        "email_security":  email_security_out,
        "smtp_security":   smtp_security,
        "hsts_preload":    hsts_preload,
        "linked_domains":  linked_domains,
        "js_analysis":     js_analysis,
        "favicon_hash":    favicon_hash,
        "geo_data":        geo_out,
        "open_ports":      ports_out,
        "zone_transfer":   zone_transfer,
        "wildcard_dns":    wildcard,
        "dns_rebinding":   dns_rebinding,
        "email_blacklist": email_blacklist,
        "html_intelligence": html_intel,
        "http_methods":    http_methods,
        "hsts_deep":       hsts_deep,
        "reverse_dns_data": rev_dns,
        "network_extended": network_ext,
        "robtex":          robtex,
        "urlscan_data":    urlscan,
        "threat_intel":    threat_intel,
        "subdomain_takeover": r2.get("subdomain_takeover"),
        "banners":         r2.get("banners"),
        "tls_deep":        r2.get("tls_deep"),
        "admin_panels":    r2.get("admin_panels"),
        "typosquatting":   typosquatting_data,
        "csp_grade":       csp_grade,
        "security_score":  security_score,
        "screenshot_path": r2.get("screenshot"),
        "scan_profile":    scan_profile,
        "shodan_data":     r2.get("shodan_data"),
        "bgpview_data":    bgpview_data,
        "certsh_data":     certsh_data,
        "builtwith_data":  builtwith_data,
        "dast_data":       dast_data,
        "pdns_data":       pdns_data,
        "observatory_data": observatory_data,
        "cert_pinning":    cert_pinning,
        "crypto_audit":    crypto_audit_data,
        "intelx_data":     intelx_data,
        "emailrep_data":   r2.get("emailrep_data"),
        "abuseipdb_data":  r2.get("abuseipdb_data"),
        "dnssec_data":      dnssec_data,
        "http_versions":    http_versions,
        "safebrowsing_data": safebrowsing_data,
        "phishtank_data":   phishtank_data,
        "doh_comparison":   doh_comp,
        "cloud_storage":    cloud_storage_data,
        "api_endpoints":    api_endpoints_data,
        "cms_data":         cms_data_result,
        "subdomain_bruteforce": subdomain_bf_data,
        "leakix_data":      r2.get("leakix_data"),
        "github_dork":      r2.get("github_dork"),
        "hibp_data":        hibp_data_result,
        "js_deps_data":     js_deps_data,
        "censys_data":      censys_data,
        "nuclei_data":      r2.get("nuclei_data"),
        "js_secrets_data":  js_secrets_data_result,
        "paste_data":       paste_data_result,
        "dnsbl_data":       r2.get("dnsbl_data"),
        "mta_sts":          mta_sts_data,
        "bimi":             bimi_data,
        "reverse_ip":       reverse_ip_data,
    }
