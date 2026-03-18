# backend/app/scanner.py
"""
DomainRecon v6.0 — Scan Orchestrator.
Execution flow:
  1. Resolve IP
  2. Wave 1: all independent async tasks
  3. Post-Wave-1: pure calculations (grade_csp, compute_spoofability)
  4. Wave 2: tasks that depend on Wave 1 output
  5. Post-Wave-2: assemble smtp_security + compute score
"""
import asyncio
import re
from datetime import datetime
from typing import Optional

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
)
from .scanners.ports import scan_ports, grab_banners
from .scanners.network import get_geo_data, extended_network_scan, robtex_lookup
from .scanners.osint import (
    get_whois_data, check_wayback_machine, urlscan_lookup,
    check_threat_intelligence, analyze_js_files, compute_favicon_hash,
    extract_linked_domains, check_hsts_preload, capture_screenshot,
    detect_typosquatting,
)
from .scanners.tech import detect_technologies, detect_waf
from .scanners.scoring import compute_security_score
from .scanners.shodan_scanner import shodan_lookup


async def _noop() -> dict:
    await asyncio.sleep(0)
    return {}


async def run_scan(
    domain: str,
    scan_profile: str = "full",
    settings: Optional[dict] = None,
    timeout: int = 180,
) -> dict:
    if settings is None:
        settings = {}
    is_full = scan_profile == "full"

    ip = await resolve_ip(domain)

    # Wave 1: all independent coroutines
    wave1_coros = [
        scan_dns_records(domain),                                         # 0
        find_subdomains(domain, scan_profile),                            # 1
        check_tls_certificate(domain),                                    # 2
        check_security_headers(domain),                                   # 3
        check_web_files(domain),                                          # 4
        analyze_cookies(domain),                                          # 5
        check_cors(domain),                                               # 6
        trace_redirects(domain),                                          # 7
        detect_technologies(domain),                                      # 8
        detect_waf(domain),                                               # 9
        get_whois_data(domain),                                           # 10
        check_wayback_machine(domain),                                    # 11
        analyze_email_security(domain),                                   # 12
        check_hsts_preload(domain),                                       # 13
        extract_linked_domains(domain),                                   # 14
        analyze_js_files(domain),                                         # 15
        compute_favicon_hash(domain),                                     # 16
        get_geo_data(ip) if ip else _noop(),                              # 17
        scan_ports(ip) if ip else _noop(),                                # 18
        check_zone_transfer(domain),                                      # 19
        check_wildcard(domain),                                           # 20
        check_dns_rebinding(domain),                                      # 21
        check_email_blacklists(ip) if ip else _noop(),                    # 22
        extract_html_intelligence(domain),                                # 23
        check_http_methods(domain),                                       # 24
        analyze_hsts_deep(domain),                                        # 25
        reverse_dns(ip) if ip else _noop(),                               # 26
        extended_network_scan(ip) if ip else _noop(),                     # 27
        robtex_lookup(domain),                                            # 28
        urlscan_lookup(domain, settings.get("urlscan_key")),              # 29
        check_threat_intelligence(domain, ip or "", settings.get("virustotal_key")),  # 30
        check_catch_all(domain),                                          # 31
    ]
    wave1_results = await asyncio.wait_for(
        asyncio.gather(*wave1_coros, return_exceptions=True),
        timeout=timeout,
    )

    def _safe(v):
        return v if not isinstance(v, Exception) else {}

    (
        dns_records, subdomains, tls_cert, security_headers, web_files,
        cookies, cors, redirects, technologies, waf, whois, wayback,
        email_security, hsts_preload, linked_domains, js_analysis, favicon_hash,
        geo, ports, zone_transfer, wildcard, dns_rebinding, email_blacklist,
        html_intel, http_methods, hsts_deep, rev_dns, network_ext, robtex,
        urlscan, threat_intel, catch_all,
    ) = [_safe(v) for v in wave1_results]

    # Post-Wave-1: pure calculations
    csp_value = (security_headers or {}).get("Content-Security-Policy")
    csp_grade = grade_csp(csp_value)
    spoofability = compute_spoofability(email_security, catch_all)

    # Wave 2: depends on Wave 1 output
    subdomains_list = (subdomains or {}).get("subdomains", [])
    ports_open = (ports or {}).get("open_ports", [])

    wave2_coros = [check_subdomain_takeover(subdomains_list)]
    wave2_keys = ["subdomain_takeover"]

    shodan_key = settings.get("shodan_key")
    if ip and shodan_key:
        wave2_coros.append(shodan_lookup(ip, shodan_key))
        wave2_keys.append("shodan_data")

    if ip and ports_open:
        wave2_coros.append(grab_banners(ip, ports_open))
        wave2_keys.append("banners")

    if is_full:
        wave2_coros += [
            scan_tls_deep(domain),
            discover_admin_panels(domain),
            check_smtp_security(domain),
            detect_typosquatting(domain),
        ]
        wave2_keys += ["tls_deep", "admin_panels", "smtp_raw", "typosquatting"]
        if settings.get("screenshot_enabled"):
            wave2_coros.append(capture_screenshot(domain))
            wave2_keys.append("screenshot")

    wave2_results = await asyncio.gather(*wave2_coros, return_exceptions=True)
    r2 = {k: _safe(v) for k, v in zip(wave2_keys, wave2_results)}

    # Post-Wave-2: assemble smtp_security
    smtp_raw = r2.get("smtp_raw", {})
    smtp_security = {
        **email_security,
        "smtp": smtp_raw,
        "spoofability_score": spoofability.get("spoofability_score"),
        "risk_level": spoofability.get("risk_level"),
        "catch_all": catch_all.get("catch_all"),
    }

    security_score = compute_security_score({
        "tls_certificate": tls_cert,
        "tls_deep": r2.get("tls_deep"),
        "security_headers": security_headers,
        "csp_grade": csp_grade,
        "hsts_deep": hsts_deep,
        "email_security": email_security,
        "smtp_security": smtp_security,
        "email_blacklist": email_blacklist,
        "threat_intel": threat_intel,
        "open_ports": ports,
        "cors": cors,
        "zone_transfer": zone_transfer,
        "js_analysis": js_analysis,
        "admin_panels": r2.get("admin_panels"),
        "http_methods": http_methods,
    }, scan_profile)

    # ─── Normalize output to v5-compatible format ─────────────────────────────
    # Must happen AFTER scoring (which uses raw v6 formats internally).

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
        _spf_g, _spf_iss = "B", ["Soft fail (~all) — use -all for strict enforcement"]
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

    # waf: {waf_detected:[names]} → {detected, waf_name, confidence, evidence}
    _waf_list = (waf or {}).get("waf_detected", [])
    waf_out = {
        "detected": bool(_waf_list),
        "waf_name": _waf_list[0] if _waf_list else None,
        "confidence": "medium" if _waf_list else None,
        "evidence": [f"Detected: {', '.join(_waf_list)}"] if _waf_list else [],
    }

    # geo_data: raw ip-api.com keys → v5 keys
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

    # technologies: {technologies:[str]} → [{name, category}]
    _tech = technologies or {}
    techs_out = (
        [{"name": t, "category": "Technologie"} for t in _tech.get("technologies", [])]
        if isinstance(_tech, dict) else _tech
    )

    # open_ports: {open_ports:[int]} → [{port, service, state}]
    _p = ports or {}
    ports_out = (
        [{"port": p, "service": _PORTS_SVC.get(p, "unknown"), "state": "open"}
         for p in _p.get("open_ports", [])]
        if isinstance(_p, dict) else _p
    )

    # tls_certificate: normalize keys to v5 format
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
        "typosquatting":   r2.get("typosquatting"),
        "csp_grade":       csp_grade,
        "security_score":  security_score,
        "screenshot_path": r2.get("screenshot"),
        "scan_profile":    scan_profile,
        "shodan_data":     r2.get("shodan_data"),
    }
