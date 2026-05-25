# backend/app/scanners/scoring.py
"""
Unified security scoring - 6 categories totaling 100 points:
  TLS(20) + Headers(20) + Email(15) + Reputation(15) + Infrastructure(15) + OSINT(15)
"""

# Ports that are genuinely dangerous when publicly exposed
_DANGEROUS_PORTS = {
    23:    ("Telnet",        5),
    2375:  ("Docker API",    8),  # cleartext Docker daemon
    4848:  ("GlassFish",     4),
    5900:  ("VNC",           5),
    6379:  ("Redis",         6),
    7001:  ("WebLogic",      5),
    9200:  ("Elasticsearch", 6),
    11211: ("Memcached",     5),
    27017: ("MongoDB",       6),
    # High-risk but common on corporate networks - lower penalty
    3389:  ("RDP",           4),
    445:   ("SMB",           4),
    1433:  ("MSSQL",         4),
    1521:  ("Oracle DB",     4),
}


def compute_security_score(scan_data: dict, scan_profile: str = "full") -> dict:
    deductions = []

    # ── TLS (20 pts) ────────────────────────────────────────────────────────
    tls_score = 20
    tls_cert = scan_data.get("tls_certificate") or {}
    tls_deep = scan_data.get("tls_deep") or {}
    if not tls_cert.get("valid"):
        tls_score -= 15
        deductions.append({"category": "TLS", "points": 15, "reason": "Invalid or missing TLS certificate"})
    if tls_deep.get("protocols", {}).get("TLSv1.0") or tls_deep.get("protocols", {}).get("TLSv1.1"):
        tls_score -= 5
        deductions.append({"category": "TLS", "points": 5, "reason": "Legacy TLS 1.0/1.1 supported"})
    if tls_deep.get("weak_ciphers"):
        tls_score -= 3
        deductions.append({"category": "TLS", "points": 3, "reason": "Weak cipher suites detected"})
    # Check days remaining - warn if cert expires soon
    days = tls_cert.get("days_remaining")
    if days is not None and days < 14:
        tls_score -= 8
        deductions.append({"category": "TLS", "points": 8, "reason": f"Certificate expires in {days} days"})
    elif days is not None and days < 30:
        tls_score -= 3
        deductions.append({"category": "TLS", "points": 3, "reason": f"Certificate expires in {days} days"})

    # ── Headers (20 pts) ────────────────────────────────────────────────────
    headers_score = 20
    headers = scan_data.get("security_headers") or {}
    csp_grade = scan_data.get("csp_grade") or {}
    hsts_deep = scan_data.get("hsts_deep") or {}
    if not headers.get("Content-Security-Policy"):
        headers_score -= 5
        deductions.append({"category": "Headers", "points": 5, "reason": "Missing Content-Security-Policy"})
    elif csp_grade.get("grade") in ("D", "F"):
        headers_score -= 3
        deductions.append({"category": "Headers", "points": 3, "reason": f"Weak CSP (grade {csp_grade.get('grade')})"})
    if not headers.get("X-Frame-Options"):
        headers_score -= 3
        deductions.append({"category": "Headers", "points": 3, "reason": "Missing X-Frame-Options"})
    if not headers.get("X-Content-Type-Options"):
        headers_score -= 2
        deductions.append({"category": "Headers", "points": 2, "reason": "Missing X-Content-Type-Options"})
    if not hsts_deep.get("present"):
        headers_score -= 5
        deductions.append({"category": "Headers", "points": 5, "reason": "Missing HSTS header"})
    elif hsts_deep.get("max_age", 0) < 31536000:
        headers_score -= 2
        deductions.append({"category": "Headers", "points": 2, "reason": "HSTS max-age < 1 year"})
    if not headers.get("Referrer-Policy"):
        headers_score -= 2
        deductions.append({"category": "Headers", "points": 2, "reason": "Missing Referrer-Policy"})
    if not headers.get("Permissions-Policy"):
        headers_score -= 1
        deductions.append({"category": "Headers", "points": 1, "reason": "Missing Permissions-Policy"})

    # ── Email (15 pts) ──────────────────────────────────────────────────────
    email_score = 15
    email = scan_data.get("email_security") or {}
    smtp = scan_data.get("smtp_security") or {}
    smtp_raw = smtp.get("smtp") or {}
    if not email.get("spf"):
        email_score -= 5
        deductions.append({"category": "Email", "points": 5, "reason": "Missing SPF record"})
    elif "?all" in (email.get("spf") or ""):
        # Neutral - treats all senders equally, no enforcement
        email_score -= 3
        deductions.append({"category": "Email", "points": 3, "reason": "SPF uses ?all (neutral, no enforcement)"})
    elif "~all" in (email.get("spf") or ""):
        email_score -= 1
        deductions.append({"category": "Email", "points": 1, "reason": "SPF uses ~all (soft fail - prefer -all)"})
    if not email.get("dmarc"):
        email_score -= 5
        deductions.append({"category": "Email", "points": 5, "reason": "Missing DMARC record"})
    else:
        import re as _re
        _pm = _re.search(r"p=(reject|quarantine|none)", email.get("dmarc") or "", _re.IGNORECASE)
        _policy = _pm.group(1).lower() if _pm else "none"
        if _policy == "none":
            email_score -= 3
            deductions.append({"category": "Email", "points": 3, "reason": "DMARC policy is 'none' (monitoring only, no enforcement)"})
        elif _policy == "quarantine":
            email_score -= 1
            deductions.append({"category": "Email", "points": 1, "reason": "DMARC policy is 'quarantine' (recommend 'reject')"})
        # p=reject: no deduction
    if not email.get("dkim"):
        email_score -= 3
        deductions.append({"category": "Email", "points": 3, "reason": "No DKIM record found"})
    if smtp_raw.get("open_relay"):
        email_score -= 5
        deductions.append({"category": "Email", "points": 5, "reason": "SMTP open relay detected"})
    if smtp_raw.get("starttls") is False and smtp_raw.get("banner"):
        # SMTP server found but no STARTTLS
        email_score -= 2
        deductions.append({"category": "Email", "points": 2, "reason": "SMTP server does not support STARTTLS"})

    # ── Reputation (15 pts) ─────────────────────────────────────────────────
    rep_score = 15
    email_blacklist = scan_data.get("email_blacklist") or {}
    dnsbl = scan_data.get("dnsbl_data") or {}
    threat = scan_data.get("threat_intel") or {}
    abuseipdb = scan_data.get("abuseipdb_data") or {}
    if email_blacklist.get("is_blacklisted"):
        rep_score -= 8
        deductions.append({"category": "Reputation", "points": 8, "reason": "IP is on a DNSBL blacklist"})
    # Additional DNSBL from dedicated scanner
    if dnsbl.get("listed_count", 0) > 0:
        pts = min(8, dnsbl["listed_count"] * 2)
        rep_score -= pts
        deductions.append({"category": "Reputation", "points": pts, "reason": f"IP listed on {dnsbl['listed_count']} DNSBL(s)"})
    vt = threat.get("virustotal") or {}
    if vt.get("malicious", 0) > 0:
        pts = min(8, vt["malicious"] * 2)
        rep_score -= pts
        deductions.append({"category": "Reputation", "points": pts, "reason": f"VirusTotal: {vt['malicious']} malicious detections"})
    if abuseipdb.get("abuse_confidence_score", 0) >= 50:
        rep_score -= 5
        deductions.append({"category": "Reputation", "points": 5, "reason": f"AbuseIPDB confidence score: {abuseipdb.get('abuse_confidence_score')}%"})

    # ── Infrastructure (15 pts) ──────────────────────────────────────────────
    infra_score = 15
    ports = scan_data.get("open_ports") or {}
    cors = scan_data.get("cors") or {}
    zone_transfer = scan_data.get("zone_transfer") or {}
    open_port_list = ports.get("open_ports") or []
    for port, (service, pts) in _DANGEROUS_PORTS.items():
        if port in open_port_list:
            infra_score -= pts
            deductions.append({"category": "Infrastructure", "points": pts, "reason": f"Exposed {service} port ({port})"})
    if cors.get("vulnerable"):
        infra_score -= 5
        deductions.append({"category": "Infrastructure", "points": 5, "reason": "Misconfigured CORS policy"})
    if zone_transfer.get("vulnerable"):
        infra_score -= 8
        deductions.append({"category": "Infrastructure", "points": 8, "reason": "DNS Zone Transfer (AXFR) is open"})

    # ── OSINT (15 pts) ──────────────────────────────────────────────────────
    osint_score = 15
    js_analysis = scan_data.get("js_analysis") or {}
    admin_panels = scan_data.get("admin_panels") or {}
    http_methods = scan_data.get("http_methods") or {}
    js_secrets = scan_data.get("js_secrets_data") or {}
    if js_analysis.get("secrets_found"):
        osint_score -= 5
        deductions.append({"category": "OSINT", "points": 5, "reason": f"Potential secrets in JS files ({len(js_analysis['secrets_found'])} found)"})
    if js_secrets.get("critical_count", 0) > 0:
        osint_score -= 8
        deductions.append({"category": "OSINT", "points": 8, "reason": f"Critical secrets in JS ({js_secrets['critical_count']} findings)"})
    elif js_secrets.get("high_count", 0) > 0:
        osint_score -= 5
        deductions.append({"category": "OSINT", "points": 5, "reason": f"High-severity secrets in JS ({js_secrets['high_count']} findings)"})
    # Only count high-confidence admin panels
    high_conf_panels = [p for p in (admin_panels.get("panels_found") or []) if p.get("confidence") in ("high", "medium")]
    if high_conf_panels:
        osint_score -= 4
        deductions.append({"category": "OSINT", "points": 4, "reason": f"Admin panels exposed ({len(high_conf_panels)} paths, medium+ confidence)"})
    if http_methods.get("dangerous_methods"):
        osint_score -= 3
        deductions.append({"category": "OSINT", "points": 3, "reason": f"Dangerous HTTP methods enabled: {', '.join(http_methods['dangerous_methods'])}"})

    # ── Assemble ─────────────────────────────────────────────────────────────
    categories = {
        "tls": max(0, tls_score),
        "headers": max(0, headers_score),
        "email": max(0, email_score),
        "reputation": max(0, rep_score),
        "infrastructure": max(0, infra_score),
        "osint": max(0, osint_score),
    }
    total = sum(categories.values())

    if total >= 95:   grade = "A+"
    elif total >= 85: grade = "A"
    elif total >= 75: grade = "B"
    elif total >= 60: grade = "C"
    elif total >= 40: grade = "D"
    else:             grade = "F"

    profile_note = None
    if scan_profile == "quick":
        profile_note = (
            "Quick scan: TLS deep analysis, admin panel discovery, SMTP checks, "
            "and typosquatting detection were skipped. Run a Full scan for complete results."
        )

    return {
        "total": total,
        "score": total,
        "grade": grade,
        "categories": categories,
        "top_recommendations": sorted(deductions, key=lambda x: x["points"], reverse=True)[:5],
        "all_deductions": deductions,
        "profile_note": profile_note,
    }
