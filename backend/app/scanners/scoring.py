# backend/app/scanners/scoring.py
"""
Unified security scoring — 6 categories totaling 100 points:
  TLS(20) + Headers(20) + Email(15) + Reputation(15) + Infrastructure(15) + OSINT(15)
"""


def compute_security_score(scan_data: dict, scan_profile: str = "full") -> dict:
    deductions = []

    # TLS (20 pts)
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

    # Headers (20 pts)
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

    # Email (15 pts)
    email_score = 15
    email = scan_data.get("email_security") or {}
    smtp = scan_data.get("smtp_security") or {}
    if not email.get("spf"):
        email_score -= 5
        deductions.append({"category": "Email", "points": 5, "reason": "Missing SPF record"})
    if not email.get("dmarc"):
        email_score -= 5
        deductions.append({"category": "Email", "points": 5, "reason": "Missing DMARC record"})
    elif "p=none" in (email.get("dmarc") or ""):
        email_score -= 2
        deductions.append({"category": "Email", "points": 2, "reason": "DMARC policy is 'none' (monitoring only)"})
    if not email.get("dkim"):
        email_score -= 3
        deductions.append({"category": "Email", "points": 3, "reason": "No DKIM record found"})
    if smtp.get("open_relay"):
        email_score -= 5
        deductions.append({"category": "Email", "points": 5, "reason": "SMTP open relay detected"})

    # Reputation (15 pts)
    rep_score = 15
    email_blacklist = scan_data.get("email_blacklist") or {}
    threat = scan_data.get("threat_intel") or {}
    if email_blacklist.get("is_blacklisted"):
        rep_score -= 10
        deductions.append({"category": "Reputation", "points": 10, "reason": "IP is on a DNSBL blacklist"})
    vt = threat.get("virustotal") or {}
    if vt.get("malicious", 0) > 0:
        rep_score -= 8
        deductions.append({"category": "Reputation", "points": 8, "reason": f"VirusTotal: {vt['malicious']} malicious detections"})

    # Infrastructure (15 pts)
    infra_score = 15
    ports = scan_data.get("open_ports") or {}
    cors = scan_data.get("cors") or {}
    zone_transfer = scan_data.get("zone_transfer") or {}
    for port, service in {23: "Telnet", 3389: "RDP", 445: "SMB"}.items():
        if port in (ports.get("open_ports") or []):
            infra_score -= 3
            deductions.append({"category": "Infrastructure", "points": 3, "reason": f"Exposed {service} port ({port})"})
    if cors.get("vulnerable"):
        infra_score -= 5
        deductions.append({"category": "Infrastructure", "points": 5, "reason": "Misconfigured CORS policy"})
    if zone_transfer.get("vulnerable"):
        infra_score -= 8
        deductions.append({"category": "Infrastructure", "points": 8, "reason": "DNS Zone Transfer (AXFR) is open"})

    # OSINT (15 pts)
    osint_score = 15
    js_analysis = scan_data.get("js_analysis") or {}
    admin_panels = scan_data.get("admin_panels") or {}
    http_methods = scan_data.get("http_methods") or {}
    if js_analysis.get("secrets_found"):
        osint_score -= 8
        deductions.append({"category": "OSINT", "points": 8, "reason": f"Potential secrets in JS files ({len(js_analysis['secrets_found'])} found)"})
    if admin_panels.get("count", 0) > 0:
        osint_score -= 4
        deductions.append({"category": "OSINT", "points": 4, "reason": f"Admin panels exposed ({admin_panels['count']} paths)"})
    if http_methods.get("dangerous_methods"):
        osint_score -= 3
        deductions.append({"category": "OSINT", "points": 3, "reason": f"Dangerous HTTP methods enabled: {', '.join(http_methods['dangerous_methods'])}"})

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
        "grade": grade,
        "categories": categories,
        "top_recommendations": sorted(deductions, key=lambda x: x["points"], reverse=True)[:5],
        "all_deductions": deductions,
        "profile_note": profile_note,
    }
