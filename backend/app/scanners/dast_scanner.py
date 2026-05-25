# backend/app/scanners/dast_scanner.py
import re
import httpx

_VERSION_HEADERS = [
    "Server", "X-Powered-By", "X-AspNet-Version",
    "X-Generator", "X-AspNetMvc-Version",
]
_DEBUG_HEADERS = [
    "X-Debug-Token", "X-Debug-Token-Link",
    "X-WT-TTL", "X-WT-TS",
]
# (framework, regex_in_body, severity)
_FINGERPRINTS = [
    ("Laravel",  r"Whoops|laravel",             "low"),
    ("Django",   r"Django|Traceback \(most",    "low"),
    ("Rails",    r"ActionController",            "low"),
    ("Spring",   r"Whitelabel Error Page",       "low"),
    ("Express",  r"Cannot GET",                  "info"),
    ("PHP",      r"Fatal error|Warning:|Parse error", "medium"),
]


async def dast_scan(domain: str) -> dict:
    """
    Passive DAST checks - version/debug header disclosure + verbose 404 detection.
    Full profile only. Makes 2 benign HTTP requests.
    """
    findings = []

    try:
        async with httpx.AsyncClient(
            timeout=8,
            follow_redirects=True,
            headers={"User-Agent": "Mozilla/5.0 (DomainRecon/7.0)"},
        ) as client:

            # Check 1 & 2: version disclosure + debug headers
            try:
                rh = await client.get(f"https://{domain}")
                hdrs = rh.headers
                for h in _VERSION_HEADERS:
                    val = hdrs.get(h, "")
                    if not val:
                        continue
                    has_version = bool(re.search(r"\d+\.\d+", val))
                    findings.append({
                        "severity": "medium" if has_version else "info",
                        "type": "version_disclosure" if has_version else "server_banner",
                        "header": h,
                        "value": val[:100],
                        "description": (
                            f"Version disclosed via {h}: {val[:60]}"
                            if has_version
                            else f"Server banner in {h}: {val[:60]}"
                        ),
                    })
                for h in _DEBUG_HEADERS:
                    val = hdrs.get(h, "")
                    if val:
                        findings.append({
                            "severity": "high" if h == "X-Debug-Token-Link" else "medium",
                            "type": "debug_header",
                            "header": h,
                            "value": val[:100],
                            "description": f"Debug header exposed: {h}",
                        })
            except Exception:
                pass

            # Check 3: verbose 404
            try:
                r404 = await client.get(f"https://{domain}/dr404test-nonexistent-dR")
                body = r404.text[:8000]
                for fw_name, pattern, severity in _FINGERPRINTS:
                    if re.search(pattern, body, re.IGNORECASE):
                        findings.append({
                            "severity": severity,
                            "type": "verbose_404",
                            "framework_detected": fw_name,
                            "status_code": r404.status_code,
                            "description": f"404 response reveals {fw_name} framework",
                        })
                        break
            except Exception:
                pass

    except Exception:
        pass

    severity_summary = {"high": 0, "medium": 0, "low": 0, "info": 0}
    for f in findings:
        s = f.get("severity", "info")
        severity_summary[s] = severity_summary.get(s, 0) + 1

    return {
        "enriched": bool(findings),
        "findings": findings,
        "finding_count": len(findings),
        "severity_summary": severity_summary,
    }
