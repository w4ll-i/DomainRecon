"""JS Secrets Scanner - finds hardcoded secrets in JS files."""
import re
import asyncio
import httpx
from urllib.parse import urljoin, urlparse

JS_SECRET_PATTERNS = [
    ("AWS Access Key",     "critical", r"AKIA[0-9A-Z]{16}"),
    ("AWS Secret Key",     "critical", r"(?i)aws[_\-]?secret[_\-]?(?:access[_\-]?)?key\s*[:=]\s*['\"][A-Za-z0-9/+=]{40}['\"]"),
    ("Stripe Live Key",    "critical", r"sk_live_[0-9A-Za-z]{24,}"),
    ("GitHub PAT",         "critical", r"ghp_[A-Za-z0-9]{36}|gho_[A-Za-z0-9]{36}"),
    ("Private Key PEM",    "critical", r"-----BEGIN (?:RSA |EC )?PRIVATE KEY-----"),
    ("JWT Token",          "high",     r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}"),
    ("Slack Token",        "high",     r"xox[baprs]-[A-Za-z0-9-]{10,}"),
    ("SendGrid Key",       "high",     r"SG\.[A-Za-z0-9_-]{22,}\.[A-Za-z0-9_-]{22,}"),
    ("Mailgun Key",        "high",     r"key-[0-9a-f]{32}"),
    ("Twilio SID",         "high",     r"AC[a-f0-9]{32}"),
    ("Google API Key",     "medium",   r"AIza[0-9A-Za-z_-]{35}"),
    ("Stripe Pub Key",     "low",      r"pk_live_[0-9A-Za-z]{24,}"),
    ("Firebase Config",    "low",      r"firebaseConfig\s*=\s*\{"),
    # Generic patterns - more specific to reduce placeholder false positives:
    # Require value to look like a real key (no common placeholder words)
    ("Generic API Key",    "medium",   r"(?i)api[_\-]?key\s*[:=]\s*['\"][A-Za-z0-9_\-]{20,}['\"]"),
    # Hardcoded password: skip obvious placeholders (yourPassword, changeme, etc.)
    ("Hardcoded Password", "medium",   r"(?i)password\s*[=:]\s*['\"](?!.*(?:your|change|enter|insert|example|placeholder|xxx|test|dummy|sample|secret_here|password_here))[^'\"]{10,}['\"]"),
    ("Bearer Token",       "low",      r"Bearer\s+[A-Za-z0-9_\-\.]{20,}"),
]

# Common placeholder values to skip (exact match after extraction)
_PLACEHOLDER_VALUES = {
    "changeme", "yourpassword", "password123", "secret", "mysecret",
    "your_api_key", "your_key_here", "insert_key_here", "xxx", "yyy",
    "todo", "fixme", "replace_me", "your_token", "sample_key",
}

CDN_WHITELIST = [
    "fonts.googleapis.com", "fonts.gstatic.com", "ajax.googleapis.com",
    "cdn.jsdelivr.net", "unpkg.com", "cdnjs.cloudflare.com",
    "code.jquery.com", "maxcdn.bootstrapcdn.com",
]


def _redact(value: str) -> str:
    if len(value) <= 8:
        return "****"
    return value[:4] + "****" + value[-4:]


def _is_cdn(url: str) -> bool:
    host = urlparse(url).netloc
    return any(cdn in host for cdn in CDN_WHITELIST)


async def scan_js_secrets(domain: str, settings: dict = {}) -> dict:
    base = f"https://{domain}"
    findings = []
    files_scanned = 0

    try:
        async with httpx.AsyncClient(timeout=10, follow_redirects=True, verify=False) as client:
            resp = await client.get(base)
            html = resp.text
    except Exception:
        return {"enriched": False, "error": "homepage unreachable"}

    src_urls = re.findall(r'<script[^>]+src=["\']([^"\']+)["\']', html, re.I)
    js_urls = []
    for src in src_urls:
        url = src if src.startswith("http") else urljoin(base, src)
        if not _is_cdn(url):
            js_urls.append(url)
    js_urls = js_urls[:10]

    async def fetch_and_scan(url):
        nonlocal files_scanned
        local_finds = []
        try:
            async with httpx.AsyncClient(timeout=10, verify=False) as c:
                r = await c.get(url)
                content = r.text[:512000]
            files_scanned += 1
            lines = content.splitlines()
            seen = set()
            for pname, severity, pattern in JS_SECRET_PATTERNS:
                for i, line in enumerate(lines):
                    for m in re.finditer(pattern, line):
                        matched = m.group()
                        # Skip if the matched value is a known placeholder
                        if matched.lower().strip("'\"/= ") in _PLACEHOLDER_VALUES:
                            continue
                        key = (url, pname)
                        if key not in seen:
                            seen.add(key)
                            local_finds.append({
                                "file_url": url,
                                "pattern": pname,
                                "severity": severity,
                                "value_redacted": _redact(matched),
                                "line_hint": i + 1,
                            })
        except Exception:
            pass
        return local_finds

    results = await asyncio.gather(*[fetch_and_scan(u) for u in js_urls])
    for r in results:
        findings.extend(r)

    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for f in findings:
        counts[f["severity"]] = counts.get(f["severity"], 0) + 1

    return {
        "enriched": bool(findings),
        "findings": findings,
        "files_scanned": files_scanned,
        "total_count": len(findings),
        "critical_count": counts["critical"],
        "high_count": counts["high"],
    }
