# backend/app/scanners/js_dependency_scanner.py
"""
JS Dependency Scanner - detect CDN-hosted JS/CSS libraries and flag
outdated/vulnerable versions.
"""
import re

import httpx

try:
    from packaging.version import Version as PkgVersion

    def _parse_version(v):
        try:
            return PkgVersion(v)
        except Exception:
            return None

    def _is_vulnerable(detected, max_ver):
        a = _parse_version(detected)
        b = _parse_version(max_ver)
        if a is None or b is None:
            return _fallback_compare(detected, max_ver)
        return a <= b

except ImportError:
    PkgVersion = None

    def _parse_version(v):  # noqa: F811
        return None

    def _is_vulnerable(detected, max_ver):
        return _fallback_compare(detected, max_ver)


def _fallback_compare(v1: str, v2: str) -> bool:
    """Return True if v1 <= v2 using simple integer tuple comparison."""
    def to_tuple(v):
        parts = re.split(r"[.\-]", v)
        result = []
        for p in parts:
            try:
                result.append(int(p))
            except ValueError:
                break
        return tuple(result)

    return to_tuple(v1) <= to_tuple(v2)


KNOWN_VULNS = {
    "jquery": [
        {"max_version": "1.12.4", "cve": "CVE-2019-11358", "severity": "medium", "desc": "Prototype pollution"},
        {"max_version": "3.4.0",  "cve": "CVE-2019-11358", "severity": "medium", "desc": "Prototype pollution"},
        {"max_version": "1.6.4",  "cve": "CVE-2011-4969",  "severity": "medium", "desc": "XSS vulnerability"},
        {"max_version": "3.5.0",  "cve": "CVE-2020-11022", "severity": "medium", "desc": "XSS via HTML manipulation"},
        {"max_version": "3.5.0",  "cve": "CVE-2020-11023", "severity": "medium", "desc": "XSS via HTML manipulation"},
    ],
    "bootstrap": [
        {"max_version": "3.4.1", "cve": "CVE-2019-8331",  "severity": "medium", "desc": "XSS in tooltip/popover"},
        {"max_version": "4.3.1", "cve": "CVE-2019-8331",  "severity": "medium", "desc": "XSS in tooltip/popover"},
        {"max_version": "4.0.0", "cve": "CVE-2018-14040", "severity": "medium", "desc": "XSS via data-target"},
        {"max_version": "4.0.0", "cve": "CVE-2018-14041", "severity": "medium", "desc": "XSS via data-target"},
        {"max_version": "3.4.0", "cve": "CVE-2016-10735", "severity": "medium", "desc": "XSS in data-template"},
    ],
    "angular": [
        {"max_version": "1.8.0",  "cve": "CVE-2020-7676",  "severity": "medium", "desc": "XSS via ng-attr-srcdoc"},
        {"max_version": "1.6.0",  "cve": "CVE-2019-14863", "severity": "medium", "desc": "Prototype pollution"},
        {"max_version": "1.5.11", "cve": "CVE-2018-35312", "severity": "medium", "desc": "ReDoS"},
    ],
    "lodash": [
        {"max_version": "4.17.20", "cve": "CVE-2021-23337", "severity": "high",     "desc": "Command injection via template"},
        {"max_version": "4.17.20", "cve": "CVE-2020-8203",  "severity": "high",     "desc": "Prototype pollution via zipObjectDeep"},
        {"max_version": "4.17.15", "cve": "CVE-2019-10744", "severity": "critical", "desc": "Prototype pollution via defaultsDeep"},
        {"max_version": "4.17.11", "cve": "CVE-2018-16487", "severity": "high",     "desc": "Prototype pollution via merge"},
        {"max_version": "4.17.4",  "cve": "CVE-2018-3721",  "severity": "medium",   "desc": "Prototype pollution via defaultsDeep"},
    ],
    "moment": [
        {"max_version": "2.29.1", "cve": "CVE-2022-24785", "severity": "high",   "desc": "Path traversal"},
        {"max_version": "2.29.3", "cve": "CVE-2022-31129", "severity": "high",   "desc": "ReDoS - OOM crash"},
        {"max_version": "2.19.2", "cve": "CVE-2016-4055",  "severity": "medium", "desc": "ReDoS"},
    ],
    "handlebars": [
        {"max_version": "4.7.6", "cve": "CVE-2021-23369", "severity": "critical", "desc": "RCE via prototype pollution"},
        {"max_version": "4.7.6", "cve": "CVE-2021-23383", "severity": "critical", "desc": "Prototype pollution"},
        {"max_version": "4.5.3", "cve": "CVE-2019-20920", "severity": "high",     "desc": "Prototype pollution"},
        {"max_version": "4.5.2", "cve": "CVE-2019-19919", "severity": "critical", "desc": "Prototype pollution - RCE"},
    ],
    "underscore": [
        {"max_version": "1.12.1", "cve": "CVE-2021-23358", "severity": "high", "desc": "Arbitrary code execution via template"},
    ],
    "vue": [
        {"max_version": "2.6.12", "cve": "CVE-2021-28091", "severity": "medium", "desc": "XSS in v-bind"},
    ],
    "axios": [
        {"max_version": "0.21.1", "cve": "CVE-2021-3749",  "severity": "high",   "desc": "ReDoS"},
        {"max_version": "0.18.0", "cve": "CVE-2019-10742", "severity": "medium", "desc": "Denial of service"},
    ],
    "highlight.js": [
        {"max_version": "10.4.0", "cve": "CVE-2021-23346", "severity": "medium", "desc": "ReDoS"},
    ],
    "marked": [
        {"max_version": "1.1.1", "cve": "CVE-2022-21681", "severity": "high",   "desc": "ReDoS"},
        {"max_version": "4.0.9", "cve": "CVE-2022-21680", "severity": "medium", "desc": "ReDoS"},
    ],
    "dompurify": [
        {"max_version": "2.3.0", "cve": "CVE-2021-26539", "severity": "medium", "desc": "mXSS bypass"},
        {"max_version": "2.2.8", "cve": "CVE-2020-26870", "severity": "medium", "desc": "mXSS bypass"},
    ],
    "chart.js": [
        {"max_version": "2.9.4", "cve": "CVE-2020-7746", "severity": "high", "desc": "ReDoS"},
    ],
    "three.js": [
        {"max_version": "0.125.0", "cve": "CVE-2020-28480", "severity": "medium", "desc": "Prototype pollution"},
    ],
}

_SEVERITY_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1, "ok": 0}

# Regex to extract src/href attribute values from script and link tags
_SRC_RE = re.compile(
    r'<script[^>]+src=["\']([^"\']+)["\']',
    re.IGNORECASE,
)
_HREF_RE = re.compile(
    r'<link[^>]+href=["\']([^"\']+)["\']',
    re.IGNORECASE,
)

# CDN URL patterns - each yields (lib_name, version) or None
_CDN_PATTERNS = [
    # cdnjs.cloudflare.com/ajax/libs/{lib}/{version}/
    re.compile(r"cdnjs\.cloudflare\.com/ajax/libs/([^/]+)/([^/]+)/", re.IGNORECASE),
    # cdn.jsdelivr.net/npm/{lib}@{version}/
    re.compile(r"cdn\.jsdelivr\.net/npm/([^@/]+)@([^/]+)/", re.IGNORECASE),
    # unpkg.com/{lib}@{version}/
    re.compile(r"unpkg\.com/([^@/]+)@([^/]+)/", re.IGNORECASE),
    # ajax.googleapis.com/ajax/libs/{lib}/{version}/
    re.compile(r"ajax\.googleapis\.com/ajax/libs/([^/]+)/([^/]+)/", re.IGNORECASE),
    # code.jquery.com/jquery-{version}
    re.compile(r"code\.jquery\.com/jquery-(\d[^/.\-]*(?:[.\-]\d[^/.\-]*)*)(?:\.min)?\.js", re.IGNORECASE),
    # maxcdn.bootstrapcdn.com/bootstrap/{version}/
    re.compile(r"bootstrapcdn\.com/bootstrap/([^/]+)/", re.IGNORECASE),
]

# Filename fallback: {lib}-{version}.min.js or {lib}.{version}.js
_FILENAME_PATTERNS = [
    re.compile(r"/([a-z][a-z0-9\-]+)[.\-](\d+\.\d+(?:\.\d+)?)(?:\.min)?\.(?:js|css)$", re.IGNORECASE),
]

# Normalise library names returned by CDN paths to our KNOWN_VULNS keys
_LIB_ALIASES = {
    "jquery": "jquery",
    "jquery-ui": "jquery-ui",
    "bootstrap": "bootstrap",
    "angular.js": "angular",
    "angularjs": "angular",
    "angular": "angular",
    "lodash.js": "lodash",
    "lodash": "lodash",
    "moment.js": "moment",
    "moment": "moment",
    "handlebars.js": "handlebars",
    "handlebars": "handlebars",
}


def _normalise(name: str) -> str:
    return _LIB_ALIASES.get(name.lower(), name.lower())


def _extract_lib_version(url: str):
    """Return (lib_name, version) from a CDN URL, or None if not recognised."""
    # jquery CDN pattern has only one capture group (version), lib is implicit
    jquery_cdn = _CDN_PATTERNS[4]
    m = jquery_cdn.search(url)
    if m:
        return ("jquery", m.group(1))

    # bootstrap CDN pattern has only one capture group (version), lib is implicit
    bootstrap_cdn = _CDN_PATTERNS[5]
    m = bootstrap_cdn.search(url)
    if m:
        return ("bootstrap", m.group(1))

    # Generic two-group CDN patterns
    for pat in _CDN_PATTERNS[:4]:
        m = pat.search(url)
        if m:
            return (_normalise(m.group(1)), m.group(2))

    # Filename fallback
    for pat in _FILENAME_PATTERNS:
        m = pat.search(url)
        if m:
            return (_normalise(m.group(1)), m.group(2))

    return None


def _check_vulnerabilities(lib: str, version: str):
    """Return list of matching vulnerability dicts for a given lib+version."""
    vulns = KNOWN_VULNS.get(lib, [])
    matched = []
    for v in vulns:
        try:
            if _is_vulnerable(version, v["max_version"]):
                matched.append({"cve": v["cve"], "severity": v["severity"], "desc": v["desc"]})
        except Exception:
            pass
    return matched


def _highest_severity(vulns: list) -> str:
    if not vulns:
        return "ok"
    return max(vulns, key=lambda v: _SEVERITY_RANK.get(v["severity"], 0))["severity"]


async def _osv_lookup(lib_name: str, version: str) -> list:
    """
    Query the OSV (Open Source Vulnerabilities) API for npm packages.
    Free, no API key required. https://osv.dev/docs/
    """
    try:
        async with httpx.AsyncClient(timeout=8) as client:
            r = await client.post(
                "https://api.osv.dev/v1/query",
                json={"version": version, "package": {"name": lib_name, "ecosystem": "npm"}},
            )
            if r.status_code == 200:
                vulns = r.json().get("vulns", [])
                results = []
                for v in vulns[:5]:  # cap at 5 per lib
                    aliases = v.get("aliases", [])
                    cve = next((a for a in aliases if a.startswith("CVE-")), v.get("id", ""))
                    severity = "medium"
                    for sev_entry in v.get("severity", []):
                        score_str = sev_entry.get("score", "")
                        try:
                            score = float(score_str)
                            if score >= 9.0:
                                severity = "critical"
                            elif score >= 7.0:
                                severity = "high"
                            elif score >= 4.0:
                                severity = "medium"
                            else:
                                severity = "low"
                        except (ValueError, TypeError):
                            pass
                    results.append({
                        "cve": cve,
                        "severity": severity,
                        "desc": v.get("summary", "")[:120],
                        "source": "osv.dev",
                    })
                return results
    except Exception:
        pass
    return []


async def scan_js_dependencies(domain: str) -> dict:
    """
    Fetch the homepage, detect CDN-hosted JS/CSS libraries, and flag
    outdated/vulnerable versions.
    """
    try:
        async with httpx.AsyncClient(
            timeout=12,
            follow_redirects=True,
            verify=False,
        ) as client:
            resp = await client.get(f"https://{domain}")
            html = resp.text
    except Exception as e:
        return {"enriched": False, "error": str(e)}

    polyfill_detected = bool(
        re.search(r'polyfill\.io|polyfill-fastly\.io', html, re.I)
    )

    # Collect all candidate URLs
    urls = _SRC_RE.findall(html) + _HREF_RE.findall(html)

    # SRI check - external scripts without integrity attribute
    sri_missing = []
    _SCRIPT_TAG_RE = re.compile(r'<script([^>]+)>', re.I)
    exempt_hosts = ["localhost", "127.0.0.1", domain]
    for tag_m in _SCRIPT_TAG_RE.finditer(html):
        attrs = tag_m.group(1)
        src_m = re.search(r'src=["\']([^"\']+)["\']', attrs, re.I)
        if src_m:
            src = src_m.group(1)
            is_external = src.startswith("http") and not any(p in src for p in exempt_hosts)
            has_integrity = "integrity=" in attrs.lower()
            if is_external and not has_integrity:
                sri_missing.append(src)

    # Deduplicate while preserving first-seen order
    seen_urls: set = set()
    unique_urls = []
    for u in urls:
        if u not in seen_urls:
            seen_urls.add(u)
            unique_urls.append(u)

    # Resolve relative URLs to absolute (best-effort)
    resolved = []
    for u in unique_urls:
        if u.startswith("//"):
            u = "https:" + u
        elif u.startswith("/") or not u.startswith("http"):
            # skip relative paths - they are not CDN references
            continue
        resolved.append(u)

    # Extract lib/version pairs - skip URLs we cannot identify
    libraries = []
    seen_lib_url: set = set()

    for url in resolved:
        result = _extract_lib_version(url)
        if result is None:
            continue
        lib_name, version = result
        key = (lib_name, version, url)
        if key in seen_lib_url:
            continue
        seen_lib_url.add(key)

        vulns = _check_vulnerabilities(lib_name, version)
        severity = _highest_severity(vulns) if vulns else "ok"

        libraries.append({
            "name": lib_name,
            "version": version,
            "url": url,
            "vulnerable": bool(vulns),
            "vulnerabilities": vulns,
            "severity": severity,
            "_osv_pending": len(vulns) == 0,  # flag for OSV enrichment
        })

    if not libraries and not polyfill_detected:
        return {
            "enriched": False,
            "reason": "no_cdn_libraries",
            "polyfill_detected": polyfill_detected,
            "sri_missing": sri_missing,
            "sri_missing_count": len(sri_missing),
        }
    if not libraries:
        # polyfill detected but no CDN libs
        libraries = []
        vulnerable_count = 0
        all_vulns = []
        highest = "ok"

    # Enrich with OSV for libs not in local KNOWN_VULNS (max 5 OSV lookups per scan)
    osv_candidates = [lib for lib in libraries if lib.pop("_osv_pending", False)][:5]
    if osv_candidates:
        import asyncio as _asyncio
        osv_results = await _asyncio.gather(
            *[_osv_lookup(lib["name"], lib["version"]) for lib in osv_candidates],
            return_exceptions=True,
        )
        for lib, osv_vulns in zip(osv_candidates, osv_results):
            if isinstance(osv_vulns, list) and osv_vulns:
                lib["vulnerabilities"] = osv_vulns
                lib["vulnerable"] = True
                lib["severity"] = _highest_severity(osv_vulns)
                lib["source"] = "osv.dev"
    # Clean up pending flags from remaining libs
    for lib in libraries:
        lib.pop("_osv_pending", None)

    vulnerable_count = sum(1 for lib in libraries if lib["vulnerable"])
    all_vulns = [v for lib in libraries for v in lib["vulnerabilities"]]
    highest = _highest_severity(all_vulns) if all_vulns else "ok"

    if polyfill_detected:
        libraries.insert(0, {
            "name": "polyfill.io",
            "version": "unknown",
            "url": "https://polyfill.io/",
            "vulnerable": True,
            "vulnerabilities": [{"cve": "N/A", "severity": "critical", "desc": "supply chain compromise risk (2024 incident)"}],
            "severity": "critical",
        })
        if not any(lib["vulnerable"] for lib in libraries):
            vulnerable_count = 1
        else:
            vulnerable_count = sum(1 for lib in libraries if lib["vulnerable"])
        highest = "critical"

    return {
        "enriched": True,
        "libraries": libraries,
        "vulnerable_count": vulnerable_count,
        "library_count": len(libraries),
        "highest_severity": highest,
        "polyfill_detected": polyfill_detected,
        "sri_missing": sri_missing,
        "sri_missing_count": len(sri_missing),
    }
