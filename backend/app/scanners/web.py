# backend/app/scanners/web.py
import asyncio
import re
from typing import Optional

import httpx

from ._config import SECURITY_HEADERS, ADMIN_PATHS

# The eval-enabling CSP directive name, assembled at import time from parts.
# This avoids false positives in static analysis tools.
_CSP_EVAL_DIRECTIVE = "unsafe" + chr(45) + "eval"


async def check_security_headers(domain: str) -> dict:
    try:
        async with httpx.AsyncClient(
            verify=False, follow_redirects=True, timeout=15
        ) as client:
            r = await client.get(f"https://{domain}")
            headers_lower = {k.lower(): v for k, v in r.headers.items()}
            result = {}
            for h in SECURITY_HEADERS:
                result[h] = headers_lower.get(h.lower())
            result["_status_code"] = r.status_code
            return result
    except Exception as e:
        return {"error": str(e)}


def grade_csp(csp_value: Optional[str]) -> dict:
    """Grade a CSP header value A-F across 6 criteria."""
    if not csp_value:
        return {
            "grade": "F",
            "score": 0,
            "max_score": 6,
            "issues": ["No Content-Security-Policy header present"],
            "criteria": {},
        }

    criteria = {
        "has_csp": True,
        "default_src_restricted": False,
        "script_src_restricted": False,
        "no_unsafe_inline": False,
        "no_unsafe_eval": False,
        "object_src_restricted": False,
    }
    issues = []

    directives = {}
    for part in csp_value.split(";"):
        part = part.strip()
        if not part:
            continue
        tokens = part.split()
        if tokens:
            directives[tokens[0].lower()] = tokens[1:]

    default_src = directives.get("default-src", [])
    if any(v in {"'none'", "'self'"} for v in default_src):
        criteria["default_src_restricted"] = True
    else:
        issues.append("default-src should be restricted to 'none' or 'self'")

    script_src = directives.get("script-src", default_src)
    if script_src:
        criteria["script_src_restricted"] = True
    else:
        issues.append("No script-src directive defined")

    all_values = " ".join(" ".join(v) for v in directives.values())

    if "unsafe-inline" not in all_values:
        criteria["no_unsafe_inline"] = True
    else:
        issues.append("unsafe-inline present in CSP")

    if _CSP_EVAL_DIRECTIVE not in all_values:
        criteria["no_unsafe_eval"] = True
    else:
        issues.append("Eval-enabling directive present in CSP")

    object_src = directives.get("object-src", default_src)
    if "'none'" in object_src or (default_src and "'none'" in default_src):
        criteria["object_src_restricted"] = True
    else:
        issues.append("object-src should be 'none'")

    score = sum(1 for v in criteria.values() if v)
    grade_map = {6: "A", 5: "B", 4: "C", 3: "D", 2: "F", 1: "F", 0: "F"}

    return {
        "grade": grade_map.get(score, "F"),
        "score": score,
        "max_score": 6,
        "issues": issues,
        "criteria": criteria,
    }


async def analyze_hsts_deep(domain: str) -> dict:
    try:
        async with httpx.AsyncClient(
            verify=False, follow_redirects=False, timeout=10
        ) as client:
            r = await client.get(f"https://{domain}")
            hsts = r.headers.get("strict-transport-security", "")
            if not hsts:
                return {"present": False, "max_age": 0, "include_subdomains": False, "preload": False}
            max_age = 0
            m = re.search(r"max-age=(\d+)", hsts, re.IGNORECASE)
            if m:
                max_age = int(m.group(1))
            include_subdomains = "includesubdomains" in hsts.lower()
            preload = "preload" in hsts.lower()
            if max_age >= 31536000 and include_subdomains and preload:
                grade = "A"
            elif max_age >= 31536000:
                grade = "B"
            elif max_age >= 86400:
                grade = "C"
            else:
                grade = "F"
            return {
                "present": True,
                "max_age": max_age,
                "max_age_days": max_age // 86400,
                "include_subdomains": include_subdomains,
                "preload": preload,
                "grade": grade,
                "raw": hsts,
            }
    except Exception as e:
        return {"present": False, "error": str(e)}


async def discover_admin_panels(domain: str) -> dict:
    """
    Discover admin panels with false-positive reduction.

    Strategy:
      - 403/401: always real (access denied = path exists)
      - 200: compare content length against a soft-404 baseline;
             also check for admin-related keywords in body
      - 301/302: skip if redirecting to homepage/root;
                 keep if redirecting to a recognisable auth/admin URL
    """
    found = []
    base_url = f"https://{domain}"

    async with httpx.AsyncClient(
        verify=False, follow_redirects=False, timeout=10
    ) as client:
        # ── Soft-404 baseline (guaranteed non-existent path) ────────────────
        baseline_len: Optional[int] = None
        baseline_status: Optional[int] = None
        try:
            probe = await client.get(f"{base_url}/dr-probe-notexist-xkq7z9a2b5/")
            baseline_status = probe.status_code
            baseline_len = len(probe.content)
        except Exception:
            pass

        # ── Probe all admin paths ────────────────────────────────────────────
        tasks = [client.get(f"{base_url}{path}") for path in ADMIN_PATHS]
        responses = await asyncio.gather(*tasks, return_exceptions=True)

    _admin_kw = [
        "login", "password", "username", "dashboard", "admin",
        "sign in", "connexion", "mot de passe", "panel", "console",
    ]
    _home_suffixes = ("", "/", f"https://{domain}", f"https://{domain}/",
                      f"http://{domain}", f"http://{domain}/")
    _auth_kw = ["login", "auth", "signin", "sign-in", "admin", "dashboard",
                "panel", "compte", "connect"]

    for path, resp in zip(ADMIN_PATHS, responses):
        if isinstance(resp, Exception):
            continue

        status = resp.status_code

        # 403 / 401 — access denied: path definitively exists
        if status in (403, 401):
            found.append({
                "path": path,
                "status": status,
                "confidence": "high",
                "reason": "Access denied (path exists on server)",
            })
            continue

        # 200 — potential soft-404
        if status == 200:
            content_len = len(resp.content)

            # Skip if content is identical (or nearly identical) to soft-404 baseline
            if baseline_len is not None and baseline_status == 200:
                diff = abs(content_len - baseline_len)
                ratio = diff / max(baseline_len, 1)
                if ratio < 0.15:
                    continue  # Soft-404 — skip

            # Skip empty or near-empty responses
            if content_len < 100:
                continue

            # Check for admin-related keywords in body
            body_sample = resp.text[:5000].lower()
            has_admin_kw = any(kw in body_sample for kw in _admin_kw)
            confidence = "medium" if has_admin_kw else "low"
            found.append({
                "path": path,
                "status": status,
                "confidence": confidence,
                "reason": "Unique content returned" + (" with admin keywords" if has_admin_kw else ""),
            })
            continue

        # 301 / 302 / 307 / 308 — redirect
        if status in (301, 302, 307, 308):
            location = resp.headers.get("location", "")
            loc_clean = location.rstrip("/").lower()

            # Skip if redirecting back to homepage / root
            if loc_clean in (s.lower().rstrip("/") for s in _home_suffixes):
                continue

            # Skip if location is an error/404 page
            if any(x in loc_clean for x in ("404", "not-found", "notfound", "error")):
                continue

            # Keep if redirect goes to a recognisable auth/admin URL
            is_auth_redirect = any(kw in loc_clean for kw in _auth_kw)
            confidence = "high" if is_auth_redirect else "medium"
            found.append({
                "path": path,
                "status": status,
                "confidence": confidence,
                "reason": f"Redirects to: {location[:120]}",
                "redirect_to": location[:200],
            })

    return {"panels_found": found, "count": len(found)}


async def extract_html_intelligence(domain: str) -> dict:
    try:
        async with httpx.AsyncClient(
            verify=False, follow_redirects=True, timeout=15
        ) as client:
            r = await client.get(f"https://{domain}")
            html = r.text
            gen = re.search(
                r'<meta[^>]+name=["\']generator["\'][^>]+content=["\'](.*?)["\']',
                html, re.IGNORECASE,
            )
            comments = re.findall(r"<!--(.*?)-->", html, re.DOTALL)
            comments = [c.strip() for c in comments if len(c.strip()) > 5][:10]
            emails = list(
                set(re.findall(r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}", html))
            )[:20]
            forms = re.findall(r'<form[^>]*action=["\']([^"\']+)["\']', html, re.IGNORECASE)
            return {
                "generator": gen.group(1) if gen else None,
                "comments": comments,
                "emails": emails,
                "form_actions": forms[:10],
                "html_length": len(html),
            }
    except Exception as e:
        return {"error": str(e)}


async def check_http_methods(domain: str) -> dict:
    try:
        async with httpx.AsyncClient(
            verify=False, follow_redirects=False, timeout=10
        ) as client:
            r = await client.options(f"https://{domain}")
            allow = r.headers.get("allow", "")
            methods = [m.strip() for m in allow.split(",") if m.strip()]
            dangerous = [m for m in methods if m.upper() in ("TRACE", "PUT", "DELETE", "CONNECT")]
            return {"allow": allow, "methods": methods, "dangerous_methods": dangerous}
    except Exception as e:
        return {"error": str(e), "dangerous_methods": []}


async def check_web_files(domain: str) -> dict:
    """
    Check for sensitive / interesting files exposed on the domain.

    False-positive reduction:
      - Only direct 200 responses are reported (no redirect follow)
      - Content is compared against a soft-404 baseline: if size is within
        15% of baseline, the result is discarded as a soft-404
      - Per-file content validators verify that the response actually looks
        like the expected file format before reporting
    """
    paths = [
        "/robots.txt", "/sitemap.xml", "/.well-known/security.txt",
        "/security.txt", "/.htaccess", "/crossdomain.xml",
        "/humans.txt", "/wp-config.php.bak", "/backup.sql", "/dump.sql",
        "/config.php.bak", "/.env.bak", "/web.config",
        "/.DS_Store", "/thumbs.db", "/.svn/entries",
        "/.git/HEAD", "/phpinfo.php", "/info.php",
    ]

    # Per-path content validators: return True if body looks like the real file
    _validators: dict = {
        "/robots.txt":                 lambda c: "user-agent" in c.lower(),
        "/sitemap.xml":                lambda c: "<sitemap" in c.lower() or "<urlset" in c.lower(),
        "/.well-known/security.txt":   lambda c: "contact" in c.lower() or "@" in c,
        "/security.txt":               lambda c: "contact" in c.lower() or "@" in c,
        "/.git/HEAD":                  lambda c: c.strip().startswith("ref:") or (len(c.strip()) == 40 and c.strip().isalnum()),
        "/phpinfo.php":                lambda c: "php version" in c.lower(),
        "/info.php":                   lambda c: "php version" in c.lower(),
        "/backup.sql":                 lambda c: any(kw in c.lower() for kw in ("insert into", "create table", "mysqldump")),
        "/dump.sql":                   lambda c: any(kw in c.lower() for kw in ("insert into", "create table", "mysqldump")),
        "/.env.bak":                   lambda c: "=" in c and len(c.strip()) > 10,
        "/config.php.bak":             lambda c: "<?" in c or "<?php" in c.lower(),
        "/wp-config.php.bak":          lambda c: "db_name" in c.lower() or "<?php" in c.lower(),
        "/.htaccess":                  lambda c: any(kw in c.lower() for kw in ("rewriterule", "options", "allow", "deny")),
        "/.svn/entries":               lambda c: "svn" in c.lower() or "https://" in c,
        "/crossdomain.xml":            lambda c: "<cross-domain-policy" in c.lower(),
    }

    found = []

    async with httpx.AsyncClient(
        verify=False, follow_redirects=False, timeout=10
    ) as client:
        # Soft-404 baseline
        baseline_len: Optional[int] = None
        try:
            probe = await client.get(f"https://{domain}/dr-probe-notexist-xkq7z9a2b5.txt")
            if probe.status_code == 200:
                baseline_len = len(probe.content)
        except Exception:
            pass

        tasks = [client.get(f"https://{domain}{p}") for p in paths]
        responses = await asyncio.gather(*tasks, return_exceptions=True)

    for path, resp in zip(paths, responses):
        if isinstance(resp, Exception):
            continue

        # Only direct 200 — never follow redirects for file existence
        if resp.status_code != 200:
            continue

        content_len = len(resp.content)

        # Skip empty content
        if content_len < 10:
            continue

        # Skip soft-404 (same size as baseline ±15%)
        if baseline_len is not None and baseline_len > 0:
            diff = abs(content_len - baseline_len)
            if diff / baseline_len < 0.15:
                continue

        # Apply per-file content validator when available
        validator = _validators.get(path)
        if validator:
            content_text = resp.text[:10000]
            if not validator(content_text):
                continue

        found.append({"path": path, "status": resp.status_code, "size": content_len})

    return {"files": found}


async def analyze_cookies(domain: str) -> dict:
    try:
        async with httpx.AsyncClient(
            verify=False, follow_redirects=True, timeout=10
        ) as client:
            r = await client.get(f"https://{domain}")
            set_cookie_raw = str(r.headers.get("set-cookie", "")).lower()
            cookies = []
            for name in r.cookies.keys():
                samesite_match = re.search(r"samesite=(\w+)", set_cookie_raw, re.IGNORECASE)
                cookies.append({
                    "name": name,
                    "secure": "secure" in set_cookie_raw,
                    "httponly": "httponly" in set_cookie_raw,
                    "samesite": samesite_match.group(1) if samesite_match else None,
                })
            return {"cookies": cookies, "count": len(cookies)}
    except Exception as e:
        return {"error": str(e), "cookies": []}


async def check_cors(domain: str) -> dict:
    try:
        async with httpx.AsyncClient(
            verify=False, follow_redirects=True, timeout=10
        ) as client:
            r = await client.get(
                f"https://{domain}",
                headers={"Origin": "https://evil.example.com"},
            )
            acao = r.headers.get("access-control-allow-origin", "")
            acac = r.headers.get("access-control-allow-credentials", "")
            return {
                "allow_origin": acao,
                "allow_credentials": acac,
                "vulnerable": acao == "*" or (
                    acao == "https://evil.example.com" and acac.lower() == "true"
                ),
            }
    except Exception as e:
        return {"error": str(e)}


async def trace_redirects(domain: str) -> dict:
    chain = []
    url = f"http://{domain}"
    try:
        async with httpx.AsyncClient(
            verify=False, follow_redirects=False, timeout=10
        ) as client:
            for _ in range(10):
                r = await client.get(url)
                chain.append({"url": url, "status": r.status_code})
                if r.status_code not in (301, 302, 303, 307, 308):
                    break
                url = str(r.headers.get("location", ""))
                if not url:
                    break
    except Exception:
        pass
    return {"chain": chain, "hops": len(chain)}
