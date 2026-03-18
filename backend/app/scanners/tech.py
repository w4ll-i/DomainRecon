# backend/app/scanners/tech.py
import httpx

TECH_SIGNATURES = {
    "WordPress":        ["wp-content", "wp-includes"],
    "Drupal":           ["drupal", "/sites/default/files"],
    "Joomla":           ["joomla", "/components/com_"],
    "React":            ["react.js", "react.min.js", "_next/static"],
    "Angular":          ["ng-version", "angular.js"],
    "Vue.js":           ["vue.js", "vue.min.js"],
    "Laravel":          ["laravel_session"],
    "Django":           ["csrfmiddlewaretoken"],
    "Ruby on Rails":    ["_rails"],
    "Express":          ["x-powered-by: express"],
    "Nginx":            ["server: nginx"],
    "Apache":           ["server: apache"],
    "IIS":              ["microsoft-iis", "x-powered-by: asp.net"],
    "Cloudflare":       ["cf-ray", "cloudflare"],
    "Varnish":          ["x-varnish"],
    "Bootstrap":        ["bootstrap.min.css"],
    "jQuery":           ["jquery.min.js"],
    "Google Analytics": ["google-analytics.com/ga.js", "gtag("],
    "Shopify":          ["cdn.shopify.com"],
    "WooCommerce":      ["woocommerce"],
}

WAF_SIGNATURES = {
    "Cloudflare": {"headers": ["cf-ray", "cf-cache-status"], "body": []},
    "AWS WAF":    {"headers": ["x-amzn-requestid"], "body": []},
    "Akamai":     {"headers": ["x-akamai-transformed"], "body": ["akamai"]},
    "Sucuri":     {"headers": ["x-sucuri-id"], "body": ["sucuri"]},
    "ModSecurity":{"headers": ["mod_security", "modsec"], "body": []},
    "Imperva":    {"headers": ["x-iinfo"], "body": ["imperva", "incapsula"]},
}


async def detect_technologies(domain: str) -> dict:
    detected = set()
    try:
        async with httpx.AsyncClient(
            verify=False, follow_redirects=True, timeout=15
        ) as client:
            r = await client.get(f"https://{domain}")
            haystack = r.text.lower() + " " + " ".join(
                f"{k}: {v}" for k, v in r.headers.items()
            ).lower()
            for tech, sigs in TECH_SIGNATURES.items():
                for sig in sigs:
                    if sig.lower() in haystack:
                        detected.add(tech)
                        break
    except Exception:
        pass
    return {"technologies": list(detected), "count": len(detected)}


async def detect_waf(domain: str) -> dict:
    detected_wafs = []
    try:
        async with httpx.AsyncClient(
            verify=False, follow_redirects=True, timeout=15
        ) as client:
            r = await client.get(f"https://{domain}")
            headers_lower = {k.lower(): v.lower() for k, v in r.headers.items()}
            body_lower = r.text.lower()
            for waf, sigs in WAF_SIGNATURES.items():
                matched = any(h in k for h in sigs["headers"] for k in headers_lower)
                if not matched:
                    matched = any(b in body_lower for b in sigs["body"])
                if matched:
                    detected_wafs.append(waf)
    except Exception:
        pass
    return {"waf_detected": detected_wafs, "protected": len(detected_wafs) > 0}
