# backend/app/scanners/tech.py
import httpx

# Each signature is a list of (signal, weight) tuples.
# A technology is detected when total weight >= DETECTION_THRESHOLD.
# Signals starting with "header:" match response headers only.
# Signals starting with "body:" match response body only.
# Plain strings match anywhere (body + headers combined).

_DETECTION_THRESHOLD = 2

TECH_SIGNATURES: dict[str, list[tuple[str, int]]] = {
    # CMS
    "WordPress":        [("wp-content/", 3), ("wp-includes/", 3), ("wp-json/", 2), ("wordpress", 2), ("/wp-login.php", 3)],
    "Drupal":           [("/sites/default/files", 3), ("x-generator: drupal", 3), ("drupal.js", 2), ("drupal.min.js", 2)],
    "Joomla":           [("/components/com_", 3), ("joomla!", 3), ("mootools", 1)],
    "Magento":          [("mage/", 2), ("varien/", 3), ("magento", 2), ("/skin/frontend/", 3)],
    "TYPO3":            [("typo3", 3), ("/typo3conf/", 3)],
    "Shopify":          [("cdn.shopify.com", 3), ("shopify", 2), ("myshopify.com", 3)],
    "WooCommerce":      [("woocommerce", 3), ("wc-api", 2)],
    "PrestaShop":       [("prestashop", 3), ("/modules/", 1), ("id_product=", 2)],
    "OpenCart":         [("catalog/view/", 3), ("route=common", 2)],
    "Ghost":            [("ghost.io", 2), ("x-ghost-cache-status", 3)],
    # Frameworks / backends
    "Laravel":          [("laravel_session", 3), ("x-powered-by: php", 1), ("laravel", 2)],
    "Django":           [("csrfmiddlewaretoken", 3), ("django", 2)],
    "Ruby on Rails":    [("x-powered-by: phusion passenger", 2), ("_rails", 2), ("rails", 1)],
    "Express":          [("x-powered-by: express", 3)],
    "Spring Boot":      [("x-application-context", 3), ("whitelabel error page", 2)],
    "ASP.NET":          [("x-powered-by: asp.net", 3), ("x-aspnet-version", 3), ("x-aspnetmvc-version", 3), ("__viewstate", 3)],
    "Flask":            [("werkzeug", 2), ("x-powered-by: flask", 3)],
    "FastAPI":          [("x-process-time", 2)],
    # Frontend frameworks
    "React":            [("react.js", 2), ("react.min.js", 2), ("_next/static", 3), ("__react", 2)],
    "Next.js":          [("_next/static", 3), ("x-nextjs-cache", 3), ("__next_data__", 3)],
    "Angular":          [("ng-version", 3), ("angular.js", 2), ("angular.min.js", 2), ("[ng-version]", 2)],
    "Vue.js":           [("vue.js", 2), ("vue.min.js", 2), ("__vue__", 2), ("nuxt", 1)],
    "Nuxt.js":          [("nuxt", 2), ("__nuxt", 3), ("_nuxt/", 2)],
    "Svelte":           [("svelte", 2), ("__svelte", 2)],
    # Web servers
    "Nginx":            [("server: nginx", 3)],
    "Apache":           [("server: apache", 3)],
    "IIS":              [("server: microsoft-iis", 3), ("x-powered-by: asp.net", 2)],
    "LiteSpeed":        [("server: litespeed", 3)],
    "Caddy":            [("server: caddy", 3)],
    "OpenResty":        [("server: openresty", 3)],
    "Gunicorn":         [("server: gunicorn", 3)],
    "Tomcat":           [("server: apache-coyote", 3), ("x-powered-by: tomcat", 3)],
    # CDN / proxy
    "Cloudflare":       [("cf-ray", 3), ("cf-cache-status", 3)],
    "Varnish":          [("x-varnish", 3), ("via: varnish", 2)],
    "Fastly":           [("x-fastly-request-id", 3), ("via: 1.1 varnish", 2)],
    "Akamai":           [("x-akamai-transformed", 3), ("x-check-cacheable", 2)],
    "AWS CloudFront":   [("x-amz-cf-id", 3), ("x-amz-cf-pop", 3)],
    "AWS S3":           [("x-amz-request-id", 2), ("x-amz-id-2", 2)],
    "Vercel":           [("x-vercel-id", 3), ("x-vercel-cache", 3)],
    "Netlify":          [("x-nf-request-id", 3), ("netlify", 2)],
    "Heroku":           [("x-heroku-queue-wait-time", 3)],
    # Analytics / marketing
    "Google Analytics": [("google-analytics.com/ga.js", 2), ("gtag(", 2), ("ga('create'", 2)],
    "Google Tag Manager": [("googletagmanager.com/gtm.js", 3)],
    "Matomo":           [("matomo.js", 3), ("piwik.js", 3)],
    "Hotjar":           [("hotjar.com", 2), ("hj('create'", 2)],
    # UI libraries
    "Bootstrap":        [("bootstrap.min.css", 2), ("bootstrap.css", 1), ("bootstrap.min.js", 2)],
    "jQuery":           [("jquery.min.js", 2), ("jquery.js", 1)],
    "Tailwind CSS":     [("tailwindcss", 2), ("tw-", 1)],
    "Font Awesome":     [("font-awesome", 2), ("fontawesome", 2)],
    "Material UI":      [("@mui/material", 2), ("material-ui", 2)],
    # E-commerce / payment
    "Stripe":           [("js.stripe.com", 3)],
    "PayPal":           [("paypal.com/sdk", 3)],
    "Braintree":        [("braintreegateway.com", 3)],
}

WAF_SIGNATURES = {
    "Cloudflare":   {"headers": ["cf-ray", "cf-cache-status"], "body": []},
    "AWS WAF":      {"headers": ["x-amzn-requestid", "x-amzn-trace-id"], "body": []},
    "Akamai":       {"headers": ["x-akamai-transformed", "x-akamai-ssl-client-sid"], "body": ["akamai"]},
    "Sucuri":       {"headers": ["x-sucuri-id", "x-sucuri-cache"], "body": ["sucuri"]},
    "ModSecurity":  {"headers": ["mod_security", "modsec"], "body": []},
    "Imperva":      {"headers": ["x-iinfo", "x-cdn"], "body": ["imperva", "incapsula"]},
    "F5 BIG-IP":    {"headers": ["x-waf-event-info", "bigipserver"], "body": ["the requested url was rejected"]},
    "Barracuda":    {"headers": ["barra_counter_session"], "body": ["barracuda"]},
    "Fortinet":     {"headers": ["x-waf-status"], "body": ["fortigate", "fortigate-web-filtering"]},
    "Palo Alto":    {"headers": ["x-pan-rematch"], "body": ["palo alto networks"]},
    "Wordfence":    {"headers": [], "body": ["generated by wordfence", "a security plugin"]},
}


async def detect_technologies(domain: str) -> dict:
    detected = []
    try:
        async with httpx.AsyncClient(
            verify=False, follow_redirects=True, timeout=15
        ) as client:
            r = await client.get(f"https://{domain}")
            body_lower = r.text.lower()
            headers_str = " ".join(f"{k.lower()}: {v.lower()}" for k, v in r.headers.items())
            haystack = body_lower + " " + headers_str

            for tech, signals in TECH_SIGNATURES.items():
                score = 0
                matched_signals = []
                for sig, weight in signals:
                    if sig.startswith("header:"):
                        target = headers_str
                        needle = sig[7:]
                    elif sig.startswith("body:"):
                        target = body_lower
                        needle = sig[5:]
                    else:
                        target = haystack
                        needle = sig
                    if needle.lower() in target:
                        score += weight
                        matched_signals.append(sig)
                if score >= _DETECTION_THRESHOLD:
                    confidence = "high" if score >= 5 else "medium" if score >= 3 else "low"
                    detected.append({
                        "name": tech,
                        "confidence": confidence,
                        "score": score,
                    })
    except Exception:
        pass
    return {"technologies": detected, "count": len(detected)}


async def detect_waf(domain: str) -> dict:
    detected_wafs = []
    try:
        async with httpx.AsyncClient(
            verify=False, follow_redirects=True, timeout=15
        ) as client:
            r = await client.get(f"https://{domain}")
            headers_lower = {k.lower(): v.lower() for k, v in r.headers.items()}
            headers_str = " ".join(f"{k}: {v}" for k, v in headers_lower.items())
            body_lower = r.text.lower()
            for waf, sigs in WAF_SIGNATURES.items():
                matched = any(h in headers_str for h in sigs["headers"])
                if not matched:
                    matched = any(b in body_lower for b in sigs["body"])
                if matched:
                    detected_wafs.append(waf)
    except Exception:
        pass
    return {"waf_detected": detected_wafs, "protected": len(detected_wafs) > 0}
