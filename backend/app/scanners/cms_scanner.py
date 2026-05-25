# backend/app/scanners/cms_scanner.py
"""
CMS Fingerprinting & Vulnerability Detection.

Detects WordPress, Drupal, Joomla, Magento and generic Laravel/PHP
framework exposures. Runs all HTTP probes concurrently via asyncio.gather.

No external API required - only httpx.
"""
import asyncio
import re
import httpx

_UA = "Mozilla/5.0 (DomainRecon/7.0)"
_TIMEOUT = 10
_CLIENT_KWARGS = dict(
    verify=False,
    follow_redirects=True,
    timeout=_TIMEOUT,
    headers={"User-Agent": _UA},
)

# WordPress plugins to probe
_WP_PLUGINS = [
    # Original 8
    "contact-form-7",
    "woocommerce",
    "elementor",
    "yoast-seo",
    "wpforms-lite",
    "wordfence",
    "really-simple-ssl",
    "all-in-one-seo-pack",
    # Extended list
    "gravityforms",
    "advanced-custom-fields",
    "js_composer",
    "revslider",
    "divi",
    "avada",
    "wpml",
    "woocommerce-payments",
    "w3-total-cache",
    "wp-super-cache",
    "duplicator",
    "backupbuddy",
    "wp-file-manager",
    "ultimate-member",
    "bbpress",
    "buddypress",
    "the-events-calendar",
    "ninja-forms",
    "formidable",
    "google-analytics-for-wordpress",
    "optinmonster",
    "coming-soon",
    "wp-smushit",
    "updraftplus",
    "ithemes-security",
    "all-in-one-wp-security-and-firewall",
    "redirection",
    "user-role-editor",
    "members",
    "publishpress",
    "query-monitor",
    "debug-bar",
    "health-check",
    "wp-optimize",
    "autoptimize",
    "litespeed-cache",
    "wp-rocket",
    "elementor-pro",
    "ocean-extra",
    "generatepress",
    "astra",
    "yith-woocommerce-wishlist",
    "mailchimp-for-woocommerce",
]


# ─── helpers ────────────────────────────────────────────────────────────────

async def _get(client: httpx.AsyncClient, url: str) -> httpx.Response | None:
    try:
        return await client.get(url)
    except Exception:
        return None


def _exists(resp: httpx.Response | None, extra_codes: tuple = ()) -> bool:
    """Return True if the response indicates the resource exists."""
    if resp is None:
        return False
    return resp.status_code in (200, 302, *extra_codes)


def _grade(issues: list) -> str:
    """Compute a letter grade from a list of issue dicts."""
    sevs = {i.get("severity", "info") for i in issues}
    if "critical" in sevs:
        return "F"
    if "high" in sevs:
        return "D"
    if "medium" in sevs:
        return "C"
    if "low" in sevs:
        return "B"
    return "A"


# ─── WordPress ──────────────────────────────────────────────────────────────

async def _detect_wordpress(client: httpx.AsyncClient, base: str) -> dict:
    """
    Probe for WordPress and, if found, run deep analysis.
    Returns a partial result dict (cms/version/issues/plugins keys).
    """
    result: dict = {"cms": None, "version": None, "issues": [], "plugins": []}

    # Detection probes (run in parallel)
    login_resp, home_resp = await asyncio.gather(
        _get(client, f"{base}/wp-login.php"),
        _get(client, base),
    )

    is_wp = False
    if login_resp and login_resp.status_code in (200, 302):
        is_wp = True
    if home_resp and home_resp.status_code == 200:
        if re.search(r'<meta[^>]+name=["\']generator["\'][^>]+content=["\'][^"\']*WordPress',
                     home_resp.text, re.IGNORECASE):
            is_wp = True

    if not is_wp:
        return result

    result["cms"] = "WordPress"

    # Deep analysis - all probes in parallel
    (
        readme_resp,
        version_php_resp,
        xmlrpc_resp,
        users_resp,
        debug_resp,
        uploads_resp,
        *plugin_resps,
    ) = await asyncio.gather(
        _get(client, f"{base}/readme.html"),
        _get(client, f"{base}/wp-includes/version.php"),
        _get(client, f"{base}/xmlrpc.php"),
        _get(client, f"{base}/wp-json/wp/v2/users"),
        _get(client, f"{base}/?debug=true"),
        _get(client, f"{base}/wp-content/uploads/"),
        *[_get(client, f"{base}/wp-content/plugins/{p}/readme.txt") for p in _WP_PLUGINS],
    )

    # Version extraction
    version = None
    if readme_resp and readme_resp.status_code == 200:
        m = re.search(r"Version\s+([0-9]+\.[0-9]+(?:\.[0-9]+)?)", readme_resp.text)
        if m:
            version = m.group(1)
    if not version and version_php_resp and version_php_resp.status_code == 200:
        m = re.search(r"\$wp_version\s*=\s*['\"]([0-9]+\.[0-9]+(?:\.[0-9]+)?)['\"]",
                      version_php_resp.text)
        if m:
            version = m.group(1)
    result["version"] = version

    issues = result["issues"]

    # XML-RPC
    if xmlrpc_resp and xmlrpc_resp.status_code == 200:
        issues.append({
            "severity": "medium",
            "title": "XML-RPC enabled",
            "path": "/xmlrpc.php",
        })

    # User enumeration via REST API
    if users_resp and users_resp.status_code == 200:
        try:
            data = users_resp.json()
            if isinstance(data, list) and len(data) > 0:
                issues.append({
                    "severity": "high",
                    "title": "User enumeration via REST API",
                    "path": "/wp-json/wp/v2/users",
                })
        except Exception:
            pass

    # Debug mode
    if debug_resp and debug_resp.status_code == 200:
        if re.search(r"WP_DEBUG|Fatal error|Warning:|Traceback", debug_resp.text):
            issues.append({
                "severity": "medium",
                "title": "Debug mode / error output exposed",
                "path": "/?debug=true",
            })

    # Exposed uploads directory listing
    if uploads_resp and uploads_resp.status_code == 200:
        body = uploads_resp.text
        if re.search(r"Index of|Directory listing", body, re.IGNORECASE):
            issues.append({
                "severity": "medium",
                "title": "wp-content/uploads directory listing enabled",
                "path": "/wp-content/uploads/",
            })

    # Plugin detection
    plugins = []
    for plugin_name, resp in zip(_WP_PLUGINS, plugin_resps):
        if resp and resp.status_code in (200, 403):
            plugin_entry: dict = {
                "name": plugin_name,
                "version": None,
                "path": f"/wp-content/plugins/{plugin_name}/",
            }
            if resp.status_code == 200:
                m = re.search(r"(?:Stable tag|Version)\s*:\s*([0-9]+\.[0-9]+(?:\.[0-9]+)?)",
                              resp.text, re.IGNORECASE)
                if m:
                    plugin_entry["version"] = m.group(1)
            plugins.append(plugin_entry)

    result["plugins"] = plugins
    return result


# ─── Drupal ─────────────────────────────────────────────────────────────────

async def _detect_drupal(client: httpx.AsyncClient, base: str) -> dict:
    result: dict = {"cms": None, "version": None, "issues": [], "plugins": []}

    changelog_resp, core_changelog_resp = await asyncio.gather(
        _get(client, f"{base}/CHANGELOG.txt"),
        _get(client, f"{base}/core/CHANGELOG.txt"),
    )

    changelog = None
    if changelog_resp and changelog_resp.status_code == 200:
        changelog = changelog_resp.text
    elif core_changelog_resp and core_changelog_resp.status_code == 200:
        changelog = core_changelog_resp.text

    if changelog is None:
        return result

    result["cms"] = "Drupal"

    # Version from first meaningful line, e.g. "Drupal 9.4.8, ..."
    m = re.search(r"Drupal\s+([0-9]+\.[0-9]+(?:\.[0-9]+)?)", changelog)
    result["version"] = m.group(1) if m else None

    # Additional probes
    settings_resp, admin_resp = await asyncio.gather(
        _get(client, f"{base}/sites/default/settings.php"),
        _get(client, f"{base}/admin/"),
    )

    issues = result["issues"]
    if settings_resp and settings_resp.status_code == 403:
        issues.append({
            "severity": "medium",
            "title": "settings.php exists (403 - not publicly readable, but present)",
            "path": "/sites/default/settings.php",
        })
    if admin_resp and admin_resp.status_code in (200, 302):
        issues.append({
            "severity": "medium",
            "title": "Drupal admin interface accessible",
            "path": "/admin/",
        })

    return result


# ─── Joomla ─────────────────────────────────────────────────────────────────

async def _detect_joomla(client: httpx.AsyncClient, base: str) -> dict:
    result: dict = {"cms": None, "version": None, "issues": [], "plugins": []}

    admin_resp, readme_resp, lang_resp = await asyncio.gather(
        _get(client, f"{base}/administrator/"),
        _get(client, f"{base}/README.txt"),
        _get(client, f"{base}/language/en-GB/en-GB.xml"),
    )

    is_joomla = False
    # /administrator/ alone is not specific enough - any site could have this path.
    # Require at least one Joomla-specific content signal.
    if readme_resp and readme_resp.status_code == 200:
        if re.search(r"Joomla", readme_resp.text, re.IGNORECASE):
            is_joomla = True
    if lang_resp and lang_resp.status_code == 200:
        if re.search(r"joomla", lang_resp.text, re.IGNORECASE):
            is_joomla = True
    # /administrator/ is only counted when a content signal is already present
    if not is_joomla and admin_resp and admin_resp.status_code in (200, 302):
        # Weak signal alone - check body for Joomla keywords before accepting
        if admin_resp.status_code == 200 and re.search(
            r"joomla|com_login|task=login", admin_resp.text, re.IGNORECASE
        ):
            is_joomla = True

    if not is_joomla:
        return result

    result["cms"] = "Joomla"

    # Version extraction
    version = None
    if readme_resp and readme_resp.status_code == 200:
        m = re.search(r"([0-9]+\.[0-9]+(?:\.[0-9]+)?)", readme_resp.text)
        if m:
            version = m.group(1)
    if not version and lang_resp and lang_resp.status_code == 200:
        m = re.search(r"<version>([0-9]+\.[0-9]+(?:\.[0-9]+)?)</version>", lang_resp.text)
        if m:
            version = m.group(1)
    result["version"] = version

    if admin_resp and admin_resp.status_code in (200, 302):
        result["issues"].append({
            "severity": "medium",
            "title": "Joomla administrator interface accessible",
            "path": "/administrator/",
        })

    return result


# ─── Magento ────────────────────────────────────────────────────────────────

async def _detect_magento(client: httpx.AsyncClient, base: str) -> dict:
    result: dict = {"cms": None, "version": None, "issues": [], "plugins": []}

    downloader_resp, pub_resp, release_resp = await asyncio.gather(
        _get(client, f"{base}/downloader/"),
        _get(client, f"{base}/pub/static/"),
        _get(client, f"{base}/RELEASE_NOTES.txt"),
    )

    is_magento = False
    # /pub/static/ returning 403 alone is not specific to Magento (any server can protect static dirs).
    # Require a content-based signal: RELEASE_NOTES or downloader body.
    if release_resp and release_resp.status_code == 200:
        if re.search(r"Magento", release_resp.text, re.IGNORECASE):
            is_magento = True
    if downloader_resp and downloader_resp.status_code in (200, 302):
        if downloader_resp.status_code == 200 and re.search(
            r"magento|mage|varien", downloader_resp.text, re.IGNORECASE
        ):
            is_magento = True
        elif downloader_resp.status_code == 302:
            # Redirect from /downloader/ is a weak signal - only count with another signal
            if is_magento:
                pass  # already confirmed
    # /pub/static/ is used as a confirming signal only when already detected
    if not is_magento and pub_resp and pub_resp.status_code == 200:
        if re.search(r"magento|mage|varien", pub_resp.text, re.IGNORECASE):
            is_magento = True

    if not is_magento:
        return result

    result["cms"] = "Magento"

    version = None
    if release_resp and release_resp.status_code == 200:
        m = re.search(r"Magento\s+(?:CE\s+)?([0-9]+\.[0-9]+(?:\.[0-9]+)?)", release_resp.text,
                      re.IGNORECASE)
        if m:
            version = m.group(1)
    result["version"] = version

    if downloader_resp and downloader_resp.status_code in (200, 302):
        result["issues"].append({
            "severity": "high",
            "title": "Magento downloader interface accessible",
            "path": "/downloader/",
        })

    return result


# ─── Laravel / generic PHP ──────────────────────────────────────────────────

async def _detect_laravel_generic(client: httpx.AsyncClient, base: str) -> list:
    """Returns a list of issues (these don't define a CMS, just generic exposure)."""
    issues = []

    env_resp, log_resp = await asyncio.gather(
        _get(client, f"{base}/.env"),
        _get(client, f"{base}/storage/logs/laravel.log"),
    )

    if env_resp and env_resp.status_code == 200:
        issues.append({
            "severity": "critical",
            "title": "Exposed .env file - may contain credentials and secrets",
            "path": "/.env",
        })

    if log_resp and log_resp.status_code == 200:
        issues.append({
            "severity": "high",
            "title": "Laravel log file exposed",
            "path": "/storage/logs/laravel.log",
        })

    return issues


# ─── Main scanner ────────────────────────────────────────────────────────────

async def scan_cms(domain: str) -> dict:
    """
    Deep CMS fingerprinting and vulnerability detection for *domain*.

    Returns a structured dict with cms, version, issues, plugins and a
    letter grade. Never raises - all exceptions are caught internally.
    """
    empty: dict = {
        "enriched": False,
        "cms": "Unknown",
        "version": None,
        "issues": [],
        "plugins": [],
        "grade": "A",
    }

    try:
        base = f"https://{domain}"

        async with httpx.AsyncClient(**_CLIENT_KWARGS) as client:
            # Run all CMS detectors concurrently
            wp_result, drupal_result, joomla_result, magento_result, generic_issues = (
                await asyncio.gather(
                    _detect_wordpress(client, base),
                    _detect_drupal(client, base),
                    _detect_joomla(client, base),
                    _detect_magento(client, base),
                    _detect_laravel_generic(client, base),
                )
            )

        # Pick the first positive CMS detection (priority: WP > Drupal > Joomla > Magento)
        detected = None
        for candidate in (wp_result, drupal_result, joomla_result, magento_result):
            if candidate.get("cms"):
                detected = candidate
                break

        all_issues = list(generic_issues)
        plugins: list = []
        cms = "Unknown"
        version = None

        if detected:
            cms = detected["cms"]
            version = detected.get("version")
            all_issues = detected.get("issues", []) + generic_issues
            plugins = detected.get("plugins", [])

        grade = _grade(all_issues)
        enriched = bool(detected or generic_issues)

        return {
            "enriched": enriched,
            "cms": cms,
            "version": version,
            "issues": all_issues,
            "plugins": plugins,
            "grade": grade,
        }

    except Exception:
        return empty
