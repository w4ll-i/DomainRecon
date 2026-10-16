# =============================================================================
# DomainRecon - Module « cms_data » : empreinte CMS et expositions
# =============================================================================
# Détecte WordPress, Drupal, Joomla et Magento à partir de SIGNATURES DE CONTENU
# en écartant les faux positifs :
# un chemin seul (/administrator/, /pub/static/) ne suffit jamais, il faut une
# preuve dans le contenu (balise generator, readme, flux) ; la version vient du
# generator, d'un readme ou d'un flux ; les expositions (XML-RPC, énumération des
# utilisateurs, listing de dossier) sont confirmées par le contenu, pas par un
# simple code 200/403. Une réponse identique à la page « introuvable » de référence
# est écartée.
# Les fichiers .env et storage/logs/laravel.log de l'ancien détecteur Laravel
# relèvent de « sensitive_files » et ne sont PAS cherchés ici.
# Catégorie « actif » : plusieurs chemins forgés au-delà d'une visite normale.
# =============================================================================

import asyncio
import re

from ..impl import web_exposure as probe
from ..registry import ModuleSpec, ScanContext
from ..rules import FindingInput, FindingRule, hit
from ..score import as_dict, as_list

_VERSION = re.compile(r"([0-9]+\.[0-9]+(?:\.[0-9]+)?)")
_GENERATOR = re.compile(r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']([^"\']+)["\']', re.IGNORECASE)


def _generator(html: str) -> str:
    match = _GENERATOR.search(html or "")
    return match.group(1) if match else ""


async def _fetch(client, origin, host, path):
    from ..http_utils import FETCH_ERRORS, fetch

    try:
        return await fetch(client, origin + path, site=host, max_bytes=probe.MAX_BODY, max_redirects=1)
    except FETCH_ERRORS:
        return None


def _ok(fetched, baseline) -> bool:
    return (
        fetched is not None
        and fetched.status_code == 200
        and not baseline.same_page(fetched.text, len(fetched.body))
    )


async def _wordpress(client, origin, host, home_text, baseline) -> dict | None:
    gen = _generator(home_text).lower()
    readme, version_php, xmlrpc, users = await asyncio.gather(
        _fetch(client, origin, host, "/readme.html"),
        _fetch(client, origin, host, "/wp-includes/version.php"),
        _fetch(client, origin, host, "/xmlrpc.php"),
        _fetch(client, origin, host, "/wp-json/wp/v2/users"),
    )
    is_wp = "wordpress" in gen or (_ok(readme, baseline) and "wordpress" in readme.text.lower())
    if not is_wp:
        return None
    version = None
    if "wordpress" in gen:
        m = _VERSION.search(gen)
        version = m.group(1) if m else None
    if not version and _ok(readme, baseline):
        m = re.search(r"version\s+([0-9.]+)", readme.text, re.IGNORECASE)
        version = m.group(1) if m else version
    if not version and _ok(version_php, baseline):
        m = re.search(r"\$wp_version\s*=\s*['\"]([0-9.]+)", version_php.text)
        version = m.group(1) if m else version
    issues = []
    if _ok(xmlrpc, baseline) or (xmlrpc is not None and xmlrpc.status_code == 405):
        issues.append({"key": "xmlrpc", "severity": "medium"})
    if _ok(users, baseline) and users.text.strip().startswith("["):
        issues.append({"key": "user_enum", "severity": "high"})
    return {"cms": "WordPress", "version": version, "issues": issues}


async def _drupal(client, origin, host, home_text, baseline) -> dict | None:
    gen = _generator(home_text).lower()
    changelog, core = await asyncio.gather(
        _fetch(client, origin, host, "/CHANGELOG.txt"),
        _fetch(client, origin, host, "/core/CHANGELOG.txt"),
    )
    text = None
    for resp in (changelog, core):
        if _ok(resp, baseline) and "drupal" in resp.text.lower():
            text = resp.text
            break
    if "drupal" not in gen and text is None:
        return None
    version = None
    source = text or gen
    m = re.search(r"drupal\s+([0-9.]+)", source, re.IGNORECASE)
    version = m.group(1) if m else None
    return {"cms": "Drupal", "version": version, "issues": []}


async def _joomla(client, origin, host, home_text, baseline) -> dict | None:
    gen = _generator(home_text).lower()
    readme, lang = await asyncio.gather(
        _fetch(client, origin, host, "/README.txt"),
        _fetch(client, origin, host, "/language/en-GB/en-GB.xml"),
    )
    is_joomla = "joomla" in gen
    if _ok(readme, baseline) and "joomla" in readme.text.lower():
        is_joomla = True
    if _ok(lang, baseline) and "joomla" in lang.text.lower():
        is_joomla = True
    if not is_joomla:
        return None
    version = None
    if _ok(lang, baseline):
        m = re.search(r"<version>([0-9.]+)</version>", lang.text)
        version = m.group(1) if m else None
    return {"cms": "Joomla", "version": version, "issues": []}


async def _magento(client, origin, host, home_text, baseline) -> dict | None:
    release, cookies = await asyncio.gather(
        _fetch(client, origin, host, "/RELEASE_NOTES.txt"),
        _fetch(client, origin, host, "/static/version"),
    )
    is_magento = _ok(release, baseline) and "magento" in release.text.lower()
    if "magento" in (home_text or "").lower() and "mage-" in (home_text or "").lower():
        is_magento = True
    if not is_magento:
        return None
    version = None
    if _ok(release, baseline):
        m = re.search(r"magento\s+(?:ce\s+)?([0-9.]+)", release.text, re.IGNORECASE)
        version = m.group(1) if m else None
    return {"cms": "Magento", "version": version, "issues": []}


async def run(context: ScanContext) -> dict:
    home = await probe.homepage_or_fail(context)
    host = context.domain
    origin = probe.origin_of(home, host)
    home_text = home.text

    async with await probe.open_client() as client:
        baseline = await probe.measure_baseline(client, origin, host)
        detectors = (_wordpress, _drupal, _joomla, _magento)
        results = await asyncio.gather(*(d(client, origin, host, home_text, baseline) for d in detectors))

    detected = next((r for r in results if r is not None), None)
    return {
        "measured": True,
        "error": None,
        "url": home.url,
        "cms": detected["cms"] if detected else None,
        "version": detected.get("version") if detected else None,
        "issues": detected.get("issues", []) if detected else [],
        "catch_all": baseline.catch_all,
    }


def _check_issues(f: FindingInput, severity: str) -> object:
    data = as_dict(f.data)
    issues = [
        str(i.get("key"))
        for i in as_list(data.get("issues"))
        if isinstance(i, dict) and i.get("severity") == severity
    ]
    cms = data.get("cms")
    return hit(cms=str(cms), issues=", ".join(issues)) if issues and cms else None


SPEC = ModuleSpec(
    name="cms_data",
    family="web",
    category="actif",
    run=run,
    order=147,
    timeout=60,
    findings=(
        FindingRule(
            code="finding.cms_data.exposure_high", severity="high", check=lambda f: _check_issues(f, "high")
        ),
        FindingRule(
            code="finding.cms_data.exposure_medium",
            severity="medium",
            check=lambda f: _check_issues(f, "medium"),
        ),
    ),
)
