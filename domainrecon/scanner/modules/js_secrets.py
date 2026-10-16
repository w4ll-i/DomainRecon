# =============================================================================
# DomainRecon - Module « js_secrets » : secrets et points d'accès d'API dans le JavaScript
# =============================================================================
# Deux contrôles :
#   - 16 motifs de secrets (clés AWS, Stripe,
#     GitHub, Slack, SendGrid, Mailgun, Twilio, Google, JWT, clé privée, mot de passe…),
#     VALEURS MASQUÉES (4 premiers et 4 derniers caractères, rien pour une clé privée) ;
#   - points d'accès d'API internes, API externes
#     référencées, liste et taille des fichiers JavaScript.
# Voir impl/wc_js_scan.py pour la liste des défauts corrigés (valeurs d'exemple,
# JWT « anon », exemple AWS, motifs lents sur un fichier minifié d'une seule ligne…).
#
# Fichiers lus : scripts du SITE ciblé (même domaine enregistrable) cités par la page
# d'accueil, 15 au plus, 1 Mio chacun, et les scripts en ligne de la page. Les scripts de
# CDN et de tiers ne sont pas lus (ils ne contiennent pas les secrets de la cible).
# Fichiers de cartes de source (.map) : seulement leur présence est vérifiée.
#
# Catégorie « sensible » : le module cherche des identifiants ; autorisation de tester la
# cible requise, hors des profils rapide et complet.
# =============================================================================

import asyncio
from urllib.parse import urljoin

from ...i18n import msg
from .. import common
from ..errors import ModuleError
from ..http_utils import FETCH_ERRORS, fetch, host_of_url, same_site
from ..impl import wc_js_scan
from ..impl.wc_html_facts import PageFacts
from ..impl.wc_runtime import require_homepage
from ..registry import ModuleSpec, ScanContext
from ..rules import FindingInput, FindingRule, Outcome, ScoreRule, hit
from ..score import as_dict, as_list

MAX_FILES = 15
MAX_SOURCE_MAPS = 3
CONCURRENCY = 4
FILE_TIMEOUT = 12.0

# Libellé de chaque type de secret (messages traduisibles).
TYPE_MESSAGES = {
    "aws_access_key": msg("js_secrets.type_aws_access_key"),
    "aws_secret_key": msg("js_secrets.type_aws_secret_key"),
    "stripe_live_key": msg("js_secrets.type_stripe_live_key"),
    "github_token": msg("js_secrets.type_github_token"),
    "private_key": msg("js_secrets.type_private_key"),
    "jwt": msg("js_secrets.type_jwt"),
    "slack_token": msg("js_secrets.type_slack_token"),
    "sendgrid_key": msg("js_secrets.type_sendgrid_key"),
    "mailgun_key": msg("js_secrets.type_mailgun_key"),
    "twilio_sid": msg("js_secrets.type_twilio_sid"),
    "google_api_key": msg("js_secrets.type_google_api_key"),
    "stripe_publishable_key": msg("js_secrets.type_stripe_publishable_key"),
    "firebase_config": msg("js_secrets.type_firebase_config"),
    "generic_api_key": msg("js_secrets.type_generic_api_key"),
    "hardcoded_password": msg("js_secrets.type_hardcoded_password"),
    "bearer_token": msg("js_secrets.type_bearer_token"),
}


def _first_party_scripts(facts: PageFacts, site: str) -> list[str]:
    """Adresses des scripts du site ciblé, sans doublon, dans l'ordre de la page."""
    urls: list[str] = []
    for script in facts.scripts:
        url = facts.resolve(script["src"])
        if url and same_site(host_of_url(url), site) and url not in urls:
            urls.append(url)
    return urls


async def run(context: ScanContext) -> dict:
    home = await require_homepage(context)
    facts = PageFacts.parse(home.text, home.url or "")
    script_urls = _first_party_scripts(facts, context.site)
    selected = script_urls[:MAX_FILES]

    secrets: list[dict] = wc_js_scan.scan_secrets(facts.inline_text, "inline") if facts.inline_scripts else []
    endpoints, hosts, apis = (
        wc_js_scan.extract_endpoints(facts.inline_text, context.site)
        if facts.inline_scripts
        else (set(), set(), set())
    )
    js_files: list[dict] = []
    map_refs: list[str] = []
    failed = 0
    semaphore = asyncio.Semaphore(CONCURRENCY)

    async with common._http_client(timeout=FILE_TIMEOUT) as client:

        async def read(url: str) -> None:
            nonlocal failed
            async with semaphore:
                try:
                    fetched = await fetch(
                        client,
                        url,
                        site=context.site,
                        max_bytes=wc_js_scan.MAX_FILE_BYTES,
                        timeout=FILE_TIMEOUT,
                    )
                except FETCH_ERRORS:
                    failed += 1
                    return
            if fetched.status_code != 200:
                failed += 1
                return
            text = fetched.text
            secrets.extend(wc_js_scan.scan_secrets(text, url))
            found_endpoints, found_hosts, found_apis = wc_js_scan.extract_endpoints(text, context.site)
            endpoints.update(found_endpoints)
            hosts.update(found_hosts)
            apis.update(found_apis)
            if (ref := wc_js_scan.source_map_reference(text)) is not None:
                map_refs.append(urljoin(url, ref))
            js_files.append(
                {"url": url[:200], "size_bytes": len(fetched.body), "truncated": fetched.truncated}
            )

        await asyncio.gather(*(read(url) for url in selected))
        source_maps = await _exposed_source_maps(client, map_refs, context.site)

    if selected and failed == len(selected):
        raise ModuleError(msg("js_secrets.fetch_failed", count=failed))

    order = {name: index for index, name in enumerate(wc_js_scan.SEVERITY_ORDER)}
    secrets.sort(key=lambda s: (order[s["severity"]], s["type"], s["source"]))
    js_files.sort(key=lambda f: f["url"])
    kept = secrets[: wc_js_scan.MAX_SECRETS]
    return {
        "measured": True,
        "error": None,
        "url": home.url,
        "files_found": len(script_urls),
        "files_scanned": len(js_files),
        "files_failed": failed,
        "inline_scanned": bool(facts.inline_scripts),
        "secrets": kept,
        "secret_counts": wc_js_scan.count_by_severity(secrets),
        "endpoints": sorted(endpoints)[: wc_js_scan.MAX_ENDPOINTS],
        "sensitive_endpoints": wc_js_scan.sensitive_endpoints(endpoints),
        "external_hosts": sorted(hosts)[: wc_js_scan.MAX_HOSTS],
        "external_apis": sorted(apis)[: wc_js_scan.MAX_HOSTS],
        "js_files": js_files[:20],
        "source_maps": source_maps,
        "truncated": home.truncated or len(script_urls) > MAX_FILES,
    }


async def _exposed_source_maps(client, refs: list[str], site: str) -> list[str]:
    """Cartes de source réellement servies (JSON de carte avec « version » ou « sources »)."""
    exposed: list[str] = []
    for url in list(dict.fromkeys(refs))[:MAX_SOURCE_MAPS]:
        if not same_site(host_of_url(url), site):
            continue
        try:
            fetched = await fetch(client, url, site=site, max_bytes=4096, timeout=FILE_TIMEOUT)
        except FETCH_ERRORS:
            continue
        head = fetched.text.lstrip()[:2000]
        if (
            fetched.status_code == 200
            and head.startswith("{")
            and ('"version"' in head or '"sources"' in head)
        ):
            exposed.append(url[:200])
    return exposed


# -----------------------------------------------------------------------------
# Constats et score
# -----------------------------------------------------------------------------


def _check_exposed(f: FindingInput):
    secrets = [as_dict(s) for s in as_list(as_dict(f.data).get("secrets"))]
    hits = []
    for level in wc_js_scan.SEVERITY_ORDER:
        group = [s for s in secrets if s.get("severity") == level]
        if not group:
            continue
        types = sorted({str(s.get("type")) for s in group})
        hits.append(
            hit(
                severity=level,
                count=len(group),
                types=[TYPE_MESSAGES[t] for t in types if t in TYPE_MESSAGES],
                source=str(group[0].get("source", "")),
            )
        )
    return hits or None


def _check_source_maps(f: FindingInput):
    maps = [m for m in as_list(as_dict(f.data).get("source_maps")) if isinstance(m, str)]
    return {"count": len(maps), "example": maps[0]} if maps else None


def _check_sensitive_endpoints(f: FindingInput):
    found = [e for e in as_list(as_dict(f.data).get("sensitive_endpoints")) if isinstance(e, str)]
    return {"count": len(found), "examples": found[:3]} if found else None


def _score(data: dict) -> Outcome:
    result = as_dict(data.get("js_secrets"))
    counts = as_dict(result.get("secret_counts"))
    if counts.get("critical") or counts.get("high"):
        points = 0
    elif counts.get("medium"):
        points = 2
    elif counts.get("low"):
        points = 4
    else:
        points = 5
    if result.get("source_maps"):
        points = min(points, 4)
    total = sum(v for v in counts.values() if isinstance(v, int) and not isinstance(v, bool))
    return Outcome(
        points, msg("js_secrets.score_detail", count=total, files=result.get("files_scanned") or 0), True
    )


SPEC = ModuleSpec(
    name="js_secrets",
    family="web",
    category="sensible",
    run=run,
    timeout=90,
    optional=True,
    order=216,
    findings=(
        FindingRule(code="finding.js_secrets.exposed", severity="high", check=_check_exposed),
        FindingRule(code="finding.js_secrets.source_maps", severity="low", check=_check_source_maps),
        FindingRule(
            code="finding.js_secrets.sensitive_endpoints", severity="low", check=_check_sensitive_endpoints
        ),
    ),
    score_rules=(ScoreRule(criterion="js_secrets", weight=5, evaluate=_score),),
)
