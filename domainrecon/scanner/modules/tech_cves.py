# =============================================================================
# DomainRecon - Module « tech_cves » : vulnérabilités connues des technologies détectées
# =============================================================================
# Prend les technologies et versions relevées par le module tech_stack et interroge OSV.dev
# (https://google.github.io/osv.dev/api/, gratuit, sans clé) pour chaque paquet
# connu : frameworks JavaScript, Django, Flask, Laravel, Symfony, Drupal, Joomla,
# TYPO3, Magento, PrestaShop, Rails…
#
# Limites, dites à l'utilisateur dans le résultat (`unchecked`) :
#   - OSV.dev recense des PAQUETS (npm, PyPI, Packagist, RubyGems), pas des serveurs :
#     nginx, Apache, IIS, PHP ne sont pas couverts ; leur version est listée telle quelle ;
#   - une version annoncée par un en-tête peut être masquée ou rétroportée : le constat
#     est un indice à vérifier, pas une preuve ;
#   - les bibliothèques JavaScript chargées par <script> sont traitées par js_dependencies
#     (avec l'intégrité SRI) et ne sont pas doublées ici.
# =============================================================================

import asyncio

from ...i18n import msg
from ..errors import ModuleError, ModuleSkipped
from ..impl import wc_osv, wc_tech_catalog
from ..impl.wc_runtime import api_client, osv_error_message
from ..impl.wc_versions import highest_version
from ..registry import ModuleSpec, ScanContext
from ..rules import FindingInput, FindingRule, Outcome, ScoreRule, hit
from ..score import as_dict, as_list

# Paquets interrogés au plus par scan, et requêtes simultanées.
MAX_PACKAGES = 12
CONCURRENCY = 4
_SEVERITY_ORDER = ("critical", "high", "medium", "low")


def _targets(stack: dict) -> tuple[list[dict], list[dict]]:
    """(technologies à interroger, technologies avec version sans base de vulnérabilités)."""
    to_check: list[dict] = []
    unchecked: list[dict] = []
    seen: set[tuple] = set()
    for tech in as_list(stack.get("technologies")):
        tech = as_dict(tech)
        name, version = tech.get("name"), tech.get("version")
        if not isinstance(name, str) or not isinstance(version, str) or not version:
            continue
        package = wc_tech_catalog.OSV_PACKAGES.get(name)
        # Une détection « faible » ou déduite n'engage pas de constat de vulnérabilité.
        if package is None or package[2] or tech.get("confidence") == "low" or tech.get("implied"):
            if package is None and tech.get("category_key") in (
                "web_server",
                "language",
                "reverse_proxy",
                "cms",
            ):
                unchecked.append({"name": name, "version": version})
            continue
        key = (package[0], package[1], version)
        if key in seen:
            continue
        seen.add(key)
        to_check.append({"name": name, "version": version, "ecosystem": package[0], "package": package[1]})
    return to_check[:MAX_PACKAGES], unchecked[:20]


def _highest(vulns: list[dict]) -> str | None:
    for level in _SEVERITY_ORDER:
        if any(v.get("severity") == level for v in vulns):
            return level
    return None


async def run(context: ScanContext) -> dict:
    stack = as_dict(context.results.get("tech_stack"))
    if not stack:
        raise ModuleSkipped(msg("tech_cves.no_stack"))
    to_check, unchecked = _targets(stack)
    base = {"measured": True, "error": None, "checked": 0, "unchecked": unchecked, "technologies": []}
    if not to_check:
        return base

    semaphore = asyncio.Semaphore(CONCURRENCY)
    errors: list[wc_osv.OsvError] = []

    async with api_client(context) as client:

        async def check(item: dict) -> dict:
            async with semaphore:
                try:
                    vulns = await wc_osv.lookup(client, item["ecosystem"], item["package"], item["version"])
                except wc_osv.OsvError as e:
                    errors.append(e)
                    return {**item, "vulnerabilities": [], "checked": False}
            return {**item, "vulnerabilities": vulns, "highest": _highest(vulns), "checked": True}

        results = await asyncio.gather(*(check(item) for item in to_check))

    if errors and len(errors) == len(results):
        raise ModuleError(osv_error_message(errors[0]))
    checked = [r for r in results if r["checked"]]
    return {
        **base,
        "checked": len(checked),
        "failed": len(errors),
        "technologies": results,
        "vulnerable_count": sum(1 for r in checked if r["vulnerabilities"]),
        "highest_severity": _highest([v for r in checked for v in r["vulnerabilities"]]),
    }


# -----------------------------------------------------------------------------
# Constats et score
# -----------------------------------------------------------------------------


def _check_vulnerable(f: FindingInput):
    hits = []
    for tech in as_list(as_dict(f.data).get("technologies")):
        tech = as_dict(tech)
        vulns = [as_dict(v) for v in as_list(tech.get("vulnerabilities"))]
        level = _highest(vulns)
        if not vulns or level is None:
            continue
        top = vulns[0]
        fixed = highest_version(v.get("fixed") for v in vulns)
        hits.append(
            hit(
                severity=level,
                name=str(tech.get("name")),
                version=str(tech.get("version")),
                count=len(vulns),
                cve=str(top.get("cve") or top.get("id") or ""),
                fixed=str(fixed) if fixed else "-",
            )
        )
    return hits or None


def _score(data: dict) -> Outcome:
    result = as_dict(data.get("tech_cves"))
    if not result.get("checked"):
        # Rien d'interrogeable (aucune version, que des serveurs) : critère sans objet, pas une note de 8/8.
        return Outcome(0, msg("tech_cves.score_nothing"), False, applicable=False)
    level = result.get("highest_severity")
    detail = msg("tech_cves.score_detail", count=result.get("vulnerable_count") or 0)
    points = {"critical": 0, "high": 2, "medium": 5, "low": 7}.get(level, 8)
    return Outcome(points, detail, True)


SPEC = ModuleSpec(
    name="tech_cves",
    family="web",
    category="passif",
    run=run,
    wave=2,
    depends_on=("tech_stack",),
    optional=True,
    timeout=60,
    order=211,
    findings=(FindingRule(code="finding.tech_cves.vulnerable", severity="medium", check=_check_vulnerable),),
    score_rules=(ScoreRule(criterion="tech_cves", weight=8, evaluate=_score),),
)
