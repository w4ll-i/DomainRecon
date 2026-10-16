# =============================================================================
# DomainRecon - Module « js_dependencies » : bibliothèques JavaScript vulnérables et SRI
# =============================================================================
# Détection des bibliothèques chargées par la page, vulnérabilités connues,
# polyfill.io, absence d'intégrité des sous-ressources (SRI). Points notables :
#   - comparaison de versions : la version CORRIGÉE n'est plus signalée (jQuery 3.5.0,
#     Bootstrap 4.3.1 l'étaient à tort) et une version illisible (« latest ») n'est plus
#     vulnérable par défaut ; plages [introduite, corrigée[ (impl/wc_versions.py) ;
#   - gravité OSV : le vecteur CVSS est lu (ce n'est pas un nombre : lu comme tel,
#     tout sortirait « moyen ») ;
#   - les fichiers hébergés par le site lui-même sont analysés ;
#   - SRI : un hôte tiers est reconnu par son domaine enregistrable (« evil-example.com »
#     n'est plus exempté parce que son nom contient « example.com »), les URL
#     protocole-relatives et les feuilles de style sont comptées, et les services dont le
#     contenu change par construction (Google Tag Manager, polices Google, Stripe…) ne sont
#     pas reprochés au site ;
#   - « polyfill-fastly.io » (miroir sûr de Fastly) n'est plus accusé ; sont signalés
#     polyfill.io et les domaines du même opérateur (Sansec, juin 2024).
#
# Vulnérabilités : OSV.dev (https://google.github.io/osv.dev/api/, gratuit) recoupé avec la
# table locale (impl/wc_js_libs.py) : hors ligne, le module répond avec la table seule.
# Passif : la page d'accueil partagée du scan ; seul OSV.dev reçoit des requêtes (nom du
# paquet et version, jamais la cible).
# =============================================================================

import asyncio

from ...i18n import msg
from ..impl import wc_js_libs, wc_osv
from ..impl.wc_runtime import api_client, osv_error_message, require_homepage
from ..impl.wc_versions import highest_version, parse_version
from ..registry import ModuleSpec, ScanContext
from ..rules import FindingInput, FindingRule, Outcome, ScoreRule, hit
from ..score import as_dict, as_list

MAX_OSV_LOOKUPS = 12
CONCURRENCY = 4
_SEVERITY_ORDER = ("critical", "high", "medium", "low")

# Natures de vulnérabilité de la table locale (messages traduisibles).
_KIND_MESSAGES = {
    "code_injection": msg("js_dependencies.kind_code_injection"),
    "csrf": msg("js_dependencies.kind_csrf"),
    "dos": msg("js_dependencies.kind_dos"),
    "path_traversal": msg("js_dependencies.kind_path_traversal"),
    "prototype_pollution": msg("js_dependencies.kind_prototype_pollution"),
    "redos": msg("js_dependencies.kind_redos"),
    "ssrf": msg("js_dependencies.kind_ssrf"),
    "xss": msg("js_dependencies.kind_xss"),
}


def _highest(vulns: list[dict]) -> str | None:
    for level in _SEVERITY_ORDER:
        if any(v.get("severity") == level for v in vulns):
            return level
    return None


def _merge(osv: list[dict], local: list[dict]) -> list[dict]:
    """Avis OSV complétés par la table locale (sans doublon de CVE)."""
    known = {v.get("cve") or v.get("id") for v in osv}
    merged = [{**v, "source": "osv.dev"} for v in osv]
    for vuln in local:
        if vuln["cve"] in known:
            continue
        merged.append(
            {**{k: v for k, v in vuln.items() if k != "kind"}, "summary": _KIND_MESSAGES[vuln["kind"]]}
        )
    merged.sort(
        key=lambda v: _SEVERITY_ORDER.index(v["severity"]) if v.get("severity") in _SEVERITY_ORDER else 9
    )
    return merged[:12]


async def run(context: ScanContext) -> dict:
    home = await require_homepage(context)
    page = wc_js_libs.analyze_html(home.text, home.url or "", context.site)
    libraries = page["libraries"]

    # Bibliothèques interrogeables dans OSV : paquet npm connu, version numérique exacte.
    pending = [
        lib
        for lib in libraries
        if lib["name"] in wc_js_libs.KNOWN_PACKAGES
        and lib["version"]
        and parse_version(lib["version"]) is not None
    ][:MAX_OSV_LOOKUPS]
    osv_results: dict[tuple, list[dict]] = {}
    errors: list[wc_osv.OsvError] = []
    if pending:
        semaphore = asyncio.Semaphore(CONCURRENCY)
        async with api_client(context) as client:

            async def query(lib: dict) -> None:
                async with semaphore:
                    try:
                        osv_results[(lib["name"], lib["version"])] = await wc_osv.lookup(
                            client, "npm", lib["name"], lib["version"]
                        )
                    except wc_osv.OsvError as e:
                        errors.append(e)

            await asyncio.gather(*(query(lib) for lib in pending))

    items = []
    for lib in libraries:
        checked = lib in pending
        local = (
            wc_js_libs.local_vulnerabilities(lib["name"], lib["version"])
            if lib["version"] and lib["name"] in wc_js_libs.KNOWN_PACKAGES
            else []
        )
        osv = osv_results.get((lib["name"], lib["version"]), [])
        vulns = _merge(osv, local)
        items.append(
            {
                **lib,
                "checked": checked and (lib["name"], lib["version"]) in osv_results,
                "vulnerabilities": vulns,
                "severity": _highest(vulns) or "ok",
            }
        )

    vulnerable = [i for i in items if i["vulnerabilities"]]
    # Toutes les requêtes OSV ont échoué : la table locale a répondu, le service est dit indisponible.
    osv_available = not (pending and len(errors) == len(pending))
    return {
        "measured": True,
        "error": None,
        "url": home.url,
        "libraries": items,
        "library_count": len(items),
        "vulnerable_count": len(vulnerable),
        "highest_severity": _highest([v for i in vulnerable for v in i["vulnerabilities"]]) or "ok",
        "risky_cdns": page["risky_cdns"],
        # Champ conservé pour la compatibilité des résultats enregistrés.
        "polyfill_detected": any(r["host"].endswith("polyfill.io") for r in page["risky_cdns"]),
        "sri_missing": page["sri_missing"],
        "sri_missing_count": len(page["sri_missing"]),
        "sri_checked": page["sri_checked"],
        "scripts_total": page["scripts_total"],
        "styles_total": page["styles_total"],
        "osv": {
            "available": osv_available,
            "queried": len(pending),
            "failed": len(errors),
            "error": osv_error_message(errors[0]) if errors else None,
        },
        "truncated": home.truncated,
    }


# -----------------------------------------------------------------------------
# Constats et score
# -----------------------------------------------------------------------------


def _check_vulnerable(f: FindingInput):
    hits = []
    for lib in as_list(as_dict(f.data).get("libraries")):
        lib = as_dict(lib)
        vulns = [as_dict(v) for v in as_list(lib.get("vulnerabilities"))]
        level = _highest(vulns)
        if level is None:
            continue
        fixed = highest_version(v.get("fixed") for v in vulns)
        hits.append(
            hit(
                severity=level,
                name=str(lib.get("name")),
                version=str(lib.get("version")),
                count=len(vulns),
                cve=str(vulns[0].get("cve") or vulns[0].get("id") or ""),
                fixed=str(fixed) if fixed else "-",
            )
        )
    return hits or None


def _check_risky_cdn(f: FindingInput):
    hits = [
        hit(
            severity=str(as_dict(r).get("severity"))
            if as_dict(r).get("severity") in _SEVERITY_ORDER
            else "high",
            host=str(as_dict(r).get("host")),
        )
        for r in as_list(as_dict(f.data).get("risky_cdns"))
    ]
    return hits or None


def _check_sri_missing(f: FindingInput):
    missing = [as_dict(m) for m in as_list(as_dict(f.data).get("sri_missing"))]
    if not missing:
        return None
    scripts = [m for m in missing if m.get("kind") == "script"]
    hosts = sorted({str(m.get("host")) for m in missing})
    # Un script tiers sans SRI peut être remplacé par du code hostile : plus grave qu'une feuille de style.
    return hit(
        severity="medium" if scripts else "low",
        count=len(missing),
        scripts=len(scripts),
        hosts=hosts[:5],
    )


def _score(data: dict) -> Outcome:
    result = as_dict(data.get("js_dependencies"))
    level = result.get("highest_severity")
    if level == "critical" or result.get("risky_cdns"):
        points = 0
    else:
        points = {"high": 1, "medium": 2, "low": 4}.get(level, 5)
    if result.get("sri_missing_count"):
        points = min(points, 4)
    detail = msg(
        "js_dependencies.score_detail",
        vulnerable=result.get("vulnerable_count") or 0,
        sri=result.get("sri_missing_count") or 0,
    )
    return Outcome(points, detail, True)


SPEC = ModuleSpec(
    name="js_dependencies",
    family="web",
    category="passif",
    run=run,
    optional=True,
    timeout=60,
    order=215,
    findings=(
        FindingRule(code="finding.js_dependencies.vulnerable", severity="medium", check=_check_vulnerable),
        FindingRule(code="finding.js_dependencies.risky_cdn", severity="critical", check=_check_risky_cdn),
        FindingRule(code="finding.js_dependencies.sri_missing", severity="medium", check=_check_sri_missing),
    ),
    score_rules=(ScoreRule(criterion="js_dependencies", weight=5, evaluate=_score),),
)
