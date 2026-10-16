# =============================================================================
# DomainRecon - Module « tech_stack » : pile technique détectée (catalogue étendu)
# =============================================================================
# Complète et dépasse le module historique « technologies » : 180 technologies
# et plus de 300 signaux pondérés (CMS, frameworks, bibliothèques, serveurs, CDN, hébergeurs,
# mesure d'audience, paiement, consentement…), avec NIVEAU DE CONFIANCE et VERSION
# quand la page ou les en-têtes la donnent. Signatures pondérées,
# bibliothèques CSS/JS et marqueurs structurels (jamais une simple mention dans le texte).
# Voir impl/wc_tech_catalog.py pour la méthode et les défauts corrigés.
#
# Source : la page d'accueil partagée du scan (ScanContext.homepage) : aucune
# requête de plus vers la cible. Passif.
#
# Constats : version de logiciel divulguée par un en-tête (Server, X-Powered-By…)
# et logiciel en fin de vie. Critère de score : « tech_stack » (3 points).
# =============================================================================

from ...i18n import msg
from ..impl import wc_tech_catalog, wc_versions
from ..impl.wc_runtime import require_homepage
from ..registry import ModuleSpec, ScanContext
from ..rules import FindingInput, FindingRule, Outcome, ScoreRule, hit
from ..score import as_dict, as_list

# Logiciels dont les versions antérieures ne reçoivent plus de correctifs (état d'octobre 2026) :
# nom -> première version encore prise en charge. AngularJS : fin de vie complète (janvier 2022).
END_OF_LIFE = {
    "PHP": "8.2",
    "AngularJS": "99999",
    "Drupal": "10",
    "Joomla": "5",
    "Bootstrap": "5",
    "Apache HTTP Server": "2.4",
    "Microsoft IIS": "10",
}

# En-têtes dont la valeur divulgue le logiciel et sa version (signal « h:… » du catalogue).
_HEADER_EVIDENCE = (
    "h:server",
    "h:x-powered-by",
    "h:x-aspnet-version",
    "h:x-aspnetmvc-version",
    "h:x-generator",
)


def _category(key: str) -> dict:
    """Catégorie d'une technologie, sous forme de message traduisible."""
    categories = {
        "advertising": msg("tech_stack.cat_advertising"),
        "analytics": msg("tech_stack.cat_analytics"),
        "backend_framework": msg("tech_stack.cat_backend_framework"),
        "builder": msg("tech_stack.cat_builder"),
        "cdn": msg("tech_stack.cat_cdn"),
        "cms": msg("tech_stack.cat_cms"),
        "consent": msg("tech_stack.cat_consent"),
        "css_framework": msg("tech_stack.cat_css_framework"),
        "ecommerce": msg("tech_stack.cat_ecommerce"),
        "font": msg("tech_stack.cat_font"),
        "generator": msg("tech_stack.cat_generator"),
        "hosting": msg("tech_stack.cat_hosting"),
        "js_framework": msg("tech_stack.cat_js_framework"),
        "js_library": msg("tech_stack.cat_js_library"),
        "language": msg("tech_stack.cat_language"),
        "maps": msg("tech_stack.cat_maps"),
        "marketing": msg("tech_stack.cat_marketing"),
        "media": msg("tech_stack.cat_media"),
        "monitoring": msg("tech_stack.cat_monitoring"),
        "payment": msg("tech_stack.cat_payment"),
        "plugin": msg("tech_stack.cat_plugin"),
        "reverse_proxy": msg("tech_stack.cat_reverse_proxy"),
        "security": msg("tech_stack.cat_security"),
        "support": msg("tech_stack.cat_support"),
        "tag_manager": msg("tech_stack.cat_tag_manager"),
        "web_server": msg("tech_stack.cat_web_server"),
    }
    return categories.get(key) or categories["generator"]


async def run(context: ScanContext) -> dict:
    home = await require_homepage(context)
    detected = wc_tech_catalog.analyze(home.headers, home.text, home.url or "")
    technologies = [{**item, "category": _category(item["category_key"])} for item in detected]
    return {
        "measured": True,
        "error": None,
        "url": home.url,
        "technologies": technologies,
        "count": len(technologies),
        "with_version": sum(1 for t in technologies if t["version"]),
        "truncated": home.truncated,
    }


# -----------------------------------------------------------------------------
# Constats et score
# -----------------------------------------------------------------------------


def _items(f: FindingInput) -> list[dict]:
    data = as_dict(f.data)
    return [t for t in as_list(data.get("technologies")) if isinstance(t, dict)]


def _label(tech: dict) -> str:
    name = str(tech.get("name", "?"))
    return f"{name} {tech['version']}" if tech.get("version") else name


def _disclosed(technologies: list[dict]) -> list[dict]:
    """Technologies dont un en-tête HTTP annonce la version (informations utiles à un attaquant)."""
    return [
        t
        for t in technologies
        if t.get("version")
        and not t.get("implied")
        and any(e in _HEADER_EVIDENCE for e in as_list(t.get("evidence")))
    ]


def _end_of_life(technologies: list[dict]) -> list[tuple[dict, str]]:
    found = []
    for tech in technologies:
        supported = END_OF_LIFE.get(str(tech.get("name")))
        version = tech.get("version")
        if supported is None or not version or tech.get("confidence") == "low":
            continue
        if wc_versions.is_affected(version, None, supported) is True:
            found.append((tech, supported))
    return found


def _check_version_disclosed(f: FindingInput):
    items = _disclosed(_items(f))
    return {"items": [_label(t) for t in items], "count": len(items)} if items else None


def _check_end_of_life(f: FindingInput):
    found = _end_of_life(_items(f))
    if not found:
        return None
    return [
        hit(name=str(tech.get("name")), version=str(tech.get("version")), supported=supported)
        for tech, supported in found[:5]
    ]


def _score(data: dict) -> Outcome:
    technologies = [
        t for t in as_list(as_dict(data.get("tech_stack")).get("technologies")) if isinstance(t, dict)
    ]
    eol = _end_of_life(technologies)
    if eol:
        return Outcome(0, msg("tech_stack.score_eol", count=len(eol)), True)
    disclosed = _disclosed(technologies)
    if disclosed:
        return Outcome(2, msg("tech_stack.score_disclosed", count=len(disclosed)), True)
    return Outcome(3, msg("tech_stack.score_ok", count=len(technologies)), True)


SPEC = ModuleSpec(
    name="tech_stack",
    family="web",
    category="passif",
    run=run,
    quick=True,
    order=210,
    findings=(
        FindingRule(
            code="finding.tech_stack.version_disclosed", severity="low", check=_check_version_disclosed
        ),
        FindingRule(code="finding.tech_stack.end_of_life", severity="medium", check=_check_end_of_life),
    ),
    score_rules=(ScoreRule(criterion="tech_stack", weight=3, evaluate=_score),),
)
