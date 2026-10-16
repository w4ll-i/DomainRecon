# =============================================================================
# DomainRecon - Module « linked_domains » : domaines externes liés à la page
# =============================================================================
# Cartographie les domaines que la page d'accueil référence (scripts, feuilles de
# style, images, cadres, formulaires, liens) : CDN, réseaux sociaux, mesure d'audience
# et publicité, paiement, polices, médias. FILTRE STRICT : un domaine
# tiers comme « evilexample.com » n'est pas pris pour le site « example.com » (un
# simple `endswith` l'exclurait), et la classification se fait par suffixe de
# domaine entier, non par sous-chaîne. Voir impl/wc_linked.py.
#
# Source : la page d'accueil partagée du scan (aucune requête de plus). Passif.
# Constats : ressources actives chargées en http:// sur une page https (contenu mixte),
# nombre élevé de traceurs tiers.
# =============================================================================

from ...i18n import msg
from ..impl import wc_linked
from ..impl.wc_runtime import require_homepage
from ..registry import ModuleSpec, ScanContext
from ..rules import FindingInput, FindingRule
from ..score import as_dict, as_list

# Au-delà de ce nombre de domaines de mesure d'audience / publicité, la page est signalée.
TRACKER_THRESHOLD = 5


def _category(key: str | None) -> dict | None:
    """Catégorie d'un domaine tiers, sous forme de message traduisible."""
    categories = {
        "analytics": msg("linked_domains.cat_analytics"),
        "cdn": msg("linked_domains.cat_cdn"),
        "font": msg("linked_domains.cat_font"),
        "maps": msg("linked_domains.cat_maps"),
        "media": msg("linked_domains.cat_media"),
        "payment": msg("linked_domains.cat_payment"),
        "social": msg("linked_domains.cat_social"),
    }
    return categories.get(key) if key else None


async def run(context: ScanContext) -> dict:
    home = await require_homepage(context)
    linked = wc_linked.analyze(home.text, home.url or "", context.site)
    for entry in linked["external_domains"]:
        entry["category_key"] = entry["category"]
        entry["category"] = _category(entry["category"])
    return {"measured": True, "error": None, "url": home.url, "truncated": home.truncated, **linked}


def _check_mixed_content(f: FindingInput):
    found = as_list(as_dict(f.data).get("mixed_content"))
    return {"count": len(found), "example": str(as_dict(found[0]).get("url", ""))} if found else None


def _check_trackers(f: FindingInput):
    trackers = [t for t in as_list(as_dict(f.data).get("analytics_trackers")) if isinstance(t, str)]
    return {"count": len(trackers)} if len(trackers) >= TRACKER_THRESHOLD else None


SPEC = ModuleSpec(
    name="linked_domains",
    family="web",
    category="passif",
    run=run,
    order=213,
    findings=(
        FindingRule(
            code="finding.linked_domains.mixed_content", severity="medium", check=_check_mixed_content
        ),
        FindingRule(code="finding.linked_domains.trackers", severity="low", check=_check_trackers),
    ),
)
