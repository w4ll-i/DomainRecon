# =============================================================================
# DomainRecon - Contenu web : domaines liés à la page (sans réseau)
# =============================================================================
# Logique du module linked_domains : cartographie des domaines externes que la
# page référence (scripts, feuilles de style, images, cadres, formulaires, liens),
# classés en CDN, réseaux sociaux, mesure d'audience et publicité, paiement,
# polices, médias et cartes.
#
# Pièges évités :
#   - filtre `endswith(domaine)` : « evilexample.com » était pris pour un domaine
#     du site « example.com » (et donc ignoré) ; `domain in ref`, pour
#     « example.com.attaquant.net » ; ici : domaine enregistrable selon la liste
#     des suffixes publics (http_utils.same_site) ;
#   - classification par SOUS-CHAÎNE (« cdn » dans « cdnexample.org », « x.com »
#     dans « netflix.com ») : ici, suffixe de domaine entier, ou premier libellé
#     exact (cdn., static., assets…) pour les CDN propres à un site ;
#   - le protocole relatif (//cdn.exemple.net/a.js) et les domaines en majuscules
#     ne sont plus ignorés ; les ressources en http:// sur une page https
#     (contenu mixte) sont comptées.
# =============================================================================

from ..http_utils import host_of_url, same_site, site_of
from .wc_html_facts import PageFacts
from .wc_js_libs import risky_cdn

MAX_DOMAINS = 60

# Suffixe de domaine -> catégorie (message `linked_domains.cat_<clé>`). Le plus long suffixe l'emporte.
_CATEGORY_SUFFIXES = {
    "cdn": (
        "cdnjs.cloudflare.com",
        "cdn.jsdelivr.net",
        "unpkg.com",
        "ajax.googleapis.com",
        "code.jquery.com",
        "bootstrapcdn.com",
        "cloudfront.net",
        "fastly.net",
        "fastlylb.net",
        "akamaihd.net",
        "akamaized.net",
        "azureedge.net",
        "b-cdn.net",
        "cdn.shopify.com",
        "stackpathcdn.com",
        "edgecastcdn.net",
        "cdn77.org",
        "keycdn.com",
        "jsdelivr.net",
        "staticfile.org",
        "bootcdn.net",
    ),
    "social": (
        "twitter.com",
        "x.com",
        "facebook.com",
        "fb.com",
        "linkedin.com",
        "instagram.com",
        "youtube.com",
        "youtu.be",
        "github.com",
        "t.me",
        "telegram.org",
        "tiktok.com",
        "reddit.com",
        "discord.com",
        "discord.gg",
        "pinterest.com",
        "whatsapp.com",
        "snapchat.com",
        "threads.net",
        "mastodon.social",
        "bsky.app",
    ),
    "analytics": (
        "google-analytics.com",
        "googletagmanager.com",
        "doubleclick.net",
        "googleadservices.com",
        "googlesyndication.com",
        "hotjar.com",
        "hotjar.io",
        "segment.io",
        "segment.com",
        "mixpanel.com",
        "mxpnl.com",
        "amplitude.com",
        "heapanalytics.com",
        "fullstory.com",
        "logrocket.io",
        "logrocket.com",
        "lr-ingest.io",
        "clarity.ms",
        "connect.facebook.net",
        "licdn.com",
        "ads-twitter.com",
        "analytics.tiktok.com",
        "matomo.cloud",
        "plausible.io",
        "quantserve.com",
        "scorecardresearch.com",
        "criteo.com",
        "criteo.net",
        "taboola.com",
        "outbrain.com",
        "adsrvr.org",
        "hs-scripts.com",
        "hs-analytics.net",
        "hsforms.net",
        "newrelic.com",
        "nr-data.net",
        "sentry.io",
        "sentry-cdn.com",
        "cloudflareinsights.com",
        "adobedtm.com",
        "demdex.net",
    ),
    "payment": (
        "stripe.com",
        "stripe.network",
        "paypal.com",
        "paypalobjects.com",
        "braintreegateway.com",
        "adyen.com",
        "klarna.com",
        "squareup.com",
    ),
    "font": ("fonts.googleapis.com", "fonts.gstatic.com", "typekit.net", "fontawesome.com", "fonts.net"),
    "media": (
        "youtube-nocookie.com",
        "vimeo.com",
        "vimeocdn.com",
        "ytimg.com",
        "soundcloud.com",
        "spotify.com",
        "twitch.tv",
    ),
    "maps": ("maps.googleapis.com", "maps.google.com", "mapbox.com", "openstreetmap.org"),
}
# Premiers libellés qui désignent, chez un tiers, un hôte de ressources statiques.
_CDN_LABELS = frozenset({"cdn", "static", "assets", "media", "img", "images", "js", "css", "fonts"})

_SUFFIX_TABLE = sorted(
    ((suffix, key) for key, suffixes in _CATEGORY_SUFFIXES.items() for suffix in suffixes),
    key=lambda item: -len(item[0]),
)
CATEGORY_KEYS = ("analytics", "cdn", "font", "maps", "media", "payment", "social")


def classify(host: str) -> str | None:
    """Catégorie d'un hôte tiers (suffixe de domaine entier), ou None."""
    for suffix, key in _SUFFIX_TABLE:
        if host == suffix or host.endswith("." + suffix):
            return key
    if host.split(".", 1)[0] in _CDN_LABELS:
        return "cdn"
    return None


def analyze(html: str, page_url: str, site: str) -> dict:
    """Domaines liés d'une page : tiers (groupés par domaine enregistrable), CDN, réseaux sociaux, traceurs."""
    facts = PageFacts.parse(html or "", page_url)
    https_page = page_url.lower().startswith("https://")

    own_hosts: dict[str, None] = {}
    groups: dict[str, dict] = {}
    for url in facts.resolved_urls():
        host = host_of_url(url)
        if not host:
            continue
        if same_site(host, site):
            own_hosts.setdefault(host, None)
            continue
        domain = site_of(host)
        group = groups.setdefault(
            domain, {"domain": domain, "hosts": {}, "references": 0, "category": None, "risky": None}
        )
        group["hosts"].setdefault(host, None)
        group["references"] += 1
        category = classify(host)
        if category and group["category"] is None:
            group["category"] = category
        severity = risky_cdn(host)
        if severity:
            group["risky"] = severity

    script_hosts = {host_of_url(u) for s in facts.scripts if (u := facts.resolve(s["src"]))}
    third_party_scripts = sorted(h for h in script_hosts if h and not same_site(h, site))

    mixed = []
    if https_page:
        for script in facts.scripts:
            url = facts.resolve(script["src"])
            if url and url.lower().startswith("http://"):
                mixed.append({"url": url[:200], "kind": "script"})
        for link in facts.links:
            url = facts.resolve(link["href"]) if "stylesheet" in link["rel"].split() else None
            if url and url.lower().startswith("http://"):
                mixed.append({"url": url[:200], "kind": "style"})

    domains = sorted(groups.values(), key=lambda g: (-g["references"], g["domain"]))
    result_domains = [
        {
            "domain": g["domain"],
            "hosts": list(g["hosts"])[:5],
            "references": g["references"],
            "category": g["category"],
            "risky": g["risky"],
        }
        for g in domains[:MAX_DOMAINS]
    ]

    def of(category: str) -> list[str]:
        return [g["domain"] for g in domains if g["category"] == category][:20]

    return {
        "external_count": len(groups),
        "external_domains": result_domains,
        "cdn_domains": of("cdn"),
        "social_media": of("social"),
        "analytics_trackers": of("analytics"),
        "payment_domains": of("payment"),
        "third_party_scripts": third_party_scripts[:30],
        "own_hosts": list(own_hosts)[:20],
        "mixed_content": mixed[:20],
        "risky_domains": [g["domain"] for g in domains if g["risky"]][:10],
    }
