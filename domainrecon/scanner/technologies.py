# =============================================================================
# DomainRecon - Scanner : détection des technologies
# =============================================================================
# La détection repose sur des marqueurs structurels (URL des scripts et
# feuilles de style, attributs, identifiants, scripts en ligne) et non sur une
# simple mention dans le texte de la page. Côté en-têtes, un CDN ou un proxy
# inverse (Cloudflare, Fastly, Varnish) est classé comme tel, et non comme le
# serveur d'origine.
# =============================================================================

import re
from html.parser import HTMLParser

from ..i18n import msg
from .common import _http_client, logger
from .errors import ModuleError
from .http_utils import fetch_first

TECH_HEADER_SIGS = {
    "server": {
        "nginx": "Nginx",
        "apache": "Apache",
        "microsoft-iis": "Microsoft IIS",
        "cloudflare": "Cloudflare",
        "litespeed": "LiteSpeed",
        "openresty": "OpenResty",
        "caddy": "Caddy",
        "gunicorn": "Gunicorn",
        "envoy": "Envoy Proxy",
        "varnish": "Varnish Cache",
    },
    "x-powered-by": {
        "php": "PHP",
        "asp.net": "ASP.NET",
        "express": "Express.js",
        "next.js": "Next.js",
        "nuxt": "Nuxt.js",
        "flask": "Flask",
        "django": "Django",
    },
}

# Catégorie propre à une technologie repérée par l'en-tête Server (sinon
# « web_server ») : un CDN ou un proxy inverse n'est pas le serveur d'origine.
# Les catégories sont des clés, traduites par `_category`.
TECH_CATEGORIES = {
    "Cloudflare": "cdn",
    "Envoy Proxy": "reverse_proxy",
    "Varnish Cache": "reverse_proxy",
    "GitHub Pages": "hosting",
}

# Infrastructure repérée par ses propres en-têtes : (technologie, catégorie,
# {en-tête: sous-chaîne attendue ("" = présence)}) ; un seul suffit.
TECH_INFRA_SIGS = [
    ("Cloudflare", "cdn", {"cf-ray": "", "cf-cache-status": ""}),
    ("Fastly", "cdn", {"x-fastly-request-id": "", "x-served-by": "cache-"}),
    ("Varnish Cache", "reverse_proxy", {"via": "varnish", "x-varnish": ""}),
]


# Règles structurelles : (technologie, catégorie, marqueurs). Chaque marqueur
# est une expression régulière appliquée à :
# - "urls"   : attributs src/href de la page (en minuscules) ;
# - "inline" : contenu des scripts en ligne ;
# - "attrs"  : noms d'attributs HTML (correspondance complète) ;
# - "ids"    : identifiants d'éléments (correspondance complète).
TECH_BODY_SIGS = [
    ("WordPress", "cms", {"urls": r"/wp-(content|includes)/"}),
    ("Joomla", "cms", {"urls": r"/media/(jui|system/js)/"}),
    (
        "Drupal",
        "cms",
        {
            "urls": r"/sites/default/files/|/misc/drupal\.js|/core/misc/drupal",
            "inline": r"\bdrupalSettings\b|\bDrupal\.settings\b",
            "attrs": r"data-drupal-[a-z-]+",
        },
    ),
    ("Next.js", "js_framework", {"urls": r"/_next/static/", "ids": r"__next_data__|__next"}),
    ("Nuxt.js", "js_framework", {"urls": r"/_nuxt/", "inline": r"window\.__NUXT__", "ids": r"__nuxt"}),
    ("Gatsby", "generator", {"ids": r"___gatsby"}),
    (
        "Shopify",
        "ecommerce",
        {
            "urls": r"//cdn\.shopify\.com/|\.myshopify\.com/",
            "inline": r"\bShopify\.(theme|shop)\b",
        },
    ),
    ("WooCommerce", "ecommerce", {"urls": r"/wp-content/plugins/woocommerce/"}),
    ("jQuery", "js_library", {"urls": r"jquery([.-][\w.-]*)?\.js|/jquery@|/jquery/\d"}),
    (
        "Bootstrap",
        "css_framework",
        {"urls": r"bootstrap(?!-icons)([.-][\w.-]*)?\.(js|css)\b|/bootstrap@|/bootstrap/\d"},
    ),
    ("Tailwind CSS", "css_framework", {"urls": r"tailwindcss|cdn\.tailwindcss\.com"}),
    (
        "React",
        "js_framework",
        {
            "urls": r"react-dom([.@/-]|$)|/react@|react\.production(\.min)?\.js",
            "attrs": r"data-reactroot|data-reactid",
        },
    ),
    (
        "Vue.js",
        "js_framework",
        {
            "urls": r"/vue(\.runtime)?(\.global)?(\.prod)?(\.min)?\.js|/vue@",
            "attrs": r"data-v-[0-9a-f]{8}|data-v-app",
        },
    ),
    ("Angular", "js_framework", {"attrs": r"ng-version"}),
    ("AngularJS", "js_framework", {"attrs": r"ng-app|data-ng-app"}),
    (
        "Google Analytics",
        "analytics",
        {
            "urls": r"google-analytics\.com/(analytics|ga)\.js|googletagmanager\.com/gtag/js",
            "inline": r"\bga\(\s*['\"](create|send)['\"]|\bgtag\(\s*['\"]config['\"]",
        },
    ),
    (
        "Google Tag Manager",
        "tag_manager",
        {
            "urls": r"googletagmanager\.com/(gtm\.js|ns\.html)",
            "inline": r"googletagmanager\.com/gtm\.js",
        },
    ),
    ("Hotjar", "analytics", {"urls": r"static\.hotjar\.com/", "inline": r"_hjSettings|static\.hotjar\.com"}),
    ("Matomo", "analytics", {"urls": r"/(matomo|piwik)\.(js|php)", "inline": r"\b_paq\.push\("}),
    ("jsDelivr", "cdn", {"urls": r"//cdn\.jsdelivr\.net/"}),
    ("cdnjs", "cdn", {"urls": r"//cdnjs\.cloudflare\.com/"}),
]

_COMPILED_BODY_SIGS = [
    (name, category, {kind: re.compile(pattern, re.I) for kind, pattern in markers.items()})
    for name, category, markers in TECH_BODY_SIGS
]

# Taille maximale cumulée des scripts en ligne conservés pour l'analyse.
_INLINE_SCRIPT_LIMIT = 256 * 1024


class _PageFacts(HTMLParser):
    """Relève les marqueurs structurels d'une page HTML."""

    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.urls: list[str] = []
        self.attrs: set[str] = set()
        self.ids: set[str] = set()
        self.generators: list[str] = []
        self.inline: list[str] = []
        self._inline_size = 0
        self._in_script = False

    def handle_starttag(self, tag, attrs):
        values = {}
        for key, value in attrs:
            key = key.lower()
            values[key] = value or ""
            self.attrs.add(key)
        for key in ("src", "href"):
            if values.get(key):
                self.urls.append(values[key])
        if values.get("id"):
            self.ids.add(values["id"].lower())
        if tag == "meta" and values.get("name", "").strip().lower() == "generator":
            content = values.get("content", "").strip()
            if content:
                self.generators.append(content)
        self._in_script = tag == "script" and not values.get("src")

    def handle_endtag(self, tag):
        if tag == "script":
            self._in_script = False

    def handle_data(self, data):
        if self._in_script and self._inline_size < _INLINE_SCRIPT_LIMIT:
            self.inline.append(data)
            self._inline_size += len(data)


def _category(key: str) -> dict:
    """Catégorie d'une technologie, sous forme de message traduisible."""
    categories = {
        "analytics": msg("tech.cat_analytics"),
        "cdn": msg("tech.cat_cdn"),
        "cms": msg("tech.cat_cms"),
        "css_framework": msg("tech.cat_css_framework"),
        "ecommerce": msg("tech.cat_ecommerce"),
        "framework": msg("tech.cat_framework"),
        "generator": msg("tech.cat_generator"),
        "hosting": msg("tech.cat_hosting"),
        "js_framework": msg("tech.cat_js_framework"),
        "js_library": msg("tech.cat_js_library"),
        "reverse_proxy": msg("tech.cat_reverse_proxy"),
        "tag_manager": msg("tech.cat_tag_manager"),
        "web_server": msg("tech.cat_web_server"),
    }
    return categories[key]


def analyze_page(headers_list, body: str) -> list:
    """Détecte les technologies d'après des en-têtes et un corps HTML (sans réseau).

    `headers_list` : en-têtes de chaque réponse du site (redirections comprises).
    Chaque technologie est {"name": nom, "category": message `tech.cat_*`}.
    """
    technologies = []
    seen = set()

    def add_tech(name: str, category: str):
        key = name.lower()
        if name and key not in seen:
            seen.add(key)
            technologies.append({"name": name, "category": _category(category)})

    # --- En-têtes ---
    for headers in headers_list:
        for header_name, signatures in TECH_HEADER_SIGS.items():
            raw_value = headers.get(header_name, "")
            value = raw_value.lower()
            if not value:
                continue
            category = "web_server" if header_name == "server" else "framework"
            matched = [tech for sig, tech in signatures.items() if sig in value]
            if header_name == "server" and "github.com" in value and headers.get("x-fastly-request-id"):
                # GitHub Pages : « Server: GitHub.com » servi par Fastly
                # (github.com lui-même ne passe pas par Fastly).
                matched.append("GitHub Pages")
            for tech in matched:
                add_tech(tech, TECH_CATEGORIES.get(tech, category))
            if not matched:
                add_tech(raw_value.strip(), category)
        for name, category, sigs in TECH_INFRA_SIGS:
            if any(
                headers.get(key) is not None and expected in headers.get(key, "").lower()
                for key, expected in sigs.items()
            ):
                add_tech(name, category)

    # --- Corps ---
    facts = _PageFacts()
    try:
        facts.feed(body)
        facts.close()
    except Exception as e:  # HTML très mal formé : on garde ce qui a été relevé
        logger.debug("Analyse HTML incomplète: %s", e)

    urls = "\n".join(facts.urls).lower()
    inline = "".join(facts.inline)

    for generator in facts.generators:
        add_tech(generator, "generator")

    for name, category, markers in _COMPILED_BODY_SIGS:
        if (
            ("urls" in markers and markers["urls"].search(urls))
            or ("inline" in markers and markers["inline"].search(inline))
            or ("attrs" in markers and any(markers["attrs"].fullmatch(a) for a in facts.attrs))
            or ("ids" in markers and any(markers["ids"].fullmatch(i) for i in facts.ids))
        ):
            add_tech(name, category)

    return technologies


# =============================================================================
# Module 8 : Technology Detection
# =============================================================================


async def detect_technologies(domain: str) -> list:
    """Détecte les technologies utilisées par un site web.

    Seules les réponses du site ciblé sont analysées (une redirection vers un
    autre site n'est pas suivie). Lève ModuleError si le site ne répond ni en
    HTTPS ni en HTTP.
    """
    async with _http_client(timeout=10.0) as client:
        fetched, error = await fetch_first(client, domain)

    if fetched is None:
        raise ModuleError(error)

    return analyze_page([r.headers for r in fetched.responses], fetched.text)
