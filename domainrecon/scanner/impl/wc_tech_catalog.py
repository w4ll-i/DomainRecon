# =============================================================================
# DomainRecon - Contenu web : catalogue de signatures des technologies
# =============================================================================
# Fusion de trois sources :
#   - le moteur actuel (scanner/technologies.py) : marqueurs STRUCTURELS (URL des
#     scripts, attributs, identifiants, scripts en ligne), jamais une simple
#     mention dans le texte ; un CDN ou un proxy n'est pas le serveur d'origine ;
#   - signatures pondérées, niveau de confiance
#     (score >= 5 élevé, >= 3 moyen, sinon faible), CMS et frameworks plus nombreux ;
#   - bibliothèques CSS/JS, support, suivi.
#
# Pièges évités (mesurés sur cloudflare.com) : les mots
# « magento », « shopify », « sentry », « cloudflare » ou « foundation » dans le
# TEXTE d'une page ne signalent plus la technologie ; « cdnjs.cloudflare.com »
# n'est plus pris pour Cloudflare.
#
# Chaque signature : (nom, catégorie, signaux, déduit_de, exige). Un signal :
# (type, expression, poids). Poids 3 : preuve forte ; 1 à 2 : indice ; 0 : sert
# seulement à lire la version (groupe nommé `v`). Une technologie est retenue à
# 2 points ou plus. Types de signaux :
#   h:<en-tête>   valeur d'un en-tête de réponse (noms en minuscules)
#   cookie        nom d'un cookie posé          url     adresses référencées
#   inline        scripts en ligne              attr    nom d'attribut (entier)
#   attrval:<a>   valeur d'un attribut          id      identifiant (entier)
#   class         classe CSS (entière)          name    nom de champ (entier)
#   meta:<nom>    contenu d'une balise <meta>   html    code HTML brut
# =============================================================================

import re

from .wc_html_facts import PageFacts
from .wc_versions import clean_version

V = r"(?P<v>\d+(?:\.\d+){0,3})"

# Catégories (clés) ; leur libellé est le message `tech_stack.cat_<clé>`.
CATEGORIES = (
    "advertising",
    "analytics",
    "backend_framework",
    "builder",
    "cdn",
    "cms",
    "consent",
    "css_framework",
    "ecommerce",
    "font",
    "generator",
    "hosting",
    "js_framework",
    "js_library",
    "language",
    "maps",
    "marketing",
    "media",
    "monitoring",
    "payment",
    "plugin",
    "reverse_proxy",
    "security",
    "support",
    "tag_manager",
    "web_server",
)


def _sig(name, category, *signals, implies=(), requires=()):
    return (name, category, tuple(signals), tuple(implies), tuple(requires))


# fmt: off
SIGNATURES = [
    # --- CMS, générateurs et constructeurs de sites ---------------------------
    _sig("WordPress", "cms",
         ("url", r"/wp-(?:content|includes)/", 3),
         ("meta:generator", rf"^wordpress(?:\s+{V})?", 3),
         ("html", r"<link[^>]+rel=[\"']https://api\.w\.org/", 3),
         ("h:link", r"rel=\"https://api\.w\.org/\"", 3),
         ("url", r"/wp-json/", 2),
         ("cookie", r"^(?:wordpress_|wp-settings-|wordpress_logged_in)", 2),
         ("url", rf"wp-emoji-release\.min\.js\?ver={V}", 0)),
    _sig("WooCommerce", "ecommerce",
         ("url", r"/plugins/woocommerce/", 3),
         ("meta:generator", rf"^woocommerce\s+{V}", 3),
         ("class", r"woocommerce(?:-[a-z0-9-]+)?", 2),
         ("url", rf"/plugins/woocommerce/\S*?[?&]ver={V}", 0),
         implies=("WordPress",)),
    _sig("Drupal", "cms",
         ("h:x-generator", rf"^drupal(?:\s+{V})?", 3),
         ("h:x-drupal-cache", "", 3),
         ("h:x-drupal-dynamic-cache", "", 3),
         ("url", r"/sites/(?:default|all)/(?:files|modules|themes)/|/core/misc/drupal|/misc/drupal\.js", 3),
         ("inline", r"\bdrupalSettings\b|\bDrupal\.settings\b", 3),
         ("attr", r"data-drupal-[a-z-]+", 2),
         ("meta:generator", rf"^drupal(?:\s+{V})?", 3),
         implies=("PHP",)),
    _sig("Joomla", "cms",
         ("meta:generator", rf"^joomla!?(?:\s*-?\s*{V})?", 3),
         ("url", r"/media/(?:jui|system)/(?:js|css)/|/components/com_[a-z0-9_]+/", 3),
         ("h:x-content-encoded-by", r"joomla", 3),
         implies=("PHP",)),
    _sig("Magento", "ecommerce",
         ("url", r"/(?:skin/frontend|static/(?:version\d+/)?frontend|media/catalog/product)/", 3),
         ("cookie", r"^(?:mage-cache-sessid|mage-cache-storage|form_key)$", 2),
         ("attr", r"data-mage-init", 3),
         ("inline", r"\bMage\.Cookies\b|\"mage/[a-z]+", 2),
         implies=("PHP",)),
    _sig("TYPO3", "cms",
         ("meta:generator", rf"^typo3(?:\s+cms)?(?:\s+{V})?", 3),
         ("url", r"/typo3(?:conf|temp)/", 3),
         implies=("PHP",)),
    _sig("PrestaShop", "ecommerce",
         ("meta:generator", r"^prestashop", 3),
         ("inline", r"\bvar prestashop\b|\bprestashop\s*=\s*\{", 3),
         ("cookie", r"^prestashop-", 3),
         ("url", r"/modules/ps_[a-z_]+/", 2),
         implies=("PHP",)),
    _sig("OpenCart", "ecommerce",
         ("url", r"catalog/view/(?:theme|javascript)/", 3),
         ("cookie", r"^ocsessid$", 3),
         implies=("PHP",)),
    _sig("Ghost", "cms",
         ("meta:generator", rf"^ghost(?:\s+{V})?", 3),
         ("h:x-ghost-cache-status", "", 3),
         implies=("Node.js",)),
    _sig("Contao", "cms", ("meta:generator", r"^contao", 3), implies=("PHP",)),
    _sig("Craft CMS", "cms",
         ("h:x-powered-by", r"^craft cms", 3),
         ("cookie", r"^craftsessionid$", 3),
         implies=("PHP",)),
    _sig("MediaWiki", "cms",
         ("meta:generator", rf"^mediawiki(?:\s+{V})?", 3),
         ("inline", r"\bmw\.config\b|\bRLCONF\b", 3),
         implies=("PHP",)),
    _sig("Squarespace", "builder",
         ("meta:generator", r"squarespace", 3),
         ("url", r"static\d*\.squarespace\.com|squarespace-cdn\.com", 3),
         ("h:server", r"^squarespace", 3)),
    _sig("Wix", "builder",
         ("meta:generator", r"^wix\.com", 3),
         ("url", r"static\.parastorage\.com|static\.wixstatic\.com", 3),
         ("h:x-wix-request-id", "", 3)),
    _sig("Webflow", "builder",
         ("meta:generator", r"^webflow", 3),
         ("attr", r"data-wf-(?:page|site)", 3)),
    _sig("Weebly", "builder", ("url", r"cdn\d*\.editmysite\.com|//[a-z0-9-]+\.weebly\.com/", 3)),
    _sig("Shopify", "ecommerce",
         ("url", r"//cdn\.shopify\.com/|\.myshopify\.com/", 3),
         ("inline", r"\bShopify\.(?:theme|shop|routes)\b", 3),
         ("h:x-shopid", "", 3),
         ("h:x-shopify-stage", "", 3),
         ("cookie", r"^_shopify_", 2)),
    _sig("BigCommerce", "ecommerce", ("url", r"cdn\d*\.bigcommerce\.com", 3)),
    _sig("Gatsby", "generator",
         ("id", r"___gatsby", 3),
         ("meta:generator", rf"^gatsby(?:\s+{V})?", 3),
         implies=("React",)),
    _sig("Hugo", "generator", ("meta:generator", rf"^hugo(?:\s+{V})?", 3)),
    _sig("Jekyll", "generator", ("meta:generator", rf"^jekyll(?:\s+v?{V})?", 3)),
    _sig("Hexo", "generator", ("meta:generator", rf"^hexo(?:\s+{V})?", 3)),
    _sig("Docusaurus", "generator", ("meta:generator", rf"^docusaurus(?:\s+v?{V})?", 3), implies=("React",)),
    _sig("Astro", "generator",
         ("meta:generator", rf"^astro(?:\s+v?{V})?", 3),
         ("attr", r"data-astro-cid-[a-z0-9]+", 3)),
    # --- Extensions et thèmes WordPress ---------------------------------------
    _sig("Elementor", "plugin",
         ("url", r"/plugins/elementor/", 3),
         ("class", r"elementor(?:-[a-z0-9_-]+)?", 3),
         ("meta:generator", rf"^elementor\s+{V}", 3),
         ("url", rf"/plugins/elementor/\S*?[?&]ver={V}", 0),
         implies=("WordPress",)),
    _sig("Yoast SEO", "plugin",
         ("html", rf"yoast seo(?: plugin)? v{V}", 3),
         implies=("WordPress",)),
    _sig("Contact Form 7", "plugin",
         ("url", r"/plugins/contact-form-7/", 3),
         ("class", r"wpcf7(?:-[a-z0-9-]+)?", 3),
         implies=("WordPress",)),
    _sig("Divi", "plugin",
         ("url", r"/themes/divi/", 3),
         ("class", r"et_pb_[a-z_]+", 3),
         implies=("WordPress",)),
    _sig("Slider Revolution", "plugin", ("url", r"/plugins/revslider/", 3), implies=("WordPress",)),
    _sig("Jetpack", "plugin", ("url", r"/plugins/jetpack/|stats\.wp\.com", 3), implies=("WordPress",)),
    _sig("WP Rocket", "plugin", ("html", r"performance optimized by wp rocket|wp rocket", 3), implies=("WordPress",)),
    # --- Serveurs web et proxys ----------------------------------------------------
    _sig("Nginx", "web_server", ("h:server", rf"^nginx(?:/{V})?", 3)),
    _sig("Apache HTTP Server", "web_server", ("h:server", rf"^apache(?!-coyote)(?:/{V})?", 3)),
    _sig("Microsoft IIS", "web_server", ("h:server", rf"^microsoft-iis(?:/{V})?", 3)),
    _sig("LiteSpeed", "web_server", ("h:server", r"^litespeed", 3), ("h:x-litespeed-cache", "", 3)),
    _sig("OpenResty", "web_server", ("h:server", rf"^openresty(?:/{V})?", 3)),
    _sig("Caddy", "web_server", ("h:server", r"^caddy", 3)),
    _sig("Lighttpd", "web_server", ("h:server", rf"^lighttpd(?:/{V})?", 3)),
    _sig("Gunicorn", "web_server", ("h:server", rf"^gunicorn(?:/{V})?", 3), implies=("Python",)),
    _sig("Uvicorn", "web_server", ("h:server", r"^uvicorn", 3), implies=("Python",)),
    _sig("Werkzeug", "backend_framework", ("h:server", rf"werkzeug(?:/{V})?", 3), implies=("Python",)),
    _sig("Kestrel", "web_server", ("h:server", r"^kestrel", 3), implies=("ASP.NET",)),
    _sig("Apache Tomcat", "web_server",
         ("h:server", r"^apache-coyote", 3),
         ("h:x-powered-by", rf"tomcat(?:/{V})?", 3),
         implies=("Java",)),
    _sig("Jetty", "web_server", ("h:server", r"^jetty(?:\(" + V + r"[^)]*\))?", 3), implies=("Java",)),
    _sig("Phusion Passenger", "web_server",
         ("h:x-powered-by", rf"phusion passenger(?:\s+{V})?", 3),
         ("h:server", rf"passenger(?:/{V})?", 3)),
    _sig("Envoy", "reverse_proxy", ("h:server", r"^envoy", 3)),
    _sig("Varnish", "reverse_proxy",
         ("h:x-varnish", "", 3), ("h:via", r"varnish", 2), ("h:server", r"^varnish", 3)),
    _sig("Apache Traffic Server", "reverse_proxy", ("h:server", r"^ats(?:/|$)|trafficserver", 3)),
    # --- Langages --------------------------------------------------------------------
    _sig("PHP", "language",
         ("h:x-powered-by", rf"^php(?:/{V})?", 3),
         ("cookie", r"^phpsessid$", 2),
         ("url", r"\.php(?:[?#\s]|$)", 1)),
    _sig("ASP.NET", "language",
         ("h:x-powered-by", r"^asp\.net", 3),
         ("h:x-aspnet-version", V, 3),
         ("h:x-aspnetmvc-version", "", 3),
         ("id", r"__viewstate|__eventvalidation", 3),
         ("cookie", r"^asp\.net_sessionid$", 3)),
    _sig("Java", "language",
         ("cookie", r"^jsessionid$", 2),
         ("h:x-powered-by", r"servlet|jsp", 3)),
    _sig("Python", "language"),
    _sig("Node.js", "language"),
    _sig("Ruby", "language"),
    # --- Frameworks applicatifs ----------------------------------------------------
    _sig("Express", "backend_framework", ("h:x-powered-by", r"^express", 3), implies=("Node.js",)),
    _sig("Laravel", "backend_framework",
         ("cookie", r"^laravel_session$", 3), ("cookie", r"^xsrf-token$", 1),
         implies=("PHP",)),
    _sig("Symfony", "backend_framework",
         ("h:x-debug-token", "", 3), ("cookie", r"^sf_redirect$", 3),
         ("h:x-powered-by", r"symfony", 3),
         implies=("PHP",)),
    _sig("Django", "backend_framework",
         ("cookie", r"^csrftoken$", 2), ("name", r"csrfmiddlewaretoken", 3),
         implies=("Python",)),
    _sig("Flask", "backend_framework", ("h:x-powered-by", r"^flask", 3), implies=("Python",)),
    _sig("Ruby on Rails", "backend_framework",
         ("meta:csrf-param", "", 3), ("h:x-runtime", r"^\d+\.\d+", 1),
         implies=("Ruby",)),
    _sig("Spring Boot", "backend_framework", ("h:x-application-context", "", 3), implies=("Java",)),
    # --- Frameworks JavaScript ---------------------------------------------------------
    _sig("Next.js", "js_framework",
         ("url", r"/_next/static/", 3),
         ("id", r"__next|__next_data__", 3),
         ("h:x-powered-by", rf"^next\.js(?:\s+{V})?", 3),
         ("h:x-nextjs-cache", "", 3), ("h:x-nextjs-matched-path", "", 3),
         implies=("React", "Node.js")),
    _sig("Nuxt.js", "js_framework",
         ("url", r"/_nuxt/", 3),
         ("inline", r"window\.__nuxt__", 3),
         ("id", r"__nuxt", 3),
         implies=("Vue.js",)),
    _sig("SvelteKit", "js_framework",
         ("url", r"/_app/immutable/", 3),
         ("attr", r"data-sveltekit-[a-z-]+", 3),
         implies=("Svelte",)),
    _sig("Remix", "js_framework", ("inline", r"window\.__remixcontext", 3), implies=("React",)),
    _sig("Angular", "js_framework",
         ("attr", r"ng-version", 3),
         ("attrval:ng-version", V, 0)),
    _sig("AngularJS", "js_framework",
         ("attr", r"ng-app|data-ng-app|ng-controller", 3),
         ("url", r"/angular(?:\.min)?\.js|angularjs[/@]", 2),
         ("url", rf"angular(?:js)?(?:\.js)?[/@-]{V}", 0)),
    _sig("React", "js_framework",
         ("attr", r"data-reactroot|data-reactid", 3),
         ("url", r"react-dom|/react@|react\.(?:production|development)(?:\.min)?\.js", 2),
         ("url", rf"/react(?:-dom)?[@/-]{V}", 0)),
    _sig("Vue.js", "js_framework",
         ("attr", r"data-v-[0-9a-f]{7,8}|data-v-app", 3),
         ("url", r"/vue(?:\.runtime)?(?:\.global)?(?:\.prod)?(?:\.min)?\.js|/vue@", 2),
         ("url", rf"/vue[@/-]{V}", 0)),
    _sig("Svelte", "js_framework", ("class", r"svelte-[a-z0-9]{5,8}", 3)),
    _sig("Ember.js", "js_framework", ("url", r"/ember(?:\.min|\.prod)?\.js|/ember@", 3), ("class", r"ember-(?:view|application)", 3)),
    _sig("Alpine.js", "js_framework",
         ("attr", r"x-data", 3), ("url", r"alpinejs|/alpine(?:\.min)?\.js", 3)),
    _sig("htmx", "js_library",
         ("attr", r"hx-(?:get|post|put|delete|trigger|target|swap|boost)", 3),
         ("url", r"htmx(?:\.org|\.min\.js|@)", 3),
         ("url", rf"htmx[\w.\-/]*?[@/]{V}", 0)),
    # --- Bibliothèques JavaScript ---------------------------------------------------
    _sig("jQuery", "js_library",
         ("url", r"/jquery(?:[.\-](?:slim|min|\d)[\w.\-]*)?\.js|/jquery@|/jquery/\d|/jquery-\d", 3),
         ("url", rf"jquery[.\-@/]{V}", 0),
         ("url", rf"jquery(?:\.min)?\.js\?ver={V}", 0)),
    _sig("jQuery UI", "js_library",
         ("url", r"jquery[.\-]ui|/jqueryui/", 3),
         ("url", rf"jquery[.\-]ui[\-.@/ ]{V}", 0),
         ("url", rf"jqueryui/{V}", 0)),
    _sig("Lodash", "js_library",
         ("url", r"/lodash(?:\.min|\.core)?\.js|/lodash@|/lodash\.js/", 3),
         ("url", rf"lodash(?:\.js)?[@/-]{V}", 0)),
    _sig("Moment.js", "js_library",
         ("url", r"/moment(?:\.min)?\.js|/moment@|moment-with-locales|/moment\.js/", 3),
         ("url", rf"moment(?:\.js)?[@/-]{V}", 0)),
    _sig("Axios", "js_library",
         ("url", r"/axios(?:\.min)?\.js|/axios@", 3), ("url", rf"axios[@/-]{V}", 0)),
    _sig("Underscore.js", "js_library",
         ("url", r"/underscore(?:-min|\.min)?\.js|/underscore@", 3),
         ("url", rf"underscore[@/-]{V}", 0)),
    _sig("Backbone.js", "js_library", ("url", r"/backbone(?:-min|\.min)?\.js|/backbone@", 3)),
    _sig("Handlebars", "js_library",
         ("url", r"/handlebars(?:\.min|\.runtime)?\.js|/handlebars@", 3),
         ("url", rf"handlebars[@/-]{V}", 0)),
    _sig("D3.js", "js_library", ("url", r"/d3(?:\.v\d+)?(?:\.min)?\.js|/d3@", 3)),
    _sig("Chart.js", "js_library",
         ("url", r"/chart(?:\.umd)?(?:\.min)?\.js|/chart\.js@|/chart\.js/", 3),
         ("url", rf"chart\.js[@/-]{V}", 0)),
    _sig("Three.js", "js_library", ("url", r"/three(?:\.module)?(?:\.min)?\.js|/three@", 3)),
    _sig("Leaflet", "maps", ("url", r"/leaflet(?:\.min)?\.(?:js|css)|/leaflet@", 3)),
    _sig("Swiper", "js_library", ("url", r"/swiper(?:-bundle)?(?:\.min)?\.(?:js|css)|/swiper@", 3)),
    _sig("Slick", "js_library", ("url", r"/slick(?:\.min)?\.(?:js|css)|/slick-carousel", 3)),
    _sig("GSAP", "js_library", ("url", r"/gsap(?:\.min)?\.js|/gsap@|tweenmax", 3)),
    _sig("Modernizr", "js_library", ("url", r"modernizr", 3)),
    _sig("Popper", "js_library", ("url", r"/popper(?:\.min)?\.js|@popperjs", 3)),
    _sig("DataTables", "js_library", ("url", r"datatables|jquery\.datatables", 3)),
    _sig("DOMPurify", "js_library", ("url", r"/purify(?:\.min)?\.js|dompurify", 3)),
    _sig("Highlight.js", "js_library", ("url", r"/highlight(?:\.min)?\.js|/highlight\.js@|highlightjs", 3)),
    # --- Cadres CSS et interface -----------------------------------------------------
    _sig("Bootstrap", "css_framework",
         ("url", r"bootstrap(?!-icons)(?:[.\-][\w.\-]*)?\.(?:js|css)\b|/bootstrap@|/bootstrap/\d", 3),
         ("url", rf"bootstrap[@/.\-]{V}", 0),
         ("class", r"col-(?:xs|sm|md|lg|xl|xxl)-\d{1,2}|navbar-expand(?:-(?:sm|md|lg|xl))?", 1)),
    _sig("Tailwind CSS", "css_framework",
         ("url", r"cdn\.tailwindcss\.com|/tailwind(?:css)?[.@/-]", 3),
         ("class", r"(?:sm|md|lg|xl|2xl|hover|focus|dark):[a-z][a-z0-9-]*", 3),
         ("url", rf"tailwindcss@{V}", 0)),
    _sig("Bulma", "css_framework", ("url", r"/bulma(?:\.min)?\.css|/bulma@", 3)),
    _sig("Foundation", "css_framework", ("url", r"/foundation(?:\.min)?\.(?:css|js)|/foundation-sites", 3)),
    _sig("Font Awesome", "font",
         ("url", r"font-?awesome|fontawesome|use\.fontawesome\.com|kit\.fontawesome\.com", 3),
         ("class", r"fa-[a-z0-9-]+", 2),
         ("url", rf"font-?awesome[/@-]?{V}", 0)),
    _sig("Material UI", "css_framework", ("class", r"mui[a-z]+-[a-z0-9]+", 3)),
    _sig("Google Fonts", "font", ("url", r"fonts\.googleapis\.com|fonts\.gstatic\.com", 3)),
    _sig("Adobe Fonts", "font", ("url", r"use\.typekit\.net", 3)),
    # --- Mesure d'audience, publicité, étiquettes ------------------------------------
    _sig("Google Analytics", "analytics",
         ("url", r"google-analytics\.com/(?:analytics|ga|urchin)\.js|googletagmanager\.com/gtag/js", 3),
         ("inline", r"\bga\(\s*['\"](?:create|send)['\"]|\bgtag\(\s*['\"]config['\"]", 3)),
    _sig("Google Tag Manager", "tag_manager",
         ("url", r"googletagmanager\.com/(?:gtm\.js|ns\.html)", 3),
         ("inline", r"googletagmanager\.com/gtm\.js|\bgtm\.start\b", 3)),
    _sig("Hotjar", "analytics", ("url", r"static\.hotjar\.com/", 3), ("inline", r"_hjSettings", 3)),
    _sig("Matomo", "analytics",
         ("url", r"/(?:matomo|piwik)\.(?:js|php)|cdn\.matomo\.cloud", 3),
         ("inline", r"\b_paq\.push\(", 3)),
    _sig("Mixpanel", "analytics",
         ("url", r"cdn\.mxpnl\.com|cdn\.mixpanel\.com|/mixpanel(?:\.min)?\.js", 3),
         ("inline", r"\bmixpanel\.init\(", 3)),
    _sig("Segment", "analytics",
         ("url", r"cdn\.segment\.(?:com|io)/analytics\.js", 3),
         ("inline", r"\banalytics\.load\(\s*['\"]", 2)),
    _sig("Amplitude", "analytics", ("url", r"cdn\.amplitude\.com", 3)),
    _sig("Plausible", "analytics", ("url", r"plausible\.io/js/", 3)),
    _sig("Fathom", "analytics", ("url", r"cdn\.usefathom\.com", 3)),
    _sig("Heap", "analytics", ("url", r"cdn\.heapanalytics\.com", 3)),
    _sig("FullStory", "analytics", ("url", r"fullstory\.com/s/fs\.js|edge\.fullstory\.com", 3)),
    _sig("Microsoft Clarity", "analytics", ("url", r"clarity\.ms/tag/", 3)),
    _sig("Cloudflare Web Analytics", "analytics", ("url", r"static\.cloudflareinsights\.com", 3)),
    _sig("Facebook Pixel", "advertising",
         ("url", r"connect\.facebook\.net/[^/\s]+/fbevents\.js", 3),
         ("inline", r"\bfbq\(\s*['\"]init", 3)),
    _sig("LinkedIn Insight", "advertising", ("url", r"snap\.licdn\.com/li\.lms-analytics", 3)),
    _sig("TikTok Pixel", "advertising", ("url", r"analytics\.tiktok\.com/i18n/pixel", 3)),
    _sig("X Pixel", "advertising", ("url", r"static\.ads-twitter\.com/uwt\.js", 3)),
    _sig("Pinterest Tag", "advertising", ("url", r"s\.pinimg\.com/ct/core\.js", 3)),
    _sig("Google Ads", "advertising", ("url", r"googleadservices\.com|doubleclick\.net", 3)),
    _sig("Google AdSense", "advertising", ("url", r"pagead2\.googlesyndication\.com/pagead/js/adsbygoogle\.js", 3)),
    _sig("Adobe Experience Platform Launch", "tag_manager", ("url", r"assets\.adobedtm\.com", 3)),
    # --- Support, marketing, supervision, paiement, sécurité ------------------------
    _sig("Intercom", "support",
         ("url", r"widget\.intercom\.io|js\.intercomcdn\.com", 3),
         ("inline", r"\bIntercom\(\s*['\"]boot", 3)),
    _sig("Zendesk", "support", ("url", r"static\.zdassets\.com|v2\.zopim\.com", 3)),
    _sig("Crisp", "support", ("url", r"client\.crisp\.chat", 3)),
    _sig("Drift", "support", ("url", r"js\.driftt\.com|js\.drift\.com", 3)),
    _sig("Tawk.to", "support", ("url", r"embed\.tawk\.to", 3)),
    _sig("LiveChat", "support", ("url", r"cdn\.livechatinc\.com", 3)),
    _sig("HubSpot", "marketing",
         ("url", r"js\.hs-scripts\.com|js\.hsforms\.net|js\.hs-analytics\.net|js\.usemessages\.com", 3),
         ("cookie", r"^hubspotutk$", 3)),
    _sig("Mailchimp", "marketing", ("url", r"chimpstatic\.com|list-manage\.com", 3)),
    _sig("Marketo", "marketing", ("url", r"munchkin\.marketo\.net|mktoforms2", 3)),
    _sig("Klaviyo", "marketing", ("url", r"static\.klaviyo\.com", 3)),
    _sig("Pardot", "marketing", ("url", r"pi\.pardot\.com", 3)),
    _sig("Sentry", "monitoring",
         ("url", r"browser\.sentry-cdn\.com|js\.sentry-cdn\.com|/sentry(?:\.bundle)?(?:\.min)?\.js", 3),
         ("inline", r"\bSentry\.init\(", 3)),
    _sig("Datadog RUM", "monitoring", ("url", r"datadoghq-browser-agent\.com", 3)),
    _sig("New Relic", "monitoring", ("url", r"js-agent\.newrelic\.com|bam\.nr-data\.net", 3), ("inline", r"\bNREUM\b", 3)),
    _sig("Bugsnag", "monitoring", ("url", r"bugsnag", 3)),
    _sig("Rollbar", "monitoring", ("url", r"cdn\.rollbar\.com", 3)),
    _sig("LogRocket", "monitoring", ("url", r"cdn\.lr-ingest\.io|cdn\.logrocket\.com", 3)),
    _sig("Stripe", "payment", ("url", r"js\.stripe\.com", 3)),
    _sig("PayPal", "payment", ("url", r"paypal\.com/sdk/js|paypalobjects\.com/api/checkout\.js", 3)),
    _sig("Braintree", "payment", ("url", r"js\.braintreegateway\.com", 3)),
    _sig("Adyen", "payment", ("url", r"checkoutshopper-(?:live|test)\.adyen\.com", 3)),
    _sig("Klarna", "payment", ("url", r"klarnacdn\.net", 3)),
    _sig("Square", "payment", ("url", r"web\.squarecdn\.com|js\.squareup\.com", 3)),
    _sig("reCAPTCHA", "security", ("url", r"google\.com/recaptcha/|gstatic\.com/recaptcha/|recaptcha\.net/recaptcha", 3)),
    _sig("hCaptcha", "security", ("url", r"hcaptcha\.com/1/api\.js|js\.hcaptcha\.com", 3)),
    _sig("Cloudflare Turnstile", "security", ("url", r"challenges\.cloudflare\.com/turnstile", 3)),
    _sig("OneTrust", "consent", ("url", r"cdn\.cookielaw\.org|onetrust\.com", 3)),
    _sig("Cookiebot", "consent", ("url", r"consent\.cookiebot\.com", 3)),
    _sig("Didomi", "consent", ("url", r"sdk\.privacy-center\.org|didomi\.io", 3)),
    _sig("Axeptio", "consent", ("url", r"static\.axept\.io", 3)),
    _sig("Tarteaucitron", "consent", ("url", r"tarteaucitron(?:\.min)?\.js", 3)),
    _sig("Osano", "consent", ("url", r"cmp\.osano\.com", 3)),
    _sig("Usercentrics", "consent", ("url", r"usercentrics\.eu/", 3)),
    _sig("YouTube", "media", ("url", r"youtube(?:-nocookie)?\.com/(?:embed|iframe_api)", 3)),
    _sig("Vimeo", "media", ("url", r"player\.vimeo\.com", 3)),
    _sig("Google Maps", "maps", ("url", r"maps\.googleapis\.com|maps\.google\.com/maps|google\.com/maps/embed", 3)),
    _sig("Mapbox", "maps", ("url", r"api\.mapbox\.com|mapbox-gl", 3)),
    # --- CDN et hébergeurs -------------------------------------------------------------
    _sig("Cloudflare", "cdn",
         ("h:cf-ray", "", 3), ("h:cf-cache-status", "", 3), ("h:server", r"^cloudflare", 3),
         ("cookie", r"^(?:__cf_bm|__cfduid)$", 1)),
    _sig("Amazon CloudFront", "cdn",
         ("h:x-amz-cf-id", "", 3), ("h:x-amz-cf-pop", "", 3),
         ("h:via", r"cloudfront", 3), ("h:server", r"^cloudfront", 3)),
    _sig("Fastly", "cdn",
         ("h:x-fastly-request-id", "", 3), ("h:fastly-debug-digest", "", 3),
         ("h:x-served-by", r"^cache-", 2), ("h:via", r"1\.1 varnish", 1)),
    _sig("Akamai", "cdn",
         ("h:x-akamai-transformed", "", 3), ("h:akamai-grn", "", 3),
         ("h:server", r"akamaighost|akamainetstorage", 3)),
    _sig("Azure Front Door", "cdn", ("h:x-azure-ref", "", 3), ("h:x-msedge-ref", "", 3)),
    _sig("Bunny CDN", "cdn", ("h:server", r"^bunnycdn", 3)),
    _sig("KeyCDN", "cdn", ("h:server", r"^keycdn-engine", 3)),
    _sig("jsDelivr", "cdn", ("url", r"//cdn\.jsdelivr\.net/", 3)),
    _sig("cdnjs", "cdn", ("url", r"//cdnjs\.cloudflare\.com/", 3)),
    _sig("unpkg", "cdn", ("url", r"//unpkg\.com/", 3)),
    _sig("Google Hosted Libraries", "cdn", ("url", r"ajax\.googleapis\.com/ajax/libs/", 3)),
    _sig("Vercel", "hosting", ("h:x-vercel-id", "", 3), ("h:x-vercel-cache", "", 3), ("h:server", r"^vercel", 3)),
    _sig("Netlify", "hosting", ("h:x-nf-request-id", "", 3), ("h:server", r"^netlify", 3)),
    _sig("Heroku", "hosting", ("h:via", r"vegur", 3)),
    # GitHub Pages : « Server: GitHub.com » servi derrière Fastly (github.com ne passe pas par Fastly).
    _sig("GitHub Pages", "hosting", ("h:server", r"^github\.com$", 3), requires=("Fastly",)),
    _sig("Amazon S3", "hosting", ("h:server", r"^amazons3$", 3), ("h:x-amz-request-id", "", 2), ("h:x-amz-id-2", "", 2)),
    _sig("Google Cloud", "hosting",
         ("h:x-cloud-trace-context", "", 3), ("h:server", r"^(?:google frontend|gse|esf|gws)$", 2),
         ("h:via", r"google", 1)),
    _sig("WP Engine", "hosting", ("h:x-powered-by", r"wp engine", 3), implies=("WordPress",)),
    _sig("Kinsta", "hosting", ("h:x-kinsta-cache", "", 3)),
    _sig("Pantheon", "hosting", ("h:x-pantheon-styx-hostname", "", 3)),
    _sig("Fly.io", "hosting", ("h:fly-request-id", "", 3)),
    _sig("Render", "hosting", ("h:x-render-origin-server", "", 3)),
]
# fmt: on

# Technologies dont la version mène à une base de vulnérabilités (OSV.dev) :
# nom -> (écosystème, paquet, bibliothèque_front). Une « bibliothèque front » est
# chargée par une balise <script>/<link> : le module js_dependencies s'en charge
# (avec SRI), tech_cves ne la traite pas pour ne pas doubler les constats.
OSV_PACKAGES: dict[str, tuple[str, str, bool]] = {
    "jQuery": ("npm", "jquery", True),
    "jQuery UI": ("npm", "jquery-ui", True),
    "Bootstrap": ("npm", "bootstrap", True),
    "AngularJS": ("npm", "angular", True),
    "Lodash": ("npm", "lodash", True),
    "Moment.js": ("npm", "moment", True),
    "Axios": ("npm", "axios", True),
    "Underscore.js": ("npm", "underscore", True),
    "Backbone.js": ("npm", "backbone", True),
    "Handlebars": ("npm", "handlebars", True),
    "D3.js": ("npm", "d3", True),
    "Chart.js": ("npm", "chart.js", True),
    "Three.js": ("npm", "three", True),
    "Leaflet": ("npm", "leaflet", True),
    "Swiper": ("npm", "swiper", True),
    "DOMPurify": ("npm", "dompurify", True),
    "Highlight.js": ("npm", "highlight.js", True),
    "htmx": ("npm", "htmx.org", True),
    "Font Awesome": ("npm", "@fortawesome/fontawesome-free", True),
    "Vue.js": ("npm", "vue", True),
    "React": ("npm", "react", True),
    "Angular": ("npm", "@angular/core", False),
    "Next.js": ("npm", "next", False),
    "Nuxt.js": ("npm", "nuxt", False),
    "Express": ("npm", "express", False),
    "Gatsby": ("npm", "gatsby", False),
    "Svelte": ("npm", "svelte", False),
    "Ghost": ("npm", "ghost", False),
    "Django": ("PyPI", "Django", False),
    "Flask": ("PyPI", "Flask", False),
    "Gunicorn": ("PyPI", "gunicorn", False),
    "Werkzeug": ("PyPI", "Werkzeug", False),
    "Laravel": ("Packagist", "laravel/framework", False),
    "Symfony": ("Packagist", "symfony/symfony", False),
    "Drupal": ("Packagist", "drupal/core", False),
    "Joomla": ("Packagist", "joomla/joomla-cms", False),
    "TYPO3": ("Packagist", "typo3/cms-core", False),
    "Magento": ("Packagist", "magento/community-edition", False),
    "PrestaShop": ("Packagist", "prestashop/prestashop", False),
    "Ruby on Rails": ("RubyGems", "actionpack", False),  # « rails » est un méta-paquet sans avis propre
}

# Catégories dont l'affichage de la version est utile mais qui n'ont pas de signal de version propre.
_FLAGS = re.I

_COMPILED = [
    (
        name,
        category,
        [(kind, re.compile(pattern, _FLAGS | re.M), weight) for kind, pattern, weight in signals],
        implies,
        requires,
    )
    for name, category, signals, implies, requires in SIGNATURES
]
_CATEGORY_OF = {name: category for name, category, *_ in SIGNATURES}

# Taille maximale de la valeur d'un en-tête brut conservée comme technologie inconnue.
_RAW_LIMIT = 60
_COOKIE_NAME_RE = re.compile(r"(?:^|,\s*)([A-Za-z0-9_.%\-]+)=")
_GENERATOR_VERSION_RE = re.compile(r"\s+v?(\d+(?:\.\d+){0,3})\s*$")


def _cookie_names(set_cookie: str) -> list[str]:
    return [name.lower() for name in _COOKIE_NAME_RE.findall(set_cookie or "")]


def confidence_of(score: int) -> str:
    """Niveau de confiance d'après la somme des poids : élevé (5+), moyen (3 à 4), faible."""
    return "high" if score >= 5 else "medium" if score >= 3 else "low"


def analyze(headers: dict[str, str], html: str, base_url: str = "") -> list[dict]:
    """Détecte les technologies d'une réponse (en-têtes en minuscules, corps HTML), sans réseau.

    Chaque technologie : {name, category_key, confidence, score, version, evidence, implied}.
    """
    headers = {str(k).lower(): str(v) for k, v in (headers or {}).items()}
    facts = PageFacts.parse(html or "", base_url)
    urls = "\n".join(
        [*facts.urls, *(s["src"] for s in facts.scripts), *(link["href"] for link in facts.links)]
    ).lower()
    inline = facts.inline_text
    cookies = _cookie_names(headers.get("set-cookie", ""))
    raw_html = html or ""

    def sources(kind: str):
        """Valeurs à tester pour un type de signal."""
        if kind.startswith("h:"):
            value = headers.get(kind[2:])
            return [] if value is None else [value]
        if kind.startswith("meta:"):
            value = facts.metas.get(kind[5:])
            return [] if value is None else [value]
        if kind.startswith("attrval:"):
            value = facts.attr_values.get(kind[8:])
            return [] if value is None else [value]
        return {
            "cookie": cookies,
            "url": [urls],
            "inline": [inline],
            "attr": sorted(facts.attr_names),
            "id": sorted(facts.ids),
            "class": sorted(facts.classes),
            "name": sorted(facts.input_names),
            "html": [raw_html],
        }.get(kind, [])

    whole_match = {"cookie", "attr", "id", "class", "name"}
    found: dict[str, dict] = {}
    matched_server = False
    for name, category, signals, implies, requires in _COMPILED:
        score = 0
        version = None
        evidence: list[str] = []
        for kind, pattern, weight in signals:
            hit_value = None
            for value in sources(kind):
                match = pattern.fullmatch(value) if kind in whole_match else pattern.search(value)
                if match:
                    hit_value = match
                    break
            if hit_value is None:
                continue
            if version is None and "v" in pattern.groupindex and hit_value.group("v"):
                version = clean_version(hit_value.group("v"))
            if weight:
                score += weight
                if kind not in evidence:
                    evidence.append(kind)
                if kind == "h:server":
                    matched_server = True
        if score >= 2:
            found[name] = {
                "name": name,
                "category_key": category,
                "confidence": confidence_of(score),
                "score": score,
                "version": version,
                "evidence": evidence[:4],
                "implied": False,
                "_implies": implies,
                "_requires": requires,
            }

    # Technologie exigeant la présence d'une autre (GitHub Pages derrière Fastly).
    for name in [n for n, item in found.items() if any(r not in found for r in item["_requires"])]:
        del found[name]

    # Technologies déduites (Next.js suppose React) : confiance faible, sauf si déjà détectées.
    for item in list(found.values()):
        for target in item["_implies"]:
            if target not in found:
                found[target] = {
                    "name": target,
                    "category_key": _CATEGORY_OF.get(target, "js_framework"),
                    "confidence": "low",
                    "score": 2,
                    "version": None,
                    "evidence": [f"implied:{item['name']}"],
                    "implied": True,
                    "_implies": (),
                    "_requires": (),
                }

    # Serveur ou langage non catalogué : relevé tel quel (comme le moteur actuel).
    server = headers.get("server", "").strip()
    if server and not matched_server and server.lower() not in {n.lower() for n in found}:
        raw = server[:_RAW_LIMIT]
        found[raw] = {
            "name": raw,
            "category_key": "web_server",
            "confidence": "medium",
            "score": 3,
            "version": None,
            "evidence": ["h:server"],
            "implied": False,
            "_implies": (),
            "_requires": (),
        }

    # Générateurs (balise <meta name="generator">) inconnus du catalogue.
    generator = facts.metas.get("generator", "").strip()
    if generator:
        base = _GENERATOR_VERSION_RE.sub("", generator)[:_RAW_LIMIT]
        known = {n.lower() for n in found}
        if base and not any(k.startswith(base.lower()) or base.lower().startswith(k) for k in known):
            version_match = _GENERATOR_VERSION_RE.search(generator)
            found[base] = {
                "name": base,
                "category_key": "generator",
                "confidence": "medium",
                "score": 3,
                "version": clean_version(version_match.group(1)) if version_match else None,
                "evidence": ["meta:generator"],
                "implied": False,
                "_implies": (),
                "_requires": (),
            }

    result = []
    for item in found.values():
        item.pop("_implies", None)
        item.pop("_requires", None)
        result.append(item)
    order = {"high": 0, "medium": 1, "low": 2}
    result.sort(key=lambda t: (order[t["confidence"]], t["category_key"], t["name"].lower()))
    return result
