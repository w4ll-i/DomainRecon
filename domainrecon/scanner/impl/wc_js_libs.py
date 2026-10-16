# =============================================================================
# DomainRecon - Contenu web : bibliothèques JavaScript, SRI et CDN à risque
# =============================================================================
# Logique sans réseau du module js_dependencies :
#   - identification d'une bibliothèque (nom npm + version) d'après l'URL d'un
#     script ou d'une feuille de style : cdnjs, jsDelivr, unpkg, Google Hosted
#     Libraries, code.jquery.com, BootstrapCDN, nom de fichier versionné, et les
#     fichiers hébergés par le site lui-même (analysés eux aussi) ;
#   - table locale des vulnérabilités connues, utilisée si OSV.dev est
#     injoignable et recoupée avec lui. Chaque ligne est une plage
#     [introduite, corrigée[ : la version CORRIGÉE n'est pas signalée (l'ancien
#     code, à borne inclusive, accusait jQuery 3.5.0 et Bootstrap 4.3.1) ;
#   - intégrité des sous-ressources (SRI) des scripts et feuilles de style tiers ;
#   - CDN compromis (polyfill.io, juin 2024, et les domaines du même opérateur).
# =============================================================================

import re
from urllib.parse import unquote, urlsplit

from ..http_utils import host_of_url, same_site
from .wc_html_facts import PageFacts
from .wc_versions import is_affected, parse_version

# Paquets npm dont la version est interrogée dans OSV (les autres bibliothèques
# sont listées mais non vérifiées : un nom de fichier n'est pas un nom de paquet).
KNOWN_PACKAGES = frozenset(
    {
        "jquery",
        "jquery-ui",
        "jquery-migrate",
        "bootstrap",
        "angular",
        "lodash",
        "moment",
        "moment-timezone",
        "handlebars",
        "underscore",
        "backbone",
        "vue",
        "react",
        "react-dom",
        "axios",
        "chart.js",
        "dompurify",
        "d3",
        "three",
        "leaflet",
        "swiper",
        "popper.js",
        "@popperjs/core",
        "select2",
        "highlight.js",
        "marked",
        "htmx.org",
        "alpinejs",
        "ckeditor4",
        "tinymce",
        "video.js",
        "plotly.js",
        "mathjax",
        "prismjs",
        "sweetalert2",
        "datatables.net",
    }
)

# Noms de cdnjs / fichiers -> nom npm.
ALIASES = {
    "twitter-bootstrap": "bootstrap",
    "angular.js": "angular",
    "angularjs": "angular",
    "jqueryui": "jquery-ui",
    "jquery.ui": "jquery-ui",
    "lodash.js": "lodash",
    "moment.js": "moment",
    "handlebars.js": "handlebars",
    "underscore.js": "underscore",
    "backbone.js": "backbone",
    "three.js": "three",
    "d3.js": "d3",
    "highlightjs": "highlight.js",
    "popper": "popper.js",
    "htmx": "htmx.org",
    "alpine": "alpinejs",
    "datatables": "datatables.net",
    "sweetalert": "sweetalert2",
}

# Version : « 3.3.1 », « 1.0.0-beta.2 » (s'arrête avant « .min.js »).
_VER = r"(?P<version>\d[\w+\-]*(?:\.\d[\w+\-]*)*)"

# (CDN, nom fixé ou None, expression) : groupes nommés `lib` (si le nom n'est pas fixé) et `version`.
_CDN_PATTERNS = [
    ("cdnjs", None, re.compile(r"cdnjs\.cloudflare\.com/ajax/libs/(?P<lib>[^/]+)/" + _VER + "/", re.I)),
    (
        "jsdelivr",
        None,
        re.compile(r"cdn\.jsdelivr\.net/npm/(?P<lib>(?:@[^/@]+/)?[^/@]+)@" + _VER + r"(?:/|$)", re.I),
    ),
    ("unpkg", None, re.compile(r"unpkg\.com/(?P<lib>(?:@[^/@]+/)?[^/@]+)@" + _VER + r"(?:/|$)", re.I)),
    ("googleapis", None, re.compile(r"ajax\.googleapis\.com/ajax/libs/(?P<lib>[^/]+)/" + _VER + "/", re.I)),
    (
        "jquery",
        "jquery",
        re.compile(r"code\.jquery\.com/jquery-" + _VER + r"(?:\.slim)?(?:\.min)?\.js", re.I),
    ),
    ("jquery", "jquery-ui", re.compile(r"code\.jquery\.com/ui/" + _VER + r"/", re.I)),
    (
        "bootstrapcdn",
        "bootstrap",
        re.compile(r"bootstrapcdn\.com/(?:twitter-)?bootstrap/" + _VER + "/", re.I),
    ),
]

# Nom de fichier versionné : « jquery-3.3.1.min.js », « lodash.4.17.4.js », « bootstrap.bundle.min.js ».
_FILE_RE = re.compile(
    r"/(?P<lib>[a-z][a-z0-9.]*?)(?:[.\-](?P<version>\d+(?:\.\d+){0,3}(?:-[a-z]+(?:\.\d+)?)?))?"
    r"(?:\.bundle)?(?:\.slim)?(?:\.min)?\.(?:js|css)$",
    re.I,
)
_QUERY_VERSION_RE = re.compile(r"(?:^|[?&])(?:ver|v|version)=(?P<version>\d+(?:\.\d+){0,3})(?:&|$)")
_PATH_VERSION_RE = re.compile(r"/(?P<version>\d+\.\d+(?:\.\d+)?)/")


def _normalize(name: str) -> str:
    name = unquote(name).lower()
    return ALIASES.get(name, name)


def identify(url: str) -> dict | None:
    """Bibliothèque désignée par l'URL d'une ressource : {name, version, via}, ou None.

    `version` vaut None si l'URL ne fixe pas de version (« @latest », fichier sans numéro).
    """
    for via, fixed_lib, pattern in _CDN_PATTERNS:
        match = pattern.search(url)
        if match:
            lib = fixed_lib or _normalize(match.group("lib"))
            return {"name": lib, "version": match.group("version"), "via": via}
    try:
        parts = urlsplit(url)
    except ValueError:
        return None
    path = parts.path
    match = _FILE_RE.search(path)
    if not match:
        return None
    lib = _normalize(match.group("lib"))
    if lib not in KNOWN_PACKAGES:
        return None
    version = match.group("version")
    if not version:
        query = _QUERY_VERSION_RE.search(parts.query)
        version = query.group("version") if query else None
    if not version:
        # Dossier versionné : /libs/jquery/3.6.0/jquery.min.js
        folder = _PATH_VERSION_RE.search(path)
        version = folder.group("version") if folder else None
    return {"name": lib, "version": version, "via": "file"}


# --- Table locale de vulnérabilités ----------------------------------------------------------
# (paquet, introduite, corrigée, CVE, gravité, nature). Sources : avis NVD / GitHub ; la
# version corrigée est la première non touchée. La table complète OSV.dev reste la référence ;
# celle-ci ne sert qu'à garder un résultat hors ligne et à recouper.
LOCAL_VULNS = [
    ("jquery", "0", "3.4.0", "CVE-2019-11358", "medium", "prototype_pollution"),
    ("jquery", "1.0.3", "3.5.0", "CVE-2020-11023", "medium", "xss"),
    ("jquery", "1.2", "3.5.0", "CVE-2020-11022", "medium", "xss"),
    ("jquery", "0", "3.0.0", "CVE-2015-9251", "medium", "xss"),
    ("jquery", "0", "1.9.0", "CVE-2012-6708", "medium", "xss"),
    ("jquery", "0", "1.6.3", "CVE-2011-4969", "medium", "xss"),
    ("jquery-ui", "0", "1.13.0", "CVE-2021-41184", "medium", "xss"),
    ("jquery-ui", "0", "1.13.0", "CVE-2021-41183", "medium", "xss"),
    ("jquery-ui", "0", "1.13.0", "CVE-2021-41182", "medium", "xss"),
    ("jquery-ui", "0", "1.13.2", "CVE-2022-31160", "medium", "xss"),
    ("bootstrap", "0", "3.4.1", "CVE-2019-8331", "medium", "xss"),
    ("bootstrap", "4.0.0", "4.3.1", "CVE-2019-8331", "medium", "xss"),
    ("bootstrap", "0", "3.4.0", "CVE-2018-14040", "medium", "xss"),
    ("bootstrap", "4.0.0", "4.1.2", "CVE-2018-14040", "medium", "xss"),
    ("bootstrap", "0", "3.4.0", "CVE-2018-14041", "medium", "xss"),
    ("bootstrap", "4.0.0", "4.1.2", "CVE-2018-14041", "medium", "xss"),
    ("bootstrap", "0", "3.4.0", "CVE-2018-14042", "medium", "xss"),
    ("bootstrap", "4.0.0", "4.1.2", "CVE-2018-14042", "medium", "xss"),
    ("angular", "0", "1.8.0", "CVE-2020-7676", "medium", "xss"),
    ("angular", "0", "1.7.9", "CVE-2019-10768", "high", "prototype_pollution"),
    ("lodash", "0", "4.17.21", "CVE-2021-23337", "high", "code_injection"),
    ("lodash", "0", "4.17.21", "CVE-2020-28500", "medium", "redos"),
    ("lodash", "0", "4.17.19", "CVE-2020-8203", "high", "prototype_pollution"),
    ("lodash", "0", "4.17.12", "CVE-2019-10744", "critical", "prototype_pollution"),
    ("lodash", "0", "4.17.11", "CVE-2018-16487", "high", "prototype_pollution"),
    ("lodash", "0", "4.17.5", "CVE-2018-3721", "medium", "prototype_pollution"),
    ("moment", "0", "2.29.2", "CVE-2022-24785", "high", "path_traversal"),
    ("moment", "2.18.0", "2.29.4", "CVE-2022-31129", "high", "redos"),
    ("moment", "0", "2.11.2", "CVE-2016-4055", "medium", "redos"),
    ("handlebars", "0", "4.7.7", "CVE-2021-23369", "critical", "code_injection"),
    ("handlebars", "0", "4.7.7", "CVE-2021-23383", "critical", "prototype_pollution"),
    ("handlebars", "0", "4.3.0", "CVE-2019-19919", "critical", "prototype_pollution"),
    ("underscore", "1.3.2", "1.12.1", "CVE-2021-23358", "high", "code_injection"),
    ("axios", "0", "0.21.1", "CVE-2020-28168", "medium", "ssrf"),
    ("axios", "0", "0.21.2", "CVE-2021-3749", "high", "redos"),
    ("axios", "0", "0.18.1", "CVE-2019-10742", "high", "dos"),
    ("axios", "0.8.1", "1.6.0", "CVE-2023-45857", "medium", "csrf"),
    ("dompurify", "0", "2.0.17", "CVE-2020-26870", "medium", "xss"),
    ("chart.js", "0", "2.9.4", "CVE-2020-7746", "high", "prototype_pollution"),
]

# Natures de vulnérabilité (codes de messages `js_dependencies.kind_<nature>`).
KINDS = (
    "code_injection",
    "csrf",
    "dos",
    "path_traversal",
    "prototype_pollution",
    "redos",
    "ssrf",
    "xss",
)

_SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}


def local_vulnerabilities(name: str, version: str) -> list[dict]:
    """Vulnérabilités de la table locale pour un paquet à une version exacte (plage [introduite, corrigée[)."""
    found: dict[str, dict] = {}
    for package, introduced, fixed, cve, severity, kind in LOCAL_VULNS:
        if package != name or is_affected(version, introduced, fixed) is not True:
            continue
        current = found.get(cve)
        # Un même CVE couvre plusieurs lignes de versions : on garde la correction la plus proche.
        if (
            current is None
            or (parse_version(fixed) or ((0,), 0))[0] < (parse_version(current["fixed"]) or ((0,), 0))[0]
        ):
            found[cve] = {
                "id": cve,
                "cve": cve,
                "severity": severity,
                "kind": kind,
                "fixed": fixed,
                "url": f"https://osv.dev/vulnerability/{cve}",
                "source": "local",
            }
    return sorted(found.values(), key=lambda v: (_SEVERITY_ORDER[v["severity"]], v["id"]))


# --- CDN compromis -------------------------------------------------------------------------------

# Domaines de la chaîne d'approvisionnement piégée (juin 2024, rapport Sansec / Cloudflare / Google) :
# polyfill.io racheté puis détourné pour injecter du code malveillant, et domaines du même opérateur.
# Les miroirs sûrs (cdnjs.cloudflare.com/polyfill, polyfill-fastly.io) ne sont PAS dans la liste.
RISKY_HOSTS = {
    "polyfill.io": "critical",
    "bootcss.com": "high",
    "bootcdn.net": "high",
    "staticfile.net": "high",
    "staticfile.org": "high",
    "unionadjs.com": "critical",
    "xhsbpza.com": "critical",
    "union.macoms.la": "critical",
    "newcrbpc.com": "critical",
}

# Hébergeurs dont le contenu change sans préavis : SRI impossible par construction (pas un défaut du site).
DYNAMIC_HOSTS = (
    "googletagmanager.com",
    "google-analytics.com",
    "googleadservices.com",
    "googlesyndication.com",
    "doubleclick.net",
    "fonts.googleapis.com",
    "fonts.gstatic.com",
    "maps.googleapis.com",
    "apis.google.com",
    "www.google.com",
    "www.gstatic.com",
    "connect.facebook.net",
    "platform.twitter.com",
    "js.stripe.com",
    "js.braintreegateway.com",
    "www.paypal.com",
    "www.paypalobjects.com",
    "widget.intercom.io",
    "snap.licdn.com",
    "static.hotjar.com",
    "js.hs-scripts.com",
    "cdn.cookielaw.org",
    "client.crisp.chat",
    "static.cloudflareinsights.com",
    "challenges.cloudflare.com",
    "use.typekit.net",
    "kit.fontawesome.com",
    "embed.tawk.to",
    "static.zdassets.com",
    "js.sentry-cdn.com",
)


def _host_matches(host: str, domains) -> bool:
    return any(host == d or host.endswith("." + d) for d in domains)


def risky_cdn(host: str) -> str | None:
    """Gravité d'un hôte de CDN compromis, ou None."""
    for domain, severity in RISKY_HOSTS.items():
        if host == domain or host.endswith("." + domain):
            return severity
    return None


# --- Analyse d'une page -------------------------------------------------------------------------


def analyze_html(html: str, page_url: str, site: str) -> dict:
    """Relève bibliothèques, CDN à risque et SRI manquants d'une page, sans réseau.

    `site` : hôte de la cible (une ressource d'un autre site est « tierce »). Rend
    {libraries: [{name, version, url, via, first_party, pinned}], risky_cdns, sri_missing,
    sri_checked, scripts_total, styles_total}.
    """
    facts = PageFacts.parse(html or "", page_url)
    resources: list[tuple[str, str, bool, bool]] = []  # (URL, nature, intégrité présente, crossorigin)
    for script in facts.scripts:
        url = facts.resolve(script["src"])
        if url and script["type"] != "importmap":
            resources.append((url, "script", bool(script["integrity"]), script["crossorigin"]))
    for link in facts.links:
        rels = link["rel"].split()
        nature = None
        if "stylesheet" in rels:
            nature = "style"
        elif "modulepreload" in rels or ("preload" in rels and link["as"] == "script"):
            nature = "script"
        elif "preload" in rels and link["as"] == "style":
            nature = "style"
        if nature and (url := facts.resolve(link["href"])):
            resources.append((url, nature, bool(link["integrity"]), link["crossorigin"]))

    libraries: list[dict] = []
    risky: list[dict] = []
    sri_missing: list[dict] = []
    seen_libs: set[tuple] = set()
    seen_urls: set[str] = set()
    sri_checked = 0
    scripts_total = styles_total = 0
    for url, nature, has_integrity, _crossorigin in resources:
        if url in seen_urls:
            continue
        seen_urls.add(url)
        scripts_total += nature == "script"
        styles_total += nature == "style"
        host = host_of_url(url)
        first_party = same_site(host, site)
        if not first_party and (severity := risky_cdn(host)):
            risky.append({"host": host, "url": url[:200], "severity": severity})
        if not first_party and not _host_matches(host, DYNAMIC_HOSTS):
            sri_checked += 1
            if not has_integrity and url.lower().startswith(("http://", "https://")):
                sri_missing.append({"url": url[:200], "host": host, "kind": nature})
        found = identify(url)
        if found:
            pinned = parse_version(found["version"]) is not None
            key = (found["name"], found["version"])
            if key in seen_libs:
                continue
            seen_libs.add(key)
            libraries.append(
                {
                    "name": found["name"],
                    "version": found["version"],
                    "url": url[:200],
                    "via": found["via"],
                    "host": host,
                    "first_party": first_party,
                    "pinned": pinned,
                }
            )
    return {
        "libraries": libraries[:60],
        "risky_cdns": risky[:20],
        "sri_missing": sri_missing[:50],
        "sri_checked": sri_checked,
        "scripts_total": scripts_total,
        "styles_total": styles_total,
    }
