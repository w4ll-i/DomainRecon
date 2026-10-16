# =============================================================================
# DomainRecon - Logique du module « web_files_extra » (fichiers informatifs et .well-known)
# =============================================================================
# Fichiers conventionnels qu'un site publie volontairement, au-delà de robots.txt,
# sitemap.xml et security.txt (déjà lus par « web_files ») : humans.txt, ads.txt,
# app-ads.txt, manifeste d'application web, fichiers .well-known (OpenID Connect,
# OAuth, changement de mot de passe, Digital Asset Links, Apple App Site
# Association, host-meta, NodeInfo, Global Privacy Control) et politiques
# inter-domaines historiques (crossdomain.xml, clientaccesspolicy.xml).
#
# Chaque fichier n'est déclaré « trouvé » que si son CONTENU a la forme attendue :
# un code 200 seul ne prouve rien (application monopage, page d'accueil servie à
# toute URL). Les fichiers sensibles (.git, .env, sauvegardes…) ne sont PAS
# recherchés ici : c'est le rôle d'un module actif distinct.
# Fonctions pures, sans réseau. Les contenus XML ne sont lus qu'avec des
# expressions régulières bornées (aucun analyseur XML, donc aucune entité externe).
# =============================================================================

import json
import re
from html.parser import HTMLParser
from urllib.parse import urljoin, urlsplit

# (clé, chemin, genre). Plusieurs chemins peuvent partager une clé (manifeste) : le premier trouvé gagne.
CANDIDATES: tuple[tuple[str, str, str], ...] = (
    ("humans", "/humans.txt", "text"),
    ("ads", "/ads.txt", "ads"),
    ("app_ads", "/app-ads.txt", "ads"),
    ("manifest", "/manifest.webmanifest", "manifest"),
    ("manifest", "/site.webmanifest", "manifest"),
    ("manifest", "/manifest.json", "manifest"),
    ("openid_configuration", "/.well-known/openid-configuration", "oidc"),
    ("oauth_authorization_server", "/.well-known/oauth-authorization-server", "oidc"),
    ("change_password", "/.well-known/change-password", "change_password"),
    ("assetlinks", "/.well-known/assetlinks.json", "assetlinks"),
    ("apple_app_site_association", "/.well-known/apple-app-site-association", "aasa"),
    ("host_meta", "/.well-known/host-meta", "host_meta"),
    ("nodeinfo", "/.well-known/nodeinfo", "nodeinfo"),
    ("gpc", "/.well-known/gpc.json", "gpc"),
    ("crossdomain", "/crossdomain.xml", "crossdomain"),
    ("clientaccesspolicy", "/clientaccesspolicy.xml", "clientaccess"),
)

KEYS = tuple(dict.fromkeys(key for key, _, _ in CANDIDATES))
MAX_BODY = 128 * 1024
EXCERPT = 500

_HTML_START = re.compile(r"<\s*(!doctype\s+html|html|head|body)\b", re.IGNORECASE)
_ADS_LINE = re.compile(
    r"^\s*([a-z0-9][a-z0-9.-]*\.[a-z]{2,})\s*,\s*([^,\s#]+)\s*,\s*(direct|reseller)\b", re.IGNORECASE
)
_ADS_VARIABLE = re.compile(
    r"^\s*(ownerdomain|managerdomain|contact|subdomain)\s*=\s*([^\s#]+)", re.IGNORECASE
)


def looks_like_html(text: str) -> bool:
    """La réponse est-elle une page HTML (soft-404, application monopage) plutôt qu'un fichier de données ?"""
    return bool(_HTML_START.search(text[:1000]))


def _loads(text: str) -> object:
    try:
        return json.loads(text)
    except ValueError:
        return None


def _short(value: object, limit: int = 200) -> str | None:
    return (
        str(value)[:limit] if isinstance(value, (str, int, float)) and not isinstance(value, bool) else None
    )


def _strings(value: object, limit: int = 10) -> list[str]:
    if not isinstance(value, list):
        return []
    return [s[:100] for s in value if isinstance(s, str)][:limit]


def validate(kind: str, text: str, content_type: str = "") -> dict | None:
    """Valide le contenu d'un fichier de genre `kind` ; renvoie ses détails, ou None s'il n'a pas la forme attendue."""
    if not text.strip():
        return None
    if "html" in content_type.lower() or looks_like_html(text):
        return None
    handler = _VALIDATORS.get(kind)
    return handler(text) if handler else None


def _text(text: str) -> dict | None:
    lines = [line for line in text.splitlines() if line.strip()]
    return {"lines": len(lines), "excerpt": text.strip()[:EXCERPT]}


def _ads(text: str) -> dict | None:
    direct = reseller = 0
    sellers: list[str] = []
    variables: dict[str, str] = {}
    for line in text.splitlines():
        record = _ADS_LINE.match(line)
        if record:
            if record.group(3).lower() == "direct":
                direct += 1
            else:
                reseller += 1
            domain = record.group(1).lower()
            if domain not in sellers:
                sellers.append(domain)
            continue
        variable = _ADS_VARIABLE.match(line)
        if variable:
            variables.setdefault(variable.group(1).lower(), variable.group(2)[:100])
    if direct + reseller == 0:
        return None
    return {
        "records": direct + reseller,
        "direct": direct,
        "reseller": reseller,
        "sellers": sellers[:10],
        **variables,
    }


def _manifest(text: str) -> dict | None:
    data = _loads(text)
    if not isinstance(data, dict) or not any(
        k in data for k in ("name", "short_name", "start_url", "icons", "display")
    ):
        return None
    icons = data.get("icons")
    return {
        "name": _short(data.get("name")),
        "short_name": _short(data.get("short_name")),
        "start_url": _short(data.get("start_url")),
        "scope": _short(data.get("scope")),
        "display": _short(data.get("display")),
        "icons": len(icons) if isinstance(icons, list) else 0,
    }


def _oidc(text: str) -> dict | None:
    data = _loads(text)
    if not isinstance(data, dict) or not isinstance(data.get("issuer"), str):
        return None
    algorithms = _strings(data.get("id_token_signing_alg_values_supported"))
    return {
        "issuer": _short(data.get("issuer")),
        "authorization_endpoint": _short(data.get("authorization_endpoint")),
        "token_endpoint": _short(data.get("token_endpoint")),
        "jwks_uri": _short(data.get("jwks_uri")),
        "response_types": _strings(data.get("response_types_supported")),
        "grant_types": _strings(data.get("grant_types_supported")),
        "signing_algorithms": algorithms,
        "alg_none": any(a.lower() == "none" for a in algorithms),
        "insecure_issuer": data["issuer"].lower().startswith("http://"),
    }


def _assetlinks(text: str) -> dict | None:
    data = _loads(text)
    if not isinstance(data, list) or not data:
        return None
    statements = [s for s in data if isinstance(s, dict) and "relation" in s and "target" in s]
    if not statements:
        return None
    packages = []
    for statement in statements:
        target = statement.get("target")
        name = target.get("package_name") if isinstance(target, dict) else None
        if isinstance(name, str) and name[:100] not in packages:
            packages.append(name[:100])
    return {"statements": len(statements), "packages": packages[:10]}


def _aasa(text: str) -> dict | None:
    data = _loads(text)
    if not isinstance(data, dict):
        return None
    sections = [k for k in ("applinks", "webcredentials", "appclips", "activitycontinuation") if k in data]
    return {"sections": sections} if sections else None


def _host_meta(text: str) -> dict | None:
    if not re.search(r"<\s*XRD\b", text[:2000], re.IGNORECASE):
        return None
    return {"links": len(re.findall(r"<\s*Link\b", text, re.IGNORECASE))}


def _nodeinfo(text: str) -> dict | None:
    data = _loads(text)
    if not isinstance(data, dict) or not isinstance(data.get("links"), list):
        return None
    return {"links": len(data["links"])}


def _gpc(text: str) -> dict | None:
    data = _loads(text)
    if not isinstance(data, dict) or not isinstance(data.get("gpc"), bool):
        return None
    return {"gpc": data["gpc"]}


def _crossdomain(text: str) -> dict | None:
    if not re.search(r"<\s*cross-domain-policy\b", text[:4000], re.IGNORECASE):
        return None
    domains = re.findall(
        r'<\s*allow-access-from\b[^>]*\bdomain\s*=\s*["\']([^"\']*)["\']', text, re.IGNORECASE
    )
    policy = re.search(r'permitted-cross-domain-policies\s*=\s*["\']([^"\']*)["\']', text, re.IGNORECASE)
    all_policies = bool(policy and policy.group(1).strip().lower() == "all")
    insecure = bool(re.search(r'\bsecure\s*=\s*["\']false["\']', text, re.IGNORECASE))
    return {
        "domains": [d[:100] for d in dict.fromkeys(domains)][:10],
        "wildcard": any(d.strip() == "*" for d in domains) or all_policies,
        "insecure": insecure,
    }


def _clientaccess(text: str) -> dict | None:
    if not re.search(r"<\s*access-policy\b", text[:4000], re.IGNORECASE):
        return None
    domains = re.findall(r'<\s*domain\b[^>]*\buri\s*=\s*["\']([^"\']*)["\']', text, re.IGNORECASE)
    return {
        "domains": [d[:100] for d in dict.fromkeys(domains)][:10],
        "wildcard": any(d.strip() == "*" for d in domains),
    }


_VALIDATORS = {
    "text": _text,
    "ads": _ads,
    "manifest": _manifest,
    "oidc": _oidc,
    "assetlinks": _assetlinks,
    "aasa": _aasa,
    "host_meta": _host_meta,
    "nodeinfo": _nodeinfo,
    "gpc": _gpc,
    "crossdomain": _crossdomain,
    "clientaccess": _clientaccess,
}


class _ManifestLink(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.href: str | None = None

    def handle_starttag(self, tag: str, attrs) -> None:
        if tag != "link" or self.href is not None:
            return
        found = {name: value for name, value in attrs if value is not None}
        if "manifest" in str(found.get("rel", "")).lower().split() and found.get("href"):
            self.href = str(found["href"]).strip()


def manifest_path(html: str, base_url: str | None, host: str) -> str | None:
    """Chemin du manifeste déclaré par <link rel="manifest"> dans la page, s'il est sur le même hôte."""
    if not html or not base_url:
        return None
    parser = _ManifestLink()
    try:
        parser.feed(html[:200_000])
        parser.close()
    except Exception:  # HTML invalide : on garde ce qui a été lu
        pass
    if not parser.href:
        return None
    target = urlsplit(urljoin(base_url, parser.href))
    if target.scheme not in ("http", "https") or (target.hostname or "").lower() != host.lower():
        return None
    return target.path + (f"?{target.query}" if target.query else "")


def is_permissive(kind: str, details: dict | None) -> bool:
    """La politique inter-domaines autorise-t-elle n'importe quel domaine ?"""
    return kind in ("crossdomain", "clientaccess") and bool(details and details.get("wildcard"))
