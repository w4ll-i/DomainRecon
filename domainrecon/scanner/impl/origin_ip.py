# =============================================================================
# DomainRecon - Recherche de l'adresse IP d'origine derrière un CDN
# =============================================================================
# Recherche de type « Cloudflare Bypass », généralisée à tous les CDN. Déroulé :
#   1. la cible est-elle derrière un CDN ? (ASN de ses adresses d'après Team
#      Cymru, et en-têtes de la page d'accueil : cf-ray, x-amz-cf-id…) ;
#   2. candidats : adresses des noms « d'administration » du même domaine qui
#      ne passent pas par le CDN (direct., origin., mail., ftp., cpanel…), des
#      serveurs de messagerie (MX), des plages ip4:/ip6: du SPF et de l'historique
#      DNS (Robtex) ; sont écartées les adresses non publiques, celles de la cible
#      et celles qui appartiennent elles-mêmes à un CDN ;
#   3. vérification : une requête HTTP(S) directe sur chaque candidat, avec
#      l'en-tête Host de la cible, est comparée à la page d'accueil vue à travers
#      le CDN (titre, ressemblance du contenu). Une page par défaut (« Welcome to
#      nginx! ») ou d'un autre site n'est JAMAIS retenue.
# Verdicts : « confirmed » (même page), « probable » (même titre ou même
# redirection, contenu différent), « rejected ». Sans page d'accueil lisible
# pour comparer, les candidats restent « unverified ».
# Catégorie SENSIBLE : l'étape 3 contacte des serveurs qui ne sont pas la cible
# publique. Rien n'est contourné : la requête est celle d'un visiteur qui
# connaîtrait l'adresse.
# =============================================================================

import asyncio
import difflib
import ipaddress
import re

from .. import common, http_utils
from ..dns import DnsQuerier, txt_record_text
from ..errors import ModuleError
from ..targets import is_public_address
from . import bgp_sources

# Systèmes autonomes d'un CDN ou d'un pare-feu applicatif en frontal : numéro -> nom.
CDN_ASNS = {
    13335: "Cloudflare",
    209242: "Cloudflare",
    20940: "Akamai",
    16625: "Akamai",
    12222: "Akamai",
    35994: "Akamai",
    21342: "Akamai",
    54113: "Fastly",
    19551: "Imperva",
    62571: "Imperva",
    30148: "Sucuri",
    15133: "Edgio",
    60068: "CDN77",
    200325: "BunnyCDN",
    30633: "Leaseweb CDN",
}
# En-têtes de la page d'accueil révélant un CDN : (en-tête, fragment de valeur ou "" pour sa seule présence, nom).
CDN_HEADERS = (
    ("cf-ray", "", "Cloudflare"),
    ("server", "cloudflare", "Cloudflare"),
    ("x-amz-cf-id", "", "Amazon CloudFront"),
    ("via", "cloudfront", "Amazon CloudFront"),
    ("x-sucuri-id", "", "Sucuri"),
    ("x-iinfo", "", "Imperva"),
    ("x-cdn", "imperva", "Imperva"),
    ("x-cdn", "incapsula", "Imperva"),
    ("server", "akamaighost", "Akamai"),
    ("x-akamai-transformed", "", "Akamai"),
    ("x-fastly-request-id", "", "Fastly"),
    ("x-azure-ref", "", "Azure Front Door"),
    ("server", "bunnycdn", "BunnyCDN"),
)

# Noms testés autour du domaine : ceux qui pointent souvent directement vers le serveur d'origine.
SIBLING_NAMES = (
    "direct", "origin", "origin-www", "mail", "smtp", "webmail", "ftp", "cpanel", "vpn", "ssh", "remote",
    "dev", "staging", "test", "admin", "api", "old", "backup", "portal", "autodiscover",
)  # fmt: skip

MAX_CANDIDATES = 24
MAX_VERIFIED = 12
SPF_MAX_ADDRESSES = 16
PROBE_CONCURRENCY = 4
PROBE_TIMEOUT = 6.0
# Ressemblance minimale (0 à 1) du contenu pour « confirmed » / « probable ».
CONFIRM_RATIO = 0.85
PROBABLE_RATIO = 0.6
COMPARE_CHARS = 20000
MAX_WORDS = 400

# Titres de pages par défaut d'un serveur : jamais une preuve, sauf si la page d'accueil porte le même.
DEFAULT_TITLES = (
    "welcome to nginx", "apache2", "apache http server test page", "it works", "iis windows server",
    "iis7", "default web site page", "test page", "default page", "domain default page", "403 forbidden",
    "404 not found", "index of /", "503 service", "502 bad gateway", "plesk", "cpanel", "directadmin",
)  # fmt: skip

_TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.IGNORECASE | re.DOTALL)
_WORD_RE = re.compile(r"[^\s<>]+")
_SPF_RE = re.compile(r"\bip([46]):([0-9a-fA-F:.]+(?:/\d{1,3})?)")


# =============================================================================
# Détection du CDN
# =============================================================================


def asn_number(asn: str | None) -> int | None:
    """Numéro d'un ASN écrit « AS13335 »."""
    if asn and asn.upper().startswith("AS") and asn[2:].isdigit():
        return int(asn[2:])
    return None


def detect_cdn(asns: list[str | None], headers: dict[str, str]) -> tuple[str, list[str]] | None:
    """(nom du CDN, preuves) d'après les ASN des adresses de la cible et les en-têtes de sa page d'accueil."""
    evidence: list[str] = []
    name: str | None = None
    for asn in asns:
        number = asn_number(asn)
        if number in CDN_ASNS:
            name = name or CDN_ASNS[number]
            evidence.append(f"asn:{asn}")
    for header, fragment, cdn in CDN_HEADERS:
        value = headers.get(header)
        if value is not None and fragment in value.lower():
            name = name or cdn
            evidence.append(f"header:{header}")
    return (name, list(dict.fromkeys(evidence))) if name else None


# =============================================================================
# Candidats
# =============================================================================


def spf_addresses(texts: list[str]) -> list[str]:
    """Adresses des mécanismes ip4:/ip6: d'enregistrements SPF (plages de 16 adresses au plus développées)."""
    found: list[str] = []
    for text in texts:
        if not text.lower().startswith("v=spf1"):
            continue
        for match in _SPF_RE.finditer(text):
            try:
                network = ipaddress.ip_network(match.group(2), strict=False)
            except ValueError:
                continue
            if network.num_addresses > SPF_MAX_ADDRESSES:
                continue
            found.extend(str(a) for a in network)
    return found


def gather_dns_candidates_sync(apex: str, querier: DnsQuerier | None = None) -> dict[str, dict]:
    """Candidats venus du DNS : {ip: {"names": [...], "sources": [...]}}. Bloquant (dnspython)."""
    querier = querier or DnsQuerier(query_timeout=3, budget=25)
    found: dict[str, dict] = {}

    def add(ip: str, source: str, name: str | None = None) -> None:
        entry = found.setdefault(ip, {"names": [], "sources": []})
        if source not in entry["sources"]:
            entry["sources"].append(source)
        if name and name not in entry["names"]:
            entry["names"].append(name)

    def addresses(name: str) -> list[str]:
        result = []
        for rtype in ("A", "AAAA"):
            lookup = querier.lookup(name, rtype)
            if lookup.status == "ok":
                result.extend(str(rdata).strip() for rdata in lookup.answers)
        return result

    for label in SIBLING_NAMES:
        name = f"{label}.{apex}"
        for ip in addresses(name):
            add(ip, "dns_sibling", name)
    mx = querier.lookup(apex, "MX")
    if mx.status == "ok":
        for record in mx.answers[:5]:
            host = str(getattr(record, "exchange", "")).rstrip(".")
            if host and host != ".":
                for ip in addresses(host):
                    add(ip, "mx", host)
    txt = querier.lookup(apex, "TXT")
    if txt.status == "ok":
        for ip in spf_addresses([txt_record_text(r) for r in txt.answers]):
            add(ip, "spf")
    return found


def merge_candidates(dns_found: dict[str, dict], history: list[str], exclude: set[str]) -> dict[str, dict]:
    """Fusionne les sources, retire adresses non publiques / de la cible / invalides, borne à MAX_CANDIDATES."""
    merged: dict[str, dict] = {}
    for ip, info in dns_found.items():
        merged[ip] = {"names": list(info["names"]), "sources": list(info["sources"])}
    for ip in history:
        entry = merged.setdefault(ip, {"names": [], "sources": []})
        if "robtex_history" not in entry["sources"]:
            entry["sources"].append("robtex_history")
    clean: dict[str, dict] = {}
    for raw, info in merged.items():
        try:
            ip = str(ipaddress.ip_address(raw))
        except ValueError:
            continue
        if ip in exclude or not is_public_address(ip):
            continue
        clean[ip] = info
    # Plus de sources concordantes d'abord (une adresse vue par le DNS et l'historique est plus probable).
    ordered = sorted(clean.items(), key=lambda kv: (-len(kv[1]["sources"]), kv[0]))
    return dict(ordered[:MAX_CANDIDATES])


async def origin_of(ip: str, semaphore: asyncio.Semaphore) -> dict | None:
    """ASN d'une adresse d'après Team Cymru (None si elle n'est pas annoncée ou si le DNS échoue)."""
    async with semaphore:
        try:
            return await asyncio.to_thread(bgp_sources.cymru_origin_sync, ip)
        except ModuleError:
            return None


# =============================================================================
# Vérification
# =============================================================================


def title_of(html: str) -> str:
    """Titre normalisé (minuscules, espaces réduits) d'une page HTML, « » s'il n'y en a pas."""
    match = _TITLE_RE.search(html or "")
    return re.sub(r"\s+", " ", match.group(1)).strip().lower()[:120] if match else ""


def similarity(a: str, b: str) -> float | None:
    """Ressemblance (0 à 1) de deux contenus, mot à mot sur leurs premiers mots ; None si l'un est vide."""
    if not (a or "").strip() or not (b or "").strip():
        return None
    words_a = _WORD_RE.findall(a[:COMPARE_CHARS])[:MAX_WORDS]
    words_b = _WORD_RE.findall(b[:COMPARE_CHARS])[:MAX_WORDS]
    if words_a == words_b:
        return 1.0
    return difflib.SequenceMatcher(None, words_a, words_b, autojunk=False).ratio()


def _is_default_title(title: str) -> bool:
    return any(marker in title for marker in DEFAULT_TITLES)


def _location_host(headers) -> str:
    """Hôte de l'en-tête Location (minuscules), « » s'il n'y en a pas."""
    location = headers.get("location", "") if headers else ""
    return location.split("//", 1)[-1].split("/", 1)[0].lower()


def judge(home, status: int, headers, text: str) -> tuple[str, float | None]:
    """(verdict, ressemblance) d'une réponse directe comparée à la page d'accueil `home` (HomePage)."""
    home_title = title_of(home.text)
    title = title_of(text)
    ratio = similarity(home.text, text)
    # Page par défaut du serveur ou d'un autre site hébergé là : jamais une preuve.
    if title and _is_default_title(title) and title != home_title:
        return "rejected", ratio
    if status >= 500 or status in (401, 403, 404):
        return "rejected", ratio
    if ratio is not None and ratio >= CONFIRM_RATIO and (not home_title or title == home_title):
        return "confirmed", ratio
    if home_title and title == home_title and ratio is not None and ratio >= PROBABLE_RATIO:
        return "confirmed", ratio
    if home_title and title == home_title:
        return "probable", ratio
    if ratio is not None and ratio >= PROBABLE_RATIO:
        return "probable", ratio
    # Redirection identique à celle de la page d'accueil (vers la même destination) : indice faible.
    if status in (301, 302, 307, 308):
        target = _location_host(headers)
        if target and target == (home.url or "").split("//", 1)[-1].split("/", 1)[0].lower():
            return "probable", ratio
    return "rejected", ratio


async def verify(ip: str, domain: str, home) -> dict:
    """Requête directe sur `ip` avec Host: domain, en https puis http ; verdict et indices."""
    result = {"verdict": "unverified", "scheme": None, "status_code": None, "title": None, "similarity": None}
    best: dict | None = None
    async with common._http_client(timeout=PROBE_TIMEOUT, follow_redirects=False) as client:
        for scheme in ("https", "http"):
            try:
                fetched = await http_utils.fetch(
                    client,
                    f"{scheme}://{common.url_host(ip)}/",
                    headers={"Host": domain},
                    site=domain,
                    max_bytes=262144,
                    max_redirects=0,
                    timeout=PROBE_TIMEOUT,
                )
            except http_utils.FETCH_ERRORS:
                continue
            status = fetched.status_code
            verdict, ratio = judge(home, status, fetched.headers, fetched.text)
            attempt = {
                "verdict": verdict,
                "scheme": scheme,
                "status_code": status,
                "title": title_of(fetched.text) or None,
                "similarity": round(ratio, 3) if ratio is not None else None,
            }
            if best is None or _rank(attempt["verdict"]) > _rank(best["verdict"]):
                best = attempt
            if verdict == "confirmed":
                break
    if best is None:
        return {**result, "verdict": "unreachable"}
    return best


def _rank(verdict: str) -> int:
    return {"confirmed": 3, "probable": 2, "rejected": 1}.get(verdict, 0)
