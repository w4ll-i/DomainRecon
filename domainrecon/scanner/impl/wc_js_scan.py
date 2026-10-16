# =============================================================================
# DomainRecon - Contenu web : secrets et points d'accès d'API dans le JavaScript
# =============================================================================
# Logique sans réseau du module js_secrets. Deux contrôles :
#   - 16 motifs de secrets, valeurs MASQUÉES ;
#   - extraction des endpoints d'API
#     internes, des API externes référencées, liste et taille des fichiers JS.
#
# Défauts corrigés :
#   - motifs génériques sans garde-fou (api_key = "xxxx…", password = "Enter your
#     password") : valeurs d'exemple, répétitions et faible entropie écartées ;
#   - JWT : l'ancien motif prenait n'importe quel « eyJ…x.y » ; ici en-tête ET
#     contenu en base64 JSON, et la clé publique « anon » de Supabase est écartée ;
#   - exemple de la documentation AWS (…EXAMPLE) écarté ;
#   - nettoyage des CDN par simple sous-chaîne de l'hôte (contournable) : la
#     sélection des fichiers (même site) est faite par le module ;
#   - motif de mot de passe avec anticipation négative sur toute la ligne (lent
#     sur un fichier minifié d'une seule ligne) : motifs bornés ;
#   - aucune valeur complète n'est jamais conservée : 4 premiers et 4 derniers
#     caractères seulement, et rien du tout pour une clé privée.
# =============================================================================

import base64
import json
import math
import re
from collections import Counter
from urllib.parse import urlsplit

from ..http_utils import host_of_url, same_site

# Octets lus au plus par fichier, nombre de constats conservés.
MAX_FILE_BYTES = 1024 * 1024
MAX_SECRETS = 100
MAX_PER_PATTERN_FILE = 3
MAX_ENDPOINTS = 100
MAX_HOSTS = 50

_PLACEHOLDER_WORDS = (
    "your",
    "example",
    "change",
    "placeholder",
    "xxxx",
    "dummy",
    "sample",
    "insert",
    "enter",
    "replace",
    "todo",
    "fixme",
    "secret_here",
    "password_here",
    "key_here",
    "token_here",
    "redacted",
    "<",
    "${",
    "{{",
)
_PLACEHOLDER_VALUES = frozenset(
    {
        "changeme",
        "password",
        "password123",
        "secret",
        "mysecret",
        "test",
        "testtest",
        "undefined",
        "null",
        "none",
    }
)


def redact(value: str, kind: str = "") -> str:
    """Valeur masquée : 4 premiers et 4 derniers caractères (jamais la valeur entière)."""
    if kind == "private_key" or len(value) <= 8:
        return "****"
    return f"{value[:4]}****{value[-4:]}"


def entropy(value: str) -> float:
    """Entropie de Shannon (bits par caractère) ; un secret aléatoire dépasse ~3,5."""
    if not value:
        return 0.0
    counts = Counter(value)
    total = len(value)
    return -sum(n / total * math.log2(n / total) for n in counts.values())


def _looks_real(value: str, min_entropy: float = 3.0) -> bool:
    lowered = value.lower()
    if lowered in _PLACEHOLDER_VALUES or any(word in lowered for word in _PLACEHOLDER_WORDS):
        return False
    if len(set(value)) <= 3:
        return False
    return entropy(value) >= min_entropy


def _jwt_ok(value: str) -> bool:
    """Un vrai JWT : en-tête et contenu en JSON ; la clé publique « anon » (Supabase) n'est pas un secret."""
    parts = value.split(".")
    if len(parts) != 3:
        return False
    try:
        decoded = []
        for part in parts[:2]:
            padded = part + "=" * (-len(part) % 4)
            decoded.append(json.loads(base64.urlsafe_b64decode(padded.encode("ascii"))))
    except (ValueError, UnicodeDecodeError):
        return False
    header, payload = decoded
    if not isinstance(header, dict) or not isinstance(payload, dict) or "alg" not in header:
        return False
    return payload.get("role") != "anon"


def _aws_ok(value: str) -> bool:
    return not value.endswith("EXAMPLE") and _looks_real(value[4:], 2.5)


def _twilio_ok(value: str) -> bool:
    # Un identifiant de compte, pas un secret : écarté s'il ressemble à un simple condensat sans lettre ou chiffre.
    return any(c.isdigit() for c in value[2:]) and any(c.isalpha() for c in value[2:])


def _generic_ok(value: str) -> bool:
    return _looks_real(value, 3.2)


def _password_ok(value: str) -> bool:
    lowered = value.lower()
    if "password" in lowered or "passwd" in lowered:
        return False
    if value.isalpha() and (value.islower() or value.isupper() or value[1:].islower()):
        return False  # un mot (intitulé de champ, valeur d'état), pas un mot de passe
    return _looks_real(value, 2.8)


# (clé, gravité, expression, groupe de la valeur, validateur ou None). Clés = codes `js_secrets.type_<clé>`.
PATTERNS = [
    ("aws_access_key", "critical", r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b", 0, _aws_ok),
    (
        "aws_secret_key",
        "critical",
        r"aws[_\-]?secret[_\-]?(?:access[_\-]?)?key[\"']?\s{0,3}[:=]\s{0,3}[\"']([A-Za-z0-9/+=]{40})[\"']",
        1,
        _looks_real,
    ),
    ("stripe_live_key", "critical", r"\b(?:sk|rk)_live_[0-9A-Za-z]{24,}\b", 0, None),
    ("github_token", "critical", r"\b(?:gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{22,})\b", 0, None),
    (
        "private_key",
        "critical",
        r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |ENCRYPTED )?PRIVATE KEY-----",
        0,
        None,
    ),
    (
        "jwt",
        "high",
        r"\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b",
        0,
        _jwt_ok,
    ),
    ("slack_token", "high", r"\bxox[baprs]-[A-Za-z0-9-]{10,}", 0, None),
    ("sendgrid_key", "high", r"\bSG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}\b", 0, None),
    ("mailgun_key", "high", r"\bkey-[0-9a-f]{32}\b", 0, _looks_real),
    ("twilio_sid", "medium", r"\bAC[a-f0-9]{32}\b", 0, _twilio_ok),
    ("google_api_key", "medium", r"\bAIza[0-9A-Za-z_-]{35}\b", 0, None),
    ("stripe_publishable_key", "low", r"\bpk_live_[0-9A-Za-z]{24,}\b", 0, None),
    ("firebase_config", "low", r"\bfirebaseConfig\s{0,3}=\s{0,3}\{", 0, None),
    (
        "generic_api_key",
        "medium",
        r"[\"']?api[_\-]?key[\"']?\s{0,3}[:=]\s{0,3}[\"']([A-Za-z0-9_\-]{20,64})[\"']",
        1,
        _generic_ok,
    ),
    (
        "hardcoded_password",
        "medium",
        r"[\"']?(?:password|passwd|pwd)[\"']?\s{0,3}[:=]\s{0,3}[\"']([^\"'\s<>{}$\\]{8,64})[\"']",
        1,
        _password_ok,
    ),
    ("bearer_token", "low", r"\bBearer\s{1,3}([A-Za-z0-9_\-.=]{20,})", 1, _generic_ok),
]
# Motifs insensibles à la casse (noms de variables) ; les formats de jetons, eux, sont exacts.
_IGNORE_CASE = frozenset(
    {"aws_secret_key", "firebase_config", "generic_api_key", "hardcoded_password", "bearer_token"}
)
_COMPILED = [
    (key, severity, re.compile(pattern, re.I if key in _IGNORE_CASE else 0), group, validator)
    for key, severity, pattern, group, validator in PATTERNS
]
SEVERITY_ORDER = ("critical", "high", "medium", "low")


def scan_secrets(text: str, source: str) -> list[dict]:
    """Secrets d'un texte JavaScript : [{type, severity, value_redacted, source, line}], valeurs masquées.

    `source` : URL du fichier, ou « inline » pour les scripts de la page. Au plus
    MAX_PER_PATTERN_FILE constats par motif et par source.
    """
    found: list[dict] = []
    for key, severity, pattern, group, validator in _COMPILED:
        seen: set[str] = set()
        kept = 0
        for match in pattern.finditer(text):
            value = match.group(group)
            if not value or value in seen:
                continue
            seen.add(value)
            if validator is not None and not validator(value):
                continue
            found.append(
                {
                    "type": key,
                    "severity": severity,
                    "value_redacted": redact(value, key),
                    "source": source[:200],
                    "line": text.count("\n", 0, match.start()) + 1,
                }
            )
            kept += 1
            if kept >= MAX_PER_PATTERN_FILE or len(seen) >= 50:
                break
    return found


def count_by_severity(secrets: list[dict]) -> dict[str, int]:
    return {level: sum(1 for s in secrets if s.get("severity") == level) for level in SEVERITY_ORDER}


# --- Points d'accès d'API ------------------------------------------------------------------------

# Chemins relatifs cités comme appels : fetch("/x"), axios.get("/x"), "/api/…", "/v2/…", "/graphql", url: "/x".
_Q = r"[\"'`]"
_PATH = r"(/[^\"'`<>\s]{2,200})"
_ENDPOINT_PATTERNS = [
    re.compile(rf"\bfetch\(\s{{0,3}}{_Q}{_PATH}{_Q}"),
    re.compile(rf"\baxios(?:\.[a-z]{{3,6}})?\(\s{{0,3}}{_Q}{_PATH}{_Q}"),
    re.compile(
        rf"\b(?:url|endpoint|path|href|baseURL|apiUrl)[\"']?\s{{0,3}}[:=]\s{{0,3}}{_Q}{_PATH}{_Q}", re.I
    ),
    re.compile(rf"{_Q}(/api(?:/[^\"'`<>\s]{{1,200}})?){_Q}"),
    re.compile(rf"{_Q}(/v\d{{1,2}}/[^\"'`<>\s]{{1,200}}){_Q}"),
    re.compile(rf"{_Q}(/(?:rest|graphql|oauth2?|auth|wp-json)(?:/[^\"'`<>\s]{{0,200}})?){_Q}"),
]
_ABSOLUTE_URL_RE = re.compile(r"https?://[A-Za-z0-9.\-]{3,100}(?::\d{2,5})?(?:/[^\"'`<>\s\)]{0,200})?")
_STATIC_SUFFIX_RE = re.compile(
    r"\.(?:png|jpe?g|gif|svg|webp|ico|css|map|woff2?|ttf|eot|otf|mp4|webm|mp3|pdf|html?|txt|md)(?:[?#].*)?$",
    re.I,
)
_JUNK_PATH_RE = re.compile(r"[*{}()\[\]|^$\<>]|//|^/[.>]")
_API_PATH_RE = re.compile(r"/(?:api|v\d{1,2}|rest|graphql)(?:/|$)")
_SENSITIVE_PATH_RE = re.compile(
    r"/(?:admin|internal|debug|actuator|swagger|api-docs|openapi|graphiql|phpinfo|\.git|\.env|backup|private|console)"
    r"(?:[/?#.-]|$)",
    re.I,
)

# Hôtes de simples liens de documentation ou d'espaces de noms : ni API ni dépendance réelle.
NOISE_HOSTS = (
    "w3.org",
    "schema.org",
    "ogp.me",
    "reactjs.org",
    "react.dev",
    "mozilla.org",
    "github.com",
    "githubusercontent.com",
    "apache.org",
    "creativecommons.org",
    "jquery.org",
    "gnu.org",
    "opensource.org",
    "wikipedia.org",
    "fb.me",
    "example.com",
    "example.org",
    "localhost",
    "stackoverflow.com",
    "npmjs.com",
    "nodejs.org",
    "json-schema.org",
    "xmlns.com",
    "purl.org",
)


def _is_noise(host: str) -> bool:
    return any(host == d or host.endswith("." + d) for d in NOISE_HOSTS)


def extract_endpoints(text: str, site: str) -> tuple[set[str], set[str], set[str]]:
    """(endpoints internes, hôtes externes, API externes) cités dans un texte JavaScript.

    Un endpoint interne est un chemin « /… » ; une API externe est un hôte hors du site dont
    l'adresse relève d'une API (hôte « api.… », chemin /api, /vN/, /graphql).
    """
    internal: set[str] = set()
    for pattern in _ENDPOINT_PATTERNS:
        for match in pattern.finditer(text):
            path = match.group(1).strip()
            if (
                3 <= len(path) <= 200
                and not _JUNK_PATH_RE.search(path)
                and not _STATIC_SUFFIX_RE.search(path)
            ):
                internal.add(path)
    hosts: set[str] = set()
    apis: set[str] = set()
    for match in _ABSOLUTE_URL_RE.finditer(text):
        url = match.group(0)
        host = host_of_url(url)
        if not host or "." not in host:
            continue
        path = urlsplit(url).path.lower()
        if same_site(host, site):
            if len(path) > 2 and _API_PATH_RE.search(path) and not _STATIC_SUFFIX_RE.search(path):
                internal.add(path[:200])
            continue
        if _is_noise(host):
            continue
        hosts.add(host)
        if host.startswith("api.") or _API_PATH_RE.search(path):
            apis.add(host)
    return internal, hosts, apis


def sensitive_endpoints(endpoints) -> list[str]:
    """Points d'accès dont le nom évoque une administration, un débogage ou une documentation d'API."""
    return sorted(e for e in endpoints if _SENSITIVE_PATH_RE.search(e))[:20]


_SOURCE_MAP_RE = re.compile(r"[/#]{2}[#@]\s{0,3}sourceMappingURL=([^\s'\"]{1,300})")


def source_map_reference(text: str) -> str | None:
    """Référence « sourceMappingURL » en fin de fichier (les 2 000 derniers caractères), ou None."""
    matches = list(_SOURCE_MAP_RE.finditer(text[-2000:]))
    match = matches[-1] if matches else None
    if match is None or match.group(1).startswith("data:"):
        return None
    return match.group(1)
