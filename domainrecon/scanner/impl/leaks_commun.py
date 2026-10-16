# =============================================================================
# DomainRecon - Outils communs aux modules de la famille « leaks »
# =============================================================================
# Partagé par hibp, leakix, intelx, github_dork, paste et emailrep :
#   - requête HTTP bornée (corps limité, flux) vers un service tiers, avec des
#     erreurs sans clé ni URL (jamais str(exception httpx)) ;
#   - masquage : une valeur sensible (identifiant, jeton, adresse e-mail,
#     mot de passe) n'est JAMAIS enregistrée en clair dans un résultat ;
#   - reconnaissance d'un nom de domaine « en entier » (évite les faux positifs
#     « notexample.com » pour « example.com »).
# Aucun accès réseau ici hors du client HTTP passé en paramètre (le client du
# scan : TLS vérifié, sans redirection, proxy et anti-SSRF).
# =============================================================================

import json
import re
from dataclasses import dataclass, field

import httpx

from ...i18n import msg
from ..errors import ModuleError, TargetNotAllowedError
from ..http_utils import read_body_limited
from ..keys import ApiKey

# Taille maximale lue dans la réponse d'un service tiers (2 Mio).
MAX_API_BYTES = 2 * 1024 * 1024

# Erreurs d'une requête vers un service tiers.
REQUEST_ERRORS = (httpx.HTTPError, httpx.InvalidURL, TargetNotAllowedError)


# =============================================================================
# Clés API partagées (déclarations identiques d'un module à l'autre)
# =============================================================================


def github_key(*, required: bool) -> ApiKey:
    """Jeton GitHub (github_dork l'exige, paste l'accepte)."""
    return ApiKey(name="github_token", service="github", label="GitHub", required=required)


def intelx_key(*, required: bool) -> ApiKey:
    """Clé Intelligence X (intelx l'exige, paste l'accepte)."""
    return ApiKey(name="intelx_key", service="intelx", label="Intelligence X", required=required)


# =============================================================================
# Requêtes bornées
# =============================================================================


@dataclass
class Reply:
    """Réponse d'un service tiers : statut, en-têtes (minuscules) et corps borné."""

    status: int
    headers: dict[str, str] = field(default_factory=dict)
    body: bytes = b""
    truncated: bool = False

    @property
    def text(self) -> str:
        return self.body.decode("utf-8", errors="replace")

    def json(self) -> object:
        """Corps JSON ; lève ValueError s'il n'en est pas un (page HTML, corps tronqué…)."""
        if self.truncated:
            raise ValueError("corps tronqué")
        return json.loads(self.body.decode("utf-8-sig"))


async def request(
    client: httpx.AsyncClient,
    method: str,
    url: str,
    *,
    headers: dict[str, str] | None = None,
    params: dict[str, object] | None = None,
    json_body: object | None = None,
    timeout: float = 15.0,
    max_bytes: int = MAX_API_BYTES,
) -> Reply:
    """Requête vers un service tiers, corps lu en flux et borné. Lève httpx.HTTPError (voir REQUEST_ERRORS)."""
    async with client.stream(
        method, url, headers=headers, params=params, json=json_body, timeout=timeout
    ) as response:
        body, truncated = await read_body_limited(response, max_bytes)
        return Reply(
            status=response.status_code,
            headers={k.lower(): v for k, v in response.headers.items()},
            body=body,
            truncated=truncated,
        )


def network_error(label: str, error: BaseException) -> ModuleError:
    """Échec réseau d'un service : seul le nom de la classe est donné (l'URL d'une erreur httpx peut citer une clé)."""
    if isinstance(error, httpx.TimeoutException):
        return ModuleError(msg("network.service_error", context=label, detail=msg("net.timeout")))
    return ModuleError(msg("network.service_error", context=label, detail=type(error).__name__))


def status_error(label: str, status: int) -> ModuleError:
    """Réponse HTTP inattendue : quota (429) ou code d'état."""
    if status == 429:
        return ModuleError(msg("network.quota", service=label))
    return ModuleError(msg("network.http_status", status=status, service=label))


def retry_after(reply: Reply, default: float = 0.0) -> float:
    """Délai demandé par l'en-tête Retry-After (secondes), sinon `default`."""
    try:
        return max(0.0, float(reply.headers.get("retry-after", "")))
    except ValueError:
        return default


# =============================================================================
# Reconnaissance d'un domaine
# =============================================================================


def domain_pattern(domain: str) -> re.Pattern[str]:
    """Le domaine (ou l'un de ses sous-domaines) en entier : « example.com » ne reconnaît pas « notexample.com »."""
    return re.compile(
        r"(?<![A-Za-z0-9-])(?:[A-Za-z0-9-]+\.)*" + re.escape(domain.lower()) + r"(?![A-Za-z0-9-])",
        re.IGNORECASE,
    )


def mentions_domain(text: str, domain: str) -> bool:
    return bool(domain_pattern(domain).search(text or ""))


def strip_html(text: str, limit: int = 300) -> str:
    """Texte sans balises, balises HTML remplacées par une espace, borné."""
    plain = re.sub(r"\s+", " ", re.sub(r"<[^>]+>", " ", text or "")).strip()
    return plain[:limit]


# =============================================================================
# Masquage
# =============================================================================

# Secrets reconnus par leur forme : (type, expression). Le type est un identifiant technique
# affiché tel quel (nom du fournisseur ou du format).
SECRET_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("aws_access_key", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")),
    ("github_token", re.compile(r"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36,}\b")),
    ("github_token", re.compile(r"\bgithub_pat_[A-Za-z0-9_]{50,}\b")),
    ("stripe_key", re.compile(r"\b[sr]k_live_[0-9A-Za-z]{20,}\b")),
    ("slack_token", re.compile(r"\bxox[abprs]-[0-9A-Za-z-]{10,}\b")),
    ("google_api_key", re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b")),
    ("private_key", re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY(?: BLOCK)?-----")),
    ("bearer_token", re.compile(r"\b[Bb]earer\s+[A-Za-z0-9_.~+/=-]{24,}")),
    (
        "password_assignment",
        # Nom de champ contenant le mot-clé (DB_PASSWORD, aws_secret_access_key, apiKey…) puis « = » ou « : ».
        re.compile(
            r"(?i)\b[\w.-]{0,40}(?:passw(?:or)?d|pwd|secret|api[_-]?key|access[_-]?key)[\w.-]{0,40}"
            r"[\"']?\s*[:=]\s*[\"']?[^\s\"',;]{6,}"
        ),
    ),
)

_EMAIL = re.compile(r"[A-Za-z0-9._%+-]+@([A-Za-z0-9.-]+\.[A-Za-z]{2,})")
_ASSIGNED = re.compile(
    r"(?i)(\b[\w.-]{0,40}(?:passw(?:or)?d|pwd|secret|token|api[_-]?key|access[_-]?key|authorization)[\w.-]{0,40}"
    r"[\"']?\s*[:=]\s*[\"']?)[^\s\"',;]+"
)
_SQL_VALUES = re.compile(r"(?i)(\bvalues\s*)\([^)]*\)")
_LONG_TOKEN = re.compile(r"\b[A-Za-z0-9+/_-]{32,}\b")
_CONTROL = re.compile(r"[\x00-\x08\x0b-\x1f\x7f]")


def mask_secret(value: str) -> str:
    """Valeur secrète masquée : quatre premiers caractères au plus, le reste jamais."""
    value = str(value)
    return value[:4] + "****" if len(value) > 12 else "****"


def mask_email(address: str) -> str:
    """Adresse masquée : première lettre de la partie locale, puis ***, domaine conservé."""
    local, _, domain = str(address).partition("@")
    if not domain:
        return mask_secret(address)
    return f"{local[:1]}***@{domain.lower()}"


def mask_text(text: str, limit: int = 160) -> str:
    """Extrait de texte sans valeur sensible : e-mails, mots de passe, jetons reconnus ou longs sont masqués."""
    cleaned = _CONTROL.sub(" ", str(text or ""))
    cleaned = re.sub(r"\s+", " ", cleaned).strip()
    # Valeurs d'un INSERT SQL (identifiants, condensats) : masquées en bloc, après les adresses.
    cleaned = _EMAIL.sub(lambda m: mask_email(m.group(0)), cleaned)
    cleaned = _SQL_VALUES.sub(r"\1(****)", cleaned)
    cleaned = _ASSIGNED.sub(lambda m: m.group(1) + "****", cleaned)
    for _, pattern in SECRET_PATTERNS[:-1]:
        cleaned = pattern.sub(lambda m: mask_secret(m.group(0)), cleaned)
    cleaned = _LONG_TOKEN.sub(lambda m: mask_secret(m.group(0)), cleaned)
    return cleaned[:limit]


# Valeurs d'exemple qui ne sont pas de vrais secrets (faux positifs : modèles, documentation).
_PLACEHOLDER_START = (
    "$", "<", "{", "%", "[", "your", "xxx", "***", "change", "example", "password", "secret", "todo",
    "null", "none", "false", "true", "env", "process", "os.", "config", "settings", "getenv",
)  # fmt: skip


def is_placeholder(value: str) -> bool:
    """Valeur d'exemple (« changeme », « ${DB_PASSWORD} », « <mot-de-passe> »…) et non un secret réel."""
    low = value.strip("\"'` ").lower()
    return not low or low.startswith(_PLACEHOLDER_START) or len(set(low)) <= 2


def find_secrets(content: str, limit: int = 10) -> list[dict]:
    """Secrets reconnus dans un contenu : [{type, masked}] sans doublon, valeurs masquées, bornés."""
    found: list[dict] = []
    seen: set[str] = set()
    for kind, pattern in SECRET_PATTERNS:
        for match in pattern.finditer(content or ""):
            raw = match.group(0)
            if kind == "password_assignment":
                # Seul le nom du champ est gardé : la valeur d'un mot de passe n'est jamais enregistrée.
                parts = re.split(r"\s*[:=]\s*", raw, maxsplit=1)
                name, value = parts[0], parts[1] if len(parts) > 1 else ""
                if is_placeholder(value):
                    continue
                masked = name.strip(" \"'") + "=****"
            elif kind == "private_key":
                masked = "BEGIN PRIVATE KEY"  # l'en-tête d'une clé privée n'est pas le secret ; le corps n'est pas lu
            else:
                masked = mask_secret(raw)
            key = f"{kind}:{masked}"
            if key in seen:
                continue
            seen.add(key)
            found.append({"type": kind, "masked": masked})
            if len(found) >= limit:
                return found
    return found
