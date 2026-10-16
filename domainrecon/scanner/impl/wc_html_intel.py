# =============================================================================
# DomainRecon - Contenu web : renseignements extraits du HTML (sans réseau)
# =============================================================================
# Logique du module html_intel : générateur, commentaires, e-mails, actions de
# formulaire, adresses IP internes, chemins de serveur, champs cachés, messages d'erreur techniques.
#
# Défauts corrigés :
#   - e-mails : l'ancien motif prenait « logo@2x.png » pour une adresse ; les
#     extensions de fichiers sont écartées et seul le TEXTE visible et les liens
#     mailto: sont lus (pas les scripts) ;
#   - RGPD : les adresses du site audité sont gardées, celles d'un tiers masquées ;
#   - commentaires : balises conditionnelles et marqueurs de gabarit écartés ; ceux
#     qui évoquent mot de passe, jeton, TODO, chemin ou IP sont signalés ;
#   - formulaires : action analysée (tiers, HTTP en clair, mot de passe en clair).
# =============================================================================

import ipaddress
import re

from ..http_utils import host_of_url, same_site
from .wc_html_facts import PageFacts

MAX_COMMENTS = 10
MAX_EMAILS = 20
MAX_FORMS = 15
COMMENT_TEXT_LIMIT = 160

_EMAIL_RE = re.compile(r"[A-Za-z0-9._%+\-]{1,64}@(?:[A-Za-z0-9\-]{1,63}\.)+[A-Za-z]{2,24}")
# « logo@2x.png », « sprite@3x.webp » : ce sont des fichiers, pas des adresses.
_FILE_TLDS = frozenset(
    {
        "png",
        "jpg",
        "jpeg",
        "gif",
        "svg",
        "webp",
        "avif",
        "ico",
        "css",
        "js",
        "map",
        "woff",
        "woff2",
        "ttf",
        "eot",
        "mp4",
    }
)

# Commentaires sans intérêt : balises conditionnelles d'Internet Explorer, marqueurs de gabarit.
_NOISE_COMMENT_RE = re.compile(
    r"^\s*(?:\[if\b|<!\[endif|/?(?:head|body|header|footer|main|nav|section|div|content|wrapper|container)\b"
    r"|end\b|start\b|begin\b|/?googleoff|/?googleon|#|-+\s*$|=+\s*$|[\w.\-]+:(?:start|end)\s*$)",
    re.I,
)
_SUSPICIOUS_COMMENT_RE = {
    "credential": re.compile(r"\b(?:passw(?:or)?d|pwd|secret|token|api[_\- ]?key|credential)\b", re.I),
    "todo": re.compile(r"\b(?:todo|fixme|hack|workaround)\b", re.I),
    "debug": re.compile(r"\b(?:debug|staging|dev(?:elopment)? server|internal use|admin)\b", re.I),
    "path": re.compile(r"(?:[A-Za-z]:\\[\w.\- ]+\\|/(?:var|home|etc|usr|opt|srv)/[\w.\-/]+)"),
}

_IPV4_RE = re.compile(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])")
_SERVER_PATH_RE = re.compile(
    r"(?:[A-Za-z]:\\(?:[\w.\- ]{1,40}\\)+[\w.\-]{1,60}"
    r"|/(?:var/www|var/lib|home/[\w.\-]{1,30}|usr/(?:local|share)|etc|opt|srv)/[\w./\-]{2,120})"
)

# Messages d'erreur techniques affichés à l'internaute : (clé, expression).
_ERROR_PATTERNS = [
    (
        "php_error",
        re.compile(
            r"(?:Warning|Notice|Fatal error|Parse error|Deprecated)(?:</b>)?:\s.{0,200}?\sin\s(?:<b>)?"
            r"(?:/|[A-Za-z]:\\)[^\s<]+(?:</b>)?\son line\b",
            re.I | re.S,
        ),
    ),
    ("php_error", re.compile(r"\b(?:Fatal error|Parse error):\s.{0,160}\bin\s+(?:/|[A-Za-z]:\\)", re.I)),
    ("python_traceback", re.compile(r"Traceback \(most recent call last\)")),
    ("java_stacktrace", re.compile(r"\bat (?:[A-Za-z_][\w$]*\.){2,}[\w$<>]+\([\w$]+\.java:\d+\)")),
    ("dotnet_error", re.compile(r"\bSystem\.[A-Z]\w+Exception\b|Server Error in '/' Application", re.I)),
    (
        "sql_error",
        re.compile(
            r"You have an error in your SQL syntax|\bSQLSTATE\[\w+\]|\bORA-\d{5}\b|Unclosed quotation mark",
            re.I,
        ),
    ),
]

_SENSITIVE_HIDDEN_RE = re.compile(
    r"pass|secret|api[_\-]?key|private|debug|admin|role|price|amount|salary", re.I
)
_CSRF_NAME_RE = re.compile(r"csrf|xsrf|token|nonce|authenticity", re.I)


def _is_private_ipv4(text: str) -> bool:
    try:
        address = ipaddress.ip_address(text)
    except ValueError:
        return False
    return address.version == 4 and (address.is_private or address.is_loopback) and not address.is_unspecified


def _mask_email(address: str) -> str:
    local, _, domain = address.partition("@")
    return f"{local[:1]}***@{domain}"


def _emails(facts: PageFacts, site: str) -> dict:
    found: dict[str, None] = {}
    for candidate in [*facts.mailto, *_EMAIL_RE.findall(facts.text)]:
        address = candidate.strip().strip(".,;:<>()[]\"'").lower()
        if not _EMAIL_RE.fullmatch(address):
            continue
        domain = address.rsplit("@", 1)[1]
        if domain.rsplit(".", 1)[-1] in _FILE_TLDS:
            continue
        found.setdefault(address, None)
    own: list[str] = []
    other: list[str] = []
    for address in found:
        domain = address.rsplit("@", 1)[1]
        (own if same_site(domain, site) else other).append(address)
    return {
        "own": own[:MAX_EMAILS],
        "third_party_masked": [_mask_email(a) for a in other[:MAX_EMAILS]],
        "total": len(found),
    }


def _comments(facts: PageFacts) -> tuple[list[dict], int]:
    kept: list[dict] = []
    seen: set[str] = set()
    total = 0
    for raw in facts.comments:
        text = " ".join(raw.split())
        if len(text) < 5 or _NOISE_COMMENT_RE.match(text) or text in seen:
            continue
        seen.add(text)
        total += 1
        flags = [key for key, pattern in _SUSPICIOUS_COMMENT_RE.items() if pattern.search(text)]
        if any(_is_private_ipv4(ip) for ip in _IPV4_RE.findall(text)):
            flags.append("internal_ip")
        kept.append({"text": text[:COMMENT_TEXT_LIMIT], "flags": flags})
    # Les commentaires suspects d'abord : ce sont eux que l'on veut lire.
    kept.sort(key=lambda c: not c["flags"])
    return kept[:MAX_COMMENTS], total


def _forms(facts: PageFacts, page_url: str, site: str) -> list[dict]:
    page_https = page_url.lower().startswith("https://")
    result = []
    for form in facts.forms[:MAX_FORMS]:
        action = facts.resolve(form["action"]) if form["action"] else page_url or None
        host = host_of_url(action) if action else ""
        insecure = bool(action) and action.lower().startswith("http://")
        result.append(
            {
                "action": (action or "")[:200],
                "method": form["method"][:10],
                "has_password": form["has_password"],
                "third_party": bool(host) and not same_site(host, site),
                # Formulaire soumis en clair : action http://, ou page en http (rien n'est chiffré).
                "insecure": insecure or (not page_https and bool(page_url)),
                "hidden_fields": len(form["hidden"]),
            }
        )
    return result


def analyze(html: str, page_url: str, site: str) -> dict:
    """Renseignements d'une page HTML : générateur, commentaires, e-mails, formulaires, fuites techniques."""
    facts = PageFacts.parse(html or "", page_url)
    generator = facts.metas.get("generator", "").strip()[:100] or None
    comments, comments_total = _comments(facts)
    comment_text = "\n".join(facts.comments)

    internal_ips = sorted(
        {ip for ip in _IPV4_RE.findall(html or "") if _is_private_ipv4(ip) and not ip.startswith("127.")}
    )[:10]
    server_paths = sorted({m.group(0) for m in _SERVER_PATH_RE.finditer(comment_text)})[:10]

    error_kinds: list[str] = []
    for kind, pattern in _ERROR_PATTERNS:
        if kind not in error_kinds and pattern.search(html or ""):
            error_kinds.append(kind)

    hidden = facts.hidden_inputs
    sensitive_hidden = sorted(
        {
            h["name"]
            for h in hidden
            if _SENSITIVE_HIDDEN_RE.search(h["name"]) and not _CSRF_NAME_RE.search(h["name"])
        }
    )[:10]

    wanted = ("generator", "author", "robots", "referrer", "description")
    return {
        "title": facts.title,
        "generator": generator,
        "generator_has_version": bool(generator and re.search(r"\d+\.\d+", generator)),
        "metas": {k: v[:200] for k, v in facts.metas.items() if k in wanted},
        "comments": comments,
        "comments_total": comments_total,
        "suspicious_comments": sum(1 for c in comments if c["flags"]),
        "emails": _emails(facts, site),
        "forms": _forms(facts, page_url, site),
        "internal_ips": internal_ips,
        "server_paths": server_paths,
        "error_disclosures": error_kinds,
        "hidden_fields": len(hidden),
        "sensitive_hidden_fields": sensitive_hidden,
        "html_length": len(html or ""),
    }
