# =============================================================================
# DomainRecon - Recherche de code public sur GitHub (partagée par github_dork et paste)
# =============================================================================
# Documentation : https://docs.github.com/en/rest/search/search#search-code
#   GET https://api.github.com/search/code?q=<requête>  AUTHENTIFIÉ obligatoire (401
#   « Requires authentication » sans jeton), 30 requêtes par minute avec jeton, plus des
#   limites secondaires (403/429 avec Retry-After). L'en-tête
#   « Accept: application/vnd.github.text-match+json » ajoute à chaque résultat des
#   extraits (text_matches[].fragment) : le domaine y est vérifié sans télécharger le fichier.
# Cette API (recherche historique) ne gère pas « OR » : chaque dork est une requête simple.
# Le jeton ne part QUE vers api.github.com (en-tête Authorization) : le contenu brut
# (raw.githubusercontent.com) est demandé sans lui.
# Valeurs sensibles : un secret trouvé n'est jamais enregistré en clair (type + valeur masquée).
# =============================================================================

import asyncio
import re
import time

import httpx

from ...i18n import msg
from ..errors import ModuleError
from ..score import as_dict, as_list
from .leaks_commun import (
    REQUEST_ERRORS,
    Reply,
    find_secrets,
    mask_text,
    mentions_domain,
    network_error,
    request,
    retry_after,
)

LABEL = "GitHub"
SEARCH_URL = "https://api.github.com/search/code"
ACCEPT = "application/vnd.github.text-match+json"

# Intervalle minimal entre deux recherches (secondes) : la limite est de 30 par minute.
SEARCH_INTERVAL = 2.2
# Attente maximale acceptée avant de reprendre après une limite atteinte, en secondes.
MAX_RATE_WAIT = 30.0
# Nombre maximal de fichiers dont le contenu brut est lu, et taille lue (octets).
MAX_RAW_FILES = 8
MAX_RAW_BYTES = 32 * 1024
# Résultats gardés dans le résultat d'un module.
MAX_RESULTS = 100

# Requêtes simples (le domaine est entre guillemets : expression exacte).
DORKS: tuple[str, ...] = (
    '"{d}"',
    '"{d}" password',
    '"{d}" secret',
    '"{d}" api_key',
    '"{d}" token',
    '"{d}" filename:.env',
    '"{d}" "BEGIN RSA PRIVATE KEY"',
    '"{d}" DATABASE_URL',
    '"{d}" filename:docker-compose.yml',
    '"{d}" filename:config.json',
    '"{d}" extension:pem',
    '"{d}" AKIA',
)

# Fichiers dont le nom suffit à faire craindre un secret.
_SENSITIVE_NAME = re.compile(
    r"""(?ix)
    ^\.env(\..+)?$ | ^id_(rsa|dsa|ecdsa|ed25519)$ | \.(pem|key|p12|pfx|jks|kdbx|ovpn|tfvars|tfstate)$
    | ^(\.htpasswd|\.npmrc|\.pypirc|\.netrc|\.git-credentials|wp-config\.php|database\.yml)$
    | (credentials?|secrets?|passwords?)
    | ^(config|settings|application)(\.[\w-]+)*\.(json|ya?ml|php|py|ini|properties|toml)$
    | ^docker-compose.*\.ya?ml$
    """
)
_BACKUP_PATH = re.compile(r"(?i)(backup|dump|export|\.sql$|\.bak$|\.old$|\.log$)")
_RAW_BLOB = re.compile(r"^https://github\.com/([\w.-]+)/([\w.-]+)/blob/([^/]+)/(.+)$")

SEVERITY_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3}


# -----------------------------------------------------------------------------
# Cadence et limites
# -----------------------------------------------------------------------------

_next_slot = 0.0


async def pace() -> None:
    """Espace les recherches (partagé par tous les modules du processus : une seule limite par jeton)."""
    global _next_slot
    now = time.monotonic()
    wait = max(0.0, _next_slot - now)
    _next_slot = max(now, _next_slot) + SEARCH_INTERVAL
    if wait > 0:
        await asyncio.sleep(wait)


def rate_wait(reply: Reply) -> float | None:
    """Attente demandée par une réponse de limite atteinte (403, 429), None si ce n'en est pas une."""
    if reply.status not in (403, 429):
        return None
    asked = retry_after(reply, -1.0)
    if asked >= 0:
        return asked
    if reply.headers.get("x-ratelimit-remaining") == "0":
        try:
            return max(0.0, float(reply.headers.get("x-ratelimit-reset", "0")) - time.time())
        except ValueError:
            return MAX_RATE_WAIT + 1
    # 403 sans indication de délai : limite secondaire ou refus d'accès ; considéré comme limite.
    return MAX_RATE_WAIT + 1


async def search_code(client: httpx.AsyncClient, token: str, query: str) -> tuple[str, dict | None]:
    """Une recherche de code. Rend (état, données) : « ok » + corps JSON, « rate_limited », « skipped » (422,
    5xx, corps illisible) ; lève ModuleError si le jeton est refusé (401) ou en cas d'échec réseau."""
    headers = {"Authorization": f"Bearer {token}", "Accept": ACCEPT, "X-GitHub-Api-Version": "2022-11-28"}
    for attempt in (1, 2):
        await pace()
        try:
            reply = await request(
                client, "GET", SEARCH_URL, headers=headers, params={"q": query, "per_page": 50}, timeout=20
            )
        except REQUEST_ERRORS as e:
            raise network_error(LABEL, e) from None
        if reply.status == 401:
            raise ModuleError(msg("github_dork.token_rejected"))
        wait = rate_wait(reply)
        if wait is not None:
            if attempt == 1 and wait <= MAX_RATE_WAIT:
                await asyncio.sleep(wait + 1)
                continue
            return "rate_limited", None
        if reply.status != 200:
            return "skipped", None
        try:
            payload = reply.json()
        except ValueError:
            return "skipped", None
        return "ok", as_dict(payload)
    return "rate_limited", None


# -----------------------------------------------------------------------------
# Analyse des résultats
# -----------------------------------------------------------------------------


def classify(filename: str, path: str) -> str:
    """Gravité d'après le nom du fichier : high (secret probable), medium (sauvegarde, export), low."""
    if _SENSITIVE_NAME.search(filename or ""):
        return "high"
    if _BACKUP_PATH.search(path or ""):
        return "medium"
    return "low"


def fragments(item: dict) -> list[str]:
    return [
        str(m.get("fragment") or "")
        for m in as_list(item.get("text_matches"))
        if isinstance(m, dict) and isinstance(m.get("fragment"), str)
    ]


def normalize_item(item: dict, domain: str) -> dict | None:
    """Résultat réduit à des champs sûrs ; None si les extraits ne mentionnent pas vraiment le domaine
    (faux positif : la recherche GitHub est approximative, « example.com » ramène « example » et « com »)."""
    parts = fragments(item)
    if parts and not any(mentions_domain(p, domain) for p in parts):
        return None
    repo = as_dict(item.get("repository"))
    filename = str(item.get("name") or "")[:200]
    path = str(item.get("path") or "")[:400]
    secrets: list[dict] = []
    for part in parts:
        secrets.extend(s for s in find_secrets(part) if s not in secrets)
    snippet = next((mask_text(p, 160) for p in parts if mentions_domain(p, domain)), "")
    return {
        "repo": str(repo.get("full_name") or "")[:200],
        "repo_url": str(repo.get("html_url") or "")[:300],
        "private": repo.get("private") is True,
        "file": filename,
        "path": path,
        "url": str(item.get("html_url") or "")[:500],
        "severity": "critical" if secrets else classify(filename, path),
        "secrets": secrets[:5],
        "snippet": snippet,
    }


def raw_url(html_url: str) -> str | None:
    """URL du contenu brut d'un fichier (https://github.com/o/r/blob/ref/chemin), None si la forme est autre."""
    match = _RAW_BLOB.match(html_url or "")
    if not match:
        return None
    owner, repo, ref, path = match.groups()
    return f"https://raw.githubusercontent.com/{owner}/{repo}/{ref}/{path}"


async def raw_secrets(client: httpx.AsyncClient, html_url: str) -> list[dict]:
    """Secrets reconnus (masqués) dans le début d'un fichier public ; vide si illisible. Sans jeton."""
    url = raw_url(html_url)
    if url is None:
        return []
    try:
        reply = await request(client, "GET", url, timeout=10, max_bytes=MAX_RAW_BYTES)
    except REQUEST_ERRORS:
        return []
    return find_secrets(reply.text)[:5] if reply.status == 200 else []


def sort_results(results: list[dict]) -> list[dict]:
    return sorted(results, key=lambda r: (SEVERITY_RANK.get(r["severity"], 9), r["repo"], r["path"]))
