# =============================================================================
# DomainRecon - Scanner : fichiers web (robots.txt, sitemap.xml, security.txt)
# =============================================================================

import asyncio
import codecs
import re

import httpx

from ..i18n import msg, unique
from .common import _http_client, logger, url_host
from .errors import message_exception
from .http_utils import FetchResult, describe_error, fetch

# Connexion courte : sur un hôte filtré (DROP), chaque tentative ne coûte que
# le délai de connexion, et les fichiers sont demandés en parallèle.
WEB_FILE_TIMEOUT = httpx.Timeout(8.0, connect=4.0)
# Budget de chaque vague (HTTPS, puis HTTP), en secondes. Les deux vagues
# tiennent sous MODULE_TIMEOUT : les fichiers déjà trouvés ne sont jamais
# perdus, même face à des redirections lentes en chaîne.
WEB_FILES_ROUND_BUDGET = 20.0

# Google ignore tout ce qui dépasse 500 Kio dans un robots.txt.
ROBOTS_MAX_BYTES = 512 * 1024
SECURITY_TXT_MAX_BYTES = 64 * 1024
# Le sitemap n'est lu que pour compter ses <loc> : limite plus haute que pour
# une page (un sitemap compte jusqu'à 50 000 URL). Au-delà, le compte est un
# minimum (`truncated`).
SITEMAP_MAX_BYTES = 8 * 1024 * 1024
# Nombre maximal d'entrées conservées par liste (Disallow, Sitemap).
LIST_LIMIT = 200

# (clé du résultat, chemin, taille maximale lue). Pour security.txt, le
# chemin normalisé (/.well-known/) est prioritaire sur l'ancien emplacement.
_WEB_FILES = [
    ("robots_txt", "/robots.txt", ROBOTS_MAX_BYTES),
    ("sitemap_xml", "/sitemap.xml", SITEMAP_MAX_BYTES),
    ("security_txt", "/.well-known/security.txt", SECURITY_TXT_MAX_BYTES),
    ("security_txt", "/security.txt", SECURITY_TXT_MAX_BYTES),
]

_ROBOTS_RE = re.compile(r"^\s*user-agent\s*:", re.I | re.M)
_SECURITY_TXT_RE = re.compile(r"^\s*(contact|policy)\s*:", re.I | re.M)
_LOC_RE = re.compile(r"<loc>", re.I)


# =============================================================================
# Analyse des fichiers (sans réseau)
# =============================================================================


def parse_robots(text: str) -> dict | None:
    if not _ROBOTS_RE.search(text):
        return None
    disallowed, sitemaps = [], []
    for line in text.splitlines():
        line = line.split("#", 1)[0].strip()
        key, _, value = line.partition(":")
        key, value = key.strip().lower(), value.strip()
        if key == "disallow" and value and len(disallowed) < LIST_LIMIT:
            disallowed.append(value)
        elif key == "sitemap" and value and len(sitemaps) < LIST_LIMIT:
            sitemaps.append(value)
    return {"content": text[:3000], "disallowed": disallowed, "sitemaps": sitemaps}


def parse_sitemap(text: str) -> dict | None:
    head = text[:500].lower()
    if "<?xml" not in head[:100] and "<urlset" not in head and "<sitemapindex" not in head:
        return None
    return {"url_count": len(_LOC_RE.findall(text)), "is_index": "<sitemapindex" in head}


def parse_security_txt(text: str) -> dict | None:
    if not _SECURITY_TXT_RE.search(text):
        return None
    contact = None
    for line in text.splitlines():
        key, _, value = line.partition(":")
        if key.strip().lower() == "contact" and value.strip():
            contact = value.strip()
            break
    return {"content": text[:2000], "contact": contact}


_PARSERS = {
    "robots_txt": parse_robots,
    "sitemap_xml": parse_sitemap,
    "security_txt": parse_security_txt,
}


def _file_text(answer: FetchResult) -> str:
    """Texte du fichier, sans BOM UTF-8 initial.

    Le BOM est ignoré, comme Google pour robots.txt, et prime sur le charset
    annoncé : laissé en tête du texte, il masquait la première ligne (souvent
    l'unique User-agent ou Contact).
    """
    if answer.body.startswith(codecs.BOM_UTF8):
        return answer.body[len(codecs.BOM_UTF8) :].decode("utf-8", errors="replace")
    return answer.text


# =============================================================================
# Module 12 : Web Files (robots.txt, sitemap.xml, security.txt)
# =============================================================================


async def _get(client: httpx.AsyncClient, url: str, domain: str, max_bytes: int) -> FetchResult | Exception:
    try:
        return await fetch(client, url, site=domain, max_bytes=max_bytes, timeout=WEB_FILE_TIMEOUT)
    except Exception as e:
        logger.debug("web_files %s: %s", url, e)
        return e


async def _gather_within(coros: list, budget: float) -> list:
    """Lance les coroutines en parallèle ; celles qui dépassent `budget` sont
    annulées et rendent une erreur de délai (les autres résultats sont gardés).
    """
    tasks = [asyncio.ensure_future(coro) for coro in coros]
    try:
        done, pending = await asyncio.wait(tasks, timeout=budget)
    finally:
        # Annulation du module lui-même, ou budget dépassé : rien ne doit survivre.
        for task in tasks:
            if not task.done():
                task.cancel()
    if pending:
        await asyncio.gather(*pending, return_exceptions=True)
    return [
        task.result()
        if task in done
        else message_exception(
            httpx.TimeoutException, msg("web_files.budget_exceeded", seconds=f"{budget:g}")
        )
        for task in tasks
    ]


def _unanswered_reason(answer: FetchResult | Exception) -> object | None:
    """Raison pour laquelle une tentative ne dit rien de la présence du fichier.

    None : réponse probante (fichier servi, ou absent : 404, page HTML,
    redirection hors du site…). Une erreur réseau, une redirection du site
    restée sans réponse, une erreur serveur (5xx) ou un refus temporaire (429)
    laissent la question ouverte.

    La raison est un message traduisible (ou le texte d'une erreur réseau).
    """
    if isinstance(answer, Exception):
        return describe_error(answer)
    if answer.redirect_error and answer.response.has_redirect_location:
        return answer.redirect_error
    if answer.status_code >= 500 or answer.status_code == 429:
        return msg("web_files.http_status", status=answer.status_code)
    return None


async def check_web_files(domain: str) -> dict:
    """Vérifie la présence et le contenu de robots.txt, sitemap.xml, security.txt.

    Les fichiers sont demandés en parallèle en HTTPS, puis en HTTP pour ceux
    qui n'ont pas été trouvés. Un fichier servi par un autre site (redirection
    hors du site ciblé) n'est pas retenu.

    État de chaque fichier (`found`) : True (trouvé), False (absent : chacun
    de ses emplacements a reçu une réponse probante), None (non vérifié, avec
    `error`). Le module est mesuré si au moins un fichier a un état connu ;
    `partial` signale alors les fichiers non vérifiés.
    Les `error` (de chaque fichier et du module) sont des messages traduisibles
    (voir domainrecon.i18n).
    """
    result = {
        "robots_txt": {"found": None, "content": None, "disallowed": [], "sitemaps": [], "error": None},
        "sitemap_xml": {"found": None, "url_count": 0, "error": None},
        "security_txt": {"found": None, "content": None, "contact": None, "error": None},
        "measured": False,
        "partial": False,
        "error": None,
    }

    # Emplacements ayant reçu une réponse probante, et échecs (schéma, raison)
    # par emplacement.
    answered: set[str] = set()
    failures: dict[str, list[tuple[str, object]]] = {path: [] for _, path, _ in _WEB_FILES}
    pending = list(_WEB_FILES)
    async with _http_client(timeout=10.0) as client:
        for scheme in ("https", "http"):
            if not pending:
                break
            answers = await _gather_within(
                [
                    _get(client, f"{scheme}://{url_host(domain)}{path}", domain, max_bytes)
                    for _, path, max_bytes in pending
                ],
                WEB_FILES_ROUND_BUDGET,
            )
            for (key, path, _), answer in zip(pending, answers, strict=True):
                reason = _unanswered_reason(answer)
                if reason is not None:
                    failures[path].append((scheme.upper(), reason))
                    continue
                answered.add(path)
                if result[key]["found"] or answer.status_code != 200:
                    continue
                parsed = _PARSERS[key](_file_text(answer))
                if parsed is not None:
                    result[key].update(parsed, found=True, url=answer.url, truncated=answer.truncated)
            pending = [item for item in pending if not result[item[0]]["found"]]

    # Un fichier non trouvé n'est absent que si tous ses emplacements ont
    # répondu : un échec réseau ne prouve pas son absence.
    for key in _PARSERS:
        entry = result[key]
        if entry["found"]:
            continue
        unanswered = [path for k, path, _ in _WEB_FILES if k == key and path not in answered]
        if unanswered:
            entry["error"] = msg(
                "common.join",
                items=[
                    msg("web_files.attempt_error", scheme=scheme, path=path, error=reason)
                    for path in unanswered
                    for scheme, reason in failures[path]
                ],
            )
        else:
            entry["found"] = False

    states = [result[key]["found"] for key in _PARSERS]
    result["measured"] = any(state is not None for state in states)
    result["partial"] = result["measured"] and None in states
    if not result["measured"]:
        errors = unique(
            [
                msg("http.scheme_error", scheme=scheme, error=reason)
                for attempts in failures.values()
                for scheme, reason in attempts
            ]
        )
        if not answered:
            result["error"] = msg("http.unreachable", errors=errors)
        else:
            result["error"] = msg("web_files.none_checked", errors=errors)
    return result
