# =============================================================================
# DomainRecon - Scanner : sécurité des cookies
# =============================================================================

import calendar
import re
import time

from ..i18n import msg, render
from .common import _http_client, logger
from .http_utils import fetch_first

_SAMESITE_VALUES = ("strict", "lax", "none")

# Analyse d'une date Expires comme les navigateurs (RFC 6265 §5.1.1).
_DATE_DELIMITERS = re.compile(r"[\x09\x20-\x2f\x3b-\x40\x5b-\x60\x7b-\x7e]+")
_DATE_TIME = re.compile(r"(\d{1,2}):(\d{1,2}):(\d{1,2})(?:\D|$)")
_DATE_DAY = re.compile(r"(\d{1,2})(?:\D|$)")
_DATE_YEAR = re.compile(r"(\d{2,4})(?:\D|$)")
_MONTHS = ("jan", "feb", "mar", "apr", "may", "jun", "jul", "aug", "sep", "oct", "nov", "dec")
_MAX_AGE = re.compile(r"-?\d+")


# =============================================================================
# Module 13 : Cookie Security Analysis
# =============================================================================


def parse_cookie_date(value: str) -> int | None:
    """Horodatage UTC d'un attribut Expires, ou None si la date est invalide.

    Algorithme des navigateurs (RFC 6265 §5.1.1) : une date invalide est
    ignorée (cookie de session), et une année sur deux chiffres vaut 19xx de
    70 à 99, 20xx sinon (« 01-Jan-70 » est 1970, pas 2070).
    """
    hms = day = month = year = None
    for token in _DATE_DELIMITERS.split(value):
        if not token:
            continue
        if hms is None and (match := _DATE_TIME.match(token)):
            hms = tuple(int(part) for part in match.groups())
        elif day is None and (match := _DATE_DAY.match(token)):
            day = int(match[1])
        elif month is None and token[:3].lower() in _MONTHS:
            month = _MONTHS.index(token[:3].lower()) + 1
        elif year is None and (match := _DATE_YEAR.match(token)):
            year = int(match[1])

    if hms is None or day is None or month is None or year is None:
        return None
    if year < 70:
        year += 2000
    elif year < 100:
        year += 1900
    hour, minute, second = hms
    if not 1 <= day <= 31 or year < 1601 or hour > 23 or minute > 59 or second > 59:
        return None
    return calendar.timegm((year, month, day, hour, minute, second))


def _is_expired(attrs: dict[str, str]) -> bool:
    """Vrai si la ligne efface le cookie : Max-Age <= 0, sinon Expires passé.

    Max-Age prime sur Expires, sauf s'il est invalide (il est alors ignoré).
    """
    max_age = attrs.get("max-age", "")
    if _MAX_AGE.fullmatch(max_age):
        return int(max_age) <= 0
    expires = parse_cookie_date(attrs["expires"]) if "expires" in attrs else None
    return expires is not None and expires <= time.time()


def parse_set_cookie(raw: str) -> dict:
    """Analyse une ligne Set-Cookie : nom, puis attributs comparés exactement.

    Le nom et la valeur du cookie ne sont jamais pris pour des attributs
    (`secure_session=…` n'a pas le drapeau Secure). `expired` signale une
    ligne qui efface le cookie (Max-Age <= 0 ou Expires passé).
    """
    parts = raw.split(";")
    name = parts[0].split("=", 1)[0].strip()
    attrs: dict[str, str] = {}
    for part in parts[1:]:
        key, _, value = part.partition("=")
        key = key.strip().lower()
        if key:
            attrs[key] = value.strip()

    samesite = attrs.get("samesite", "").lower()
    return {
        "name": name,
        "secure": "secure" in attrs,
        "httponly": "httponly" in attrs,
        "samesite": samesite if samesite in _SAMESITE_VALUES else None,
        "path": attrs.get("path") or "/",
        "domain": attrs.get("domain") or None,
        "expired": _is_expired(attrs),
        "issues": [],
    }


def _grade(total_issues: int, max_issues: int) -> str:
    ratio = 1 - (total_issues / max_issues)
    if ratio >= 0.9:
        return "A"
    if ratio >= 0.7:
        return "B"
    if ratio >= 0.5:
        return "C"
    if ratio >= 0.25:
        return "D"
    return "F"


def analyze_cookie_headers(set_cookie_headers: list[str]) -> dict:
    """Évalue une liste de lignes Set-Cookie (sans réseau).

    Les problèmes de chaque cookie (`issues`) sont des messages traduisibles.
    """
    result = {"cookies": [], "issues": [], "score": "N/A", "cookies_present": False}

    # Un même cookie reposé plus loin dans la chaîne : la dernière valeur l'emporte.
    by_key: dict[tuple, dict] = {}
    for raw in set_cookie_headers:
        cookie = parse_set_cookie(raw)
        if cookie["name"]:
            key = (cookie["name"], cookie["domain"], cookie["path"])
            by_key.pop(key, None)
            # Cookie supprimé : le navigateur l'efface, il n'expose rien.
            if not cookie["expired"]:
                by_key[key] = cookie

    if not by_key:
        return result

    result["cookies_present"] = True
    total_issues = 0
    for cookie in by_key.values():
        if not cookie["secure"]:
            cookie["issues"].append(msg("cookies.no_secure"))
        if not cookie["httponly"]:
            cookie["issues"].append(msg("cookies.no_httponly"))
        if not cookie["samesite"]:
            cookie["issues"].append(msg("cookies.no_samesite"))
        elif cookie["samesite"] == "none" and not cookie["secure"]:
            cookie["issues"].append(msg("cookies.samesite_none_insecure"))
        total_issues += len(cookie["issues"])
        result["cookies"].append(cookie)

    result["score"] = _grade(total_issues, len(result["cookies"]) * 3)
    return result


async def analyze_cookies(domain: str) -> dict:
    """Analyse la sécurité des cookies HTTP posés par le site ciblé.

    Les Set-Cookie de toute la chaîne de redirections du site sont pris en
    compte (un cookie posé sur la 301/302 initiale compte). Une redirection
    vers un autre site n'est pas suivie : ses cookies ne sont pas attribués
    à la cible.
    """
    async with _http_client(timeout=10.0) as client:
        fetched, error = await fetch_first(client, domain, max_bytes=0)

    if fetched is None:
        logger.debug("Analyse des cookies impossible sur %s: %s", domain, render(error, "fr"))
        result = analyze_cookie_headers([])
        result.update(measured=False, error=error, url=None, off_site_redirect=None)
        return result

    headers = [raw for response in fetched.responses for raw in response.headers.get_list("set-cookie")]
    result = analyze_cookie_headers(headers)
    result.update(measured=True, error=None, url=fetched.url, off_site_redirect=fetched.off_site_url)
    return result
