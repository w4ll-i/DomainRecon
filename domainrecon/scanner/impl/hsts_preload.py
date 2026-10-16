# =============================================================================
# DomainRecon - Logique du module « hsts_preload » (HSTS approfondi et précharge)
# =============================================================================
# Deux sources complémentaires :
#   - l'en-tête Strict-Transport-Security réellement servi (RFC 6797) : max-age,
#     includeSubDomains, preload, note A à F et éligibilité à la précharge ;
#   - l'état dans la liste de précharge des navigateurs, par l'API de
#     hstspreload.org (https://hstspreload.org/api/v2/status) : preloaded,
#     pending ou unknown.
# Fonctions pures pour l'analyse de l'en-tête ; l'API est interrogée avec le
# client des API tierces du scan (TLS vérifié, aucune redirection suivie).
# =============================================================================

import httpx

from ...i18n import msg
from ..cache import MEDIUM_TTL, cached
from ..common import proxy_scope
from ..errors import ModuleError

STATUS_API = "https://hstspreload.org/api/v2/status"
PRELOADABLE_API = "https://hstspreload.org/api/v2/preloadable"

# Durées de référence, en secondes : 180 jours (recommandation minimale) et un an
# (exigence de la liste de précharge).
MIN_MAX_AGE = 15_552_000
PRELOAD_MAX_AGE = 31_536_000

GRADES = ("A", "B", "C", "D", "F")


def parse_hsts(value: str | None) -> dict:
    """Analyse un en-tête Strict-Transport-Security.

    Seul le premier en-tête compte si le serveur en envoie plusieurs (RFC 6797 §8.1) ;
    les directives sont insensibles à la casse, max-age peut être entre guillemets.
    Renvoie present, valid (max-age lisible), max_age, max_age_days,
    include_subdomains, preload, grade, preload_eligible et raw.
    """
    result = {
        "present": False,
        "valid": False,
        "max_age": 0,
        "max_age_days": 0,
        "include_subdomains": False,
        "preload": False,
        "grade": "F",
        "preload_eligible": False,
        "raw": None,
    }
    if not value or not value.strip():
        return result
    first = value.split(",")[0]
    result.update(present=True, raw=value.strip()[:300])
    directives: dict[str, str] = {}
    for part in first.split(";"):
        name, _, raw = part.partition("=")
        name = name.strip().lower()
        if name:
            directives.setdefault(name, raw.strip().strip('"'))
    raw_age = directives.get("max-age", "")
    if raw_age.isascii() and raw_age.isdigit():
        result.update(valid=True, max_age=int(raw_age), max_age_days=int(raw_age) // 86400)
    result["include_subdomains"] = "includesubdomains" in directives
    result["preload"] = "preload" in directives
    result["grade"] = grade(result)
    result["preload_eligible"] = (
        result["valid"]
        and result["max_age"] >= PRELOAD_MAX_AGE
        and result["include_subdomains"]
        and result["preload"]
    )
    return result


def grade(hsts: dict) -> str:
    """Note de l'en-tête : A (un an, sous-domaines, preload), B (un an), C (180 jours), D (court), F (inutile)."""
    if not hsts["present"] or not hsts["valid"] or hsts["max_age"] == 0:
        return "F"
    age = hsts["max_age"]
    if age >= PRELOAD_MAX_AGE and hsts["include_subdomains"] and hsts["preload"]:
        return "A"
    if age >= PRELOAD_MAX_AGE:
        return "B"
    if age >= MIN_MAX_AGE:
        return "C"
    return "D"


def _service_error(response: httpx.Response) -> ModuleError:
    if response.status_code == 429:
        return ModuleError(msg("network.quota", service="hstspreload.org"))
    return ModuleError(msg("network.http_status", status=response.status_code, service="hstspreload.org"))


@cached(MEDIUM_TTL, scope=proxy_scope, ignore=("client",))
async def preload_status(client: httpx.AsyncClient, domain: str) -> dict:
    """État du domaine dans la liste de précharge (API hstspreload.org, sans clé).

    Renvoie status (preloaded, pending, unknown), preloaded_domain et bulk.
    Lève ModuleError si le service est injoignable ou répond de travers.
    """
    try:
        response = await client.get(STATUS_API, params={"domain": domain}, timeout=12)
    except httpx.HTTPError as e:
        # Jamais str(e) : le texte d'une erreur httpx cite l'URL.
        raise ModuleError(
            msg("network.service_error", context="hstspreload.org", detail=type(e).__name__)
        ) from None
    if response.status_code != 200:
        raise _service_error(response)
    try:
        data = response.json()
    except ValueError:
        raise ModuleError(msg("network.service_error", context="hstspreload.org", detail="JSON")) from None
    if not isinstance(data, dict) or data.get("status") not in ("preloaded", "pending", "unknown"):
        raise ModuleError(msg("network.service_error", context="hstspreload.org", detail="format"))
    return {
        "measured": True,
        "error": None,
        "status": data["status"],
        "preloaded_domain": str(data.get("preloadedDomain") or "")[:253] or None,
        "bulk": bool(data.get("bulk")),
    }


@cached(MEDIUM_TTL, scope=proxy_scope, ignore=("client",))
async def preload_blockers(client: httpx.AsyncClient, domain: str) -> dict:
    """Obstacles à la soumission du domaine à la liste (API /preloadable de hstspreload.org).

    Le service examine lui-même le site : c'est lui qui contacte la cible. Renvoie
    les codes d'erreur et d'avertissement (par exemple « preload.missing » ou
    « redirects.http.no_redirect »), jamais leurs textes anglais.
    """
    try:
        response = await client.get(PRELOADABLE_API, params={"domain": domain}, timeout=20)
    except httpx.HTTPError as e:
        raise ModuleError(
            msg("network.service_error", context="hstspreload.org", detail=type(e).__name__)
        ) from None
    if response.status_code != 200:
        raise _service_error(response)
    try:
        data = response.json()
    except ValueError:
        raise ModuleError(msg("network.service_error", context="hstspreload.org", detail="JSON")) from None
    if not isinstance(data, dict):
        raise ModuleError(msg("network.service_error", context="hstspreload.org", detail="format"))

    def codes(key: str) -> list[str]:
        items = data.get(key)
        found = [str(i.get("code"))[:80] for i in items if isinstance(i, dict) and i.get("code")]
        return found[:20] if isinstance(items, list) else []

    return {"measured": True, "error": None, "errors": codes("errors"), "warnings": codes("warnings")}
