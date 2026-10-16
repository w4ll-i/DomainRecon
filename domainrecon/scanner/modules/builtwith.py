# =============================================================================
# DomainRecon - Module « builtwith » : pile technologique selon BuiltWith (clé facultative)
# =============================================================================
# API actuelle :
#   GET https://api.builtwith.com/v26/api.json?KEY=…&LOOKUP=exemple.com
#   (documentation : https://api.builtwith.com/domain-api ; l'ancienne v21 répond encore).
# BuiltWith recense l'historique des technologies d'un domaine (dates de première et de
# dernière détection), ce que la détection locale (module tech_stack) ne peut pas voir.
#
# Pièges évités :
#   - une clé invalide ou un quota épuisé répondent HTTP 200 avec {"Errors":[{"Code":-2}]} :
#     l'erreur du corps est lue (-2 clé refusée, -3 crédits épuisés) ;
#   - le texte d'une exception était recopié dans le résultat (`str(e)`) : il peut citer l'URL,
#     donc la clé en paramètre. Seul le NOM de l'exception est conservé ;
#   - résultat gardé 24 h en mémoire (chaque appel consomme des crédits).
#
# Clé facultative `builtwith_key` (aucune offre gratuite : l'interface web seule l'est).
# Sans clé, le module est « sans objet » avec un message clair et ne dégrade pas le scan ;
# sa catégorie est donc « passif » et non « cle_api » (qui exige une clé requise).
# Le test de la clé (bouton « Tester ») est celui déjà fourni par l'application.
# =============================================================================

from datetime import datetime, timezone

import httpx

from ...i18n import msg
from .. import common
from ..cache import LONG_TTL, cached
from ..errors import ModuleError
from ..impl.wc_runtime import api_client
from ..keys import ApiKey
from ..registry import ModuleSpec, ScanContext, skip_for_ip_target
from ..score import as_dict, as_list

_API = "https://api.builtwith.com/v26/api.json"
MAX_TECHNOLOGIES = 300

# Codes d'erreur renvoyés dans le corps d'une réponse 200 (https://api.builtwith.com/errorCodes).
_CODE_KEY_REJECTED = -2
_CODE_NO_CREDITS = -3


def skip_reason(context: ScanContext) -> object | None:
    if context.is_ip_target:
        return skip_for_ip_target(context)
    if not context.secrets.get("builtwith_key"):
        return msg("builtwith.no_key")
    return None


def _date(milliseconds: object) -> str | None:
    """Date ISO (jour) d'un horodatage BuiltWith en millisecondes, ou None."""
    if isinstance(milliseconds, bool) or not isinstance(milliseconds, (int, float)) or milliseconds <= 0:
        return None
    try:
        return datetime.fromtimestamp(milliseconds / 1000, tz=timezone.utc).strftime("%Y-%m-%d")
    except (OverflowError, OSError, ValueError):
        return None


def _error_from_body(data: dict) -> ModuleError | None:
    """Erreur signalée dans le corps (HTTP 200) : clé refusée, crédits épuisés, autre."""
    errors = [as_dict(e) for e in as_list(data.get("Errors"))]
    for result in as_list(data.get("Results")):
        errors.extend(as_dict(e) for e in as_list(as_dict(result).get("Errors")))
    if not errors:
        return None
    code = errors[0].get("Code")
    if code == _CODE_KEY_REJECTED:
        return ModuleError(msg("builtwith.key_rejected"))
    if code == _CODE_NO_CREDITS:
        return ModuleError(msg("network.quota", service="BuiltWith"))
    return ModuleError(
        msg(
            "network.service_error", context="BuiltWith", detail=msg("builtwith.error_code", number=str(code))
        )
    )


def parse(data: object) -> dict:
    """Technologies d'une réponse BuiltWith : {technologies, categories, count, paths}. Lève ModuleError."""
    data = as_dict(data)
    if (error := _error_from_body(data)) is not None:
        raise error
    results = as_list(data.get("Results"))
    if not results:
        return {"technologies": [], "categories": {}, "count": 0, "paths": 0}
    paths = as_list(as_dict(as_dict(results[0]).get("Result")).get("Paths"))
    technologies: list[dict] = []
    categories: dict[str, list[str]] = {}
    seen: set[str] = set()
    for path in paths:
        for raw in as_list(as_dict(path).get("Technologies")):
            tech = as_dict(raw)
            name = tech.get("Name")
            if not isinstance(name, str) or not name or name in seen:
                continue
            seen.add(name)
            tag = str(tech.get("Tag") or "other").lower()[:40]
            categories.setdefault(tag, []).append(name)
            technologies.append(
                {
                    "name": name[:80],
                    "category": tag,
                    "first_detected": _date(tech.get("FirstDetected")),
                    "last_detected": _date(tech.get("LastDetected")),
                    "premium": str(tech.get("IsPremium", "")).lower() == "yes",
                }
            )
    return {
        "technologies": technologies[:MAX_TECHNOLOGIES],
        "categories": {tag: names[:50] for tag, names in sorted(categories.items())},
        "count": len(technologies),
        "paths": len(paths),
    }


@cached(LONG_TTL, scope=common.proxy_scope, ignore=("client",))
async def _lookup(client: httpx.AsyncClient, domain: str, key: str) -> dict:
    """Interroge BuiltWith (résultat gardé 24 h : chaque appel consomme des crédits)."""
    try:
        response = await client.get(_API, params={"KEY": key, "LOOKUP": domain}, timeout=20)
    except httpx.HTTPError as e:
        # Jamais str(e) : le texte d'une erreur httpx cite l'URL, donc la clé.
        raise ModuleError(
            msg("network.service_error", context="BuiltWith", detail=type(e).__name__)
        ) from None
    if response.status_code in (401, 403):
        raise ModuleError(msg("builtwith.key_rejected"))
    if response.status_code == 429:
        raise ModuleError(msg("network.quota", service="BuiltWith"))
    if response.status_code != 200:
        raise ModuleError(msg("network.http_status", status=response.status_code, service="BuiltWith"))
    try:
        data = response.json()
    except ValueError:
        raise ModuleError(
            msg("network.service_error", context="BuiltWith", detail=msg("http.protocol_error"))
        ) from None
    return {"measured": True, "error": None, **parse(data)}


async def run(context: ScanContext) -> dict:
    key = context.secrets.get("builtwith_key")
    if not key:  # protégé par skip_reason ; garde-fou si le module est lancé autrement
        raise ModuleError(msg("builtwith.no_key"))
    async with api_client(context, timeout=20) as client:
        return await _lookup(client, context.site, key)


SPEC = ModuleSpec(
    name="builtwith",
    family="web",
    category="passif",
    run=run,
    keys=(ApiKey(name="builtwith_key", service="builtwith", label="BuiltWith", required=False),),
    skip_reason=skip_reason,
    optional=True,
    timeout=40,
    order=217,
)
