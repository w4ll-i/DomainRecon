# =============================================================================
# DomainRecon - Logique du module « observatory » (MDN HTTP Observatory v2)
# =============================================================================
# L'ancienne API Mozilla (http-observatory.security.mozilla.org, v1) est arrêtée
# (HTTP 502, vérifié le 15/10/2026). Le service est repris par le MDN HTTP
# Observatory :
#   POST https://observatory-api.mdn.mozilla.net/api/v2/scan?host=<hôte>
#   -> {id, details_url, algorithm_version, scanned_at, error, grade, score,
#       status_code, tests_failed, tests_passed, tests_quantity}
# Gratuit, sans clé ; un nouveau scan du même hôte au plus toutes les 60 s. Les
# erreurs sont rendues avec un code HTTP 4xx et {error, message} (« invalid-hostname »).
# La réponse v2 est concise : la liste détaillée des tests n'y figure plus, un lien
# vers le rapport MDN la remplace. Le scan est réalisé par les serveurs de Mozilla,
# pas depuis cette machine : la cible reçoit donc une requête de leur part.
# =============================================================================

import re

import httpx

from ...i18n import msg
from ..cache import MEDIUM_TTL, cached
from ..common import proxy_scope
from ..errors import ModuleError

SCAN_API = "https://observatory-api.mdn.mozilla.net/api/v2/scan"
REPORT_PREFIX = "https://developer.mozilla.org/"
SERVICE = "MDN Observatory"

# Notes de l'Observatory : A+ à F.
_GRADE = re.compile(r"^[A-F][+-]?$")
_ERROR_CODE = re.compile(r"^[a-z0-9_-]{1,60}$")


def _integer(value: object) -> int | None:
    return value if isinstance(value, int) and not isinstance(value, bool) else None


def _service_error(detail: str) -> ModuleError:
    return ModuleError(msg("network.service_error", context=SERVICE, detail=detail))


def interpret(status_code: int, body: object) -> dict:
    """Transforme la réponse de l'API en résultat normalisé ; lève ModuleError si le scan a échoué."""
    if status_code == 429:
        raise ModuleError(msg("network.quota", service=SERVICE))
    data = body if isinstance(body, dict) else {}
    code = data.get("error")
    if isinstance(code, str) and code:
        safe = code if _ERROR_CODE.match(code) else "inconnu"
        raise ModuleError(msg("observatory.scan_error", reason=safe))
    if status_code != 200:
        raise ModuleError(msg("network.http_status", status=status_code, service=SERVICE))
    grade = data.get("grade")
    if not isinstance(grade, str) or not _GRADE.match(grade):
        raise _service_error("format")
    details = data.get("details_url")
    return {
        "measured": True,
        "error": None,
        "grade": grade,
        "score": _integer(data.get("score")),
        "tests_passed": _integer(data.get("tests_passed")),
        "tests_failed": _integer(data.get("tests_failed")),
        "tests_quantity": _integer(data.get("tests_quantity")),
        "scan_id": _integer(data.get("id")),
        "algorithm_version": _integer(data.get("algorithm_version")),
        "scanned_at": str(data.get("scanned_at") or "")[:40] or None,
        "site_status_code": _integer(data.get("status_code")),
        "details_url": details if isinstance(details, str) and details.startswith(REPORT_PREFIX) else None,
    }


@cached(MEDIUM_TTL, scope=proxy_scope, ignore=("client",))
async def scan_host(client: httpx.AsyncClient, host: str) -> dict:
    """Lance (ou relit, selon le service) le scan Observatory de `host`.

    Lève ModuleError si le service est injoignable, saturé, ou si le scan échoue.
    """
    try:
        response = await client.post(SCAN_API, params={"host": host}, timeout=40)
    except httpx.HTTPError as e:
        # Jamais str(e) : le texte d'une erreur httpx cite l'URL.
        raise _service_error(type(e).__name__) from None
    try:
        body = response.json()
    except ValueError:
        body = None
        if response.status_code == 200:
            raise _service_error("JSON") from None
    return interpret(response.status_code, body)
