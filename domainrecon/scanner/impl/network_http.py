# =============================================================================
# DomainRecon - Aides HTTP communes aux modules de la famille « réseau »
# =============================================================================
# Requêtes JSON vers les services tiers (RIPEstat, RDAP, Robtex, Shodan,
# Censys…) avec les mêmes règles partout :
#   - jamais de `raise_for_status()` ni de `str(exception_httpx)` : le texte
#     d'une erreur httpx cite l'URL, donc parfois une clé d'API (?key=…) ;
#   - une erreur réseau devient un ModuleError au message traduisible ;
#   - un code HTTP inattendu ou un quota (429) devient un ModuleError aussi.
# Le client est celui du scan (ScanContext.http : TLS vérifié, aucune
# redirection, proxy du scan, anti-SSRF) ; à défaut, `common._api_client()`.
# =============================================================================

import contextlib
import json
import re
from collections.abc import AsyncIterator, Mapping

import httpx

from ...i18n import msg
from .. import common
from ..errors import ModuleError

# Taille maximale d'une réponse JSON lue (octets) : au-delà, la réponse est jugée illisible.
MAX_JSON_BYTES = 4_000_000

_CONTROL_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")


def clean_text(value: object, limit: int = 300) -> str:
    """Texte affichable venu d'un tiers (bannière, nom) : sans caractère de contrôle, borné."""
    if not isinstance(value, str):
        return ""
    return _CONTROL_RE.sub("", value).strip()[:limit]


@contextlib.asynccontextmanager
async def use_client(
    client: httpx.AsyncClient | None, timeout: float = 15.0
) -> AsyncIterator[httpx.AsyncClient]:
    """Le client du scan s'il existe (non fermé ici), sinon un client d'API tiers ouvert le temps du bloc."""
    if client is not None:
        yield client
        return
    async with common._api_client(timeout=timeout) as own:
        yield own


def status_error(service: str, status: int) -> ModuleError:
    """Erreur d'un code HTTP inattendu (429 : quota dépassé)."""
    if status == 429:
        return ModuleError(msg("network.quota", service=service))
    return ModuleError(msg("network.http_status", status=status, service=service))


def network_error(service: str, exc: BaseException) -> ModuleError:
    """Erreur réseau sans le texte de l'exception (il peut citer l'URL, donc une clé)."""
    if isinstance(exc, httpx.TimeoutException):
        return ModuleError(msg("net.timeout"))
    return ModuleError(msg("network.service_error", context=service, detail=type(exc).__name__))


async def get(
    client: httpx.AsyncClient,
    url: str,
    *,
    service: str,
    params: Mapping[str, str] | None = None,
    headers: Mapping[str, str] | None = None,
    timeout: float = 15.0,
) -> httpx.Response:
    """GET sans suivi de redirection ; lève ModuleError sur une erreur réseau (la clé n'y figure jamais)."""
    try:
        return await client.get(url, params=params, headers=headers, timeout=timeout)
    except httpx.HTTPError as exc:
        raise network_error(service, exc) from None


def parse_json(response: httpx.Response) -> object | None:
    """Corps JSON d'une réponse, ou None s'il est illisible ou démesuré."""
    if len(response.content) > MAX_JSON_BYTES:
        return None
    try:
        return response.json()
    except (ValueError, json.JSONDecodeError):
        return None
