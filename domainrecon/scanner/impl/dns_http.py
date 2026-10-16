# =============================================================================
# DomainRecon - Requêtes HTTP aux sources tierces de la famille « dns »
# =============================================================================
# Un seul chemin pour toutes les sources (crt.sh mis à part) : client HTTP du
# scan (ScanContext.http : TLS vérifié, aucune redirection, proxy du scan,
# anti-SSRF) ou, à défaut, common._api_client ; corps lu en streaming et borné ;
# erreurs ramenées à des ModuleError dont le message ne cite jamais l'URL (elle
# peut contenir une clé) ni le texte d'une exception httpx.
# =============================================================================

import contextlib
import json
from collections.abc import AsyncIterator, Mapping
from typing import NamedTuple

import httpx

from ...i18n import msg
from ..common import ACCEPT_ENCODING, _api_client
from ..errors import ModuleError, TargetNotAllowedError
from ..http_utils import read_body_limited

# Corps lu au plus (octets décodés) : une source ne doit pas pouvoir saturer la mémoire.
MAX_BODY_BYTES = 4 * 1024 * 1024


class Reply(NamedTuple):
    """Réponse bornée d'une source."""

    status: int
    body: bytes
    truncated: bool

    @property
    def text(self) -> str:
        return self.body.decode("utf-8", errors="replace")

    def json(self) -> object:
        """Corps JSON ; lève ValueError s'il n'en est pas un."""
        return json.loads(self.body)


@contextlib.asynccontextmanager
async def session(
    client: httpx.AsyncClient | None, timeout: float = 15.0
) -> AsyncIterator[httpx.AsyncClient]:
    """Client à utiliser : celui du scan s'il existe (non fermé ici), sinon un client des API tierces."""
    if client is not None:
        yield client
        return
    async with _api_client(timeout=timeout) as own:
        yield own


async def get(
    client: httpx.AsyncClient,
    url: str,
    *,
    service: str,
    params: Mapping[str, str] | list[tuple[str, str]] | None = None,
    headers: Mapping[str, str] | None = None,
    auth: tuple[str, str] | None = None,
    timeout: float = 15.0,
    max_bytes: int = MAX_BODY_BYTES,
) -> Reply:
    """GET borné ; lève ModuleError (réseau, délai, cible refusée) sans jamais citer l'URL ni l'exception."""
    merged = {"Accept-Encoding": ACCEPT_ENCODING, **(headers or {})}
    try:
        async with client.stream(
            "GET", url, params=params, headers=merged, auth=auth, timeout=timeout
        ) as response:
            body, truncated = await read_body_limited(response, max_bytes)
            return Reply(response.status_code, body, truncated)
    except httpx.TimeoutException:
        raise ModuleError(msg("network.service_error", context=service, detail=msg("net.timeout"))) from None
    except TargetNotAllowedError as e:
        raise ModuleError(e.message) from None
    except httpx.HTTPError as e:
        raise ModuleError(msg("network.service_error", context=service, detail=type(e).__name__)) from None


def status_error(service: str, status: int) -> ModuleError:
    """Erreur HTTP d'une source : quota (429) ou statut inattendu."""
    if status == 429:
        return ModuleError(msg("network.quota", service=service))
    return ModuleError(msg("network.http_status", status=status, service=service))
