# =============================================================================
# DomainRecon - Contenu web : aides d'exécution partagées par les modules web
# =============================================================================
# Page d'accueil partagée du scan (une seule requête pour tous les modules) et
# client des API tierces du scan (proxy, anti-SSRF, TLS vérifié).
# =============================================================================

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import TYPE_CHECKING

import httpx

from ...i18n import msg
from .. import common
from ..errors import ModuleError
from ..page import HomePage
from .wc_osv import OsvError

if TYPE_CHECKING:  # registry charge les modules, qui importent ce fichier : import différé
    from ..registry import ScanContext


async def require_homepage(context: "ScanContext") -> HomePage:
    """Page d'accueil de la cible ; ModuleError (message traduisible) si aucun schéma n'a répondu."""
    home = await context.homepage()
    if not home.reachable:
        raise ModuleError(home.error or msg("http.unreachable", errors=[]))
    return home


@asynccontextmanager
async def api_client(context: "ScanContext", timeout: float = 15.0) -> AsyncIterator[httpx.AsyncClient]:
    """Client HTTP des API tierces : celui du scan, sinon un client neuf soumis aux mêmes protections."""
    if context.http is not None:
        yield context.http
    else:
        async with common._api_client(timeout=timeout) as client:
            yield client


def osv_error_message(error: OsvError) -> dict:
    """Message traduisible d'un échec d'OSV.dev (jamais le texte d'une exception httpx : il contient l'URL)."""
    if error.kind == "quota":
        return msg("network.quota", service="OSV.dev")
    if error.kind == "http":
        return msg("network.http_status", status=error.status, service="OSV.dev")
    if error.kind == "invalid":
        return msg("network.service_error", context="OSV.dev", detail=msg("http.protocol_error"))
    return msg("network.service_error", context="OSV.dev", detail=msg("http.connect_failed"))
