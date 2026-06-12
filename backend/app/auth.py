# backend/app/auth.py
"""
Optional API-key authentication.

When the ``DOMAINRECON_API_KEY`` environment variable is set, every request to
an ``/api/*`` route (and the scan WebSocket) must present that key, via either:
  * ``X-API-Key: <key>`` header, or
  * ``Authorization: Bearer <key>`` header, or
  * a ``?key=<key>`` query parameter (mainly for the WebSocket, where setting
    headers from the browser is awkward).

When the variable is unset the middleware is a no-op, preserving the original
open behaviour for local single-user installs.
"""
import hmac
import os
from urllib.parse import parse_qs

from starlette.types import ASGIApp, Receive, Scope, Send

# Paths reachable without a key even when auth is enabled.
_EXEMPT_PATHS = {
    "/",
    "/api/health",
    "/api/docs",
    "/api/redoc",
    "/api/openapi.json",
}


def _configured_key() -> str | None:
    return os.getenv("DOMAINRECON_API_KEY") or None


def _is_protected(path: str) -> bool:
    if path in _EXEMPT_PATHS:
        return False
    return path.startswith("/api")


def _extract_key(scope: Scope) -> str | None:
    headers = {k.decode("latin-1").lower(): v.decode("latin-1") for k, v in scope.get("headers", [])}
    if "x-api-key" in headers:
        return headers["x-api-key"]
    auth = headers.get("authorization", "")
    if auth.lower().startswith("bearer "):
        return auth[7:].strip()
    qs = parse_qs(scope.get("query_string", b"").decode("latin-1"))
    if "key" in qs:
        return qs["key"][0]
    return None


def _valid(provided: str | None, expected: str) -> bool:
    return bool(provided) and hmac.compare_digest(provided, expected)


class ApiKeyAuthMiddleware:
    """Pure-ASGI middleware so it also guards WebSocket connections."""

    def __init__(self, app: ASGIApp):
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        expected = _configured_key()
        if expected is None or scope["type"] not in ("http", "websocket"):
            await self.app(scope, receive, send)
            return

        # Always let CORS preflight through.
        if scope["type"] == "http" and scope.get("method") == "OPTIONS":
            await self.app(scope, receive, send)
            return

        path = scope.get("path", "")
        if not _is_protected(path) or _valid(_extract_key(scope), expected):
            await self.app(scope, receive, send)
            return

        if scope["type"] == "websocket":
            await send({"type": "websocket.close", "code": 1008})
            return

        await send({
            "type": "http.response.start",
            "status": 401,
            "headers": [(b"content-type", b"application/json")],
        })
        await send({
            "type": "http.response.body",
            "body": b'{"detail":"Invalid or missing API key"}',
        })
