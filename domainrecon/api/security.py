# =============================================================================
# DomainRecon - API : en-têtes de sécurité, contrôle de Host, jeton, taille du corps,
# requêtes locales et même origine
# =============================================================================

import ipaddress
import logging
import secrets
from collections.abc import Callable, Iterable, Mapping
from urllib.parse import urlsplit

from fastapi import Request
from starlette.datastructures import Headers, MutableHeaders
from starlette.middleware.cors import CORSMiddleware
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from ..core import config
from ..i18n import msg
from .errors import ApiError, error_response, scope_lang

logger = logging.getLogger(__name__)

# Taille maximale d'un corps de requête : les plus gros corps légitimes (notes
# de 10 000 caractères) restent très en dessous.
MAX_REQUEST_BODY_BYTES = 1024 * 1024


# =============================================================================
# Middlewares
# =============================================================================

SECURITY_HEADERS = {
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "no-referrer",
    "X-Frame-Options": "DENY",
}

# Content-Security-Policy : une politique par sorte de réponse, choisie par
# SecurityHeadersMiddleware d'après le chemin vu par le routeur (root_path
# retiré). Tout ce qui est sous /api et n'est pas une page de la documentation
# (JSON de l'API, captures PNG, erreurs de /api) reçoit API_CSP : ces réponses
# ne sont pas des pages, rien n'y est chargé ni exécuté. Seuls les styles en
# ligne restent permis : ceux que le navigateur applique lui-même à une capture
# ouverte directement dans un onglet (visionneuse d'images).
API_CSP = "default-src 'none'; style-src 'unsafe-inline'; frame-ancestors 'none'"

# Interface (build React + Vite servi par spa.py) : tout vient de la même
# origine, sans script ni style en ligne ni eval, sans aucune origine externe :
# la carte géographique est un fond vectoriel embarqué (Natural Earth). data: et
# blob: servent aux images générées (captures chargées par fetch avec le jeton d'API).
FRONTEND_CSP = "; ".join(
    (
        "default-src 'self'",
        "script-src 'self'",
        "style-src 'self'",
        "img-src 'self' data: blob:",
        "font-src 'self'",
        "connect-src 'self'",
        "object-src 'none'",
        "base-uri 'none'",
        "form-action 'self'",
        "frame-ancestors 'none'",
    )
)

# Documentation interactive (Swagger UI, ReDoc) : pages générées par FastAPI,
# sans donnée de scan, qui chargent scripts et styles sur cdn.jsdelivr.net et
# les lancent par un script en ligne. Aucune restriction de chargement, pour
# ne pas les casser : seulement les directives sans effet sur elles.
DOCS_CSP = "object-src 'none'; base-uri 'none'; frame-ancestors 'none'"


class SecurityHeadersMiddleware:
    """En-têtes de sécurité sur toutes les réponses, erreurs 500 comprises.

    Content-Security-Policy selon la réponse : FRONTEND_CSP pour l'interface
    (tout chemin hors /api), DOCS_CSP pour les pages de `docs_paths`, API_CSP
    pour /api. Une exception non gérée devient un 500 générique : le détail ne part que
    dans les journaux, jamais vers le client.
    """

    def __init__(self, app: ASGIApp, docs_paths: Iterable[str] = ()) -> None:
        self.app = app
        self.docs_paths = frozenset(docs_paths)

    def content_security_policy(self, scope: Scope) -> str:
        path = _route_path(scope)
        if path in self.docs_paths:
            return DOCS_CSP
        if is_api_path(path):
            return API_CSP
        return FRONTEND_CSP

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        response_started = False
        policy = self.content_security_policy(scope)

        async def send_with_headers(message: Message) -> None:
            nonlocal response_started
            if message["type"] == "http.response.start":
                response_started = True
                headers = MutableHeaders(scope=message)
                for name, value in SECURITY_HEADERS.items():
                    headers.setdefault(name, value)
                headers.setdefault("Content-Security-Policy", policy)
            await send(message)

        try:
            await self.app(scope, receive, send_with_headers)
        except Exception:
            if response_started:
                raise
            logger.exception("Erreur non gérée sur %s %s", scope.get("method"), scope.get("path"))
            response = error_response(500, msg("api.internal_error"), scope_lang(scope))
            await response(scope, receive, send_with_headers)


def trusted_host_patterns(hosts: list[str]) -> list[str]:
    """Motifs de TrustedHostMiddleware à partir de ALLOWED_HOSTS.

    Minuscules, port retiré ; une IPv6 est acceptée avec ou sans crochets
    (Starlette compare l'hôte tel que reçu, crochets compris). Un motif
    invalide est ignoré avec un avertissement au lieu de faire échouer
    chaque requête.
    """
    patterns: list[str] = []
    for raw in hosts:
        host = raw.strip().lower()
        if host == "*":
            return ["*"]
        bare = host[1:-1] if host.startswith("[") and host.endswith("]") else host
        try:
            ipv6 = ipaddress.IPv6Address(bare)
        except ValueError:
            pass
        else:
            patterns.extend([f"[{ipv6.compressed}]", ipv6.compressed])
            continue
        name, _, port = host.rpartition(":")
        if name and port.isdigit():
            host = name
        if not host or "*" in host[1:] or (host.startswith("*") and not host.startswith("*.")):
            logger.warning("ALLOWED_HOSTS : motif ignoré %r (joker accepté : *.exemple.com)", raw)
            continue
        patterns.append(host)
    return list(dict.fromkeys(patterns))


# Caractères qui n'ont rien à faire dans un nom d'hôte (structure d'URL, espace).
_HOST_FORBIDDEN_CHARS = frozenset("/?#@[]\\ ")


def _request_host(scope: Scope) -> str | None:
    """Nom d'hôte de l'en-tête Host, en minuscules : port retiré, crochets d'une IPv6 conservés.

    None si l'en-tête est absent ou mal formé.
    """
    value = Headers(scope=scope).get("host", "").strip().lower()
    if value.startswith("["):
        end = value.find("]")
        host, rest = value[: end + 1], value[end + 1 :]
        if end == -1 or (rest and not (rest.startswith(":") and rest[1:].isdigit())):
            return None
        try:
            ipaddress.IPv6Address(host[1:-1])
        except ValueError:
            return None
        return host
    host, separator, port = value.partition(":")
    if not host or (separator and not port.isdigit()) or any(c in host for c in _HOST_FORBIDDEN_CHARS):
        return None
    return host


class ConfiguredTrustedHostMiddleware:
    """Contrôle de l'en-tête Host d'après config.ALLOWED_HOSTS.

    Refuse (400, JSON d'erreur api.invalid_host) un Host inconnu : protège
    l'API locale du DNS rebinding, où une page tierce devient « même origine »
    que l'API. `*` désactive le contrôle. Même comportement que le
    TrustedHostMiddleware de Starlette, mais avec la forme d'erreur de l'API
    (le texte brut de Starlette sortait du contrat {detail, code, params}).
    """

    def __init__(self, app: ASGIApp) -> None:
        self.app = app
        self.allowed_hosts = trusted_host_patterns(config.ALLOWED_HOSTS)
        self.allow_any = "*" in self.allowed_hosts

    def _is_allowed(self, host: str) -> bool:
        return any(
            host == pattern or (pattern.startswith("*") and host.endswith(pattern[1:]))
            for pattern in self.allowed_hosts
        )

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if self.allow_any or scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        host = _request_host(scope)
        if host is not None and self._is_allowed(host):
            await self.app(scope, receive, send)
            return
        response = error_response(400, msg("api.invalid_host"), scope_lang(scope))
        await response(scope, receive, send)


class ConfiguredCORSMiddleware(CORSMiddleware):
    """CORS d'après config.CORS_ORIGINS, lue à la construction de la pile de middlewares.

    Le frontend est servi par la même application : par défaut (liste vide),
    aucune origine tierce n'est autorisée. Sans cookies ni identifiants
    partagés (allow_credentials=False) : le jeton d'API voyage dans un en-tête.
    """

    def __init__(self, app: ASGIApp) -> None:
        super().__init__(
            app,
            allow_origins=config.CORS_ORIGINS,
            allow_credentials=False,
            allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE"],
            allow_headers=["*"],
        )


def _route_path(scope: Scope) -> str:
    """Chemin vu par le routeur : root_path retiré, comme le fait Starlette.

    Derrière un proxy (uvicorn --root-path /recon), scope["path"] vaut
    « /recon/api/history » alors que la route servie est « /api/history ».
    """
    path, root_path = scope["path"], scope.get("root_path", "")
    if root_path and path.startswith(root_path) and path[len(root_path) : len(root_path) + 1] in ("", "/"):
        return path[len(root_path) :] or "/"
    return path


def is_api_path(path: str) -> bool:
    """Vrai pour /api et ses sous-chemins (routes JSON) ; faux pour l'interface."""
    return path == "/api" or path.startswith("/api/")


def _token_matches(headers: Headers, token: str) -> bool:
    """Compare le jeton reçu (Authorization: Bearer ou X-API-Token) en temps constant."""
    expected = token.encode("utf-8")
    candidates = []
    scheme, _, value = headers.get("authorization", "").partition(" ")
    if scheme.lower() == "bearer" and value.strip():
        candidates.append(value.strip())
    if headers.get("x-api-token", "").strip():
        candidates.append(headers["x-api-token"].strip())
    # Les en-têtes sont décodés en latin-1 : ré-encodés tels quels en octets.
    return any([secrets.compare_digest(c.encode("latin-1"), expected) for c in candidates])


class ApiTokenMiddleware:
    """Si API_TOKEN est défini, toute requête HTTP exige le jeton (sinon 401),
    sauf sur les chemins de `public_paths` et sur l'interface (GET/HEAD hors /api).

    Liste de chemins publics pour l'API : une route /api ajoutée, ou un chemin
    compris autrement que prévu, reste protégé. Le chemin comparé
    est celui que verra le routeur (root_path retiré) : sans cela,
    `--root-path` suffisait à contourner le contrôle. Le jeton est relu à
    chaque requête (config.API_TOKEN).
    """

    def __init__(self, app: ASGIApp, public_paths: Iterable[str] = ("/", "/api/health")) -> None:
        self.app = app
        self.public_paths = frozenset(public_paths)

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        token = config.API_TOKEN
        if scope["type"] != "http" or not token:
            await self.app(scope, receive, send)
            return
        path = _route_path(scope)
        # L'interface (GET hors /api : page, assets, routes du navigateur) ne
        # contient aucune donnée : publique, pour pouvoir demander le jeton.
        interface = scope.get("method") in ("GET", "HEAD") and not is_api_path(path)
        if path in self.public_paths or interface or _token_matches(Headers(scope=scope), token):
            await self.app(scope, receive, send)
            return
        response = error_response(
            401,
            msg("api.auth_required"),
            scope_lang(scope),
            headers={"WWW-Authenticate": 'Bearer realm="DomainRecon"'},
        )
        await response(scope, receive, send)


class RequestBodyTooLarge(ApiError):
    def __init__(self, message: object | None = None) -> None:
        super().__init__(413, message if message is not None else msg("api.body_too_large"))


# Limite propre à un chemin (POST seulement) : fonction sans argument qui renvoie
# (octets au maximum, message de l'erreur 413). Elle est appelée à chaque requête :
# la limite se règle sans reconstruire la pile de middlewares (tests).
PathLimit = Callable[[], tuple[int, object]]


class BodySizeLimitMiddleware:
    """Refuse (413) un corps de requête plus gros que `max_bytes`.

    Content-Length est vérifié d'emblée ; un corps envoyé par morceaux est
    compté au fil de la lecture. `path_limits` remplace la limite (et le message
    de l'erreur) pour un chemin qui reçoit de gros envois, comme l'import d'une
    ancienne base : le chemin est celui que verra le routeur (root_path retiré).
    """

    def __init__(
        self, app: ASGIApp, max_bytes: int, path_limits: Mapping[str, PathLimit] | None = None
    ) -> None:
        self.app = app
        self.max_bytes = max_bytes
        self.path_limits = dict(path_limits or {})

    def _limit(self, scope: Scope) -> tuple[int, object]:
        """(octets au maximum, message de l'erreur) pour la requête."""
        resolve = self.path_limits.get(_route_path(scope)) if scope.get("method") == "POST" else None
        if resolve is not None:
            return resolve()
        return self.max_bytes, msg("api.body_too_large")

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        max_bytes, too_large = self._limit(scope)
        declared = Headers(scope=scope).get("content-length", "")
        if declared.isdigit() and int(declared) > max_bytes:
            response = error_response(413, too_large, scope_lang(scope))
            await response(scope, receive, send)
            return

        received = 0

        async def limited_receive() -> Message:
            nonlocal received
            message = await receive()
            if message["type"] == "http.request":
                received += len(message.get("body", b""))
                if received > max_bytes:
                    # HTTPException : FastAPI la laisse remonter telle quelle
                    # depuis la lecture du corps, d'où un 413.
                    raise RequestBodyTooLarge(too_large)
            return message

        await self.app(scope, limited_receive, send)


async def require_json_body(request: Request) -> None:
    """Exige `Content-Type: application/json`, sinon 415.

    Défense anti-CSRF indépendante de la version de FastAPI : un formulaire
    ou un fetch cross-origin sans préflight ne peut pas envoyer ce type.
    """
    media_type = request.headers.get("content-type", "").split(";", 1)[0].strip().lower()
    if media_type != "application/json":
        raise ApiError(415, msg("api.json_required"))


# =============================================================================
# Requêtes locales et requêtes de même origine
# =============================================================================


def is_local_client(request: Request) -> bool:
    """Vrai si la requête vient de cette machine (adresse de bouclage, IPv4 ou IPv6)."""
    host = request.client.host if request.client else ""
    if host == "localhost":
        return True
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        return False
    # Un socket à double pile donne ::ffff:127.0.0.1 : c'est la même machine.
    return (getattr(address, "ipv4_mapped", None) or address).is_loopback


async def require_local_client(request: Request) -> None:
    """Réserve la route aux requêtes venues de cette machine, sinon 403 (api.local_only).

    Pour toute action qui agit sur la machine du serveur (ouvrir un dossier, installer
    une tâche système, importer un fichier). L'adresse est celle de la connexion :
    le lanceur n'accorde aucune confiance à X-Forwarded-For (desktop/launcher.py,
    proxy_headers désactivé).
    """
    if not is_local_client(request):
        raise ApiError(403, msg("api.local_only"))


def is_same_origin(request: Request) -> bool:
    """Faux si le navigateur déclare une requête venue d'une autre origine que l'application.

    Sec-Fetch-Site et Origin sont posés par le navigateur lui-même, jamais par le script
    d'une page : un site tiers ne peut pas les falsifier. Une requête sans ces en-têtes
    (curl, script) n'est pas un navigateur que ce site pourrait détourner : acceptée. Une
    origine que l'opérateur a déclarée (CORS_ORIGINS : interface servie ailleurs) est de
    confiance ; le joker « * » n'en fait pas partie, il ne désigne aucune origine précise.
    """
    origin = request.headers.get("origin")
    if origin is not None and origin in config.CORS_ORIGINS:
        return True
    site = request.headers.get("sec-fetch-site")
    if site is not None and site.strip().lower() not in ("same-origin", "none"):
        return False
    if origin is None:
        return True
    host = request.headers.get("host", "").strip().lower()
    try:
        return bool(host) and urlsplit(origin).netloc.lower() == host
    except ValueError:
        return False


async def require_same_origin(request: Request) -> None:
    """Refuse (403, api.cross_origin) une requête de navigateur venue d'une autre origine.

    Défense anti-CSRF des routes qui reçoivent autre chose que du JSON : un formulaire HTML
    d'un site tiers peut envoyer un corps multipart vers l'API locale sans préflight CORS,
    ce que Content-Type: application/json (require_json_body) interdit ailleurs.
    """
    if not is_same_origin(request):
        raise ApiError(403, msg("api.cross_origin"))
