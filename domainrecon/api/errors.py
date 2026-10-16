# =============================================================================
# DomainRecon - API : erreurs et langue des réponses
# =============================================================================
# Toute erreur renvoyée au client a la même forme :
#   {"detail": "<texte dans la langue demandée>", "code": "<code ou null>", "params": {…}}
# (422 : plus "errors", la liste détaillée de Pydantic, dont les messages des
# règles de l'application sont traduits ; detail et code sont alors ceux de la
# première de ces règles, sinon « Requête invalide (champs) »). La langue vient
# de ?lang=, sinon d'Accept-Language, sinon le français.
# =============================================================================

import logging
from http import HTTPStatus
from urllib.parse import parse_qs

from fastapi import FastAPI, HTTPException, Request
from fastapi.encoders import jsonable_encoder
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from sqlalchemy.exc import OperationalError, SQLAlchemyError
from sqlalchemy.exc import TimeoutError as PoolTimeoutError
from starlette.datastructures import Headers
from starlette.exceptions import HTTPException as StarletteHTTPException
from starlette.types import Scope

from ..i18n import DEFAULT_LANG, catalog, is_msg, msg, negotiate_lang, render

logger = logging.getLogger(__name__)

# Emplacements d'un paramètre dans les erreurs de validation (préfixe retiré).
_LOCATIONS = ("body", "query", "path", "header", "cookie")


class ApiError(HTTPException):
    """Erreur HTTP dont le détail est un message traduisible (ou un texte)."""

    def __init__(self, status_code: int, message: object, headers: dict[str, str] | None = None) -> None:
        super().__init__(status_code=status_code, detail=message, headers=headers)
        self.message = message


def scope_lang(scope: Scope) -> str:
    """Langue d'une requête ASGI : ?lang=, sinon Accept-Language, sinon français."""
    query = parse_qs(scope.get("query_string", b"").decode("latin-1"))
    values = query.get("lang") or [None]
    return negotiate_lang(values[0], Headers(scope=scope).get("accept-language"))


def request_lang(request: Request) -> str:
    """Langue des messages de la réponse à `request`."""
    return scope_lang(request.scope)


def error_body(message: object, lang: str) -> dict:
    """Corps d'erreur : texte rendu, code et paramètres (rendus) du message."""
    if is_msg(message):
        return {"detail": render(message, lang), "code": message["$t"], "params": render(message["p"], lang)}
    return {"detail": render(message, lang), "code": None, "params": {}}


def error_response(
    status_code: int, message: object, lang: str, headers: dict[str, str] | None = None
) -> JSONResponse:
    return JSONResponse(error_body(message, lang), status_code=status_code, headers=headers)


def _standard_message(status_code: int, detail: object) -> object:
    """Message des erreurs produites par le routeur (« Not Found », « Method Not Allowed »)."""
    try:
        phrase = HTTPStatus(status_code).phrase
    except ValueError:
        return detail
    if detail == phrase:
        if status_code == 404:
            return msg("api.not_found")
        if status_code == 405:
            return msg("api.method_not_allowed")
    return detail


def _field_name(loc) -> str:
    parts = [str(part) for part in loc]
    if len(parts) > 1 and parts[0] in _LOCATIONS:
        parts = parts[1:]
    return ".".join(parts)


def _translate_rule_errors(errors: list[dict], lang: str) -> dict | None:
    """Rend dans `lang` les messages (errors[].msg) des règles de l'application ; renvoie le premier message.

    Une règle de l'application (schemas._rule_error) a pour type le code d'un
    message du catalogue (« api.… ») et pour contexte ses paramètres ; les types
    de Pydantic (« string_too_long »…) n'en font pas partie et restent tels quels.
    """
    first = None
    for error in errors:
        code = error.get("type")
        if not (isinstance(code, str) and code.startswith("api.") and code in catalog(DEFAULT_LANG)):
            continue
        # Même forme que msg() : le code vient de l'erreur, pas d'un littéral.
        message = {"$t": code, "p": dict(error.get("ctx") or {})}
        error["msg"] = render(message, lang)
        first = first or message
    return first


# Messages de Pydantic qui reprennent le texte d'une exception de validateur
# (« Value error, … ») : ce texte peut citer la valeur soumise, il est retiré.
_GENERIC_MESSAGES = {"value_error": "Value error", "assertion_error": "Assertion failed"}


def _public_errors(errors: list[dict]) -> list[dict]:
    """Erreurs de validation sans la valeur soumise : seuls loc, msg et type sortent.

    `input` reprend l'entrée fautive (clef d'API, mot de passe de proxy…) et
    `ctx` peut la répéter (`error`, `pattern`…) : ni l'un ni l'autre ne doit
    revenir au client. Les paramètres des règles de l'application (ctx) ont déjà
    été rendus dans `params` par _translate_rule_errors.
    """
    public = []
    for error in errors:
        kind = error.get("type")
        message = _GENERIC_MESSAGES.get(kind, error.get("msg"))
        public.append({"loc": error.get("loc", []), "msg": message, "type": kind})
    return public


def install_error_handlers(app: FastAPI) -> None:
    """Gestionnaires d'erreurs : HTTP (404 → interface si besoin), validation, base de données."""

    @app.exception_handler(StarletteHTTPException)
    async def http_error_handler(request: Request, exc: StarletteHTTPException):
        if exc.status_code == 404 and not isinstance(exc, ApiError):
            # 404 du routeur (aucune route) : une route inconnue hors /api rend
            # l'application monopage (spa.py). Un 404 levé par une route
            # (ApiError : scan, capture, asset absents) reste un 404.
            fallback = getattr(request.app.state, "spa_fallback", None)
            if fallback is not None:
                response = fallback(request)
                if response is not None:
                    return response
        message = _standard_message(exc.status_code, exc.detail)
        return error_response(
            exc.status_code, message, request_lang(request), headers=getattr(exc, "headers", None)
        )

    @app.exception_handler(RequestValidationError)
    async def validation_error_handler(request: Request, exc: RequestValidationError):
        lang = request_lang(request)
        # Copies : la traduction réécrit msg, et exc garde ses erreurs d'origine.
        errors = [dict(error) for error in exc.errors()]
        rule = _translate_rule_errors(errors, lang)
        if rule is None:
            fields = ", ".join(dict.fromkeys(_field_name(error.get("loc", ())) for error in errors))
            rule = msg("api.validation_error", fields=fields)
        body = error_body(rule, lang)
        # Jamais la valeur soumise (input, ctx) : une clef d'API ou un mot de passe de proxy
        # refusé par la validation ne doit pas revenir dans la réponse.
        body["errors"] = jsonable_encoder(_public_errors(errors))
        return JSONResponse(body, status_code=422)

    @app.exception_handler(SQLAlchemyError)
    async def database_error_handler(request: Request, exc: SQLAlchemyError):
        """Erreur de base : message générique côté client, détail dans les journaux."""
        logger.error("Erreur de base de données sur %s %s", request.method, request.url.path, exc_info=exc)
        if isinstance(exc, (OperationalError, PoolTimeoutError)):
            return error_response(503, msg("api.database_unavailable"), request_lang(request))
        return error_response(500, msg("api.internal_error"), request_lang(request))
