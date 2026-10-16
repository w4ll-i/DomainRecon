# =============================================================================
# DomainRecon - Module « http_methods » : méthodes HTTP autorisées
# =============================================================================
# Trois requêtes sur la racine du site :
#   - OPTIONS : lit l'en-tête Allow (méthodes annoncées) ;
#   - TRACE puis TRACK (variante IIS) avec un marqueur aléatoire : la méthode est
#     RÉELLEMENT activée si le serveur renvoie la requête dans le corps (Cross-Site
#     Tracing, vol de cookies HttpOnly ou d'en-têtes d'authentification).
# Le module ne se fie pas au seul en-tête Allow (souvent absent des réponses
# OPTIONS), teste TRACE, et distingue « annoncé » de « actif ».
# Une absence d'en-tête Allow n'est jamais présentée comme « aucune méthode
# dangereuse » : le résultat indique si Allow était présent. PUT et DELETE ne sont
# JAMAIS envoyés (ils modifieraient le serveur) : ils sont seulement signalés
# quand Allow les annonce, ce qui peut être légitime pour une API.
# Catégorie « actif » : requêtes forgées au-delà d'une visite normale.
# =============================================================================

import secrets as _secrets

from ...i18n import msg
from .. import common
from ..errors import ModuleError
from ..http_utils import FETCH_ERRORS, FetchResult, describe_error, fetch
from ..registry import ModuleSpec, ScanContext
from ..rules import FindingInput, FindingRule, Outcome, ScoreRule, hit
from ..score import as_dict, as_list

# Méthodes dont l'annonce mérite attention (hors TRACE/TRACK, testées pour de bon).
_DANGEROUS = ("PUT", "DELETE", "CONNECT")
_WEBDAV = ("PROPFIND", "PROPPATCH", "MKCOL", "COPY", "MOVE", "LOCK", "UNLOCK")
_TRACE_METHODS = ("TRACE", "TRACK")
_REQUEST_TIMEOUT = 10.0
_MAX_BODY = 4096


def parse_allow(value: str | None) -> list[str]:
    """Méthodes d'un en-tête Allow, en majuscules, sans doublon (au plus 30)."""
    methods: list[str] = []
    for item in (value or "").split(","):
        method = item.strip().upper()
        if method.isascii() and method.isalpha() and method not in methods:
            methods.append(method)
    return methods[:30]


def trace_reflected(fetched: FetchResult, token: str, method: str) -> bool:
    """Le serveur a-t-il renvoyé la requête TRACE ? (statut 200 et marqueur dans un corps de type écho).

    Un 200 seul ne prouve rien (serveur « fourre-tout ») : le marqueur aléatoire doit être renvoyé,
    avec un type message/http ou une première ligne qui commence par la méthode.
    """
    if fetched.status_code != 200:
        return False
    text = fetched.text
    if token not in text:
        return False
    content_type = fetched.headers.get("content-type", "").lower()
    return content_type.startswith("message/http") or text.lstrip()[: len(method) + 1].upper() == f"{method} "


async def _request(client, url: str, method: str, headers: dict | None = None) -> FetchResult:
    return await fetch(
        client, url, method=method, headers=headers, site=None, max_bytes=_MAX_BODY, max_redirects=0
    )


async def run(context: ScanContext) -> dict:
    host = common.url_host(context.domain)
    errors: list[object] = []
    async with common._http_client(timeout=_REQUEST_TIMEOUT, follow_redirects=False) as client:
        options = url = None
        for scheme in ("https", "http"):
            url = f"{scheme}://{host}/"
            try:
                options = await _request(client, url, "OPTIONS")
                break
            except FETCH_ERRORS as e:
                errors.append(msg("http.scheme_error", scheme=scheme.upper(), error=describe_error(e)))
        if options is None:
            raise ModuleError(msg("http.unreachable", errors=errors))

        allow_header = options.headers.get("allow") or options.headers.get("public")
        allow = parse_allow(allow_header)
        trace: dict[str, dict] = {}
        for method in _TRACE_METHODS:
            token = _secrets.token_hex(8)
            try:
                fetched = await _request(client, url, method, {"X-DomainRecon-Trace": token})
            except FETCH_ERRORS as e:
                trace[method.lower()] = {"tested": False, "enabled": False, "status_code": None}
                common.logger.debug("http_methods %s %s : %s", method, url, type(e).__name__)
                continue
            trace[method.lower()] = {
                "tested": True,
                "enabled": trace_reflected(fetched, token, method),
                "status_code": fetched.status_code,
            }

    advertised = [m for m in allow if m in _DANGEROUS]
    webdav = [m for m in allow if m in _WEBDAV]
    return {
        "measured": True,
        "error": None,
        "url": url,
        "options_status": options.status_code,
        "allow_header_present": bool(allow_header),
        "allow": allow,
        # Annoncées par Allow, jamais testées : peut être légitime (API).
        "advertised_dangerous": advertised + webdav,
        "webdav": bool(webdav),
        "trace": trace.get("trace"),
        "track": trace.get("track"),
        "trace_enabled": any(info["enabled"] for info in trace.values()),
    }


def _check_trace(f: FindingInput) -> object:
    data = as_dict(f.data)
    if data.get("trace_enabled") is not True:
        return None
    methods = [m.upper() for m in _TRACE_METHODS if as_dict(data.get(m.lower())).get("enabled") is True]
    return hit(methods=", ".join(methods))


def _check_dangerous(f: FindingInput) -> object:
    methods = [str(m) for m in as_list(as_dict(f.data).get("advertised_dangerous"))]
    return {"methods": ", ".join(methods)} if methods else None


def _score(data: dict) -> Outcome:
    result = as_dict(data.get("http_methods"))
    if result.get("trace_enabled") is True:
        return Outcome(0, msg("http_methods.score_trace"), True)
    if as_list(result.get("advertised_dangerous")):
        return Outcome(2, msg("http_methods.score_advertised"), True)
    if not any(as_dict(result.get(method)).get("tested") for method in ("trace", "track")):
        # Les requêtes TRACE/TRACK ont échoué : on ne prétend pas qu'elles sont refusées.
        return Outcome(2, msg("http_methods.score_untested"), True)
    if result.get("allow_header_present") is not True:
        return Outcome(3, msg("http_methods.score_no_allow"), True)
    return Outcome(3, msg("http_methods.score_ok"), True)


SPEC = ModuleSpec(
    name="http_methods",
    family="web",
    category="actif",
    run=run,
    order=150,
    timeout=45,
    findings=(
        FindingRule(code="finding.http_methods.trace_enabled", severity="medium", check=_check_trace),
        FindingRule(code="finding.http_methods.dangerous_advertised", severity="low", check=_check_dangerous),
    ),
    score_rules=(ScoreRule(criterion="http_methods", weight=3, evaluate=_score),),
)
