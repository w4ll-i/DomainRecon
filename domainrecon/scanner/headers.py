# =============================================================================
# DomainRecon - Scanner : en-têtes de sécurité HTTP
# =============================================================================
# Un en-tête n'est « conforme » que si sa valeur protège réellement :
# `Strict-Transport-Security: max-age=0` ou `X-Frame-Options: ALLOWALL` sont
# présents mais sans effet. Chaque en-tête reçoit un statut :
#   - ok      : valeur protectrice ;
#   - weak    : présent mais permissif (compte pour moitié dans le score) ;
#   - invalid : présent mais sans effet (valeur inconnue, HSTS servi en HTTP
#               ou avec un certificat invalide…) ;
#   - missing : absent ;
#   - info    : jamais noté — en-tête obsolète rapporté à titre indicatif, ou
#               HSTS sur une cible IP, où il est sans effet (RFC 6797 §8.1).
# =============================================================================

from collections.abc import Mapping

import httpx

from ..i18n import msg, unique
from .common import _http_client, logger, url_host
from .http_utils import describe_error, fetch, host_of_url
from .targets import is_ip_literal

# En-têtes notés (critère « headers » du score).
SECURITY_HEADERS = [
    "Strict-Transport-Security",
    "X-Frame-Options",
    "X-Content-Type-Options",
    "Content-Security-Policy",
    "Referrer-Policy",
    "Permissions-Policy",
]

# En-têtes obsolètes : rapportés s'ils sont présents, sans effet sur le score.
# X-XSS-Protection est ignoré par les navigateurs modernes et OWASP recommande
# de l'omettre (ou de le fixer à 0).
INFORMATIONAL_HEADERS = ["X-XSS-Protection"]

# Durée HSTS minimale recommandée : 180 jours.
HSTS_MIN_MAX_AGE = 15_552_000

HEADER_STATUSES = ("ok", "weak", "invalid", "missing")

_REFERRER_OK = {"no-referrer", "same-origin", "strict-origin", "strict-origin-when-cross-origin"}
_REFERRER_WEAK = {"origin", "origin-when-cross-origin", "no-referrer-when-downgrade"}
_REFERRER_INVALID = {"unsafe-url"}

# Sources de script qui autorisent n'importe quel contenu.
_CSP_PERMISSIVE_SOURCES = {"*", "http:", "https:", "data:", "blob:"}
_CSP_HASH_PREFIXES = ("'nonce-", "'sha256-", "'sha384-", "'sha512-")


# =============================================================================
# Validation des valeurs
# =============================================================================


def _check_hsts(value: str, https: bool, cert_valid: bool | None = None) -> tuple[str, object]:
    if not https:
        return "invalid", msg("headers.hsts_http")
    if cert_valid is False:
        return "invalid", msg("headers.hsts_bad_cert")
    # Si l'en-tête est répété, seul le premier est pris en compte (RFC 6797 §8.1).
    directives: dict[str, str] = {}
    for part in value.split(",")[0].split(";"):
        name, _, raw = part.partition("=")
        name = name.strip().lower()
        if name:
            directives.setdefault(name, raw.strip().strip('"'))

    raw_max_age = directives.get("max-age", "")
    if not (raw_max_age.isascii() and raw_max_age.isdigit()):
        return "invalid", msg("headers.hsts_no_max_age")
    max_age = int(raw_max_age)
    if max_age == 0:
        return "invalid", msg("headers.hsts_zero")
    if max_age < HSTS_MIN_MAX_AGE:
        return "weak", msg("headers.hsts_short", max_age=max_age, minimum=HSTS_MIN_MAX_AGE)
    if "includesubdomains" in directives:
        return "ok", msg("headers.hsts_ok_subdomains", max_age=max_age)
    return "ok", msg("headers.hsts_ok", max_age=max_age)


def _parse_csp(value: str) -> list[dict[str, list[str]]]:
    """Découpe une ou plusieurs politiques CSP (séparées par des virgules)."""
    policies = []
    for policy in value.split(","):
        directives: dict[str, list[str]] = {}
        for directive in policy.split(";"):
            tokens = directive.strip().lower().split()
            if tokens:
                # Une directive répétée est ignorée : seule la première compte.
                directives.setdefault(tokens[0], tokens[1:])
        if directives:
            policies.append(directives)
    return policies


def _check_csp_policy(directives: dict[str, list[str]]) -> tuple[str, object]:
    sources = directives.get("script-src", directives.get("default-src"))
    if sources is None:
        return "weak", msg("headers.csp_no_script_rule")

    has_nonce_or_hash = any(s.startswith(_CSP_HASH_PREFIXES) for s in sources)
    issues = []
    # Avec un nonce ou un hash, 'unsafe-inline' est ignoré par les navigateurs.
    if "'unsafe-inline'" in sources and not has_nonce_or_hash:
        issues.append("'unsafe-inline'")
    if "'unsafe-eval'" in sources:
        issues.append("'unsafe-eval'")
    # 'strict-dynamic' avec nonce ou hash neutralise les sources d'hôte et de schéma.
    if not ("'strict-dynamic'" in sources and has_nonce_or_hash):
        issues.extend(s for s in sources if s in _CSP_PERMISSIVE_SOURCES)
    if issues:
        return "weak", msg("headers.csp_weak", sources=", ".join(issues))
    return "ok", msg("headers.csp_ok")


def _check_csp(value: str) -> tuple[str, object]:
    results = [_check_csp_policy(policy) for policy in _parse_csp(value)]
    if not results:
        return "invalid", msg("headers.csp_empty")
    # Plusieurs politiques s'appliquent toutes : la plus stricte l'emporte.
    return next((r for r in results if r[0] == "ok"), results[0])


def _frame_ancestors(csp: str | None) -> list[str] | None:
    """Sources de la directive CSP frame-ancestors, ou None si elle est absente."""
    if not csp:
        return None
    for policy in _parse_csp(csp):
        if "frame-ancestors" in policy:
            return policy["frame-ancestors"]
    return None


def _check_frame_options(value: str | None, csp: str | None) -> tuple[str, object]:
    # Les navigateurs modernes font primer CSP frame-ancestors sur X-Frame-Options.
    ancestors = _frame_ancestors(csp)
    if ancestors is not None:
        if any(s in _CSP_PERMISSIVE_SOURCES for s in ancestors):
            return "invalid", msg("headers.xfo_ancestors_any")
        return "ok", msg("headers.xfo_ancestors_ok")
    if value is None:
        return "missing", msg("headers.missing")

    values = {v.strip().lower() for v in value.split(",") if v.strip()}
    if values and values <= {"deny", "sameorigin"}:
        return "ok", value.strip().upper()
    if any(v.startswith("allow-from") for v in values):
        return "invalid", msg("headers.xfo_allow_from")
    return "invalid", msg("headers.xfo_unknown")


def _check_content_type_options(value: str) -> tuple[str, object]:
    if value.split(",")[0].strip().lower() == "nosniff":
        return "ok", "nosniff"
    return "invalid", msg("headers.xcto_invalid")


def _check_referrer_policy(value: str) -> tuple[str, object]:
    # Le navigateur applique le dernier jeton qu'il reconnaît.
    known = [
        token
        for token in (t.strip().lower() for t in value.split(","))
        if token in _REFERRER_OK | _REFERRER_WEAK | _REFERRER_INVALID
    ]
    if not known:
        return "invalid", msg("headers.unknown_value")
    policy = known[-1]
    if policy in _REFERRER_OK:
        return "ok", policy
    if policy in _REFERRER_WEAK:
        return "weak", msg("headers.referrer_weak", policy=policy)
    return "invalid", msg("headers.referrer_unsafe", policy=policy)


def _check_xss_protection(value: str) -> object:
    if value.strip().startswith("0"):
        return msg("headers.xss_disabled")
    return msg("headers.xss_obsolete")


def evaluate_security_headers(
    headers: Mapping[str, str], https: bool, *, ip_target: bool = False, cert_valid: bool | None = None
) -> dict:
    """Évalue la valeur de chaque en-tête de sécurité.

    `headers` : en-têtes de la réponse (noms insensibles à la casse).
    `https` : la réponse a-t-elle été servie en HTTPS (HSTS n'a d'effet qu'ainsi).
    `ip_target` : la cible est une adresse IP ; les navigateurs y ignorent HSTS
    (RFC 6797 §8.1), qui est alors rapporté en « info » et sort du barème.
    `cert_valid` : verdict sur le certificat présenté (None : inconnu). Les
    navigateurs ignorent un HSTS reçu avec un certificat invalide (RFC 6797 §8.1).
    Renvoie `checks` (statut et explication par en-tête : un message
    traduisible, ou la valeur protectrice elle-même), `counts` (entiers) et
    `graded` (en-têtes notés).
    """
    values = {str(name).lower(): str(value) for name, value in headers.items() if value}
    csp = values.get("content-security-policy")
    checks: dict[str, dict] = {}
    graded = [h for h in SECURITY_HEADERS if not (ip_target and h == "Strict-Transport-Security")]

    for header in SECURITY_HEADERS:
        value = values.get(header.lower())
        if header not in graded:
            status, detail = "info", msg("headers.hsts_ip")
        elif header == "X-Frame-Options":
            status, detail = _check_frame_options(value, csp)
        elif value is None:
            status, detail = "missing", msg("headers.missing")
        elif header == "Strict-Transport-Security":
            status, detail = _check_hsts(value, https, cert_valid)
        elif header == "X-Content-Type-Options":
            status, detail = _check_content_type_options(value)
        elif header == "Content-Security-Policy":
            status, detail = _check_csp(value)
        elif header == "Referrer-Policy":
            status, detail = _check_referrer_policy(value)
        else:  # Permissions-Policy : la présence suffit.
            status, detail = "ok", msg("headers.present")
        checks[header] = {"value": value, "status": status, "detail": detail}

    for header in INFORMATIONAL_HEADERS:
        value = values.get(header.lower())
        if value is not None:
            checks[header] = {"value": value, "status": "info", "detail": _check_xss_protection(value)}

    counts = {status: 0 for status in HEADER_STATUSES}
    for header in graded:
        counts[checks[header]["status"]] += 1
    counts["total"] = len(graded)
    return {"checks": checks, "counts": counts, "graded": graded}


def empty_headers_result(error: object = None, *, ip_target: bool = False) -> dict:
    """Résultat « non mesuré » du module (aussi utilisable comme valeur de repli).

    `error` : texte ou message traduisible (voir domainrecon.i18n), ou None.
    """
    graded = [h for h in SECURITY_HEADERS if not (ip_target and h == "Strict-Transport-Security")]
    return {
        "headers_found": {},
        # En-têtes notés absents de la réponse (HSTS exclu sur une cible IP).
        "headers_missing": graded,
        "score": f"0/{len(graded)}",
        "counts": None,
        "checks": {},
        "url": None,
        "https": False,
        # Vrai si https:// a été redirigé vers une réponse notée servie en HTTP.
        "https_downgrade": False,
        # Redirection vers un autre site, non suivie : ses en-têtes ne sont pas
        # attribués à la cible.
        "off_site_redirect": None,
        "measured": False,
        "error": error,
    }


# =============================================================================
# Module 3 : Security Headers
# =============================================================================


async def check_security_headers(domain: str) -> dict:
    """Analyse les en-têtes de sécurité HTTP et la validité de leurs valeurs (OWASP).

    Seules les réponses du site ciblé sont évaluées : une redirection vers un
    autre site n'est pas suivie (`off_site_redirect`), et c'est la dernière
    réponse du site ciblé qui est notée. Le corps n'est jamais lu. Sur une
    cible IP, HSTS (sans effet) sort du barème, et de `headers_missing`.
    """
    ip_target = is_ip_literal(domain)
    result = empty_headers_result(ip_target=ip_target)
    # Échecs de chaque tentative, par schéma : aucun n'est masqué par le suivant.
    errors: list[object] = []

    async with _http_client(timeout=10.0) as client:
        for scheme in ("https", "http"):
            url = f"{scheme}://{url_host(domain)}"
            # Beaucoup de serveurs répondent 405/501 à HEAD ou omettent des
            # en-têtes : on retombe sur GET pour éviter les faux négatifs.
            for method in ("HEAD", "GET"):
                try:
                    fetched = await fetch(client, url, method=method, site=domain, max_bytes=0)
                except Exception as e:
                    errors.append(msg("http.scheme_error", scheme=scheme.upper(), error=describe_error(e)))
                    logger.debug("security_headers %s %s: %s", method, url, e)
                    if isinstance(e, (httpx.ConnectError, httpx.ConnectTimeout)):
                        # Schéma injoignable : un GET n'aboutirait pas davantage.
                        break
                    continue

                response = fetched.response
                if method == "HEAD" and response.status_code >= 400:
                    logger.debug("security_headers HEAD %s -> %s, retry GET", url, response.status_code)
                    continue

                # Après redirections, c'est le schéma de la réponse finale qui compte.
                https = response.url.scheme == "https"
                evaluation = evaluate_security_headers(response.headers, https, ip_target=ip_target)
                found = {h: response.headers[h] for h in SECURITY_HEADERS if response.headers.get(h)}

                result.update(
                    headers_found=found,
                    headers_missing=[h for h in evaluation["graded"] if h not in found],
                    score=f"{evaluation['counts']['ok']}/{evaluation['counts']['total']}",
                    counts=evaluation["counts"],
                    checks=evaluation["checks"],
                    url=fetched.url,
                    https=https,
                    https_downgrade=scheme == "https" and not https,
                    off_site_redirect=fetched.off_site_url,
                    measured=True,
                    error=None,
                )
                return result

    result["error"] = msg("http.unreachable", errors=unique(errors))
    return result


def apply_tls_verdict(result: dict, tls: dict | None, domain: str) -> dict:
    """Recoupe l'évaluation HSTS avec le verdict du module TLS (RFC 6797 §8.1).

    Les en-têtes sont lus sans vérification TLS ; or les navigateurs ignorent
    un Strict-Transport-Security reçu avec un certificat invalide. Si le module
    TLS a mesuré un certificat invalide pour `domain` (port 443) et que la
    réponse notée vient de ce même hôte en HTTPS, les en-têtes sont réévalués
    avec HSTS « invalid ». Renvoie `result`, modifié sur place.
    """
    if not (isinstance(result, dict) and result.get("measured") and result.get("https")):
        return result
    if not (isinstance(tls, dict) and tls.get("measured") and tls.get("https") and tls.get("valid") is False):
        return result
    url = result.get("url")
    try:
        final = httpx.URL(url) if isinstance(url, str) else None
    except Exception:
        final = None
    if (
        final is None
        or final.port not in (None, 443)
        or host_of_url(final) != host_of_url(f"https://{url_host(domain)}")
    ):
        return result

    values = {
        header: check["value"]
        for header, check in (result.get("checks") or {}).items()
        if isinstance(check, dict) and check.get("value")
    }
    evaluation = evaluate_security_headers(values, True, ip_target=is_ip_literal(domain), cert_valid=False)
    result.update(
        score=f"{evaluation['counts']['ok']}/{evaluation['counts']['total']}",
        counts=evaluation["counts"],
        checks=evaluation["checks"],
    )
    return result
