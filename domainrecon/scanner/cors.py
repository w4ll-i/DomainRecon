# =============================================================================
# DomainRecon - Scanner : configuration CORS
# =============================================================================
# Verdicts :
#   - « * » sans credentials : acceptable pour des ressources publiques
#     (sévérité info, pas une erreur de configuration) ;
#   - origine arbitraire ou « null » acceptée (reflet de l'en-tête Origin), ou
#     credentials avec une origine permissive : erreur de configuration,
#     critique si le reflet s'accompagne de credentials (exploitable).
# Une conclusion « rien à signaler » exige que tous les tests d'origine aient
# abouti : sinon le module n'est pas mesuré (measured=False).
# =============================================================================

from ..i18n import msg, render
from .common import _http_client, logger
from .http_utils import describe_error, fetch, fetch_first

# =============================================================================
# Module 14 : CORS Misconfiguration Check
# =============================================================================


def _allows_credentials(headers) -> bool:
    return headers.get("access-control-allow-credentials", "").strip().lower() == "true"


def cors_test_origins(domain: str) -> list[str]:
    """Origines de test : arbitraire, contournements préfixe/suffixe, et null."""
    return [
        "https://evil.com",
        f"https://{domain}.evil.com",  # contrôle « commence par le domaine »
        f"https://evil{domain}",  # contrôle « se termine par le domaine »
        "null",
    ]


async def check_cors(domain: str) -> dict:
    """Vérifie les erreurs de configuration CORS.

    Une origine arbitraire (ou null) reflétée est une erreur de configuration ;
    avec Access-Control-Allow-Credentials: true, c'est une faille exploitable
    (sévérité critique). « * » sans credentials est acceptable pour des données
    publiques (info). « * » avec credentials est incohérent : les navigateurs
    refusent cette combinaison (erreur de configuration non exploitable).

    Chaque test d'origine en échec (délai, connexion coupée) est compté dans
    `origin_tests`. Sans erreur de configuration avérée, un seul test en échec
    suffit à ne pas conclure : measured=False, avec l'erreur. Les explications
    (`details`) et les erreurs des tests d'origine sont des messages
    traduisibles (voir domainrecon.i18n).
    """
    origins = cors_test_origins(domain)
    result = {
        "cors_enabled": False,
        "misconfigured": False,
        "allows_any_origin": False,
        "allows_credentials_with_wildcard": False,
        "reflects_origin": False,
        "reflects_with_credentials": False,
        "reflected_origin": None,
        "severity": None,
        "details": [],
        "url": None,
        "off_site_redirect": None,
        # Tests du reflet de l'en-tête Origin : aboutis et en échec.
        "origin_tests": {"total": len(origins), "succeeded": 0, "errors": []},
        # Vrai si des tests d'origine ont échoué (verdict établi sans eux).
        "partial": False,
        "measured": False,
        "error": None,
    }

    async with _http_client(timeout=8.0) as client:
        base, error = await fetch_first(client, domain, max_bytes=0)
        if base is None:
            logger.debug("Analyse CORS impossible sur %s: %s", domain, render(error, "fr"))
            result["error"] = error
            return result

        result.update(url=base.url, off_site_redirect=base.off_site_url)

        acao = base.headers.get("access-control-allow-origin", "").strip()
        if acao:
            result["cors_enabled"] = True
        if acao == "*":
            result["allows_any_origin"] = True
            if _allows_credentials(base.headers):
                result["allows_credentials_with_wildcard"] = True
                result["details"].append(msg("cors.wildcard_credentials"))
            else:
                result["details"].append(msg("cors.wildcard_public"))

        # Test du reflet de l'en-tête Origin, sur l'URL finale du site.
        tests = result["origin_tests"]
        for origin in origins:
            try:
                test = await fetch(client, base.url, headers={"Origin": origin}, site=domain, max_bytes=0)
            except Exception as e:
                logger.debug("Test CORS (origin=%s) échoué: %s", origin, e)
                tests["errors"].append(msg("cors.origin_error", origin=origin, error=describe_error(e)))
                continue
            tests["succeeded"] += 1

            reflected = test.headers.get("access-control-allow-origin", "").strip()
            if reflected:
                result["cors_enabled"] = True
            if reflected != origin:
                continue

            credentials = _allows_credentials(test.headers)
            if not result["reflects_origin"]:
                result["reflects_origin"] = True
                result["reflected_origin"] = origin
            if credentials:
                result["reflects_with_credentials"] = True
                result["reflected_origin"] = origin
                break

    origin = result["reflected_origin"]
    if result["reflects_with_credentials"]:
        result["misconfigured"] = True
        result["severity"] = "critical"
        result["details"].append(msg("cors.reflect_credentials", origin=origin))
    elif result["reflects_origin"]:
        # Sans credentials, rien d'authentifié n'est lisible, mais le site
        # accepte une origine qu'un attaquant contrôle.
        result["misconfigured"] = True
        result["severity"] = "low"
        if origin == "null":
            result["details"].append(msg("cors.reflect_null", origin=origin))
        else:
            result["details"].append(msg("cors.reflect_third_party", origin=origin))
    elif result["allows_credentials_with_wildcard"]:
        result["misconfigured"] = True
        result["severity"] = "low"
    elif result["allows_any_origin"]:
        result["severity"] = "info"

    failures = tests["errors"]
    result["partial"] = bool(failures)
    if failures and not result["misconfigured"]:
        # Sans les tests en échec, l'absence de reflet n'est pas établie.
        if not tests["succeeded"]:
            result["error"] = msg("cors.tests_impossible", errors=failures)
        else:
            result["error"] = msg(
                "cors.tests_incomplete", failed=len(failures), total=tests["total"], errors=failures
            )
        return result

    result["measured"] = True
    return result
