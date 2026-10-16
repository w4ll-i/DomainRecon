# =============================================================================
# DomainRecon - Logique du module « headers_extra » (en-têtes complémentaires)
# =============================================================================
# Évalue, sur les en-têtes de la page d'accueil déjà récupérée, ce que les six
# en-têtes notés de « security_headers » ne couvrent pas :
#   - l'isolation d'origine croisée : Cross-Origin-Opener-Policy (COOP),
#     Cross-Origin-Embedder-Policy (COEP), Cross-Origin-Resource-Policy (CORP) ;
#   - les en-têtes OBSOLÈTES à retirer : Public-Key-Pins (HPKP, retiré des
#     navigateurs), Expect-CT (déprécié), X-XSS-Protection (filtre supprimé des
#     navigateurs), Feature-Policy (remplacé par Permissions-Policy), en-têtes CSP
#     préfixés d'avant la norme.
# Fonctions pures : aucun accès réseau, testables seules.
# =============================================================================

from collections.abc import Mapping

from ...i18n import msg

# Valeurs reconnues, par en-tête (jeton avant le premier « ; »).
_COOP_OK = {"same-origin", "noopener-allow-popups"}
_COOP_PARTIAL = {"same-origin-allow-popups"}
_COOP_NONE = {"unsafe-none"}
_COEP_OK = {"require-corp", "credentialless"}
_COEP_NONE = {"unsafe-none"}
_CORP_OK = {"same-origin", "same-site"}
_CORP_OPEN = {"cross-origin"}

# Statuts d'un en-tête : ok, partial (protège en partie), weak (valeur par défaut,
# sans protection), invalid (valeur inconnue), missing (absent).
STATUSES = ("ok", "partial", "weak", "invalid", "missing")

# En-têtes obsolètes : nom en minuscules -> (clé de la raison, gravité).
_OBSOLETE = {
    "public-key-pins": "hpkp",
    "public-key-pins-report-only": "hpkp",
    "expect-ct": "expect_ct",
    "feature-policy": "feature_policy",
    "x-webkit-csp": "legacy_csp",
    "x-content-security-policy": "legacy_csp",
}


def _token(value: str) -> str:
    """Première valeur de l'en-tête, sans paramètres (« same-origin; report-to=… »)."""
    return value.split(",")[0].split(";")[0].strip().strip('"').lower()


def check_coop(value: str | None) -> tuple[str, object]:
    if value is None:
        return "missing", msg("headers_extra.missing")
    token = _token(value)
    if token in _COOP_OK:
        return "ok", msg("headers_extra.coop_ok", value=token)
    if token in _COOP_PARTIAL:
        return "partial", msg("headers_extra.coop_partial", value=token)
    if token in _COOP_NONE:
        return "weak", msg("headers_extra.value_unsafe_none", value=token)
    return "invalid", msg("headers_extra.value_unknown", value=token[:60])


def check_coep(value: str | None) -> tuple[str, object]:
    if value is None:
        return "missing", msg("headers_extra.missing")
    token = _token(value)
    if token in _COEP_OK:
        return "ok", msg("headers_extra.coep_ok", value=token)
    if token in _COEP_NONE:
        return "weak", msg("headers_extra.value_unsafe_none", value=token)
    return "invalid", msg("headers_extra.value_unknown", value=token[:60])


def check_corp(value: str | None) -> tuple[str, object]:
    if value is None:
        return "missing", msg("headers_extra.missing")
    token = _token(value)
    if token in _CORP_OK:
        return "ok", msg("headers_extra.corp_ok", value=token)
    if token in _CORP_OPEN:
        # Choix explicite d'ouvrir la ressource à tous : valide, mais sans protection.
        return "partial", msg("headers_extra.corp_open", value=token)
    return "invalid", msg("headers_extra.value_unknown", value=token[:60])


def obsolete_headers(headers: Mapping[str, str]) -> list[dict]:
    """En-têtes obsolètes présents : [{header, value, reason, severity}].

    X-XSS-Protection n'est signalé que s'il active le filtre (valeur autre que 0) :
    « 0 » est la valeur recommandée par l'OWASP quand l'en-tête est conservé.
    """
    found: list[dict] = []
    for name, value in headers.items():
        key = str(name).lower()
        text = str(value)[:200]
        if key in _OBSOLETE:
            reason = _OBSOLETE[key]
            if reason == "hpkp":
                found.append(
                    {
                        "header": key,
                        "value": text,
                        "reason": msg("headers_extra.obsolete_hpkp"),
                        "severity": "medium",
                    }
                )
            elif reason == "expect_ct":
                found.append(
                    {
                        "header": key,
                        "value": text,
                        "reason": msg("headers_extra.obsolete_expect_ct"),
                        "severity": "low",
                    }
                )
            elif reason == "feature_policy":
                found.append(
                    {
                        "header": key,
                        "value": text,
                        "reason": msg("headers_extra.obsolete_feature_policy"),
                        "severity": "low",
                    }
                )
            else:
                found.append(
                    {
                        "header": key,
                        "value": text,
                        "reason": msg("headers_extra.obsolete_legacy_csp"),
                        "severity": "low",
                    }
                )
        elif key == "x-xss-protection" and not text.strip().startswith("0"):
            found.append(
                {
                    "header": key,
                    "value": text,
                    "reason": msg("headers_extra.obsolete_xss"),
                    "severity": "low",
                }
            )
    found.sort(key=lambda item: item["header"])
    return found


def evaluate(headers: Mapping[str, str]) -> dict:
    """Évalue COOP, COEP, CORP et les en-têtes obsolètes d'une réponse (noms insensibles à la casse)."""
    values = {str(name).lower(): str(value) for name, value in headers.items() if value}
    checks: dict[str, dict] = {}
    for key, header, check in (
        ("coop", "cross-origin-opener-policy", check_coop),
        ("coep", "cross-origin-embedder-policy", check_coep),
        ("corp", "cross-origin-resource-policy", check_corp),
    ):
        value = values.get(header)
        status, detail = check(value)
        checks[key] = {
            "header": header,
            "value": value[:200] if value else None,
            "status": status,
            "detail": detail,
        }
    coop = _token(values["cross-origin-opener-policy"]) if "cross-origin-opener-policy" in values else ""
    coep = _token(values["cross-origin-embedder-policy"]) if "cross-origin-embedder-policy" in values else ""
    return {
        "checks": checks,
        # Isolation d'origine croisée effective (SharedArrayBuffer, minuteries précises).
        "cross_origin_isolated": coop == "same-origin" and coep in _COEP_OK,
        "obsolete": obsolete_headers(values),
    }
