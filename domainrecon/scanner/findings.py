# =============================================================================
# DomainRecon - Scanner : points à corriger (« À corriger »)
# =============================================================================
# Calculés à la lecture d'un scan (jamais enregistrés) à partir des résultats
# des modules : les anciens scans en bénéficient aussi. Chaque module déclare
# ses règles (ModuleSpec.findings : FindingRule de rules.py) ; ce fichier les
# applique dans l'ordre du registre, sans aucune liste figée.
#
# Seuls les modules mesurés (statut « ok », déduit des résultats pour un scan
# antérieur à module_status, comme pour les familles) sont lus : un module en
# échec, ou non lancé (profil de scan), n'est jamais présenté comme un constat.
# Toute donnée inattendue (ancien format, type imprévu) est ignorée, et une règle
# qui lève une exception est écartée (journal) : jamais une erreur de lecture.
#
# Les règles de 17 des 18 modules historiques sont définies plus bas et rattachées
# à leurs modules (modules/*.py) ; le module d'exemple email_security déclare les
# siennes dans son propre fichier, comme tout nouveau module. Leur lecture des données est celle du barème
# (score.py : as_*, sensitive_open_ports, takeover_confirmed, tls_measured…) :
# score et constats tirent les mêmes conclusions des mêmes données.
# =============================================================================

import logging
from collections.abc import Callable, Mapping

from ..i18n import message, msg
from .families import FAMILY_KEYS, module_family, module_run_status, module_value
from .rules import SEVERITIES, FindingInput, FindingRule, Hit, hit
from .score import (
    as_dict,
    as_int,
    as_list,
    cors_credentials_checked,
    sensitive_open_ports,
    takeover_confirmed,
    tls_legacy_invalid,
    tls_measured,
)

logger = logging.getLogger(__name__)

__all__ = ["SEVERITIES", "compute_findings"]

# Statuts d'en-tête qui signalent une protection sans effet ou partielle.
_WEAK_HEADER_STATUSES = frozenset({"weak", "invalid"})
# En-têtes regroupés dans un seul constat de faible gravité.
_OTHER_HEADERS = ("X-Frame-Options", "X-Content-Type-Options", "Referrer-Policy", "Permissions-Policy")
_OBSOLETE_PROTOCOLS = frozenset({"SSLv3", "TLSv1", "TLSv1.1"})
# Nombre de noms de cookies cités dans le constat.
_COOKIE_NAMES_SHOWN = 5


def _measured(scan: dict, module: str) -> bool:
    """Module mesuré : statut « ok », selon la règle des familles (module_run_status).

    Scan antérieur à module_status : statut déduit des résultats ; un scan au
    statut « error » n'a aucun module mesuré, donc aucun constat.
    """
    return module_run_status(scan, module) == "ok"


# =============================================================================
# Moteur
# =============================================================================


def _hits(result: object) -> list[Hit]:
    """Constats rendus par FindingRule.check, sous une forme unique."""
    if result is None or result is False:
        return []
    if result is True:
        return [Hit()]
    if isinstance(result, Hit):
        return [result]
    if isinstance(result, Mapping):
        return [Hit(dict(result))]
    if isinstance(result, (list, tuple)):
        hits: list[Hit] = []
        for item in result:
            hits.extend(_hits(item))
        return hits
    raise TypeError(f"résultat de règle inattendu : {type(result).__name__}")


def _apply(rule: FindingRule, scan: dict, module: str, families: dict[str, str]) -> list[dict]:
    if rule.requires_measured and not _measured(scan, module):
        return []
    try:
        hits = _hits(rule.check(FindingInput(scan, module, module_value, _measured)))
    except Exception:
        logger.exception("Règle de constat %s du module %s en échec : ignorée", rule.code, module)
        return []
    found = []
    for item in hits:
        severity = item.severity or rule.severity
        source = item.module or module
        if severity not in SEVERITIES:
            logger.warning("Règle %s : gravité %r inconnue, constat ignoré", rule.code, severity)
            continue
        found.append(
            {
                "severity": severity,
                "family": families.get(source, families.get(module)),
                "module": source,
                "message": message(rule.code, item.params),
            }
        )
    return found


def compute_findings(scan: dict) -> list[dict]:
    """Points à corriger d'un scan, du plus grave au moins grave, puis par famille (ordre du registre ensuite)."""
    from . import registry

    scan = as_dict(scan)
    families = module_family()
    findings = [
        finding
        for spec in registry.MODULES.values()
        for rule in spec.findings
        for finding in _apply(rule, scan, spec.name, families)
    ]
    family_rank = {family: index for index, family in enumerate(FAMILY_KEYS)}
    return sorted(
        findings,
        key=lambda finding: (
            SEVERITIES.index(finding["severity"]),
            family_rank.get(finding["family"], len(family_rank)),
        ),
    )


# =============================================================================
# Règles des modules historiques (rattachées par modules/*.py)
# =============================================================================

# --- tls_certificate --------------------------------------------------------


def _tls(f: FindingInput) -> dict | None:
    """Résultat TLS exploitable, sinon None."""
    tls = as_dict(f.data)
    return tls if tls and tls_measured(tls) else None


def _tls_invalid(tls: dict) -> bool:
    # Scan antérieur : l'erreur « certificate verify failed » vaut certificat invalide.
    return tls.get("valid") is False or tls_legacy_invalid(tls)


def _tls_usable(f: FindingInput) -> dict | None:
    """Résultat TLS d'un certificat servi en HTTPS et valide (expiration, protocole)."""
    tls = _tls(f)
    if tls is None or tls.get("https") is False or _tls_invalid(tls):
        return None
    return tls


def _check_tls_no_https(f: FindingInput) -> bool:
    tls = _tls(f)
    return tls is not None and tls.get("https") is False


def _check_tls_invalid(f: FindingInput) -> dict | None:
    tls = _tls(f)
    if tls is None or tls.get("https") is False or not _tls_invalid(tls):
        return None
    return {"reason": tls.get("verify_error") or tls.get("error") or msg("finding.tls_refused")}


def _check_tls_expires(f: FindingInput) -> Hit | None:
    tls = _tls_usable(f)
    days = as_int(tls.get("days_remaining")) if tls else None
    if days is None or days > 30:
        return None
    return hit(days=days, severity="high" if days <= 7 else "medium")


def _check_tls_protocol(f: FindingInput) -> dict | None:
    tls = _tls_usable(f)
    protocol = tls.get("protocol") if tls else None
    if isinstance(protocol, str) and protocol in _OBSOLETE_PROTOCOLS:
        return {"protocol": protocol}
    return None


TLS_FINDINGS = (
    FindingRule(code="finding.tls_no_https", severity="high", check=_check_tls_no_https),
    FindingRule(code="finding.tls_invalid", severity="critical", check=_check_tls_invalid),
    FindingRule(code="finding.tls_expires_soon", severity="medium", check=_check_tls_expires),
    FindingRule(code="finding.tls_old_protocol", severity="medium", check=_check_tls_protocol),
)


# --- security_headers (et rétrogradation HTTPS -> HTTP) -------------------------


def _check_downgrade(f: FindingInput) -> Hit | None:
    """Rétrogradation HTTPS → HTTP, signalée une seule fois (chaîne de redirections d'abord)."""
    if f.measured("redirect_chain") and as_dict(f.data_of("redirect_chain")).get("https_downgrade"):
        return hit(module="redirect_chain")
    if f.measured("security_headers") and as_dict(f.data_of("security_headers")).get("https_downgrade"):
        return hit(module="security_headers")
    return None


def _headers(f: FindingInput) -> tuple[dict, Callable[[str], str | None]] | None:
    """(résultat, statut d'un en-tête) des en-têtes mesurés, sinon None."""
    sec = as_dict(f.data)
    if not sec.get("measured", bool(sec.get("headers_found"))):
        return None
    checks = as_dict(sec.get("checks"))
    # Ancien format (sans checks) : seule la liste des en-têtes absents est connue.
    missing = {name for name in as_list(sec.get("headers_missing")) if isinstance(name, str)}

    def status(name: str) -> str | None:
        if checks:
            return as_dict(checks.get(name)).get("status")
        return "missing" if name in missing else None

    return sec, status


def _detail(sec: dict, name: str) -> object:
    return as_dict(as_dict(sec.get("checks")).get(name)).get("detail") or ""


def _hsts_status(f: FindingInput) -> tuple[dict, str | None] | None:
    found = _headers(f)
    # Sans HTTPS, HSTS est sans objet : le constat TLS le dit déjà.
    if found is None or found[0].get("https") is False:
        return None
    sec, status = found
    return sec, status("Strict-Transport-Security")


def _check_hsts_missing(f: FindingInput) -> bool:
    found = _hsts_status(f)
    return found is not None and found[1] == "missing"


def _check_hsts_weak(f: FindingInput) -> dict | None:
    found = _hsts_status(f)
    if found is None or found[1] not in _WEAK_HEADER_STATUSES:
        return None
    return {"detail": _detail(found[0], "Strict-Transport-Security")}


def _check_csp_missing(f: FindingInput) -> bool:
    found = _headers(f)
    return found is not None and found[1]("Content-Security-Policy") == "missing"


def _check_csp_weak(f: FindingInput) -> dict | None:
    found = _headers(f)
    if found is None or found[1]("Content-Security-Policy") not in _WEAK_HEADER_STATUSES:
        return None
    return {"detail": _detail(found[0], "Content-Security-Policy")}


def _check_other_headers(f: FindingInput) -> dict | None:
    found = _headers(f)
    if found is None:
        return None
    others = [name for name in _OTHER_HEADERS if found[1](name) in ("missing", "invalid")]
    return {"headers": ", ".join(others)} if others else None


HEADERS_FINDINGS = (
    FindingRule(
        code="finding.https_downgrade", severity="high", check=_check_downgrade, requires_measured=False
    ),
    FindingRule(code="finding.hsts_missing", severity="high", check=_check_hsts_missing),
    FindingRule(code="finding.hsts_weak", severity="medium", check=_check_hsts_weak),
    FindingRule(code="finding.csp_missing", severity="medium", check=_check_csp_missing),
    FindingRule(code="finding.csp_weak", severity="low", check=_check_csp_weak),
    FindingRule(code="finding.headers_missing", severity="low", check=_check_other_headers),
)


# --- redirect_chain -----------------------------------------------------------


def _check_no_https_redirect(f: FindingInput) -> bool:
    redirect = as_dict(f.data)
    if not redirect.get("measured", bool(redirect.get("chain"))):
        return False
    # Sans HTTPS (établi par le module TLS, mesuré), le constat TLS le dit déjà.
    # Un module TLS en échec ne prouve rien : le défaut de redirection reste signalé.
    tls = as_dict(f.data_of("tls_certificate"))
    no_https = f.measured("tls_certificate") and tls_measured(tls) and tls.get("https") is False
    if redirect.get("https_downgrade") or no_https:
        return False
    return redirect.get("forces_https") is False


REDIRECT_FINDINGS = (
    FindingRule(code="finding.no_https_redirect", severity="medium", check=_check_no_https_redirect),
)


# --- cors ---------------------------------------------------------------------


def _cors(f: FindingInput) -> dict | None:
    cors = as_dict(f.data)
    return None if cors.get("measured") is False else cors


def _origin(cors: dict) -> str:
    return str(cors.get("reflected_origin") or "?")


def _check_cors_credentials(f: FindingInput) -> dict | None:
    cors = _cors(f)
    return {"origin": _origin(cors)} if cors and cors.get("reflects_with_credentials") else None


def _check_cors_reflect(f: FindingInput) -> dict | None:
    cors = _cors(f)
    if not cors or cors.get("reflects_with_credentials") or not cors.get("reflects_origin"):
        return None
    return {"origin": _origin(cors)} if cors_credentials_checked(cors) else None


def _check_cors_reflect_legacy(f: FindingInput) -> dict | None:
    # Ancien format : credentials non vérifiés, ce que le barème sanctionne de tout
    # le critère (0 point) : gravité « high », sans affirmer l'absence de credentials.
    cors = _cors(f)
    if not cors or cors.get("reflects_with_credentials") or not cors.get("reflects_origin"):
        return None
    return None if cors_credentials_checked(cors) else {"origin": _origin(cors)}


def _check_cors_wildcard(f: FindingInput) -> bool:
    cors = _cors(f)
    return bool(
        cors
        and not cors.get("reflects_with_credentials")
        and not cors.get("reflects_origin")
        and cors.get("allows_credentials_with_wildcard")
    )


CORS_FINDINGS = (
    FindingRule(code="finding.cors_reflect_credentials", severity="critical", check=_check_cors_credentials),
    FindingRule(code="finding.cors_reflect", severity="medium", check=_check_cors_reflect),
    FindingRule(code="finding.cors_reflect_legacy", severity="high", check=_check_cors_reflect_legacy),
    FindingRule(code="finding.cors_wildcard_credentials", severity="low", check=_check_cors_wildcard),
)


# --- cookie_security, web_files -------------------------------------------------


def _check_cookies(f: FindingInput) -> dict | None:
    cookies = [
        cookie
        for cookie in as_list(as_dict(f.data).get("cookies"))
        if isinstance(cookie, dict) and cookie.get("issues")
    ]
    if not cookies:
        return None
    names = ", ".join(str(cookie.get("name") or "?") for cookie in cookies[:_COOKIE_NAMES_SHOWN])
    if len(cookies) > _COOKIE_NAMES_SHOWN:
        names += "…"
    return {"count": len(cookies), "names": names}


COOKIE_FINDINGS = (FindingRule(code="finding.cookies_insecure", severity="medium", check=_check_cookies),)


def _check_security_txt(f: FindingInput) -> bool:
    return as_dict(as_dict(f.data).get("security_txt")).get("found") is False


WEB_FILES_FINDINGS = (
    FindingRule(code="finding.security_txt_missing", severity="low", check=_check_security_txt),
)


# --- subdomain_takeover, open_ports ----------------------------------------------


def _takeover_entries(f: FindingInput) -> list[tuple[dict, str, str]]:
    entries = []
    for entry in as_list(f.data):
        if isinstance(entry, dict):
            subdomain = str(entry.get("subdomain") or "?")
            provider = str(entry.get("provider") or entry.get("cname") or "?")
            entries.append((entry, subdomain, provider))
    return entries


def _check_takeover_confirmed(f: FindingInput) -> list[dict]:
    return [
        {"subdomain": subdomain, "provider": provider}
        for entry, subdomain, provider in _takeover_entries(f)
        if takeover_confirmed(entry)
    ]


def _check_takeover_to_check(f: FindingInput) -> list[Hit]:
    return [
        hit(
            subdomain=subdomain,
            provider=provider,
            severity="high" if entry.get("risk") == "medium" else "medium",
        )
        for entry, subdomain, provider in _takeover_entries(f)
        if not takeover_confirmed(entry)
    ]


TAKEOVER_FINDINGS = (
    FindingRule(code="finding.takeover_confirmed", severity="critical", check=_check_takeover_confirmed),
    FindingRule(code="finding.takeover_to_check", severity="medium", check=_check_takeover_to_check),
)


def _check_ports(f: FindingInput) -> list[Hit]:
    return [
        hit(port=port, service=service, severity=severity)
        for port, service, severity in sensitive_open_ports(f.data)
    ]


PORT_FINDINGS = (FindingRule(code="finding.port_exposed", severity="high", check=_check_ports),)
