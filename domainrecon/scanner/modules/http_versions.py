# =============================================================================
# DomainRecon - Module « http_versions » : HTTP/1.1, HTTP/2 et HTTP/3
# =============================================================================
# Détecte les versions de HTTP prises en charge par le serveur :
#   - HTTP/2 et HTTP/1.1 par négociation ALPN (poignée de main TLS sur 443, sans
#     vérifier le certificat : un certificat invalide ne masque plus HTTP/2) ;
#   - HTTP/3 par l'en-tête Alt-Svc de la page d'accueil partagée et par
#     l'enregistrement DNS HTTPS (« annoncé », aucune connexion QUIC).
# HTTP/1.1 est réellement testé, HTTP/2 ne dépend pas de la validité du certificat,
# et l'ancien jeton « quic » (Google QUIC) n'est pas pris pour HTTP/3.
# La sonde TLS est directe (comme tls_certificate) et ne vise que les adresses
# validées par la politique de cibles. Elle n'est lancée que si le site répond :
# une cible injoignable est un échec, pas un « HTTP/2 absent ».
# =============================================================================

import asyncio
import ssl

from ...i18n import msg
from .. import dns as scanner_dns
from ..errors import ModuleError
from ..impl import http_versions as logic
from ..registry import ModuleSpec, ScanContext, skip_without_address
from ..rules import FindingInput, FindingRule, Outcome, ScoreRule
from ..score import as_dict

_DNS_QUERY_TIMEOUT = 3.0
_DNS_BUDGET = 6.0


def _probe_all(sni: str | None, addresses: list[str]) -> dict:
    """Sonde ALPN (HTTP/2 puis HTTP/1.1) ; exécutée dans un thread."""
    first = logic.probe_alpn(sni, addresses, ["h2", "http/1.1"])
    negotiated = first["alpn"]
    if negotiated == "h2":
        # HTTP/1.1 est-il aussi accepté ? Un serveur 100 % HTTP/2 refuse cette offre.
        try:
            second = logic.probe_alpn(sni, addresses, ["http/1.1"])
            http1 = second["alpn"] == "http/1.1" or second["alpn"] is None
        except (OSError, ssl.SSLError):
            http1 = False
    else:
        http1 = True
    return {
        "tls_version": first["tls_version"],
        "negotiated_protocol": negotiated,
        # Sans ALPN, le serveur parle HTTP/1.1 (valeur par défaut) : ni h2 ni h3 par ce canal.
        "alpn_supported": negotiated is not None,
        "http1_1": http1,
        "http2": negotiated == "h2",
    }


def _dns_https_alpn(domain: str) -> list[str] | None:
    """Identifiants ALPN de l'enregistrement DNS HTTPS du domaine, ou None si non lisible."""
    querier = scanner_dns.DnsQuerier(query_timeout=_DNS_QUERY_TIMEOUT, budget=_DNS_BUDGET)
    lookup = querier.lookup(domain, "HTTPS")
    if lookup.status == "error":
        return None
    found: list[str] = []
    for record in lookup.answers:
        for token in logic.alpn_from_https_record(str(record)):
            if token not in found:
                found.append(token)
    return found


async def run(context: ScanContext) -> dict:
    home = await context.homepage()
    if not home.reachable:
        raise ModuleError(home.error or msg("orchestrator.module_failed"))

    result: dict = {
        "measured": True,
        "error": None,
        "https": False,
        "tls_version": None,
        "negotiated_protocol": None,
        "alpn_supported": False,
        "http1_1": None,
        "http2": False,
        "http3": False,
        "http3_source": None,
        "http3_verified": False,
        "alt_svc": None,
        "alt_svc_raw": None,
        "dns_https_alpn": None,
        "tls_error": None,
    }
    # SNI : le nom d'hôte, jamais une adresse IP littérale.
    sni = None if context.is_ip_target else context.domain
    try:
        result.update(await asyncio.to_thread(_probe_all, sni, context.addresses), https=True)
    except ssl.SSLError as e:
        # Port ouvert mais aucune poignée de main possible : pas de HTTPS utilisable.
        result["tls_error"] = msg(
            "http_versions.tls_failed", detail=str(getattr(e, "reason", None) or type(e).__name__)[:80]
        )
    except OSError as e:
        result["tls_error"] = (
            msg("net.timeout") if isinstance(e, TimeoutError) else msg("http_versions.no_https")
        )

    raw_alt_svc = home.headers.get("alt-svc") if home.https else None
    if raw_alt_svc:
        alt_svc = logic.parse_alt_svc(raw_alt_svc)
        result["alt_svc"] = alt_svc
        result["alt_svc_raw"] = raw_alt_svc[:300]
        if alt_svc["http3"]:
            result.update(http3=True, http3_source="alt-svc")
    alpn = None
    if not context.is_ip_target:
        try:
            alpn = await asyncio.wait_for(asyncio.to_thread(_dns_https_alpn, context.domain), timeout=10)
        except (asyncio.TimeoutError, TimeoutError, OSError):
            alpn = None
    result["dns_https_alpn"] = alpn
    if alpn and any(token.startswith("h3") for token in alpn) and not result["http3"]:
        result.update(http3=True, http3_source="dns")
    return result


def _check_no_http2(f: FindingInput) -> bool:
    data = as_dict(f.data)
    return data.get("https") is True and data.get("http2") is False


def _score(data: dict) -> Outcome:
    result = as_dict(data.get("http_versions"))
    if result.get("https") is not True:
        return Outcome(0, msg("http_versions.score_no_https"), False, applicable=False)
    if result.get("http3") is True:
        return Outcome(3, msg("http_versions.score_h3"), True)
    if result.get("http2") is True:
        return Outcome(2, msg("http_versions.score_h2"), True)
    return Outcome(0, msg("http_versions.score_h1"), True)


SPEC = ModuleSpec(
    name="http_versions",
    family="web",
    category="passif",
    run=run,
    order=34,
    skip_reason=skip_without_address,
    findings=(FindingRule(code="finding.http_versions.no_http2", severity="low", check=_check_no_http2),),
    score_rules=(ScoreRule(criterion="http_versions", weight=3, evaluate=_score),),
)
