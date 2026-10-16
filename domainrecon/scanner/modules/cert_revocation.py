# =============================================================================
# DomainRecon - Module « cert_revocation » : révocation du certificat (OCSP, CRL)
# =============================================================================
# Le certificat du site a-t-il été révoqué par son autorité de certification ?
# Trois sources, toutes réellement interrogées (voir scanner/impl/cert_revocation.py) :
#   - l'agrafe OCSP que le serveur joint à sa poignée de main (TLS 1.2) ;
#   - le répondeur OCSP de l'autorité (réponse vérifiée : état, fraîcheur, signature) ;
#   - la CRL de l'autorité, en secours (Let's Encrypt n'a plus d'OCSP depuis 2025).
# Signale aussi un certificat « Must-Staple » sans agrafe (le site serait
# inaccessible dans Firefox) et l'absence de toute information de révocation.
#
# Passif : une poignée de main ordinaire vers la
# cible, puis des requêtes vers l'autorité de certification (pas vers la cible).
# =============================================================================

import asyncio

from ...i18n import msg
from ..errors import ModuleError, ModuleSkipped
from ..impl import cert_revocation as revocation
from ..impl import tls_x509
from ..registry import ModuleSpec, ScanContext, skip_without_address
from ..rules import FindingRule, Outcome, ScoreRule, hit
from ..score import as_dict
from ..targets import ensure_ip_allowed

TLS_PORT = 443
# Budget des requêtes à l'autorité de certification (OCSP puis CRL), secondes.
LOOKUP_BUDGET = 40.0


async def _lookup(context: ScanContext, certificates: list, info: dict) -> tuple[dict, dict]:
    """Interroge l'autorité (OCSP, puis CRL si OCSP ne conclut pas). Remplit `info` des anomalies."""
    leaf = certificates[0]
    ocsp_result: dict = {"checked": False}
    crl_result: dict = {"checked": False}
    issuer = await revocation.find_issuer(leaf, certificates[1:], context.http)
    if issuer is None:
        info["issuer_missing"] = True
        return ocsp_result, crl_result
    if info["ocsp_urls"]:
        ocsp_result = await revocation.query_ocsp(context.http, leaf, issuer, tls_x509.ocsp_urls(leaf))
    if info["crl_urls"] and ocsp_result.get("status") not in ("good", "revoked"):
        crl_result = await revocation.query_crl(context.http, leaf, issuer, tls_x509.crl_urls(leaf))
    return ocsp_result, crl_result


async def run(context: ScanContext) -> dict:
    if context.http is None:
        raise ModuleError(msg("cert_revocation.no_client"))
    sni = None if context.is_ip_target else context.domain
    failure = "refused"
    fetched = None
    ip = ""
    for address in context.addresses[:2]:
        ip = ensure_ip_allowed(address)
        try:
            fetched = await asyncio.to_thread(tls_x509.fetch_chain, ip, TLS_PORT, sni)
            break
        except tls_x509.ChainFetchError as e:
            failure = e.kind
            if failure != "refused":
                break
    if fetched is None:
        if failure == "timeout":
            raise ModuleError(msg("net.timeout"))
        raise ModuleSkipped(msg("tls.https_closed", port=TLS_PORT))

    der_list = fetched["served"][: tls_x509.MAX_CHAIN_LENGTH]
    certificates = [c for c in (tls_x509.load(der) for der in der_list) if c]
    if not certificates:
        raise ModuleError(msg("cert_revocation.unreadable", source="TLS"))
    leaf = certificates[0]
    info = {
        "measured": True,
        "error": None,
        "trusted": bool(fetched.get("verified")),
        "self_signed": tls_x509.is_self_issued(leaf),
        "short_lived": revocation.short_lived(leaf),
        # Un certificat expiré disparaît des CRL : « non révoqué » ne voudrait rien dire.
        "expired": revocation.expired(leaf),
        "must_staple": tls_x509.must_staple(leaf),
        "ocsp_urls": tls_x509.ocsp_urls(leaf)[:3],
        "crl_urls": tls_x509.crl_urls(leaf)[:3],
    }
    stapling = await asyncio.to_thread(revocation.probe_stapling, ip, TLS_PORT, sni, leaf)
    ocsp_result: dict = {"checked": False}
    crl_result: dict = {"checked": False}
    if not info["self_signed"] and not info["expired"] and (info["ocsp_urls"] or info["crl_urls"]):
        try:
            ocsp_result, crl_result = await asyncio.wait_for(
                _lookup(context, certificates, info), timeout=LOOKUP_BUDGET
            )
        except asyncio.TimeoutError:
            info["lookup_timeout"] = True
    info.update(stapling=stapling, ocsp=ocsp_result, crl=crl_result)
    info["status"] = revocation.conclude(ocsp_result, crl_result, stapling)
    return info


# -----------------------------------------------------------------------------
# Constats
# -----------------------------------------------------------------------------


def _usable(data: object) -> dict:
    report = as_dict(data)
    return {} if report.get("measured") is False else report


def _revoked(report: dict) -> object:
    if report.get("status") != "revoked":
        return None
    ocsp, crl, stapling = (as_dict(report.get(key)) for key in ("ocsp", "crl", "stapling"))
    # Réponse authentifiée : signature vérifiée (OCSP, CRL) ; l'agrafe est jointe par le serveur lui-même.
    authentic = (
        (ocsp.get("status") == "revoked" and ocsp.get("signature_ok") is True)
        or (crl.get("status") == "revoked" and crl.get("signature_ok") is True)
        or stapling.get("status") == "revoked"
    )
    return hit(severity="critical" if authentic else "high")


def _must_staple_missing(report: dict) -> bool:
    return report.get("must_staple") is True and as_dict(report.get("stapling")).get("supported") is False


def _stale_staple(report: dict) -> bool:
    stapling = as_dict(report.get("stapling"))
    return stapling.get("supported") is True and stapling.get("stale") is True


def _no_info(report: dict) -> bool:
    if not report or not report.get("trusted") or report.get("short_lived") or report.get("self_signed"):
        return False
    return not report.get("ocsp_urls") and not report.get("crl_urls")


def _unverifiable(report: dict) -> bool:
    """Informations de révocation présentes, mais aucune source n'a pu les confirmer."""
    if not report or report.get("self_signed") or report.get("expired"):
        return False
    if not (report.get("ocsp_urls") or report.get("crl_urls")):
        return False
    return report.get("status") == "unknown" and as_dict(report.get("stapling")).get("supported") is not True


FINDINGS = (
    FindingRule(
        code="finding.cert_revocation.revoked", severity="critical", check=lambda f: _revoked(_usable(f.data))
    ),
    FindingRule(
        code="finding.cert_revocation.must_staple_missing",
        severity="high",
        check=lambda f: _must_staple_missing(_usable(f.data)),
    ),
    FindingRule(
        code="finding.cert_revocation.stale_staple",
        severity="medium",
        check=lambda f: _stale_staple(_usable(f.data)),
    ),
    FindingRule(
        code="finding.cert_revocation.no_revocation_info",
        severity="low",
        check=lambda f: _no_info(_usable(f.data)),
    ),
    FindingRule(
        code="finding.cert_revocation.unverifiable",
        severity="low",
        check=lambda f: _unverifiable(_usable(f.data)),
    ),
)


# -----------------------------------------------------------------------------
# Score : 5 points ; un certificat révoqué plafonne la note
# -----------------------------------------------------------------------------


def _score(data: dict) -> Outcome:
    report = as_dict(data.get("cert_revocation"))
    status = report.get("status")
    if report.get("self_signed") or report.get("expired"):
        return Outcome(0, msg("cert_revocation.score_not_applicable"), False, applicable=False)
    if status == "revoked":
        return Outcome(
            0, msg("cert_revocation.score_revoked"), True, cap_reason=msg("cert_revocation.score_cap")
        )
    if _must_staple_missing(report):
        return Outcome(1, msg("cert_revocation.score_must_staple"), True)
    if status == "good":
        return Outcome(5, msg("cert_revocation.score_good"), True)
    if not report.get("ocsp_urls") and not report.get("crl_urls"):
        return Outcome(3, msg("cert_revocation.score_no_info"), True)
    return Outcome(3, msg("cert_revocation.score_unknown"), True)


SPEC = ModuleSpec(
    name="cert_revocation",
    family="tls",
    category="passif",
    run=run,
    skip_reason=skip_without_address,
    wave=1,
    timeout=60,
    # Les autorités de certification sont des services tiers parfois lents ou injoignables.
    optional=True,
    order=43,
    findings=FINDINGS,
    score_rules=(ScoreRule(criterion="cert_revocation", weight=5, evaluate=_score, rank=23),),
)
