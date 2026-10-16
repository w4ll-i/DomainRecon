# =============================================================================
# DomainRecon - Module « crypto_audit » : audit cryptographique du certificat
# =============================================================================
# Lit la chaîne de certificats envoyée par le serveur (port 443) et vérifie :
# algorithmes de signature (SHA-1, MD5), tailles et types de clé, durée de
# validité selon le calendrier actuel du CA/Browser Forum, intermédiaires
# expirés, chaîne complète, SAN, usage serveur, SCT (Certificate Transparency),
# type de validation (DV, OV, EV). Les révocations (OCSP, CRL) sont vues par le
# module cert_revocation ; le protocole et les suites par tls_deep.
#
# Chaîne réellement lue, seuil de validité à jour, bruit supprimé : voir
# scanner/impl/crypto_audit.py. Passif : une seule poignée de main ordinaire.
# =============================================================================

import asyncio

from ...i18n import msg
from ..errors import ModuleError, ModuleSkipped
from ..impl import crypto_audit as audit
from ..impl import tls_x509
from ..registry import ModuleSpec, ScanContext, skip_without_address
from ..rules import FindingInput, FindingRule, Outcome, ScoreRule, hit
from ..score import as_dict, as_list
from ..targets import ensure_ip_allowed

TLS_PORT = 443


async def run(context: ScanContext) -> dict:
    sni = None if context.is_ip_target else context.domain
    failure = "refused"
    for address in context.addresses[:2]:
        ip = ensure_ip_allowed(address)
        try:
            fetched = await asyncio.to_thread(tls_x509.fetch_chain, ip, TLS_PORT, sni)
        except tls_x509.ChainFetchError as e:
            failure = e.kind
            if failure != "refused":
                break
            continue
        result = await asyncio.to_thread(audit.analyze, fetched)
        if result.get("measured") is False:
            raise ModuleError(msg("crypto_audit.unreadable"))
        return result
    if failure == "timeout":
        raise ModuleError(msg("net.timeout"))
    raise ModuleSkipped(msg("tls.https_closed", port=TLS_PORT))


# -----------------------------------------------------------------------------
# Constats : une règle par type de défaut relevé dans `issues`
# -----------------------------------------------------------------------------


def _issues(f: FindingInput, code: str) -> list:
    data = as_dict(f.data)
    if data.get("measured") is False:
        return []
    return [i for i in as_list(data.get("issues")) if as_dict(i).get("code") == code]


def _hits(code: str, keys: tuple[str, ...], severity: str | None = None):
    """Règle qui rend un constat par défaut du type `code`, avec les paramètres `keys`."""

    def check(f: FindingInput) -> list:
        found = []
        for issue in _issues(f, code):
            params = as_dict(issue.get("params"))
            found.append(
                hit(severity=severity or issue.get("severity"), **{k: params.get(k, "") for k in keys})
            )
        return found

    return check


def _flag(code: str):
    return lambda f: bool(_issues(f, code))


FINDINGS = (
    FindingRule(
        code="finding.crypto_audit.weak_signature",
        severity="critical",
        check=_hits("weak_signature", ("subject", "algorithm")),
    ),
    FindingRule(
        code="finding.crypto_audit.weak_key",
        severity="high",
        check=_hits("weak_key", ("subject", "key_type", "bits")),
    ),
    FindingRule(code="finding.crypto_audit.no_san", severity="high", check=_flag("no_san")),
    FindingRule(code="finding.crypto_audit.no_server_auth", severity="high", check=_flag("no_server_auth")),
    FindingRule(
        code="finding.crypto_audit.chain_expired",
        severity="high",
        check=_hits("chain_expired", ("subject", "days")),
    ),
    FindingRule(
        code="finding.crypto_audit.chain_expiring",
        severity="medium",
        check=_hits("chain_expiring", ("subject", "days")),
    ),
    FindingRule(
        code="finding.crypto_audit.incomplete_chain", severity="medium", check=_flag("incomplete_chain")
    ),
    FindingRule(
        code="finding.crypto_audit.validity_too_long",
        severity="medium",
        check=_hits("validity_too_long", ("days", "limit")),
    ),
    FindingRule(code="finding.crypto_audit.no_sct", severity="low", check=_flag("no_sct")),
)


# -----------------------------------------------------------------------------
# Score : 10 points moins les défauts relevés ; signature ou clé de la feuille cassée plafonnent la note
# -----------------------------------------------------------------------------

_PENALTY = {"critical": 5, "high": 3, "medium": 2, "low": 1}


def _score(data: dict) -> Outcome:
    report = as_dict(data.get("crypto_audit"))
    issues = [as_dict(i) for i in as_list(report.get("issues"))]
    grade = str(report.get("grade") or "?")
    points = 10 - sum(_PENALTY.get(str(i.get("severity")), 0) for i in issues)
    leaf_broken = any(
        i.get("code") in ("weak_signature", "weak_key") and as_dict(i.get("params")).get("position") == "leaf"
        for i in issues
    )
    detail = msg("crypto_audit.score_detail", grade=grade, count=len(issues))
    cap = msg("crypto_audit.score_cap") if leaf_broken else None
    return Outcome(max(points, 0), detail, True, cap_reason=cap)


SPEC = ModuleSpec(
    name="crypto_audit",
    family="tls",
    category="passif",
    run=run,
    skip_reason=skip_without_address,
    wave=1,
    timeout=30,
    order=42,
    findings=FINDINGS,
    score_rules=(ScoreRule(criterion="crypto_audit", weight=10, evaluate=_score, rank=22),),
)
