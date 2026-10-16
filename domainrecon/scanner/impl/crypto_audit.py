# =============================================================================
# DomainRecon - Audit cryptographique du certificat : analyse de la chaîne
# =============================================================================
# Logique du module « crypto_audit » (modules/crypto_audit.py). Empreintes,
# type de clé, algorithme de signature, validité, SAN, SCT, type EV/OV/DV, avec
# ces précautions :
#   - chaîne : lue pour de vrai (impl/tls_x509.py), plus de « chaîne incomplète »
#     systématique sur le seul certificat feuille ;
#   - durée de validité : la limite de 398 jours est périmée. Calendrier du
#     CA/Browser Forum (ballot SC-081v3) selon la date d'émission : 398 jours
#     avant le 15/03/2026, 200 jours jusqu'au 14/03/2027, 100 jours jusqu'au
#     14/03/2029, puis 47 jours. Appliqué seulement aux chaînes approuvées par le
#     magasin public (une AC privée n'est pas soumise à ces règles) ;
#   - « RSA 2048 : envisagez 4096 » (bruit) supprimé ; « pas d'URL OCSP » aussi
#     (Let's Encrypt a arrêté OCSP en 2025 : la révocation est vue par
#     cert_revocation, OCSP et CRL).
# =============================================================================

from datetime import datetime, timezone

from . import tls_x509 as x509tools

# Calendrier des durées de validité maximales (date d'émission -> jours).
_VALIDITY_SCHEDULE = (
    (datetime(2029, 3, 15, tzinfo=timezone.utc), 47),
    (datetime(2027, 3, 15, tzinfo=timezone.utc), 100),
    (datetime(2026, 3, 15, tzinfo=timezone.utc), 200),
    (datetime(2020, 9, 1, tzinfo=timezone.utc), 398),
)
_LEGACY_MAX_VALIDITY = 825
# Marge d'un jour : certaines AC émettent « 200 jours et quelques secondes ».
_VALIDITY_MARGIN = 1
# Les navigateurs exigent des SCT (Certificate Transparency) depuis le 30/04/2018.
_SCT_REQUIRED_SINCE = datetime(2018, 4, 30, tzinfo=timezone.utc)
EXPIRY_WARNING_DAYS = 30
MAX_LISTED_NAMES = 50


def max_validity_days(issued: datetime) -> int:
    """Durée de validité maximale (jours) d'un certificat public émis à cette date."""
    for since, days in _VALIDITY_SCHEDULE:
        if issued >= since:
            return days
    return _LEGACY_MAX_VALIDITY


def _position(index: int, count: int, info_self_signed: bool) -> str:
    if index == 0:
        return "leaf"
    return "root" if info_self_signed and index == count - 1 else "intermediate"


def _issue(code: str, severity: str, **params) -> dict:
    return {"code": code, "severity": severity, "params": params}


def _grade(issues: list[dict]) -> str:
    severities = {issue["severity"] for issue in issues}
    for severity, grade in (("critical", "F"), ("high", "D"), ("medium", "C"), ("low", "B")):
        if severity in severities:
            return grade
    return "A"


def _name(info: dict) -> str:
    return str(info.get("subject_cn") or info.get("subject_org") or info.get("serial") or "?")


def analyze(fetched: dict, now: datetime | None = None) -> dict:
    """Audit d'une chaîne obtenue par tls_x509.fetch_chain. Renvoie le résultat JSON du module."""
    now = now or datetime.now(timezone.utc)
    certificates = [
        c for c in (x509tools.load(der) for der in fetched["served"][: x509tools.MAX_CHAIN_LENGTH]) if c
    ]
    if not certificates:
        return {"measured": False, "error": None, "failure": "unreadable"}

    chain = []
    for index, cert in enumerate(certificates):
        position = _position(index, len(certificates), x509tools.is_self_issued(cert))
        chain.append(x509tools.parse_certificate(cert, position, now))
    leaf = chain[0]
    complete = x509tools.chain_is_complete(certificates, fetched)
    trusted = bool(fetched.get("verified"))

    issues: list[dict] = []
    for info in chain:
        # Une racine est approuvée par sa présence dans le magasin, pas par sa signature.
        if info["signature_weak"] and not info["self_signed"]:
            issues.append(
                _issue(
                    "weak_signature",
                    "critical" if info["position"] == "leaf" else "high",
                    subject=_name(info),
                    algorithm=info["signature"].upper(),
                    position=info["position"],
                )
            )
        if info["key_weak"] and info["position"] != "root":
            key = info["key"]
            issues.append(
                _issue(
                    "weak_key",
                    "high",
                    subject=_name(info),
                    key_type=key["type"],
                    bits=key["bits"],
                    position=info["position"],
                )
            )
        if info["position"] == "intermediate":
            days = info["days_remaining"]
            if days < 0:
                issues.append(_issue("chain_expired", "high", subject=_name(info), days=-days))
            elif days <= EXPIRY_WARNING_DAYS:
                issues.append(_issue("chain_expiring", "medium", subject=_name(info), days=days))

    issued = datetime.fromisoformat(leaf["not_before"])
    if trusted:
        limit = max_validity_days(issued)
        if leaf["validity_days"] > limit + _VALIDITY_MARGIN:
            issues.append(_issue("validity_too_long", "medium", days=leaf["validity_days"], limit=limit))
        if leaf["sct_count"] == 0 and issued >= _SCT_REQUIRED_SINCE:
            issues.append(_issue("no_sct", "low"))
    if complete is False:
        issues.append(_issue("incomplete_chain", "medium"))
    if not leaf["has_san"]:
        issues.append(_issue("no_san", "high"))
    if not leaf["server_auth"]:
        issues.append(_issue("no_server_auth", "high"))

    return {
        "measured": True,
        "error": None,
        "protocol": fetched.get("protocol"),
        "cipher": fetched.get("cipher"),
        "chain_source": fetched.get("source"),
        "trusted": trusted,
        "verify_code": fetched.get("verify_code"),
        "chain_length": len(chain),
        "chain_complete": complete,
        "chain": chain,
        "leaf": leaf,
        "issues": issues,
        "grade": _grade(issues),
        "summary": {
            "validation": leaf["validation"],
            "key_type": leaf["key"]["type"],
            "key_bits": leaf["key"]["bits"],
            "signature": leaf["signature"].upper(),
            "validity_days": leaf["validity_days"],
            "days_remaining": leaf["days_remaining"],
            "sct_count": leaf["sct_count"],
            "wildcard": leaf["wildcard"],
            "self_signed": leaf["self_signed"],
            "issue_count": len(issues),
        },
    }
