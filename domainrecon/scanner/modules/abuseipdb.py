# =============================================================================
# DomainRecon - Module « abuseipdb » : réputation de l'adresse IP (AbuseIPDB v2)
# =============================================================================
# GET https://api.abuseipdb.com/api/v2/check?ipAddress=…&maxAgeInDays=90
# Documentation : https://docs.abuseipdb.com/#check-endpoint. Clé gratuite (1000
# vérifications par jour) dans l'en-tête « Key », réponse en JSON (« Accept »).
#
# Points notables :
# score branché au barème et aux constats, réponses 401/403/422/429 distinguées,
# cache de 24 h (un appel du quota par adresse et par jour), adresse inscrite en
# liste blanche par AbuseIPDB écartée du constat (faux positif), message d'erreur
# sans clé ni URL.
# =============================================================================

import httpx

from ...i18n import msg
from ..cache import LONG_TTL, cached
from ..common import proxy_scope
from ..errors import ModuleError, TargetNotAllowedError
from ..keys import ApiKey
from ..registry import ModuleSpec, ScanContext, skip_without_address
from ..rules import FindingInput, FindingRule, Outcome, ScoreRule, hit
from ..score import as_dict, as_int

_API = "https://api.abuseipdb.com/api/v2/check"
_SERVICE = "AbuseIPDB"
_TIMEOUT = 15
_MAX_AGE_DAYS = 90
# Seuils du score de confiance d'abus (0 à 100).
_HIGH = 75
_MEDIUM = 50
_LOW = 25


def _text(value: object) -> str:
    return value if isinstance(value, str) else ""


@cached(LONG_TTL, scope=proxy_scope, ignore=("client", "key"))
async def _check(client: httpx.AsyncClient, key: str, address: str) -> dict:
    """Rapport AbuseIPDB d'une adresse, gardé 24 h (le quota gratuit est de 1000 appels par jour)."""
    try:
        response = await client.get(
            _API,
            params={"ipAddress": address, "maxAgeInDays": str(_MAX_AGE_DAYS)},
            headers={"Key": key, "Accept": "application/json"},
            timeout=_TIMEOUT,
        )
    except httpx.TimeoutException:
        raise ModuleError(msg("network.service_error", context=_SERVICE, detail=msg("net.timeout"))) from None
    except (httpx.HTTPError, TargetNotAllowedError) as e:
        # Jamais str(e) : le texte d'une erreur httpx cite l'URL.
        raise ModuleError(msg("network.service_error", context=_SERVICE, detail=type(e).__name__)) from None
    if response.status_code == 429:
        raise ModuleError(msg("network.quota", service=_SERVICE))
    if response.status_code != 200:
        raise ModuleError(msg("network.http_status", status=response.status_code, service=_SERVICE))
    try:
        data = as_dict(as_dict(response.json()).get("data"))
    except ValueError:
        raise ModuleError(msg("abuseipdb.unreadable")) from None
    score = as_int(data.get("abuseConfidenceScore"))
    if score is None:
        raise ModuleError(msg("abuseipdb.unreadable"))
    return {
        "measured": True,
        "error": None,
        "ip": _text(data.get("ipAddress")) or address,
        "abuse_confidence_score": score,
        "risk_level": "high" if score >= _HIGH else "medium" if score >= _LOW else "low",
        "total_reports": as_int(data.get("totalReports")) or 0,
        "num_distinct_users": as_int(data.get("numDistinctUsers")) or 0,
        "last_reported_at": data.get("lastReportedAt")
        if isinstance(data.get("lastReportedAt"), str)
        else None,
        "is_public": data.get("isPublic") is not False,
        "is_whitelisted": data.get("isWhitelisted") is True,
        "is_tor": data.get("isTor") is True,
        "country_code": _text(data.get("countryCode")),
        "usage_type": _text(data.get("usageType")),
        "isp": _text(data.get("isp")),
        "domain": _text(data.get("domain")),
        "max_age_days": _MAX_AGE_DAYS,
    }


async def run(context: ScanContext) -> dict:
    return await _check(context.http, context.secrets.get("abuseipdb_key", ""), context.ip_address)


# -----------------------------------------------------------------------------
# Constats et score
# -----------------------------------------------------------------------------


def _effective_score(data: dict) -> int:
    """Score retenu : 0 pour une adresse que AbuseIPDB a mise en liste blanche."""
    if data.get("is_whitelisted") is True:
        return 0
    return as_int(data.get("abuse_confidence_score")) or 0


def _check_abuse(f: FindingInput):
    data = as_dict(f.data)
    score = _effective_score(data)
    if score < _LOW:
        return None
    severity = "high" if score >= _HIGH else "medium" if score >= _MEDIUM else "low"
    return hit(
        severity=severity,
        score=score,
        reports=as_int(data.get("total_reports")) or 0,
        users=as_int(data.get("num_distinct_users")) or 0,
    )


def _score(data: dict) -> Outcome:
    result = as_dict(data.get("abuseipdb"))
    if as_int(result.get("abuse_confidence_score")) is None:
        return Outcome(0, msg("abuseipdb.unreadable"), False)
    score = _effective_score(result)
    detail = msg("abuseipdb.score_detail", score=score, reports=as_int(result.get("total_reports")) or 0)
    points = 0 if score >= _HIGH else 1 if score >= _MEDIUM else 3 if score >= _LOW else 5
    return Outcome(points, detail, True)


SPEC = ModuleSpec(
    name="abuseipdb",
    family="reputation",
    category="cle_api",
    run=run,
    keys=(ApiKey(name="abuseipdb_key", service="abuseipdb", label="AbuseIPDB"),),
    wave=1,
    timeout=30,
    optional=True,
    skip_reason=skip_without_address,
    order=630,
    findings=(FindingRule(code="finding.abuseipdb.reported", severity="medium", check=_check_abuse),),
    score_rules=(ScoreRule(criterion="abuseipdb", weight=5, evaluate=_score),),
)
