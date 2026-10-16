# =============================================================================
# DomainRecon - Module « otx » : réputation AlienVault OTX (LevelBlue)
# =============================================================================
# Interroge l'API publique d'OTX (https://otx.alienvault.com/api) :
#   - GET /api/v1/indicators/domain/{domaine}/general (ou IPv4/IPv6/{ip}/general
#     pour une cible IP) : nombre de « pulses » (listes de menaces publiées par la
#     communauté), étiquettes, familles de malwares, validations de liste blanche ;
#   - GET /api/v1/indicators/domain/{domaine}/passive_dns : DNS passif, réservé
#     aux requêtes authentifiées (429 « Anonymous access … limited » sans clé).
# La clé (facultative) voyage dans l'en-tête « X-OTX-API-KEY ».
#
# Piège évité (malicious = au moins un pulse) : tout grand domaine est cité dans des pulses (listes de
# surveillance, analyses de malwares qui le contactent). Le verdict tient donc
# compte des validations de liste blanche d'OTX (domaines populaires) et des
# familles de malwares / adversaires nommés dans les pulses :
#   propre         aucun pulse ;
#   cite           pulses, mais domaine en liste blanche ou sans indice de menace ;
#   suspect        pulses avec indices de menace (étiquettes, malwares, adversaire) ;
#   malveillant    au moins 3 pulses avec familles de malwares ou adversaire.
# =============================================================================

import httpx

from ...i18n import msg
from ..cache import MEDIUM_TTL, cached
from ..common import proxy_scope
from ..errors import ModuleError, TargetNotAllowedError
from ..keys import ApiKey
from ..registry import ModuleSpec, ScanContext
from ..rules import FindingInput, FindingRule, Outcome, ScoreRule
from ..score import as_dict, as_int, as_list
from ..targets import is_ip_literal

_API = "https://otx.alienvault.com/api/v1/indicators"
_SERVICE = "AlienVault OTX"
_TIMEOUT = 15
_MAX_PULSES = 5
_MAX_TAGS = 10
_MAX_MALWARE = 5
_MAX_PASSIVE_DNS = 15
# Nombre de pulses porteurs d'indices de menace à partir duquel le verdict est « malveillant ».
_MALICIOUS_PULSES = 3


def _headers(key: str) -> dict:
    headers = {"Accept": "application/json"}
    if key:
        headers["X-OTX-API-KEY"] = key
    return headers


async def _request(client: httpx.AsyncClient, path: str, key: str) -> httpx.Response:
    try:
        return await client.get(f"{_API}/{path}", headers=_headers(key), timeout=_TIMEOUT)
    except httpx.TimeoutException:
        raise ModuleError(msg("network.service_error", context=_SERVICE, detail=msg("net.timeout"))) from None
    except (httpx.HTTPError, TargetNotAllowedError) as e:
        # Jamais str(e) : le texte d'une erreur httpx cite l'URL.
        raise ModuleError(msg("network.service_error", context=_SERVICE, detail=type(e).__name__)) from None


def _names(items: object, field: str, limit: int) -> list[str]:
    found = []
    for item in as_list(items):
        value = as_dict(item).get(field) if isinstance(item, dict) else item
        if isinstance(value, str) and value and value not in found:
            found.append(value)
    return found[:limit]


def _analyze(general: dict) -> dict:
    """Verdict et éléments d'un rapport « general » d'OTX."""
    info = as_dict(general.get("pulse_info"))
    count = as_int(info.get("count")) or 0
    pulses = [as_dict(p) for p in as_list(info.get("pulses"))]
    validation = [as_dict(v) for v in as_list(general.get("validation"))]
    whitelisted = [v.get("name") for v in validation if isinstance(v.get("name"), str)]

    tags: list[str] = []
    malware: list[str] = []
    threat_pulses = 0
    for pulse in pulses:
        families = _names(pulse.get("malware_families"), "display_name", _MAX_MALWARE) or _names(
            pulse.get("malware_families"), "id", _MAX_MALWARE
        )
        adversary = pulse.get("adversary")
        for tag in _names(pulse.get("tags"), "", _MAX_TAGS):
            if tag not in tags:
                tags.append(tag)
        for family in families:
            if family not in malware:
                malware.append(family)
        if families or (isinstance(adversary, str) and adversary):
            threat_pulses += 1

    if count == 0:
        verdict = "clean"
    elif whitelisted:
        verdict = "mentioned"
    elif threat_pulses >= _MALICIOUS_PULSES:
        verdict = "malicious"
    elif threat_pulses or tags:
        verdict = "suspicious"
    else:
        verdict = "mentioned"
    return {
        "found": True,
        "pulse_count": count,
        "verdict": verdict,
        "malicious": verdict == "malicious",
        "whitelisted": bool(whitelisted),
        "whitelist_sources": whitelisted[:_MAX_PULSES],
        "threat_pulses": threat_pulses,
        "threat_types": tags[:_MAX_TAGS],
        "malware_families": malware[:_MAX_MALWARE],
        "sources": [name[:80] for name in _names(pulses, "name", _MAX_PULSES)],
    }


async def _passive_dns(client: httpx.AsyncClient, domain: str, key: str) -> list[dict] | None:
    """DNS passif (15 entrées), ou None si indisponible : service restreint, non fatal."""
    try:
        response = await _request(client, f"domain/{domain}/passive_dns", key)
        if response.status_code != 200:
            return None
        entries = as_list(as_dict(response.json()).get("passive_dns"))
    except (ModuleError, ValueError):
        return None
    rows = []
    for entry in entries:
        entry = as_dict(entry)
        if isinstance(entry.get("address"), str) and entry["address"]:
            rows.append(
                {
                    "ip": entry["address"],
                    "first": entry.get("first") if isinstance(entry.get("first"), str) else None,
                    "last": entry.get("last") if isinstance(entry.get("last"), str) else None,
                    "record_type": entry.get("record_type")
                    if isinstance(entry.get("record_type"), str)
                    else None,
                    "asn": entry.get("asn") if isinstance(entry.get("asn"), str) else None,
                }
            )
    return rows[:_MAX_PASSIVE_DNS]


@cached(MEDIUM_TTL, scope=proxy_scope, ignore=("client", "key"))
async def _lookup(client: httpx.AsyncClient, key: str, target: str) -> dict:
    """Rapport OTX d'un domaine ou d'une adresse IP, gardé 1 h."""
    if is_ip_literal(target):
        path = f"{'IPv6' if ':' in target else 'IPv4'}/{target}/general"
    else:
        path = f"domain/{target}/general"
    response = await _request(client, path, key)
    if response.status_code == 404:
        return {"measured": True, "error": None, "found": False, "pulse_count": 0, "verdict": "clean"}
    if response.status_code == 429:
        raise ModuleError(msg("network.quota", service=_SERVICE))
    if response.status_code != 200:
        raise ModuleError(msg("network.http_status", status=response.status_code, service=_SERVICE))
    try:
        general = as_dict(response.json())
    except ValueError:
        raise ModuleError(msg("otx.unreadable")) from None
    if "pulse_info" not in general:
        raise ModuleError(msg("otx.unreadable"))
    result = {"measured": True, "error": None, **_analyze(general)}
    if not is_ip_literal(target):
        passive = await _passive_dns(client, target, key)
        result["passive_dns"] = passive or []
        result["passive_dns_available"] = passive is not None
    return result


async def run(context: ScanContext) -> dict:
    key = context.secrets.get("otx_key", "")
    result = await _lookup(context.http, key, context.domain)
    return {**result, "authenticated": bool(key)}


# -----------------------------------------------------------------------------
# Constats et score
# -----------------------------------------------------------------------------


def _check_malicious(f: FindingInput):
    data = as_dict(f.data)
    if data.get("verdict") != "malicious":
        return None
    return {
        "pulses": as_int(data.get("pulse_count")) or 0,
        "malware": ", ".join(str(m) for m in as_list(data.get("malware_families"))) or "-",
    }


def _check_suspicious(f: FindingInput):
    data = as_dict(f.data)
    if data.get("verdict") != "suspicious":
        return None
    return {
        "pulses": as_int(data.get("pulse_count")) or 0,
        "tags": ", ".join(str(t) for t in as_list(data.get("threat_types"))[:5]) or "-",
    }


def _score(data: dict) -> Outcome:
    result = as_dict(data.get("otx"))
    verdict = result.get("verdict")
    count = as_int(result.get("pulse_count")) or 0
    if verdict == "malicious":
        return Outcome(0, msg("otx.score_malicious", pulses=count), True)
    if verdict == "suspicious":
        return Outcome(1, msg("otx.score_suspicious", pulses=count), True)
    if verdict == "mentioned":
        return Outcome(3, msg("otx.score_mentioned", pulses=count), True)
    return Outcome(3, msg("otx.score_clean"), True)


SPEC = ModuleSpec(
    name="otx",
    family="reputation",
    category="passif",
    run=run,
    keys=(ApiKey(name="otx_key", service="otx", label="AlienVault OTX", required=False),),
    wave=1,
    timeout=45,
    optional=True,
    order=620,
    findings=(
        FindingRule(code="finding.otx.malicious", severity="high", check=_check_malicious),
        FindingRule(code="finding.otx.suspicious", severity="medium", check=_check_suspicious),
    ),
    score_rules=(ScoreRule(criterion="otx", weight=3, evaluate=_score),),
)
