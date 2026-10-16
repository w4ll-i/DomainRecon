# =============================================================================
# DomainRecon - Module « safebrowsing » : Google Safe Browsing (API v5)
# =============================================================================
# L'API v4 (threatMatches:find) est dépréciée : ce
# module utilise la v5, méthode hashes.search
# (https://developers.google.com/safe-browsing/reference/rest/v5/hashes/search).
#
# Principe : l'URL n'est jamais envoyée à Google. Le client calcule les
# « expressions » de l'URL (suffixes d'hôte + chemin « / »), leur SHA-256, envoie
# les préfixes de 4 octets (GET hashes:search?hashPrefixes=…, base64) puis compare
# les empreintes complètes de la réponse (fullHashes) aux siennes. Les détails
# marqués CANARY (jamais pour l'application) ou inconnus sont ignorés, comme le
# demande la documentation. Les clés Google Cloud passent par l'en-tête
# « x-goog-api-key » : elles n'apparaissent pas dans l'URL.
#
# Types de menace : MALWARE, SOCIAL_ENGINEERING (hameçonnage),
# UNWANTED_SOFTWARE, POTENTIALLY_HARMFUL_APPLICATION. Usage non commercial.
# =============================================================================

import base64
import hashlib

import httpx

from ...i18n import msg
from ..cache import SHORT_TTL, cached
from ..common import proxy_scope
from ..errors import ModuleError, TargetNotAllowedError
from ..keys import ApiKey
from ..registry import ModuleSpec, ScanContext
from ..rules import FindingInput, FindingRule, Outcome, ScoreRule, hit
from ..score import as_dict, as_list

_API = "https://safebrowsing.googleapis.com/v5/hashes:search"
_SERVICE = "Google Safe Browsing"
_TIMEOUT = 15
# Longueur des préfixes envoyés (exactement 4 octets en v5).
_PREFIX_BYTES = 4
# Composants d'hôte conservés au plus (spécification : l'hôte exact et 4 suffixes).
_MAX_HOST_SUFFIXES = 5
# Types de menace connus du client ; tout autre détail est ignoré (consigne de la documentation).
_THREAT_TYPES = (
    "MALWARE",
    "SOCIAL_ENGINEERING",
    "UNWANTED_SOFTWARE",
    "POTENTIALLY_HARMFUL_APPLICATION",
)
_IGNORED_ATTRIBUTES = frozenset({"CANARY", "THREAT_ATTRIBUTE_UNSPECIFIED"})
_SEVERE = frozenset({"MALWARE", "SOCIAL_ENGINEERING"})


def host_expressions(host: str) -> list[str]:
    """Expressions Safe Browsing de la page d'accueil d'un hôte : « hôte/ » et ses suffixes de domaine."""
    host = host.strip(".").lower()
    if not host:
        return []
    labels = host.split(".")
    expressions = [f"{host}/"]
    # Une IP littérale n'a pas de suffixe ; sinon on retire les labels de tête, en gardant au moins deux composants.
    if not all(part.isdigit() for part in labels) and ":" not in host:
        for index in range(1, len(labels) - 1):
            if len(expressions) >= _MAX_HOST_SUFFIXES:
                break
            expressions.append(".".join(labels[index:]) + "/")
    return expressions


def _is_ip(host: str) -> bool:
    return ":" in host or all(part.isdigit() for part in host.split("."))


def target_expressions(domain: str, apex: str) -> list[str]:
    """Expressions à vérifier pour la cible : elle-même, ses suffixes de domaine et, pour l'apex, « www. »."""
    hosts = [domain]
    if not _is_ip(domain):
        if domain == apex:
            hosts.append(f"www.{domain}")
        elif apex and domain.endswith(f".{apex}"):
            hosts.append(apex)
    found: list[str] = []
    for host in hosts:
        for expression in host_expressions(host):
            if expression not in found:
                found.append(expression)
    return found


def _digest(expression: str) -> bytes:
    return hashlib.sha256(expression.encode("utf-8")).digest()


@cached(SHORT_TTL, scope=proxy_scope, ignore=("client", "key"))
async def _search(client: httpx.AsyncClient, key: str, expressions: tuple[str, ...]) -> dict:
    """Interroge hashes:search et rapproche les empreintes complètes de celles des expressions."""
    hashes = {_digest(e): e for e in expressions}
    prefixes = sorted({base64.b64encode(h[:_PREFIX_BYTES]).decode("ascii") for h in hashes})
    try:
        response = await client.get(
            _API,
            params=[("hashPrefixes", p) for p in prefixes],
            headers={"x-goog-api-key": key, "Accept": "application/json"},
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
        data = as_dict(response.json())
    except ValueError:
        raise ModuleError(msg("safebrowsing.unreadable")) from None
    if not isinstance(data.get("fullHashes", []), list):
        raise ModuleError(msg("safebrowsing.unreadable"))

    threats: list[dict] = []
    for item in as_list(data.get("fullHashes")):
        item = as_dict(item)
        try:
            text = str(item.get("fullHash", "")).replace("-", "+").replace("_", "/")
            full = base64.b64decode(text + "=" * (-len(text) % 4))
        except ValueError:
            continue
        expression = hashes.get(full)
        if expression is None:
            # Collision de préfixe : une autre URL que les nôtres, sans rapport avec la cible.
            continue
        for detail in as_list(item.get("fullHashDetails")):
            detail = as_dict(detail)
            threat = detail.get("threatType")
            attributes = [a for a in as_list(detail.get("attributes")) if isinstance(a, str)]
            if threat not in _THREAT_TYPES or _IGNORED_ATTRIBUTES & set(attributes):
                continue
            threats.append(
                {"threat_type": threat, "expression": expression, "attributes": sorted(attributes)}
            )
    threats.sort(key=lambda t: (t["threat_type"], t["expression"]))
    return {
        "measured": True,
        "error": None,
        "safe": not threats,
        "threat_count": len(threats),
        "threat_types": sorted({t["threat_type"] for t in threats}),
        "threats": threats,
        "checked": list(expressions),
    }


async def run(context: ScanContext) -> dict:
    expressions = tuple(target_expressions(context.domain, context.apex))
    key = context.secrets.get("safebrowsing_key", "")
    result = await _search(context.http, key, expressions)
    return {**result, "domain": context.domain, "api_version": 5}


# -----------------------------------------------------------------------------
# Constats et score
# -----------------------------------------------------------------------------

_KNOWN_THREATS = frozenset(_THREAT_TYPES)


def _threat_label(threat: str):
    # Codes littéraux : un code calculé échapperait au contrôle des textes.
    if threat == "MALWARE":
        return msg("safebrowsing.threat_malware")
    if threat == "SOCIAL_ENGINEERING":
        return msg("safebrowsing.threat_social_engineering")
    if threat == "UNWANTED_SOFTWARE":
        return msg("safebrowsing.threat_unwanted_software")
    return msg("safebrowsing.threat_harmful_application")


def _check_flagged(f: FindingInput):
    data = as_dict(f.data)
    types = [t for t in as_list(data.get("threat_types")) if t in _KNOWN_THREATS]
    if not types:
        return None
    severity = "critical" if _SEVERE & set(types) else "high"
    return hit(severity=severity, threats=[_threat_label(t) for t in types])


def _score(data: dict) -> Outcome:
    result = as_dict(data.get("safebrowsing"))
    types = [t for t in as_list(result.get("threat_types")) if t in _KNOWN_THREATS]
    if result.get("safe") is True and not types:
        return Outcome(5, msg("safebrowsing.score_safe"), True)
    if not types:
        return Outcome(0, msg("safebrowsing.unreadable"), False)
    cap = msg("safebrowsing.cap_reason") if _SEVERE & set(types) else None
    return Outcome(
        0, msg("safebrowsing.score_flagged", threats=[_threat_label(t) for t in types]), True, True, cap
    )


SPEC = ModuleSpec(
    name="safebrowsing",
    family="reputation",
    category="cle_api",
    run=run,
    keys=(ApiKey(name="safebrowsing_key", service="safebrowsing", label="Google Safe Browsing"),),
    wave=1,
    timeout=30,
    optional=True,
    order=640,
    findings=(FindingRule(code="finding.safebrowsing.flagged", severity="critical", check=_check_flagged),),
    score_rules=(ScoreRule(criterion="safebrowsing", weight=5, evaluate=_score),),
)
