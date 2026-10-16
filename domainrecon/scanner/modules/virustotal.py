# =============================================================================
# DomainRecon - Module « virustotal » : réputation du domaine et de l'IP (VirusTotal v3)
# =============================================================================
# Interroge l'API publique VirusTotal v3 (clé gratuite, 4 requêtes par minute) :
#   - GET /api/v3/domains/{domaine}      (sauf cible IP littérale) ;
#   - GET /api/v3/ip_addresses/{ip}      (adresse principale de la cible).
# Documentation : https://docs.virustotal.com/reference/domain-info et
# https://docs.virustotal.com/reference/ip-info. La clé voyage dans l'en-tête
# « x-apikey », jamais dans l'URL.
#
# Choix de lecture (faux positifs) :
#   - le verdict du DOMAINE fait foi : une adresse mutualisée (CDN, hébergeur)
#     porte souvent les détections de ses voisins, la leur est donc rapportée
#     avec une gravité moindre ;
#   - une seule détection sur une centaine de moteurs est un signal faible ;
#   - un 404 (objet inconnu de VirusTotal) n'est pas une erreur.
# Limites : quota gratuit (usage non commercial), réponses mises en cache 1 h.
# =============================================================================

import httpx

from ...i18n import msg
from ..cache import MEDIUM_TTL, cached
from ..common import proxy_scope
from ..errors import ModuleError, TargetNotAllowedError
from ..keys import ApiKey
from ..registry import ModuleSpec, ScanContext
from ..rules import FindingInput, FindingRule, Outcome, ScoreRule, hit
from ..score import as_dict, as_int, as_list

_API = "https://www.virustotal.com/api/v3"
_SERVICE = "VirusTotal"
_TIMEOUT = 15
# Moteurs détaillés dans le résultat (le rapport complet en compte plus de 90).
_MAX_ENGINES = 10
_MAX_CATEGORIES = 10


async def _get(client: httpx.AsyncClient, path: str, key: str) -> dict | None:
    """Attributs d'un objet VirusTotal, ou None s'il est inconnu (404). Lève ModuleError sinon."""
    try:
        response = await client.get(f"{_API}/{path}", headers={"x-apikey": key}, timeout=_TIMEOUT)
    except httpx.TimeoutException:
        raise ModuleError(msg("network.service_error", context=_SERVICE, detail=msg("net.timeout"))) from None
    except (httpx.HTTPError, TargetNotAllowedError) as e:
        # Jamais str(e) : le texte d'une erreur httpx cite l'URL.
        raise ModuleError(msg("network.service_error", context=_SERVICE, detail=type(e).__name__)) from None
    if response.status_code == 404:
        return None
    if response.status_code == 429:
        raise ModuleError(msg("network.quota", service=_SERVICE))
    if response.status_code != 200:
        raise ModuleError(msg("network.http_status", status=response.status_code, service=_SERVICE))
    try:
        data = as_dict(response.json())
    except ValueError:
        raise ModuleError(msg("virustotal.unreadable")) from None
    attributes = as_dict(as_dict(data.get("data")).get("attributes"))
    if not attributes:
        raise ModuleError(msg("virustotal.unreadable"))
    return attributes


def _text(value: object) -> str | None:
    return value if isinstance(value, str) else None


def _summary(attributes: dict) -> dict:
    """Résumé JSON d'un objet VirusTotal (domaine ou adresse)."""
    stats = as_dict(attributes.get("last_analysis_stats"))
    results = as_dict(attributes.get("last_analysis_results"))
    flagged = sorted(
        name
        for name, result in results.items()
        if as_dict(result).get("category") in ("malicious", "suspicious")
    )
    categories = attributes.get("categories")
    values = categories.values() if isinstance(categories, dict) else []
    votes = as_dict(attributes.get("total_votes"))
    return {
        "found": True,
        "malicious": as_int(stats.get("malicious")) or 0,
        "suspicious": as_int(stats.get("suspicious")) or 0,
        "harmless": as_int(stats.get("harmless")) or 0,
        "undetected": as_int(stats.get("undetected")) or 0,
        "reputation": as_int(attributes.get("reputation")) or 0,
        "votes_malicious": as_int(votes.get("malicious")) or 0,
        "votes_harmless": as_int(votes.get("harmless")) or 0,
        "categories": sorted({str(v) for v in values if isinstance(v, str)})[:_MAX_CATEGORIES],
        "flagged_engines": flagged[:_MAX_ENGINES],
        "last_analysis_date": as_int(attributes.get("last_analysis_date")),
        "country": _text(attributes.get("country")),
        "as_owner": _text(attributes.get("as_owner")),
    }


@cached(MEDIUM_TTL, scope=proxy_scope, ignore=("client", "key"))
async def _lookup(client: httpx.AsyncClient, key: str, kind: str, value: str) -> dict:
    """Rapport d'un domaine (kind « domains ») ou d'une adresse (« ip_addresses »), gardé 1 h."""
    attributes = await _get(client, f"{kind}/{value}", key)
    # `error` à None : seul un résultat sans erreur entre dans le cache.
    return {
        "measured": True,
        "error": None,
        **({"found": False} if attributes is None else _summary(attributes)),
    }


def _strip(report: dict | None) -> dict | None:
    """Rapport sans les champs de contrat (measured/error) : ils restent au niveau du module."""
    if report is None:
        return None
    return {k: v for k, v in report.items() if k not in ("measured", "error")}


async def run(context: ScanContext) -> dict:
    key = context.secrets.get("virustotal_key", "")
    domain = None
    if not context.is_ip_target:
        domain = await _lookup(context.http, key, "domains", context.domain)
    address = None
    if context.ip_address:
        address = await _lookup(context.http, key, "ip_addresses", context.ip_address)
    return {"measured": True, "error": None, "domain": _strip(domain), "ip": _strip(address)}


# -----------------------------------------------------------------------------
# Constats et score
# -----------------------------------------------------------------------------


def _report(data: object, part: str) -> dict:
    return as_dict(as_dict(data).get(part))


def _check_domain(f: FindingInput):
    report = _report(f.data, "domain")
    malicious = as_int(report.get("malicious")) or 0
    if malicious < 1:
        return None
    severity = "high" if malicious >= 5 else "medium" if malicious >= 2 else "low"
    engines = ", ".join(str(e) for e in as_list(report.get("flagged_engines")))
    return hit(severity=severity, count=malicious, engines=engines)


def _check_ip(f: FindingInput):
    # Adresse mutualisée possible : gravité plus basse, et seulement si le domaine n'est pas déjà signalé.
    malicious = as_int(_report(f.data, "ip").get("malicious")) or 0
    if malicious < 3 or (as_int(_report(f.data, "domain").get("malicious")) or 0) > 0:
        return None
    return hit(severity="medium" if malicious >= 10 else "low", count=malicious)


def _score(data: dict) -> Outcome:
    result = as_dict(data.get("virustotal"))
    report = _report(result, "domain")
    if not report.get("found"):
        report = _report(result, "ip")
    if not report.get("found"):
        return Outcome(0, msg("virustotal.score_unknown"), False)
    malicious = as_int(report.get("malicious")) or 0
    suspicious = as_int(report.get("suspicious")) or 0
    if malicious >= 5:
        return Outcome(0, msg("virustotal.score_flagged", count=malicious), True)
    if malicious >= 2:
        return Outcome(1, msg("virustotal.score_flagged", count=malicious), True)
    if malicious == 1 or suspicious >= 2:
        return Outcome(3, msg("virustotal.score_weak", count=malicious + suspicious), True)
    return Outcome(5, msg("virustotal.score_clean"), True)


SPEC = ModuleSpec(
    name="virustotal",
    family="reputation",
    category="cle_api",
    run=run,
    keys=(ApiKey(name="virustotal_key", service="virustotal", label="VirusTotal"),),
    wave=1,
    timeout=45,
    optional=True,
    order=610,
    findings=(
        FindingRule(code="finding.virustotal.domain_flagged", severity="medium", check=_check_domain),
        FindingRule(code="finding.virustotal.ip_flagged", severity="low", check=_check_ip),
    ),
    score_rules=(ScoreRule(criterion="virustotal", weight=5, evaluate=_score),),
)
