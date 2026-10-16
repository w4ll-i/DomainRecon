# =============================================================================
# DomainRecon - Module « shodan » : ports, services et CVE vus par Shodan
# =============================================================================
# Utilise aussi InternetDB, la base
# gratuite de Shodan, qui rend le module utile SANS clé :
#   - avec la clé (shodan_key, facultative) : API hôte, avec services, bannières,
#     produits, versions et CVE par service (https://developer.shodan.io/api) ;
#   - sans clé, ou si la clé échoue (quota, panne) : InternetDB, qui donne ports,
#     noms d'hôte, CPE, tags et CVE (https://internetdb.shodan.io).
# Une clé refusée (401) est signalée dans `key_error` sans faire échouer le module.
# La clé n'apparaît jamais dans un message, un journal ni le résultat.
# Limites : Shodan décrit l'adresse telle que SES sondes l'ont vue (parfois il y
# a des semaines) ; derrière un CDN, c'est le CDN qui est décrit. Ses CVE sont
# déduites des bannières, donc à vérifier (correctifs rétroportés).
# =============================================================================

from ...i18n import msg
from ..errors import ModuleError, ModuleSkipped
from ..impl import shodan as shodan_api
from ..keys import ApiKey
from ..registry import ModuleSpec, ScanContext, skip_without_address
from ..rules import FindingInput, FindingRule, Outcome, ScoreRule, hit
from ..score import as_dict, as_list
from ..targets import is_public_address


async def run(context: ScanContext) -> dict:
    ip = context.ip_address
    if ip is None or not is_public_address(ip):
        raise ModuleSkipped(msg("shodan.not_public"))
    key = context.secrets.get("shodan_key")
    source = None
    data = None
    key_error = None
    if key:
        try:
            data = await shodan_api.host(context.http, ip, key)
            source = "shodan"
        except ModuleError as error:
            # Clé refusée, quota ou panne : InternetDB prend le relais, l'erreur reste visible.
            key_error = error.message
    if source is None:
        data = await shodan_api.internetdb(context.http, ip)
        source = "internetdb"
    result = {
        "measured": True,
        "error": None,
        "ip": ip,
        "source": source,
        "key_used": bool(key) and source == "shodan",
        "key_error": key_error,
        "found": data is not None,
    }
    if data is not None:
        result.update(data)
    return result


# -----------------------------------------------------------------------------
# Constats et score
# -----------------------------------------------------------------------------


def _vulns(f: FindingInput) -> list[dict]:
    return [v for v in as_list(as_dict(f.data).get("vulns")) if isinstance(v, dict)]


def _check_vulns(f: FindingInput):
    vulns = _vulns(f)
    if not vulns:
        return None
    top = vulns[0]
    cvss = float(top.get("cvss") or 0)
    total = int(as_dict(f.data).get("vuln_count") or len(vulns))
    severity = "high" if cvss >= 7 or any(v.get("verified") for v in vulns) else "medium"
    return hit(severity=severity, count=total, cve=str(top.get("id") or "?"))


def _score(data: dict) -> Outcome:
    shodan = as_dict(data.get("shodan"))
    vulns = [v for v in as_list(shodan.get("vulns")) if isinstance(v, dict)]
    count = int(shodan.get("vuln_count") or len(vulns))
    if not count:
        return Outcome(5, msg("shodan.score_clean"), True)
    cvss = max((float(v.get("cvss") or 0) for v in vulns), default=0.0)
    points = 0 if cvss >= 9 else 1 if cvss >= 7 else 3
    return Outcome(points, msg("shodan.score_vulns", count=count), True)


SPEC = ModuleSpec(
    name="shodan",
    family="network",
    category="passif",
    run=run,
    keys=(ApiKey(name="shodan_key", service="shodan", label="Shodan", required=False),),
    skip_reason=skip_without_address,
    wave=1,
    timeout=40,
    optional=True,
    order=240,
    findings=(FindingRule(code="finding.shodan.vulnerabilities", severity="medium", check=_check_vulns),),
    score_rules=(ScoreRule(criterion="shodan", weight=5, evaluate=_score),),
)
