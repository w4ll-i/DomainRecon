# =============================================================================
# DomainRecon - Module « wildcard_dns » : joker DNS (*.domaine)
# =============================================================================
# Résout trois labels aléatoires du domaine du site (A et AAAA), puis un nom à
# deux niveaux : s'ils résolvent, un joker DNS répond à n'importe quel nom. Les
# adresses de toutes les sondes sont réunies (un joker derrière un CDN change
# d'adresse d'une requête à l'autre). Un joker rend l'énumération de
# sous-domaines trompeuse (tout « existe ») : « subdomains » marque les entrées
# qui tombent dessus, « subdomain_bruteforce » les écarte. Un joker qui pointe
# vers un service tiers (CNAME externe) élargit le risque de détournement.
# Passif : quelques requêtes DNS publiques. Sans objet pour une adresse IP.
# =============================================================================

import asyncio

from ...i18n import msg
from .. import dns
from ..errors import ModuleError
from ..http_utils import same_site
from ..impl import dns_tools
from ..registry import ModuleSpec, ScanContext, skip_for_ip_target
from ..rules import FindingInput, FindingRule
from ..score import as_dict

QUERY_TIMEOUT = 3.0
BUDGET = 25.0


def _probe(zone: str) -> dns_tools.WildcardProbe:
    return dns_tools.probe_wildcard(dns.DnsQuerier(QUERY_TIMEOUT, BUDGET), zone)


async def run(context: ScanContext) -> dict:
    zone = context.site
    probe = await asyncio.to_thread(_probe, zone)
    if probe.probes == 0 and probe.failed:
        raise ModuleError(msg("wildcard_dns.query_failed", zone=zone))
    return {
        "measured": True,
        "error": None,
        "zone": zone,
        "wildcard": probe.wildcard,
        "intermittent": probe.intermittent,
        "addresses": sorted(probe.addresses),
        "cname": probe.cname,
        "cname_external": bool(probe.cname) and not same_site(probe.cname, zone),
        "deep": probe.deep_positive,
        "probes": probe.probes,
        "positives": probe.positives,
        "failed": probe.failed,
        "test_names": probe.names,
    }


def _check_external_cname(f: FindingInput) -> dict | None:
    data = as_dict(f.data)
    if data.get("wildcard") and data.get("cname_external") and data.get("cname"):
        return {"zone": str(data.get("zone") or ""), "cname": str(data["cname"])}
    return None


SPEC = ModuleSpec(
    name="wildcard_dns",
    family="dns",
    category="passif",
    run=run,
    skip_reason=skip_for_ip_target,
    order=23,
    findings=(
        FindingRule(
            code="finding.wildcard_dns.external_cname", severity="medium", check=_check_external_cname
        ),
    ),
)
