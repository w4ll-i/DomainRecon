# =============================================================================
# DomainRecon - Module « dns_rebinding » : IP privée exposée en DNS
# =============================================================================
# Cherche des adresses NON PUBLIQUES dans les réponses DNS publiques de la cible :
# 10/8, 172.16/12, 192.168/16, 127/8, 169.254/16, 100.64/10 en IPv4 ; ::1, fc00::/7,
# fe80::/10 en IPv6 (les adresses « mappées » ::ffff:a.b.c.d sont ramenées à leur
# IPv4). Examine les enregistrements A ET AAAA du site, de la cible et de ses MX
# principaux. Une adresse interne publiée révèle le plan d'adressage du réseau et
# sert de point d'appui aux attaques par rebinding DNS contre les navigateurs du
# réseau interne.
# Renommé « IP privée exposée en DNS » : l'ancien nom « DNS rebinding » promettait
# une détection de l'attaque elle-même, que la lecture des enregistrements ne
# permet pas. Les motifs IPv4 et IPv6 sont lus.
# Passif. Sans objet pour une adresse IP.
# =============================================================================

import asyncio

from ...i18n import msg
from .. import dns
from ..errors import ModuleError
from ..impl import dns_tools
from ..registry import ModuleSpec, ScanContext, skip_for_ip_target
from ..rules import FindingInput, FindingRule, Outcome, ScoreRule, hit
from ..score import as_dict, as_list

QUERY_TIMEOUT = 3.0
BUDGET = 25.0
MAX_MX = 3

# Gravité selon la catégorie : bouclage ou plage réservée = reste de test ; réseau privé = fuite d'adressage.
_SEVERITY = {"private": "medium", "link_local": "medium", "shared": "medium"}


def _scan(hosts: list[str]) -> dict:
    querier = dns.DnsQuerier(QUERY_TIMEOUT, BUDGET)
    names = list(dict.fromkeys(hosts))
    # MX principaux : une messagerie interne publiée dans le DNS est la fuite la plus courante.
    mx = querier.lookup(names[0], "MX")
    if mx.status == "ok":
        exchanges = sorted(mx.answers, key=lambda r: r.preference)
        for record in exchanges[:MAX_MX]:
            host = str(record.exchange).rstrip(".").lower()
            if host and host not in names:
                names.append(host)
    entries = []
    answered = False
    for host in names:
        addresses, failed = dns_tools.addresses_of(querier, host)
        answered = answered or bool(addresses) or not failed
        private = [
            {"address": address, "kind": kind}
            for address in addresses
            if (kind := dns_tools.classify_address(address))
        ]
        entries.append({"host": host, "addresses": addresses, "private": private})
    return {"entries": entries, "answered": answered}


async def run(context: ScanContext) -> dict:
    hosts = [context.domain, *([context.site] if context.site != context.domain else [])]
    scan = await asyncio.to_thread(_scan, hosts)
    if not scan["answered"]:
        raise ModuleError(msg("dns_rebinding.query_failed", host=context.domain))
    private = [{"host": entry["host"], **item} for entry in scan["entries"] for item in entry["private"]]
    return {
        "measured": True,
        "error": None,
        "hosts": scan["entries"],
        "exposed": bool(private),
        "private_addresses": private,
        "count": len(private),
    }


def _check_private(f: FindingInput) -> list | None:
    hits = []
    for entry in as_list(as_dict(f.data).get("hosts")):
        entry = as_dict(entry)
        private = [as_dict(item) for item in as_list(entry.get("private"))]
        if not private:
            continue
        worst = "medium" if any(_SEVERITY.get(str(p.get("kind"))) for p in private) else "low"
        addresses = [str(p.get("address")) for p in private]
        hits.append(hit(severity=worst, host=str(entry.get("host")), addresses=addresses))
    return hits or None


def _score(data: dict) -> Outcome:
    result = as_dict(data.get("dns_rebinding"))
    count = int(result.get("count") or 0)
    if count:
        return Outcome(0, msg("dns_rebinding.score_exposed", count=count), True)
    return Outcome(3, msg("dns_rebinding.score_clean"), True)


SPEC = ModuleSpec(
    name="dns_rebinding",
    family="dns",
    category="passif",
    run=run,
    skip_reason=skip_for_ip_target,
    order=24,
    findings=(FindingRule(code="finding.dns_rebinding.private_ip", severity="medium", check=_check_private),),
    score_rules=(
        ScoreRule(criterion="dns_rebinding", weight=3, evaluate=_score, not_applicable_for_ip=True),
    ),
)
