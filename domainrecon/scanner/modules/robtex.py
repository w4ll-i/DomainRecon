# =============================================================================
# DomainRecon - Module « robtex » : DNS passif Robtex
# =============================================================================
# Historique DNS d'un domaine (adresses A/AAAA, MX, NS, CNAME déjà vus) ou, pour
# une cible IP, réseau et noms vus sur l'adresse. API gratuite sans clé
# (https://www.robtex.com/api/), limitée à 10 requêtes par heure : une seule
# requête par scan, résultat gardé une heure (impl/robtex.py).
# Les adresses A/AAAA qui ne sont plus celles de la cible (`historical_ips`)
# sont la piste classique d'un ancien hébergement ou d'une IP d'origine.
# Limites : base collaborative et partielle ; l'absence d'un enregistrement ne
# prouve rien.
# =============================================================================

from ..impl import robtex as robtex_api
from ..registry import ModuleSpec, ScanContext


async def run(context: ScanContext) -> dict:
    current = set(context.addresses)
    if context.is_ip_target:
        info = await robtex_api.ip_query(context.http, context.domain)
        return {"measured": True, "error": None, "mode": "ip", "target": context.domain, **info}
    data = await robtex_api.forward(context.http, context.domain)
    records = data["records"]
    by_type: dict[str, int] = {}
    for record in records:
        by_type[record["type"]] = by_type.get(record["type"], 0) + 1
    historical = sorted(
        {r["data"] for r in records if r["type"] in ("A", "AAAA") and r["data"] not in current}
    )
    return {
        "measured": True,
        "error": None,
        "mode": "domain",
        "target": context.domain,
        "records": records,
        "total": data["total"],
        "by_type": by_type,
        "historical_ips": historical,
    }


SPEC = ModuleSpec(
    name="robtex",
    family="network",
    category="passif",
    run=run,
    wave=1,
    timeout=30,
    optional=True,
    order=230,
)
