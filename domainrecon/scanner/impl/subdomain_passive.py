# =============================================================================
# DomainRecon - Sous-domaines : sources passives complémentaires (module « subdomains_passive »)
# =============================================================================
# Interroge en parallèle les sources gratuites de impl/subdomain_sources.py
# (HackerTarget, RapidDNS, Anubis, AlienVault OTX, urlscan.io, Wayback Machine et,
# avec clé facultative, SecurityTrails), classe les noms (surface la plus exposée
# d'abord), résout les premiers et marque ceux qui tombent sous un joker DNS.
# Complète le module « subdomains » (journaux Certificate Transparency) : un nom
# est rarement vu partout, c'est la réunion des deux qui donne la meilleure carte.
# Le module n'échoue que si TOUTES les sources échouent.
# =============================================================================

import asyncio
from typing import TYPE_CHECKING

from ...i18n import msg
from .. import dns as scanner_dns
from ..common import logger
from ..errors import ModuleError
from ..targets import resolve_ip
from . import subdomain_sources

if TYPE_CHECKING:
    from ..registry import ScanContext

RESOLVE_LIMIT = scanner_dns.SUBDOMAIN_RESOLVE_LIMIT
MAX_RESULTS = scanner_dns.SUBDOMAIN_MAX_RESULTS
RESOLVE_CONCURRENCY = scanner_dns.SUBDOMAIN_RESOLVE_CONCURRENCY


def _priority(name: str, sources: int) -> tuple:
    """Clé de tri : labels les plus exposés d'abord, noms vus par plusieurs sources avant les autres."""
    base = scanner_dns._subdomain_priority(name)
    return (base[0], -sources, *base[1:])


async def enumerate_subdomains(context: "ScanContext") -> dict:
    """Sous-domaines de `context.site` d'après les sources passives complémentaires."""
    domain = (context.site or "").strip().lower().rstrip(".")
    key = context.secrets.get("securitytrails_key") or None
    found, reports = await subdomain_sources.collect_extra(context.http, domain, key)
    if not any(report.status == "ok" for report in reports):
        errors = [report.error for report in reports if report.error is not None]
        raise ModuleError(msg("subdomains_passive.all_failed", errors=errors, sep="; "))

    ordered = sorted(found, key=lambda name: _priority(name, len(found[name])))
    total_found = len(ordered)
    if total_found > MAX_RESULTS:
        logger.warning(
            "%d sous-domaines trouvés pour %s, liste limitée à %d", total_found, domain, MAX_RESULTS
        )
        ordered = ordered[:MAX_RESULTS]

    semaphore = asyncio.Semaphore(RESOLVE_CONCURRENCY)

    async def resolve_sub(name: str) -> dict:
        async with semaphore:
            try:
                ip = await resolve_ip(name)
            except Exception as e:
                # Un nom anormal ne doit pas faire échouer tout le module.
                logger.debug("Résolution de %s échouée : %r", name, e)
                ip = None
        return {
            "subdomain": name,
            "ip": ip,
            "resolution": "resolved" if ip else "unresolved",
            "sources": sorted(found[name]),
        }

    to_resolve = ordered[:RESOLVE_LIMIT]
    resolved: list[dict] = []
    if to_resolve:
        wildcard, *resolved = await asyncio.gather(
            scanner_dns._wildcard_addresses(domain), *[resolve_sub(name) for name in to_resolve]
        )
        if wildcard:
            for entry in resolved:
                if entry["ip"] in wildcard:
                    entry["wildcard"] = True
    not_tested = [
        {"subdomain": name, "ip": None, "resolution": "not_tested", "sources": sorted(found[name])}
        for name in ordered[RESOLVE_LIMIT:]
    ]
    return {
        "measured": True,
        "error": None,
        "domain": domain,
        "subdomains": [*resolved, *not_tested],
        "count": len(ordered),
        "total_found": total_found,
        "sources": [report.as_dict() for report in reports],
    }
