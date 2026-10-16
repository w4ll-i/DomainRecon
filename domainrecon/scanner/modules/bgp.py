# =============================================================================
# DomainRecon - Module « bgp » : ASN, préfixes annoncés et pairs BGP de l'adresse IP
# =============================================================================
# BGPView ayant fermé en novembre 2025, deux sources vivantes, sans clé :
#   - RIPEstat (https://stat.ripe.net/docs/02.data-api/) : prefix-overview,
#     announced-prefixes, asn-neighbours ;
#   - Team Cymru (DNS, https://www.team-cymru.com/ip-asn-mapping) : ASN d'origine.
# Les deux sources sont interrogées ensemble : une seule suffit à conclure. Une
# adresse non annoncée en BGP (rare, ex. plage retirée) n'est pas une erreur.
# Limites : les pairs viennent des collecteurs de RIPE (vue partielle de la table
# de routage) ; la liste des préfixes est bornée (le total est donné à côté).
# =============================================================================

import asyncio

from ...i18n import msg
from ..errors import ModuleSkipped
from ..impl import bgp_sources as sources
from ..registry import ModuleSpec, ScanContext, skip_without_address
from ..targets import is_public_address


async def run(context: ScanContext) -> dict:
    ip = context.ip_address
    if ip is None or not is_public_address(ip):
        # Adresse interne (ALLOW_PRIVATE_TARGETS) : rien à apprendre d'un service public.
        raise ModuleSkipped(msg("bgp.not_public"))
    origin = await sources.asn_of(context.http, ip)
    result: dict = {
        "measured": True,
        "error": None,
        "ip": ip,
        "announced": origin["announced"],
        "asn": origin["asn"],
        "holder": origin["holder"],
        "prefix": origin["prefix"],
        "country": origin["country"],
        "rir": origin["rir"],
        "sources": origin["sources"],
        "prefixes_v4": [],
        "prefixes_v6": [],
        "prefixes_total": 0,
        "peers": [],
        "peers_total": 0,
        "upstreams": 0,
        "downstreams": 0,
        "prefixes_error": None,
        "peers_error": None,
    }
    if not origin["asn"]:
        return result

    # Préfixes et pairs : un échec de l'un n'annule ni l'autre ni l'ASN déjà établi.
    prefixes, peers = await asyncio.gather(
        sources.ripestat_prefixes(context.http, origin["asn"]),
        sources.ripestat_neighbours(context.http, origin["asn"]),
        return_exceptions=True,
    )
    for outcome in (prefixes, peers):
        if isinstance(outcome, BaseException) and not isinstance(outcome, Exception):
            raise outcome
    if isinstance(prefixes, Exception):
        result["prefixes_error"] = _message(prefixes)
    else:
        result.update(
            prefixes_v4=prefixes["v4"],
            prefixes_v6=prefixes["v6"],
            prefixes_total=prefixes["total_v4"] + prefixes["total_v6"],
        )
    if isinstance(peers, Exception):
        result["peers_error"] = _message(peers)
    else:
        result.update(
            peers=peers["peers"],
            peers_total=peers["total"],
            upstreams=peers["upstreams"],
            downstreams=peers["downstreams"],
        )
    if not result["holder"]:
        try:
            result["holder"] = await sources.ripestat_holder(context.http, origin["asn"])
        except Exception as e:  # titulaire facultatif : l'ASN suffit
            context.logger.debug("Titulaire de %s indisponible : %s", origin["asn"], type(e).__name__)
    return result


def _message(error: Exception) -> object:
    """Message traduisible d'une erreur de service (jamais le texte brut d'une exception)."""
    message = getattr(error, "message", None)
    return (
        message if message else msg("network.service_error", context="RIPEstat", detail=type(error).__name__)
    )


SPEC = ModuleSpec(
    name="bgp",
    family="network",
    category="passif",
    run=run,
    skip_reason=skip_without_address,
    wave=1,
    timeout=45,
    optional=True,
    order=210,
)
