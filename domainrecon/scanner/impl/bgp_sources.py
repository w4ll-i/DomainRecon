# =============================================================================
# DomainRecon - Sources BGP / ASN : RIPEstat et Team Cymru
# =============================================================================
# BGPView (api.bgpview.io) est fermé depuis novembre 2025 : ses données (ASN,
# préfixes annoncés, pairs BGP) viennent désormais de deux sources vivantes.
#   - RIPEstat (https://stat.ripe.net/docs/02.data-api/), gratuit, sans clé,
#     HTTPS : prefix-overview (ASN et préfixe d'une IP), as-overview,
#     announced-prefixes, asn-neighbours, geoloc ;
#   - Team Cymru (https://www.team-cymru.com/ip-asn-mapping), en DNS :
#     TXT <ip inversée>.origin.asn.cymru.com (origin6 pour IPv6) et
#     AS<n>.asn.cymru.com pour le nom du système autonome.
# Ce fichier sert aussi aux modules geo_data, network_extended et origin_ip.
# Les réponses de RIPEstat sont gardées en cache (1 h) : un scan interroge
# souvent la même IP depuis plusieurs modules.
# =============================================================================

import asyncio
import ipaddress

import httpx

from ...i18n import msg
from ..cache import MEDIUM_TTL, cached
from ..common import proxy_scope
from ..dns import DnsQuerier, txt_record_text
from ..errors import ModuleError
from . import network_http as nh

RIPESTAT_URL = "https://stat.ripe.net/data/{call}/data.json"
RIPESTAT_SOURCEAPP = "domainrecon"
RIPESTAT_SERVICE = "RIPEstat"
CYMRU_ORIGIN4 = "origin.asn.cymru.com"
CYMRU_ORIGIN6 = "origin6.asn.cymru.com"
CYMRU_ASN = "asn.cymru.com"

# Bornes des listes renvoyées (le total est toujours donné à côté).
MAX_PREFIXES_V4 = 30
MAX_PREFIXES_V6 = 10
MAX_PEERS = 40


# =============================================================================
# RIPEstat
# =============================================================================


@cached(MEDIUM_TTL, scope=proxy_scope, ignore=("client",), max_entries=256)
async def ripestat(client: httpx.AsyncClient | None, call: str, resource: str) -> dict:
    """Champ `data` d'un appel RIPEstat ; lève ModuleError (réseau, quota, réponse illisible ou dépréciée)."""
    async with nh.use_client(client, timeout=15) as http:
        response = await nh.get(
            http,
            RIPESTAT_URL.format(call=call),
            service=RIPESTAT_SERVICE,
            params={"resource": resource, "sourceapp": RIPESTAT_SOURCEAPP},
        )
    if response.status_code != 200:
        raise nh.status_error(RIPESTAT_SERVICE, response.status_code)
    body = nh.parse_json(response)
    data = body.get("data") if isinstance(body, dict) else None
    # data_call_status « deprecated » : endpoint à retirer, ses données ne sont plus fiables.
    if not isinstance(data, dict) or str(body.get("data_call_status", "")).startswith("deprecated"):
        raise ModuleError(msg("bgp.unreadable", service=RIPESTAT_SERVICE))
    return data


def parse_prefix_overview(data: dict) -> dict:
    """ASN, titulaire et préfixe annoncé d'une IP d'après prefix-overview (annoncée ou non)."""
    asns = [a for a in data.get("asns") or [] if isinstance(a, dict) and a.get("asn") is not None]
    first = asns[0] if asns else {}
    block = data.get("block") if isinstance(data.get("block"), dict) else {}
    return {
        "announced": bool(asns),
        "asn": f"AS{first['asn']}" if first else None,
        "holder": str(first.get("holder") or "") or None,
        # Sans annonce BGP, « resource » n'est que l'adresse demandée, pas un préfixe.
        "prefix": (str(data.get("resource") or "") or None) if asns else None,
        "block": str(block.get("desc") or "") or None,
    }


async def ripestat_origin(client: httpx.AsyncClient | None, ip: str) -> dict:
    """Origine BGP d'une IP : {announced, asn, holder, prefix, block}."""
    return parse_prefix_overview(await ripestat(client, "prefix-overview", ip))


async def ripestat_geoloc(client: httpx.AsyncClient | None, ip: str) -> dict:
    """Localisation (pays, coordonnées) d'une IP d'après RIPEstat : {country, city, lat, lon} ou {}."""
    data = await ripestat(client, "geoloc", ip)
    for resource in data.get("located_resources") or []:
        for location in (resource or {}).get("locations") or []:
            if isinstance(location, dict) and location.get("country"):
                return {
                    "country": str(location.get("country") or ""),
                    "city": str(location.get("city") or ""),
                    "lat": _number(location.get("latitude")),
                    "lon": _number(location.get("longitude")),
                }
    return {}


async def ripestat_prefixes(client: httpx.AsyncClient | None, asn: str) -> dict:
    """Préfixes annoncés par un ASN : {v4, v6, total_v4, total_v6} (listes bornées, chaînes CIDR)."""
    data = await ripestat(client, "announced-prefixes", asn)
    v4: list[ipaddress.IPv4Network] = []
    v6: list[ipaddress.IPv6Network] = []
    for entry in data.get("prefixes") or []:
        prefix = str(entry.get("prefix") or "") if isinstance(entry, dict) else ""
        try:
            network = ipaddress.ip_network(prefix, strict=False)
        except ValueError:
            continue
        (v6 if network.version == 6 else v4).append(network)
    # Les plus larges d'abord (les plus parlants), puis par adresse : ordre stable d'un scan à l'autre.
    v4.sort(key=lambda n: (n.prefixlen, n))
    v6.sort(key=lambda n: (n.prefixlen, n))
    return {
        "v4": [str(n) for n in v4[:MAX_PREFIXES_V4]],
        "v6": [str(n) for n in v6[:MAX_PREFIXES_V6]],
        "total_v4": len(v4),
        "total_v6": len(v6),
    }


async def ripestat_neighbours(client: httpx.AsyncClient | None, asn: str) -> dict:
    """Pairs BGP d'un ASN : {peers: [{asn, type, power, v4, v6}], total, upstreams, downstreams}.

    RIPEstat classe chaque voisin « left » (en amont du chemin : fournisseur de transit) ou
    « right » (en aval : client), avec le nombre de pairs observés par les collecteurs.
    """
    data = await ripestat(client, "asn-neighbours", asn)
    peers = []
    for entry in data.get("neighbours") or []:
        if not isinstance(entry, dict) or entry.get("asn") is None:
            continue
        kind = str(entry.get("type") or "")
        peers.append(
            {
                "asn": f"AS{entry['asn']}",
                "type": kind if kind in ("left", "right", "uncertain") else "uncertain",
                "power": _integer(entry.get("power")),
                "v4": _integer(entry.get("v4_peers")),
                "v6": _integer(entry.get("v6_peers")),
            }
        )
    peers.sort(key=lambda p: (-p["power"], p["asn"]))
    return {
        "peers": peers[:MAX_PEERS],
        "total": len(peers),
        "upstreams": sum(1 for p in peers if p["type"] == "left"),
        "downstreams": sum(1 for p in peers if p["type"] == "right"),
    }


async def ripestat_holder(client: httpx.AsyncClient | None, asn: str) -> str | None:
    """Nom du titulaire d'un ASN (as-overview) ou None."""
    data = await ripestat(client, "as-overview", asn)
    return str(data.get("holder") or "") or None


# =============================================================================
# Team Cymru (DNS)
# =============================================================================


def cymru_name(ip: str) -> str:
    """Nom DNS à interroger pour l'origine d'une IP (« 8.8.8.8 » -> « 8.8.8.8.origin.asn.cymru.com »)."""
    address = ipaddress.ip_address(ip)
    pointer = address.reverse_pointer
    if address.version == 6:
        return pointer.removesuffix(".ip6.arpa") + "." + CYMRU_ORIGIN6
    return pointer.removesuffix(".in-addr.arpa") + "." + CYMRU_ORIGIN4


def _fields(text: str) -> list[str]:
    return [part.strip() for part in text.strip().strip('"').split("|")]


def cymru_origin_sync(ip: str, querier: DnsQuerier | None = None) -> dict | None:
    """Origine d'une IP d'après Team Cymru : {asn, prefix, country, rir, name} ; None si non annoncée.

    Bloquant (dnspython) : à lancer dans `asyncio.to_thread`. Lève ModuleError si le DNS ne répond pas.
    """
    querier = querier or DnsQuerier(query_timeout=3, budget=8)
    lookup = querier.lookup(cymru_name(ip), "TXT")
    if lookup.status in ("nxdomain", "noanswer"):
        return None
    if lookup.status != "ok" or not lookup.answers:
        raise ModuleError(msg("network.service_error", context="Team Cymru", detail=msg("net.timeout")))
    fields = _fields(txt_record_text(lookup.answers[0]))
    # Plusieurs ASN d'origine possibles (« 13335 209242 ») : le premier est retenu.
    numbers = fields[0].split() if fields else []
    if not numbers or not numbers[0].isdigit():
        return None
    result = {
        "asn": f"AS{numbers[0]}",
        "prefix": fields[1] if len(fields) > 1 and fields[1] else None,
        "country": fields[2] if len(fields) > 2 and fields[2] else None,
        "rir": fields[3] if len(fields) > 3 and fields[3] else None,
        "name": None,
    }
    named = querier.lookup(f"AS{numbers[0]}.{CYMRU_ASN}", "TXT")
    if named.status == "ok" and named.answers:
        fields = _fields(txt_record_text(named.answers[0]))
        result["name"] = fields[4] if len(fields) > 4 and fields[4] else None
    return result


# =============================================================================
# Origine fusionnée
# =============================================================================


async def asn_of(client: httpx.AsyncClient | None, ip: str) -> dict:
    """ASN d'une IP selon RIPEstat et Team Cymru, interrogés ensemble ; lève ModuleError si aucun ne répond.

    Rend {announced, asn, holder, prefix, country, rir, sources}. Une IP non annoncée donne
    `announced: False` (mesure valide). `sources` liste les services qui ont répondu.
    """

    async def from_cymru() -> dict | None:
        return await asyncio.to_thread(cymru_origin_sync, ip)

    ripe_result, cymru_result = await asyncio.gather(
        ripestat_origin(client, ip), from_cymru(), return_exceptions=True
    )
    for outcome in (ripe_result, cymru_result):
        # Une annulation (asyncio.CancelledError) n'est pas une Exception : elle traverse gather telle quelle.
        if isinstance(outcome, BaseException) and not isinstance(outcome, Exception):
            raise outcome
    ripe = None if isinstance(ripe_result, Exception) else ripe_result
    cymru_ok = not isinstance(cymru_result, Exception)
    if ripe is None and not cymru_ok:
        if isinstance(ripe_result, ModuleError):
            raise ripe_result
        raise ModuleError(
            msg("network.service_error", context=RIPESTAT_SERVICE, detail=type(ripe_result).__name__)
        )
    cymru = cymru_result if cymru_ok else None
    sources: list[str] = []
    result = {
        "announced": False,
        "asn": None,
        "holder": None,
        "prefix": None,
        "country": None,
        "rir": None,
        "sources": sources,
    }
    if ripe is not None:
        sources.append("ripestat")
        result.update({key: ripe[key] for key in ("announced", "asn", "holder", "prefix")})
    if cymru_ok:
        sources.append("cymru")
        if cymru:
            if not result["asn"]:
                result["asn"] = cymru["asn"]
                result["prefix"] = cymru["prefix"]
            if result["asn"] == cymru["asn"]:
                result["holder"] = result["holder"] or cymru["name"]
                result["country"] = cymru["country"]
                result["rir"] = cymru["rir"]
            result["announced"] = True
    return result


def _number(value: object) -> float | None:
    return float(value) if isinstance(value, (int, float)) and not isinstance(value, bool) else None


def _integer(value: object) -> int:
    return int(value) if isinstance(value, (int, float)) and not isinstance(value, bool) else 0
