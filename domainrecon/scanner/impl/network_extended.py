# =============================================================================
# DomainRecon - Réseau étendu : ASN, bloc d'adresses et voisins reverse-IP
# =============================================================================
# Sources réunies (ipinfo.io, HackerTarget, RDAP, Robtex, reverse IP) :
#   - ASN, titulaire, préfixe, pays et registre : RIPEstat + Team Cymru (sans clé),
#     complétés par le nom d'hôte (PTR) et le drapeau anycast d'ipinfo.io. L'ASN
#     d'ipinfo.io n'est plus fourni en accès anonyme (jeton facultatif) ;
#   - voisins reverse-IP : HackerTarget (50 appels par jour sans clé), puis, s'il
#     est épuisé ou en panne, Robtex (ipquery) ; les noms en .arpa (bruit du
#     DNS inverse) et le domaine scanné sont écartés.
# Même résultat que network.extended_network_scan, plus `neighbors_source` et des
# champs `asn_info` (prefix, country, rir). Le module « reverse_ip » des anciennes
# versions est fusionné ici (mêmes voisins).
# =============================================================================

import httpx

from ...i18n import msg
from .. import network
from ..common import logger
from ..errors import ModuleError
from ..targets import is_valid_target
from . import bgp_sources, geo_data, robtex
from . import network_http as nh


def _usable(name: str) -> bool:
    """Nom d'hôte exploitable comme voisin : valide et hors du bruit du DNS inverse (.arpa)."""
    return not name.endswith(".arpa") and is_valid_target(name)


async def neighbors_of(client: httpx.AsyncClient | None, ip: str, domain: str) -> tuple[list[str], str]:
    """(voisins, source) : HackerTarget, sinon Robtex ; lève ModuleError si les deux échouent."""
    try:
        hosts = [h for h in await network._reverse_ip_hosts(ip) if _usable(h)]
        return [h for h in hosts if h != domain], "hackertarget"
    except (ModuleError, httpx.HTTPError) as error:
        # network._reverse_ip_hosts laisse passer les erreurs réseau d'httpx : ramenées à un ModuleError
        # sans le texte de l'exception.
        first = error if isinstance(error, ModuleError) else nh.network_error("HackerTarget", error)
        try:
            data = await robtex.ip_query(client, ip)
        except ModuleError:
            raise first from None
        return [h for h in data["names"] if _usable(h) and h != domain], "robtex"


async def extended_network_scan(
    ip: str, domain: str, *, token: str | None = None, client: httpx.AsyncClient | None = None
) -> dict:
    """Scan réseau étendu : ASN (RIPEstat, Team Cymru, ipinfo.io) et voisins reverse-IP.

    `measured` vaut True si une source d'ASN ou de voisins a répondu ; l'échec de chacune est
    détaillé dans `asn_error` et `neighbors_error`.
    """
    result: dict = {
        "reverse_ip_neighbors": [],
        "neighbors_total": 0,
        "neighbors_truncated": False,
        "neighbors_error": None,
        "neighbors_source": None,
        "asn_info": {},
        "asn_error": None,
        "measured": False,
        "error": None,
    }
    refusal = network._third_party_refusal(ip, msg("network.what_extended"))
    if refusal is not None:
        result["error"], result["skipped"] = refusal
        return result

    info: dict = {
        "asn": None,
        "org": None,
        "hostname": None,
        "anycast": False,
        "prefix": None,
        "country": None,
        "rir": None,
    }
    asn_failures: list[object] = []
    try:
        data = await geo_data.ipinfo(client, ip, bool(token), token)
        hostname = str(data.get("hostname") or "").lower().rstrip(".")
        # Le PTR est choisi par le propriétaire de l'IP : gardé seulement s'il est valide.
        info["hostname"] = hostname if is_valid_target(hostname) else None
        info["anycast"] = bool(data.get("anycast", False))
        asn, org_name = network._split_org(str(data.get("org") or ""))
        info["asn"], info["org"] = asn, org_name or None
    except ModuleError as e:
        logger.warning("Informations ipinfo.io indisponibles pour %s", ip)
        asn_failures.append(e.message)
    ipinfo_answered = not asn_failures
    try:
        origin = await bgp_sources.asn_of(client, ip)
        info["asn"] = info["asn"] or origin["asn"]
        info["org"] = info["org"] or origin["holder"]
        info.update(prefix=origin["prefix"], country=origin["country"], rir=origin["rir"])
        origin_answered = True
    except ModuleError as e:
        origin_answered = False
        asn_failures.append(e.message)
    result["asn_info"] = info
    if not (ipinfo_answered or origin_answered):
        result["asn_error"] = msg("common.join", items=asn_failures)

    try:
        neighbors, source = await neighbors_of(client, ip, domain)
        limit = network.REVERSE_IP_MAX_NEIGHBORS
        result.update(
            reverse_ip_neighbors=neighbors[:limit],
            neighbors_total=len(neighbors),
            neighbors_truncated=len(neighbors) > limit,
            neighbors_source=source,
        )
    except ModuleError as e:
        logger.warning("Reverse IP indisponible pour %s", ip)
        result["neighbors_error"] = msg(
            "network.service_error", context=msg("network.reverse_ip_unavailable"), detail=e.message
        )

    result["measured"] = result["asn_error"] is None or result["neighbors_error"] is None
    if not result["measured"]:
        result["error"] = msg("common.join", items=[result["asn_error"], result["neighbors_error"]])
    return result
