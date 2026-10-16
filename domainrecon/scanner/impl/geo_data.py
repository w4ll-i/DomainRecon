# =============================================================================
# DomainRecon - Géolocalisation d'une adresse IP : sources vivantes, jeton facultatif
# =============================================================================
# État des sources en octobre 2026 :
#   - ip-api.com : HTTP clair seulement en gratuit, abandonné ;
#   - ipinfo.io : l'accès anonyme répond encore (pays, région, ville, coordonnées) mais
#     sans organisation ni ASN ; avec un jeton (Authorization: Bearer), le champ « org »
#     (« AS15169 Google LLC ») revient ; le niveau gratuit « Lite » rend pays + ASN.
#     Un jeton se saisit dans les Réglages (clé facultative « ipinfo_token »).
#   - RIPEstat (geoloc, prefix-overview) et Team Cymru (DNS) : gratuits, sans clé.
# Chaîne : ipinfo.io (jeton si présent) pour la position ; l'ASN et l'organisation
# manquants viennent de RIPEstat / Team Cymru ; si ipinfo.io échoue (quota, 403,
# panne), RIPEstat donne le pays et les coordonnées (sans ville).
# Même résultat que network.get_geo_data (country = code ISO du pays), plus `source`.
# =============================================================================

import httpx

from ...i18n import msg
from .. import network
from ..cache import LONG_TTL, cached
from ..common import logger, proxy_scope
from ..errors import ModuleError
from . import bgp_sources
from . import network_http as nh

IPINFO_URL = "https://ipinfo.io/{ip}/json"
SERVICE = "ipinfo.io"


@cached(LONG_TTL, scope=proxy_scope, ignore=("client", "token"), max_entries=256)
async def ipinfo(client: httpx.AsyncClient | None, ip: str, authenticated: bool, token: str | None) -> dict:
    """Réponse ipinfo.io pour `ip` (jeton en Bearer s'il est donné) ; lève ModuleError si inexploitable.

    `authenticated` fait partie de la clé du cache (une réponse anonyme et une réponse avec jeton
    diffèrent) ; le jeton lui-même n'y figure pas.
    """
    headers = {"Authorization": f"Bearer {token}", "Accept": "application/json"} if token else None
    async with nh.use_client(client, timeout=8) as http:
        response = await nh.get(http, IPINFO_URL.format(ip=ip), service=SERVICE, headers=headers, timeout=8)
    if response.status_code != 200:
        raise nh.status_error(SERVICE, response.status_code)
    data = nh.parse_json(response)
    if not isinstance(data, dict) or "error" in data:
        raise ModuleError(msg("network.ipinfo_error"))
    return data


def empty_result(ip: str | None) -> dict:
    """Résultat vide au format de network.get_geo_data."""
    return {**network._geo_result(ip), "source": None}


async def get_geo_data(ip: str, *, token: str | None = None, client: httpx.AsyncClient | None = None) -> dict:
    """Géolocalise une IP publique ; `measured` vaut True si une source a donné au moins le pays.

    Aucune requête vers un tiers pour une adresse non publique (`skipped=True`).
    """
    result = empty_result(ip)
    refusal = network._third_party_refusal(ip, msg("network.what_geo"))
    if refusal is not None:
        result["error"], result["skipped"] = refusal
        return result

    failure: object | None = None
    try:
        data = await ipinfo(client, ip, bool(token), token)
    except ModuleError as e:
        logger.warning("Géolocalisation ipinfo.io indisponible pour %s", ip)
        failure = e.message
        data = None
    except httpx.HTTPError as e:  # pragma: no cover - nh.get convertit déjà ces erreurs
        failure = nh.network_error(SERVICE, e).message
        data = None

    org = ""
    if data is not None:
        org = str(data.get("org") or "")
        _, org_name = network._split_org(org)
        lat, lon = network._parse_loc(data.get("loc"))
        country = str(data.get("country") or "")
        result.update(
            {
                "country": country,
                "country_code": country,
                "region": str(data.get("region") or ""),
                "city": str(data.get("city") or ""),
                "zip": str(data.get("postal") or ""),
                "lat": lat,
                "lon": lon,
                "timezone": str(data.get("timezone") or ""),
                "isp": org_name,
                "org": org_name,
                "as_info": org,
                "anycast": bool(data.get("anycast", False)),
                "measured": bool(country),
                "source": "ipinfo",
            }
        )

    # ASN et titulaire manquants (accès anonyme) ; position de repli si ipinfo a échoué.
    try:
        origin = await bgp_sources.asn_of(client, ip)
    except ModuleError as e:
        origin = None
        failure = failure or e.message
    if origin and origin["asn"] and not result["as_info"]:
        holder = origin["holder"] or ""
        result.update({"isp": holder, "org": holder, "as_info": f"{origin['asn']} {holder}".strip()})
    if not result["measured"]:
        try:
            located = await bgp_sources.ripestat_geoloc(client, ip)
        except ModuleError as e:
            located = {}
            failure = failure or e.message
        if located:
            result.update(
                {
                    "country": located["country"],
                    "country_code": located["country"],
                    "city": located["city"],
                    "lat": located["lat"],
                    "lon": located["lon"],
                    "measured": True,
                    "source": "ripestat",
                }
            )
    if result["measured"]:
        result["error"] = None
    else:
        result["error"] = failure or msg("network.geo_unavailable")
    return result
