# =============================================================================
# DomainRecon - RDAP d'une adresse IP : bloc d'adresses, titulaire, contact abuse
# =============================================================================
# Source : RDAP (RFC 9082 / 9083), le successeur gratuit et sans clé de WHOIS.
# Le registre compétent (ARIN, RIPE NCC, APNIC, LACNIC, AFRINIC) est trouvé dans
# les tables d'amorçage de l'IANA (https://data.iana.org/rdap/ipv4.json, ipv6.json) ;
# à défaut, l'agrégateur https://rdap.org/ip/<ip> redirige vers le bon registre.
# Pas d'appel codé en dur sur rdap.arin.net, qui ne rendrait rien pour les
# adresses des autres registres.
# Données personnelles : seuls les noms d'organisations et l'adresse de contact
# « abuse » (adresse de rôle) sont gardés ; les noms de personnes ne le sont pas.
# =============================================================================

import ipaddress

import httpx

from ...i18n import msg
from ..cache import LONG_TTL, cached
from ..common import proxy_scope
from ..errors import ModuleError
from . import network_http as nh

BOOTSTRAP_URL = "https://data.iana.org/rdap/{family}.json"
AGGREGATOR_URL = "https://rdap.org/ip/{ip}"
SERVICE = "RDAP"
RDAP_HEADERS = {"Accept": "application/rdap+json, application/json"}
MAX_HOPS = 2
_REDIRECTS = (301, 302, 303, 307, 308)
MAX_CIDRS = 10


@cached(LONG_TTL, scope=proxy_scope, ignore=("client",), max_entries=4)
async def _bootstrap(client: httpx.AsyncClient | None, family: str) -> list:
    """Table d'amorçage IANA (« ipv4 » ou « ipv6 ») : [(réseaux, URL de base RDAP en https)]."""
    async with nh.use_client(client, timeout=15) as http:
        response = await nh.get(
            http, BOOTSTRAP_URL.format(family=family), service="IANA", headers=RDAP_HEADERS
        )
    if response.status_code != 200:
        raise nh.status_error("IANA", response.status_code)
    body = nh.parse_json(response)
    services = body.get("services") if isinstance(body, dict) else None
    if not isinstance(services, list):
        raise ModuleError(msg("rdap_ip.unreadable", service="IANA"))
    table = []
    for entry in services:
        if not (isinstance(entry, list) and len(entry) == 2 and all(isinstance(x, list) for x in entry)):
            continue
        networks = []
        for text in entry[0]:
            try:
                networks.append(ipaddress.ip_network(str(text), strict=False))
            except ValueError:
                continue
        urls = [u for u in entry[1] if isinstance(u, str) and u.startswith("https://")]
        if networks and urls:
            table.append((networks, urls[0]))
    return table


async def registry_url(client: httpx.AsyncClient | None, ip: str) -> str | None:
    """URL RDAP de l'adresse chez le registre compétent d'après l'amorçage IANA, ou None s'il est indisponible."""
    address = ipaddress.ip_address(ip)
    try:
        table = await _bootstrap(client, "ipv6" if address.version == 6 else "ipv4")
    except ModuleError:
        return None
    for networks, base in table:
        if any(address in network for network in networks if network.version == address.version):
            return f"{base.rstrip('/')}/ip/{ip}"
    return None


async def _fetch(client: httpx.AsyncClient, url: str) -> httpx.Response:
    """GET de l'objet RDAP, redirections (agrégateur) suivies à la main, en https seulement."""
    for _ in range(MAX_HOPS + 1):
        response = await nh.get(client, url, service=SERVICE, headers=RDAP_HEADERS)
        if response.status_code not in _REDIRECTS:
            return response
        location = response.headers.get("location", "")
        target = httpx.URL(location) if location else None
        if target is None or target.scheme != "https" or not target.host:
            raise ModuleError(msg("rdap_ip.unreadable", service=SERVICE))
        url = str(target)
    raise ModuleError(msg("rdap_ip.unreadable", service=SERVICE))


def _vcard(entity: dict) -> dict[str, str]:
    """Champs fn / org / email / kind d'une fiche vCard RDAP."""
    fields: dict[str, str] = {}
    array = entity.get("vcardArray")
    items = array[1] if isinstance(array, list) and len(array) == 2 and isinstance(array[1], list) else []
    for item in items:
        if (
            isinstance(item, list)
            and len(item) >= 4
            and isinstance(item[0], str)
            and isinstance(item[3], str)
        ):
            fields.setdefault(item[0], item[3])
    return fields


def _walk(entities: object, depth: int = 0):
    """Entités et entités imbriquées (profondeur bornée)."""
    if depth > 3 or not isinstance(entities, list):
        return
    for entity in entities:
        if isinstance(entity, dict):
            yield entity
            yield from _walk(entity.get("entities"), depth + 1)


def _event(data: dict, action: str) -> str | None:
    for event in data.get("events") or []:
        if isinstance(event, dict) and event.get("eventAction") == action:
            return str(event.get("eventDate") or "") or None
    return None


def parse(data: dict) -> dict:
    """Champs utiles d'un objet « ip network » RDAP."""
    cidrs = []
    for entry in data.get("cidr0_cidrs") or []:
        if isinstance(entry, dict):
            prefix = entry.get("v4prefix") or entry.get("v6prefix")
            if prefix and entry.get("length") is not None:
                cidrs.append(f"{prefix}/{entry['length']}")
    organization = None
    abuse_email = None
    roles: set[str] = set()
    for entity in _walk(data.get("entities")):
        entity_roles = [r for r in entity.get("roles") or [] if isinstance(r, str)]
        roles.update(entity_roles)
        card = _vcard(entity)
        # Une personne physique n'est pas rapportée (RGPD) : seules les organisations le sont.
        # Le rôle « abuse » seul (fiche de contact « Abuse-C Role ») n'est pas le titulaire du bloc.
        if (
            organization is None
            and set(entity_roles) != {"abuse"}
            and card.get("kind", "org") != "individual"
        ):
            organization = card.get("org") or (
                card.get("fn") if card.get("kind") in ("org", "group") else None
            )
        if abuse_email is None and "abuse" in entity_roles and card.get("email"):
            abuse_email = card["email"]
    return {
        "name": str(data.get("name") or "") or None,
        "handle": str(data.get("handle") or "") or None,
        "type": str(data.get("type") or "") or None,
        "country": str(data.get("country") or "") or None,
        "ip_version": str(data.get("ipVersion") or "") or None,
        "start": str(data.get("startAddress") or "") or None,
        "end": str(data.get("endAddress") or "") or None,
        "cidrs": cidrs[:MAX_CIDRS],
        "parent_handle": str(data.get("parentHandle") or "") or None,
        "status": [s for s in data.get("status") or [] if isinstance(s, str)][:6],
        "registered": _event(data, "registration"),
        "last_changed": _event(data, "last changed"),
        "organization": organization,
        "abuse_email": abuse_email,
        "roles": sorted(roles),
    }


async def lookup(client: httpx.AsyncClient | None, ip: str) -> dict:
    """RDAP de l'adresse : {found, source, **champs} ; lève ModuleError (réseau, quota, réponse illisible)."""
    async with nh.use_client(client, timeout=15) as http:
        url = await registry_url(http, ip) or AGGREGATOR_URL.format(ip=ip)
        response = await _fetch(http, url)
    if response.status_code == 404:
        return {"found": False, "source": httpx.URL(url).host}
    if response.status_code != 200:
        raise nh.status_error(SERVICE, response.status_code)
    data = nh.parse_json(response)
    if not isinstance(data, dict) or data.get("objectClassName") not in (None, "ip network"):
        raise ModuleError(msg("rdap_ip.unreadable", service=SERVICE))
    return {"found": True, "source": str(response.url.host), **parse(data)}
