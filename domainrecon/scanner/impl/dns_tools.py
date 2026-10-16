# =============================================================================
# DomainRecon - Briques DNS communes aux modules de la famille « dns »
# =============================================================================
# Sonde de joker DNS (wildcard), adresses d'un nom, classement des adresses non
# publiques. Tout passe par scanner.dns.DnsQuerier (délais et budget bornés,
# résolveur simulable en test). Aucune requête réseau directe ici.
# =============================================================================

import ipaddress
import secrets
from dataclasses import dataclass, field

from ..dns import DnsQuerier

# Résolutions de test d'un joker : labels aléatoires à un niveau, puis à deux.
WILDCARD_PROBES = 3


def probe_name(zone: str, depth: int = 1) -> str:
    """Nom aléatoire sous `zone` : il n'existe pas, sauf joker DNS (*.zone)."""
    labels = [f"dr-{secrets.token_hex(6)}" for _ in range(depth)]
    return ".".join([*labels, zone])


def addresses_of(querier: DnsQuerier, name: str) -> tuple[list[str], bool]:
    """Adresses A et AAAA de `name` : (adresses triées sans doublon, au moins une requête a échoué)."""
    found: set[str] = set()
    failed = False
    for rtype in ("A", "AAAA"):
        result = querier.lookup(name, rtype)
        if result.status == "error":
            failed = True
        elif result.status == "ok":
            found.update(str(rdata) for rdata in result.answers)
    return sorted(found), failed


def cname_of(querier: DnsQuerier, name: str) -> str | None:
    """Cible du CNAME de `name`, ou None."""
    result = querier.lookup(name, "CNAME")
    if result.status == "ok" and result.answers:
        return str(result.answers[0].target).rstrip(".").lower()
    return None


@dataclass
class WildcardProbe:
    """Résultat de la sonde d'un joker DNS sur une zone."""

    zone: str
    probes: int = 0  # sondes dont la réponse est exploitable
    positives: int = 0  # sondes qui ont résolu
    failed: int = 0  # sondes dont la requête a échoué (rien de prouvé)
    addresses: set[str] = field(default_factory=set)
    cname: str | None = None
    deep_positive: bool | None = None  # joker aussi à deux niveaux (*.*.zone) ; None : non testé
    names: list[str] = field(default_factory=list)

    @property
    def wildcard(self) -> bool:
        return self.positives > 0

    @property
    def intermittent(self) -> bool:
        """Certaines sondes seulement résolvent : joker partiel ou réponses instables."""
        return 0 < self.positives < self.probes


def probe_wildcard(querier: DnsQuerier, zone: str, probes: int = WILDCARD_PROBES) -> WildcardProbe:
    """Sonde le joker DNS de `zone` : `probes` labels aléatoires, plus un nom à deux niveaux.

    Les adresses de toutes les sondes sont réunies : un joker derrière un CDN ou un
    équilibreur renvoie des adresses différentes d'une requête à l'autre.
    """
    result = WildcardProbe(zone=zone)
    for _ in range(probes):
        name = probe_name(zone)
        result.names.append(name)
        addresses, failed = addresses_of(querier, name)
        if addresses:
            result.probes += 1
            result.positives += 1
            result.addresses.update(addresses)
            if result.cname is None:
                result.cname = cname_of(querier, name)
        elif failed:
            result.failed += 1
        else:
            result.probes += 1
    if result.positives:
        deep = probe_name(zone, depth=2)
        result.names.append(deep)
        addresses, failed = addresses_of(querier, deep)
        if addresses:
            result.deep_positive = True
            result.addresses.update(addresses)
        elif not failed:
            result.deep_positive = False
    return result


def classify_address(value: str) -> str | None:
    """Catégorie d'une adresse non publique, ou None si elle est publique ou illisible.

    loopback, private (RFC 1918 et ULA IPv6), link_local, shared (100.64.0.0/10),
    unspecified, reserved (documentation, bancs d'essai, multicast…). Une IPv6
    « mappée » (::ffff:10.0.0.1) est classée selon son adresse IPv4.
    """
    try:
        address = ipaddress.ip_address(value.strip())
    except ValueError:
        return None
    mapped = getattr(address, "ipv4_mapped", None)
    if mapped is not None:
        address = mapped
    if address.is_unspecified:
        return "unspecified"
    if address.is_loopback:
        return "loopback"
    if address.is_link_local:
        return "link_local"
    if address.version == 4 and address in ipaddress.ip_network("100.64.0.0/10"):
        return "shared"
    if address.is_private and not address.is_global:
        # Documentation, bancs d'essai (198.18.0.0/15) et autres plages réservées : « private »
        # n'est vrai que pour RFC 1918 et ULA ; le reste du non-global est « reserved ».
        if address.version == 4:
            rfc1918 = any(
                address in ipaddress.ip_network(net)
                for net in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")
            )
            return "private" if rfc1918 else "reserved"
        return "private" if address in ipaddress.ip_network("fc00::/7") else "reserved"
    if address.is_multicast or address.is_reserved:
        return "reserved"
    return None if address.is_global else "reserved"
