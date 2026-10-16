# =============================================================================
# DomainRecon - Transfert de zone DNS (AXFR, RFC 5936) : module actif
# =============================================================================
# Demande à chaque serveur de noms autoritaire de la zone une copie complète de
# la zone. Un serveur qui accepte à n'importe qui livre tous les noms d'hôtes et
# adresses du domaine (cartographie interne, environnements de test…).
#
# dns.query.xfr exige une adresse IP, pas le NOM du serveur (la tentative
# échouerait toujours et un transfert ouvert ne serait jamais détecté). Chaque
# serveur est donc résolu
# (A et AAAA), l'adresse est validée par la politique de cibles puis interrogée en
# TCP, de façon bornée : délai de connexion, durée totale et nombre
# d'enregistrements limités. Le DNS est direct (sans proxy), comme les autres
# modules DNS.
# =============================================================================

import asyncio
from typing import NamedTuple

import dns.exception
import dns.query
import dns.rcode
import dns.rdatatype
import dns.xfr

from ...i18n import msg
from .. import dns as scanner_dns
from ..common import logger
from ..errors import ModuleError, ModuleSkipped, TargetNotAllowedError
from ..targets import ensure_ip_allowed
from . import dns_tools

# Serveurs essayés, enregistrements gardés dans le résultat et plafond de lecture.
MAX_SERVERS = 6
MAX_SAMPLE = 200
MAX_NAMES = 500
MAX_RRSETS = 20000
CONNECT_TIMEOUT = 6.0
LIFETIME = 20.0

# Point d'injection des tests (dns.query.xfr, qui ouvre une connexion TCP).
_xfr = dns.query.xfr


class Transfer(NamedTuple):
    """Résultat d'une tentative sur une adresse."""

    status: str  # transferred | refused | timeout | unreachable | blocked | error
    rrsets: list  # (nom, type, ttl, [valeurs]) lus
    detail: str | None = None  # code de réponse DNS ou nom de l'exception


def transfer(address: str, zone: str) -> Transfer:
    """Tente un AXFR de `zone` auprès de `address` (bloquant : à lancer dans un thread)."""
    try:
        ensure_ip_allowed(address)
    except TargetNotAllowedError:
        return Transfer("blocked", [])
    rrsets: list = []
    try:
        for message in _xfr(
            address,
            zone,
            timeout=CONNECT_TIMEOUT,
            lifetime=LIFETIME,
            relativize=False,
        ):
            for rrset in message.answer:
                rrsets.append(
                    (
                        str(rrset.name).rstrip(".").lower(),
                        dns.rdatatype.to_text(rrset.rdtype),
                        int(rrset.ttl),
                        [rdata.to_text() for rdata in rrset],
                    )
                )
            if len(rrsets) >= MAX_RRSETS:
                break
    except dns.xfr.TransferError as e:
        return Transfer("refused", [], dns.rcode.to_text(e.rcode))
    except dns.exception.FormError:
        # Réponse qui n'est pas un transfert (serveur qui ne parle pas AXFR).
        return Transfer("refused", [], "FORMERR")
    except (dns.exception.Timeout, TimeoutError):
        return Transfer("timeout", rrsets)
    except (OSError, EOFError) as e:
        return Transfer("unreachable", rrsets, type(e).__name__)
    except dns.exception.DNSException as e:
        logger.debug("AXFR %s auprès de %s : %r", zone, address, e)
        return Transfer("error", rrsets, type(e).__name__)
    # Un transfert valide commence et finit par le SOA de la zone.
    if rrsets and rrsets[0][1] == "SOA":
        return Transfer("transferred", rrsets)
    return Transfer("refused", rrsets, "EMPTY")


def _nameserver_addresses(querier: scanner_dns.DnsQuerier, zone: str) -> list[tuple[str, str]]:
    """(serveur, adresse) de chaque NS de la zone : une adresse IPv4 et une IPv6 au plus par serveur."""
    result = querier.lookup(zone, "NS")
    if result.status == "error":
        raise ModuleError(msg("dns.lookup_error", name=zone, error=result.error))
    if result.status != "ok":
        raise ModuleSkipped(msg("zone_transfer.no_ns", zone=zone))
    pairs: list[tuple[str, str]] = []
    for ns in sorted({str(r.target).rstrip(".").lower() for r in result.answers})[:MAX_SERVERS]:
        addresses, _ = dns_tools.addresses_of(querier, ns)
        v4 = [a for a in addresses if ":" not in a][:1]
        v6 = [a for a in addresses if ":" in a][:1]
        pairs.extend((ns, address) for address in (*v4, *v6))
    return pairs


def _summarize(zone: str, rrsets: list) -> dict:
    """Résumé d'une zone transférée : nombre d'enregistrements, types, noms et échantillon."""
    types: dict[str, int] = {}
    names: set[str] = set()
    sample: list[dict] = []
    total = 0
    suffix = "." + zone
    for name, rtype, ttl, values in rrsets:
        total += len(values)
        types[rtype] = types.get(rtype, 0) + len(values)
        if name == zone or name.endswith(suffix):
            names.add(name)
        for value in values:
            if len(sample) < MAX_SAMPLE:
                sample.append({"name": name, "type": rtype, "ttl": ttl, "value": value[:200]})
    return {
        "record_count": total,
        "record_types": dict(sorted(types.items())),
        "names": sorted(names)[:MAX_NAMES],
        "name_count": len(names),
        "records": sample,
    }


async def attempt(zone: str) -> dict:
    """AXFR de `zone` auprès de tous ses serveurs. Lève ModuleSkipped (aucun NS) ou ModuleError (aucune réponse)."""
    querier = scanner_dns.DnsQuerier(4.0, 25.0)
    pairs = await asyncio.to_thread(_nameserver_addresses, querier, zone)
    if not pairs:
        raise ModuleError(msg("zone_transfer.no_address", zone=zone))
    outcomes = await asyncio.gather(*(asyncio.to_thread(transfer, address, zone) for _, address in pairs))

    servers = []
    vulnerable: list[str] = []
    summary: dict = {}
    answered = 0
    for (ns, address), outcome in zip(pairs, outcomes, strict=True):
        if outcome.status in ("transferred", "refused"):
            answered += 1
        entry = {"nameserver": ns, "address": address, "status": outcome.status}
        if outcome.detail:
            entry["detail"] = outcome.detail
        if outcome.status == "transferred":
            vulnerable.append(ns)
            entry["record_count"] = sum(len(values) for *_, values in outcome.rrsets)
            if not summary:
                summary = _summarize(zone, outcome.rrsets)
        servers.append(entry)
    if not answered:
        raise ModuleError(msg("zone_transfer.unreachable", count=len(pairs)))
    return {
        "measured": True,
        "error": None,
        "zone": zone,
        "servers": servers,
        "attempted": sorted({ns for ns, _ in pairs}),
        "vulnerable": bool(vulnerable),
        "vulnerable_servers": sorted(set(vulnerable)),
        **summary,
    }
