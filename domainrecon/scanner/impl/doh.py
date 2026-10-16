# =============================================================================
# DomainRecon - Comparaison de résolveurs chiffrés (DoH RFC 8484, DoT RFC 7858)
# =============================================================================
# Interroge le même nom auprès de plusieurs résolveurs publics et du résolveur
# local, puis compare leurs réponses. Détecte le filtrage ou la censure (un
# résolveur refuse un nom que les autres résolvent), les réponses non publiques
# (puits de sondage 0.0.0.0, adresse interne : empoisonnement ou split-horizon) et
# relève quels résolveurs ont VALIDÉ DNSSEC (bit AD).
#
# Format BINAIRE de la RFC 8484 (application/dns-message, GET ?dns=<base64url>) :
#   - Cloudflare : https://cloudflare-dns.com/dns-query
#   - Google     : https://dns.google/dns-query
# L'API JSON n'est pas utilisée : Quad9 l'a retirée le 5 mai 2025 ; son
# point d'accès DoH exige HTTP/2, que le client HTTP du projet ne parle pas (et
# l'extension « h2 » n'est pas une dépendance du projet) : Quad9 est donc interrogé
# en DNS-sur-TLS (9.9.9.9, port 853, certificat vérifié), tout aussi chiffré.
#
# Les adresses différentes d'un résolveur à l'autre sont NORMALES derrière un CDN
# (réponse selon la localisation) : ce n'est pas une anomalie.
# Elles ne sont signalées qu'à titre d'information (`ip_variation`).
# =============================================================================

import asyncio
import base64
import time
from typing import NamedTuple

import dns.exception
import dns.flags
import dns.message
import dns.query
import dns.rcode
import dns.rdatatype
import httpx

from ...i18n import msg
from .. import dns as scanner_dns
from ..errors import ModuleError
from ..targets import ensure_ip_allowed
from . import dns_http, dns_tools

DOH_TIMEOUT = 8.0
DOT_TIMEOUT = 6.0
PAYLOAD = 1232

# Résolveurs DoH : nom -> URL (RFC 8484).
DOH_PROVIDERS = {
    "cloudflare": "https://cloudflare-dns.com/dns-query",
    "google": "https://dns.google/dns-query",
}
# Résolveurs DoT : nom -> (adresse, nom du certificat).
DOT_PROVIDERS = {"quad9": ("9.9.9.9", "dns.quad9.net")}
SYSTEM = "system"

# Statuts qui comptent comme une réponse du résolveur (les autres : panne ou refus technique).
ANSWERED = ("NOERROR", "NXDOMAIN")
BLOCKING = ("NXDOMAIN", "REFUSED", "SERVFAIL")


class Answer(NamedTuple):
    """Réponse d'un résolveur."""

    status: str  # NOERROR, NXDOMAIN, SERVFAIL, REFUSED… ou « error »
    ips: list[str]
    ad: bool
    ttl: int | None
    transport: str
    latency_ms: int | None
    error: object | None = None

    def as_dict(self) -> dict:
        return {
            "status": self.status,
            "ips": self.ips,
            "ad": self.ad,
            "ttl": self.ttl,
            "transport": self.transport,
            "latency_ms": self.latency_ms,
            "error": self.error,
        }


def build_query(domain: str) -> dns.message.Message:
    """Requête A avec DO ; identifiant 0 (RFC 8484 §4.1, favorise le cache HTTP)."""
    return dns.message.make_query(domain, "A", want_dnssec=True, use_edns=0, payload=PAYLOAD, id=0)


def parse_response(response: dns.message.Message, transport: str, latency_ms: int | None) -> Answer:
    """Réponse DNS -> Answer (adresses A de la réponse finale, rcode, bit AD, plus petit TTL)."""
    ips: list[str] = []
    ttls: list[int] = []
    for rrset in response.answer:
        if rrset.rdtype == dns.rdatatype.A:
            ips.extend(str(rdata) for rdata in rrset)
            ttls.append(int(rrset.ttl))
    return Answer(
        status=dns.rcode.to_text(response.rcode()),
        ips=sorted(set(ips)),
        ad=bool(response.flags & dns.flags.AD),
        ttl=min(ttls) if ttls else None,
        transport=transport,
        latency_ms=latency_ms,
    )


def failure(transport: str, error: object) -> Answer:
    return Answer("error", [], False, None, transport, None, error)


async def query_doh(client: httpx.AsyncClient | None, name: str, url: str, domain: str) -> Answer:
    """Requête DoH (GET, RFC 8484) ; ne lève pas : un échec devient une Answer « error »."""
    wire = base64.urlsafe_b64encode(build_query(domain).to_wire()).rstrip(b"=").decode("ascii")
    started = time.monotonic()
    try:
        async with dns_http.session(client, DOH_TIMEOUT) as http:
            reply = await dns_http.get(
                http,
                url,
                service=name,
                params={"dns": wire},
                headers={"Accept": "application/dns-message"},
                timeout=DOH_TIMEOUT,
                max_bytes=65535,
            )
    except ModuleError as e:
        return failure("doh", e.message)
    if reply.status != 200:
        return failure("doh", msg("network.http_status", status=reply.status, service=name))
    try:
        response = dns.message.from_wire(reply.body)
    except (dns.exception.DNSException, ValueError):
        return failure("doh", msg("doh_comparison.unreadable", service=name))
    return parse_response(response, "doh", int((time.monotonic() - started) * 1000))


def _dot_exchange(query: dns.message.Message, address: str, hostname: str) -> dns.message.Message:
    """Requête DNS-sur-TLS, certificat vérifié. Point d'injection des tests."""
    return dns.query.tls(query, address, timeout=DOT_TIMEOUT, port=853, server_hostname=hostname)


def _query_dot(name: str, address: str, hostname: str, domain: str) -> Answer:
    started = time.monotonic()
    try:
        ensure_ip_allowed(address)
        response = _dot_exchange(build_query(domain), address, hostname)
    except dns.exception.Timeout:
        return failure("dot", msg("net.timeout"))
    except (dns.exception.DNSException, OSError, EOFError, ValueError) as e:
        return failure("dot", msg("network.service_error", context=name, detail=type(e).__name__))
    return parse_response(response, "dot", int((time.monotonic() - started) * 1000))


def _query_system(domain: str) -> Answer:
    """Résolveur du système (celui qui sert le scan), pour repérer un filtrage local."""
    started = time.monotonic()
    result = scanner_dns.DnsQuerier(3.0, 6.0).lookup(domain, "A")
    elapsed = int((time.monotonic() - started) * 1000)
    if result.status == "error":
        return failure("system", result.error)
    status = {"ok": "NOERROR", "noanswer": "NOERROR", "nxdomain": "NXDOMAIN"}[result.status]
    ips = sorted({str(r) for r in result.answers})
    return Answer(status, ips, False, None, "system", elapsed)


async def compare(client: httpx.AsyncClient | None, domain: str) -> dict:
    """Interroge tous les résolveurs et analyse leurs réponses. Lève ModuleError si aucun ne répond."""
    names = [*DOH_PROVIDERS, *DOT_PROVIDERS, SYSTEM]
    results = await asyncio.gather(
        *(query_doh(client, name, url, domain) for name, url in DOH_PROVIDERS.items()),
        *(
            asyncio.to_thread(_query_dot, name, address, host, domain)
            for name, (address, host) in DOT_PROVIDERS.items()
        ),
        asyncio.to_thread(_query_system, domain),
    )
    answers = dict(zip(names, results, strict=True))
    public = [n for n in names if n != SYSTEM]
    if not any(answers[n].status in ANSWERED for n in public):
        raise ModuleError(msg("doh_comparison.no_resolver"))
    return analyze(domain, answers)


def analyze(domain: str, answers: dict[str, Answer]) -> dict:
    """Compare les réponses : filtrage, adresses non publiques, variation d'adresses, validation DNSSEC."""
    responded = {n: a for n, a in answers.items() if a.status in ANSWERED}
    resolving = {n: a for n, a in responded.items() if a.ips}
    anomalies: list[dict] = []

    # Un résolveur qui refuse un nom que d'autres résolvent (filtrage de sécurité, blocage, censure).
    if resolving:
        refused = [
            n
            for n, a in answers.items()
            if n not in resolving
            and (a.status in BLOCKING or (a.status == "NOERROR" and not a.ips))
            and a.status != "error"
        ]
        if refused:
            anomalies.append({"type": "blocked", "providers": sorted(refused)})

    # Adresse non publique renvoyée par certains seulement (puits de sondage, empoisonnement).
    non_public = sorted(
        n for n, a in resolving.items() if any(dns_tools.classify_address(ip) for ip in a.ips)
    )
    if non_public and len(non_public) < len(resolving):
        anomalies.append({"type": "sinkhole", "providers": non_public})
    # Si tous renvoient une adresse non publique, c'est le domaine lui-même qui la publie : voir « dns_rebinding ».

    # Variation d'adresses : à titre d'information (CDN, répartition géographique).
    sets = [frozenset(a.ips) for n, a in resolving.items() if n not in non_public]
    ip_variation = len(sets) > 1 and len(set(sets)) > 1
    overlap = bool(sets) and bool(frozenset.intersection(*sets)) if len(sets) > 1 else True

    return {
        "measured": True,
        "error": None,
        "domain": domain,
        "providers": {n: a.as_dict() for n, a in answers.items()},
        "answered": sorted(responded),
        "consistent": not anomalies,
        "ip_variation": ip_variation,
        "ip_overlap": overlap,
        "anomalies": anomalies,
        "dnssec_validated_by": sorted(n for n, a in responded.items() if a.ad and a.ips),
    }
