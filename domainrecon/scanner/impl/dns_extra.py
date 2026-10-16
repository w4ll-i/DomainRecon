# =============================================================================
# DomainRecon - Enregistrements DNS complémentaires : CAA, SRV, TLSA (DANE)
# =============================================================================
# Utilisés par le module « dns_records_extra » (complément du module « dns_records »).
#
#   CAA   (RFC 8659) : autorités de certification autorisées. La recherche remonte
#         du nom cible vers le domaine organisationnel et s'arrête au premier
#         ensemble CAA trouvé (« climbing »), comme une autorité de certification.
#   SRV   (RFC 2782) : interroger le domaine nu ne renvoie jamais rien ; on
#         interroge les services courants
#         (_sip._tcp, _submission._tcp, _imaps._tcp…).
#   TLSA  (RFC 6698, DANE) : _443._tcp.<cible> et _25._tcp.<MX principaux>.
# Toutes les requêtes passent par DnsQuerier (délais bornés, résolveur simulable).
# =============================================================================

import asyncio

from ...i18n import msg
from .. import dns as scanner_dns
from ..targets import registrable_domain

# Services SRV courants (annuaire, messagerie, téléphonie, messagerie instantanée).
SRV_SERVICES = (
    "_sip._tcp",
    "_sip._udp",
    "_sips._tcp",
    "_xmpp-client._tcp",
    "_xmpp-server._tcp",
    "_submission._tcp",
    "_submissions._tcp",
    "_imap._tcp",
    "_imaps._tcp",
    "_pop3._tcp",
    "_pop3s._tcp",
    "_autodiscover._tcp",
    "_caldavs._tcp",
    "_carddavs._tcp",
    "_ldap._tcp",
    "_kerberos._tcp",
    "_matrix._tcp",
    "_minecraft._tcp",
)

# Requêtes en parallèle et budget de temps du complément.
CONCURRENCY = 8
QUERY_TIMEOUT = 3.0
BUDGET = 20.0
MAX_TLSA_MX = 3
MAX_RECORDS = 50

TLSA_USAGES = {0: "PKIX-TA", 1: "PKIX-EE", 2: "DANE-TA", 3: "DANE-EE"}


def _text(value: object) -> str:
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    return str(value)


def format_caa(answers: list) -> list[dict]:
    """CAA : [{flags, tag, value}], tag en minuscules."""
    records = [{"flags": int(r.flags), "tag": _text(r.tag).lower(), "value": _text(r.value)} for r in answers]
    return sorted(records, key=lambda r: (r["tag"], r["value"]))[:MAX_RECORDS]


def format_srv(name: str, answers: list) -> list[dict]:
    return [
        {
            "name": name,
            "priority": int(r.priority),
            "weight": int(r.weight),
            "port": int(r.port),
            "target": str(r.target).rstrip("."),
        }
        for r in answers
    ]


def format_tlsa(name: str, answers: list) -> list[dict]:
    return [
        {
            "name": name,
            "usage": int(r.usage),
            "usage_name": TLSA_USAGES.get(int(r.usage), str(int(r.usage))),
            "selector": int(r.selector),
            "matching": int(r.mtype),
            "data": r.cert.hex(),
        }
        for r in answers
    ]


def caa_issuers(records: list[dict]) -> list[str]:
    """Autorités autorisées par les CAA (tags issue et issuewild), noms de domaine seuls, triés."""
    issuers = set()
    for record in records:
        if record["tag"] in ("issue", "issuewild"):
            issuer = record["value"].split(";", 1)[0].strip().lower()
            if issuer:
                issuers.add(issuer)
    return sorted(issuers)


def caa_names(domain: str) -> list[str]:
    """Noms interrogés pour le CAA : de `domain` au domaine organisationnel inclus."""
    organizational = registrable_domain(domain) or domain
    names = [domain]
    current = domain
    while current != organizational and "." in current:
        current = current.split(".", 1)[1]
        names.append(current)
    return names


def _find_caa(
    querier: scanner_dns.DnsQuerier, domain: str
) -> tuple[list[dict], str | None, object | None, bool | None]:
    """(enregistrements, nom qui les porte, erreur, le nom existe) : premier CAA en remontant l'arbre.

    « Le nom existe » vient de la première requête : NXDOMAIN sur le nom lui-même veut dire qu'il n'existe
    pas (None si la requête a échoué).
    """
    exists: bool | None = None
    for index, name in enumerate(caa_names(domain)):
        result = querier.lookup(name, "CAA")
        if index == 0 and result.status != "error":
            exists = result.status != "nxdomain"
        if result.status == "error":
            return [], None, msg("dns.lookup_error", name=name, error=result.error), exists
        if result.status == "ok" and result.answers:
            return format_caa(result.answers), name, None, exists
    return [], None, None, exists


async def scan_extra(domain: str, base: dict | None = None) -> dict:
    """CAA, SRV et TLSA de `domain`. Clés : domain_exists, CAA, caa_source, caa_issuers, SRV, TLSA, extra_errors."""
    querier = scanner_dns.DnsQuerier(QUERY_TIMEOUT, BUDGET)
    errors: dict[str, object] = {}
    semaphore = asyncio.Semaphore(CONCURRENCY)

    async def lookup(name: str, rtype: str):
        async with semaphore:
            return await asyncio.to_thread(querier.lookup, name, rtype)

    caa_task = asyncio.to_thread(_find_caa, querier, domain)
    srv_names = [f"{service}.{domain}" for service in SRV_SERVICES]
    mx_hosts: list[str] = []
    if base:
        candidates = [mx.get("value") for mx in base.get("MX") or [] if isinstance(mx, dict)]
    else:
        mx = await lookup(domain, "MX")
        ordered = sorted(mx.answers, key=lambda r: r.preference) if mx.status == "ok" else []
        candidates = [str(r.exchange).rstrip(".") for r in ordered]
    for host in candidates:
        if isinstance(host, str) and host and host != "." and host not in mx_hosts:
            mx_hosts.append(host)
    tlsa_names = [f"_443._tcp.{domain}", *[f"_25._tcp.{host}" for host in mx_hosts[:MAX_TLSA_MX]]]

    caa_result, *lookups = await asyncio.gather(
        caa_task,
        *[lookup(name, "SRV") for name in srv_names],
        *[lookup(name, "TLSA") for name in tlsa_names],
    )
    caa, caa_source, caa_error, domain_exists = caa_result
    if caa_error:
        errors["CAA"] = caa_error

    srv: list[dict] = []
    srv_failed = 0
    for name, result in zip(srv_names, lookups[: len(srv_names)], strict=True):
        if result.status == "ok":
            srv.extend(format_srv(name, result.answers))
        elif result.status == "error":
            srv_failed += 1
    if srv_failed == len(srv_names):
        errors["SRV"] = msg("dns.query_failed", error=msg("net.timeout"))

    tlsa: list[dict] = []
    tlsa_failed = 0
    for name, result in zip(tlsa_names, lookups[len(srv_names) :], strict=True):
        if result.status == "ok":
            tlsa.extend(format_tlsa(name, result.answers))
        elif result.status == "error":
            tlsa_failed += 1
    if tlsa_failed == len(tlsa_names):
        errors["TLSA"] = msg("dns.query_failed", error=msg("net.timeout"))

    return {
        "domain_exists": domain_exists,
        "CAA": caa,
        "caa_source": caa_source,
        "caa_issuers": caa_issuers(caa),
        "SRV": srv[:MAX_RECORDS],
        "TLSA": tlsa[:MAX_RECORDS],
        "extra_errors": errors,
    }
