# =============================================================================
# DomainRecon - Analyse DNSSEC d'un domaine
# =============================================================================
# Interroge un résolveur public QUI VALIDE (1.1.1.1, 8.8.8.8, 9.9.9.9) avec le bit
# DO (EDNS0) : les signatures RRSIG sont renvoyées et le bit AD (« authenticated
# data ») dit si le résolveur a pu valider la chaîne de confiance jusqu'à la racine.
#
# Piège évité : resolver.resolve(..., want_dnssec=True) n'existe pas ; un `except`
# trop large avalerait l'erreur, si bien que RRSIG et AD ne seraient jamais vus,
# qu'un domaine signé et valide recevrait la note D et que NSEC3 ne serait pas distingué.
# Ici les requêtes sont construites avec dns.message.make_query(want_dnssec=True).
#
# Vérifications :
#   - DNSKEY à l'apex (rôles KSK/ZSK, algorithme RFC 8624, taille des clés RSA) ;
#   - DS chez le parent, et correspondance réelle DS <-> DNSKEY (empreinte recalculée) ;
#   - signatures (RRSIG) : présence, échéance dépassée ;
#   - validation par le résolveur (AD) et détection d'une chaîne CASSÉE (« bogus » :
#     SERVFAIL avec validation, réponse normale avec CD=1 : le domaine est
#     inaccessible pour tous les résolveurs qui valident) ;
#   - déni d'existence : NSEC (énumérable) ou NSEC3 (itérations, RFC 9276 : 0).
# DNS direct, sans proxy, comme les autres modules DNS.
# =============================================================================

import secrets
import time
from datetime import datetime, timezone

import dns.dnssec
import dns.exception
import dns.flags
import dns.message
import dns.name
import dns.query
import dns.rcode
import dns.rdatatype

from ...i18n import msg

# Résolveurs validants publics, essayés dans l'ordre.
RESOLVERS = ("1.1.1.1", "8.8.8.8", "9.9.9.9")
QUERY_TIMEOUT = 4.0
BUDGET = 30.0
PAYLOAD = 1232

# Algorithmes (RFC 8624) : nom et caractère déconseillé ou interdit.
ALGORITHMS = {
    1: ("RSAMD5", True),
    3: ("DSA", True),
    5: ("RSASHA1", True),
    6: ("DSA-NSEC3-SHA1", True),
    7: ("RSASHA1-NSEC3-SHA1", True),
    8: ("RSASHA256", False),
    10: ("RSASHA512", False),
    12: ("ECC-GOST", True),
    13: ("ECDSAP256SHA256", False),
    14: ("ECDSAP384SHA384", False),
    15: ("ED25519", False),
    16: ("ED448", False),
}
_RSA = {1, 5, 7, 8, 10}
# Empreintes de DS : SHA-1 déconseillée (RFC 8624 §3.3).
DIGESTS = {1: ("SHA-1", True), 2: ("SHA-256", False), 3: ("GOST R 34.11-94", True), 4: ("SHA-384", False)}
MIN_RSA_BITS = 1024


class Unavailable(Exception):
    """Aucun résolveur n'a répondu."""


class Session:
    """Requêtes vers un résolveur validant, sous un budget de temps commun."""

    def __init__(self) -> None:
        self.deadline = time.monotonic() + BUDGET
        self.resolver: str | None = None

    def ask(self, name: str, rdtype: str, *, cd: bool = False) -> dns.message.Message:
        """Réponse du premier résolveur qui répond ; lève Unavailable si aucun."""
        query = dns.message.make_query(name, rdtype, want_dnssec=True, use_edns=0, payload=PAYLOAD)
        query.flags |= dns.flags.AD
        if cd:
            query.flags |= dns.flags.CD
        servers = [self.resolver] if self.resolver else list(RESOLVERS)
        for server in servers:
            remaining = self.deadline - time.monotonic()
            if remaining <= 0:
                break
            try:
                response = _send(query, server, min(QUERY_TIMEOUT, remaining))
            except (dns.exception.DNSException, OSError, EOFError):
                continue
            self.resolver = server
            return response
        raise Unavailable


def _send(query: dns.message.Message, server: str, timeout: float) -> dns.message.Message:
    """Envoie la requête en UDP (TCP si la réponse est tronquée). Point d'injection des tests."""
    response, _ = dns.query.udp_with_fallback(query, server, timeout=timeout)
    return response


# --- Lecture des réponses ------------------------------------------------------


def _rrsets(response: dns.message.Message, rdtype: int, section: str = "answer") -> list:
    return [rr for rr in getattr(response, section) if rr.rdtype == rdtype]


def _rrsigs(response: dns.message.Message, covers: int) -> list:
    return [
        sig for rr in _rrsets(response, dns.rdatatype.RRSIG) for sig in rr if int(sig.type_covered) == covers
    ]


def _rsa_bits(key: bytes) -> int | None:
    """Taille du module d'une clé publique RSA (RFC 3110) ; None si le format est illisible."""
    if not key:
        return None
    if key[0] == 0:
        if len(key) < 3:
            return None
        exponent_length, offset = int.from_bytes(key[1:3], "big"), 3
    else:
        exponent_length, offset = key[0], 1
    modulus = key[offset + exponent_length :]
    return len(modulus) * 8 if modulus else None


def _key_info(key) -> dict:
    algorithm = int(key.algorithm)
    name, weak = ALGORITHMS.get(algorithm, (f"ALG{algorithm}", False))
    flags = int(key.flags)
    info = {
        "key_tag": dns.dnssec.key_id(key),
        "flags": flags,
        "role": "KSK" if flags & 0x0001 else "ZSK",
        "algorithm": algorithm,
        "algorithm_name": name,
        "weak": weak,
        "bits": _rsa_bits(key.key) if algorithm in _RSA else None,
    }
    return info


def _ds_info(zone: str, ds, keys: list) -> dict:
    """Empreinte DS, et vérité de sa correspondance avec l'une des DNSKEY du domaine."""
    digest_type = int(ds.digest_type)
    name, weak = DIGESTS.get(digest_type, (f"DIGEST{digest_type}", False))
    matched = False
    for key in keys:
        if dns.dnssec.key_id(key) != int(ds.key_tag) or int(key.algorithm) != int(ds.algorithm):
            continue
        try:
            computed = dns.dnssec.make_ds(dns.name.from_text(zone), key, digest_type)
        except (dns.dnssec.UnsupportedAlgorithm, ValueError):
            continue
        if computed.digest == ds.digest:
            matched = True
    return {
        "key_tag": int(ds.key_tag),
        "algorithm": int(ds.algorithm),
        "digest_type": digest_type,
        "digest_name": name,
        "weak": weak,
        "matches_dnskey": matched,
    }


def _isoformat(timestamp: int) -> str:
    return datetime.fromtimestamp(timestamp, tz=timezone.utc).strftime("%Y-%m-%d")


# --- Analyse -------------------------------------------------------------------


def analyze(zone: str) -> dict:
    """Analyse DNSSEC de `zone` (bloquant : à lancer dans un thread). Lève Unavailable sans résolveur."""
    session = Session()
    zone = zone.rstrip(".").lower()

    dnskey_resp = session.ask(zone, "DNSKEY")
    dnskey_sets = _rrsets(dnskey_resp, dns.rdatatype.DNSKEY)
    keys = [key for rr in dnskey_sets for key in rr]
    bogus = False
    if dnskey_resp.rcode() == dns.rcode.SERVFAIL:
        # SERVFAIL avec validation : si les données existent sans validation (CD=1), la chaîne est cassée.
        unchecked = session.ask(zone, "DNSKEY", cd=True)
        if _rrsets(unchecked, dns.rdatatype.DNSKEY):
            bogus = True
            keys = [key for rr in _rrsets(unchecked, dns.rdatatype.DNSKEY) for key in rr]
            dnskey_resp = unchecked

    ds_resp = session.ask(zone, "DS")
    ds_records = [ds for rr in _rrsets(ds_resp, dns.rdatatype.DS) for ds in rr]
    ds_info = [_ds_info(zone, ds, keys) for ds in ds_records]

    address_resp = session.ask(zone, "A")
    address_sigs = _rrsigs(address_resp, int(dns.rdatatype.A))
    if not address_sigs:
        # Pas d'adresse A signée (domaine sans A) : les signatures du DNSKEY font foi.
        address_sigs = _rrsigs(dnskey_resp, int(dns.rdatatype.DNSKEY))
    ad_flag = bool(address_resp.flags & dns.flags.AD) or bool(dnskey_resp.flags & dns.flags.AD)

    nsec_type, nsec3_iterations, nsec3_optout = None, None, False
    if keys:
        denial = session.ask(f"dr-{secrets.token_hex(6)}.{zone}", "A")
        nsec3 = _rrsets(denial, dns.rdatatype.NSEC3, "authority")
        if nsec3:
            nsec_type = "NSEC3"
            nsec3_iterations = int(nsec3[0][0].iterations)
            nsec3_optout = bool(int(nsec3[0][0].flags) & 1)
        elif _rrsets(denial, dns.rdatatype.NSEC, "authority"):
            nsec_type = "NSEC"

    key_infos = [_key_info(key) for key in keys]
    expirations = [int(sig.expiration) for sig in address_sigs]
    soonest = min(expirations) if expirations else None
    days_left = int((soonest - time.time()) // 86400) if soonest is not None else None

    result = {
        "zone": zone,
        "resolver": session.resolver,
        "dnskey_found": bool(keys),
        "ds_found": bool(ds_records),
        "rrsig_found": bool(address_sigs),
        "validated": ad_flag and not bogus,
        "bogus": bogus,
        "ds_match": (any(d["matches_dnskey"] for d in ds_info) if ds_info and keys else None),
        "nsec_type": nsec_type,
        "nsec3_iterations": nsec3_iterations,
        "nsec3_optout": nsec3_optout,
        "keys": key_infos,
        "key_count": len(key_infos),
        "algorithms": sorted(
            {(k["algorithm"], k["algorithm_name"], k["weak"]) for k in key_infos}, key=lambda a: a[0]
        ),
        "ds_records": ds_info,
        "signature_expires": _isoformat(soonest) if soonest is not None else None,
        "days_left": days_left,
    }
    result["algorithms"] = [{"id": a, "name": n, "weak": w} for a, n, w in result["algorithms"]]
    result["signed"] = result["dnskey_found"] and result["ds_found"]
    result["status"] = _status(result)
    result["issues"] = _issues(result)
    result["grade"] = _grade(result)
    return result


def _status(r: dict) -> str:
    if r["bogus"] or r["ds_match"] is False or (r["days_left"] is not None and r["days_left"] < 0):
        return "broken"
    if r["dnskey_found"] and not r["ds_found"]:
        return "incomplete"
    if r["ds_found"] and not r["dnskey_found"]:
        return "broken"
    if r["signed"]:
        return "signed"
    return "unsigned"


def _issues(r: dict) -> list:
    issues: list = []
    if r["bogus"]:
        issues.append(msg("dnssec_data.issue_bogus"))
    if r["status"] == "unsigned":
        issues.append(msg("dnssec_data.issue_unsigned"))
        return issues
    if r["dnskey_found"] and not r["ds_found"]:
        issues.append(msg("dnssec_data.issue_no_ds"))
    if r["ds_found"] and not r["dnskey_found"]:
        issues.append(msg("dnssec_data.issue_no_dnskey"))
    if r["ds_match"] is False:
        issues.append(msg("dnssec_data.issue_ds_mismatch"))
    for algorithm in r["algorithms"]:
        if algorithm["weak"]:
            issues.append(msg("dnssec_data.issue_weak_algorithm", algorithm=algorithm["name"]))
    for ds in r["ds_records"]:
        if ds["weak"] and not any(not d["weak"] for d in r["ds_records"]):
            issues.append(msg("dnssec_data.issue_weak_digest", digest=ds["digest_name"]))
            break
    for key in r["keys"]:
        if key["bits"] is not None and key["bits"] < MIN_RSA_BITS:
            issues.append(msg("dnssec_data.issue_short_key", bits=key["bits"], key_tag=key["key_tag"]))
    if r["dnskey_found"] and not r["rrsig_found"] and not r["bogus"]:
        issues.append(msg("dnssec_data.issue_no_rrsig"))
    if r["days_left"] is not None:
        # Une signature qui expire dans quelques jours est normale (les signeurs automatiques renouvellent
        # bien avant l'échéance, Cloudflare compris) : seule une signature DÉJÀ échue est un défaut.
        if r["days_left"] < 0:
            issues.append(msg("dnssec_data.issue_sig_expired"))
    if r["nsec3_iterations"]:
        issues.append(msg("dnssec_data.issue_nsec3_iterations", iterations=r["nsec3_iterations"]))
    if r["signed"] and not r["validated"] and not r["bogus"]:
        issues.append(msg("dnssec_data.issue_unvalidated"))
    return issues


def _has_reserves(r: dict) -> bool:
    """Chaîne valide, mais un paramètre est déconseillé (algorithme, empreinte, clé courte, NSEC3)."""
    if any(a["weak"] for a in r["algorithms"]):
        return True
    if r["ds_records"] and all(d["weak"] for d in r["ds_records"]):
        return True
    if any(k["bits"] is not None and k["bits"] < MIN_RSA_BITS for k in r["keys"]):
        return True
    return bool(r["nsec3_iterations"])


def _grade(r: dict) -> str:
    """A : chaîne valide et paramètres sains ; B : valide avec réserves ; C : signé mais non validé ;
    D : chaîne incomplète (DNSKEY sans DS) ; F : non signé ou cassé."""
    if r["status"] in ("unsigned", "broken"):
        return "F"
    if r["status"] == "incomplete":
        return "D"
    if not r["validated"]:
        return "C"
    return "B" if _has_reserves(r) else "A"
