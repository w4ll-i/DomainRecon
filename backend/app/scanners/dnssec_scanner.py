# backend/app/scanners/dnssec_scanner.py
"""
DNSSEC Scanner - Verify DNSSEC signing status.
No external API. Uses dnspython (already in requirements).

Checks: DNSKEY, DS, RRSIG, NSEC/NSEC3, AD flag (chain validation).
"""
import asyncio
import dns.resolver
import dns.rdatatype
import dns.flags
import dns.exception

_ALGORITHMS = {
    1: "RSA/MD5",  3: "DSA/SHA1",  5: "RSA/SHA-1",
    6: "DSA-NSEC3-SHA1",  7: "RSASHA1-NSEC3-SHA1",
    8: "RSA/SHA-256",  10: "RSA/SHA-512",
    13: "ECDSA/P-256/SHA-256",  14: "ECDSA/P-384/SHA-384",
    15: "Ed25519",  16: "Ed448",
}
_WEAK_ALGOS = {1, 3, 5, 6, 7}


def _dnssec_sync(domain: str) -> dict:
    result = {
        "enriched": False,
        "signed": False,
        "dnskey_found": False,
        "ds_found": False,
        "rrsig_found": False,
        "validated": False,
        "nsec_type": None,
        "algorithms": [],
        "key_count": 0,
        "issues": [],
        "grade": "F",
    }
    resolver = dns.resolver.Resolver()
    resolver.nameservers = ["8.8.8.8", "1.1.1.1", "9.9.9.9"]
    resolver.timeout = 5
    resolver.lifetime = 10

    # 1. DNSKEY at apex
    try:
        ans = resolver.resolve(domain, "DNSKEY")
        result.update(enriched=True, dnskey_found=True, signed=True)
        algos = []
        for rdata in ans:
            n = rdata.algorithm.value if hasattr(rdata.algorithm, "value") else int(rdata.algorithm)
            name = _ALGORITHMS.get(n, f"Algorithm {n}")
            algos.append(name)
            if n in _WEAK_ALGOS:
                result["issues"].append(f"Weak DNSSEC algorithm: {name}")
        result["algorithms"] = list(set(algos))
        result["key_count"] = len(ans.rrset)
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
        result["enriched"] = True
    except Exception:
        result["enriched"] = True

    # 2. DS in parent zone
    try:
        resolver.resolve(domain, "DS")
        result.update(ds_found=True, signed=True)
    except Exception:
        pass

    # 3. RRSIG on A records + AD flag
    try:
        a_ans = resolver.resolve(domain, "A", want_dnssec=True)
        for rrset in a_ans.response.answer:
            if rrset.rdtype == dns.rdatatype.RRSIG:
                result.update(rrsig_found=True, signed=True)
                break
        if a_ans.response.flags & dns.flags.AD:
            result["validated"] = True
    except Exception:
        pass

    # 4. NSEC/NSEC3
    for nsec_type in ("NSEC3", "NSEC"):
        try:
            resolver.resolve(domain, nsec_type)
            result["nsec_type"] = nsec_type
            break
        except Exception:
            pass

    # Issues
    if not result["signed"]:
        result["issues"].append("DNSSEC not configured - zone is unsigned")
    elif result["dnskey_found"] and not result["ds_found"]:
        result["issues"].append("DNSKEY present but no DS - chain of trust broken (not verifiable from parent)")
    elif result["signed"] and not result["rrsig_found"]:
        result["issues"].append("Zone appears signed but RRSIG missing on A records")

    # Grade
    if result["validated"] and not [i for i in result["issues"] if "Weak" not in i]:
        grade = "A"
    elif result["validated"]:
        grade = "B"
    elif result["signed"] and result["rrsig_found"]:
        grade = "C"
    elif result["signed"]:
        grade = "D"
    else:
        grade = "F"
    result["grade"] = grade
    return result


async def check_dnssec(domain: str) -> dict:
    loop = asyncio.get_event_loop()
    return await loop.run_in_executor(None, _dnssec_sync, domain)
