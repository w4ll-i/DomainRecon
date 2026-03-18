# backend/app/scanners/dns.py
import asyncio
import socket
from typing import Optional

import dns.resolver
import dns.zone
import dns.query
import dns.exception

from ._config import SUBDOMAIN_WORDLIST, PRIVATE_IP_PATTERNS


async def resolve_ip(domain: str) -> Optional[str]:
    loop = asyncio.get_event_loop()
    try:
        info = await loop.getaddrinfo(domain, None)
        return info[0][4][0]
    except Exception:
        return None


def _scan_dns_sync(domain: str) -> dict:
    records = {}
    for rtype in ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA"]:
        try:
            r = dns.resolver.resolve(domain, rtype, lifetime=5)
            if rtype == "MX":
                records[rtype] = [{"priority": x.preference, "value": str(x.exchange).rstrip(".")} for x in r]
            else:
                records[rtype] = [str(x) for x in r]
        except Exception:
            records[rtype] = []
    return records


async def scan_dns_records(domain: str) -> dict:
    loop = asyncio.get_event_loop()
    return await loop.run_in_executor(None, _scan_dns_sync, domain)


def _check_zone_transfer_sync(domain: str) -> dict:
    """Attempt AXFR against each authoritative NS."""
    result = {"attempted": [], "vulnerable": False, "records": []}
    try:
        ns_answers = dns.resolver.resolve(domain, "NS", lifetime=5)
        nameservers = [str(ns).rstrip(".") for ns in ns_answers]
    except Exception:
        return result
    for ns in nameservers:
        result["attempted"].append(ns)
        try:
            z = dns.zone.from_xfr(dns.query.xfr(ns, domain, timeout=5))
            result["vulnerable"] = True
            for name in z.nodes.keys():
                result["records"].append(str(name))
            break
        except Exception:
            continue
    return result


async def check_zone_transfer(domain: str) -> dict:
    loop = asyncio.get_event_loop()
    return await loop.run_in_executor(None, _check_zone_transfer_sync, domain)


def _check_wildcard_sync(domain: str) -> dict:
    """Resolve a random subdomain to detect wildcard DNS."""
    test_sub = f"randomxyz_no_exist_abc.{domain}"
    try:
        dns.resolver.resolve(test_sub, "A", lifetime=5)
        return {"wildcard": True, "test_subdomain": test_sub}
    except dns.resolver.NXDOMAIN:
        return {"wildcard": False}
    except Exception:
        return {"wildcard": None, "error": "timeout"}


async def check_wildcard(domain: str) -> dict:
    loop = asyncio.get_event_loop()
    return await loop.run_in_executor(None, _check_wildcard_sync, domain)


def _check_dns_rebinding_sync(domain: str) -> dict:
    """Check A records for private/loopback IPs (DNS rebinding risk)."""
    import re
    risk_ips = []
    try:
        answers = dns.resolver.resolve(domain, "A", lifetime=5)
        for rdata in answers:
            ip = str(rdata)
            if any(re.match(p, ip) for p in PRIVATE_IP_PATTERNS):
                risk_ips.append(ip)
    except Exception:
        pass
    return {"rebinding_risk": len(risk_ips) > 0, "private_ips": risk_ips}


async def check_dns_rebinding(domain: str) -> dict:
    loop = asyncio.get_event_loop()
    return await loop.run_in_executor(None, _check_dns_rebinding_sync, domain)


async def _permute_subdomains(domain: str) -> list:
    """Resolve all wordlist permutations concurrently (Semaphore 50)."""
    sem = asyncio.Semaphore(50)

    async def resolve_one(sub: str) -> Optional[str]:
        async with sem:
            fqdn = f"{sub}.{domain}"
            ip = await resolve_ip(fqdn)
            return fqdn if ip else None

    tasks = [resolve_one(w) for w in SUBDOMAIN_WORDLIST]
    results = await asyncio.gather(*tasks, return_exceptions=True)
    return [r for r in results if isinstance(r, str)]


async def find_subdomains(domain: str, scan_profile: str = "full") -> dict:
    """Enumerate subdomains via crt.sh CT logs + optional wordlist permutation."""
    found = set()
    try:
        import httpx
        async with httpx.AsyncClient(timeout=15) as client:
            r = await client.get(f"https://crt.sh/?q=%.{domain}&output=json")
            if r.status_code == 200:
                for entry in r.json():
                    name = entry.get("name_value", "")
                    for sub in name.split("\n"):
                        sub = sub.strip().lstrip("*.")
                        if sub.endswith(f".{domain}") and sub != domain:
                            found.add(sub)
    except Exception:
        pass

    if scan_profile == "full":
        permuted = await _permute_subdomains(domain)
        found.update(permuted)

    return {"subdomains": sorted(found), "count": len(found)}


TAKEOVER_CNAMES = {
    "github.io": "There isn't a GitHub Pages site here.",
    "herokuapp.com": "No such app",
    "netlify.app": "Not found",
    "surge.sh": "project not found",
    "azurewebsites.net": "404 Web Site not found",
}


def _check_takeover_sync(subdomain: str) -> Optional[str]:
    try:
        answers = dns.resolver.resolve(subdomain, "CNAME", lifetime=5)
        cname = str(answers[0]).rstrip(".")
        for service, signature in TAKEOVER_CNAMES.items():
            if cname.endswith(service):
                import urllib.request
                try:
                    resp = urllib.request.urlopen(f"http://{subdomain}", timeout=5)
                    body = resp.read(2000).decode(errors="ignore")
                    if signature.lower() in body.lower():
                        return f"VULNERABLE -> {cname}"
                except Exception:
                    return f"POSSIBLE -> {cname}"
    except Exception:
        pass
    return None


async def check_subdomain_takeover(subdomains: list) -> dict:
    loop = asyncio.get_event_loop()
    vulnerable = []
    for sub in subdomains[:50]:
        result = await loop.run_in_executor(None, _check_takeover_sync, sub)
        if result:
            vulnerable.append({"subdomain": sub, "status": result})
    return {"vulnerable": vulnerable, "count": len(vulnerable)}


def _reverse_dns_sync(ip: str) -> Optional[str]:
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return None


async def reverse_dns(ip: str) -> dict:
    loop = asyncio.get_event_loop()
    hostname = await loop.run_in_executor(None, _reverse_dns_sync, ip)
    return {"ptr": hostname, "ip": ip}
