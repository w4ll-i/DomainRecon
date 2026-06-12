# backend/app/scanners/dns.py
import asyncio
import logging
import socket
from concurrent.futures import ThreadPoolExecutor
from typing import Optional

import dns.resolver
import dns.zone
import dns.query
import dns.exception

from pathlib import Path

from ._config import SUBDOMAIN_WORDLIST, PRIVATE_IP_PATTERNS

_log = logging.getLogger(__name__)

# Dedicated thread pool for brute-force DNS lookups (avoids saturating default pool)
_brute_pool = ThreadPoolExecutor(max_workers=100, thread_name_prefix="dns_brute")

# Load extended wordlist for full scan (SecLists-compatible)
_WORDLIST_FILE = Path(__file__).parent / "wordlists" / "subdomains.txt"
try:
    _FULL_WORDLIST = [
        w.strip() for w in _WORDLIST_FILE.read_text(encoding="utf-8").splitlines()
        if w.strip() and not w.startswith("#")
    ]
except Exception:
    _FULL_WORDLIST = SUBDOMAIN_WORDLIST


async def resolve_ip(domain: str) -> Optional[str]:
    """Resolve a domain to an IP, preferring IPv4 (A) over IPv6 (AAAA).

    Most downstream modules (geo, ports, DNSBL, BGPView) expect an IPv4
    address, so we return the first IPv4 result and only fall back to IPv6
    when no A record exists.
    """
    loop = asyncio.get_event_loop()
    try:
        info = await loop.getaddrinfo(domain, None)
    except Exception:
        return None
    ipv4 = [item[4][0] for item in info if item[0] == socket.AF_INET]
    if ipv4:
        return ipv4[0]
    return info[0][4][0] if info else None


def _scan_dns_sync(domain: str) -> dict:
    records = {}
    for rtype in ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA", "CAA", "SRV"]:
        try:
            r = dns.resolver.resolve(domain, rtype, lifetime=5)
            if rtype == "MX":
                records[rtype] = [{"priority": x.preference, "value": str(x.exchange).rstrip(".")} for x in r]
            elif rtype == "CAA":
                records[rtype] = [{"flags": x.flags, "tag": x.tag.decode() if isinstance(x.tag, bytes) else str(x.tag), "value": x.value.decode() if isinstance(x.value, bytes) else str(x.value)} for x in r]
            elif rtype == "SRV":
                records[rtype] = [{"priority": x.priority, "weight": x.weight, "port": x.port, "target": str(x.target).rstrip(".")} for x in r]
            else:
                records[rtype] = [str(x) for x in r]
        except Exception:
            records[rtype] = []

    # Check TLSA (DANE) on port 443
    try:
        tlsa_answers = dns.resolver.resolve(f"_443._tcp.{domain}", "TLSA", lifetime=5)
        records["TLSA"] = [str(x) for x in tlsa_answers]
    except Exception:
        records["TLSA"] = []

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
    """Resolve multiple random subdomains to detect wildcard DNS (multi-probe for accuracy)."""
    import random
    import string
    probes = [
        "".join(random.choices(string.ascii_lowercase, k=12)) + f".{domain}"
        for _ in range(3)
    ]
    positive = 0
    for test_sub in probes:
        try:
            dns.resolver.resolve(test_sub, "A", lifetime=5)
            positive += 1
        except dns.resolver.NXDOMAIN:
            pass
        except Exception:
            pass
    if positive >= 2:
        return {"wildcard": True, "test_subdomains": probes}
    elif positive == 1:
        return {"wildcard": True, "test_subdomains": probes, "note": "1/3 probes resolved - possible intermittent wildcard"}
    return {"wildcard": False}


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


def _resolve_fqdn_sync(fqdn: str) -> Optional[str]:
    """Synchronous DNS lookup with hard 3s lifetime (runs in _brute_pool)."""
    try:
        dns.resolver.resolve(fqdn, "A", lifetime=3)
        return fqdn
    except Exception:
        return None


async def _permute_subdomains(domain: str, wordlist: list) -> list:
    """Resolve all wordlist permutations concurrently via dedicated thread pool.

    Uses dns.resolver.resolve(lifetime=3) instead of loop.getaddrinfo so each
    lookup is capped at 3 seconds - prevents thread pool saturation in Docker.
    """
    loop = asyncio.get_event_loop()
    sem = asyncio.Semaphore(100)

    async def resolve_one(sub: str) -> Optional[str]:
        async with sem:
            fqdn = f"{sub}.{domain}"
            return await loop.run_in_executor(_brute_pool, _resolve_fqdn_sync, fqdn)

    tasks = [resolve_one(w) for w in wordlist]
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
        wordlist = _FULL_WORDLIST if _FULL_WORDLIST else SUBDOMAIN_WORDLIST
        try:
            permuted = await asyncio.wait_for(
                _permute_subdomains(domain, wordlist), timeout=50
            )
            found.update(permuted)
        except (asyncio.TimeoutError, TimeoutError):
            pass  # best-effort - keep whatever crt.sh found
    # Quick scan: crt.sh only - no brute-force

    return {"subdomains": sorted(found), "count": len(found)}


TAKEOVER_CNAMES = {
    # GitHub Pages
    "github.io":              "There isn't a GitHub Pages site here.",
    # Heroku
    "herokuapp.com":          "No such app",
    "herokudns.com":          "No such app",
    # Netlify
    "netlify.app":            "Not Found",
    "netlify.com":            "Not Found",
    # Surge
    "surge.sh":               "project not found",
    # Azure
    "azurewebsites.net":      "404 Web Site not found",
    "azure-api.net":          "404 Web Site not found",
    "cloudapp.azure.com":     "404 Web Site not found",
    "trafficmanager.net":     "404 Web Site not found",
    # AWS
    "s3.amazonaws.com":       "NoSuchBucket",
    "s3-website":             "NoSuchBucket",
    "elasticbeanstalk.com":   "NXDOMAIN",
    # Fastly
    "fastly.net":             "Fastly error: unknown domain",
    # Shopify
    "myshopify.com":          "Sorry, this shop is currently unavailable.",
    # Tumblr
    "tumblr.com":             "There's nothing here.",
    # Ghost
    "ghost.io":               "The thing you were looking for is no longer here",
    # Helpjuice
    "helpjuice.com":          "We could not find what you're looking for.",
    # Help Scout
    "helpscoutdocs.com":      "No settings were found for this company",
    # Cargo
    "cargocollective.com":    "404",
    # UserVoice
    "uservoice.com":          "This UserVoice subdomain is currently available",
    # Statuspage
    "statuspage.io":          "You are being redirected",
    # Readme
    "readme.io":              "Project doesnt exist",
    # Pantheon
    "pantheonsite.io":        "The gods are wise",
    # Webflow
    "webflow.io":             "The page you are looking for doesn't exist",
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
