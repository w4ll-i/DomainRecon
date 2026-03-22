"""Typosquatting Scanner — generates and DNS-checks domain variants."""
import asyncio
import socket
import random
import string
from typing import Optional

EXTENDED_TLDS = [
    "com", "net", "org", "io", "co", "app", "dev", "online",
    "site", "store", "club", "xyz", "tech", "ai", "security",
    "cloud", "network", "info", "biz", "me",
]

TYPO_SUBSTITUTIONS = {
    "a": ["4", "@"], "e": ["3"], "i": ["1", "l"],
    "o": ["0"], "s": ["5", "$"], "t": ["7"],
}

HOMOGLYPHS = {"rn": "m", "vv": "w", "cl": "d"}


def _variants(domain: str) -> list:
    if "." in domain:
        parts = domain.rsplit(".", 1)
        name, tld = parts[0], parts[1]
    else:
        name, tld = domain, "com"

    variants = set()

    for t in EXTENDED_TLDS:
        if t != tld:
            variants.add(f"{name}.{t}")

    for i, ch in enumerate(name):
        for sub in TYPO_SUBSTITUTIONS.get(ch, []):
            variants.add(f"{name[:i]}{sub}{name[i+1:]}.{tld}")

    for i in range(len(name)):
        if len(name) > 3:
            variants.add(f"{name[:i]}{name[i+1:]}.{tld}")

    for i, ch in enumerate(name):
        variants.add(f"{name[:i]}{ch}{ch}{name[i+1:]}.{tld}")

    for src, dst in HOMOGLYPHS.items():
        if src in name:
            variants.add(name.replace(src, dst, 1) + f".{tld}")

    for affix in ["my", "the", "get", "app", "login", "secure", "official"]:
        variants.add(f"{affix}-{name}.{tld}")
        variants.add(f"{name}-{affix}.{tld}")
        variants.add(f"{affix}{name}.{tld}")

    variants.discard(domain)
    return list(variants)[:200]


async def _resolve(domain: str) -> Optional[str]:
    try:
        loop = asyncio.get_event_loop()
        return await asyncio.wait_for(
            loop.run_in_executor(None, socket.gethostbyname, domain),
            timeout=5.0
        )
    except Exception:
        return None


async def _whois_registrar(domain: str) -> Optional[str]:
    try:
        import whois
        w = whois.whois(domain)
        return w.registrar
    except Exception:
        return None


async def scan_typosquatting(domain: str, settings: dict = {}) -> dict:
    target_ip = await _resolve(domain)
    variants = _variants(domain)
    sem = asyncio.Semaphore(50)

    async def check(variant):
        async with sem:
            ip = await _resolve(variant)
            if ip:
                same_ip = (ip == target_ip) if target_ip else None
                registrar = await _whois_registrar(variant)
                if "." in variant and "." in domain:
                    vtld = variant.rsplit(".", 1)[1]
                    dtld = domain.rsplit(".", 1)[1]
                    typ = "tld_swap" if vtld != dtld else "char_variant"
                else:
                    typ = "char_variant"
                return {
                    "domain": variant, "type": typ,
                    "active": True, "ip": ip,
                    "same_ip": same_ip, "registrar": registrar,
                }
        return None

    results = await asyncio.gather(*[check(v) for v in variants])
    active = [r for r in results if r]
    threat_count = sum(1 for r in active if r.get("same_ip") is False)

    return {
        "enriched": bool(active),
        "variants_checked": len(variants),
        "active_count": len(active),
        "threat_count": threat_count,
        "variants": active,
    }
