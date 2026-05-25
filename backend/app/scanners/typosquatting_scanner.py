"""Typosquatting Scanner - generates and DNS-checks domain variants."""
import asyncio
import socket
import random
import string
from datetime import datetime, timezone
from typing import Optional

EXTENDED_TLDS = [
    "com", "net", "org", "io", "co", "app", "dev", "online",
    "site", "store", "club", "xyz", "tech", "ai", "security",
    "cloud", "network", "info", "biz", "me", "us", "uk", "ca",
    "de", "fr", "eu", "finance", "bank", "support", "help",
]

TYPO_SUBSTITUTIONS = {
    "a": ["4", "@"], "e": ["3"], "i": ["1", "l"],
    "o": ["0"], "s": ["5", "$"], "t": ["7"],
}

# Extended homoglyphs - visual lookalikes
HOMOGLYPHS = {
    "rn": "m",    # rn → m
    "vv": "w",    # vv → w
    "cl": "d",    # cl → d
    "m": "rn",    # m → rn
    "w": "vv",    # w → vv
    "nn": "m",    # nn → m
    "li": "li",   # for cases where l looks like i
    "1": "l",     # 1 → l
    "0": "o",     # 0 → o
}


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


async def _whois_age(domain: str) -> Optional[int]:
    """Return domain age in days, or None if unavailable."""
    try:
        import whois
        loop = asyncio.get_event_loop()
        w = await asyncio.wait_for(
            loop.run_in_executor(None, whois.whois, domain),
            timeout=8,
        )
        creation = w.creation_date
        if isinstance(creation, list):
            creation = creation[0]
        if creation:
            if creation.tzinfo is None:
                creation = creation.replace(tzinfo=timezone.utc)
            return (datetime.now(timezone.utc) - creation).days
    except Exception:
        pass
    return None


async def scan_typosquatting(domain: str, settings: dict = {}) -> dict:
    target_ip = await _resolve(domain)
    variants = _variants(domain)
    sem = asyncio.Semaphore(50)

    async def check(variant):
        async with sem:
            ip = await _resolve(variant)
            if not ip:
                return None
            same_ip = (ip == target_ip) if target_ip else None
            if "." in variant and "." in domain:
                vtld = variant.rsplit(".", 1)[1]
                dtld = domain.rsplit(".", 1)[1]
                typ = "tld_swap" if vtld != dtld else "char_variant"
            else:
                typ = "char_variant"
            return {
                "domain": variant, "type": typ,
                "active": True, "ip": ip, "same_ip": same_ip,
            }

    results = await asyncio.gather(*[check(v) for v in variants])
    active = [r for r in results if r]

    # WHOIS age check - only for suspicious variants (different IP, not CDN)
    # Limit to 15 lookups max to avoid timeout
    suspicious = [r for r in active if r.get("same_ip") is False][:15]
    if suspicious:
        age_results = await asyncio.gather(
            *[_whois_age(r["domain"]) for r in suspicious],
            return_exceptions=True,
        )
        for entry, age in zip(suspicious, age_results):
            if isinstance(age, int):
                entry["age_days"] = age
                entry["recently_registered"] = age < 90

    threat_count = sum(
        1 for r in active
        if r.get("same_ip") is False or r.get("recently_registered")
    )

    return {
        "enriched": bool(active),
        "variants_checked": len(variants),
        "active_count": len(active),
        "threat_count": threat_count,
        "variants": active,
    }
