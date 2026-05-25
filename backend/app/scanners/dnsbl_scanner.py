"""Multi-DNSBL Scanner - checks IP against 28 DNS blocklists."""
import asyncio
import socket
import re

DNSBLS = [
    ("zen.spamhaus.org",        "spam+botnet+policy"),
    ("sbl.spamhaus.org",        "spam"),
    ("xbl.spamhaus.org",        "botnet/exploit"),
    ("pbl.spamhaus.org",        "policy"),
    ("cbl.abuseat.org",         "botnet"),
    ("bl.spamcop.net",          "spam"),
    ("dnsbl.sorbs.net",         "spam+abuse"),
    ("b.barracudacentral.org",  "spam"),
    ("psbl.surriel.com",        "spam"),
    ("dnsbl-1.uceprotect.net",  "spam"),
    ("dnsbl-2.uceprotect.net",  "spam"),
    ("dnsbl-3.uceprotect.net",  "spam"),
    ("ips.backscatterer.org",   "backscatter"),
    ("ix.dnsbl.manitu.net",     "spam"),
    ("spam.dnsbl.anonmails.de", "spam"),
    ("dnsbl.spfbl.net",         "spam"),
    ("singular.ttk.pte.hu",     "spam"),
    ("korea.services.net",      "geographic"),
    ("dnsbl.dronebl.org",       "botnet/drone"),
    ("combined.rbl.msrbl.net",  "combined"),
    ("all.s5h.net",             "spam"),
    ("bl.0spam.org",            "spam"),
    ("db.wpbl.info",            "spam"),
    ("dnsbl.inps.de",           "spam"),
    ("bl.mailspike.net",        "spam"),
    ("wl.mailspike.net",        "whitelist"),
    ("ubl.unsubscore.com",      "unsub_abuse"),
    ("dnsbl.tornevall.org",     "abuse"),
]

PRIVATE_RANGES = [
    r"^10\.", r"^172\.(1[6-9]|2[0-9]|3[01])\.",
    r"^192\.168\.", r"^127\.", r"^169\.254\.",
]


def _is_private(ip: str) -> bool:
    return any(re.match(p, ip) for p in PRIVATE_RANGES)


async def _check_one(reversed_ip: str, dnsbl: str) -> str | None:
    query = f"{reversed_ip}.{dnsbl}"
    try:
        loop = asyncio.get_event_loop()
        return await asyncio.wait_for(
            loop.run_in_executor(None, socket.gethostbyname, query),
            timeout=5.0
        )
    except Exception:
        return None


async def scan_dnsbl(ip: str, settings: dict = {}) -> dict:
    if not ip or _is_private(ip):
        return {"enriched": False, "reason": "private_or_missing_ip"}

    parts = ip.split(".")
    if len(parts) != 4:
        return {"enriched": False, "reason": "invalid_ip"}

    reversed_ip = ".".join(reversed(parts))
    responses = await asyncio.gather(*[_check_one(reversed_ip, d) for d, _ in DNSBLS])

    listings = []
    whitelisted = False

    for (dnsbl, category), response in zip(DNSBLS, responses):
        if response is not None:
            if dnsbl == "wl.mailspike.net":
                whitelisted = True
            else:
                listings.append({
                    "dnsbl": dnsbl,
                    "response": response,
                    "category": category,
                })

    n = len(listings)
    severity = "clean" if n == 0 else "medium" if n <= 2 else "high" if n <= 5 else "critical"

    return {
        "enriched": True,
        "ip": ip,
        "listed_count": n,
        "checked_count": len(DNSBLS),
        "whitelisted": whitelisted,
        "severity": severity,
        "listings": listings,
    }
