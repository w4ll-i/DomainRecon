# backend/app/scanners/doh_scanner.py
"""
DNS over HTTPS Comparison — Resolve domain via Cloudflare, Google, Quad9.
Detects: split-horizon DNS, censorship, DNS poisoning, DNSSEC validation status.
No external API key required. Uses httpx (already in requirements).
"""
import asyncio
import httpx

_PROVIDERS = {
    "cloudflare": "https://cloudflare-dns.com/dns-query",
    "google":     "https://dns.google/resolve",
    "quad9":      "https://dns.quad9.net/dns-query",
}

_STATUS = {0: "NOERROR", 1: "FORMERR", 2: "SERVFAIL", 3: "NXDOMAIN", 5: "REFUSED"}


async def _query_one(client: httpx.AsyncClient, url: str, domain: str) -> dict:
    try:
        r = await client.get(
            url,
            params={"name": domain, "type": "A"},
            headers={"Accept": "application/dns-json"},
            timeout=8,
        )
        if r.status_code == 200:
            data = r.json()
            status = data.get("Status", -1)
            ips = [a["data"] for a in data.get("Answer", []) if a.get("type") == 1]
            return {
                "status": status,
                "status_name": _STATUS.get(status, f"Code {status}"),
                "ips": ips,
                "ad": data.get("AD", False),
            }
    except Exception as e:
        return {"status": -1, "status_name": "Error", "ips": [], "ad": False, "error": str(e)[:80]}
    return {"status": -1, "status_name": "HTTP error", "ips": [], "ad": False}


async def doh_comparison(domain: str) -> dict:
    result: dict = {
        "enriched": False,
        "domain": domain,
        "providers": {},
        "consistent": True,
        "issues": [],
        "dnssec_validated_by": [],
    }

    async with httpx.AsyncClient(follow_redirects=True) as client:
        responses = await asyncio.gather(
            *[_query_one(client, url, domain) for url in _PROVIDERS.values()],
            return_exceptions=True,
        )

    for provider, resp in zip(_PROVIDERS.keys(), responses):
        result["providers"][provider] = (
            {"status": -1, "ips": [], "ad": False, "error": str(resp)[:80]}
            if isinstance(resp, Exception) else resp
        )

    result["enriched"] = True

    # Compare IP sets across providers
    valid = {p: v for p, v in result["providers"].items() if not v.get("error") and v["ips"]}
    ip_sets = [frozenset(v["ips"]) for v in valid.values()]
    if len(ip_sets) > 1 and len(set(ip_sets)) > 1:
        result["consistent"] = False
        nxdomains = [p for p, v in result["providers"].items() if v.get("status") == 3]
        if nxdomains and len(nxdomains) < len(result["providers"]):
            result["issues"].append(
                f"NXDOMAIN from {', '.join(nxdomains)} but others resolve — possible DNS censorship/blocking"
            )
        else:
            result["issues"].append(
                "Different IPs returned by different resolvers — possible split-horizon DNS or CDN geo-routing"
            )

    # DNSSEC validation across providers
    result["dnssec_validated_by"] = [
        p for p, v in result["providers"].items() if v.get("ad")
    ]

    return result
