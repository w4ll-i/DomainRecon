# backend/app/scanners/network.py
import asyncio
import json
import httpx


async def get_geo_data(ip: str) -> dict:
    if not ip:
        return {}
    try:
        async with httpx.AsyncClient(timeout=10) as client:
            r = await client.get(
                f"http://ip-api.com/json/{ip}"
                "?fields=status,country,countryCode,region,city,isp,org,as,lat,lon,timezone"
            )
            if r.status_code == 200:
                data = r.json()
                if data.get("status") == "success":
                    return data
    except Exception:
        pass
    return {}


async def extended_network_scan(ip: str) -> dict:
    result = {}
    try:
        async with httpx.AsyncClient(timeout=10) as client:
            r = await client.get(f"https://rdap.arin.net/registry/ip/{ip}")
            if r.status_code == 200:
                data = r.json()
                result["rdap"] = {
                    "name": data.get("name"),
                    "handle": data.get("handle"),
                    "type": data.get("type"),
                }
    except Exception:
        pass
    return result


async def robtex_lookup(domain: str) -> dict:
    """Robtex passive DNS - free, no API key required."""
    try:
        async with httpx.AsyncClient(timeout=15) as client:
            r = await client.get(f"https://freeapi.robtex.com/pdns/forward/{domain}")
            if r.status_code == 429:
                return {"error": "rate_limited"}
            if r.status_code == 200:
                records = []
                for line in r.text.strip().split("\n"):
                    try:
                        records.append(json.loads(line))
                    except Exception:
                        pass
                return {"records": records, "count": len(records)}
    except Exception as e:
        return {"error": str(e)}
    return {}


async def reverse_ip_lookup(ip: str) -> dict:
    """
    Find other domains hosted on the same IP using HackerTarget API.
    Free tier: 100 requests/day, no key required.
    """
    if not ip:
        return {"domains": [], "count": 0}
    try:
        async with httpx.AsyncClient(timeout=15) as client:
            r = await client.get(
                f"https://api.hackertarget.com/reverseiplookup/?q={ip}"
            )
            if r.status_code == 200:
                text = r.text.strip()
                if "error" in text.lower() or "API count" in text:
                    return {"domains": [], "count": 0, "note": text[:100]}
                domains = [d.strip() for d in text.splitlines() if d.strip() and "." in d]
                return {
                    "domains": domains[:50],
                    "count": len(domains),
                    "truncated": len(domains) > 50,
                }
    except Exception as e:
        return {"domains": [], "count": 0, "error": str(e)}
    return {"domains": [], "count": 0}
