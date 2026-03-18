# backend/app/scanners/shodan_scanner.py
"""
Shodan host lookup via REST API.
Called only when a Shodan API key is configured in settings.
"""
from typing import Optional
import httpx


async def shodan_lookup(ip: str, api_key: str) -> dict:
    """
    Fetch Shodan host data for the given IP.

    Returns a normalized dict:
      {
        ports: [int],
        services: [{port, protocol, product, version, banner, cpe}],
        vulns: [{id, cvss, summary}],
        org: str,
        isp: str,
        asn: str,
        hostnames: [str],
        tags: [str],
        country: str,
        city: str,
        last_update: str,
        total_services: int,
        enriched: True
      }
    """
    if not ip or not api_key:
        return {"enriched": False, "error": "No IP or API key"}

    try:
        async with httpx.AsyncClient(timeout=15) as client:
            r = await client.get(
                f"https://api.shodan.io/shodan/host/{ip}",
                params={"key": api_key},
            )
            if r.status_code == 401:
                return {"enriched": False, "error": "Invalid Shodan API key"}
            if r.status_code == 404:
                return {"enriched": False, "error": "No Shodan data for this IP"}
            if r.status_code != 200:
                return {"enriched": False, "error": f"Shodan API error {r.status_code}"}

            raw = r.json()

            # Normalize services from `data` array
            services = []
            for svc in raw.get("data", []):
                banner = svc.get("data", "") or svc.get("banner", "")
                if isinstance(banner, str):
                    banner = banner.strip()[:500]  # cap banner size
                services.append({
                    "port":     svc.get("port"),
                    "protocol": svc.get("transport", "tcp"),
                    "product":  svc.get("product", ""),
                    "version":  svc.get("version", ""),
                    "banner":   banner,
                    "cpe":      svc.get("cpe", []),
                    "os":       svc.get("os", ""),
                    "module":   svc.get("_shodan", {}).get("module", ""),
                })

            # Normalize vulns
            vulns_raw = raw.get("vulns", {})
            vulns = []
            if isinstance(vulns_raw, dict):
                for cve_id, details in vulns_raw.items():
                    if isinstance(details, dict):
                        vulns.append({
                            "id":      cve_id,
                            "cvss":    details.get("cvss", 0),
                            "summary": details.get("summary", ""),
                        })
                    else:
                        vulns.append({"id": cve_id, "cvss": 0, "summary": ""})
            elif isinstance(vulns_raw, list):
                vulns = [{"id": v, "cvss": 0, "summary": ""} for v in vulns_raw]

            # Sort vulns by CVSS descending
            vulns.sort(key=lambda x: x.get("cvss", 0) or 0, reverse=True)

            return {
                "enriched":       True,
                "ip":             raw.get("ip_str", ip),
                "ports":          sorted(raw.get("ports", [])),
                "services":       services,
                "vulns":          vulns,
                "vuln_count":     len(vulns),
                "org":            raw.get("org", ""),
                "isp":            raw.get("isp", ""),
                "asn":            raw.get("asn", ""),
                "hostnames":      raw.get("hostnames", []),
                "tags":           raw.get("tags", []),
                "country":        raw.get("country_name", ""),
                "city":           raw.get("city", ""),
                "region":         raw.get("region_code", ""),
                "last_update":    raw.get("last_update", ""),
                "total_services": len(services),
                "os":             raw.get("os", ""),
            }

    except httpx.TimeoutException:
        return {"enriched": False, "error": "Shodan request timed out"}
    except Exception as e:
        return {"enriched": False, "error": str(e)[:120]}
