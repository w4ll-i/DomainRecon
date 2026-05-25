# backend/app/scanners/leakix_scanner.py
"""
LeakIX - exposed services and data leak detection.
No auth required for basic use; provide an API key for higher rate limits.
https://leakix.net/
"""
import httpx


async def leakix_lookup(domain: str, api_key: str = None) -> dict:
    """
    Query LeakIX for leaked/exposed services associated with a domain.

    Returns a normalized dict:
      {
        enriched: True,
        leaks: [{event_type, severity, source, host, port, protocol, summary, time}],
        services: [{event_type, severity, source, host, port, protocol, summary}],
        leak_count: int,
        service_count: int,
        critical_count: int,
      }
    """
    if not domain:
        return {"enriched": False, "error": "No domain provided"}

    headers = {"Accept": "application/json"}
    if api_key:
        headers["api-key"] = api_key

    try:
        async with httpx.AsyncClient(timeout=10) as client:
            r = await client.get(
                f"https://leakix.net/api/domain/{domain}",
                headers=headers,
            )

            if r.status_code == 429:
                return {"enriched": False, "error": "LeakIX rate limit reached - provide an API key for higher limits"}
            if r.status_code == 404:
                return {"enriched": False, "error": "No LeakIX data for this domain"}
            if r.status_code != 200:
                return {"enriched": False, "error": f"LeakIX API error {r.status_code}"}

            raw = r.json()

            # API may return null instead of an empty array
            if not raw:
                return {"enriched": False, "error": "No results found"}

            if not isinstance(raw, list):
                return {"enriched": False, "error": "Unexpected LeakIX response format"}

            leaks = []
            services = []
            critical_count = 0

            for item in raw:
                event_type = item.get("event_type", "service")
                severity = item.get("severity", "info")
                entry = {
                    "event_type": event_type,
                    "severity": severity,
                    "source": item.get("event_source", ""),
                    "host": item.get("host", ""),
                    "port": item.get("port"),
                    "protocol": item.get("protocol", "tcp"),
                    "summary": item.get("summary", ""),
                    "time": item.get("time", ""),
                }

                if severity == "critical":
                    critical_count += 1

                if event_type == "leak":
                    leaks.append(entry)
                else:
                    services.append(entry)

            return {
                "enriched": True,
                "leaks": leaks,
                "services": services,
                "leak_count": len(leaks),
                "service_count": len(services),
                "critical_count": critical_count,
            }

    except httpx.TimeoutException:
        return {"enriched": False, "error": "LeakIX request timed out"}
    except Exception as e:
        return {"enriched": False, "error": str(e)[:200]}
