# backend/app/scanners/abuseipdb_scanner.py
"""
AbuseIPDB - IP reputation and abuse confidence score.
Free API key required: https://www.abuseipdb.com/
"""
import httpx


async def abuseipdb_lookup(ip: str, api_key: str) -> dict:
    """Check IP reputation on AbuseIPDB."""
    if not ip:
        return {"enriched": False, "reason": "no_ip"}
    if not api_key:
        return {"enriched": False, "reason": "no_key"}

    try:
        async with httpx.AsyncClient(timeout=10) as client:
            r = await client.get(
                "https://api.abuseipdb.com/api/v2/check",
                params={"ipAddress": ip, "maxAgeInDays": 90},
                headers={"Key": api_key, "Accept": "application/json"},
            )
            if r.status_code == 200:
                data = r.json().get("data", {})
                score = data.get("abuseConfidenceScore", 0)
                return {
                    "enriched": True,
                    "ip": data.get("ipAddress", ip),
                    "abuse_confidence_score": score,
                    "risk_level": (
                        "high" if score >= 75
                        else "medium" if score >= 25
                        else "low"
                    ),
                    "total_reports": data.get("totalReports", 0),
                    "num_distinct_users": data.get("numDistinctUsers", 0),
                    "last_reported_at": data.get("lastReportedAt"),
                    "is_public": data.get("isPublic", True),
                    "is_whitelisted": data.get("isWhitelisted", False),
                    "country_code": data.get("countryCode", ""),
                    "usage_type": data.get("usageType", ""),
                    "isp": data.get("isp", ""),
                    "domain": data.get("domain", ""),
                }
            return {"enriched": False, "reason": f"http_{r.status_code}"}
    except Exception as e:
        return {"enriched": False, "reason": str(e)[:200]}
