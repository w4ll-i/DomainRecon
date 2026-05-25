# backend/app/scanners/phishtank_scanner.py
"""
PhishTank - Check if domain is in PhishTank phishing database.
Free without API key (100 req/hour per IP). Optional free key available
at phishtank.org for higher limits.
"""
from typing import Optional
import httpx

_ENDPOINT = "https://checkurl.phishtank.com/checkurl/"


async def phishtank_check(domain: str, api_key: Optional[str] = None) -> dict:
    result = {
        "enriched": False,
        "domain": domain,
        "in_database": False,
        "phish_id": None,
        "verified": False,
        "valid": False,
    }

    data: dict = {"url": f"http://{domain}", "format": "json"}
    if api_key:
        data["app_key"] = api_key

    try:
        async with httpx.AsyncClient(timeout=10) as client:
            resp = await client.post(
                _ENDPOINT,
                data=data,
                headers={"User-Agent": "phishtank/DomainRecon"},
            )
            if resp.status_code == 200:
                result["enriched"] = True
                res = resp.json().get("results", {})
                result["in_database"] = res.get("in_database", False)
                result["phish_id"] = res.get("phish_id") or None
                result["verified"] = res.get("verified", False)
                result["valid"] = res.get("valid", False)
                if result["in_database"]:
                    result["phish_detail_page"] = res.get("phish_detail_page", "")
            elif resp.status_code == 429:
                result["error"] = "Rate limited - configure a PhishTank API key for higher limits"
    except Exception as e:
        result["error"] = str(e)[:200]

    return result
