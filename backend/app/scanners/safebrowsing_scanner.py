# backend/app/scanners/safebrowsing_scanner.py
"""
Google Safe Browsing v4 — Check if domain is flagged as malware/phishing.
Free API key available from Google Cloud Console (generous quota).
"""
from typing import Optional
import httpx

_THREAT_TYPES = [
    "MALWARE", "SOCIAL_ENGINEERING",
    "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION",
]
_ENDPOINT = "https://safebrowsing.googleapis.com/v4/threatMatches:find"


async def safebrowsing_check(domain: str, api_key: Optional[str]) -> dict:
    result = {
        "enriched": False,
        "domain": domain,
        "safe": None,
        "threats": [],
        "threat_count": 0,
    }
    if not api_key:
        return result

    try:
        async with httpx.AsyncClient(timeout=10) as client:
            resp = await client.post(
                f"{_ENDPOINT}?key={api_key}",
                json={
                    "client": {"clientId": "domainrecon", "clientVersion": "7.0"},
                    "threatInfo": {
                        "threatTypes": _THREAT_TYPES,
                        "platformTypes": ["ANY_PLATFORM"],
                        "threatEntryTypes": ["URL"],
                        "threatEntries": [
                            {"url": f"http://{domain}"},
                            {"url": f"https://{domain}"},
                            {"url": f"http://www.{domain}"},
                        ],
                    },
                },
            )
            result["enriched"] = True
            if resp.status_code == 200:
                matches = resp.json().get("matches", [])
                result["safe"] = len(matches) == 0
                result["threat_count"] = len(matches)
                for m in matches:
                    result["threats"].append({
                        "threat_type": m.get("threatType"),
                        "platform_type": m.get("platformType"),
                        "url": m.get("threat", {}).get("url", ""),
                    })
            elif resp.status_code == 400:
                result["error"] = "Invalid API key or request format"
            elif resp.status_code == 403:
                result["error"] = "API key not authorized or quota exceeded"
    except Exception as e:
        result["error"] = str(e)[:200]

    return result
