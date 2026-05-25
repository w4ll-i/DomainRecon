# backend/app/scanners/emailrep_scanner.py
"""
EmailRep.io - email reputation lookup.
Free tier (public, no key): 10 req/day per IP.
"""
import asyncio
import httpx


async def emailrep_lookup(emails: list) -> dict:
    """Query emailrep.io for up to 5 emails found in HTML/WHOIS intel."""
    if not emails:
        return {"enriched": False, "reason": "no_emails", "results": []}

    results = []
    async with httpx.AsyncClient(timeout=10) as client:
        for email in emails[:5]:
            try:
                r = await client.get(
                    f"https://emailrep.io/{email}",
                    headers={"User-Agent": "DomainRecon/8.0"},
                )
                if r.status_code == 200:
                    data = r.json()
                    details = data.get("details", {})
                    results.append({
                        "email": email,
                        "reputation": data.get("reputation", "unknown"),
                        "suspicious": data.get("suspicious", False),
                        "references": data.get("references", 0),
                        "blacklisted": details.get("blacklisted", False),
                        "credentials_leaked": details.get("credentials_leaked", False),
                        "data_breach": details.get("data_breach", False),
                        "malicious_activity": details.get("malicious_activity", False),
                        "spam": details.get("spam", False),
                        "free_provider": details.get("free_provider", False),
                        "disposable": details.get("disposable", False),
                        "profiles": details.get("profiles", []),
                    })
                elif r.status_code == 400:
                    results.append({"email": email, "error": "invalid_email"})
                elif r.status_code == 429:
                    # Rate limited - stop querying
                    break
            except Exception:
                continue

    return {"enriched": bool(results), "results": results, "count": len(results)}
