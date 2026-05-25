# backend/app/scanners/hibp_scanner.py
"""
Have I Been Pwned (HIBP) - public breach lookup by domain.
No API key required for the /breaches endpoint.
https://haveibeenpwned.com/API/v3
"""
import re
import httpx


def _strip_html(text: str) -> str:
    """Remove HTML tags from a string."""
    return re.sub(r'<[^>]+>', '', text or '')


async def hibp_check(domain: str) -> dict:
    """
    Check the HIBP public breach list for records matching the given domain.

    Returns a normalized dict:
      {
        enriched: True,
        breaches: [{name, title, date, pwn_count, data_classes, is_verified,
                    is_sensitive, description}],
        breach_count: int,
        total_pwned: int,
        sensitive_count: int,
        data_classes_seen: list,
      }
    """
    if not domain:
        return {"enriched": False, "reason": "no_domain"}

    # Normalize: strip leading www.
    clean_domain = domain.lower()
    if clean_domain.startswith("www."):
        clean_domain = clean_domain[4:]

    try:
        async with httpx.AsyncClient(
            timeout=10,
            headers={"User-Agent": "DomainRecon/7.0"},
        ) as client:
            r = await client.get("https://haveibeenpwned.com/api/v3/breaches")

            if r.status_code != 200:
                return {"enriched": False, "error": f"HIBP API error {r.status_code}"}

            all_breaches = r.json()

        # Filter breaches whose Domain matches our target
        matched = [
            b for b in all_breaches
            if b.get("Domain", "").lower() == clean_domain
        ]

        if not matched:
            return {"enriched": False, "reason": "no_breaches"}

        breaches = []
        total_pwned = 0
        sensitive_count = 0
        seen_classes: set = set()

        for b in matched:
            data_classes = b.get("DataClasses", [])
            pwn_count = b.get("PwnCount", 0)
            is_sensitive = b.get("IsSensitive", False)

            total_pwned += pwn_count
            if is_sensitive:
                sensitive_count += 1
            seen_classes.update(data_classes)

            breaches.append({
                "name": b.get("Name"),
                "title": b.get("Title"),
                "date": b.get("BreachDate"),
                "pwn_count": pwn_count,
                "data_classes": data_classes,
                "is_verified": b.get("IsVerified", False),
                "is_sensitive": is_sensitive,
                "description": _strip_html(b.get("Description", "")),
            })

        return {
            "enriched": True,
            "breaches": breaches,
            "breach_count": len(breaches),
            "total_pwned": total_pwned,
            "sensitive_count": sensitive_count,
            "data_classes_seen": sorted(seen_classes),
        }

    except httpx.TimeoutException:
        return {"enriched": False, "error": "HIBP request timed out"}
    except Exception as e:
        return {"enriched": False, "error": str(e)[:200]}
