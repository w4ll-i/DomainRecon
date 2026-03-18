# backend/app/scanners/builtwith_scanner.py
import httpx


async def builtwith_lookup(domain: str, api_key: str = "") -> dict:
    """
    Technology stack lookup via BuiltWith API.
    Free tier key available at builtwith.com.
    """
    if not api_key:
        return {"enriched": False, "error": "No BuiltWith API key configured"}

    try:
        async with httpx.AsyncClient(timeout=12) as client:
            r = await client.get(
                "https://api.builtwith.com/v21/api.json",
                params={"KEY": api_key, "LOOKUP": domain},
            )
            if r.status_code in (401, 403):
                return {"enriched": False, "error": "Invalid BuiltWith API key"}
            if r.status_code == 404:
                return {"enriched": False, "error": "Domain not found in BuiltWith"}
            if r.status_code != 200:
                return {"enriched": False, "error": f"BuiltWith API error {r.status_code}"}

            data = r.json()
            results = data.get("Results", [])
            if not results:
                return {"enriched": False, "error": "BuiltWith: no results for this domain"}

            paths = (results[0].get("Result") or {}).get("Paths") or []
            techs_raw = paths[0].get("Technologies", []) if paths else []

            categories: dict = {}
            technologies = []
            for t in techs_raw:
                name = t.get("Name", "")
                if not name:
                    continue
                tag = (t.get("Tag") or "other").lower()
                categories.setdefault(tag, [])
                if name not in categories[tag]:
                    categories[tag].append(name)
                technologies.append({"name": name, "category": tag})

            return {
                "enriched": True,
                "categories": categories,
                "technologies": technologies,
                "tech_count": len(technologies),
            }

    except httpx.TimeoutException:
        return {"enriched": False, "error": "BuiltWith request timed out"}
    except Exception as e:
        return {"enriched": False, "error": str(e)[:120]}
