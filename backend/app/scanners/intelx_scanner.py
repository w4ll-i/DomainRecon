# backend/app/scanners/intelx_scanner.py
"""
IntelX Scanner — Search Intelligence X for credential leaks.

Triggered only when admin panels are confirmed found.
Requires a free IntelX API key (register at intelx.io — free tier available).

Flow:
  1. POST /intelligent/search  → search ID
  2. Wait 2s
  3. GET  /intelligent/search/result?id={id}&limit=10&k={key} → records

Searches for "@domain.com" to find email:password combos from stealer
logs, redlines, credential dumps, and paste sites indexed by IntelX.
"""
import asyncio
from typing import Optional

import httpx

_BASE = "https://2.intelx.io"
_TIMEOUT = 15


async def intelx_search(domain: str, api_key: Optional[str]) -> dict:
    """
    Search IntelX for credential leaks related to the domain.

    Returns:
      enriched         bool   — True if API call succeeded
      domain           str
      search_terms     list   — terms queried
      total_found      int    — number of records returned
      has_credentials  bool   — True if any results found
      results          list   — sanitized record summaries
      error            str    — present only on failure
    """
    result: dict = {
        "enriched": False,
        "domain": domain,
        "search_terms": [],
        "total_found": 0,
        "has_credentials": False,
        "results": [],
    }

    if not api_key:
        return result

    # Search for email-style entries (@domain.com catches credential dumps)
    search_term = f"@{domain}"
    result["search_terms"] = [search_term]

    try:
        async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
            # Step 1 — submit search
            post_resp = await client.post(
                f"{_BASE}/intelligent/search",
                json={
                    "term": search_term,
                    "sort": 4,          # sort by date descending
                    "media": 0,         # all media types
                    "terminate": [],
                    "timeout": 5,
                    "target": 0,
                    "buckets": [],
                    "maxresults": 10,
                },
                headers={"x-key": api_key},
            )

            if post_resp.status_code == 401:
                result["error"] = "Invalid IntelX API key"
                return result

            if post_resp.status_code != 200:
                result["error"] = f"IntelX search returned HTTP {post_resp.status_code}"
                return result

            search_id = post_resp.json().get("id")
            if not search_id:
                result["error"] = "IntelX returned no search ID"
                return result

            # Step 2 — wait for indexing (IntelX search is async)
            await asyncio.sleep(2)

            # Step 3 — retrieve results
            get_resp = await client.get(
                f"{_BASE}/intelligent/search/result",
                params={"id": search_id, "limit": 10, "k": api_key},
            )

            if get_resp.status_code != 200:
                result["error"] = f"IntelX result fetch returned HTTP {get_resp.status_code}"
                return result

            data = get_resp.json()
            records = data.get("records") or []

            result["enriched"] = True
            result["total_found"] = len(records)
            result["has_credentials"] = len(records) > 0

            # Sanitize records — never expose raw content, only metadata
            for rec in records:
                result["results"].append({
                    "name":      rec.get("name", ""),
                    "bucket":    rec.get("bucket", ""),
                    "date":      rec.get("date", ""),
                    "media":     rec.get("media", 0),
                    "type":      rec.get("type", 0),
                    # storageid allows manual review in IntelX dashboard
                    "storageid": rec.get("storageid", ""),
                })

    except httpx.TimeoutException:
        result["error"] = "IntelX request timed out"
    except Exception as e:
        result["error"] = str(e)[:200]

    return result
