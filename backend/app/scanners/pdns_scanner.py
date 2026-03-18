# backend/app/scanners/pdns_scanner.py
import json
import httpx


async def pdns_lookup(domain: str, circl_user: str = "", circl_password: str = "") -> dict:
    """
    CIRCL Passive DNS lookup.
    Requires free account at circl.lu. Returns NDJSON parsed to list.
    """
    if not circl_user or not circl_password:
        return {"enriched": False, "error": "CIRCL credentials not configured"}

    try:
        async with httpx.AsyncClient(timeout=12) as client:
            r = await client.get(
                f"https://www.circl.lu/pdns/query/{domain}",
                auth=(circl_user, circl_password),
                headers={"Accept": "application/json"},
            )
            if r.status_code == 401:
                return {"enriched": False, "error": "CIRCL PDNS: unauthorized (check credentials)"}
            if r.status_code != 200:
                return {"enriched": False, "error": f"CIRCL PDNS error {r.status_code}"}

            records = []
            for line in r.text.strip().split("\n"):
                if not line.strip():
                    continue
                try:
                    records.append(json.loads(line))
                except json.JSONDecodeError:
                    pass

            records.sort(key=lambda x: x.get("time_last", ""), reverse=True)
            records = records[:100]

            unique_ips = list({
                rec.get("rdata", "")
                for rec in records
                if rec.get("rrtype") in ("A", "AAAA") and rec.get("rdata")
            })

            record_types: dict = {}
            for rec in records:
                t = rec.get("rrtype", "?")
                record_types[t] = record_types.get(t, 0) + 1

            return {
                "enriched": True,
                "total": len(records),
                "records": records,
                "unique_ips": unique_ips,
                "record_types": record_types,
            }

    except httpx.TimeoutException:
        return {"enriched": False, "error": "CIRCL PDNS request timed out"}
    except Exception as e:
        return {"enriched": False, "error": str(e)[:120]}
