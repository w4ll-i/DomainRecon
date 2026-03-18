# backend/app/scanners/certsh_scanner.py
import httpx


async def certsh_lookup(domain: str) -> dict:
    """
    Certificate Transparency lookup via crt.sh.
    Public API, no key required.
    NOTE: ct_only_subdomains is computed post-Wave-1 in scanner.py, not here.
    """
    try:
        async with httpx.AsyncClient(
            timeout=15,
            headers={"User-Agent": "DomainRecon/7.0"},
            follow_redirects=True,
        ) as client:
            r = await client.get(f"https://crt.sh/?q=%.{domain}&output=json")
            if r.status_code != 200:
                return {"enriched": False, "error": f"crt.sh error {r.status_code}"}

            try:
                data = r.json()
            except Exception:
                return {"enriched": False, "error": "crt.sh returned invalid JSON"}

            if not data:
                return {"enriched": False, "error": "crt.sh returned no results"}

            # Deduplicate by min_cert_id
            seen: set = set()
            unique = []
            for entry in data:
                cid = entry.get("min_cert_id") or entry.get("id")
                if cid not in seen:
                    seen.add(cid)
                    unique.append(entry)

            # Most recent 200
            unique.sort(key=lambda x: x.get("logged_at") or "", reverse=True)
            unique = unique[:200]

            # Extract issuer display names
            issuers = list({
                entry.get("issuer_name", "").split("O=")[-1].split(",")[0].strip()
                for entry in unique
                if entry.get("issuer_name")
            })[:10]

            # Parse cert list
            certs = []
            dates = []
            for entry in unique:
                san_raw = entry.get("name_value", "") or ""
                san = [s.strip() for s in san_raw.split("\n") if s.strip()]
                logged = (entry.get("logged_at") or "")[:10]
                if logged:
                    dates.append(logged)
                certs.append({
                    "id": entry.get("min_cert_id") or entry.get("id"),
                    "logged_at": logged,
                    "not_before": (entry.get("not_before") or "")[:10],
                    "not_after": (entry.get("not_after") or "")[:10],
                    "issuer_name": (entry.get("issuer_name") or "")[:80],
                    "common_name": entry.get("common_name") or "",
                    "san": san,
                })

            return {
                "enriched": True,
                "total_certs": len(data),
                "unique_certs": len(unique),
                "issuers": issuers,
                "certs": certs,
                "date_range": {"oldest": min(dates), "newest": max(dates)} if dates else {},
            }

    except httpx.TimeoutException:
        return {"enriched": False, "error": "crt.sh request timed out"}
    except Exception as e:
        return {"enriched": False, "error": str(e)[:120]}
