# backend/app/scanners/bgpview_scanner.py
import asyncio
import httpx


async def bgpview_lookup(ip: str) -> dict:
    """
    BGP routing data for an IP via api.bgpview.io.
    Public API, no key. Full profile only (3 chained HTTP calls).
    Step 1: /ip/{ip} → get ASN. Steps 2+3: prefixes + peers in parallel.
    """
    if not ip:
        return {"enriched": False, "error": "No IP provided"}

    try:
        async with httpx.AsyncClient(timeout=10) as client:
            # Step 1: resolve ASN for IP
            r1 = await client.get(f"https://api.bgpview.io/ip/{ip}")
            if r1.status_code == 429:
                return {"enriched": False, "error": "BGPView API rate limited"}
            if r1.status_code != 200:
                return {"enriched": False, "error": f"BGPView API error {r1.status_code}"}

            d1 = r1.json().get("data", {})
            prefixes_raw = d1.get("prefixes", [])
            if not prefixes_raw:
                return {"enriched": False, "error": "BGPView: no ASN found for this IP"}

            p = prefixes_raw[0]
            asn_obj = p.get("asn") or {}
            asn_number = asn_obj.get("asn")
            if not asn_number:
                return {"enriched": False, "error": "BGPView: no ASN found for this IP"}

            rir_obj = p.get("rir_allocation") or {}
            rir = rir_obj.get("rir_name", "") if isinstance(rir_obj, dict) else ""

            # Steps 2+3: parallel
            r_pref, r_peer = await asyncio.gather(
                client.get(f"https://api.bgpview.io/asn/{asn_number}/prefixes"),
                client.get(f"https://api.bgpview.io/asn/{asn_number}/peers"),
                return_exceptions=True,
            )

            def _parse_prefix(pf: dict) -> dict:
                return {
                    "prefix": pf.get("prefix", ""),
                    "name": pf.get("name", ""),
                    "description": pf.get("description", ""),
                }

            def _parse_peer(pe: dict) -> dict:
                return {
                    "asn": pe.get("asn", ""),
                    "name": pe.get("name", ""),
                    "description": pe.get("description", ""),
                }

            prefixes_v4, prefixes_v6 = [], []
            if not isinstance(r_pref, Exception) and r_pref.status_code == 200:
                pd = r_pref.json().get("data", {})
                prefixes_v4 = [_parse_prefix(pf) for pf in (pd.get("ipv4_prefixes") or [])[:30]]
                prefixes_v6 = [_parse_prefix(pf) for pf in (pd.get("ipv6_prefixes") or [])[:10]]

            peers_v4, peers_v6 = [], []
            if not isinstance(r_peer, Exception) and r_peer.status_code == 200:
                prd = r_peer.json().get("data", {})
                peers_v4 = [_parse_peer(pe) for pe in (prd.get("ipv4_peers") or [])[:30]]
                peers_v6 = [_parse_peer(pe) for pe in (prd.get("ipv6_peers") or [])[:10]]

            return {
                "enriched": True,
                "asn": f"AS{asn_number}",
                "asn_description": asn_obj.get("description_short", ""),
                "prefix": p.get("prefix", ""),
                "rir_allocation": rir,
                "country_code": asn_obj.get("country_code", ""),
                "prefixes_v4": prefixes_v4,
                "prefixes_v6": prefixes_v6,
                "peers_v4": peers_v4,
                "peers_v6": peers_v6,
                "peer_count": len(peers_v4) + len(peers_v6),
            }

    except httpx.TimeoutException:
        return {"enriched": False, "error": "BGPView request timed out"}
    except Exception as e:
        return {"enriched": False, "error": str(e)[:120]}
