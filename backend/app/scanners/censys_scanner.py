# backend/app/scanners/censys_scanner.py
"""
Censys Search v2 - certificate and host intelligence via REST API.
API credentials required: https://search.censys.io/account/api
"""
import asyncio
import httpx


async def censys_lookup(domain: str, api_id: str, api_secret: str) -> dict:
    """
    Query Censys for certificates and hosts associated with the given domain.

    Returns a normalized dict:
      {
        enriched: True,
        certificates: [{fingerprint, subject_dn, issuer_dn, names,
                        not_before, not_after}],
        hosts: [{ip, services: [{port, transport_protocol, service_name}],
                 labels}],
        cert_count: int,
        host_count: int,
      }
    """
    if not api_id or not api_secret:
        return {"enriched": False, "reason": "no_credentials"}

    auth = (api_id, api_secret)

    async def fetch_certs(client: httpx.AsyncClient) -> list:
        r = await client.post(
            "https://search.censys.io/api/v2/certificates/search",
            json={"q": f"parsed.names: {domain}", "per_page": 25},
        )
        if r.status_code in (401, 403):
            raise PermissionError("Invalid Censys credentials")
        r.raise_for_status()
        hits = r.json().get("result", {}).get("hits", [])
        certs = []
        for cert in hits:
            parsed = cert.get("parsed", {})
            validity = parsed.get("validity", {})
            certs.append({
                "fingerprint": parsed.get("fingerprint_sha256"),
                "subject_dn": parsed.get("subject_dn"),
                "issuer_dn": parsed.get("issuer_dn"),
                "names": parsed.get("names", []),
                "not_before": validity.get("start"),
                "not_after": validity.get("end"),
            })
        return certs

    async def fetch_hosts(client: httpx.AsyncClient) -> list:
        r = await client.post(
            "https://search.censys.io/api/v2/hosts/search",
            json={
                "q": f"services.tls.certificates.leaf_data.names: {domain}",
                "per_page": 10,
            },
        )
        if r.status_code in (401, 403):
            raise PermissionError("Invalid Censys credentials")
        r.raise_for_status()
        hits = r.json().get("result", {}).get("hits", [])
        hosts = []
        for host in hits:
            services = [
                {
                    "port": s.get("port"),
                    "transport_protocol": s.get("transport_protocol"),
                    "service_name": s.get("service_name"),
                }
                for s in host.get("services", [])
            ]
            hosts.append({
                "ip": host.get("ip"),
                "services": services,
                "labels": host.get("labels", []),
            })
        return hosts

    try:
        async with httpx.AsyncClient(
            auth=auth,
            timeout=15,
            verify=True,
            headers={"Accept": "application/json"},
        ) as client:
            certificates, hosts = await asyncio.gather(
                fetch_certs(client),
                fetch_hosts(client),
            )

        return {
            "enriched": True,
            "certificates": certificates,
            "hosts": hosts,
            "cert_count": len(certificates),
            "host_count": len(hosts),
        }

    except PermissionError:
        return {"enriched": False, "error": "Invalid Censys credentials"}
    except httpx.TimeoutException:
        return {"enriched": False, "error": "Censys request timed out"}
    except Exception as e:
        return {"enriched": False, "error": str(e)[:200]}
