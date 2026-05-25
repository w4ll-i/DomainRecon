# backend/app/scanners/http_version_scanner.py
"""
HTTP Version Scanner - Detect HTTP/1.1, HTTP/2, HTTP/3 (QUIC) support.

HTTP/2 : ALPN negotiation in TLS handshake (checks for 'h2').
HTTP/3 : Alt-Svc response header (looks for 'h3' or 'h3-xx').
No external API. Uses ssl + socket + httpx (already in requirements).
"""
import asyncio
import ssl
import socket
from typing import Optional
import httpx


def _check_alpn_sync(domain: str) -> Optional[str]:
    """Return negotiated ALPN protocol ('h2', 'http/1.1', or None)."""
    ctx = ssl.create_default_context()
    ctx.set_alpn_protocols(["h2", "http/1.1"])
    try:
        with socket.create_connection((domain, 443), timeout=8) as sock:
            with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
                return ssock.selected_alpn_protocol()
    except Exception:
        return None


async def check_http_versions(domain: str) -> dict:
    result = {
        "enriched": False,
        "http1_1": True,
        "http2": False,
        "http3": False,
        "quic": False,
        "negotiated_protocol": None,
        "alt_svc": None,
    }

    # HTTP/2 via ALPN
    loop = asyncio.get_event_loop()
    negotiated = await loop.run_in_executor(None, _check_alpn_sync, domain)
    if negotiated is not None:
        result["enriched"] = True
        result["negotiated_protocol"] = negotiated
        result["http2"] = (negotiated == "h2")

    # HTTP/3 via Alt-Svc header
    try:
        async with httpx.AsyncClient(
            verify=False, follow_redirects=True, timeout=8,
            headers={"User-Agent": "Mozilla/5.0 (DomainRecon/7.0)"},
        ) as client:
            r = await client.get(f"https://{domain}")
            alt_svc = r.headers.get("alt-svc", "")
            if alt_svc:
                result["alt_svc"] = alt_svc[:300]
                result["enriched"] = True
                for part in alt_svc.split(","):
                    p = part.strip()
                    if p.startswith("h3") or "h3=" in p:
                        result["http3"] = True
                    if "quic" in p.lower():
                        result["quic"] = True
    except Exception:
        pass

    return result
