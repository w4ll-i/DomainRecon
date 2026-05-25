# backend/app/scanners/osint.py
import asyncio
import base64
import re
from typing import Optional

import httpx
import tldextract

from ._config import JS_SECRET_PATTERNS, TYPO_SUBSTITUTIONS, TYPO_TLDS


async def get_whois_data(domain: str) -> dict:
    try:
        import whois
        loop = asyncio.get_event_loop()
        w = await loop.run_in_executor(None, whois.whois, domain)
        return {
            "registrar": str(w.registrar) if w.registrar else None,
            "creation_date": str(w.creation_date) if w.creation_date else None,
            "expiration_date": str(w.expiration_date) if w.expiration_date else None,
            "updated_date": str(w.updated_date) if w.updated_date else None,
            "name_servers": list(w.name_servers) if w.name_servers else [],
            "status": (
                w.status if isinstance(w.status, list)
                else [w.status] if w.status else []
            ),
        }
    except Exception as e:
        return {"error": str(e)}


async def check_wayback_machine(domain: str) -> dict:
    try:
        async with httpx.AsyncClient(timeout=15) as client:
            r = await client.get(f"http://archive.org/wayback/available?url={domain}")
            if r.status_code == 200:
                snapshot = r.json().get("archived_snapshots", {}).get("closest", {})
                return {
                    "available": snapshot.get("available", False),
                    "url": snapshot.get("url"),
                    "timestamp": snapshot.get("timestamp"),
                    "status": snapshot.get("status"),
                }
    except Exception as e:
        return {"error": str(e)}
    return {}


async def urlscan_lookup(domain: str, api_key: Optional[str] = None) -> dict:
    try:
        headers = {}
        if api_key:
            headers["API-Key"] = api_key
        async with httpx.AsyncClient(timeout=15) as client:
            r = await client.get(
                f"https://urlscan.io/api/v1/search/?q=domain:{domain}&size=5",
                headers=headers,
            )
            if r.status_code == 200:
                data = r.json()
                return {"results": data.get("results", [])[:5], "total": data.get("total", 0)}
    except Exception as e:
        return {"error": str(e)}
    return {}


async def check_threat_intelligence(
    domain: str, ip: str, vt_key: Optional[str] = None
) -> dict:
    result = {}
    if not vt_key:
        return result
    try:
        async with httpx.AsyncClient(timeout=15) as client:
            headers = {"x-apikey": vt_key}

            # Domain reputation
            r_domain = await client.get(
                f"https://www.virustotal.com/api/v3/domains/{domain}",
                headers=headers,
            )
            if r_domain.status_code == 200:
                attrs = r_domain.json().get("data", {}).get("attributes", {})
                result["virustotal"] = {
                    **attrs.get("last_analysis_stats", {}),
                    "reputation": attrs.get("reputation", 0),
                    "categories": attrs.get("categories", {}),
                    "last_analysis_date": attrs.get("last_analysis_date"),
                }

            # IP reputation (if available)
            if ip:
                r_ip = await client.get(
                    f"https://www.virustotal.com/api/v3/ip_addresses/{ip}",
                    headers=headers,
                )
                if r_ip.status_code == 200:
                    ip_attrs = r_ip.json().get("data", {}).get("attributes", {})
                    result["virustotal_ip"] = {
                        **ip_attrs.get("last_analysis_stats", {}),
                        "reputation": ip_attrs.get("reputation", 0),
                        "country": ip_attrs.get("country"),
                        "as_owner": ip_attrs.get("as_owner"),
                        "last_analysis_date": ip_attrs.get("last_analysis_date"),
                    }
    except Exception:
        pass
    return result


async def analyze_js_files(domain: str) -> dict:
    secrets_found = []
    js_urls = []
    try:
        async with httpx.AsyncClient(
            verify=False, follow_redirects=True, timeout=15
        ) as client:
            r = await client.get(f"https://{domain}")
            html = r.text
            js_srcs = re.findall(
                r'<script[^>]+src=["\']([^"\']+\.js[^"\']*)["\']', html, re.IGNORECASE
            )
            for src in js_srcs[:10]:
                if src.startswith("http"):
                    js_urls.append(src)
                elif src.startswith("/"):
                    js_urls.append(f"https://{domain}{src}")
            for url in js_urls:
                try:
                    rjs = await client.get(url, timeout=10)
                    for pattern in JS_SECRET_PATTERNS:
                        matches = re.findall(pattern, rjs.text)
                        if matches:
                            secrets_found.append({
                                "url": url,
                                "pattern": pattern[:50],
                                "matches_count": len(matches),
                            })
                            break
                except Exception:
                    pass
    except Exception as e:
        return {"error": str(e)}
    return {"js_files_scanned": len(js_urls), "secrets_found": secrets_found}


async def compute_favicon_hash(domain: str) -> dict:
    try:
        async with httpx.AsyncClient(
            verify=False, follow_redirects=True, timeout=10
        ) as client:
            r = await client.get(f"https://{domain}/favicon.ico")
            if r.status_code == 200 and r.content:
                from .tls import _mmh3_hash
                h = _mmh3_hash(base64.encodebytes(r.content))
                return {"hash": h, "shodan_query": f"http.favicon.hash:{h}"}
    except Exception:
        pass
    return {}


async def extract_linked_domains(domain: str) -> dict:
    try:
        async with httpx.AsyncClient(
            verify=False, follow_redirects=True, timeout=15
        ) as client:
            r = await client.get(f"https://{domain}")
            hrefs = re.findall(r'href=["\']https?://([^/"\']+)', r.text)
            ext = tldextract.extract(domain)
            base_domain = f"{ext.domain}.{ext.suffix}"
            external = list(
                {h for h in hrefs if not h.endswith(base_domain) and "." in h}
            )[:20]
            return {"linked_domains": external, "count": len(external)}
    except Exception as e:
        return {"error": str(e), "linked_domains": []}


async def check_hsts_preload(domain: str) -> dict:
    try:
        async with httpx.AsyncClient(timeout=10) as client:
            r = await client.get(
                f"https://hstspreload.org/api/v2/status?domain={domain}"
            )
            if r.status_code == 200:
                return r.json()
    except Exception:
        pass
    return {}


async def capture_screenshot(domain: str) -> Optional[str]:
    try:
        from playwright.async_api import async_playwright
        async with async_playwright() as p:
            browser = await p.chromium.launch(headless=True)
            page = await browser.new_page()
            await page.goto(f"https://{domain}", timeout=30000)
            path = f"/tmp/screenshot_{domain}.png"
            await page.screenshot(path=path)
            await browser.close()
            return path
    except Exception:
        return None
