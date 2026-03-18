# backend/app/scanners/cert_pinning_scanner.py
"""
Certificate Pinning — detect HPKP and Expect-CT response headers.
Checks: Public-Key-Pins, Public-Key-Pins-Report-Only, Expect-CT.
"""
import httpx


async def check_cert_pinning(domain: str) -> dict:
    """
    Fetch HTTPS headers and analyse certificate pinning directives.
    Returns HPKP pin count, max-age, report-uri, and Expect-CT enforcement.
    """
    result = {
        "enriched": False,
        "hpkp": None,
        "hpkp_report_only": None,
        "expect_ct": None,
        "pins": [],
        "max_age": None,
        "report_uri": None,
        "include_subdomains": False,
        "deprecated_warning": None,
    }
    try:
        async with httpx.AsyncClient(
            timeout=10,
            follow_redirects=True,
            verify=False,
        ) as client:
            r = await client.get(f"https://{domain}")
            headers = {k.lower(): v for k, v in r.headers.items()}
            result["enriched"] = True

            # HPKP
            pkp = headers.get("public-key-pins")
            if pkp:
                pins = []
                max_age = None
                report_uri = None
                include_sub = False
                for part in pkp.split(";"):
                    part = part.strip()
                    if part.startswith("pin-sha256="):
                        pins.append(part)
                    elif part.lower().startswith("max-age="):
                        try:
                            max_age = int(part.split("=", 1)[1])
                        except Exception:
                            pass
                    elif part.lower().startswith("report-uri="):
                        report_uri = part.split("=", 1)[1].strip('"')
                    elif part.lower() == "includesubdomains":
                        include_sub = True
                result["hpkp"] = pkp[:500]
                result["pins"] = pins
                result["max_age"] = max_age
                result["report_uri"] = report_uri
                result["include_subdomains"] = include_sub
                result["deprecated_warning"] = (
                    "HPKP is deprecated since Chrome 72 — consider removing"
                )

            # HPKP Report-Only
            pkp_ro = headers.get("public-key-pins-report-only")
            if pkp_ro:
                result["hpkp_report_only"] = pkp_ro[:500]

            # Expect-CT
            ect = headers.get("expect-ct")
            if ect:
                result["expect_ct"] = ect

    except Exception as e:
        result["error"] = str(e)[:200]

    return result
