# backend/app/scanners/observatory_scanner.py
"""
Mozilla Observatory - HTTP security scan and grade.
Public API, no key required.
API: https://http-observatory.security.mozilla.org/api/v1/
"""
import asyncio
import httpx

_BASE = "https://http-observatory.security.mozilla.org/api/v1"


async def observatory_scan(domain: str) -> dict:
    """
    Trigger an Observatory scan and poll for results.
    Max wait: 10 retries × 3s = 30s.
    """
    try:
        async with httpx.AsyncClient(timeout=8) as client:
            # Trigger scan (POST)
            r = await client.post(
                f"{_BASE}/analyze",
                params={"host": domain},
                data={"hidden": "true", "rescan": "false"},
            )
            if r.status_code not in (200, 201):
                return {"enriched": False, "reason": f"trigger_http_{r.status_code}"}

            data = r.json()

            # Poll until FINISHED - max 6 retries × 3s = 18s wait
            for _ in range(6):
                state = data.get("state", "")
                if state in ("FINISHED", "ABORTED", "FAILED"):
                    break
                await asyncio.sleep(3)
                r2 = await client.get(f"{_BASE}/analyze", params={"host": domain})
                if r2.status_code == 200:
                    data = r2.json()

            if data.get("state") != "FINISHED":
                return {
                    "enriched": False,
                    "reason": f"scan_state_{data.get('state', 'unknown')}",
                }

            # Fetch per-test results
            tests = {}
            scan_id = data.get("scan_id")
            if scan_id:
                try:
                    rt = await client.get(
                        f"{_BASE}/getScanResults",
                        params={"scan": scan_id},
                    )
                    if rt.status_code == 200:
                        for name, res in rt.json().items():
                            tests[name] = {
                                "pass": res.get("pass", False),
                                "score_modifier": res.get("score_modifier", 0),
                                "score_description": res.get("score_description", ""),
                            }
                except Exception:
                    pass

            return {
                "enriched": True,
                "grade": data.get("grade", "?"),
                "score": data.get("score", 0),
                "tests_passed": data.get("tests_passed", 0),
                "tests_failed": data.get("tests_failed", 0),
                "tests_quantity": data.get("tests_quantity", 0),
                "state": data.get("state"),
                "scan_id": scan_id,
                "tests": tests,
            }
    except Exception as e:
        return {"enriched": False, "reason": str(e)[:200]}
