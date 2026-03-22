# backend/app/scanners/nuclei_scanner.py
"""
Nuclei Scanner — run Project Discovery's nuclei against a domain and
parse JSON findings.
"""
import asyncio
import json
import re
import shutil


async def nuclei_scan(domain: str) -> dict:
    """
    Run nuclei against https://{domain} and return structured findings.

    Returns enriched=False when:
    - nuclei binary is not installed
    - subprocess raises an exception
    - scan times out after 120 s
    """
    if shutil.which("nuclei") is None:
        return {"enriched": False, "reason": "nuclei_not_installed"}

    # Arguments are passed as a list — no shell involved, no injection risk.
    cmd = [
        "nuclei",
        "-target", f"https://{domain}",
        "-tags", "osint,exposure,misconfig,cve,takeover",
        "-severity", "critical,high,medium",
        "-json",
        "-no-color",
        "-silent",
        "-timeout", "5",
        "-rate-limit", "50",
        "-c", "10",
    ]

    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        try:
            stdout_bytes, stderr_bytes = await asyncio.wait_for(
                proc.communicate(), timeout=120
            )
        except asyncio.TimeoutError:
            try:
                proc.kill()
            except Exception:
                pass
            return {"enriched": False, "error": "Nuclei timeout after 120s"}
    except Exception as e:
        return {"enriched": False, "error": str(e)}

    # Parse JSON findings — each stdout line is one JSON object
    findings = []
    for raw_line in stdout_bytes.splitlines():
        line = raw_line.strip()
        if not line:
            continue
        try:
            item = json.loads(line)
        except json.JSONDecodeError:
            continue

        info = item.get("info", {})
        findings.append({
            "template_id": item.get("template-id"),
            "name": info.get("name"),
            "severity": info.get("severity"),
            "description": info.get("description"),
            "matched_at": item.get("matched-at"),
            "tags": info.get("tags", []),
            "reference": info.get("reference", []),
        })

    # Count by severity
    critical_count = sum(1 for f in findings if f.get("severity") == "critical")
    high_count = sum(1 for f in findings if f.get("severity") == "high")
    medium_count = sum(1 for f in findings if f.get("severity") == "medium")

    # Try to extract templates_run count from stderr.
    # Nuclei typically prints something like "[INF] Templates loaded: 123"
    templates_run = None
    stderr_text = stderr_bytes.decode(errors="replace") if stderr_bytes else ""
    m = re.search(r"Templates(?:\s+\w+)*\s*:\s*(\d+)", stderr_text, re.IGNORECASE)
    if m:
        try:
            templates_run = int(m.group(1))
        except ValueError:
            templates_run = None

    return {
        "enriched": True,
        "findings": findings,
        "critical_count": critical_count,
        "high_count": high_count,
        "medium_count": medium_count,
        "total_count": len(findings),
        "templates_run": templates_run,
    }
