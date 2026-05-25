# backend/app/routers/scans.py
"""Scan endpoints - POST /scan, /history, /scan/{id}, bulk, diff, WebSocket."""

import asyncio
import logging
import traceback
from datetime import datetime, timezone
from typing import Optional

from fastapi import (
    APIRouter, Depends, HTTPException,
    WebSocket, WebSocketDisconnect,
)
from sqlalchemy.orm import Session

from ..database import SessionLocal, get_db
from ..helpers import (
    build_scan_kwargs, extract_list,
    get_or_create_settings, scan_to_response,
    settings_to_scan_config, timeout_for_profile,
)
from ..models import Scan
from ..scanner import run_scan
from ..schemas import (
    BulkScanRequest, HistoryResponse, ScanRequest,
    ScanResponse, TagsNotesRequest,
)

logger = logging.getLogger("domainrecon")
router = APIRouter(prefix="/api", tags=["Scans"])


# ─── POST /scan ──────────────────────────────────────────────────────────────

@router.post("/scan", response_model=ScanResponse)
async def scan_domain(request: ScanRequest, db: Session = Depends(get_db)):
    """Run a full/quick domain scan and persist the result."""
    try:
        s = get_or_create_settings(db)
        settings = settings_to_scan_config(s)
        timeout = timeout_for_profile(s, request.profile)

        try:
            result = await run_scan(request.domain, request.profile, settings, timeout)
        except asyncio.TimeoutError:
            raise HTTPException(status_code=504, detail="Le scan a pris trop de temps et a dépassé le délai autorisé.")

        db_scan = Scan(
            domain=request.domain,
            scan_profile=request.profile,
            scan_timestamp=datetime.now(timezone.utc),
            status="success",
            **build_scan_kwargs(result),
        )
        db.add(db_scan)
        db.commit()
        db.refresh(db_scan)
        return scan_to_response(db_scan)

    except HTTPException:
        db.rollback()
        raise
    except Exception as e:
        db.rollback()
        logger.error("SCAN ERROR [%s]: %s\n%s", request.domain, e, traceback.format_exc())
        raise HTTPException(status_code=500, detail=str(e))


# ─── History / single scan / delete ──────────────────────────────────────────

@router.get("/history", response_model=HistoryResponse)
async def get_scan_history(
    limit: int = 10,
    offset: int = 0,
    domain: Optional[str] = None,
    db: Session = Depends(get_db),
):
    """Paginated scan history with optional domain filter."""
    query = db.query(Scan)
    if domain:
        query = query.filter(Scan.domain.contains(domain))
    total = query.count()
    scans = query.order_by(Scan.scan_timestamp.desc()).offset(offset).limit(limit).all()
    return HistoryResponse(total=total, scans=[scan_to_response(s) for s in scans])


@router.get("/scan/{scan_id}", response_model=ScanResponse)
async def get_scan_by_id(scan_id: int, db: Session = Depends(get_db)):
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan non trouvé")
    return scan_to_response(scan)


@router.delete("/scan/{scan_id}")
async def delete_scan(scan_id: int, db: Session = Depends(get_db)):
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan non trouvé")
    db.delete(scan)
    db.commit()
    return {"message": "Scan supprimé", "id": scan_id}


@router.patch("/scan/{scan_id}/meta")
async def update_scan_meta(scan_id: int, request: TagsNotesRequest, db: Session = Depends(get_db)):
    """Update tags and notes on a scan."""
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan non trouvé")
    if request.tags is not None:
        scan.tags = request.tags
    if request.notes is not None:
        scan.notes = request.notes
    db.commit()
    db.refresh(scan)
    return scan_to_response(scan)


# ─── DNS timeline ────────────────────────────────────────────────────────────

@router.get("/dns-timeline/{domain}")
async def get_dns_timeline(domain: str, db: Session = Depends(get_db)):
    """Return DNS history for a domain across its scans."""
    scans = (
        db.query(Scan)
        .filter(Scan.domain == domain)
        .order_by(Scan.scan_timestamp.asc())
        .all()
    )
    if not scans:
        raise HTTPException(status_code=404, detail="Aucun scan trouvé pour ce domaine")

    timeline = [
        {
            "scan_id": s.id,
            "timestamp": s.scan_timestamp.isoformat(),
            "ip_address": s.ip_address,
            "dns_records": s.dns_records or {},
            "subdomains_count": len(extract_list(s.subdomains, "subdomains")),
            "open_ports_count": len(extract_list(s.open_ports, "open_ports")),
            "security_score": (s.security_score or {}).get("score") or (s.security_score or {}).get("total"),
        }
        for s in scans
    ]
    return {"domain": domain, "total_scans": len(timeline), "timeline": timeline}


# ─── Bulk scan ───────────────────────────────────────────────────────────────

def _clean_domain(raw: str) -> str:
    """Strip protocol + path from a user-provided domain string."""
    d = raw.strip().lower()
    for prefix in ("https://", "http://"):
        if d.startswith(prefix):
            d = d[len(prefix):]
    return d.split("/", 1)[0]


@router.post("/scan/bulk")
async def bulk_scan(request: BulkScanRequest, db: Session = Depends(get_db)):
    """Sequentially scan up to 20 domains."""
    s = get_or_create_settings(db)
    settings = settings_to_scan_config(s)
    settings["screenshot_enabled"] = False  # never capture during bulk
    timeout = getattr(s, "quick_timeout", None) or 60

    results = []
    for raw in request.domains:
        domain = _clean_domain(raw)
        if not domain:
            continue
        try:
            result = await run_scan(domain, request.profile, settings, timeout)
            db_scan = Scan(
                domain=domain,
                scan_profile=request.profile,
                scan_timestamp=datetime.now(timezone.utc),
                status="success",
                **build_scan_kwargs(result),
            )
            # bulk scans never capture screenshots
            db_scan.screenshot_path = None
            db.add(db_scan)
            db.commit()
            db.refresh(db_scan)
            results.append({
                "domain": domain,
                "scan_id": db_scan.id,
                "status": "success",
                "score": (result.get("security_score") or {}).get("score") or (result.get("security_score") or {}).get("total"),
                "ip": result.get("ip_address"),
            })
        except Exception as e:
            db.rollback()
            logger.error("BULK SCAN ERROR [%s]: %s", domain, e)
            results.append({"domain": domain, "scan_id": None, "status": "error", "error": str(e)[:200]})

    return {"total": len(results), "results": results}


# ─── Diff ────────────────────────────────────────────────────────────────────

@router.get("/scan/{scan_id}/diff/{other_id}")
async def diff_scans(scan_id: int, other_id: int, db: Session = Depends(get_db)):
    """Compare two scans of the same domain and return changes."""
    s1 = db.query(Scan).filter(Scan.id == scan_id).first()
    s2 = db.query(Scan).filter(Scan.id == other_id).first()
    if not s1 or not s2:
        raise HTTPException(status_code=404, detail="Scan non trouvé")

    def _list_diff(a, b):
        sa, sb = set(a or []), set(b or [])
        return {"added": sorted(sb - sa), "removed": sorted(sa - sb), "unchanged": len(sa & sb)}

    subs1 = set(extract_list(s1.subdomains, "subdomains"))
    subs2 = set(extract_list(s2.subdomains, "subdomains"))

    ports1 = {p["port"] for p in (s1.open_ports or []) if isinstance(p, dict)} if isinstance(s1.open_ports, list) else set()
    ports2 = {p["port"] for p in (s2.open_ports or []) if isinstance(p, dict)} if isinstance(s2.open_ports, list) else set()

    sh1 = set((s1.security_headers or {}).get("headers_found", {}).keys())
    sh2 = set((s2.security_headers or {}).get("headers_found", {}).keys())

    score1 = (s1.security_score or {}).get("score") or (s1.security_score or {}).get("total")
    score2 = (s2.security_score or {}).get("score") or (s2.security_score or {}).get("total")
    score_delta = (score2 - score1) if (score1 is not None and score2 is not None) else None

    changes = []
    if s1.ip_address != s2.ip_address:
        changes.append({"type": "ip_change", "severity": "high",
                        "old": s1.ip_address, "new": s2.ip_address,
                        "message": f"IP changed: {s1.ip_address} → {s2.ip_address}"})
    if subs2 - subs1:
        changes.append({"type": "new_subdomains", "severity": "medium",
                        "items": sorted(subs2 - subs1),
                        "message": f"{len(subs2 - subs1)} new subdomain(s) discovered"})
    if subs1 - subs2:
        changes.append({"type": "removed_subdomains", "severity": "low",
                        "items": sorted(subs1 - subs2),
                        "message": f"{len(subs1 - subs2)} subdomain(s) no longer found"})
    if ports2 - ports1:
        changes.append({"type": "new_ports", "severity": "high",
                        "items": sorted(ports2 - ports1),
                        "message": f"New open port(s): {sorted(ports2 - ports1)}"})
    if ports1 - ports2:
        changes.append({"type": "closed_ports", "severity": "info",
                        "items": sorted(ports1 - ports2),
                        "message": f"Port(s) no longer open: {sorted(ports1 - ports2)}"})
    if sh1 - sh2:
        changes.append({"type": "headers_removed", "severity": "medium",
                        "items": sorted(sh1 - sh2),
                        "message": f"Security header(s) removed: {', '.join(sorted(sh1 - sh2))}"})
    if sh2 - sh1:
        changes.append({"type": "headers_added", "severity": "info",
                        "items": sorted(sh2 - sh1),
                        "message": f"Security header(s) added: {', '.join(sorted(sh2 - sh1))}"})
    if score_delta is not None and abs(score_delta) >= 5:
        sev = "high" if score_delta < -10 else "medium" if score_delta < 0 else "info"
        changes.append({"type": "score_change", "severity": sev,
                        "old": score1, "new": score2, "delta": score_delta,
                        "message": f"Security score: {score1} → {score2} ({score_delta:+d})"})

    tls1 = s1.tls_certificate or {}
    tls2 = s2.tls_certificate or {}
    if tls1.get("issuer_org") != tls2.get("issuer_org") and tls2.get("issuer_org"):
        changes.append({"type": "cert_issuer_change", "severity": "medium",
                        "old": tls1.get("issuer_org"), "new": tls2.get("issuer_org"),
                        "message": f"TLS cert issuer changed: {tls1.get('issuer_org')} → {tls2.get('issuer_org')}"})

    return {
        "scan_a": {"id": s1.id, "domain": s1.domain, "timestamp": s1.scan_timestamp.isoformat()},
        "scan_b": {"id": s2.id, "domain": s2.domain, "timestamp": s2.scan_timestamp.isoformat()},
        "changes": changes,
        "change_count": len(changes),
        "critical_changes": sum(1 for c in changes if c["severity"] in ("high", "critical")),
        "summary": {
            "ip": {"a": s1.ip_address, "b": s2.ip_address},
            "subdomains": {"a": len(subs1), "b": len(subs2), "diff": _list_diff(subs1, subs2)},
            "ports": {"a": sorted(ports1), "b": sorted(ports2)},
            "score": {"a": score1, "b": score2, "delta": score_delta},
        },
    }


# ─── WebSocket - live progress ───────────────────────────────────────────────

# Mounted at /api/ws/scan by main.py (WebSockets aren't declared through APIRouter.*ws).
async def websocket_scan(ws: WebSocket):
    """WebSocket endpoint: client sends {domain, profile}, receives progress events."""
    await ws.accept()
    try:
        data = await asyncio.wait_for(ws.receive_json(), timeout=30)
        domain = (data.get("domain") or "").strip().lower()
        profile = data.get("profile", "full")
        if not domain or profile not in ("quick", "full"):
            await ws.send_json({"type": "error", "message": "Paramètres invalides (domain + profile requis)"})
            return

        # Load settings (sync ORM query - use a fresh session, close ASAP).
        db = SessionLocal()
        try:
            s = get_or_create_settings(db)
            settings = settings_to_scan_config(s)
            timeout = timeout_for_profile(s, profile)
        finally:
            db.close()

        await ws.send_json({"type": "started", "domain": domain, "profile": profile})

        async def progress_cb(event: dict):
            try:
                await ws.send_json({"type": "progress", **event})
            except Exception:
                pass

        result = await run_scan(domain, profile, settings, timeout, progress_cb=progress_cb)

        db2 = SessionLocal()
        scan_id = None
        try:
            db_scan = Scan(
                domain=domain,
                scan_profile=profile,
                scan_timestamp=datetime.now(timezone.utc),
                status="success",
                **build_scan_kwargs(result),
            )
            db2.add(db_scan)
            db2.commit()
            db2.refresh(db_scan)
            scan_id = db_scan.id
        except Exception as e:
            db2.rollback()
            logger.error("WS SCAN DB ERROR: %s", e)
        finally:
            db2.close()

        await ws.send_json({"type": "complete", "scan_id": scan_id, "domain": domain})

    except asyncio.TimeoutError:
        await ws.send_json({"type": "error", "message": "Timeout - aucune donnée reçue"})
    except WebSocketDisconnect:
        pass
    except Exception as e:
        logger.error("WS SCAN ERROR: %s\n%s", e, traceback.format_exc())
        try:
            await ws.send_json({"type": "error", "message": str(e)[:200]})
        except Exception:
            pass
