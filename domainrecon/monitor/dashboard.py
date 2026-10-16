# =============================================================================
# DomainRecon - Surveillance : tableau de bord (un élément par domaine)
# =============================================================================
# Pour chaque domaine scanné : dernier scan (date, statut), note et score
# affichés, tendance des derniers scans, nombre de constats ouverts par
# gravité, surveillance éventuelle. Les totaux résument l'ensemble.
# =============================================================================

from sqlalchemy import func
from sqlalchemy.orm import Session, load_only

from ..api.schemas import iso_utc
from ..core.models import Scan
from ..scanner.rules import SEVERITIES
from .compare import scan_view
from .models import Watch
from .scorefmt import GRADES, display_score

# Nombre de scans de la tendance (les plus récents, en ordre chronologique).
TREND_POINTS = 10
# Nombre maximal de domaines renvoyés.
MAX_DOMAINS = 500


def _trend(db: Session, domain: str) -> list[dict]:
    rows = (
        db.query(Scan)
        .options(load_only(Scan.id, Scan.scan_timestamp, Scan.status, Scan.security_score))
        .filter(Scan.domain == domain)
        .order_by(Scan.scan_timestamp.desc(), Scan.id.desc())
        .limit(TREND_POINTS)
        .all()
    )
    points = []
    for row in reversed(rows):
        shown = display_score(row.security_score)
        points.append(
            {
                "scan_id": row.id,
                "timestamp": iso_utc(row.scan_timestamp),
                "status": row.status,
                "score": shown["score"],
                "grade": shown["grade"],
            }
        )
    return points


def _findings_count(scan: Scan) -> dict:
    counts = dict.fromkeys(SEVERITIES, 0)
    for finding in scan_view(scan)["findings"]:
        severity = finding.get("severity")
        if severity in counts:
            counts[severity] += 1
    counts["total"] = sum(counts.values())
    return counts


def _watch_info(watch: Watch | None) -> dict | None:
    if watch is None:
        return None
    return {
        "id": watch.id,
        "enabled": watch.enabled,
        "frequency": watch.frequency,
        "next_run_at": iso_utc(watch.next_run_at),
        "last_status": watch.last_status,
    }


def build_dashboard(db: Session, limit: int = MAX_DOMAINS) -> dict:
    """{domains: [...], totals: {...}} : un élément par domaine, du dernier scanné au plus ancien."""
    latest_ids = db.query(func.max(Scan.id)).group_by(Scan.domain).scalar_subquery()
    latest = (
        db.query(Scan)
        .filter(Scan.id.in_(latest_ids))
        .order_by(Scan.scan_timestamp.desc(), Scan.id.desc())
        .limit(limit)
        .all()
    )
    totals_domains = db.query(func.count(func.distinct(Scan.domain))).scalar() or 0
    watches = {w.domain: w for w in db.query(Watch).all()}
    counts = {
        domain: total for domain, total in db.query(Scan.domain, func.count(Scan.id)).group_by(Scan.domain)
    }

    items = []
    findings_total = dict.fromkeys(SEVERITIES, 0)
    grades = dict.fromkeys((*GRADES, "N/A"), 0)
    scores = []
    for scan in latest:
        shown = display_score(scan.security_score)
        findings = _findings_count(scan)
        for severity in SEVERITIES:
            findings_total[severity] += findings[severity]
        grades[shown["grade"]] += 1
        if shown["score"] is not None:
            scores.append(shown["score"])
        items.append(
            {
                "domain": scan.domain,
                "scan_id": scan.id,
                "scan_timestamp": iso_utc(scan.scan_timestamp),
                "status": scan.status,
                "grade": shown["grade"],
                "score": shown["score"],
                "coverage": shown["coverage"],
                "scans_count": counts.get(scan.domain, 1),
                "trend": _trend(db, scan.domain),
                "findings": findings,
                "watch": _watch_info(watches.get(scan.domain)),
            }
        )
    return {
        "domains": items,
        "totals": {
            "domains": totals_domains,
            "shown": len(items),
            "watched": sum(1 for w in watches.values() if w.enabled),
            "average_score": round(sum(scores) / len(scores), 1) if scores else None,
            "grades": grades,
            "findings": {**findings_total, "total": sum(findings_total.values())},
            "with_critical_or_high": sum(
                1 for item in items if item["findings"]["critical"] or item["findings"]["high"]
            ),
        },
    }
