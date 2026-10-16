# =============================================================================
# DomainRecon - Ligne de commande : domainrecon history
# =============================================================================

from __future__ import annotations

import argparse
import json

from ._common import add_lang, grade_of, open_storage, table


def register(subparsers) -> None:
    parser = subparsers.add_parser(
        "history",
        help="historique des scans",
        description="Liste les scans enregistrés, du plus récent au plus ancien.",
    )
    parser.add_argument("-n", "--limit", type=int, default=20, help="nombre de scans (défaut : 20)")
    parser.add_argument("--domain", help="filtre sur le domaine (texte contenu)")
    parser.add_argument(
        "--grade", type=str.upper, choices=("A", "B", "C", "D", "F", "N/A"), help="filtre sur la note"
    )
    parser.add_argument("--status", choices=("success", "partial", "error"), help="filtre sur le statut")
    parser.add_argument(
        "--format", choices=("text", "json"), default="text", help="présentation (défaut : text)"
    )
    add_lang(parser)
    parser.set_defaults(handler=run)


def _rows(args: argparse.Namespace) -> tuple[int, list[dict]]:
    from sqlalchemy.orm import load_only

    from ..api.routes.history import _grade_filter
    from ..core.database import SessionLocal
    from ..core.models import Scan

    with SessionLocal() as db:
        query = db.query(Scan)
        if args.domain and args.domain.strip():
            query = query.filter(Scan.domain.icontains(args.domain.strip(), autoescape=True))
        if args.grade:
            query = query.filter(_grade_filter(args.grade))
        if args.status:
            query = query.filter(Scan.status == args.status)
        total = query.count()
        scans = (
            query.options(
                load_only(Scan.domain, Scan.security_score, Scan.scan_timestamp, Scan.status, Scan.profile)
            )
            .order_by(Scan.scan_timestamp.desc(), Scan.id.desc())
            .limit(max(1, args.limit))
            .all()
        )
        rows = []
        for scan in scans:
            score = scan.security_score if isinstance(scan.security_score, dict) else {}
            value = score.get("score")
            rows.append(
                {
                    "id": scan.id,
                    "domain": scan.domain,
                    "timestamp": scan.scan_timestamp.strftime("%Y-%m-%d %H:%M")
                    if scan.scan_timestamp
                    else "",
                    "grade": grade_of({"security_score": score}),
                    "score": value
                    if isinstance(value, (int, float)) and not isinstance(value, bool)
                    else None,
                    "status": scan.status,
                    "profile": scan.profile,
                }
            )
    return total, rows


def run(args: argparse.Namespace) -> int:
    open_storage()
    total, rows = _rows(args)
    if args.format == "json":
        print(json.dumps({"total": total, "scans": rows}, ensure_ascii=False, indent=2))
        return 0
    if not rows:
        print("Aucun scan enregistré." if args.lang == "fr" else "No scan recorded.")
        return 0
    print(
        table(
            ("ID", "DATE (UTC)", "DOMAINE", "NOTE", "SCORE", "STATUT", "PROFIL"),
            [
                (
                    r["id"],
                    r["timestamp"],
                    r["domain"],
                    r["grade"],
                    "" if r["score"] is None else f"{r['score']:g}",
                    r["status"],
                    r["profile"] or "",
                )
                for r in rows
            ],
        )
    )
    if total > len(rows):
        print(f"\n{len(rows)} scan(s) affiché(s) sur {total} (voir --limit).")
    return 0
