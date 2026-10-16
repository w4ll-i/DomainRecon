# =============================================================================
# DomainRecon - API : historique des scans et timeline d'un domaine
# =============================================================================

import json

from fastapi import APIRouter, Depends, Query, Request
from fastapi.responses import JSONResponse
from sqlalchemy import and_, func, not_, or_
from sqlalchemy.orm import Session, load_only

from ...core.database import get_db
from ...core.models import Scan
from ...i18n import msg, render
from ...scanner import DNS_RECORD_TYPES, is_valid_target, normalize_target, site_domain
from ...scanner.score import MIN_GRADED_COVERAGE
from ..errors import ApiError, request_lang
from ..schemas import (
    MAX_SCAN_ID,
    DnsChange,
    GradeFilter,
    HistoryResponse,
    LangQuery,
    RelatedDomain,
    ScanSummary,
    StatusFilter,
    TimelineEntry,
    TimelineResponse,
)

router = APIRouter(prefix="/api", tags=["API"])

# Clés de `dns_records` comparées par la timeline : les types d'enregistrement
# (en majuscules). Les clés en minuscules (measured, error, errors,
# dmarc_source, nxdomain, wildcard, notes) sont des métadonnées.
_DNS_TIMELINE_TYPES = (*DNS_RECORD_TYPES, "DMARC")

_SUMMARY_COLUMNS = (
    Scan.domain,
    Scan.ip_address,
    Scan.subdomains,
    Scan.open_ports,
    Scan.module_status,
    Scan.modules_launched,
    Scan.security_score,
    Scan.tags,
    Scan.scan_timestamp,
    Scan.status,
)

_TIMELINE_COLUMNS = (
    Scan.scan_timestamp,
    Scan.status,
    Scan.ip_address,
    Scan.dns_records,
    Scan.module_status,
    Scan.modules_launched,
    Scan.subdomains,
    Scan.open_ports,
    Scan.security_score,
)

RELATED_DOMAINS_LIMIT = 10

# Scans antérieurs à la fenêtre de la timeline, lus en plus : le plus récent
# dont le relevé DNS a réussi sert de référence au premier scan affiché.
TIMELINE_REFERENCE_ROWS = 10


def _count(value) -> int:
    return len(value) if isinstance(value, list) else 0


def _launched_modules(scan: Scan) -> set[str] | None:
    """Modules que le scan déclare avoir lancés, ou None si la liste est inconnue.

    Lecture directe de l'attribut ORM (score.launched_modules attend un dict) :
    `modules_launched` réuni à `module_status`, dont un statut prouve que le
    module a tourné. None (scan d'avant les profils, ou lancé sans profil) :
    on ne sait pas quels modules ont tourné.
    """
    declared = scan.modules_launched
    if not isinstance(declared, (list, tuple)):
        return None
    status = scan.module_status if isinstance(scan.module_status, dict) else {}
    return {name for name in (*declared, *status) if isinstance(name, str)}


def _module_count(scan: Scan, module: str) -> int | None:
    """Taille de la liste d'un module (colonne du même nom), ou None s'il n'a rien mesuré.

    Un module en échec, hors délai ou sans objet enregistre une liste vide
    qui ne signifie pas « rien trouvé ». Il en va de même d'un module non
    lancé (profil rapide, sélection personnalisée) : None, pas 0. Scan
    antérieur à module_status et à modules_launched : la liste est comptée
    telle quelle.
    """
    launched = _launched_modules(scan)
    if launched is not None and module not in launched:
        return None
    status = scan.module_status.get(module) if isinstance(scan.module_status, dict) else None
    if isinstance(status, dict) and status.get("status") not in (None, "ok"):
        return None
    count = _count(getattr(scan, module))
    # Liste plafonnée (sous-domaines) : le total trouvé, pas la taille enregistrée.
    total = _number(status.get("total_found")) if isinstance(status, dict) else None
    return max(count, int(total)) if total is not None else count


def _number(value) -> int | float | None:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    return value


def _scan_to_summary(scan: Scan) -> ScanSummary:
    """Vue allégée d'un scan pour les listes."""
    return ScanSummary(
        id=scan.id,
        domain=scan.domain,
        ip_address=scan.ip_address,
        subdomains_count=_module_count(scan, "subdomains"),
        open_ports_count=_module_count(scan, "open_ports"),
        security_score=scan.security_score,
        tags=scan.tags,
        scan_timestamp=scan.scan_timestamp,
        status=scan.status,
    )


def _record_key(value) -> str:
    """Clé de comparaison d'un enregistrement DNS.

    Le numéro de série SOA change à chaque modification de la zone : il est
    ignoré pour ne signaler que les vrais changements (serveur, contact…).
    """
    if isinstance(value, dict):
        value = {k: v for k, v in value.items() if k != "serial"}
    return json.dumps(value, sort_keys=True, default=str)


def _dns_snapshot(scan: Scan) -> dict[str, list] | None:
    """Enregistrements DNS exploitables d'un scan, ou None si la mesure a échoué.

    Un type dont la requête a échoué (`errors`) est écarté : sa liste vide ne
    signifie pas que les enregistrements ont disparu.
    """
    status = scan.module_status.get("dns_records") if isinstance(scan.module_status, dict) else None
    if isinstance(status, dict) and status.get("status") not in (None, "ok"):
        return None
    records = scan.dns_records
    if not isinstance(records, dict) or not records or records.get("measured") is False:
        return None
    failed = records.get("errors") if isinstance(records.get("errors"), dict) else {}
    return {
        rtype: records[rtype]
        for rtype in _DNS_TIMELINE_TYPES
        if isinstance(records.get(rtype), list) and rtype not in failed
    }


def _dns_changes(previous: dict | None, current: dict | None) -> dict[str, DnsChange] | None:
    """Différences par type d'enregistrement entre deux relevés DNS."""
    if previous is None or current is None:
        return None
    changes: dict[str, DnsChange] = {}
    # Seuls les types relevés les deux fois : un type nouvellement collecté
    # n'est pas un changement du domaine.
    for rtype in sorted(set(previous) & set(current)):
        before = {_record_key(v): v for v in previous[rtype]}
        after = {_record_key(v): v for v in current[rtype]}
        added = [v for key, v in after.items() if key not in before]
        removed = [v for key, v in before.items() if key not in after]
        if added or removed:
            changes[rtype] = DnsChange(added=added, removed=removed)
    return changes


def _timeline_entry(scan: Scan, dns_changes: dict[str, DnsChange] | None) -> TimelineEntry:
    score = scan.security_score if isinstance(scan.security_score, dict) else {}
    grade = score.get("grade")
    coverage = _number(score.get("coverage"))
    measured_max = _number(score.get("measured_max"))
    version = score.get("version")
    # Règle complète de l'Historique (frontend lib/score.ts, scoreView) : un
    # score transmis est toujours un score affiché. Note valable (couverture
    # d'au moins MIN_GRADED_COVERAGE) : score gardé ; sinon (note N/A, ou
    # ancien scan noté sous ce seuil), gardé seulement s'il est indicatif,
    # c'est-à-dire calculé sur des critères comptés (measured_max > 0).
    # Couverture nulle : jamais de score.
    low = coverage is not None and coverage < MIN_GRADED_COVERAGE
    measured = coverage != 0 and (
        (grade != "N/A" and not low) or (measured_max is not None and measured_max > 0)
    )
    return TimelineEntry(
        scan_id=scan.id,
        timestamp=scan.scan_timestamp,
        status=scan.status,
        ip_address=scan.ip_address,
        subdomains_count=_module_count(scan, "subdomains"),
        open_ports_count=_module_count(scan, "open_ports"),
        security_score=_number(score.get("score")) if measured else None,
        grade=grade if isinstance(grade, str) else None,
        coverage=coverage,
        measured_max=measured_max,
        score_version=version if isinstance(version, int) and not isinstance(version, bool) else None,
        dns_changes=dns_changes,
    )


def _related_domains(db: Session, target: str, site: str) -> list[RelatedDomain]:
    """Autres cibles scannées du même site (voir scanner.site_domain).

    Le filtre SQL (le site et ses sous-domaines) est affiné ensuite : sous le
    domaine d'une plateforme mutualisée (github.io), les sites de ses
    utilisateurs (alice.github.io) sont distincts, pas des cibles liées.
    """
    count = func.count(Scan.id)
    rows = (
        db.query(Scan.domain, count)
        .filter(
            Scan.domain != target,
            or_(Scan.domain == site, Scan.domain.endswith("." + site, autoescape=True)),
        )
        .group_by(Scan.domain)
        .order_by(count.desc(), Scan.domain)
        .all()
    )
    related = [
        RelatedDomain(domain=domain, total_scans=total)
        for domain, total in rows
        if site_domain(domain) == site
    ]
    return related[:RELATED_DOMAINS_LIMIT]


GRADES = ("A", "B", "C", "D", "F")


def _grade_filter(grade: str):
    """Note affichée (displayGrade du frontend) : une note A à F stockée sans
    score, ou sur une couverture inférieure à MIN_GRADED_COVERAGE (scans notés
    avant cette règle), s'affiche N/A et doit être filtrée comme telle.

    Colonne JSON lue dans security_score (SQLite comme PostgreSQL).
    """
    stored = Scan.security_score["grade"].as_string()
    coverage = Scan.security_score["coverage"].as_float()
    graded = and_(
        stored.in_(GRADES),
        Scan.security_score["score"].as_float().is_not(None),
        or_(coverage.is_(None), coverage >= MIN_GRADED_COVERAGE),
    )
    if grade == "N/A":
        return or_(Scan.security_score.is_(None), stored.is_(None), not_(graded))
    return and_(stored == grade, graded)


@router.get("/history", response_model=HistoryResponse)
def get_scan_history(
    request: Request,
    limit: int = Query(10, ge=1, le=200),
    offset: int = Query(0, ge=0, le=MAX_SCAN_ID),
    domain: str | None = Query(None, max_length=255),
    grade: GradeFilter | None = Query(None, description="Grade du score : A à F, ou N/A"),
    status: StatusFilter | None = Query(None, description="Statut du scan"),
    lang: LangQuery = None,
    db: Session = Depends(get_db),
):
    """Historique des scans, du plus récent au plus ancien, filtrable par domaine, note et statut."""
    query = db.query(Scan)
    needle = (domain or "").strip()
    if needle:
        # autoescape : % et _ saisis sont cherchés littéralement ; insensible
        # à la casse sous SQLite comme sous PostgreSQL.
        query = query.filter(Scan.domain.icontains(needle, autoescape=True))
    if grade is not None:
        query = query.filter(_grade_filter(grade))
    if status is not None:
        query = query.filter(Scan.status == status)

    total = query.count()
    scans = (
        query.options(load_only(*_SUMMARY_COLUMNS))
        .order_by(Scan.scan_timestamp.desc(), Scan.id.desc())
        .offset(offset)
        .limit(limit)
        .all()
    )
    response = HistoryResponse(total=total, scans=[_scan_to_summary(s) for s in scans])
    return JSONResponse(render(response.model_dump(mode="json"), request_lang(request)))


@router.get("/dns-timeline/{domain}", response_model=TimelineResponse)
def get_dns_timeline(
    domain: str,
    limit: int = Query(100, ge=1, le=500),
    db: Session = Depends(get_db),
):
    """Évolution d'un domaine à travers ses scans (les `limit` plus récents, en ordre chronologique)."""
    target = normalize_target(domain)
    if not target or not is_valid_target(target):
        raise ApiError(400, msg("api.invalid_domain"))

    query = db.query(Scan).filter(Scan.domain == target)
    total = query.count()
    if not total:
        raise ApiError(404, msg("api.no_scan_for_domain"))

    # Quelques scans de plus que demandé, non affichés : le plus récent dont le
    # relevé DNS a réussi sert de référence aux changements DNS du premier
    # scan affiché (un relevé en échec est sauté, comme dans la fenêtre).
    rows = (
        query.options(load_only(*_TIMELINE_COLUMNS))
        .order_by(Scan.scan_timestamp.desc(), Scan.id.desc())
        .limit(limit + TIMELINE_REFERENCE_ROWS)
        .all()
    )
    rows.reverse()
    first_shown = max(0, len(rows) - limit)

    timeline: list[TimelineEntry] = []
    previous_dns = None
    for position, scan in enumerate(rows):
        dns = _dns_snapshot(scan)
        changes = _dns_changes(previous_dns, dns)
        if dns is not None:
            previous_dns = dns
        if position >= first_shown:
            timeline.append(_timeline_entry(scan, changes))

    # Site plutôt que domaine enregistrable : bob.github.io n'est pas lié à alice.github.io.
    site = site_domain(target)
    return TimelineResponse(
        domain=target,
        apex=site,
        total_scans=total,
        timeline=timeline,
        related_domains=_related_domains(db, target, site),
    )
