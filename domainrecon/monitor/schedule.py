# =============================================================================
# DomainRecon - Surveillance : fréquences et échéances
# =============================================================================
# Les échéances sont des horodatages UTC naïfs, comme toute la base. Une
# échéance se « réserve » avant le scan (claim) par une mise à jour conditionnelle :
# si l'application et la tâche système (`domainrecon monitor run-due`) se
# déclenchent en même temps, un seul des deux lance le scan. La réservation ne
# vaut que pour une même échéance : le bail d'exécution (lease.py) empêche en
# plus de relancer une surveillance dont le scan tourne encore.
# =============================================================================

import calendar
from datetime import datetime, timedelta

from sqlalchemy.orm import Session

from .models import Watch

FREQUENCIES = ("daily", "weekly", "monthly")

# Délai avant une nouvelle tentative quand un scan surveillé échoue.
RETRY_DELAY = timedelta(hours=1)


def add_months(value: datetime, months: int) -> datetime:
    """`value` plus `months` mois ; le jour est ramené au dernier jour du mois d'arrivée si besoin (31 janvier -> 28 février)."""
    index = value.month - 1 + months
    year, month = value.year + index // 12, index % 12 + 1
    day = min(value.day, calendar.monthrange(year, month)[1])
    return value.replace(year=year, month=month, day=day)


def next_run(frequency: str, after: datetime) -> datetime:
    """Prochaine échéance après `after` pour une fréquence (ValueError si elle est inconnue)."""
    if frequency == "daily":
        return after + timedelta(days=1)
    if frequency == "weekly":
        return after + timedelta(days=7)
    if frequency == "monthly":
        return add_months(after, 1)
    raise ValueError(f"fréquence inconnue : {frequency!r}")


def list_due(db: Session, now: datetime) -> list[tuple[int, datetime]]:
    """(identifiant, échéance) des surveillances actives échues à `now`, les plus en retard d'abord."""
    rows = (
        db.query(Watch.id, Watch.next_run_at)
        .filter(Watch.enabled.is_(True), Watch.next_run_at <= now)
        .order_by(Watch.next_run_at, Watch.id)
        .all()
    )
    return [(row.id, row.next_run_at) for row in rows]


def claim(db: Session, watch_id: int, expected: datetime, new_next: datetime) -> bool:
    """Réserve l'échéance : vrai si elle valait encore `expected` (et la surveillance est active)."""
    updated = (
        db.query(Watch)
        .filter(Watch.id == watch_id, Watch.enabled.is_(True), Watch.next_run_at == expected)
        .update({Watch.next_run_at: new_next}, synchronize_session=False)
    )
    db.commit()
    return updated == 1
