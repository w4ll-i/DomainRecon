# =============================================================================
# DomainRecon - Aides de test : surveillance, comparaison, tableau de bord, notifications
# =============================================================================
# Scans enregistrés directement en base (colonnes lues par les règles de constats),
# et remise à zéro des tables de la surveillance entre les tests.
# =============================================================================

import asyncio
import functools
from datetime import datetime, timedelta

from domainrecon.core import database
from domainrecon.core.models import Scan
from domainrecon.monitor.models import Watch, WatchLease
from domainrecon.notify.models import Notification, NotifyChannel

BASE_TIME = datetime(2026, 3, 1, 12, 0, 0)
OK = {"status": "ok", "error": None}
MODULES_MESURES = ("dns_records", "subdomains", "open_ports", "tls_certificate", "technologies")


def reset_tables() -> None:
    """Vide les tables de la surveillance (baux compris), des notifications et des scans."""
    database.Base.metadata.create_all(bind=database.engine)
    with database.SessionLocal() as db:
        for model in (Watch, WatchLease, Notification, NotifyChannel, Scan):
            db.query(model).delete()
        db.commit()


def add_scan(
    domain: str = "exemple.test",
    *,
    minutes: int = 0,
    grade: str = "A",
    score: float | None = 95,
    coverage: int = 100,
    ports: tuple[int, ...] = (),
    subdomains: tuple[str, ...] = (),
    cert_days: int | None = 90,
    cert_valid: bool = True,
    cert_serial: str = "01",
    technologies: tuple[str, ...] = (),
    dns: dict | None = None,
    status: str = "success",
    measured: tuple[str, ...] = MODULES_MESURES,
) -> int:
    """Enregistre un scan et renvoie son identifiant (`minutes` : décalage depuis BASE_TIME)."""
    values = {
        "domain": domain,
        "status": status,
        "scan_timestamp": BASE_TIME + timedelta(minutes=minutes),
        "security_score": {
            "score": score,
            "max_score": 100,
            "grade": grade,
            "coverage": coverage,
            "measured_max": 100,
            "breakdown": {},
        },
        "module_status": {name: dict(OK) for name in measured},
        "ip_address": "93.184.216.34",
        "dns_records": dns if dns is not None else {"A": ["93.184.216.34"], "measured": True},
        "open_ports": [{"port": p, "state": "open", "service": "svc"} for p in ports],
        "subdomains": [{"subdomain": n, "ip": None, "resolution": "unresolved"} for n in subdomains],
        "tls_certificate": {
            "measured": True,
            "https": True,
            "valid": cert_valid,
            "subject": domain,
            "issuer_org": "Autorité",
            "issuer_cn": "Autorité CA",
            "serial_number": cert_serial,
            "not_before": "Jan  1 00:00:00 2026 GMT",
            "not_after": "Jun  1 00:00:00 2026 GMT",
            "days_remaining": cert_days,
        },
        "technologies": [{"name": name, "category": "web"} for name in technologies],
    }
    with database.SessionLocal() as db:
        scan = Scan(**values)
        db.add(scan)
        db.commit()
        return scan.id


def add_watch(domain: str = "exemple.test", **values) -> int:
    """Enregistre une surveillance (échue à BASE_TIME par défaut) et renvoie son identifiant."""
    fields = {
        "domain": domain,
        "profile": "rapide",
        "frequency": "daily",
        "next_run_at": BASE_TIME,
        "rules": {},
        "channels": [],
        "alert_state": {},
        **values,
    }
    with database.SessionLocal() as db:
        watch = Watch(**fields)
        db.add(watch)
        db.commit()
        return watch.id


def read_watch(watch_id: int) -> Watch:
    with database.SessionLocal() as db:
        watch = db.get(Watch, watch_id)
        db.expunge(watch)
        return watch


def asynchrone(func):
    """Exécute un test `async def` dans sa propre boucle d'événements (pas de greffon asyncio)."""

    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        return asyncio.run(func(*args, **kwargs))

    return wrapper
