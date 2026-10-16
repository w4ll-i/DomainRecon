# =============================================================================
# DomainRecon - Surveillance : tables des surveillances et de leurs baux d'exécution
# =============================================================================
# Une surveillance = un domaine scanné à intervalle régulier (quotidien,
# hebdomadaire, mensuel), avec des règles d'alerte et des canaux de
# notification. `next_run_at` (UTC naïf, comme tous les horodatages de la base)
# est l'échéance du prochain scan ; `alert_state` mémorise les états déjà
# signalés pour n'alerter que sur un changement d'état. Le bail d'exécution
# (WatchLease, voir lease.py) empêche deux processus de scanner la même
# surveillance en même temps.
# =============================================================================

from sqlalchemy import JSON, Boolean, Column, DateTime, Integer, String

from ..core.database import Base
from ..core.models import utcnow


class Watch(Base):
    """Table des surveillances (un domaine par surveillance)."""

    __tablename__ = "watches"

    id = Column(Integer, primary_key=True)
    domain = Column(String(255), nullable=False, unique=True, index=True)
    profile = Column(String(16), nullable=False, default="complet")
    # Modules du profil « personnalise » ; NULL pour les autres profils.
    selected = Column(JSON, nullable=True)
    authorized_target = Column(Boolean, nullable=False, default=False)
    frequency = Column(String(16), nullable=False, default="daily")
    enabled = Column(Boolean, nullable=False, default=True, index=True)
    next_run_at = Column(DateTime, nullable=False, index=True)
    last_run_at = Column(DateTime, nullable=True)
    last_scan_id = Column(Integer, nullable=True)
    # Issue de la dernière exécution : done ou failed ; message traduisible en cas d'échec.
    last_status = Column(String(16), nullable=True)
    last_error = Column(JSON, nullable=True)
    # Règles d'alerte (voir alerts.AlertRules), canaux externes et langue des messages envoyés.
    rules = Column(JSON, nullable=False, default=dict)
    channels = Column(JSON, nullable=False, default=list)
    lang = Column(String(8), nullable=False, default="fr")
    # États déjà signalés (ex. {"cert_expiring": true}) : pas de répétition d'une alerte inchangée.
    alert_state = Column(JSON, nullable=False, default=dict)
    created_at = Column(DateTime, default=utcnow, nullable=False)

    def __repr__(self):
        return f"<Watch(id={self.id}, domain='{self.domain}', frequency='{self.frequency}')>"


class WatchLease(Base):
    """Bail d'exécution d'une surveillance : tant qu'il court, un seul processus la scanne.

    Une ligne par surveillance en cours d'exécution (lease.py). `holder` désigne
    l'exécution qui le tient, `expires_at` (UTC naïf) la date après laquelle un
    autre processus peut le reprendre, si le premier s'est arrêté sans le libérer.
    Pas de clé étrangère : SQLite ne les applique pas ici, la ligne est supprimée
    avec la surveillance (routes.py) ou expire d'elle-même.
    """

    __tablename__ = "watch_leases"

    watch_id = Column(Integer, primary_key=True, autoincrement=False)
    holder = Column(String(64), nullable=False)
    acquired_at = Column(DateTime, nullable=False)
    expires_at = Column(DateTime, nullable=False)

    def __repr__(self):
        return f"<WatchLease(watch_id={self.watch_id}, expires_at={self.expires_at})>"
