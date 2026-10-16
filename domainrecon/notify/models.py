# =============================================================================
# DomainRecon - Notifications : tables du centre de notifications et des canaux
# =============================================================================
# `notifications` : le centre de notifications de l'application (une ligne par
# alerte). `notify_channels` : la configuration des canaux externes (webhooks,
# e-mail, bureau) ; les secrets (URL de webhook, identifiants SMTP) y sont
# chiffrés comme les clés d'API (core/crypto.py).
# =============================================================================

from sqlalchemy import JSON, Boolean, Column, DateTime, Integer, String

from ..core.database import Base
from ..core.models import utcnow


class Notification(Base):
    """Une alerte du centre de notifications."""

    __tablename__ = "notifications"

    id = Column(Integer, primary_key=True)
    created_at = Column(DateTime, default=utcnow, nullable=False, index=True)
    domain = Column(String(255), nullable=False, index=True)
    scan_id = Column(Integer, nullable=True)
    watch_id = Column(Integer, nullable=True)
    # Règle d'alerte à l'origine (grade_drop, new_finding, cert_expiry, new_port,
    # new_subdomain, test) et gravité (critical, high, medium, low, info).
    rule = Column(String(40), nullable=False)
    severity = Column(String(16), nullable=False, default="info")
    # Message traduisible ({"$t": code, "p": params}), rendu à la lecture.
    message = Column(JSON, nullable=False)
    is_read = Column(Boolean, nullable=False, default=False, index=True)
    # Issue de l'envoi par canal : {canal: {"ok": bool, "error": message|None}}.
    delivery = Column(JSON, nullable=True)

    def __repr__(self):
        return f"<Notification(id={self.id}, domain='{self.domain}', rule='{self.rule}')>"


class NotifyChannel(Base):
    """Configuration d'un canal externe (une ligne par canal)."""

    __tablename__ = "notify_channels"

    name = Column(String(16), primary_key=True)
    enabled = Column(Boolean, nullable=False, default=False)
    # Réglages du canal ; les valeurs secrètes sont chiffrées (« enc:v1:… »).
    config = Column(JSON, nullable=False, default=dict)
    updated_at = Column(DateTime, default=utcnow, onupdate=utcnow, nullable=False)

    def __repr__(self):
        # Jamais la configuration : elle porte des secrets, même chiffrés.
        return f"<NotifyChannel(name='{self.name}', enabled={self.enabled})>"
