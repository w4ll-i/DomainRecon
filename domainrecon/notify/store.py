# =============================================================================
# DomainRecon - Notifications : réglages des canaux et centre de notifications
# =============================================================================
# Réglages des canaux : une ligne par canal (table notify_channels). Les
# secrets (URL de webhook, identifiant et mot de passe SMTP) sont chiffrés comme
# les clés d'API (core/crypto.py) et ne sortent jamais en clair : la vue de
# l'API les masque. À l'écriture, un secret absent ou renvoyé masqué est
# conservé ; une chaîne vide l'efface.
# Centre de notifications : lecture, marquage « lu » et suppression des lignes
# de la table notifications.
# =============================================================================

import logging
import re
from urllib.parse import urlsplit

from sqlalchemy.orm import Session

from ..core.crypto import MASK, DecryptionError, decrypt, encrypt
from ..core.models import utcnow
from ..i18n import msg
from ..scanner.errors import message_exception
from .channels import CHANNELS, WEBHOOK_CHANNELS, Alert
from .models import Notification, NotifyChannel

logger = logging.getLogger(__name__)

# Champs secrets de chaque canal.
SECRET_KEYS = {
    "discord": ("url",),
    "slack": ("url",),
    "teams": ("url",),
    "webhook": ("url",),
    "email": ("username", "password"),
    "desktop": (),
}

MAX_URL_LENGTH = 2000
MAX_RECIPIENTS = 10
SECURITY_MODES = ("starttls", "ssl", "none")
DEFAULT_SMTP_PORT = {"starttls": 587, "ssl": 465, "none": 25}

_EMAIL_RE = re.compile(r"[^@\s<>,;]+@[^@\s<>,;]+\.[^@\s<>,;]+")
_HOST_RE = re.compile(r"[A-Za-z0-9._:-]{1,253}")


def _invalid(field: str) -> ValueError:
    return message_exception(ValueError, msg("notify.config_invalid", field=field))


def mask_url(url: str) -> str:
    """URL de webhook masquée : seuls le schéma et l'hôte restent visibles."""
    parts = urlsplit(url)
    return f"{parts.scheme}://{parts.hostname}/…" if parts.hostname else MASK


# =============================================================================
# Validation
# =============================================================================


def _clean_url(name: str, value: object) -> str:
    if not isinstance(value, str):
        raise _invalid("url")
    url = value.strip()
    parts = urlsplit(url)
    allowed = ("https", "http") if name == "webhook" else ("https",)
    if not url or len(url) > MAX_URL_LENGTH or parts.scheme not in allowed or not parts.hostname:
        raise _invalid("url")
    if parts.username or parts.password or any(c in url for c in " \r\n\t"):
        raise _invalid("url")
    return url


def _clean_email(config: dict) -> dict:
    host = config.get("host")
    if not isinstance(host, str) or not _HOST_RE.fullmatch(host.strip()):
        raise _invalid("host")
    security = config.get("security", "starttls")
    if security not in SECURITY_MODES:
        raise _invalid("security")
    port = config.get("port", DEFAULT_SMTP_PORT[security])
    if isinstance(port, bool) or not isinstance(port, int) or not 1 <= port <= 65535:
        raise _invalid("port")
    sender = config.get("sender")
    if not isinstance(sender, str) or not _EMAIL_RE.fullmatch(sender.strip()):
        raise _invalid("sender")
    recipients = config.get("recipients")
    if (
        not isinstance(recipients, list)
        or not 1 <= len(recipients) <= MAX_RECIPIENTS
        or not all(isinstance(r, str) and _EMAIL_RE.fullmatch(r.strip()) for r in recipients)
    ):
        raise _invalid("recipients")
    for secret in ("username", "password"):
        if not isinstance(config.get(secret, ""), str):
            raise _invalid(secret)
    return {
        "host": host.strip(),
        "port": port,
        "security": security,
        "sender": sender.strip(),
        "recipients": [r.strip() for r in recipients],
        "username": config.get("username", ""),
        "password": config.get("password", ""),
    }


def clean_config(name: str, config: object) -> dict:
    """Réglages d'un canal validés, secrets en clair ; ValueError (message traduisible) sinon."""
    if name not in CHANNELS:
        raise _invalid("channel")
    if not isinstance(config, dict):
        raise _invalid("config")
    if name in WEBHOOK_CHANNELS:
        return {"url": _clean_url(name, config.get("url"))}
    if name == "email":
        return _clean_email(config)
    return {}


# =============================================================================
# Stockage
# =============================================================================


def _decrypt_config(name: str, stored: dict) -> dict | None:
    """Réglages en clair ; None si un secret est illisible (fichier .secret_key différent)."""
    config = dict(stored)
    for key in SECRET_KEYS[name]:
        try:
            config[key] = decrypt(config.get(key))
        except DecryptionError:
            logger.warning("Réglage du canal %s illisible (fichier .secret_key différent ?)", name)
            return None
    return config


def load_channel(db: Session, name: str) -> tuple[bool, dict] | None:
    """(activé, réglages en clair) d'un canal, ou None s'il n'est pas configuré (ou illisible)."""
    row = db.get(NotifyChannel, name) if name in CHANNELS else None
    if row is None or not isinstance(row.config, dict):
        return None
    config = _decrypt_config(name, row.config)
    if config is None:
        return None
    return bool(row.enabled), config


def _complete(name: str, config: dict) -> bool:
    """Le canal a-t-il de quoi envoyer ? (le bureau n'a besoin de rien)."""
    if name == "desktop":
        return True
    if name in WEBHOOK_CHANNELS:
        return bool(config.get("url"))
    return bool(config.get("host") and config.get("sender") and config.get("recipients"))


def _view(name: str, row: NotifyChannel | None) -> dict:
    """Vue publique d'un canal : secrets masqués, jamais en clair."""
    config = _decrypt_config(name, row.config) if row is not None and isinstance(row.config, dict) else None
    if config is None:
        config = {}
    shown = {k: v for k, v in config.items() if k not in SECRET_KEYS[name]}
    if name in WEBHOOK_CHANNELS:
        shown["url"] = mask_url(config["url"]) if config.get("url") else ""
    elif name == "email":
        shown["username"] = MASK if config.get("username") else ""
        shown["password"] = MASK if config.get("password") else ""
    return {
        "name": name,
        "enabled": bool(row.enabled) if row is not None else False,
        "configured": row is not None and _complete(name, config),
        "config": shown,
    }


def channels_view(db: Session) -> list[dict]:
    rows = {row.name: row for row in db.query(NotifyChannel).all()}
    return [_view(name, rows.get(name)) for name in CHANNELS]


def _merge_secrets(name: str, new: dict, current: dict) -> dict:
    """Secrets absents ou renvoyés masqués : ceux déjà enregistrés. Chaîne vide : effacés."""
    merged = dict(new)
    for key in SECRET_KEYS[name]:
        value = new.get(key)
        if (
            value is None
            or value == MASK
            or (key == "url" and isinstance(value, str) and value.endswith("/…"))
        ):
            merged[key] = current.get(key, "")
    return merged


def save_channel(db: Session, name: str, enabled: bool, config: object) -> dict:
    """Enregistre un canal (secrets chiffrés) et renvoie sa vue. ValueError si les réglages sont invalides."""
    if name not in CHANNELS:
        raise _invalid("channel")
    row = db.get(NotifyChannel, name)
    current = _decrypt_config(name, row.config) if row is not None and isinstance(row.config, dict) else None
    merged = _merge_secrets(name, config if isinstance(config, dict) else {}, current or {})
    # Canal désactivé et vidé : rien à valider ni à conserver.
    cleaned = clean_config(name, merged) if enabled or any(merged.values()) else {}
    if enabled and not _complete(name, cleaned):
        raise _invalid("config")
    stored = dict(cleaned)
    for key in SECRET_KEYS[name]:
        if stored.get(key):
            stored[key] = encrypt(stored[key])
    if row is None:
        row = NotifyChannel(name=name)
        db.add(row)
    row.enabled = bool(enabled)
    row.config = stored
    row.updated_at = utcnow()
    db.commit()
    return _view(name, row)


def delete_channel(db: Session, name: str) -> bool:
    row = db.get(NotifyChannel, name) if name in CHANNELS else None
    if row is None:
        return False
    db.delete(row)
    db.commit()
    return True


# =============================================================================
# Centre de notifications
# =============================================================================


def add_notifications(
    db: Session, domain: str, scan_id: int | None, watch_id: int | None, alerts: list[Alert]
) -> list[int]:
    """Une ligne par alerte dans le centre ; renvoie leurs identifiants."""
    rows = [
        Notification(
            domain=domain,
            scan_id=scan_id,
            watch_id=watch_id,
            rule=alert.rule,
            severity=alert.severity,
            message=alert.message,
        )
        for alert in alerts
    ]
    db.add_all(rows)
    db.commit()
    return [row.id for row in rows]


def set_delivery(db: Session, ids: list[int], delivery: dict) -> None:
    if not ids:
        return
    db.query(Notification).filter(Notification.id.in_(ids)).update(
        {Notification.delivery: delivery}, synchronize_session=False
    )
    db.commit()
