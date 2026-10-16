# =============================================================================
# DomainRecon - API : centre de notifications et canaux d'envoi
# =============================================================================
# GET    /api/notifications            liste (filtre « non lues »), total et non lues
# POST   /api/notifications/read       marque comme lues (ids, sinon toutes)
# DELETE /api/notifications/{id}       supprime une notification
# DELETE /api/notifications            supprime les notifications lues (ou toutes : all=true)
# GET    /api/notify/channels          réglages des canaux (secrets masqués)
# PUT    /api/notify/channels/{nom}    enregistre un canal (secrets chiffrés)
# DELETE /api/notify/channels/{nom}    supprime les réglages d'un canal
# POST   /api/notify/channels/{nom}/test   envoie un message d'essai (bouton « Tester »)
# Canaux : discord, slack, teams, webhook, email, desktop. Le centre de
# notifications reçoit toujours les alertes.
# =============================================================================

from typing import Annotated, Literal

import httpx
from fastapi import APIRouter, Depends, Query, Request
from fastapi import Path as PathParam
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import func
from sqlalchemy.orm import Session

from ..api.errors import ApiError, request_lang
from ..api.schemas import MAX_SCAN_ID, LangQuery, iso_utc
from ..api.security import require_json_body
from ..core.database import get_db
from ..i18n import msg, render
from ..scanner.errors import message_of
from . import dispatch, store
from .channels import CHANNELS
from .models import Notification

router = APIRouter(prefix="/api", tags=["Notifications"])

ChannelName = Annotated[Literal["discord", "slack", "teams", "webhook", "email", "desktop"], PathParam()]
NotificationId = Annotated[int, PathParam(ge=1, le=MAX_SCAN_ID)]


def get_notify_transport() -> httpx.AsyncBaseTransport | None:
    """Dépendance FastAPI : transport HTTP des envois (remplacé dans les tests ; None : réseau réel)."""
    return None


class ChannelUpdate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    enabled: bool = False
    config: dict = Field(default_factory=dict)


class ReadRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    ids: list[int] | None = Field(None, max_length=1000, description="Identifiants ; absent : toutes")


def _item(row: Notification) -> dict:
    return {
        "id": row.id,
        "created_at": iso_utc(row.created_at),
        "domain": row.domain,
        "scan_id": row.scan_id,
        "watch_id": row.watch_id,
        "rule": row.rule,
        "severity": row.severity,
        "message": row.message,
        "is_read": bool(row.is_read),
        "delivery": row.delivery or {},
    }


@router.get("/notifications")
def list_notifications(
    request: Request,
    unread_only: bool = False,
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0, le=MAX_SCAN_ID),
    lang: LangQuery = None,
    db: Session = Depends(get_db),
):
    """Notifications, de la plus récente à la plus ancienne."""
    query = db.query(Notification)
    if unread_only:
        query = query.filter(Notification.is_read.is_(False))
    total = query.count()
    rows = (
        query.order_by(Notification.created_at.desc(), Notification.id.desc())
        .offset(offset)
        .limit(limit)
        .all()
    )
    unread = db.query(func.count(Notification.id)).filter(Notification.is_read.is_(False)).scalar() or 0
    body = {"total": total, "unread": unread, "items": [_item(row) for row in rows]}
    return JSONResponse(render(body, request_lang(request)))


@router.post("/notifications/read", dependencies=[Depends(require_json_body)])
def mark_read(body: ReadRequest, db: Session = Depends(get_db)):
    """Marque des notifications (ou toutes) comme lues."""
    query = db.query(Notification).filter(Notification.is_read.is_(False))
    if body.ids is not None:
        query = query.filter(Notification.id.in_(body.ids))
    updated = query.update({Notification.is_read: True}, synchronize_session=False)
    db.commit()
    return {"updated": updated}


@router.delete("/notifications/{notification_id}")
def delete_notification(notification_id: NotificationId, db: Session = Depends(get_db)):
    row = db.get(Notification, notification_id)
    if row is None:
        raise ApiError(404, msg("notify.not_found"))
    db.delete(row)
    db.commit()
    return {"id": notification_id}


@router.delete("/notifications")
def clear_notifications(all: bool = False, db: Session = Depends(get_db)):
    """Supprime les notifications lues, ou toutes avec all=true."""
    query = db.query(Notification)
    if not all:
        query = query.filter(Notification.is_read.is_(True))
    deleted = query.delete(synchronize_session=False)
    db.commit()
    return {"deleted": deleted}


@router.get("/notify/channels")
def get_channels(db: Session = Depends(get_db)):
    """Réglages des canaux : secrets masqués, jamais en clair."""
    return {"channels": store.channels_view(db)}


@router.put("/notify/channels/{name}", dependencies=[Depends(require_json_body)])
def put_channel(name: ChannelName, body: ChannelUpdate, request: Request, db: Session = Depends(get_db)):
    """Enregistre un canal. Un secret absent (ou renvoyé masqué) est conservé, une chaîne vide l'efface."""
    try:
        return store.save_channel(db, name, body.enabled, body.config)
    except ValueError as e:
        raise ApiError(400, message_of(e) or msg("notify.config_invalid", field="config")) from e


@router.delete("/notify/channels/{name}")
def remove_channel(name: ChannelName, db: Session = Depends(get_db)):
    if not store.delete_channel(db, name):
        raise ApiError(404, msg("notify.channel_not_found"))
    return {"name": name}


@router.post("/notify/channels/{name}/test", dependencies=[Depends(require_json_body)])
async def test_channel(
    name: ChannelName,
    request: Request,
    transport: httpx.AsyncBaseTransport | None = Depends(get_notify_transport),
):
    """Envoie un message d'essai ; {ok, error} (l'échec d'un envoi n'est pas une erreur HTTP)."""
    lang = request_lang(request)
    result = await dispatch.send_test(name, lang, transport=transport)
    return JSONResponse(render(result, lang))


__all__ = ["CHANNELS", "router"]
