# =============================================================================
# DomainRecon - Notifications : envoi d'une alerte au centre et aux canaux
# =============================================================================
# Le centre de notifications reçoit toujours chaque alerte. Les canaux externes
# (liste de la surveillance) la reçoivent ensuite, chacun isolé des autres : un
# canal en échec n'empêche pas les suivants et n'interrompt jamais le scan. Le
# résultat de chaque envoi est rangé avec la notification (colonne delivery).
# =============================================================================

import asyncio
import logging

import httpx

from ..core.database import SessionLocal
from ..i18n import msg
from ..scanner.proxy import get_proxy_url
from . import channels, store
from .channels import Alert, ChannelError, Outgoing

logger = logging.getLogger(__name__)


def _load(name: str) -> tuple[bool, dict] | None:
    with SessionLocal() as db:
        return store.load_channel(db, name)


async def send_one(
    name: str,
    out: Outgoing,
    *,
    proxy: str | None = None,
    transport: httpx.AsyncBaseTransport | None = None,
    require_enabled: bool = True,
) -> dict:
    """Envoie `out` sur le canal `name` ; {"ok": bool, "error": message|None}. Ne lève jamais.

    `require_enabled=False` : bouton de test, qui essaie un canal configuré même désactivé.
    """
    try:
        loaded = await asyncio.to_thread(_load, name)
        if loaded is None:
            raise ChannelError(msg("notify.error_not_configured"))
        enabled, config = loaded
        if require_enabled and not enabled:
            raise ChannelError(msg("notify.error_disabled"))
        if name in channels.WEBHOOK_CHANNELS:
            if not config.get("url"):
                raise ChannelError(msg("notify.error_not_configured"))
            await channels.send_webhook(name, config["url"], out, proxy=proxy, transport=transport)
        elif name == "email":
            if not (config.get("host") and config.get("sender") and config.get("recipients")):
                raise ChannelError(msg("notify.error_not_configured"))
            await channels.send_email(config, out)
        elif name == "desktop":
            await channels.send_desktop(out)
        else:
            raise ChannelError(msg("notify.error_not_configured"))
    except ChannelError as e:
        return {"ok": False, "error": e.message}
    except Exception as e:
        # Jamais le texte de l'exception : il peut citer une URL de webhook ou un identifiant.
        logger.warning("Canal %s : erreur inattendue (%s)", name, type(e).__name__)
        return {"ok": False, "error": msg("notify.error_unknown")}
    return {"ok": True, "error": None}


def _store_center(domain: str, scan_id: int | None, watch_id: int | None, alerts: list[Alert]) -> list[int]:
    with SessionLocal() as db:
        return store.add_notifications(db, domain, scan_id, watch_id, alerts)


def _store_delivery(ids: list[int], delivery: dict) -> None:
    with SessionLocal() as db:
        store.set_delivery(db, ids, delivery)


async def dispatch_alerts(
    domain: str,
    scan_id: int | None,
    watch_id: int | None,
    alerts: list[Alert],
    channel_names: list[str],
    lang: str = "fr",
    *,
    transport: httpx.AsyncBaseTransport | None = None,
) -> dict:
    """Range les alertes dans le centre puis les envoie aux canaux ; renvoie l'issue par canal."""
    if not alerts:
        return {}
    ids = await asyncio.to_thread(_store_center, domain, scan_id, watch_id, alerts)
    out = channels.build_outgoing(domain, scan_id, alerts, lang)
    names = [name for name in dict.fromkeys(channel_names) if name in channels.CHANNELS]
    delivery: dict = {}
    if names:
        proxy = (
            await asyncio.to_thread(get_proxy_url)
            if any(n in channels.WEBHOOK_CHANNELS for n in names)
            else None
        )
        results = await asyncio.gather(
            *(send_one(name, out, proxy=proxy, transport=transport) for name in names)
        )
        delivery = dict(zip(names, results, strict=True))
    if delivery:
        await asyncio.to_thread(_store_delivery, ids, delivery)
    return delivery


async def send_test(
    name: str, lang: str = "fr", *, transport: httpx.AsyncBaseTransport | None = None
) -> dict:
    """Message d'essai sur un canal (bouton « Tester ») ; même forme que send_one."""
    alert = Alert("test", "info", msg("notify.test_body"))
    out = channels.build_outgoing("domainrecon.local", None, [alert], lang)
    proxy = await asyncio.to_thread(get_proxy_url) if name in channels.WEBHOOK_CHANNELS else None
    return await send_one(name, out, proxy=proxy, transport=transport, require_enabled=False)
