# =============================================================================
# DomainRecon - Notifications : canaux d'envoi
# =============================================================================
# Canaux externes : webhooks Discord, Slack, Teams (carte adaptative des
# Workflows) et JSON générique, e-mail SMTP, notification de bureau. Le centre
# de notifications de l'application n'est pas un canal : voir dispatch.py.
#
# Sécurité :
#   - les webhooks passent par le client HTTP du scanner (proxy.make_http_client) :
#     politique de cibles (anti-SSRF) appliquée à chaque requête, TLS vérifié,
#     aucune redirection suivie, proxy sortant des Réglages ;
#   - l'hôte SMTP est contrôlé de la même façon et la connexion est épinglée sur
#     l'adresse validée (pas de seconde résolution) ; le proxy HTTP ne s'applique pas à SMTP ;
#   - une URL de webhook porte son jeton : jamais journalisée ni renvoyée dans une
#     erreur (ChannelError ne porte qu'un message du catalogue) ;
#   - la notification de bureau est facultative : sans environnement graphique ou
#     sans la bibliothèque, l'envoi échoue sans bruit (ChannelError, journal en debug).
# =============================================================================

import asyncio
import logging
import smtplib
import ssl
import threading
from dataclasses import dataclass, field
from email.message import EmailMessage

import httpx

from ..i18n import msg, render
from ..scanner.errors import message_of
from ..scanner.proxy import make_http_client
from ..scanner.targets import ensure_target_allowed

logger = logging.getLogger(__name__)

WEBHOOK_CHANNELS = ("discord", "slack", "teams", "webhook")
CHANNELS = (*WEBHOOK_CHANNELS, "email", "desktop")

# Délais d'envoi, en secondes.
HTTP_TIMEOUT = 10.0
SMTP_TIMEOUT = 15.0
DESKTOP_WAIT = 3.0

# Longueurs maximales des messages (Discord : 2000 caractères, Slack : 3000).
_DISCORD_MAX = 2000
_SLACK_MAX = 3000

SEVERITY_COLORS = {
    "critical": 0xB91C1C,
    "high": 0xEA580C,
    "medium": 0xCA8A04,
    "low": 0x2563EB,
    "info": 0x64748B,
}


class ChannelError(Exception):
    """Envoi impossible ; `message` est un message du catalogue (jamais d'URL ni d'identifiant)."""

    def __init__(self, message: dict) -> None:
        super().__init__(message["$t"])
        self.message = message


@dataclass(frozen=True)
class Alert:
    """Une alerte : règle à l'origine, gravité et message traduisible."""

    rule: str
    severity: str
    message: dict
    data: dict = field(default_factory=dict)


@dataclass(frozen=True)
class Outgoing:
    """Ce qu'un canal envoie : textes déjà rendus dans la langue choisie."""

    domain: str
    scan_id: int | None
    title: str
    body: str
    severity: str
    lang: str
    alerts: tuple[dict, ...]


def severity_message(severity: str) -> dict:
    """Libellé traduisible d'une gravité (critical, high, medium, low ; sinon « Info »)."""
    return {
        "critical": msg("notify.severity_critical"),
        "high": msg("notify.severity_high"),
        "medium": msg("notify.severity_medium"),
        "low": msg("notify.severity_low"),
    }.get(severity, msg("notify.severity_info"))


def worst_severity(alerts: list[Alert]) -> str:
    order = ("critical", "high", "medium", "low", "info")
    ranks = [order.index(a.severity) for a in alerts if a.severity in order]
    return order[min(ranks)] if ranks else "info"


def build_outgoing(domain: str, scan_id: int | None, alerts: list[Alert], lang: str) -> Outgoing:
    """Textes d'un envoi : titre « DomainRecon : domaine » et une ligne par alerte."""
    lines = [f"[{render(severity_message(a.severity), lang)}] {render(a.message, lang)}" for a in alerts]
    return Outgoing(
        domain=domain,
        scan_id=scan_id,
        title=str(render(msg("notify.title", domain=domain), lang)),
        body="\n".join(lines),
        severity=worst_severity(alerts),
        lang=lang,
        alerts=tuple(
            {
                "rule": a.rule,
                "severity": a.severity,
                "code": a.message["$t"],
                "params": render(a.message["p"], lang),
                "message": render(a.message, lang),
            }
            for a in alerts
        ),
    )


# =============================================================================
# Webhooks
# =============================================================================


def webhook_payload(kind: str, out: Outgoing) -> dict:
    """Corps JSON propre à chaque service."""
    if kind == "discord":
        return {
            "username": "DomainRecon",
            "content": f"**{out.title}**\n{out.body}"[:_DISCORD_MAX],
            "allowed_mentions": {"parse": []},
        }
    if kind == "slack":
        return {"text": f"*{out.title}*\n{out.body}"[:_SLACK_MAX]}
    if kind == "teams":
        return {
            "type": "message",
            "attachments": [
                {
                    "contentType": "application/vnd.microsoft.card.adaptive",
                    "contentUrl": None,
                    "content": {
                        "$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
                        "type": "AdaptiveCard",
                        "version": "1.4",
                        "body": [
                            {
                                "type": "TextBlock",
                                "text": out.title,
                                "weight": "Bolder",
                                "size": "Medium",
                                "wrap": True,
                            },
                            {"type": "TextBlock", "text": out.body, "wrap": True},
                        ],
                    },
                }
            ],
        }
    return {
        "event": "domainrecon.alert",
        "domain": out.domain,
        "scan_id": out.scan_id,
        "severity": out.severity,
        "title": out.title,
        "alerts": list(out.alerts),
    }


async def send_webhook(
    kind: str,
    url: str,
    out: Outgoing,
    *,
    proxy: str | None = None,
    transport: httpx.AsyncBaseTransport | None = None,
) -> None:
    """Poste l'alerte sur le webhook ; ChannelError sans l'URL si l'envoi échoue."""
    try:
        async with make_http_client(proxy, timeout=HTTP_TIMEOUT, transport=transport) as client:
            response = await client.post(url, json=webhook_payload(kind, out))
    except httpx.TimeoutException as e:
        raise ChannelError(msg("notify.error_timeout")) from e
    except ValueError as e:
        # Cible refusée par la politique (adresse privée, schéma) : message du catalogue.
        message = message_of(e)
        if message is not None:
            raise ChannelError(message) from e
        raise ChannelError(msg("notify.error_network")) from e
    except httpx.HTTPError as e:
        # Le texte de l'exception peut citer l'URL (jeton) : seul son type est journalisé.
        logger.info("Webhook %s : échec réseau (%s)", kind, type(e).__name__)
        raise ChannelError(msg("notify.error_network")) from e
    if response.status_code >= 300:
        raise ChannelError(msg("notify.error_http", status=response.status_code))


# =============================================================================
# E-mail SMTP
# =============================================================================


def build_email(config: dict, out: Outgoing) -> EmailMessage:
    message = EmailMessage()
    message["Subject"] = out.title.replace("\r", " ").replace("\n", " ")
    message["From"] = config["sender"]
    message["To"] = ", ".join(config["recipients"])
    message.set_content(out.body)
    return message


def _smtp_deliver(config: dict, message: EmailMessage, address: str) -> None:
    """Envoi synchrone, connexion épinglée sur `address` (déjà validée), TLS vérifié contre le nom d'hôte."""
    security = config.get("security", "starttls")
    context = ssl.create_default_context()
    base = smtplib.SMTP_SSL if security == "ssl" else smtplib.SMTP

    class Pinned(base):  # type: ignore[valid-type, misc]
        def _get_socket(self, host, port, timeout):
            return super()._get_socket(address, port, timeout)

    kwargs = {"context": context} if security == "ssl" else {}
    smtp = Pinned(timeout=SMTP_TIMEOUT, **kwargs)
    # Nom vérifié par le certificat (SNI compris) ; la connexion, elle, vise l'adresse validée.
    smtp._host = config["host"]
    try:
        smtp.connect(config["host"], int(config["port"]))
        smtp.ehlo()
        if security == "starttls":
            smtp.starttls(context=context)
            smtp.ehlo()
        if config.get("username"):
            smtp.login(config["username"], config.get("password", ""))
        smtp.send_message(message)
    finally:
        try:
            smtp.quit()
        except (smtplib.SMTPException, OSError):
            smtp.close()


async def send_email(config: dict, out: Outgoing) -> None:
    """Envoie l'alerte par e-mail ; ChannelError sans identifiant si l'envoi échoue."""
    host = config["host"]
    try:
        addresses = await ensure_target_allowed(host)
    except ValueError as e:
        raise ChannelError(message_of(e) or msg("notify.error_network")) from e
    if not addresses:
        raise ChannelError(msg("notify.error_resolve"))
    try:
        await asyncio.to_thread(_smtp_deliver, config, build_email(config, out), addresses[0])
    except smtplib.SMTPAuthenticationError as e:
        raise ChannelError(msg("notify.error_smtp_auth")) from e
    except (smtplib.SMTPException, OSError, ssl.SSLError) as e:
        logger.info("E-mail : échec d'envoi (%s)", type(e).__name__)
        raise ChannelError(msg("notify.error_smtp")) from e


# =============================================================================
# Notification de bureau
# =============================================================================


def _desktop_notify(title: str, body: str) -> None:
    """Notification du système (bibliothèque plyer), importée à la demande."""
    from plyer import notification

    notification.notify(title=title[:128], message=body[:256], app_name="DomainRecon", timeout=10)


def _desktop_blocking(title: str, body: str) -> None:
    errors: list[BaseException] = []

    def work() -> None:
        try:
            _desktop_notify(title, body)
        except BaseException as e:  # repli silencieux : tout échec, même d'import
            errors.append(e)

    # Fil à part : certains systèmes gardent l'appel ouvert le temps d'affichage.
    thread = threading.Thread(target=work, name="domainrecon-desktop-notify", daemon=True)
    thread.start()
    thread.join(DESKTOP_WAIT)
    if errors:
        logger.debug("Notification de bureau indisponible (%s)", type(errors[0]).__name__)
        raise ChannelError(msg("notify.desktop_unavailable"))


async def send_desktop(out: Outgoing) -> None:
    await asyncio.to_thread(_desktop_blocking, out.title, out.body)
