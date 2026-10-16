# =============================================================================
# DomainRecon - Tests des canaux d'envoi (webhooks, e-mail SMTP, bureau)
# =============================================================================
# Aucun envoi réel : transports httpx simulés, serveur SMTP local jetable,
# notification de bureau remplacée. L'anti-SSRF est testé avec le vrai client.
# =============================================================================

import json
import logging
import smtplib
import socket
import threading

import httpx
import pytest
from surveillance import asynchrone

from domainrecon.notify import channels
from domainrecon.notify.channels import Alert, ChannelError, build_outgoing

TOKEN = "jeton-ultra-secret-123"
URL = f"https://hooks.exemple.test/services/{TOKEN}"


def _out(lang: str = "fr", alerts: list[Alert] | None = None):
    alerts = alerts or [
        Alert(
            "grade_drop",
            "high",
            {"$t": "alert.grade_drop", "p": {"domain": "a.test", "before": "A", "after": "D"}},
        ),
        Alert(
            "new_port", "medium", {"$t": "alert.new_port", "p": {"domain": "a.test", "ports": [3306, 8080]}}
        ),
    ]
    return build_outgoing("a.test", 7, alerts, lang)


# --- Textes -------------------------------------------------------------------


def test_textes_rendus_dans_la_langue():
    fr, en = _out("fr"), _out("en")
    assert fr.title == "DomainRecon : a.test" and en.title == "DomainRecon: a.test"
    assert fr.body.splitlines() == [
        "[Élevée] La note de a.test baisse : A → D.",
        "[Moyenne] Nouveau port ouvert sur a.test : 3306 ; 8080.",
    ]
    assert en.body.splitlines()[0] == "[High] The grade of a.test dropped: A → D."
    assert fr.severity == "high" and fr.scan_id == 7
    assert fr.alerts[0]["rule"] == "grade_drop" and fr.alerts[0]["code"] == "alert.grade_drop"
    assert fr.alerts[1]["params"]["ports"] == [3306, 8080]


def test_gravite_la_plus_haute():
    assert channels.worst_severity([Alert("a", "low", {}), Alert("b", "critical", {})]) == "critical"
    assert channels.worst_severity([]) == "info"


# --- Webhooks : corps ---------------------------------------------------------


def test_corps_discord_slack_teams_et_generique():
    out = _out()
    discord = channels.webhook_payload("discord", out)
    assert discord["username"] == "DomainRecon" and discord["allowed_mentions"] == {"parse": []}
    assert discord["content"].startswith("**DomainRecon : a.test**\n")
    assert channels.webhook_payload("slack", out)["text"].startswith("*DomainRecon : a.test*\n")
    teams = channels.webhook_payload("teams", out)
    card = teams["attachments"][0]
    assert teams["type"] == "message" and card["contentType"] == "application/vnd.microsoft.card.adaptive"
    assert card["content"]["type"] == "AdaptiveCard"
    assert card["content"]["body"][0]["text"] == "DomainRecon : a.test"
    assert "baisse" in card["content"]["body"][1]["text"]
    generic = channels.webhook_payload("webhook", out)
    assert generic["event"] == "domainrecon.alert" and generic["domain"] == "a.test"
    assert generic["scan_id"] == 7 and generic["severity"] == "high"
    assert [a["rule"] for a in generic["alerts"]] == ["grade_drop", "new_port"]
    json.dumps(generic)  # sérialisable


def test_messages_longs_tronques():
    long_alert = Alert(
        "new_subdomain",
        "low",
        {"$t": "alert.new_finding", "p": {"domain": "x" * 5000, "severity": "", "finding": ""}},
    )
    out = _out(alerts=[long_alert])
    assert len(channels.webhook_payload("discord", out)["content"]) == 2000
    assert len(channels.webhook_payload("slack", out)["text"]) == 3000


# --- Webhooks : envoi ------------------------------------------------------------


@asynchrone
async def test_envoi_webhook_reussi():
    seen: list[httpx.Request] = []

    def handler(request):
        seen.append(request)
        return httpx.Response(204)

    await channels.send_webhook("slack", URL, _out(), transport=httpx.MockTransport(handler))
    (request,) = seen
    assert request.method == "POST" and str(request.url) == URL
    assert request.headers["content-type"] == "application/json"
    assert "baisse" in json.loads(request.content)["text"]


@asynchrone
async def test_webhook_refuse_par_le_service():
    transport = httpx.MockTransport(lambda r: httpx.Response(404, text="introuvable"))
    with pytest.raises(ChannelError) as error:
        await channels.send_webhook("discord", URL, _out(), transport=transport)
    assert error.value.message == {"$t": "notify.error_http", "p": {"status": 404}}
    assert TOKEN not in str(error.value)


@asynchrone
async def test_webhook_erreur_reseau_ne_divulgue_pas_l_url(caplog):
    def handler(request):
        raise httpx.ConnectError(f"connexion refusée vers {request.url}", request=request)

    caplog.set_level(logging.DEBUG)
    with pytest.raises(ChannelError) as error:
        await channels.send_webhook("slack", URL, _out(), transport=httpx.MockTransport(handler))
    assert error.value.message["$t"] == "notify.error_network"
    assert TOKEN not in str(error.value) and TOKEN not in repr(error.value.message)
    assert TOKEN not in caplog.text


@asynchrone
async def test_webhook_delai_depasse():
    def handler(request):
        raise httpx.ReadTimeout("trop lent", request=request)

    with pytest.raises(ChannelError) as error:
        await channels.send_webhook("slack", URL, _out(), transport=httpx.MockTransport(handler))
    assert error.value.message["$t"] == "notify.error_timeout"


@asynchrone
@pytest.mark.parametrize("url", ["https://127.0.0.1/hook", "https://10.0.0.5/hook", "https://[::1]/hook"])
async def test_webhook_anti_ssrf_adresses_non_publiques(url):
    # Vrai client du scanner (sans transport simulé) : la politique de cibles refuse avant toute connexion.
    with pytest.raises(ChannelError) as error:
        await channels.send_webhook("webhook", url, _out())
    assert error.value.message["$t"] == "target.not_allowed_host"


@asynchrone
async def test_webhook_anti_ssrf_meme_derriere_un_transport_simule():
    transport = httpx.MockTransport(lambda r: httpx.Response(204))
    with pytest.raises(ChannelError):
        await channels.send_webhook("webhook", "https://169.254.169.254/latest", _out(), transport=transport)


@asynchrone
async def test_webhook_schema_non_http_refuse():
    with pytest.raises(ChannelError):
        await channels.send_webhook(
            "webhook",
            "ftp://exemple.test/x",
            _out(),
            transport=httpx.MockTransport(lambda r: httpx.Response(204)),
        )


@asynchrone
async def test_le_proxy_des_reglages_est_transmis_au_client(monkeypatch):
    seen = {}
    real = channels.make_http_client

    def espion(proxy=None, **kwargs):
        seen["proxy"] = proxy
        return real(proxy, **kwargs)

    monkeypatch.setattr(channels, "make_http_client", espion)
    await channels.send_webhook(
        "slack",
        URL,
        _out(),
        proxy="http://proxy.exemple.test:3128",
        transport=httpx.MockTransport(lambda r: httpx.Response(200)),
    )
    assert seen["proxy"] == "http://proxy.exemple.test:3128"


# --- E-mail -----------------------------------------------------------------------


class FauxServeurSmtp(threading.Thread):
    """Serveur SMTP minimal sur 127.0.0.1 (un seul message, sans TLS ni authentification)."""

    def __init__(self) -> None:
        super().__init__(daemon=True)
        self.sock = socket.socket()
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(1)
        self.port = self.sock.getsockname()[1]
        self.commands: list[str] = []
        self.message = ""

    def run(self) -> None:
        conn, _ = self.sock.accept()
        with conn, conn.makefile("rwb") as stream:

            def say(line: str) -> None:
                stream.write((line + "\r\n").encode())
                stream.flush()

            say("220 localhost ESMTP")
            while line := stream.readline().decode().rstrip("\r\n"):
                self.commands.append(line)
                verb = line.split(" ", 1)[0].upper()
                if verb == "DATA":
                    say("354 go")
                    data = []
                    while (row := stream.readline().decode()) != ".\r\n":
                        data.append(row)
                    self.message = "".join(data)
                    say("250 ok")
                elif verb == "QUIT":
                    say("221 bye")
                    break
                else:
                    say("250 ok")
        self.sock.close()


def _smtp_config(port: int, host: str = "127.0.0.1") -> dict:
    return {
        "host": host,
        "port": port,
        "security": "none",
        "sender": "domainrecon@exemple.test",
        "recipients": ["moi@exemple.test", "equipe@exemple.test"],
        "username": "",
        "password": "",
    }


def test_construction_du_message():
    message = channels.build_email(_smtp_config(25), _out())
    assert message["Subject"] == "DomainRecon : a.test"
    assert message["From"] == "domainrecon@exemple.test"
    assert message["To"] == "moi@exemple.test, equipe@exemple.test"
    assert "baisse" in message.get_content()


@asynchrone
async def test_envoi_smtp_epingle_sur_l_adresse_validee(monkeypatch):
    server = FauxServeurSmtp()
    server.start()
    resolved = []

    async def resoudre(host):
        resolved.append(host)
        return ["127.0.0.1"]

    monkeypatch.setattr(channels, "ensure_target_allowed", resoudre)
    # Le nom d'hôte n'existe pas : seule l'adresse validée est jointe.
    await channels.send_email(_smtp_config(server.port, host="smtp.exemple.test"), _out())
    server.join(5)
    assert resolved == ["smtp.exemple.test"]
    assert any(c.upper().startswith("MAIL FROM:<DOMAINRECON@EXEMPLE.TEST>") for c in server.commands)
    assert sum(c.upper().startswith("RCPT TO:") for c in server.commands) == 2
    assert "Subject: DomainRecon : a.test" in server.message


@asynchrone
async def test_smtp_anti_ssrf_adresse_locale_refusee():
    with pytest.raises(ChannelError) as error:
        await channels.send_email(_smtp_config(25), _out())
    assert error.value.message["$t"] == "target.not_allowed_host"


@asynchrone
async def test_smtp_nom_sans_adresse(monkeypatch):
    async def rien(host):
        return []

    monkeypatch.setattr(channels, "ensure_target_allowed", rien)
    with pytest.raises(ChannelError) as error:
        await channels.send_email(_smtp_config(25, host="smtp.exemple.test"), _out())
    assert error.value.message["$t"] == "notify.error_resolve"


@asynchrone
async def test_smtp_erreurs_sans_identifiant(monkeypatch, caplog):
    async def public(host):
        return ["93.184.216.34"]

    monkeypatch.setattr(channels, "ensure_target_allowed", public)
    config = {
        **_smtp_config(587, host="smtp.exemple.test"),
        "username": "utilisateur-secret",
        "password": "mdp-secret",
    }

    def refus_auth(*args, **kwargs):
        raise smtplib.SMTPAuthenticationError(535, b"mdp-secret refuse")

    monkeypatch.setattr(channels, "_smtp_deliver", refus_auth)
    with pytest.raises(ChannelError) as error:
        await channels.send_email(config, _out())
    assert error.value.message["$t"] == "notify.error_smtp_auth"

    def panne(*args, **kwargs):
        raise ConnectionRefusedError("refusé pour utilisateur-secret")

    monkeypatch.setattr(channels, "_smtp_deliver", panne)
    caplog.set_level(logging.DEBUG)
    with pytest.raises(ChannelError) as error:
        await channels.send_email(config, _out())
    assert error.value.message["$t"] == "notify.error_smtp"
    assert "mdp-secret" not in caplog.text and "utilisateur-secret" not in caplog.text


# --- Bureau ---------------------------------------------------------------------


@asynchrone
async def test_notification_de_bureau(monkeypatch):
    shown = []
    monkeypatch.setattr(channels, "_desktop_notify", lambda title, body: shown.append((title, body)))
    await channels.send_desktop(_out())
    assert shown[0][0] == "DomainRecon : a.test" and "baisse" in shown[0][1]


@asynchrone
async def test_notification_de_bureau_repli_silencieux(monkeypatch, caplog):
    def indisponible(title, body):
        raise NotImplementedError("pas de service de notification")

    monkeypatch.setattr(channels, "_desktop_notify", indisponible)
    caplog.set_level(logging.WARNING)
    with pytest.raises(ChannelError) as error:
        await channels.send_desktop(_out())
    assert error.value.message["$t"] == "notify.desktop_unavailable"
    assert caplog.text == ""  # aucun bruit : repli silencieux


@asynchrone
async def test_notification_de_bureau_bibliotheque_absente(monkeypatch):
    def absente(title, body):
        raise ImportError("plyer")

    monkeypatch.setattr(channels, "_desktop_notify", absente)
    with pytest.raises(ChannelError):
        await channels.send_desktop(_out())
