# =============================================================================
# DomainRecon - Tests du centre de notifications et des réglages des canaux (API)
# =============================================================================
# Secrets chiffrés en base, masqués dans les réponses ; envois simulés.
# =============================================================================

import json

import httpx
import pytest
from fastapi.testclient import TestClient
from surveillance import asynchrone

from domainrecon.api.app import app
from domainrecon.core import database
from domainrecon.core.crypto import is_encrypted
from domainrecon.notify import dispatch, routes, store
from domainrecon.notify.channels import Alert
from domainrecon.notify.models import Notification, NotifyChannel

TOKEN = "jeton-ultra-secret-123"
URL = f"https://hooks.slack.com/services/T000/B000/{TOKEN}"


@pytest.fixture
def client(monkeypatch):
    monkeypatch.setenv("SCHEDULER", "0")
    with TestClient(app) as c:
        yield c


@pytest.fixture
def transport():
    """Transport simulé des envois ; `requetes` recueille les requêtes, `reponse` fixe le code."""
    etat = {"code": 200, "requetes": []}

    def handler(request):
        etat["requetes"].append(request)
        return httpx.Response(etat["code"])

    app.dependency_overrides[routes.get_notify_transport] = lambda: httpx.MockTransport(handler)
    yield etat
    app.dependency_overrides.pop(routes.get_notify_transport, None)


def _raw(name: str) -> dict:
    with database.SessionLocal() as db:
        return dict(db.get(NotifyChannel, name).config)


# --- Réglages des canaux -----------------------------------------------------------


def test_tous_les_canaux_sont_listes_non_configures(client):
    channels = client.get("/api/notify/channels").json()["channels"]
    assert [c["name"] for c in channels] == ["discord", "slack", "teams", "webhook", "email", "desktop"]
    assert all(c["enabled"] is False and c["configured"] is False for c in channels)


def test_webhook_enregistre_chiffre_et_masque(client):
    response = client.put("/api/notify/channels/slack", json={"enabled": True, "config": {"url": URL}})
    assert response.status_code == 200
    view = response.json()
    assert view["enabled"] is True and view["configured"] is True
    assert view["config"] == {"url": "https://hooks.slack.com/…"}
    assert TOKEN not in response.text
    stored = _raw("slack")
    assert is_encrypted(stored["url"]) and TOKEN not in json.dumps(stored)
    assert TOKEN not in client.get("/api/notify/channels").text


def test_secret_absent_ou_masque_est_conserve_et_chaine_vide_l_efface(client):
    client.put(
        "/api/notify/channels/discord",
        json={"enabled": True, "config": {"url": "https://discord.com/api/webhooks/1/abc"}},
    )
    before = _raw("discord")["url"]
    kept = client.put("/api/notify/channels/discord", json={"enabled": True, "config": {}})
    assert kept.status_code == 200 and kept.json()["configured"] is True
    masked = client.put(
        "/api/notify/channels/discord", json={"enabled": False, "config": {"url": "https://discord.com/…"}}
    )
    assert masked.json()["enabled"] is False and masked.json()["configured"] is True
    assert store.load_channel(_session(), "discord") == (
        False,
        {"url": "https://discord.com/api/webhooks/1/abc"},
    )
    assert before  # l'ancien secret n'a pas été modifié ni effacé
    cleared = client.put("/api/notify/channels/discord", json={"enabled": False, "config": {"url": ""}})
    assert cleared.json()["configured"] is False and cleared.json()["config"]["url"] == ""


def _session():
    return database.SessionLocal()


def test_email_identifiants_chiffres(client):
    config = {
        "host": "smtp.exemple.test",
        "port": 587,
        "security": "starttls",
        "sender": "domainrecon@exemple.test",
        "recipients": ["moi@exemple.test"],
        "username": "utilisateur-secret",
        "password": "mdp-secret",
    }
    response = client.put("/api/notify/channels/email", json={"enabled": True, "config": config})
    assert response.status_code == 200
    view = response.json()
    assert view["configured"] is True
    assert view["config"]["host"] == "smtp.exemple.test" and view["config"]["recipients"] == [
        "moi@exemple.test"
    ]
    assert view["config"]["username"] == "****" and view["config"]["password"] == "****"
    assert "mdp-secret" not in response.text and "utilisateur-secret" not in response.text
    stored = _raw("email")
    assert is_encrypted(stored["username"]) and is_encrypted(stored["password"])
    assert "mdp-secret" not in json.dumps(stored) and "utilisateur-secret" not in json.dumps(stored)
    # Les identifiants déchiffrés sont ceux de l'envoi.
    enabled, plain = store.load_channel(_session(), "email")
    assert enabled and plain["password"] == "mdp-secret" and plain["username"] == "utilisateur-secret"
    # Modification d'un autre champ : identifiants conservés.
    changed = {**config, "port": 465, "security": "ssl", "username": "****", "password": "****"}
    client.put("/api/notify/channels/email", json={"enabled": True, "config": changed})
    _, plain = store.load_channel(_session(), "email")
    assert plain["port"] == 465 and plain["password"] == "mdp-secret"


def test_reglages_invalides(client):
    def put(name, config, enabled=True):
        return client.put(f"/api/notify/channels/{name}", json={"enabled": enabled, "config": config})

    for config in (
        {"url": "http://hooks.slack.com/x"},  # Slack : HTTPS seulement
        {"url": "https://u:p@hooks.slack.com/x"},
        {"url": "https://exemple.test/a b"},
        {"url": ""},
        {},
        {"url": 12},
        {"url": "https://" + "a" * 2100 + ".test"},
    ):
        response = put("slack", config)
        assert response.status_code == 400 and response.json()["code"] == "notify.config_invalid", config
    assert (
        put("webhook", {"url": "http://interne.exemple.test/hook"}).status_code == 200
    )  # HTTP admis en générique
    base = {"host": "smtp.exemple.test", "sender": "a@exemple.test", "recipients": ["b@exemple.test"]}
    for patch in (
        {"host": "bad host!"},
        {"port": 0},
        {"port": "25"},
        {"security": "sslv3"},
        {"sender": "pas-un-mail"},
        {"recipients": []},
        {"recipients": ["ok@exemple.test", "x"]},
        {"recipients": ["a@exemple.test"] * 11},
        {"username": 5},
    ):
        response = put("email", {**base, **patch})
        assert response.status_code == 400, patch
    assert put("email", base).status_code == 200
    assert client.put("/api/notify/channels/fax", json={"enabled": True, "config": {}}).status_code == 422
    assert client.put("/api/notify/channels/slack", json={"enabled": True, "extra": 1}).status_code == 422
    assert (
        client.put(
            "/api/notify/channels/slack", content="x", headers={"content-type": "text/plain"}
        ).status_code
        == 415
    )


def test_canal_bureau_sans_reglage(client):
    view = client.put("/api/notify/channels/desktop", json={"enabled": True, "config": {}}).json()
    assert view["enabled"] is True and view["configured"] is True


def test_suppression_d_un_canal(client):
    client.put("/api/notify/channels/slack", json={"enabled": True, "config": {"url": URL}})
    assert client.delete("/api/notify/channels/slack").json() == {"name": "slack"}
    assert client.delete("/api/notify/channels/slack").json()["code"] == "notify.channel_not_found"
    assert client.get("/api/notify/channels").json()["channels"][1]["configured"] is False


def test_bouton_de_test(client, transport):
    pas_configure = client.post("/api/notify/channels/slack/test", json={}).json()
    assert pas_configure == {"ok": False, "error": "Canal non configuré."}
    client.put("/api/notify/channels/slack", json={"enabled": False, "config": {"url": URL}})
    # Un canal désactivé s'essaie quand même : c'est le but du bouton.
    ok = client.post("/api/notify/channels/slack/test?lang=en", json={}).json()
    assert ok == {"ok": True, "error": None}
    (request,) = transport["requetes"]
    assert str(request.url) == URL and "Test message" in json.loads(request.content)["text"]
    transport["code"] = 500
    ko = client.post("/api/notify/channels/slack/test", json={}).json()
    assert ko["ok"] is False and "500" in ko["error"] and TOKEN not in json.dumps(ko)


def test_bouton_de_test_bureau_et_email_non_configures(client, monkeypatch):
    from domainrecon.notify import channels

    def indisponible(title, body):
        raise NotImplementedError

    monkeypatch.setattr(channels, "_desktop_notify", indisponible)
    client.put("/api/notify/channels/desktop", json={"enabled": True, "config": {}})
    assert client.post("/api/notify/channels/desktop/test", json={}).json()["ok"] is False
    assert client.post("/api/notify/channels/email/test", json={}).json()["error"] == "Canal non configuré."


# --- Distribution -------------------------------------------------------------------


def _alerte(rule="grade_drop", severity="high") -> Alert:
    return Alert(
        rule, severity, {"$t": "alert.grade_drop", "p": {"domain": "a.test", "before": "A", "after": "D"}}
    )


@asynchrone
async def test_le_centre_recoit_toujours_les_alertes_meme_sans_canal():
    delivery = await dispatch.dispatch_alerts("a.test", 5, 9, [_alerte(), _alerte("new_port", "medium")], [])
    assert delivery == {}
    with database.SessionLocal() as db:
        rows = db.query(Notification).order_by(Notification.id).all()
    assert [(r.rule, r.severity, r.scan_id, r.watch_id, r.is_read) for r in rows] == [
        ("grade_drop", "high", 5, 9, False),
        ("new_port", "medium", 5, 9, False),
    ]


@asynchrone
async def test_aucune_alerte_rien_n_est_ecrit():
    assert await dispatch.dispatch_alerts("a.test", 5, 9, [], ["slack"]) == {}
    with database.SessionLocal() as db:
        assert db.query(Notification).count() == 0


@asynchrone
async def test_canaux_isoles_les_uns_des_autres(monkeypatch):
    with database.SessionLocal() as db:
        store.save_channel(db, "slack", True, {"url": URL})
        store.save_channel(db, "teams", True, {"url": "https://exemple.webhook.office.com/hook/abc"})
    appels = []

    def handler(request):
        appels.append(request.url.host)
        if request.url.host.startswith("hooks.slack"):
            raise httpx.ConnectError("panne", request=request)
        return httpx.Response(202)

    delivery = await dispatch.dispatch_alerts(
        "a.test",
        1,
        None,
        [_alerte()],
        ["slack", "teams", "teams", "inconnu", "email"],
        "en",
        transport=httpx.MockTransport(handler),
    )
    assert set(delivery) == {"slack", "teams", "email"}
    assert delivery["slack"] == {"ok": False, "error": {"$t": "notify.error_network", "p": {}}}
    assert delivery["teams"] == {"ok": True, "error": None}
    assert delivery["email"]["error"]["$t"] == "notify.error_not_configured"
    assert appels.count("exemple.webhook.office.com") == 1
    with database.SessionLocal() as db:
        (row,) = db.query(Notification).all()
    assert row.delivery["teams"]["ok"] is True and row.delivery["slack"]["ok"] is False


@asynchrone
async def test_proxy_des_reglages_utilise_pour_les_webhooks(monkeypatch):
    seen = []
    real = dispatch.channels.send_webhook

    async def espion(kind, url, out, *, proxy=None, transport=None):
        seen.append(proxy)
        return await real(kind, url, out, proxy=proxy, transport=transport)

    monkeypatch.setattr(dispatch.channels, "send_webhook", espion)
    monkeypatch.setattr(dispatch, "get_proxy_url", lambda: "socks5h://127.0.0.1:9050")
    with database.SessionLocal() as db:
        store.save_channel(db, "slack", True, {"url": URL})
    await dispatch.dispatch_alerts(
        "a.test",
        1,
        None,
        [_alerte()],
        ["slack"],
        transport=httpx.MockTransport(lambda r: httpx.Response(200)),
    )
    assert seen == ["socks5h://127.0.0.1:9050"]


@asynchrone
async def test_erreur_inattendue_d_un_canal_sans_divulguer_le_secret(monkeypatch, caplog):
    async def boom(*args, **kwargs):
        raise RuntimeError(f"échec avec {TOKEN}")

    monkeypatch.setattr(dispatch.channels, "send_webhook", boom)
    with database.SessionLocal() as db:
        store.save_channel(db, "slack", True, {"url": URL})
    delivery = await dispatch.dispatch_alerts("a.test", 1, None, [_alerte()], ["slack"])
    assert delivery["slack"]["error"]["$t"] == "notify.error_unknown"
    assert TOKEN not in caplog.text and TOKEN not in json.dumps(delivery)


@asynchrone
async def test_secret_illisible_traite_comme_absent(monkeypatch):
    with database.SessionLocal() as db:
        store.save_channel(db, "slack", True, {"url": URL})
        row = db.get(NotifyChannel, "slack")
        row.config = {"url": "enc:v1:jeton-invalide"}
        db.commit()
    delivery = await dispatch.dispatch_alerts("a.test", 1, None, [_alerte()], ["slack"])
    assert delivery["slack"]["error"]["$t"] == "notify.error_not_configured"


# --- Centre de notifications (routes) -----------------------------------------------


@pytest.fixture
def centre(client):
    import asyncio

    asyncio.run(dispatch.dispatch_alerts("a.test", 3, 1, [_alerte(), _alerte("new_port", "medium")], []))
    asyncio.run(dispatch.dispatch_alerts("b.test", 4, 2, [_alerte("cert_expiry", "high")], []))
    return client


def test_liste_des_notifications_rendue_dans_la_langue(centre):
    fr = centre.get("/api/notifications").json()
    assert fr["total"] == 3 and fr["unread"] == 3
    assert [i["domain"] for i in fr["items"]] == ["b.test", "a.test", "a.test"]  # plus récentes d'abord
    first = fr["items"][0]
    assert first["message"] == "La note de a.test baisse : A → D."
    assert first["created_at"].endswith("Z") and first["is_read"] is False and first["scan_id"] == 4
    assert (
        centre.get("/api/notifications?lang=en").json()["items"][0]["message"]
        == "The grade of a.test dropped: A → D."
    )


def test_pagination_et_filtre_non_lues(centre):
    assert len(centre.get("/api/notifications?limit=2").json()["items"]) == 2
    assert len(centre.get("/api/notifications?limit=2&offset=2").json()["items"]) == 1
    ids = [i["id"] for i in centre.get("/api/notifications").json()["items"]]
    assert centre.post("/api/notifications/read", json={"ids": [ids[0]]}).json() == {"updated": 1}
    body = centre.get("/api/notifications?unread_only=true").json()
    assert body["total"] == 2 and body["unread"] == 2 and ids[0] not in [i["id"] for i in body["items"]]
    assert centre.get("/api/notifications?limit=0").status_code == 422


def test_tout_marquer_lu_puis_nettoyer(centre):
    assert centre.post("/api/notifications/read", json={}).json() == {"updated": 3}
    assert centre.post("/api/notifications/read", json={}).json() == {"updated": 0}
    assert centre.get("/api/notifications").json()["unread"] == 0
    assert centre.delete("/api/notifications").json() == {"deleted": 3}
    assert centre.get("/api/notifications").json()["total"] == 0


def test_nettoyage_garde_les_non_lues(centre):
    first = centre.get("/api/notifications").json()["items"][0]["id"]
    centre.post("/api/notifications/read", json={"ids": [first]})
    assert centre.delete("/api/notifications").json() == {"deleted": 1}
    assert centre.get("/api/notifications").json()["total"] == 2
    assert centre.delete("/api/notifications?all=true").json() == {"deleted": 2}


def test_suppression_d_une_notification(centre):
    first = centre.get("/api/notifications").json()["items"][0]["id"]
    assert centre.delete(f"/api/notifications/{first}").json() == {"id": first}
    assert centre.delete(f"/api/notifications/{first}").json()["code"] == "notify.not_found"
    assert centre.get("/api/notifications").json()["total"] == 2
    assert (
        centre.post(
            "/api/notifications/read", content="x", headers={"content-type": "text/plain"}
        ).status_code
        == 415
    )
