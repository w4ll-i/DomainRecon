# =============================================================================
# DomainRecon - Tests des routes /api/watches et /api/monitor/task
# =============================================================================

from datetime import datetime, timedelta, timezone

import pytest
from fastapi.testclient import TestClient
from surveillance import add_watch, read_watch

from domainrecon.api.app import app
from domainrecon.core.models import utcnow
from domainrecon.monitor import routes as monitor_routes
from domainrecon.monitor import systask


@pytest.fixture
def client(monkeypatch):
    # Pas de planificateur réel : il lancerait de vrais scans.
    monkeypatch.setenv("SCHEDULER", "0")
    with TestClient(app) as c:
        yield c


def _create(client, **body):
    payload = {"domain": "Exemple.TEST", "profile": "rapide", **body}
    return client.post("/api/watches", json=payload)


def test_creation_avec_valeurs_par_defaut(client):
    before = utcnow()
    response = _create(client)
    assert response.status_code == 201
    body = response.json()
    assert body["domain"] == "exemple.test"
    assert body["frequency"] == "daily" and body["enabled"] is True
    assert body["profile"] == "rapide" and body["authorized_target"] is False
    assert body["channels"] == [] and body["lang"] == "fr"
    assert body["rules"] == {
        "grade_drop": True,
        "new_findings": True,
        "cert_expiry_days": 14,
        "new_port": True,
        "new_subdomain": True,
    }
    due = datetime.fromisoformat(body["next_run_at"].replace("Z", "+00:00"))
    assert abs(due - before.replace(tzinfo=timezone.utc)) < timedelta(minutes=1)
    assert body["last_run_at"] is None and body["last_status"] is None


def test_creation_personnalisee(client):
    first = datetime(2030, 1, 2, 3, 4, tzinfo=timezone.utc)
    response = _create(
        client,
        frequency="monthly",
        channels=["discord", "discord", "center", "email"],
        rules={"cert_expiry_days": 30, "new_port": False},
        lang="en",
        next_run_at=first.isoformat(),
    )
    body = response.json()
    assert response.status_code == 201
    assert body["frequency"] == "monthly" and body["channels"] == ["discord", "center", "email"]
    assert body["rules"]["cert_expiry_days"] == 30 and body["rules"]["new_port"] is False
    assert body["rules"]["grade_drop"] is True
    assert body["next_run_at"] == "2030-01-02T03:04:00Z"
    assert read_watch(body["id"]).next_run_at == datetime(2030, 1, 2, 3, 4)


def test_creation_refusee(client):
    assert _create(client).status_code == 201
    doublon = _create(client, domain="exemple.test")
    assert doublon.status_code == 409 and doublon.json()["code"] == "monitor.watch_exists"
    assert _create(client, domain="!!!").status_code == 400
    prive = _create(client, domain="10.0.0.1")
    assert prive.status_code == 400 and prive.json()["code"] == "target.ip_not_allowed"
    sans_autorisation = _create(client, domain="b.test", profile="personnalise", selected=["open_ports"])
    assert sans_autorisation.status_code == 400
    assert sans_autorisation.json()["code"] == "api.authorization_required"
    assert _create(client, domain="c.test", frequency="hourly").status_code == 422
    assert _create(client, domain="d.test", rules={"cert_expiry_days": 0}).status_code == 422
    assert _create(client, domain="e.test", rules={"inconnue": 1}).status_code == 422
    assert _create(client, domain="f.test", channels=["fax"]).status_code == 422
    assert _create(client, domain="g.test", inconnu=True).status_code == 422
    assert client.post("/api/watches", content="x", headers={"content-type": "text/plain"}).status_code == 415


def test_creation_avec_autorisation_et_modules_choisis(client):
    response = _create(
        client,
        profile="personnalise",
        selected=["open_ports"],
        authorized_target=True,
    )
    assert response.status_code == 201
    assert response.json()["selected"] == ["open_ports"] and response.json()["authorized_target"] is True


def test_liste_lecture_et_suppression(client):
    one = _create(client, domain="b.test").json()["id"]
    two = _create(client, domain="a.test").json()["id"]
    listing = client.get("/api/watches").json()["watches"]
    assert [w["domain"] for w in listing] == ["a.test", "b.test"]
    assert client.get(f"/api/watches/{one}").json()["domain"] == "b.test"
    assert client.delete(f"/api/watches/{two}").json() == {"id": two}
    assert client.get(f"/api/watches/{two}").status_code == 404
    assert client.delete(f"/api/watches/{two}").json()["code"] == "monitor.watch_not_found"
    assert client.get("/api/watches/0").status_code == 422


def test_modification_partielle(client):
    watch_id = _create(client).json()["id"]
    response = client.patch(
        f"/api/watches/{watch_id}",
        json={
            "frequency": "weekly",
            "enabled": False,
            "channels": ["slack"],
            "rules": {"grade_drop": False},
            "next_run_at": "2031-05-06T07:08:00Z",
            "lang": "en",
        },
    )
    body = response.json()
    assert response.status_code == 200
    assert body["frequency"] == "weekly" and body["enabled"] is False and body["channels"] == ["slack"]
    assert body["rules"]["grade_drop"] is False and body["rules"]["new_port"] is True
    assert body["next_run_at"] == "2031-05-06T07:08:00Z" and body["lang"] == "en"
    assert body["domain"] == "exemple.test" and body["profile"] == "rapide"
    # Un champ absent n'est pas modifié.
    assert client.patch(f"/api/watches/{watch_id}", json={}).json()["frequency"] == "weekly"
    assert client.patch(f"/api/watches/{watch_id}", json={"domain": "autre.test"}).status_code == 422
    assert client.patch("/api/watches/999", json={"enabled": True}).status_code == 404


def test_modification_du_profil_revalide_l_autorisation(client):
    watch_id = _create(client).json()["id"]
    refus = client.patch(
        f"/api/watches/{watch_id}", json={"profile": "personnalise", "selected": ["open_ports"]}
    )
    assert refus.status_code == 400 and refus.json()["code"] == "api.authorization_required"
    ok = client.patch(
        f"/api/watches/{watch_id}",
        json={"profile": "personnalise", "selected": ["open_ports"], "authorized_target": True},
    )
    assert ok.status_code == 200 and ok.json()["selected"] == ["open_ports"]
    back = client.patch(f"/api/watches/{watch_id}", json={"profile": "rapide"})
    assert back.json()["selected"] is None


def test_lancement_immediat_reveille_le_planificateur(client):
    class FauxPlanificateur:
        running = True

        def __init__(self):
            self.reveils = 0

        def wake(self):
            self.reveils += 1

        async def stop(self):
            pass

    watch_id = _create(client, next_run_at="2040-01-01T00:00:00Z").json()["id"]
    # Sans planificateur (SCHEDULER=0) : refus explicite.
    refus = client.post(f"/api/watches/{watch_id}/run", json={})
    assert refus.status_code == 409 and refus.json()["code"] == "monitor.scheduler_off"
    faux = FauxPlanificateur()
    app.state.scheduler = faux
    try:
        ok = client.post(f"/api/watches/{watch_id}/run", json={})
        assert ok.status_code == 202 and faux.reveils == 1
        assert read_watch(watch_id).next_run_at <= utcnow()
        client.patch(f"/api/watches/{watch_id}", json={"enabled": False})
        off = client.post(f"/api/watches/{watch_id}/run", json={})
        assert off.status_code == 409 and off.json()["code"] == "monitor.watch_disabled"
    finally:
        app.state.scheduler = None
    assert client.post("/api/watches/999/run", json={}).status_code == 404


def test_la_surveillance_modifiee_en_base_est_relue():
    watch_id = add_watch("x.test", rules={"cert_expiry_days": 7})
    assert monitor_routes.watch_view(read_watch(watch_id))["rules"]["cert_expiry_days"] == 7


# --- Tâche système -----------------------------------------------------------

LOCAL = ("127.0.0.1", 50000)
LOCAL_ONLY = {
    "fr": "Action réservée à l'utilisateur de cette machine",
    "en": "Action reserved for the user of this machine",
}


@pytest.fixture
def local_client(monkeypatch):
    """Client venu de cette machine (adresse de bouclage) : le seul à pouvoir (dés)installer la tâche système."""
    monkeypatch.setenv("SCHEDULER", "0")
    with TestClient(app, client=LOCAL) as c:
        yield c


def test_routes_de_la_tache_systeme(client, local_client, monkeypatch):
    state = {"supported": True, "platform": "windows", "installed": False, "command": "x"}
    monkeypatch.setattr(systask, "status", lambda: dict(state))
    monkeypatch.setattr(systask, "install", lambda: {**state, "installed": True})
    monkeypatch.setattr(systask, "uninstall", lambda: dict(state))
    # L'état se lit depuis n'importe quelle machine ; installer et désinstaller exigent une requête locale.
    assert client.get("/api/monitor/task").json() == state
    assert local_client.get("/api/monitor/task").json() == state
    assert local_client.post("/api/monitor/task/install", json={}).json()["installed"] is True
    assert local_client.post("/api/monitor/task/uninstall", json={}).json()["installed"] is False
    assert (
        local_client.post(
            "/api/monitor/task/install", content="", headers={"content-type": "text/plain"}
        ).status_code
        == 415
    )


def test_route_d_installation_refusee(local_client, monkeypatch):
    from domainrecon.i18n import msg
    from domainrecon.scanner.errors import message_exception

    def refuse():
        raise message_exception(ValueError, msg("systask.unsupported"))

    monkeypatch.setattr(systask, "install", refuse)
    response = local_client.post("/api/monitor/task/install", json={})
    assert response.status_code == 400 and response.json()["code"] == "systask.unsupported"


@pytest.mark.parametrize("action", ["install", "uninstall"])
def test_tache_systeme_reservee_aux_requetes_locales(client, monkeypatch, action):
    """Comme POST /api/system/open-data-dir : 403 api.local_only, et le système n'est pas touché."""
    appels = []
    monkeypatch.setattr(systask, action, lambda: appels.append(action))
    for langue, detail in LOCAL_ONLY.items():
        response = client.post(f"/api/monitor/task/{action}?lang={langue}", json={})  # client « testclient »
        assert response.status_code == 403
        assert response.json() == {"detail": detail, "code": "api.local_only", "params": {}}
    # L'en-tête X-Forwarded-For n'est pas cru : il n'est pas un moyen de se dire local.
    usurpation = client.post(
        f"/api/monitor/task/{action}",
        json={},
        headers={"X-Forwarded-For": "127.0.0.1", "Forwarded": "for=127.0.0.1", "X-Real-IP": "127.0.0.1"},
    )
    assert usurpation.status_code == 403
    assert appels == []


@pytest.mark.parametrize("action", ["install", "uninstall"])
@pytest.mark.parametrize("adresse", ["127.0.0.1", "127.8.9.10", "::1", "localhost", "::ffff:127.0.0.1"])
def test_tache_systeme_acceptee_depuis_une_adresse_de_bouclage(monkeypatch, action, adresse):
    monkeypatch.setenv("SCHEDULER", "0")
    state = {"supported": True, "platform": "linux", "installed": action == "install", "command": "x"}
    appels = []
    monkeypatch.setattr(systask, action, lambda: appels.append(action) or state)
    with TestClient(app, client=(adresse, 50000)) as local:
        response = local.post(f"/api/monitor/task/{action}", json={})
    assert response.status_code == 200 and response.json() == state
    assert appels == [action]


@pytest.mark.parametrize("action", ["install", "uninstall"])
@pytest.mark.parametrize(
    "adresse", ["192.168.1.20", "10.0.0.5", "8.8.8.8", "fe80::1", "::ffff:192.168.1.20", ""]
)
def test_tache_systeme_refusee_hors_de_la_machine(monkeypatch, action, adresse):
    monkeypatch.setenv("SCHEDULER", "0")
    appels = []
    monkeypatch.setattr(systask, action, lambda: appels.append(action))
    with TestClient(app, client=(adresse, 50000)) as distant:
        response = distant.post(f"/api/monitor/task/{action}", json={})
    assert response.status_code == 403 and response.json()["code"] == "api.local_only"
    assert appels == []


@pytest.mark.parametrize("action", ["install", "uninstall"])
def test_tache_systeme_corps_non_json_refuse_avant_la_provenance(client, local_client, monkeypatch, action):
    """Même ordre que POST /api/system/open-data-dir : le type du corps (415) est vérifié avant la provenance (403)."""
    monkeypatch.setattr(systask, action, lambda: pytest.fail("la tâche système ne doit pas être touchée"))
    texte = {"content": "{}", "headers": {"content-type": "text/plain"}}
    assert client.post(f"/api/monitor/task/{action}", **texte).status_code == 415
    assert local_client.post(f"/api/monitor/task/{action}", **texte).status_code == 415
    assert client.post(f"/api/monitor/task/{action}", json={}).status_code == 403


def test_les_deux_routes_sont_documentees_comme_locales():
    operations = app.openapi()["paths"]
    for action in ("install", "uninstall"):
        reponses = operations[f"/api/monitor/task/{action}"]["post"]["responses"]
        assert {"400", "403", "415"} <= set(reponses)
