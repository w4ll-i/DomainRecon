# =============================================================================
# DomainRecon - Tests de GET /api/system/vpn (statut du VPN Mullvad)
# =============================================================================
# Le statut vient de scanner/vpn.py, simulé ici : le contrat de la route, sa
# protection par jeton et ses messages FR/EN sont seuls en jeu.
# =============================================================================

import pytest
from fastapi.testclient import TestClient

from domainrecon.api import app as app_module
from domainrecon.api.app import app
from domainrecon.core import config
from domainrecon.scanner import vpn

FIELDS = {"connected", "ip", "country", "provider", "mullvad_cli", "message"}


@pytest.fixture
def client():
    with TestClient(app) as c:
        yield c


def _statut(connected, *, ip=None, country=None, cli=False, error=None):
    """Forme de vpn.get_vpn_status() : renvoyée par une copie neuve à chaque appel."""
    return lambda: {
        "connected": connected,
        "ip": ip,
        "country": country,
        "provider": "Mullvad" if connected else None,
        "mullvad_cli": cli,
        "error": error,
    }


def test_connecte(client, monkeypatch):
    monkeypatch.setattr(vpn, "get_vpn_status", _statut(True, ip="185.213.154.68", country="Sweden", cli=True))

    response = client.get("/api/system/vpn")

    assert response.status_code == 200
    body = response.json()
    assert set(body) == FIELDS  # `error` reste interne
    assert body == {
        "connected": True,
        "ip": "185.213.154.68",
        "country": "Sweden",
        "provider": "Mullvad",
        "mullvad_cli": True,
        "message": "Mullvad VPN est connecté : le trafic sort par un serveur Mullvad.",
    }


def test_non_connecte(client, monkeypatch):
    monkeypatch.setattr(vpn, "get_vpn_status", _statut(False, ip="203.0.113.9", country="Germany"))

    body = client.get("/api/system/vpn").json()

    assert body["connected"] is False and body["provider"] is None
    assert (body["ip"], body["country"], body["mullvad_cli"]) == ("203.0.113.9", "Germany", False)
    assert (
        body["message"] == "Mullvad VPN n'est pas connecté : le trafic sort par votre connexion habituelle."
    )


def test_statut_illisible_repond_200_avec_la_cause(client, monkeypatch):
    erreur = {"$t": "api.vpn_cli_failed", "p": {}}
    monkeypatch.setattr(vpn, "get_vpn_status", _statut(None, cli=True, error=erreur))

    response = client.get("/api/system/vpn")

    assert response.status_code == 200
    body = response.json()
    assert body["connected"] is None and body["provider"] is None and body["mullvad_cli"] is True
    assert body["message"] == (
        "Statut du VPN indisponible : la commande « mullvad status » a échoué "
        "(service Mullvad arrêté ou sortie non reconnue)."
    )


def test_messages_dans_la_langue_de_la_requete(client, monkeypatch):
    erreur = {"$t": "api.vpn_api_failed", "p": {}}
    cas = {
        "connecté": (_statut(True), "Mullvad VPN is connected: traffic leaves through a Mullvad server."),
        "non connecté": (
            _statut(False),
            "Mullvad VPN is not connected: traffic leaves through your usual connection.",
        ),
        "inconnu": (
            _statut(None, error=erreur),
            "VPN status unavailable: am.i.mullvad.net could not be queried (no response or unexpected response).",
        ),
    }
    for nom, (statut, attendu) in cas.items():
        monkeypatch.setattr(vpn, "get_vpn_status", statut)
        assert client.get("/api/system/vpn", params={"lang": "en"}).json()["message"] == attendu, nom
        assert (
            client.get("/api/system/vpn", headers={"Accept-Language": "en-US,en"}).json()["message"]
            == attendu
        )
        assert client.get("/api/system/vpn").json()["message"] != attendu  # français par défaut


def test_route_de_bout_en_bout_sans_cli(client, monkeypatch):
    """Route, get_vpn_status() et lecture de l'API Mullvad (réponse simulée), sans CLI."""
    monkeypatch.setattr(vpn, "_find_cli", lambda: None)
    monkeypatch.setattr(
        vpn,
        "_fetch_json",
        lambda transport: {"ip": "193.32.126.81", "country": "Sweden", "mullvad_exit_ip": True},
    )

    body = client.get("/api/system/vpn").json()

    assert body["connected"] is True and body["ip"] == "193.32.126.81"
    assert body["country"] == "Sweden" and body["mullvad_cli"] is False


def test_protegee_par_le_jeton_d_api(client, monkeypatch):
    monkeypatch.setattr(config, "API_TOKEN", "s3cret-jeton")
    monkeypatch.setattr(vpn, "get_vpn_status", lambda: pytest.fail("statut lu sans jeton"))

    refus = client.get("/api/system/vpn")

    assert refus.status_code == 401
    assert refus.headers["www-authenticate"].startswith("Bearer")
    assert client.get("/api/system/vpn", headers={"X-API-Token": "mauvais"}).status_code == 401

    monkeypatch.setattr(vpn, "get_vpn_status", _statut(False))
    assert client.get("/api/system/vpn", headers={"X-API-Token": "s3cret-jeton"}).status_code == 200
    assert client.get("/api/system/vpn", headers={"Authorization": "Bearer s3cret-jeton"}).status_code == 200


def test_route_publique_seulement_en_lecture_seule():
    """Pas un chemin public, et aucun pilotage : GET seulement."""
    assert "/api/system/vpn" not in app_module.PUBLIC_PATHS
    operations = app_module.openapi_with_token_auth()["paths"]["/api/system/vpn"]
    assert list(operations) == ["get"]
    assert "security" not in operations["get"]  # protégée comme les autres routes de données
    reponse = operations["get"]["responses"]["200"]["content"]["application/json"]["schema"]
    assert reponse["$ref"].endswith("/VpnStatusResponse")


@pytest.mark.parametrize("method", ["post", "put", "delete", "patch"])
def test_aucun_pilotage_du_vpn(client, method):
    response = getattr(client, method)("/api/system/vpn")
    assert response.status_code == 405
