# =============================================================================
# DomainRecon - Tests des aides de sécurité de l'API (api/security.py)
# =============================================================================
# Requêtes locales (is_local_client, require_local_client), requêtes de même
# origine (is_same_origin) et limite de corps propre à un chemin
# (BodySizeLimitMiddleware). Les routes qui s'en servent ont leurs propres tests :
# elles doivent toutes refuser une autre machine de la même façon.
# =============================================================================

import pytest
from fastapi import Depends, FastAPI, Request
from fastapi.testclient import TestClient
from starlette.requests import Request as StarletteRequest

from domainrecon.api import security
from domainrecon.api.app import app
from domainrecon.api.errors import install_error_handlers
from domainrecon.api.routes import system as system_routes
from domainrecon.core import config
from domainrecon.monitor import systask


def _requete(host: str | None, en_tetes: dict[str, str] | None = None) -> StarletteRequest:
    scope = {
        "type": "http",
        "method": "POST",
        "path": "/",
        "headers": [(nom.lower().encode(), valeur.encode()) for nom, valeur in (en_tetes or {}).items()],
        "client": (host, 50000) if host is not None else None,
    }
    return StarletteRequest(scope)


# --- is_local_client ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "adresse",
    ["127.0.0.1", "127.255.255.254", "::1", "localhost", "::ffff:127.0.0.1", "0:0:0:0:0:0:0:1"],
)
def test_adresses_locales(adresse):
    assert security.is_local_client(_requete(adresse)) is True


@pytest.mark.parametrize(
    "adresse",
    [
        "192.168.0.10",
        "10.1.2.3",
        "172.16.0.1",
        "169.254.169.254",
        "8.8.8.8",
        "0.0.0.0",
        "::",
        "fe80::1",
        "2001:db8::1",
        "::ffff:10.0.0.1",
        "::ffff:192.168.0.10",
        "testclient",
        "127.0.0.1.evil.example",
        "",
        None,
    ],
)
def test_adresses_non_locales(adresse):
    assert security.is_local_client(_requete(adresse)) is False


def test_les_en_tetes_de_proxy_ne_donnent_pas_une_adresse_locale():
    requete = _requete(
        "203.0.113.9",
        {
            "X-Forwarded-For": "127.0.0.1",
            "Forwarded": "for=127.0.0.1",
            "X-Real-IP": "127.0.0.1",
            "Host": "localhost",
        },
    )
    assert security.is_local_client(requete) is False


# --- is_same_origin ----------------------------------------------------------------------------


@pytest.mark.parametrize(
    "en_tetes",
    [
        {},
        {"Host": "127.0.0.1:8000"},
        {"Host": "127.0.0.1:8000", "Origin": "http://127.0.0.1:8000"},
        {"Host": "localhost:8000", "Origin": "http://LOCALHOST:8000"},
        {"Host": "[::1]:8000", "Origin": "http://[::1]:8000"},
        {"Host": "localhost", "Origin": "http://localhost"},
        {"Host": "localhost", "Sec-Fetch-Site": "same-origin"},
        {"Host": "localhost", "Sec-Fetch-Site": "none"},
        {"Host": "localhost", "Sec-Fetch-Site": " Same-Origin "},
    ],
)
def test_meme_origine(en_tetes):
    assert security.is_same_origin(_requete("127.0.0.1", en_tetes)) is True


@pytest.mark.parametrize(
    "en_tetes",
    [
        {"Host": "127.0.0.1:8000", "Origin": "http://evil.example"},
        {"Host": "127.0.0.1:8000", "Origin": "http://127.0.0.1:8001"},
        {"Host": "127.0.0.1:8000", "Origin": "http://127.0.0.1"},
        {"Host": "127.0.0.1:8000", "Origin": "null"},
        {"Host": "127.0.0.1:8000", "Origin": ""},
        {"Host": "127.0.0.1:8000", "Origin": "http://[::1"},
        {"Origin": "http://127.0.0.1:8000"},  # sans Host : rien à comparer
        {"Host": "localhost", "Sec-Fetch-Site": "cross-site"},
        {"Host": "localhost", "Sec-Fetch-Site": "same-site"},
        {"Host": "localhost", "Sec-Fetch-Site": ""},
        {"Host": "localhost", "Origin": "http://localhost", "Sec-Fetch-Site": "cross-site"},
    ],
)
def test_autre_origine(en_tetes):
    assert security.is_same_origin(_requete("127.0.0.1", en_tetes)) is False


def test_origine_declaree_dans_cors_origins_de_confiance(monkeypatch):
    """Interface servie ailleurs (CORS_ORIGINS) : son origine est celle de l'opérateur, pas d'un site tiers."""
    monkeypatch.setattr(config, "CORS_ORIGINS", ["http://localhost:5173"])
    en_tetes = {"Host": "127.0.0.1:8000", "Origin": "http://localhost:5173", "Sec-Fetch-Site": "same-site"}
    assert security.is_same_origin(_requete("127.0.0.1", en_tetes)) is True
    assert (
        security.is_same_origin(_requete("127.0.0.1", {**en_tetes, "Origin": "http://evil.example"})) is False
    )
    # Le joker ne désigne aucune origine précise : il ne rend pas une origine quelconque de confiance.
    monkeypatch.setattr(config, "CORS_ORIGINS", ["*"])
    assert (
        security.is_same_origin(_requete("127.0.0.1", {**en_tetes, "Origin": "http://evil.example"})) is False
    )
    monkeypatch.setattr(config, "CORS_ORIGINS", [])
    assert security.is_same_origin(_requete("127.0.0.1", en_tetes)) is False


# --- Les trois sortes de routes locales refusent une autre machine de la même façon -------------


def test_toutes_les_routes_locales_refusent_pareil(monkeypatch):
    """open-data-dir, installation et désinstallation de la tâche système, import : même 403, même corps."""
    monkeypatch.setenv("SCHEDULER", "0")
    monkeypatch.setattr(system_routes, "_open_folder", lambda path: pytest.fail("dossier ouvert"))
    monkeypatch.setattr(systask, "install", lambda: pytest.fail("tâche installée"))
    monkeypatch.setattr(systask, "uninstall", lambda: pytest.fail("tâche retirée"))
    with TestClient(app) as distant:  # adresse « testclient »
        reponses = [
            distant.post("/api/system/open-data-dir?lang=en", json={}),
            distant.post("/api/monitor/task/install?lang=en", json={}),
            distant.post("/api/monitor/task/uninstall?lang=en", json={}),
            distant.post("/api/import?lang=en", files={"file": ("x.db", b"x", "application/octet-stream")}),
        ]
    assert {r.status_code for r in reponses} == {403}
    assert {r.text for r in reponses} == {reponses[0].text}
    assert reponses[0].json() == {
        "detail": "Action reserved for the user of this machine",
        "code": "api.local_only",
        "params": {},
    }


# --- Limite de corps propre à un chemin ----------------------------------------------------------


def _application(limite_import=None, max_bytes=100):
    """Petite application avec la vraie pile d'erreurs : /petit et /gros reçoivent un corps, rendu tel quel."""
    appli = FastAPI()
    install_error_handlers(appli)

    async def lire(request: Request):
        return {"octets": len(await request.body())}

    appli.add_api_route("/petit", lire, methods=["POST"])
    appli.add_api_route("/gros", lire, methods=["POST", "PUT"])
    if limite_import is None:
        appli.add_middleware(security.BodySizeLimitMiddleware, max_bytes=max_bytes)
    else:
        appli.add_middleware(
            security.BodySizeLimitMiddleware, max_bytes=max_bytes, path_limits={"/gros": limite_import}
        )
    return appli


def test_limite_commune_sans_limite_par_chemin():
    with TestClient(_application()) as client:
        assert client.post("/petit", content=b"x" * 100).json() == {"octets": 100}
        refus = client.post("/petit", content=b"x" * 101)
        assert refus.status_code == 413 and refus.json()["code"] == "api.body_too_large"
        assert client.post("/gros", content=b"x" * 101).status_code == 413


def test_limite_propre_a_un_chemin_avec_son_message():
    message = {"$t": "api.import_too_large", "p": {"max": 7}}
    with TestClient(_application(lambda: (1000, message))) as client:
        assert client.post("/gros", content=b"x" * 1000).json() == {"octets": 1000}
        # Content-Length trop grand : refusé d'emblée, avec le message du chemin.
        refus = client.post("/gros", content=b"x" * 1001)
        assert refus.status_code == 413
        assert refus.json() == {
            "detail": "Fichier trop volumineux : 7 Mio au maximum.",
            "code": "api.import_too_large",
            "params": {"max": 7},
        }
        # Par morceaux, sans Content-Length : compté au fil de la lecture, même message.
        refus = client.post("/gros", content=(b"x" * 100 for _ in range(11)))
        assert refus.status_code == 413 and refus.json()["code"] == "api.import_too_large"
        # Les autres chemins gardent la limite commune.
        assert client.post("/petit", content=b"x" * 101).json()["code"] == "api.body_too_large"


def test_limite_par_chemin_reservee_a_post():
    with TestClient(_application(lambda: (1000, {"$t": "api.import_too_large", "p": {"max": 1}}))) as client:
        assert client.put("/gros", content=b"x" * 101).json()["code"] == "api.body_too_large"
        assert client.post("/gros", content=b"x" * 101).status_code == 200


def test_limite_par_chemin_relue_a_chaque_requete():
    limite = {"octets": 1000}
    with TestClient(
        _application(lambda: (limite["octets"], {"$t": "api.import_too_large", "p": {"max": 1}}))
    ) as client:
        assert client.post("/gros", content=b"x" * 500).status_code == 200
        limite["octets"] = 400
        assert client.post("/gros", content=b"x" * 500).status_code == 413


def test_limite_par_chemin_derriere_un_root_path():
    appli = _application(lambda: (1000, {"$t": "api.import_too_large", "p": {"max": 1}}))
    with TestClient(appli, root_path="/recon") as client:
        assert client.post("/recon/gros", content=b"x" * 500).status_code == 200
        assert client.post("/recon/gros", content=b"x" * 1001).json()["code"] == "api.import_too_large"


def test_dependances_local_et_origine_en_isolation():
    appli = FastAPI()
    install_error_handlers(appli)

    @appli.post("/local", dependencies=[Depends(security.require_local_client)])
    async def local():
        return {"ok": True}

    @appli.post("/origine", dependencies=[Depends(security.require_same_origin)])
    async def origine():
        return {"ok": True}

    with (
        TestClient(appli, client=("127.0.0.1", 1)) as ici,
        TestClient(appli, client=("203.0.113.9", 1)) as la_bas,
    ):
        assert ici.post("/local").json() == {"ok": True}
        assert la_bas.post("/local").status_code == 403
        assert ici.post("/origine", headers={"Origin": "http://testserver"}).json() == {"ok": True}
        refus = ici.post("/origine", headers={"Origin": "http://evil.example"})
        assert refus.status_code == 403 and refus.json()["code"] == "api.cross_origin"
