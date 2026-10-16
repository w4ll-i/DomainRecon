# =============================================================================
# DomainRecon - Tests de l'API
# =============================================================================
# Le scan réseau est simulé : ces tests vérifient le contrat de l'API, pas la
# collecte OSINT elle-même.
# =============================================================================

import codecs
import logging
import os
import threading
import time
from datetime import datetime, timedelta, timezone
from html.parser import HTMLParser
from urllib.parse import urlsplit

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.engine import make_url
from sqlalchemy.exc import OperationalError
from sqlalchemy.orm import Session, sessionmaker

from domainrecon.api import app as app_module
from domainrecon.api import schemas, security, spa, storage
from domainrecon.api.app import app
from domainrecon.api.routes import history as history_routes
from domainrecon.api.routes import jobs as jobs_routes
from domainrecon.api.routes import scans as scans_routes
from domainrecon.core import config, database
from domainrecon.core.database import get_db
from domainrecon.core.models import Scan
from domainrecon.scanner import MODULE_NAMES, TargetNotAllowedError, normalize_target

# Comportement des 18 modules historiques : registre ramené à eux (tests/conftest.py).
pytestmark = pytest.mark.usefixtures("registre_historique")

PNG = b"\x89PNG\r\n\x1a\n"


@pytest.fixture
def client():
    with TestClient(app) as c:
        yield c


def _iso(value: str) -> datetime:
    """Lit une date de l'API. fromisoformat n'accepte « Z » qu'à partir de Python 3.11."""
    assert value.endswith("Z"), value
    return datetime.fromisoformat(value[:-1] + "+00:00")


def _statuts_modules(**exceptions) -> dict:
    """module_status complet (tous les modules de l'orchestrateur), « ok » par défaut."""
    statuts = {name: {"status": "ok", "error": None} for name in MODULE_NAMES}
    statuts.update(exceptions)
    return statuts


def _faux_resultat(domain="example.com", screenshot=None, **overrides):
    """Résultat minimal conforme à ce que renvoie perform_full_scan()."""
    result = {
        "domain": domain,
        "ip_address": "93.184.216.34",
        "dns_records": {"A": ["93.184.216.34"]},
        "subdomains": [{"subdomain": f"www.{domain}", "ip": "93.184.216.34"}],
        "security_headers": {"score": "3/7", "measured": True, "headers_found": {"X": "1"}},
        "tls_certificate": {"measured": True, "protocol": "TLSv1.3", "days_remaining": 90},
        "technologies": [],
        "geo_data": {},
        "whois_data": {},
        "open_ports": [{"port": 443, "state": "open", "service": "HTTPS"}],
        "email_security": {"measured": True, "overall_grade": "B"},
        "waf": {"measured": True, "detected": False},
        "redirect_chain": {"measured": True, "forces_https": True, "chain": []},
        "web_files": {},
        "cookie_security": {"measured": True, "cookies_present": False, "score": "N/A"},
        "cors": {"measured": True, "misconfigured": False},
        "reverse_dns": {"ptr": "host.example.net"},
        "subdomain_takeover": [],
        "network_extended": {},
        "security_score": {
            "score": 78,
            "max_score": 100,
            "grade": "B",
            "breakdown": {},
            "coverage": 90,
            "confidence": "high",
        },
        "module_status": _statuts_modules(
            whois_data={"status": "failed", "error": "WHOIS : délai dépassé (10 s)"},
        ),
        "scan_duration": 12.3,
        "screenshot_path": screenshot,
        "status": "partial",
        "error_message": "1 module(s) en échec : whois_data",
    }
    result.update(overrides)
    return result


def _simuler_scan(monkeypatch, **overrides):
    """Remplace perform_full_scan ; renvoie la liste des cibles reçues."""
    appels = []

    async def fake_scan(domain):
        appels.append(domain)
        return _faux_resultat(domain, **overrides)

    monkeypatch.setattr(scans_routes, "perform_full_scan", fake_scan)
    return appels


def _creer_scan(client, monkeypatch, domain, **overrides) -> dict:
    _simuler_scan(monkeypatch, **overrides)
    response = client.post("/api/scan", json={"domain": domain})
    assert response.status_code == 200, response.text
    return response.json()


# =============================================================================
# Santé
# =============================================================================


def test_health(client):
    response = client.get("/api/health")
    assert response.status_code == 200
    body = response.json()
    assert body["api"] == "healthy"
    assert body["database"] == "connected"
    assert body["version"] == config.APP_VERSION


def test_health_503_si_la_base_est_injoignable(client):
    class SessionEnPanne:
        def execute(self, *args, **kwargs):
            raise OperationalError("SELECT 1", {}, Exception("unable to open /chemin/secret.db"))

    app.dependency_overrides[get_db] = lambda: SessionEnPanne()
    try:
        response = client.get("/api/health")
    finally:
        app.dependency_overrides.pop(get_db, None)

    assert response.status_code == 503
    assert response.json()["database"] == "error"
    # Le détail de l'exception reste dans les journaux.
    assert "secret" not in response.text


def test_health_503_si_la_base_est_en_lecture_seule(client, monkeypatch):
    monkeypatch.setattr(storage, "_database_writable", lambda: False)
    response = client.get("/api/health")
    assert response.status_code == 503
    assert response.json()["database"] == "read-only"


def test_erreur_de_base_renvoie_503_generique(client):
    class SessionVerrouillee:
        def query(self, *args, **kwargs):
            raise OperationalError("SELECT", {}, Exception("database is locked : détail interne"))

    app.dependency_overrides[get_db] = lambda: SessionVerrouillee()
    try:
        response = client.get("/api/history")
    finally:
        app.dependency_overrides.pop(get_db, None)

    assert response.status_code == 503
    assert "interne" not in response.text


def test_exception_non_geree_renvoie_500_generique(client, monkeypatch):
    def boom(scan):
        raise RuntimeError("détail très interne")

    _creer_scan(client, monkeypatch, "erreur-500.com")
    monkeypatch.setattr(history_routes, "_scan_to_summary", boom)

    response = client.get("/api/history")
    assert response.status_code == 500
    assert response.json() == {
        "detail": "Erreur interne du serveur.",
        "code": "api.internal_error",
        "params": {},
    }
    # Même une erreur 500 porte les en-têtes de sécurité.
    assert response.headers["x-content-type-options"] == "nosniff"


# =============================================================================
# Cycle de vie d'un scan
# =============================================================================


def test_scan_puis_lecture_puis_suppression(client, monkeypatch):
    body = _creer_scan(client, monkeypatch, "example.com")
    scan_id = body["id"]

    # Le statut par module est bien exposé au client.
    assert body["module_status"]["whois_data"]["status"] == "failed"
    assert body["scan_duration"] == 12.3
    assert body["reverse_dns"] == {"ptr": "host.example.net"}
    # L'horodatage porte le fuseau UTC, sinon le navigateur l'affiche décalé.
    assert _iso(body["scan_timestamp"]).utcoffset().total_seconds() == 0

    fetched = client.get(f"/api/scan/{scan_id}")
    assert fetched.status_code == 200
    assert fetched.json()["domain"] == "example.com"
    assert fetched.json()["reverse_dns"] == {"ptr": "host.example.net"}

    assert client.delete(f"/api/scan/{scan_id}").status_code == 200
    assert client.get(f"/api/scan/{scan_id}").status_code == 404


def test_cible_invalide_renvoie_400(client, monkeypatch):
    async def fake_scan(domain):
        raise ValueError(f"Cible invalide : {domain!r}")

    monkeypatch.setattr(scans_routes, "perform_full_scan", fake_scan)

    response = client.post("/api/scan", json={"domain": "pas une cible"})
    assert response.status_code == 400
    assert "invalide" in response.json()["detail"]


@pytest.mark.parametrize(
    ("cible", "code"),
    [("pas une cible", 400), ("../../etc/passwd", 400), ("exa mple.com", 400), ("xx", 422)],
)
def test_cible_invalide_sans_simulation(client, cible, code):
    """TEST-10 d : vraie validation (normalize_target puis is_valid_target), sans simulation."""
    avant = client.get("/api/history?limit=1").json()["total"]
    response = client.post("/api/scan", json={"domain": cible})
    assert response.status_code == code, response.text
    if code == 400:
        assert "invalide" in response.json()["detail"].lower()
    assert client.get("/api/history?limit=1").json()["total"] == avant


def test_cible_non_autorisee_renvoie_400(client, monkeypatch):
    async def fake_scan(domain):
        raise TargetNotAllowedError("Cible refusée : 10.0.0.1 n'est pas une adresse publique")

    monkeypatch.setattr(scans_routes, "perform_full_scan", fake_scan)

    response = client.post("/api/scan", json={"domain": "intranet.local"})
    assert response.status_code == 400
    assert response.json() == {
        "detail": "Cible refusée : 10.0.0.1 n'est pas une adresse publique",
        "code": None,
        "params": {},
    }


@pytest.mark.parametrize(
    "cible",
    [
        "169.254.169.254",
        "http://169.254.169.254/latest/meta-data/",
        "10.0.0.1",
        "[::1]",
        "127.1",
        "0x7f000001",
    ],
)
def test_scan_reel_refuse_les_cibles_internes(client, monkeypatch, cible):
    """Chaîne réelle, sans simulation : API → perform_full_scan → politique de cibles.

    IP littérales ou formes refusées dès la validation syntaxique : aucune requête
    DNS ni connexion. 400, et rien n'est enregistré.
    """
    monkeypatch.setenv("ALLOW_PRIVATE_TARGETS", "0")
    avant = client.get("/api/history?limit=1").json()["total"]

    response = client.post("/api/scan", json={"domain": cible})

    assert response.status_code == 400, response.text
    assert client.get("/api/history?limit=1").json()["total"] == avant


def test_echec_du_scan_renvoie_un_message_generique(client, monkeypatch):
    async def fake_scan(domain):
        raise RuntimeError("chaîne de connexion secrète")

    monkeypatch.setattr(scans_routes, "perform_full_scan", fake_scan)

    response = client.post("/api/scan", json={"domain": "example.com"})
    assert response.status_code == 500
    assert "secrète" not in response.text


class _SessionQuiEchoue(Session):
    """Session dont les `echecs` premiers commits lèvent une OperationalError."""

    echecs = 0

    def commit(self):
        if _SessionQuiEchoue.echecs > 0:
            _SessionQuiEchoue.echecs -= 1
            raise OperationalError("INSERT", {}, Exception("database is locked"))
        super().commit()


def _sessions_qui_echouent(monkeypatch, echecs):
    _SessionQuiEchoue.echecs = echecs
    monkeypatch.setattr(storage, "SAVE_RETRY_DELAY", 0)
    monkeypatch.setattr(
        storage,
        "SessionLocal",
        sessionmaker(bind=database.engine, class_=_SessionQuiEchoue, autoflush=False),
    )


def test_enregistrement_reessaye_une_fois_si_la_base_est_verrouillee(client, monkeypatch):
    _sessions_qui_echouent(monkeypatch, echecs=1)
    body = _creer_scan(client, monkeypatch, "reessai.com")
    assert client.get(f"/api/scan/{body['id']}").status_code == 200


def test_echec_d_enregistrement_supprime_la_capture(client, monkeypatch):
    storage.SCREENSHOTS_DIR.mkdir(parents=True, exist_ok=True)
    capture = storage.SCREENSHOTS_DIR / "echec_enregistrement_1.png"
    capture.write_bytes(PNG)
    _sessions_qui_echouent(monkeypatch, echecs=storage.SAVE_ATTEMPTS)
    _simuler_scan(monkeypatch, screenshot=capture.name)

    try:
        response = client.post("/api/scan", json={"domain": "echec-enregistrement.com"})
        assert response.status_code == 500
        assert "locked" not in response.text
        assert not capture.exists()  # pas d'orpheline
    finally:
        capture.unlink(missing_ok=True)


def test_scan_inexistant(client):
    assert client.get("/api/scan/999999").status_code == 404
    assert client.delete("/api/scan/999999").status_code == 404


@pytest.mark.parametrize("scan_id", ["0", "-1", "2147483648", "99999999999999999999"])
def test_identifiant_hors_plage_jamais_500(client, scan_id):
    assert client.get(f"/api/scan/{scan_id}").status_code == 422
    assert client.delete(f"/api/scan/{scan_id}").status_code == 422
    assert client.patch(f"/api/scan/{scan_id}/meta", json={"notes": "x"}).status_code == 422


# =============================================================================
# Dates : ISO 8601 UTC avec suffixe Z partout
# =============================================================================


def test_toutes_les_dates_sont_en_utc_avec_suffixe_z(client, monkeypatch):
    avant = datetime.now(timezone.utc)
    body = _creer_scan(client, monkeypatch, "dates-utc.com")
    _creer_scan(client, monkeypatch, "dates-utc.com")
    apres = datetime.now(timezone.utc)

    dates = [
        body["scan_timestamp"],
        client.get(f"/api/scan/{body['id']}").json()["scan_timestamp"],
        *(s["scan_timestamp"] for s in client.get("/api/history?domain=dates-utc.com").json()["scans"]),
        *(t["timestamp"] for t in client.get("/api/dns-timeline/dates-utc.com").json()["timeline"]),
    ]
    assert len(dates) == 6
    for value in dates:
        # Heure UTC réelle, pas l'heure locale étiquetée UTC.
        assert avant.replace(microsecond=0) <= _iso(value) <= apres


def test_as_utc_convertit_les_dates_avec_fuseau():
    paris = timezone(timedelta(hours=2))
    assert schemas.iso_utc(datetime(2026, 1, 1, 12, 0, tzinfo=paris)) == "2026-01-01T10:00:00Z"
    assert schemas.iso_utc(datetime(2026, 1, 1, 12, 0)) == "2026-01-01T12:00:00Z"


# =============================================================================
# Content-Type, taille du corps
# =============================================================================


@pytest.mark.parametrize(
    "headers",
    [
        {"Content-Type": "text/plain"},
        {"Content-Type": "application/x-www-form-urlencoded"},
        {"Content-Type": "multipart/form-data; boundary=x"},
        {},
    ],
)
def test_scan_exige_du_json(client, monkeypatch, headers):
    appels = _simuler_scan(monkeypatch)
    response = client.post("/api/scan", content=b'{"domain": "example.com"}', headers=headers)
    assert response.status_code == 415
    assert appels == []


def test_scan_accepte_json_avec_charset(client, monkeypatch):
    _simuler_scan(monkeypatch)
    response = client.post(
        "/api/scan",
        content=b'{"domain": "charset.com"}',
        headers={"Content-Type": "application/json; charset=utf-8"},
    )
    assert response.status_code == 200


def test_meta_exige_du_json(client, monkeypatch):
    scan_id = _creer_scan(client, monkeypatch, "meta-json.com")["id"]
    response = client.patch(
        f"/api/scan/{scan_id}/meta", content=b'{"notes": "x"}', headers={"Content-Type": "text/plain"}
    )
    assert response.status_code == 415


def test_corps_trop_volumineux_413(client, monkeypatch):
    appels = _simuler_scan(monkeypatch)
    gros = b'{"domain": "' + b"a" * security.MAX_REQUEST_BODY_BYTES + b'"}'

    response = client.post("/api/scan", content=gros, headers={"Content-Type": "application/json"})
    assert response.status_code == 413

    # Envoi par morceaux, sans Content-Length.
    def morceaux():
        for i in range(0, len(gros), 64 * 1024):
            yield gros[i : i + 64 * 1024]

    response = client.post("/api/scan", content=morceaux(), headers={"Content-Type": "application/json"})
    assert response.status_code == 413
    assert appels == []


# =============================================================================
# Plafond de scans simultanés
# =============================================================================


def test_trop_de_scans_simultanes_renvoie_429(client, monkeypatch):
    slots = threading.BoundedSemaphore(1)
    monkeypatch.setattr(jobs_routes.manager, "slots", slots)
    appels = _simuler_scan(monkeypatch)

    assert slots.acquire(blocking=False)  # un scan « en cours »
    try:
        response = client.post("/api/scan", json={"domain": "occupe.com"})
        assert response.status_code == 429
        assert response.headers["retry-after"]
        assert "réessayez" in response.json()["detail"]
        assert appels == []
    finally:
        slots.release()

    assert client.post("/api/scan", json={"domain": "occupe.com"}).status_code == 200


def test_l_emplacement_est_libere_meme_si_le_scan_echoue(client, monkeypatch):
    monkeypatch.setattr(jobs_routes.manager, "slots", threading.BoundedSemaphore(1))

    async def fake_scan(domain):
        raise ValueError("Cible invalide")

    monkeypatch.setattr(scans_routes, "perform_full_scan", fake_scan)
    assert client.post("/api/scan", json={"domain": "echec.com"}).status_code == 400
    assert client.post("/api/scan", json={"domain": "echec.com"}).status_code == 400

    _simuler_scan(monkeypatch)
    assert client.post("/api/scan", json={"domain": "apres-echec.com"}).status_code == 200


# =============================================================================
# Authentification par jeton
# =============================================================================


def test_sans_jeton_configure_l_api_est_ouverte(client):
    assert config.API_TOKEN in (None, "")
    assert client.get("/api/history").status_code == 200


def test_jeton_exige_quand_api_token_est_defini(client, monkeypatch):
    monkeypatch.setattr(config, "API_TOKEN", "s3cret-jeton")
    appels = _simuler_scan(monkeypatch)

    refus = client.get("/api/history")
    assert refus.status_code == 401
    assert refus.headers["www-authenticate"].startswith("Bearer")
    assert refus.headers["x-frame-options"] == "DENY"

    for headers in (
        {"Authorization": "Bearer mauvais"},
        {"X-API-Token": "mauvais"},
        {"Authorization": "Basic s3cret-jeton"},
        {"Authorization": "Bearer "},
    ):
        assert client.get("/api/history", headers=headers).status_code == 401

    for headers in (
        {"Authorization": "Bearer s3cret-jeton"},
        {"Authorization": "bearer s3cret-jeton"},
        {"X-API-Token": "s3cret-jeton"},
    ):
        assert client.get("/api/history", headers=headers).status_code == 200

    # Toutes les routes de données sont protégées, captures comprises, ainsi
    # que tout chemin inconnu (liste de chemins publics, pas de préfixe).
    assert client.post("/api/scan", json={"domain": "example.com"}).status_code == 401
    assert appels == []
    assert client.get("/api/screenshot/capture_1.png").status_code == 401
    assert client.get("/api/route-inconnue").status_code == 401
    assert client.get("/api").status_code == 401
    # Interface (GET hors /api) : publique et sans donnée ; toute autre méthode exige le jeton.
    assert client.get("/chemin-inconnu").status_code == 200
    assert client.post("/chemin-inconnu").status_code == 401

    # Sauf /api/health (supervision), le frontend et la documentation (sans
    # donnée de scan), si elle est activée.
    assert client.get("/api/health").status_code == 200
    assert client.get("/").status_code == 200
    for path in ("/api/docs", "/api/redoc", "/api/openapi.json"):
        assert client.get(path).status_code == (200 if config.API_DOCS_ENABLED else 401), path


def test_chemins_publics():
    documentation = {"/api/docs", "/api/redoc", "/api/openapi.json", "/docs/oauth2-redirect"}
    attendus = {"/", "/api/health"} | (documentation if config.API_DOCS_ENABLED else set())
    assert app_module.PUBLIC_PATHS == attendus


def test_jeton_exige_derriere_un_root_path(monkeypatch):
    """uvicorn --root-path /recon : scope["path"] vaut « /recon/api/history ».

    Le contrôle porte sur le chemin vu par le routeur, sinon il était contourné.
    """
    monkeypatch.setattr(config, "API_TOKEN", "s3cret-jeton")
    with TestClient(app, root_path="/recon") as proxy:
        assert proxy.get("/recon/api/history").status_code == 401
        assert proxy.post("/recon/api/scan", json={"domain": "example.com"}).status_code == 401
        assert proxy.get("/recon/api/history", headers={"X-API-Token": "s3cret-jeton"}).status_code == 200
        assert proxy.get("/recon/api/health").status_code == 200
        assert proxy.get("/recon/").status_code == 200


@pytest.mark.parametrize(
    ("path", "root_path", "attendu"),
    [
        ("/api/history", "", "/api/history"),
        ("/recon/api/history", "/recon", "/api/history"),
        ("/recon", "/recon", "/"),
        ("/recon/", "/recon", "/"),
        # Préfixe partiel : le routeur garde le chemin entier (et ne trouve rien).
        ("/reconapi/history", "/recon", "/reconapi/history"),
        ("/api/history", "/recon", "/api/history"),
    ],
)
def test_route_path(path, root_path, attendu):
    assert security._route_path({"path": path, "root_path": root_path}) == attendu


def test_schema_openapi_declare_le_jeton(client):
    """Le bouton « Authorize » de /api/docs envoie le jeton sous l'une des formes acceptées."""
    schema = app_module.openapi_with_token_auth()
    if config.API_DOCS_ENABLED:
        assert client.get("/api/openapi.json").json() == schema
    schemes = schema["components"]["securitySchemes"]
    assert schemes["ApiToken"] == {
        **schemes["ApiToken"],
        "type": "apiKey",
        "in": "header",
        "name": "X-API-Token",
    }
    assert schemes["Bearer"] == {**schemes["Bearer"], "type": "http", "scheme": "bearer"}
    # L'une ou l'autre forme suffit ; /api/health n'exige rien.
    assert schema["security"] == [{"ApiToken": []}, {"Bearer": []}]
    assert schema["paths"]["/api/health"]["get"]["security"] == []
    assert "security" not in schema["paths"]["/api/history"]["get"]


def test_cors_autorise_l_en_tete_du_jeton(monkeypatch):
    """Préflight CORS d'une origine configurée : jamais bloqué par le jeton, en-tête permis."""
    monkeypatch.setattr(config, "API_TOKEN", "s3cret-jeton")
    monkeypatch.setattr(config, "CORS_ORIGINS", ["https://front.example"])
    # La pile de middlewares est reconstruite avec la configuration modifiée.
    monkeypatch.setattr(app, "middleware_stack", None)
    response = TestClient(app).options(
        "/api/history",
        headers={
            "Origin": "https://front.example",
            "Access-Control-Request-Method": "GET",
            "Access-Control-Request-Headers": "x-api-token",
        },
    )
    assert response.status_code == 200
    assert response.headers["access-control-allow-origin"] == "https://front.example"
    assert "x-api-token" in response.headers["access-control-allow-headers"].lower()


@pytest.mark.parametrize(
    "origine", ["http://localhost:8000", "http://127.0.0.1:8000", "https://tiers.example"]
)
def test_cors_aucune_origine_autorisee_par_defaut(client, origine):
    """Revue finale I1 : le défaut ne doit pas ouvrir l'API à une autre application locale (même port 8000).

    L'interface est servie par la même origine : aucune origine n'a besoin du CORS.
    """
    assert config.CORS_ORIGINS == []
    preflight = client.options(
        "/api/history",
        headers={
            "Origin": origine,
            "Access-Control-Request-Method": "DELETE",
            "Access-Control-Request-Headers": "content-type",
        },
    )
    assert preflight.status_code == 400
    assert "access-control-allow-origin" not in preflight.headers
    lecture = client.get("/api/history", headers={"Origin": origine})
    assert lecture.status_code == 200  # la requête passe (même machine), le navigateur bloque la lecture
    assert "access-control-allow-origin" not in lecture.headers


# =============================================================================
# Contrôle de l'en-tête Host (DNS rebinding)
# =============================================================================


def test_hote_non_autorise_refuse(monkeypatch):
    monkeypatch.setattr(config, "ALLOWED_HOSTS", ["localhost", "127.0.0.1", "::1"])
    # La pile de middlewares est reconstruite avec la configuration modifiée ;
    # monkeypatch remet l'ancienne en fin de test.
    monkeypatch.setattr(app, "middleware_stack", None)

    refus = TestClient(app).get("/api/health")  # Host: testserver
    assert refus.status_code == 400
    assert refus.headers["x-content-type-options"] == "nosniff"
    assert TestClient(app, base_url="http://rebind.attacker.test:8000").get("/api/health").status_code == 400

    for base_url in ("http://localhost:8000", "http://127.0.0.1:8000", "http://[::1]:8000"):
        assert TestClient(app, base_url=base_url).get("/api/health").status_code == 200, base_url


def test_hote_refuse_en_json_d_erreur_dans_la_langue(monkeypatch):
    """Revue finale M4 : le 400 respecte le contrat {detail, code, params}, pas un texte brut."""
    monkeypatch.setattr(config, "ALLOWED_HOSTS", ["localhost"])
    monkeypatch.setattr(app, "middleware_stack", None)
    client = TestClient(app, base_url="http://192.168.1.10:47815")

    francais = client.get("/api/health")
    assert francais.status_code == 400
    assert francais.headers["content-type"].startswith("application/json")
    assert francais.json() == {
        "detail": "Adresse (en-tête Host) non autorisée : ajoutez-la à ALLOWED_HOSTS.",
        "code": "api.invalid_host",
        "params": {},
    }
    anglais = client.get("/api/health?lang=en").json()
    assert anglais == {
        "detail": "Host header not allowed: add it to ALLOWED_HOSTS.",
        "code": "api.invalid_host",
        "params": {},
    }
    # Même contrôle sur l'interface : la page « Invalid host header » n'existe plus.
    assert client.get("/").json()["code"] == "api.invalid_host"


@pytest.mark.parametrize(
    ("en_tete", "attendu"),
    [
        ("localhost", "localhost"),
        ("LocalHost:8000", "localhost"),
        ("127.0.0.1:47815", "127.0.0.1"),
        ("[::1]:8000", "[::1]"),
        ("[::1]", "[::1]"),
        ("recon.example.com", "recon.example.com"),
        ("", None),
        ("localhost:", None),
        ("localhost:port", None),
        ("[::1", None),
        ("[::1]x", None),
        ("[pas-une-ip]:80", None),
        ("evil.com/chemin", None),
        ("bon.example@evil.com", None),
        ("deux mots", None),
    ],
)
def test_hote_de_l_en_tete_host(en_tete, attendu):
    scope = {"type": "http", "headers": [(b"host", en_tete.encode("latin-1"))]}
    assert security._request_host(scope) == attendu


def test_hote_absent_refuse(monkeypatch):
    monkeypatch.setattr(config, "ALLOWED_HOSTS", ["localhost"])
    monkeypatch.setattr(app, "middleware_stack", None)
    sans_hote = TestClient(app, base_url="http://localhost", headers={"Host": ""})
    assert sans_hote.get("/api/health").json()["code"] == "api.invalid_host"


def test_motifs_d_hotes_autorises():
    assert security.trusted_host_patterns(["*"]) == ["*"]
    assert security.trusted_host_patterns(["localhost", "*"]) == ["*"]
    assert security.trusted_host_patterns(
        [
            " LocalHost ",
            "::1",
            "[0:0:0:0:0:0:0:1]",
            "recon.example.com:8000",
            "*.example.org",
            "mau*vais",
            "*mauvais.com",
            "",
        ]
    ) == ["localhost", "[::1]", "::1", "recon.example.com", "*.example.org"]


# =============================================================================
# En-têtes de sécurité
# =============================================================================


@pytest.mark.parametrize("path", ["/", "/api/health", "/api/scan/999999", "/api/docs"])
def test_entetes_de_securite(client, path):
    headers = client.get(path).headers
    assert headers["x-content-type-options"] == "nosniff"
    assert headers["referrer-policy"] == "no-referrer"
    assert headers["x-frame-options"] == "DENY"
    assert headers["content-security-policy"]


# CSP des réponses qui ne sont pas des pages : rien n'est chargé ni exécuté ;
# styles en ligne permis pour la visionneuse d'images du navigateur.
CSP_API = {"default-src": ["'none'"], "style-src": ["'unsafe-inline'"], "frame-ancestors": ["'none'"]}


def _csp_texte(politique: str) -> dict[str, list[str]]:
    """Directives d'une Content-Security-Policy : nom -> sources."""
    directives = {}
    for part in politique.split(";"):
        name, *sources = part.split()
        directives[name] = sources
    return directives


def _csp(response) -> dict[str, list[str]]:
    """Directives de la Content-Security-Policy d'une réponse."""
    return _csp_texte(response.headers["content-security-policy"])


class _RessourcesDuFrontend(HTMLParser):
    """URL chargées par la page construite, rangées par directive CSP."""

    def __init__(self) -> None:
        super().__init__()
        self.urls: dict[str, list[str]] = {"script-src": [], "style-src": [], "img-src": []}

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        rel = (attrs.get("rel") or "").lower().split()
        if tag == "script" and attrs.get("src"):
            self.urls["script-src"].append(attrs["src"])
        elif tag == "link" and "stylesheet" in rel:
            self.urls["style-src"].append(attrs["href"])
        elif tag == "link" and "icon" in rel:
            self.urls["img-src"].append(attrs["href"])
        elif tag == "img" and attrs.get("src"):
            self.urls["img-src"].append(attrs["src"])


@pytest.mark.parametrize(
    "path",
    [
        "/api/health",
        "/api/history",
        "/api/scan/999999",
        "/api/openapi.json",
        "/api/screenshot/absente.png",
        "/api/route-inconnue",
    ],
)
def test_csp_stricte_hors_des_pages(client, path):
    """JSON de l'API, erreurs, routes /api inconnues : rien n'est chargé ni exécuté, ni encadré."""
    assert _csp(client.get(path)) == CSP_API


def test_csp_stricte_sur_une_capture(client):
    storage.SCREENSHOTS_DIR.mkdir(parents=True, exist_ok=True)
    fichier = storage.SCREENSHOTS_DIR / "csp_exemple_com_1700000000.png"
    fichier.write_bytes(PNG)
    try:
        response = client.get(f"/api/screenshot/{fichier.name}")
        assert response.status_code == 200
        assert _csp(response) == CSP_API
    finally:
        fichier.unlink(missing_ok=True)


def test_csp_du_frontend_compatible_avec_la_page(client, web_build):
    """La CSP de « / » autorise chaque ressource de la page construite (même origine)."""
    response = client.get("/")
    assert response.status_code == 200
    csp = _csp(response)
    for directive in ("default-src", "script-src", "style-src", "font-src", "connect-src"):
        assert csp[directive] == ["'self'"], directive
    assert csp["object-src"] == ["'none'"]
    assert csp["base-uri"] == ["'none'"]
    assert csp["form-action"] == ["'self'"]
    assert csp["frame-ancestors"] == ["'none'"]
    assert csp["img-src"] == ["'self'", "data:", "blob:"]
    ressources = _RessourcesDuFrontend()
    ressources.feed(response.text)
    urls = [url for liste in ressources.urls.values() for url in liste]
    assert urls  # scripts, feuilles de style et icône de la page
    for url in urls:
        assert urlsplit(url).scheme == "" and url.startswith("/"), f"{url} : ressource hors de l'origine"
        assert client.get(url).status_code == 200, url


def test_csp_du_frontend_sans_origine_externe():
    """Aucun CDN ni tuile en ligne : aucune origine externe (carte vectorielle embarquée)."""
    externes = {
        directive: [source for source in sources if source.startswith("https://")]
        for directive, sources in _csp_texte(security.FRONTEND_CSP).items()
    }
    assert {d: s for d, s in externes.items() if s} == {}


def test_csp_du_frontend_interdit_le_code_en_ligne():
    """Ni script ni style en ligne, ni eval : une donnée de scan injectée ne s'exécute pas."""
    for sources in _csp_texte(security.FRONTEND_CSP).values():
        assert not {"'unsafe-inline'", "'unsafe-eval'", "'unsafe-hashes'"} & set(sources)


@pytest.mark.skipif(not config.API_DOCS_ENABLED, reason="documentation désactivée (API_DOCS=0)")
@pytest.mark.parametrize("path", ["/api/docs", "/api/redoc", "/docs/oauth2-redirect"])
def test_csp_de_la_documentation_laisse_charger_ses_scripts(client, path):
    """Swagger UI et ReDoc chargent leurs scripts sur cdn.jsdelivr.net : aucune directive de chargement."""
    response = client.get(path)
    assert response.status_code == 200
    csp = _csp(response)
    assert not {"default-src", "script-src", "style-src", "img-src", "connect-src", "worker-src"} & set(csp)
    assert csp == {"object-src": ["'none'"], "base-uri": ["'none'"], "frame-ancestors": ["'none'"]}


def test_csp_choisie_derriere_un_root_path():
    with TestClient(app, root_path="/recon") as proxy:
        assert _csp(proxy.get("/recon/"))["connect-src"] == ["'self'"]
        assert _csp(proxy.get("/recon/api/health")) == CSP_API


def test_csp_sur_une_erreur_500(client, monkeypatch, web_build):
    """Le 500 générique produit par le middleware porte aussi la CSP."""

    def panne(*args, **kwargs):
        raise RuntimeError("panne")

    monkeypatch.setattr(spa, "FileResponse", panne)
    response = client.get("/")
    assert response.status_code == 500
    assert _csp(response)["default-src"] == ["'self'"]


# =============================================================================
# Tags & notes
# =============================================================================


def test_meta_tags_nettoyes_et_dedoublonnes(client, monkeypatch):
    scan_id = _creer_scan(client, monkeypatch, "tags.com")["id"]

    response = client.patch(f"/api/scan/{scan_id}/meta", json={"tags": [" prod ", "Prod", "web", "web "]})
    assert response.status_code == 200
    assert response.json()["tags"] == ["prod", "web"]

    # Notes seules : les tags ne bougent pas.
    response = client.patch(f"/api/scan/{scan_id}/meta", json={"notes": "À surveiller\nligne 2\tfin"})
    assert response.json()["tags"] == ["prod", "web"]
    assert response.json()["notes"] == "À surveiller\nligne 2\tfin"

    # Tags seuls : les notes ne bougent pas ; une liste vide efface les tags.
    response = client.patch(f"/api/scan/{scan_id}/meta", json={"tags": []})
    assert response.json()["tags"] == []
    assert response.json()["notes"] == "À surveiller\nligne 2\tfin"

    assert client.get(f"/api/scan/{scan_id}").json()["notes"] == "À surveiller\nligne 2\tfin"


def test_meta_limites_acceptees(client, monkeypatch):
    scan_id = _creer_scan(client, monkeypatch, "limites.com")["id"]
    payload = {
        "tags": [f"tag-{i}" for i in range(schemas.MAX_TAGS)] + ["TAG-0"],  # doublon ignoré
        "notes": "n" * schemas.MAX_NOTES_LENGTH,
    }
    response = client.patch(f"/api/scan/{scan_id}/meta", json=payload)
    assert response.status_code == 200
    assert len(response.json()["tags"]) == schemas.MAX_TAGS

    response = client.patch(f"/api/scan/{scan_id}/meta", json={"tags": ["x" * schemas.MAX_TAG_LENGTH]})
    assert response.status_code == 200


@pytest.mark.parametrize(
    "payload",
    [
        {"tags": [42]},
        {"tags": [{"x": 1}]},
        {"tags": [None]},
        {"tags": [["imbriqué"]]},
        {"tags": "pas une liste"},
        {"tags": ["x" * 51]},
        {"tags": ["   "]},
        {"tags": [""]},
        {"tags": ["a\x00b"]},
        {"tags": ["ligne\nsuivante"]},
        {"tags": ["inversé\u202e"]},
        {"tags": [f"t{i}" for i in range(21)]},
        {"notes": "x" * 10_001},
        {"notes": "nul\x00"},
        {"notes": 123},
        {"champ_inconnu": "x"},
    ],
)
def test_meta_refuse_les_valeurs_invalides(client, monkeypatch, payload):
    scan_id = _creer_scan(client, monkeypatch, "meta-invalide.com")["id"]
    response = client.patch(f"/api/scan/{scan_id}/meta", json=payload)
    assert response.status_code == 422
    assert client.get(f"/api/scan/{scan_id}").json()["tags"] == []


def test_meta_scan_inexistant(client):
    assert client.patch("/api/scan/999999/meta", json={"tags": ["x"]}).status_code == 404


def test_anciens_tags_non_textuels_ignores_a_la_lecture(client):
    with database.SessionLocal() as db:
        scan = Scan(domain="anciens-tags.com", status="success", tags=[{"x": 1}, "ok", 3])
        db.add(scan)
        db.commit()
        scan_id = scan.id

    assert client.get(f"/api/scan/{scan_id}").json()["tags"] == ["ok"]
    history = client.get("/api/history?domain=anciens-tags.com").json()
    assert history["scans"][0]["tags"] == ["ok"]


# =============================================================================
# Historique
# =============================================================================


def test_historique_renvoie_une_vue_allegee(client, monkeypatch):
    _creer_scan(client, monkeypatch, "history-test.com")

    body = client.get("/api/history?limit=5&domain=history-test.com").json()
    entry = body["scans"][0]

    # Les blobs JSON complets ne doivent pas transiter dans les listes.
    assert "dns_records" not in entry
    assert entry["subdomains_count"] == 1
    assert entry["open_ports_count"] == 1
    assert entry["security_score"]["grade"] == "B"


_ECHEC_CRTSH = {"status": "failed", "error": "crt.sh : délai dépassé (30 s)"}
_PORTS_HORS_DELAI = {"status": "timeout", "error": "Délai dépassé (60 s)"}
_SANS_OBJET_IP = {"status": "skipped", "error": "Sans objet pour une adresse IP"}


def test_historique_compteurs_null_si_le_module_n_a_rien_mesure(client, monkeypatch):
    """Régression : une énumération en échec ou sans objet s'affichait « 0 subs »."""
    _creer_scan(
        client,
        monkeypatch,
        "echec.compteurs-nuls.com",
        subdomains=[],
        open_ports=[],
        module_status=_statuts_modules(subdomains=_ECHEC_CRTSH, open_ports=_PORTS_HORS_DELAI),
    )
    _creer_scan(
        client,
        monkeypatch,
        "ip.compteurs-nuls.com",
        subdomains=[],
        module_status=_statuts_modules(subdomains=_SANS_OBJET_IP),
    )
    # Mesuré, rien trouvé : 0, pas null.
    _creer_scan(client, monkeypatch, "vides.compteurs-nuls.com", subdomains=[], open_ports=[])

    scans = {s["domain"]: s for s in client.get("/api/history?domain=compteurs-nuls").json()["scans"]}
    compteurs = {d: (s["subdomains_count"], s["open_ports_count"]) for d, s in scans.items()}
    assert compteurs == {
        "echec.compteurs-nuls.com": (None, None),
        "ip.compteurs-nuls.com": (None, 1),
        "vides.compteurs-nuls.com": (0, 0),
    }


def test_historique_compte_le_total_des_sous_domaines_trouves(client, monkeypatch):
    """Liste plafonnée par le scanner : l'historique annonce le total trouvé, pas la taille gardée."""
    _creer_scan(
        client,
        monkeypatch,
        "plafond.compteurs-total.com",
        subdomains=[{"subdomain": "www.plafond.compteurs-total.com", "ip": None, "resolution": "not_tested"}],
        module_status=_statuts_modules(subdomains={"status": "ok", "error": None, "total_found": 9974}),
    )
    (entry,) = client.get("/api/history?domain=compteurs-total").json()["scans"]
    assert entry["subdomains_count"] == 9974


def test_historique_compteurs_des_scans_sans_module_status(client):
    """Scan antérieur à module_status : les listes enregistrées sont comptées telles quelles."""
    with database.SessionLocal() as db:
        db.add(
            Scan(
                domain="compteurs-ancien.com",
                status="success",
                subdomains=[{"subdomain": "www.compteurs-ancien.com"}],
                open_ports=[],
            )
        )
        db.commit()

    (entry,) = client.get("/api/history?domain=compteurs-ancien.com").json()["scans"]
    assert (entry["subdomains_count"], entry["open_ports_count"]) == (1, 0)
    (point,) = client.get("/api/dns-timeline/compteurs-ancien.com").json()["timeline"]
    assert (point["subdomains_count"], point["open_ports_count"]) == (1, 0)


def test_historique_pagination_total_et_ordre(client, monkeypatch):
    ids = [_creer_scan(client, monkeypatch, f"page-{i}.pagination.com")["id"] for i in range(3)]

    body = client.get("/api/history?domain=pagination.com&limit=2").json()
    assert body["total"] == 3
    assert [s["id"] for s in body["scans"]] == [ids[2], ids[1]]  # plus récent d'abord

    body = client.get("/api/history?domain=pagination.com&limit=2&offset=2").json()
    assert body["total"] == 3
    assert [s["id"] for s in body["scans"]] == [ids[0]]


def test_historique_filtre_insensible_a_la_casse(client, monkeypatch):
    _creer_scan(client, monkeypatch, "casse-filtre.com")
    assert client.get("/api/history?domain=CASSE-Filtre").json()["total"] == 1


@pytest.mark.parametrize("joker", ["%", "_", "%25", "casse%filtre", "casse_filtre"])
def test_historique_jokers_like_echappes(client, monkeypatch, joker):
    _creer_scan(client, monkeypatch, "joker-filtre.com")
    # « % » et « _ » sont cherchés littéralement : aucun domaine n'en contient.
    assert client.get("/api/history", params={"domain": joker}).json()["total"] == 0


@pytest.mark.parametrize(
    "query", ["limit=0", "limit=201", "limit=-1", "offset=-1", "offset=99999999999999999999"]
)
def test_parametres_historique_bornes(client, query):
    assert client.get(f"/api/history?{query}").status_code == 422


# =============================================================================
# Timeline DNS
# =============================================================================


def _dns(a, soa_serial=1, **extra):
    return {
        "A": a,
        "MX": [{"priority": 10, "value": "mx.timeline.com"}],
        "SOA": [{"mname": "ns1.timeline.com", "rname": "admin.timeline.com", "serial": soa_serial}],
        **extra,
    }


def test_timeline(client, monkeypatch):
    domaine = "timeline-exemple.com"
    premier = _creer_scan(client, monkeypatch, domaine, dns_records=_dns(["1.1.1.1"]), status="success")
    _creer_scan(client, monkeypatch, domaine, dns_records=_dns(["1.1.1.1", "2.2.2.2"], soa_serial=2))
    # Domaine injoignable : rien de mesuré (grade N/A) et DNS en échec.
    _creer_scan(
        client,
        monkeypatch,
        domaine,
        status="error",
        ip_address=None,
        dns_records={},
        security_score={"score": 0, "max_score": 100, "grade": "N/A", "coverage": 0},
        module_status={"dns_records": {"status": "failed", "error": "Délai dépassé"}},
    )
    _creer_scan(
        client,
        monkeypatch,
        domaine,
        dns_records=_dns(["2.2.2.2"], soa_serial=3),
        security_score={"score": 81, "grade": "B", "coverage": 75, "version": 2},
    )

    # Le domaine est normalisé comme à la création du scan.
    response = client.get("/api/dns-timeline/Timeline-Exemple.COM")
    assert response.status_code == 200
    body = response.json()
    assert body["domain"] == domaine
    assert body["total_scans"] == 4
    timeline = body["timeline"]
    assert [t["scan_id"] for t in timeline][0] == premier["id"]

    # Ordre chronologique, dates en UTC avec Z.
    dates = [_iso(t["timestamp"]) for t in timeline]
    assert dates == sorted(dates)

    # Statut, grade et couverture exposés ; N/A n'est pas tracé comme 0.
    assert [t["status"] for t in timeline] == ["success", "partial", "error", "partial"]
    assert [t["security_score"] for t in timeline] == [78, 78, None, 81]
    assert [t["grade"] for t in timeline] == ["B", "B", "N/A", "B"]
    assert timeline[2]["coverage"] == 0
    # Scans sans measured_max (antérieurs à ce champ) : transmis à null.
    assert [t["measured_max"] for t in timeline] == [None, None, None, None]
    assert [t["score_version"] for t in timeline] == [None, None, None, 2]

    # Changements DNS depuis le relevé précédent (le numéro de série SOA seul
    # n'est pas un changement ; un relevé en échec est ignoré).
    assert timeline[0]["dns_changes"] is None
    assert timeline[1]["dns_changes"] == {"A": {"added": ["2.2.2.2"], "removed": []}}
    assert timeline[2]["dns_changes"] is None
    assert timeline[3]["dns_changes"] == {"A": {"added": [], "removed": ["1.1.1.1"]}}

    # Les blobs complets ne transitent pas.
    assert "dns_records" not in timeline[0]


@pytest.mark.parametrize(
    ("security_score", "score_attendu"),
    [
        # Note normale.
        ({"score": 78, "grade": "B", "coverage": 90, "measured_max": 90}, 78),
        # Note N/A sous 50 % de couverture, critères comptés : score indicatif
        # gardé, comme dans l'Historique (« 60/100 (indicatif) »).
        ({"score": 60, "grade": "N/A", "coverage": 40, "measured_max": 40}, 60),
        # Aucune mesure : couverture nulle.
        ({"score": 0, "grade": "N/A", "coverage": 0, "measured_max": 0}, None),
        # Seul le bonus WAF mesuré : aucun critère compté, pas de score.
        ({"score": 0, "grade": "N/A", "coverage": 10, "measured_max": 0}, None),
        # Anciens scans, sans measured_max : note N/A, ou note d'avant la règle
        # des 50 % sous ce seuil, pas de score (N/A dans l'Historique aussi).
        ({"score": 40, "grade": "N/A", "coverage": 30}, None),
        ({"score": 71, "grade": "C", "coverage": 45}, None),
        ({"score": 81, "grade": "B"}, 81),
        # Valeurs non numériques : jamais un score (N/A des deux côtés).
        ({"score": "78", "grade": "B", "coverage": 90}, None),
        ({"score": 60, "grade": "N/A", "coverage": 40, "measured_max": "40"}, None),
        ({"score": 60, "grade": "N/A", "coverage": 40, "measured_max": True}, None),
    ],
)
def test_timeline_entry_score_meme_regle_que_l_historique(security_score, score_attendu):
    """Régression : « 60/100 (indicatif) » dans l'Historique, « N/A » dans la Timeline."""
    scan = Scan(
        id=1,
        domain="timeline-regle.com",
        scan_timestamp=datetime(2026, 9, 1, tzinfo=timezone.utc),
        status="partial",
        module_status={},
        subdomains=[],
        open_ports=[],
        security_score=security_score,
    )
    entry = history_routes._timeline_entry(scan, None)
    assert entry.security_score == score_attendu
    assert entry.grade == security_score["grade"]
    assert entry.coverage == security_score.get("coverage")
    measured_max = security_score.get("measured_max")
    assert entry.measured_max == (measured_max if type(measured_max) in (int, float) else None)


def test_timeline_compteurs_null_si_le_module_n_a_rien_mesure(client, monkeypatch):
    """Régression : « Sous-dom. 0 » sur chaque scan dont l'énumération crt.sh avait échoué."""
    domaine = "timeline-compteurs.com"
    _creer_scan(client, monkeypatch, domaine)
    _creer_scan(
        client,
        monkeypatch,
        domaine,
        subdomains=[],
        open_ports=[],
        module_status=_statuts_modules(subdomains=_ECHEC_CRTSH, open_ports=_PORTS_HORS_DELAI),
    )

    timeline = client.get(f"/api/dns-timeline/{domaine}").json()["timeline"]
    assert [(t["subdomains_count"], t["open_ports_count"]) for t in timeline] == [(1, 1), (None, None)]


def test_timeline_type_dns_en_echec_n_est_pas_une_suppression(client, monkeypatch):
    """Une requête MX en échec (liste vide + errors) ne signale pas la disparition du MX ;
    les métadonnées en minuscules (errors, dmarc_source…) ne sont jamais comparées."""
    domaine = "timeline-echec-mx.com"
    meta = {"measured": True, "error": None, "dmarc_source": None}
    _creer_scan(client, monkeypatch, domaine, dns_records=_dns(["1.1.1.1"], DMARC=[], errors={}, **meta))
    _creer_scan(
        client,
        monkeypatch,
        domaine,
        dns_records={
            **_dns(["1.1.1.1"], DMARC=["v=DMARC1; p=reject"], **meta),
            "MX": [],
            "errors": {"MX": "délai dépassé"},
            "dmarc_source": "_dmarc.x",
        },
    )

    timeline = client.get(f"/api/dns-timeline/{domaine}").json()["timeline"]
    assert timeline[1]["dns_changes"] == {"DMARC": {"added": ["v=DMARC1; p=reject"], "removed": []}}


def test_timeline_limite_avec_reference(client, monkeypatch):
    domaine = "timeline-limite.com"
    for a in (["1.1.1.1"], ["1.1.1.1", "3.3.3.3"], ["3.3.3.3"]):
        _creer_scan(client, monkeypatch, domaine, dns_records=_dns(a))

    body = client.get(f"/api/dns-timeline/{domaine}?limit=2").json()
    assert body["total_scans"] == 3
    assert len(body["timeline"]) == 2
    # Le premier scan affiché est comparé au scan précédent, hors fenêtre.
    assert body["timeline"][0]["dns_changes"] == {"A": {"added": ["3.3.3.3"], "removed": []}}
    assert body["timeline"][1]["dns_changes"] == {"A": {"added": [], "removed": ["1.1.1.1"]}}


def test_timeline_reference_hors_fenetre_en_echec(client, monkeypatch):
    """Le scan juste avant la fenêtre a un relevé DNS en échec : la référence du
    premier scan affiché est le relevé réussi précédent, quelle que soit `limit`."""
    domaine = "timeline-reference.com"
    _creer_scan(client, monkeypatch, domaine, dns_records=_dns(["1.1.1.1"]))
    _creer_scan(client, monkeypatch, domaine, dns_records=_dns(["2.2.2.2"]))
    _creer_scan(
        client,
        monkeypatch,
        domaine,
        dns_records={},
        module_status={"dns_records": {"status": "failed", "error": "Délai dépassé"}},
    )
    dernier = _creer_scan(client, monkeypatch, domaine, dns_records=_dns(["3.3.3.3"]))

    attendu = {"A": {"added": ["3.3.3.3"], "removed": ["2.2.2.2"]}}
    for limit in (1, 2, 4):
        timeline = client.get(f"/api/dns-timeline/{domaine}?limit={limit}").json()["timeline"]
        assert len(timeline) == limit
        assert timeline[-1]["scan_id"] == dernier["id"]
        assert timeline[-1]["dns_changes"] == attendu, limit


def test_domaines_des_anciens_scans_normalises(client):
    """Les anciennes versions enregistraient la saisie telle quelle (casse, Unicode) :
    la timeline, qui cherche le domaine normalisé, doit retrouver ces scans."""
    idn = normalize_target("bücher-ancien.de")
    with database.SessionLocal() as db:
        db.add_all(
            [
                Scan(domain="Ancien-Format.COM", status="success"),
                Scan(domain="ancien-format.com", status="success"),
                Scan(domain="Bücher-Ancien.de", status="success"),
                Scan(domain="pas un domaine", status="success"),  # invalide : laissé tel quel
            ]
        )
        db.commit()

    assert storage.normalize_legacy_domains() >= 2
    assert storage.normalize_legacy_domains() == 0  # déjà fait

    with database.SessionLocal() as db:
        domaines = {d for (d,) in db.query(Scan.domain)}
    assert {"ancien-format.com", idn, "pas un domaine"} <= domaines
    assert not {"Ancien-Format.COM", "Bücher-Ancien.de"} & domaines

    body = client.get("/api/dns-timeline/Ancien-Format.COM").json()
    assert (body["domain"], body["total_scans"]) == ("ancien-format.com", 2)
    assert client.get("/api/dns-timeline/bücher-ancien.de").json()["total_scans"] == 1


def test_timeline_domaines_lies(client, monkeypatch):
    _creer_scan(client, monkeypatch, "lie-exemple.com")
    _creer_scan(client, monkeypatch, "lie-exemple.com")
    _creer_scan(client, monkeypatch, "www.lie-exemple.com")

    body = client.get("/api/dns-timeline/www.lie-exemple.com").json()
    assert body["apex"] == "lie-exemple.com"
    assert body["related_domains"] == [{"domain": "lie-exemple.com", "total_scans": 2}]

    body = client.get("/api/dns-timeline/lie-exemple.com").json()
    assert body["related_domains"] == [{"domain": "www.lie-exemple.com", "total_scans": 1}]


def test_timeline_domaines_lies_par_site_sur_une_plateforme_mutualisee(client, monkeypatch):
    """alice.github.io et bob.github.io sont deux sites : ni l'un ni l'autre n'est « lié »."""
    for domain in ("alice.github.io", "www.alice.github.io", "bob.github.io", "github.io"):
        _creer_scan(client, monkeypatch, domain)

    body = client.get("/api/dns-timeline/www.alice.github.io").json()
    assert body["apex"] == "alice.github.io"
    assert body["related_domains"] == [{"domain": "alice.github.io", "total_scans": 1}]

    body = client.get("/api/dns-timeline/alice.github.io").json()
    assert body["related_domains"] == [{"domain": "www.alice.github.io", "total_scans": 1}]

    # La plateforme elle-même : les sites de ses utilisateurs ne lui sont pas liés.
    body = client.get("/api/dns-timeline/github.io").json()
    assert body["apex"] == "github.io"
    assert body["related_domains"] == []


def test_timeline_domaine_inconnu_ou_invalide(client):
    assert client.get("/api/dns-timeline/jamais-scanne.com").status_code == 404
    assert client.get("/api/dns-timeline/%20").status_code == 400
    assert client.get("/api/dns-timeline/timeline-exemple.com?limit=0").status_code == 422


# =============================================================================
# Endpoint screenshot — confinement du chemin
# =============================================================================


@pytest.mark.parametrize(
    "filename",
    [
        "..\\..\\.env",
        "../.env",
        "..%5C..%5C.env",
        "domainrecon.db",
        "capture.png.exe",
        "sous/dossier.png",
        "capture.png%0A",
        "CAPTURE.PNG",
        "capture:flux.png",
        "..png",
        "a b.png",
    ],
)
def test_screenshot_refuse_les_chemins_hors_dossier(client, filename):
    assert client.get(f"/api/screenshot/{filename}").status_code == 404


@pytest.mark.parametrize("name", ["Example_COM_1700000000.png", "Bücher_de_1700000000.png"])
def test_capture_d_une_ancienne_version_servie_et_supprimee(client, monkeypatch, name):
    """Les anciennes versions gardaient la casse et l'Unicode de la saisie dans le nom."""
    storage.SCREENSHOTS_DIR.mkdir(parents=True, exist_ok=True)
    capture = storage.SCREENSHOTS_DIR / name
    capture.write_bytes(PNG)
    try:
        assert client.get(f"/api/screenshot/{name}").status_code == 200

        scan_id = _creer_scan(client, monkeypatch, "ancienne-capture.com", screenshot=name)["id"]
        assert client.delete(f"/api/scan/{scan_id}").status_code == 200
        assert not capture.exists()
    finally:
        capture.unlink(missing_ok=True)


def test_screenshot_sert_un_fichier_legitime(client):
    storage.SCREENSHOTS_DIR.mkdir(parents=True, exist_ok=True)
    fichier = storage.SCREENSHOTS_DIR / "test_capture_1.png"
    fichier.write_bytes(PNG)
    try:
        response = client.get(f"/api/screenshot/{fichier.name}")
        assert response.status_code == 200
        assert response.headers["content-type"] == "image/png"
    finally:
        fichier.unlink(missing_ok=True)


def test_suppression_efface_la_capture(client, monkeypatch):
    storage.SCREENSHOTS_DIR.mkdir(parents=True, exist_ok=True)
    capture = storage.SCREENSHOTS_DIR / "a_supprimer_1.png"
    capture.write_bytes(PNG)

    try:
        scan_id = _creer_scan(client, monkeypatch, "capture.com", screenshot=capture.name)["id"]
        assert capture.exists()

        client.delete(f"/api/scan/{scan_id}")
        assert not capture.exists()  # plus de fichier orphelin
    finally:
        capture.unlink(missing_ok=True)


def test_capture_partagee_conservee_tant_qu_un_scan_la_reference(client, monkeypatch):
    storage.SCREENSHOTS_DIR.mkdir(parents=True, exist_ok=True)
    capture = storage.SCREENSHOTS_DIR / "partagee_1.png"
    capture.write_bytes(PNG)

    try:
        premier = _creer_scan(client, monkeypatch, "partage.com", screenshot=capture.name)["id"]
        second = _creer_scan(client, monkeypatch, "partage.com", screenshot=capture.name)["id"]

        client.delete(f"/api/scan/{premier}")
        assert capture.exists()
        client.delete(f"/api/scan/{second}")
        assert not capture.exists()
    finally:
        capture.unlink(missing_ok=True)


def _vieillir(fichier, secondes):
    date = time.time() - secondes
    os.utime(fichier, (date, date))


@pytest.fixture
def dossier_captures(monkeypatch, tmp_path):
    """Dossier des captures propre au test (et donc son registre des bases)."""
    dossier = tmp_path / "data" / "screenshots"
    dossier.mkdir(parents=True)
    monkeypatch.setattr(storage, "SCREENSHOTS_DIR", dossier)
    return dossier


def _base_sqlite(chemin, *horodatages):
    """Base SQLite neuve, avec un scan par horodatage ; renvoie son moteur."""
    moteur = create_engine(f"sqlite:///{chemin.as_posix()}")
    database.Base.metadata.create_all(moteur)
    with sessionmaker(bind=moteur)() as db:
        for horodatage in horodatages:
            db.add(Scan(domain="base-partagee.com", status="success", scan_timestamp=horodatage))
        db.commit()
    return moteur


def test_nettoyage_des_captures_orphelines(client, monkeypatch, dossier_captures):
    dossier = dossier_captures
    vieux = storage.ORPHAN_SCREENSHOT_MIN_AGE + 60

    # Plus ancien scan de la base : il y a 2 h.
    with database.SessionLocal() as db:
        db.add(
            Scan(
                domain="ancien-nettoyage.com",
                status="success",
                scan_timestamp=datetime.now(timezone.utc).replace(tzinfo=None) - timedelta(hours=2),
            )
        )
        db.commit()

    orpheline = dossier / "orpheline_1.png"
    recente = dossier / "recente_1.png"
    referencee = dossier / "referencee_1.png"
    autre_base = dossier / "autre_base_1.png"
    # Hors du motif exact des noms générés (slug_horodatage[_suffixe].png),
    # même quand le nom ressemble à une capture.
    etrangers = [
        dossier / "notes.txt",
        dossier / "Majuscules.PNG",
        dossier / "logo.png",
        dossier / "capture_1_zzzz.png",
    ]
    fichiers = (orpheline, recente, referencee, autre_base, *etrangers)
    for fichier in fichiers:
        fichier.write_bytes(PNG)
    for fichier in (orpheline, referencee, *etrangers):
        _vieillir(fichier, vieux)
    _vieillir(autre_base, 5 * 3600)  # antérieure à tous les scans de la base

    _creer_scan(client, monkeypatch, "referencee.com", screenshot=referencee.name)
    assert storage.cleanup_orphan_screenshots() == 1

    assert not orpheline.exists()
    assert recente.exists()  # peut appartenir à un scan en cours
    assert referencee.exists()
    assert autre_base.exists()  # peut appartenir à une autre base
    assert all(f.exists() for f in etrangers)  # hors motif : jamais touchés
    # La base s'est inscrite au registre du dossier.
    registre = (dossier / storage.SCREENSHOT_OWNERS_FILE).read_text(encoding="ascii").split()
    assert registre == [storage._database_fingerprint(database.engine.url)]


def test_nettoyage_sans_effet_sur_une_base_vide(monkeypatch, tmp_path, dossier_captures):
    # Base neuve (changement de DATABASE_URL) : les captures présentes
    # appartiennent peut-être à l'ancienne base.
    vide = _base_sqlite(tmp_path / "vide.db")
    monkeypatch.setattr(storage, "SessionLocal", sessionmaker(bind=vide))

    capture = dossier_captures / "base_vide_1.png"
    capture.write_bytes(PNG)
    _vieillir(capture, storage.ORPHAN_SCREENSHOT_MIN_AGE + 60)
    try:
        assert storage.cleanup_orphan_screenshots() == 0
        assert capture.exists()
    finally:
        vide.dispose()


def test_nettoyage_n_efface_pas_les_captures_d_une_autre_base(monkeypatch, tmp_path, dossier_captures):
    """DATABASE_URL passe de A à B puis revient à A, même DATA_DIR : les captures
    de B, même postérieures au plus ancien scan de A, sont conservées."""
    il_y_a_60_jours = datetime.now(timezone.utc).replace(tzinfo=None) - timedelta(days=60)
    base_a = _base_sqlite(tmp_path / "a.db", il_y_a_60_jours)
    base_b = _base_sqlite(tmp_path / "b.db")
    capture_b = dossier_captures / "b_com_1767225600_cafebabe.png"
    try:
        monkeypatch.setattr(storage, "SessionLocal", sessionmaker(bind=base_a))
        assert storage.cleanup_orphan_screenshots() == 0  # A seule : le nettoyage tourne
        monkeypatch.setattr(storage, "SessionLocal", sessionmaker(bind=base_b))
        assert storage.cleanup_orphan_screenshots() == 0  # B s'inscrit, encore vide

        capture_b.write_bytes(PNG)  # scan fait sous B, il y a 10 jours
        _vieillir(capture_b, 10 * 24 * 3600)

        monkeypatch.setattr(storage, "SessionLocal", sessionmaker(bind=base_a))
        assert storage.cleanup_orphan_screenshots() == 0
        assert capture_b.exists()
    finally:
        base_a.dispose()
        base_b.dispose()


def test_nettoyage_suspendu_si_le_registre_est_inaccessible(monkeypatch, tmp_path, dossier_captures):
    base = _base_sqlite(
        tmp_path / "seule.db", datetime.now(timezone.utc).replace(tzinfo=None) - timedelta(days=1)
    )
    monkeypatch.setattr(storage, "SessionLocal", sessionmaker(bind=base))
    registre = dossier_captures / storage.SCREENSHOT_OWNERS_FILE
    registre.mkdir()  # registre illisible
    orpheline = dossier_captures / "orpheline_registre_1.png"
    orpheline.write_bytes(PNG)
    _vieillir(orpheline, storage.ORPHAN_SCREENSHOT_MIN_AGE + 60)
    try:
        assert storage.cleanup_orphan_screenshots() == 0
        assert orpheline.exists()

        # Registre de nouveau utilisable : la même orpheline est supprimée.
        registre.rmdir()
        assert storage.cleanup_orphan_screenshots() == 1
        assert not orpheline.exists()
    finally:
        base.dispose()


def test_empreinte_de_la_base(monkeypatch, tmp_path):
    # Base SQLite dans le dossier de données : chemin relatif, l'empreinte
    # survit au déplacement du dossier.
    empreintes = []
    for dossier in (tmp_path / "ici", tmp_path / "ailleurs"):
        monkeypatch.setattr(storage, "SCREENSHOTS_DIR", dossier / "screenshots")
        empreintes.append(
            storage._database_fingerprint(make_url(f"sqlite:///{(dossier / 'recon.db').as_posix()}"))
        )
    assert empreintes[0] == empreintes[1]
    autre = make_url(f"sqlite:///{(tmp_path / 'autre.db').as_posix()}")
    assert storage._database_fingerprint(autre) != empreintes[0]

    # Le mot de passe n'entre pas dans l'empreinte ; l'hôte, si.
    pg = "postgresql+psycopg://recon:{}@{}/recon"
    assert storage._database_fingerprint(make_url(pg.format("mdp1", "db"))) == storage._database_fingerprint(
        make_url(pg.format("mdp2", "db"))
    )
    assert storage._database_fingerprint(make_url(pg.format("mdp1", "db"))) != storage._database_fingerprint(
        make_url(pg.format("mdp1", "db2"))
    )


# =============================================================================
# Frontend
# =============================================================================


def test_frontend_get_et_head(client, web_build):
    response = client.get("/")
    assert response.status_code == 200
    assert response.headers["content-type"].startswith("text/html")
    assert client.head("/").status_code == 200


# =============================================================================
# Configuration
# =============================================================================


def test_log_level_invalide_ne_plante_pas(monkeypatch, caplog):
    monkeypatch.setenv("LOG_LEVEL", "verbose")
    with caplog.at_level(logging.WARNING, logger="domainrecon.core.config"):
        assert config._log_level() == "INFO"
    assert "LOG_LEVEL invalide" in caplog.text

    monkeypatch.setenv("LOG_LEVEL", "warning")
    assert config._log_level() == "WARNING"


@pytest.mark.parametrize(
    "contenu",
    [
        "DOMAINRECON_TEST_JETON=s3cret\n# Jeton d'accès\n".encode(),
        codecs.BOM_UTF8 + b"DOMAINRECON_TEST_JETON=s3cret\n",
        # Windows PowerShell 5.1 : « > » et Out-File écrivent en UTF-16 avec BOM.
        "DOMAINRECON_TEST_JETON=s3cret\r\n# Jeton d'accès\r\n".encode("utf-16"),
        codecs.BOM_UTF16_BE + "DOMAINRECON_TEST_JETON=s3cret\n".encode("utf-16-be"),
    ],
    ids=["utf-8", "utf-8-bom", "utf-16-le", "utf-16-be"],
)
def test_fichier_env_utf8_ou_utf16(monkeypatch, tmp_path, contenu):
    # setenv puis delenv : la variable posée par le chargement est retirée en fin de test.
    monkeypatch.setenv("DOMAINRECON_TEST_JETON", "")
    monkeypatch.delenv("DOMAINRECON_TEST_JETON")
    fichier = tmp_path / ".env"
    fichier.write_bytes(contenu)

    config.load_env_file(fichier)
    assert os.environ["DOMAINRECON_TEST_JETON"] == "s3cret"


def test_fichier_env_illisible_arrete_le_demarrage(monkeypatch, tmp_path):
    """Un .env en ANSI n'est pas ignoré en silence : API_TOKEN serait perdu."""
    monkeypatch.setenv("DOMAINRECON_TEST_JETON", "")
    monkeypatch.delenv("DOMAINRECON_TEST_JETON")
    fichier = tmp_path / ".env"
    fichier.write_bytes("DOMAINRECON_TEST_JETON=s3cret\n# Jeton d'accès\n".encode("cp1252"))

    with pytest.raises(RuntimeError, match="UTF-8") as erreur:
        config.load_env_file(fichier)
    assert str(fichier) in str(erreur.value)
    assert "DOMAINRECON_TEST_JETON" not in os.environ


def test_fichier_env_ne_remplace_pas_l_environnement(monkeypatch, tmp_path):
    monkeypatch.setenv("DOMAINRECON_TEST_JETON", "depuis-l-environnement")
    fichier = tmp_path / ".env"
    fichier.write_bytes("DOMAINRECON_TEST_JETON=s3cret\n".encode("utf-16"))

    config.load_env_file(fichier)
    assert os.environ["DOMAINRECON_TEST_JETON"] == "depuis-l-environnement"


def test_log_level_s_applique_aux_journaux_d_uvicorn(monkeypatch):
    noms = ("uvicorn", "uvicorn.error", "uvicorn.access", "httpcore")
    niveaux = {nom: logging.getLogger(nom).level for nom in noms}
    monkeypatch.setenv("LOG_LEVEL", "WARNING")
    monkeypatch.setattr(config, "LOG_LEVEL", "WARNING")
    try:
        config.configure_logging()
        assert logging.getLogger("uvicorn.access").level == logging.WARNING
        assert logging.getLogger("uvicorn.error").level == logging.WARNING
    finally:
        for nom, niveau in niveaux.items():
            logging.getLogger(nom).setLevel(niveau)
