# =============================================================================
# DomainRecon - Tests : langue des réponses et forme des erreurs de l'API
# =============================================================================
# Les messages sont enregistrés sous forme de codes et rendus à la lecture
# (?lang=, sinon Accept-Language, sinon français). Les codes api.* servent ici
# de messages quelconques : seul le mécanisme est testé.
# =============================================================================

import threading

import pytest
from fastapi.responses import PlainTextResponse
from fastapi.testclient import TestClient
from sqlalchemy.exc import OperationalError, SQLAlchemyError
from sqlalchemy.exc import TimeoutError as PoolTimeoutError

from domainrecon.api import storage
from domainrecon.api.app import app
from domainrecon.api.routes import jobs as jobs_routes
from domainrecon.api.routes import scans as scans_routes
from domainrecon.core import config
from domainrecon.core.database import SessionLocal, get_db
from domainrecon.core.models import Scan
from domainrecon.i18n import msg
from domainrecon.scanner import MODULE_NAMES, TargetNotAllowedError

# Comportement des 18 modules historiques : registre ramené à eux (tests/conftest.py).
pytestmark = pytest.mark.usefixtures("registre_historique")


@pytest.fixture
def client():
    with TestClient(app) as c:
        yield c


def _resultat(domain="messages.example.com", **overrides) -> dict:
    """Résultat minimal de perform_full_scan, avec des messages traduisibles."""
    statuts = {name: {"status": "ok", "error": None} for name in MODULE_NAMES}
    statuts["whois_data"] = {"status": "failed", "error": msg("api.too_many_scans", max=2)}
    resultat = {
        "domain": domain,
        "ip_address": "93.184.216.34",
        "security_score": {
            "score": 50,
            "max_score": 100,
            "grade": "N/A",
            "grade_reason": msg("api.invalid_domain"),
            "breakdown": {},
        },
        "module_status": statuts,
        "status": "partial",
        "error_message": msg("api.scan_not_found"),
    }
    resultat.update(overrides)
    return resultat


def test_404_en_francais_par_defaut(client):
    response = client.get("/api/scan/999999")
    assert response.status_code == 404
    assert response.json() == {"detail": "Scan non trouvé", "code": "api.scan_not_found", "params": {}}


def test_404_en_anglais_par_parametre_ou_en_tete(client):
    assert client.get("/api/scan/999999?lang=en").json()["detail"] == "Scan not found"
    response = client.get("/api/scan/999999", headers={"Accept-Language": "en-GB,en;q=0.9"})
    assert response.json()["detail"] == "Scan not found"
    # ?lang= prime sur Accept-Language.
    response = client.get("/api/scan/999999?lang=fr", headers={"Accept-Language": "en"})
    assert response.json()["detail"] == "Scan non trouvé"


def test_route_api_inconnue(client):
    response = client.get("/api/route-inconnue?lang=en")
    assert response.status_code == 404
    assert response.json() == {"detail": "Not found", "code": "api.not_found", "params": {}}


def test_415_et_429_avec_parametres(client, monkeypatch):
    response = client.post("/api/scan?lang=en", content=b"{}", headers={"Content-Type": "text/plain"})
    assert response.status_code == 415
    assert response.json() == {
        "detail": "The request body must be JSON (Content-Type: application/json).",
        "code": "api.json_required",
        "params": {},
    }

    slots = threading.BoundedSemaphore(1)
    monkeypatch.setattr(jobs_routes.manager, "slots", slots)
    assert slots.acquire(blocking=False)
    try:
        response = client.post(
            "/api/scan", json={"domain": "occupe.example.com"}, headers={"Accept-Language": "en"}
        )
    finally:
        slots.release()
    assert response.status_code == 429
    assert response.headers["retry-after"] == "30"
    assert response.json() == {
        "detail": f"Too many scans in progress ({config.MAX_CONCURRENT_SCANS} at most): try again in a few moments.",
        "code": "api.too_many_scans",
        "params": {"max": config.MAX_CONCURRENT_SCANS},
    }


def test_401_413_422_en_anglais(client, monkeypatch):
    monkeypatch.setattr(config, "API_TOKEN", "jeton")
    response = client.get("/api/history?lang=en")
    assert response.status_code == 401
    assert response.json() == {
        "detail": "Authentication required: missing or invalid API token.",
        "code": "api.auth_required",
        "params": {},
    }
    monkeypatch.setattr(config, "API_TOKEN", None)

    gros = b'{"domain": "' + b"a" * (1024 * 1024) + b'"}'
    response = client.post("/api/scan?lang=en", content=gros, headers={"Content-Type": "application/json"})
    assert response.status_code == 413
    assert response.json() == {
        "detail": "Request body too large.",
        "code": "api.body_too_large",
        "params": {},
    }

    response = client.post("/api/scan?lang=en", json={"domain": "xx"})
    assert response.status_code == 422
    corps = response.json()
    assert corps["code"] == "api.validation_error"
    assert corps["detail"] == "Invalid request (domain)"
    assert corps["params"] == {"fields": "domain"}
    assert corps["errors"][0]["loc"] == ["body", "domain"]


def test_messages_d_un_scan_rendus_a_la_lecture(client, monkeypatch):
    async def faux_scan(domain):
        return _resultat(domain)

    monkeypatch.setattr(scans_routes, "perform_full_scan", faux_scan)
    cree = client.post("/api/scan", json={"domain": "messages.example.com"})
    assert cree.status_code == 200, cree.text
    corps = cree.json()
    assert corps["error_message"] == "Scan non trouvé"
    assert (
        corps["module_status"]["whois_data"]["error"]
        == "Trop de scans en cours (2 au maximum) : réessayez dans quelques instants."
    )

    anglais = client.get(f"/api/scan/{corps['id']}?lang=en").json()
    assert anglais["error_message"] == "Scan not found"
    assert (
        anglais["module_status"]["whois_data"]["error"]
        == "Too many scans in progress (2 at most): try again in a few moments."
    )
    assert anglais["security_score"]["grade_reason"] == "Invalid domain"

    historique = client.get("/api/history?domain=messages.example.com&lang=en").json()
    assert historique["scans"][0]["security_score"]["grade_reason"] == "Invalid domain"

    suppression = client.delete(f"/api/scan/{corps['id']}?lang=en")
    assert suppression.json() == {"message": "Scan deleted", "id": corps["id"]}


def test_message_stocke_en_code_dans_la_base(client):
    # `client` démarre l'application, qui crée les tables : le test ne dépend
    # pas de l'ordre d'exécution.
    scan_id = storage.save_scan(_resultat("stockage.example.com"))
    with SessionLocal() as db:
        brut = db.get(Scan, scan_id)
        assert brut.error_message == '{"$t": "api.scan_not_found", "p": {}}'
        assert brut.module_status["whois_data"]["error"] == {"$t": "api.too_many_scans", "p": {"max": 2}}


def test_texte_brut_d_un_ancien_scan_rendu_tel_quel(client):
    with SessionLocal() as db:
        scan = Scan(
            domain="ancien-texte.example.com", status="partial", error_message="1 module(s) en échec : waf"
        )
        db.add(scan)
        db.commit()
        scan_id = scan.id
    corps = client.get(f"/api/scan/{scan_id}?lang=en").json()
    assert corps["error_message"] == "1 module(s) en échec : waf"


# --- Compléments : chemins du gestionnaire d'erreurs et des routes ------------


def test_erreur_400_avec_message_garde_son_code(client, monkeypatch):
    async def faux_scan(domain):
        raise TargetNotAllowedError(msg("api.invalid_domain"))

    monkeypatch.setattr(scans_routes, "perform_full_scan", faux_scan)
    response = client.post("/api/scan?lang=en", json={"domain": "refuse.example.com"})
    assert response.status_code == 400
    assert response.json() == {"detail": "Invalid domain", "code": "api.invalid_domain", "params": {}}


def test_405_rendu_dans_la_langue_demandee(client):
    response = client.delete("/api/history?lang=en")
    assert response.status_code == 405
    assert response.json() == {"detail": "Method not allowed", "code": "api.method_not_allowed", "params": {}}
    # Les en-têtes de l'exception (Allow) sont conservés.
    assert "GET" in response.headers["allow"]


def test_413_par_morceaux_rendu_dans_la_langue_demandee(client):
    gros = b'{"domain": "' + b"a" * (1024 * 1024) + b'"}'

    def morceaux():
        for i in range(0, len(gros), 64 * 1024):
            yield gros[i : i + 64 * 1024]

    response = client.post(
        "/api/scan?lang=en", content=morceaux(), headers={"Content-Type": "application/json"}
    )
    assert response.status_code == 413
    assert response.json() == {
        "detail": "Request body too large.",
        "code": "api.body_too_large",
        "params": {},
    }


def test_parametre_lang_trop_long_refuse(client):
    response = client.get("/api/history?lang=" + "x" * 17)
    assert response.status_code == 422
    assert response.json()["params"] == {"fields": "lang"}


def test_meta_rend_les_messages_dans_la_langue_demandee(client, monkeypatch):
    async def faux_scan(domain):
        return _resultat(domain)

    monkeypatch.setattr(scans_routes, "perform_full_scan", faux_scan)
    scan_id = client.post("/api/scan", json={"domain": "meta-langue.example.com"}).json()["id"]

    response = client.patch(f"/api/scan/{scan_id}/meta?lang=en", json={"notes": "à revoir"})
    assert response.status_code == 200
    corps = response.json()
    assert corps["notes"] == "à revoir"
    assert corps["error_message"] == "Scan not found"
    assert corps["module_status"]["whois_data"]["error"].startswith("Too many scans in progress")


@pytest.mark.parametrize(
    ("chemin", "statut", "code", "detail"),
    [
        (
            "/api/dns-timeline/sans-scan.example.com",
            404,
            "api.no_scan_for_domain",
            "No scan found for this domain",
        ),
        ("/api/dns-timeline/exa%20mple.com", 400, "api.invalid_domain", "Invalid domain"),
        ("/api/screenshot/absente.png", 404, "api.screenshot_not_found", "Screenshot not found"),
    ],
)
def test_erreurs_de_l_historique_et_des_captures(client, chemin, statut, code, detail):
    response = client.get(f"{chemin}?lang=en")
    assert response.status_code == statut
    assert response.json() == {"detail": detail, "code": code, "params": {}}


@pytest.mark.parametrize(
    ("echec", "code", "detail"),
    [
        ("scan", "api.scan_failed", "The scan failed because of an internal error. See the server logs."),
        (
            "enregistrement",
            "api.save_failed",
            "The scan completed but could not be saved. See the server logs.",
        ),
    ],
)
def test_echec_interne_du_scan_ou_de_son_enregistrement(client, monkeypatch, echec, code, detail):
    async def faux_scan(domain):
        if echec == "scan":
            raise RuntimeError("détail interne")
        return _resultat(domain)

    def faux_enregistrement(result):
        raise storage.ScanSaveError(result["domain"])

    monkeypatch.setattr(scans_routes, "perform_full_scan", faux_scan)
    monkeypatch.setattr(storage, "save_scan", faux_enregistrement)
    response = client.post("/api/scan?lang=en", json={"domain": "panne.example.com"})
    assert response.status_code == 500
    assert response.json() == {"detail": detail, "code": code, "params": {}}
    assert "interne" not in response.text


class _SessionEnPanne:
    """Session dont toute requête lève `erreur`."""

    def __init__(self, erreur):
        self.erreur = erreur

    def query(self, *args, **kwargs):
        raise self.erreur


@pytest.mark.parametrize(
    ("erreur", "statut", "code", "detail"),
    [
        (
            OperationalError("SELECT", {}, Exception("database is locked : détail interne")),
            503,
            "api.database_unavailable",
            "Database unavailable: try again in a few moments.",
        ),
        (
            PoolTimeoutError("délai du pool : détail interne"),
            503,
            "api.database_unavailable",
            "Database unavailable: try again in a few moments.",
        ),
        (SQLAlchemyError("détail interne"), 500, "api.internal_error", "Internal server error."),
    ],
    ids=["base-verrouillee", "pool-sature", "autre-erreur"],
)
def test_erreur_de_base_avec_code_et_langue(client, erreur, statut, code, detail):
    app.dependency_overrides[get_db] = lambda: _SessionEnPanne(erreur)
    try:
        response = client.get("/api/history?lang=en")
    finally:
        app.dependency_overrides.pop(get_db, None)
    assert response.status_code == statut
    assert response.json() == {"detail": detail, "code": code, "params": {}}
    assert "interne" not in response.text


def test_repli_interface_seulement_pour_un_404_du_routeur(client, monkeypatch):
    appels = []

    def repli(request):
        appels.append(request.url.path)
        return None if request.url.path.startswith("/api") else PlainTextResponse("interface")

    monkeypatch.setattr(app.state, "spa_fallback", repli, raising=False)

    # Route inconnue hors /api : la réponse du repli.
    response = client.get("/page-inconnue")
    assert (response.status_code, response.text) == (200, "interface")
    # Repli sans réponse (None) : le 404 JSON habituel.
    assert client.get("/api/route-inconnue").json()["code"] == "api.not_found"
    # 404 levé par une route (ApiError) : le repli n'est pas consulté.
    assert client.get("/api/scan/999999").json()["code"] == "api.scan_not_found"
    assert appels == ["/page-inconnue", "/api/route-inconnue"]


# --- 422 des tags et notes : raison traduite (revue finale M1) ---------------------


@pytest.mark.parametrize(
    ("payload", "code", "params", "francais", "anglais"),
    [
        (
            {"tags": ["x" * 51]},
            "api.meta_tag_length",
            {"max": 50},
            "Chaque tag doit faire de 1 à 50 caractères.",
            "Each tag must be 1 to 50 characters long.",
        ),
        (
            {"tags": ["   "]},
            "api.meta_tag_length",
            {"max": 50},
            "Chaque tag doit faire de 1 à 50 caractères.",
            "Each tag must be 1 to 50 characters long.",
        ),
        (
            {"tags": [f"t{i}" for i in range(21)]},
            "api.meta_too_many_tags",
            {"max": 20},
            "20 tags au maximum.",
            "At most 20 tags.",
        ),
    ],
    ids=["tag-trop-long", "tag-vide", "trop-de-tags"],
)
def test_meta_422_raison_rendue_dans_la_langue(client, payload, code, params, francais, anglais):
    for langue, attendu in (("fr", francais), ("en", anglais)):
        response = client.patch(f"/api/scan/1/meta?lang={langue}", json=payload)
        assert response.status_code == 422
        corps = response.json()
        # detail, code et params sont ceux de la règle : l'interface affiche detail tel quel.
        assert (corps["detail"], corps["code"], corps["params"]) == (attendu, code, params)
        # La liste détaillée de Pydantic porte la même raison, dans la même langue.
        (erreur,) = corps["errors"]
        assert (erreur["type"], erreur["msg"], erreur["loc"]) == (code, attendu, ["body", "tags"])


@pytest.mark.parametrize(
    ("payload", "code", "extrait_fr", "extrait_en"),
    [
        ({"tags": ["a\x00b"]}, "api.meta_tag_forbidden_chars", "caractère de contrôle", "control characters"),
        ({"tags": ["a\u2028b"]}, "api.meta_tag_forbidden_chars", "U+2028", "U+2028"),
        ({"tags": ["inversé\u202e"]}, "api.meta_tag_forbidden_chars", "bidirectionnelle", "bidirectional"),
        ({"notes": "nul\x00"}, "api.meta_notes_forbidden_chars", "hors tabulation", "except tab"),
        ({"notes": "copié d'un PDF\u2028suite"}, "api.meta_notes_forbidden_chars", "U+2029", "U+2029"),
        ({"notes": "texte\u2066isolé\u2069"}, "api.meta_notes_forbidden_chars", "U+2066", "U+2066"),
    ],
    ids=["tag-nul", "tag-u2028", "tag-bidi", "notes-nul", "notes-u2028", "notes-isolat-bidi"],
)
def test_meta_422_caracteres_interdits_expliques(client, payload, code, extrait_fr, extrait_en):
    champ = next(iter(payload))
    for langue, extrait in (("fr", extrait_fr), ("en", extrait_en)):
        corps = client.patch(f"/api/scan/1/meta?lang={langue}", json=payload).json()
        assert corps["code"] == code and corps["params"] == {}
        assert extrait in corps["detail"]
        assert corps["errors"][0]["msg"] == corps["detail"]
        assert corps["errors"][0]["loc"][:2] == ["body", champ]
    # Les deux langues ne se mélangent pas.
    francais = client.patch("/api/scan/1/meta?lang=fr", json=payload).json()["detail"]
    anglais = client.patch("/api/scan/1/meta?lang=en", json=payload).json()["detail"]
    assert francais != anglais and "Unicode" in anglais


def test_meta_422_regle_de_pydantic_garde_le_message_generique(client):
    """Une erreur de type (pas une règle de l'application) reste « Requête invalide (champ) »."""
    corps = client.patch("/api/scan/1/meta?lang=en", json={"tags": [42]}).json()
    assert corps["code"] == "api.validation_error"
    assert corps["detail"] == "Invalid request (tags.0)"
    assert corps["params"] == {"fields": "tags.0"}
    assert corps["errors"][0]["type"] == "string_type"
