# =============================================================================
# DomainRecon - Tests de l'API v1 : familles, points à corriger, anciens scans,
# filtres de l'historique, informations système, battement de l'interface
# =============================================================================

import time

import pytest
from fastapi.testclient import TestClient

from domainrecon import __version__
from domainrecon.api import storage
from domainrecon.api.app import app
from domainrecon.api.routes import jobs as jobs_routes
from domainrecon.api.routes import system as system_routes
from domainrecon.core import config
from domainrecon.core.database import SessionLocal
from domainrecon.core.models import Scan
from domainrecon.i18n import msg
from domainrecon.scanner.families import FAMILY_KEYS
from domainrecon.scanner.orchestrator import MODULE_NAMES
from domainrecon.scanner.registry import PROFILE_QUICK, get_modules
from domainrecon.scanner.score import compute_security_score

# Comportement des 18 modules historiques : registre ramené à eux (tests/conftest.py).
pytestmark = pytest.mark.usefixtures("registre_historique")


@pytest.fixture
def client():
    with TestClient(app) as c:
        yield c


def _resultat(domain: str, **overrides) -> dict:
    """Résultat de perform_full_scan : certificat expiré et Redis exposé."""
    resultat = {
        "domain": domain,
        "ip_address": "93.184.216.34",
        "module_status": {name: {"status": "ok", "error": None} for name in MODULE_NAMES},
        "tls_certificate": {
            "measured": True,
            "https": True,
            "valid": False,
            "verify_error": msg("tls.verify_10"),
        },
        "open_ports": [{"port": 6379, "state": "open", "service": "Redis"}],
        "security_score": {
            "score": 40,
            "max_score": 100,
            "grade": "D",
            "breakdown": {"tls": {"score": 0, "max": 20, "measured": True, "counted": True}},
        },
        "status": "success",
    }
    resultat.update(overrides)
    return resultat


def test_familles_et_points_a_corriger_exposes(client):
    scan_id = storage.save_scan(_resultat("familles.example.com"))
    corps = client.get(f"/api/scan/{scan_id}?lang=en").json()
    assert list(corps["families"]) == list(FAMILY_KEYS)
    assert corps["families"]["tls"] == {"state": "critical", "grade": "F", "summary": "1 issue(s) to fix"}
    assert corps["families"]["network"]["state"] == "critical"
    assert corps["findings"] == [
        {
            "severity": "critical",
            "family": "tls",
            "module": "tls_certificate",
            "message": "Invalid TLS certificate: Certificate expired",
        },
        {
            "severity": "critical",
            "family": "network",
            "module": "open_ports",
            "message": "Port 6379 (Redis) exposed to the Internet",
        },
    ]
    francais = client.get(f"/api/scan/{scan_id}").json()
    assert francais["findings"][0]["message"] == "Certificat TLS invalide : Certificat expiré"


def test_ancien_scan_en_base_lu_tel_quel(client):
    """Textes bruts, barème v1, sans module_status (Review Focus n° 2)."""
    with SessionLocal() as db:
        scan = Scan(
            domain="ancien.example.com",
            status="partial",
            error_message="{inattendu} Cible injoignable : aucune résolution DNS ni réponse HTTP",
            security_score={
                "score": 40,
                "grade": "D",
                "breakdown": {"headers": {"score": 10, "max": 25, "detail": "2/6 conformes"}},
            },
            tls_certificate={"error": "certificate verify failed: self signed certificate"},
            security_headers={
                "headers_found": {"X-Frame-Options": "DENY"},
                "headers_missing": ["Strict-Transport-Security"],
                "score": "1/7",
            },
            open_ports=[23, 443],
            module_status=None,
        )
        db.add(scan)
        db.commit()
        scan_id = scan.id
    for lang in ("fr", "en"):
        response = client.get(f"/api/scan/{scan_id}?lang={lang}")
        assert response.status_code == 200, response.text
        corps = response.json()
        assert (
            corps["error_message"] == "{inattendu} Cible injoignable : aucune résolution DNS ni réponse HTTP"
        )
        assert corps["security_score"]["breakdown"]["headers"]["detail"] == "2/6 conformes"
        assert list(corps["families"]) == list(FAMILY_KEYS)
        assert corps["families"]["web"]["grade"] == "D"
        # Le certificat « verify failed » d'avant les statuts de module est un constat (TLS critique).
        assert sorted(f["module"] for f in corps["findings"]) == [
            "open_ports",
            "security_headers",
            "tls_certificate",
        ]
    assert client.get("/api/history?domain=ancien.example.com&lang=en").status_code == 200


# Score noté au barème v3 (avant la 7e famille et les profils de scan).
SCORE_V3 = {
    "version": 3,
    "score": 71,
    "max_score": 100,
    "grade": "C",
    "grade_reason": None,
    "coverage": 90,
    "measured_points": 57,
    "measured_max": 80,
    "confidence": "high",
    "breakdown": {
        "tls": {
            "score": 0,
            "max": 20,
            "detail": "Invalide",
            "measured": True,
            "counted": True,
            "applicable": True,
        },
        "waf": {
            "score": 0,
            "max": 10,
            "detail": "Aucun WAF",
            "measured": True,
            "counted": False,
            "applicable": True,
        },
    },
    "penalties": [],
    "grade_cap": None,
    "grade_cap_reasons": [],
}


def test_scan_v3_relu_avec_son_score_sans_recalcul(client):
    """Un scan noté en v3 garde son score tel quel : le barème v4 ne vaut que pour les nouveaux scans."""
    scan_id = storage.save_scan(_resultat("v3.example.com", security_score=SCORE_V3))
    for lang in ("fr", "en"):
        corps = client.get(f"/api/scan/{scan_id}?lang={lang}").json()
        # Ni version 4, ni critère ajouté, ni valeur recalculée.
        assert corps["security_score"] == SCORE_V3
        assert list(corps["families"]) == list(FAMILY_KEYS)
        assert corps["families"]["tls"]["grade"] == "F"
        # 7e famille : aucun module, donc non mesurée, y compris pour un scan d'avant son existence.
        assert (corps["families"]["reputation"]["state"], corps["families"]["reputation"]["grade"]) == (
            "unmeasured",
            None,
        )
    assert client.get(f"/api/scan/{scan_id}?lang=en").json()["families"]["reputation"]["summary"] == (
        "Not measured: modules not run"
    )
    # La lecture n'écrit rien : la base garde le score d'origine.
    with SessionLocal() as db:
        assert db.get(Scan, scan_id).security_score == SCORE_V3
    assert client.get("/api/history?domain=v3.example.com").json()["scans"][0]["security_score"] == SCORE_V3


def test_scan_v4_profil_rapide_dit_ses_modules_non_lances(client):
    lances = [spec.name for spec in get_modules(PROFILE_QUICK)]
    statuts = {name: {"status": "ok", "error": None} for name in lances}
    donnees = _resultat("rapide.example.com", module_status=statuts, modules_launched=lances)
    donnees["security_score"] = compute_security_score(
        {
            "tls_certificate": donnees["tls_certificate"],
            "open_ports": donnees["open_ports"],
            "module_status": statuts,
            "modules_launched": lances,
        }
    )
    scan_id = storage.save_scan(donnees)

    corps = client.get(f"/api/scan/{scan_id}?lang=en").json()

    score = corps["security_score"]
    assert score["version"] == 4
    assert "takeover" not in score["breakdown"]  # module actif : critère omis
    assert score["breakdown"]["whois"]["launched"] is False
    assert score["breakdown"]["whois"]["detail"] == "Not run (outside the scan profile)"
    assert score["breakdown"]["tls"]["measured"] is True and "launched" not in score["breakdown"]["tls"]
    # Les modules non lancés ne sont ni « réussis » ni des échecs : familles et résumés le disent.
    assert corps["families"]["identity"] == {
        "state": "unmeasured",
        "grade": None,
        "summary": "Not measured: modules not run",
    }
    assert corps["families"]["dns"]["state"] == "unmeasured"
    # Ports (actifs) non lancés : aucun verdict honnête pour le réseau.
    assert corps["families"]["network"] == {
        "state": "unmeasured",
        "grade": None,
        "summary": "Not measured: modules not run",
    }
    assert corps["families"]["tls"]["state"] == "critical"
    # Les ports, non lancés, ne produisent aucun constat même si le résultat enregistré en contient.
    assert [finding["module"] for finding in corps["findings"]] == ["tls_certificate"]


def test_scan_sans_modules_launched_lit_module_status(client):
    """modules_launched NULL (scan d'avant les profils, ou route synchrone) : module_status dit les modules lancés."""
    for version in (3, 4):
        donnees = _resultat(f"complet{version}.example.com", security_score={**SCORE_V3, "version": version})
        corps = client.get(f"/api/scan/{storage.save_scan(donnees)}?lang=en").json()
        assert corps["families"]["identity"]["state"] == "info"
        assert corps["families"]["network"]["summary"] == "1 issue(s) to fix"
    # Même scan, mais module_status sans les ports : non lancés, jamais « ok ».
    statuts = {name: {"status": "ok", "error": None} for name in MODULE_NAMES if name != "open_ports"}
    donnees = _resultat("complet2.example.com", module_status=statuts)
    donnees["security_score"] = {**SCORE_V3, "version": 4}
    corps = client.get(f"/api/scan/{storage.save_scan(donnees)}?lang=en").json()
    assert corps["families"]["network"]["state"] == "unmeasured"
    assert all(finding["module"] != "open_ports" for finding in corps["findings"])


def _ancien_scan_en_base(**colonnes) -> int:
    """Ancien scan enregistré sans module_status ; colonnes absentes à NULL."""
    with SessionLocal() as db:
        scan = Scan(domain="ancien.example.com", module_status=None, **colonnes)
        db.add(scan)
        db.commit()
        return scan.id


def test_ancien_scan_en_erreur_famille_non_mesuree_sans_constat(client):
    """Statut « error » : familles « non mesurées » et constats suivent la même règle."""
    scan_id = _ancien_scan_en_base(
        status="error",
        whois_data={"registrar": "x"},
        subdomains=[{"subdomain": "shop.example.com"}],
        subdomain_takeover=[{"subdomain": "shop.example.com", "provider": "Heroku", "risk": "high"}],
        open_ports=[3306],
    )
    corps = client.get(f"/api/scan/{scan_id}?lang=en").json()
    assert (corps["families"]["dns"]["state"], corps["families"]["network"]["state"]) == (
        "unmeasured",
        "unmeasured",
    )
    assert corps["findings"] == []


def test_ancien_scan_takeover_jamais_verifie_relu_en_liste_vide(client):
    """Colonne takeover NULL (relue en []) et critère takeover absent : DNS non mesuré."""
    colonnes = {
        "status": "success",
        "dns_records": {"A": ["93.184.216.34"]},
        "subdomains": [{"subdomain": "www.example.com"}],
        "reverse_dns": {"ptr": "x.example.net"},
    }
    sans_takeover = {"breakdown": {"headers": {"score": 25, "max": 25}}}
    scan_id = _ancien_scan_en_base(security_score=sans_takeover, **colonnes)
    corps = client.get(f"/api/scan/{scan_id}?lang=en").json()
    assert corps["subdomain_takeover"] == []
    assert corps["families"]["dns"]["state"] == "unmeasured"
    # Critère takeover mesuré au barème : « rien trouvé », la famille garde son verdict.
    verifie = {"breakdown": {"takeover": {"score": 5, "max": 5, "measured": True}}}
    scan_id = _ancien_scan_en_base(security_score=verifie, **colonnes)
    assert client.get(f"/api/scan/{scan_id}").json()["families"]["dns"]["state"] == "ok"


def test_filtres_de_l_historique(client):
    for grade, status in (("A", "success"), ("F", "partial"), ("N/A", "error")):
        score = {"score": 50, "max_score": 100, "grade": grade, "breakdown": {}}
        storage.save_scan(_resultat("filtres.example.com", security_score=score, status=status))

    def notes(**params):
        corps = client.get("/api/history", params={"domain": "filtres.example.com", **params}).json()
        return corps["total"], sorted(s["security_score"]["grade"] for s in corps["scans"])

    assert notes() == (3, ["A", "F", "N/A"])
    assert notes(grade="A") == (1, ["A"])
    assert notes(grade="N/A") == (1, ["N/A"])
    assert notes(status="partial") == (1, ["F"])
    assert notes(grade="A", status="partial") == (0, [])
    assert client.get("/api/history?grade=Z").status_code == 422
    assert client.get("/api/history?status=inconnu").status_code == 422


def test_filtre_note_suit_la_note_affichee_des_anciens_scans(client):
    anciens = {
        "c_faible": {"score": 60, "grade": "C", "coverage": 45},
        "b_sans_score": {"score": None, "grade": "B"},
        "sans_note": {"score": 40},
        "c_v2": {"score": 70, "grade": "C"},
        "c_v3": {"score": 70, "grade": "C", "coverage": 80},
    }
    for nom, score in anciens.items():
        storage.save_scan(_resultat(f"{nom}.notes.example.com", security_score=score))
    storage.save_scan(_resultat("aucun.notes.example.com", security_score=None))

    def domaines(grade):
        corps = client.get("/api/history", params={"domain": "notes.example.com", "grade": grade}).json()
        return sorted(s["domain"].split(".")[0] for s in corps["scans"])

    assert domaines("C") == ["c_v2", "c_v3"]
    assert domaines("B") == []
    assert domaines("N/A") == ["aucun", "b_sans_score", "c_faible", "sans_note"]


def test_informations_systeme(client):
    assert client.get("/api/system/info").json() == {
        "version": __version__,
        "data_dir": str(config.DATA_DIR),
        "portable": False,
        "frozen": False,
        "docs_enabled": config.API_DOCS_ENABLED,
    }


@pytest.mark.parametrize("active", [True, False])
def test_informations_systeme_annoncent_la_documentation(client, monkeypatch, active):
    """L'interface n'affiche le lien /api/docs que si la documentation est active (API_DOCS)."""
    monkeypatch.setattr(config, "API_DOCS_ENABLED", active)
    assert client.get("/api/system/info").json()["docs_enabled"] is active


def test_ouvrir_le_dossier_des_donnees_depuis_la_machine_seulement(monkeypatch):
    ouverts = []
    monkeypatch.setattr(system_routes, "_open_folder", ouverts.append)
    with TestClient(app) as distant:  # client « testclient » : pas une adresse locale
        response = distant.post("/api/system/open-data-dir?lang=en", json={})
        assert response.status_code == 403
        assert response.json() == {
            "detail": "Action reserved for the user of this machine",
            "code": "api.local_only",
            "params": {},
        }
    with TestClient(app, client=("127.0.0.1", 50000)) as local:
        refus = local.post("/api/system/open-data-dir", content=b"{}", headers={"Content-Type": "text/plain"})
        assert refus.status_code == 415
        assert local.post("/api/system/open-data-dir", json={}).status_code == 204
    assert ouverts == [config.DATA_DIR]


def test_battement_de_l_interface(client):
    """POST /api/system/heartbeat : 204, horodatage monotone rangé pour le lanceur (mode navigateur)."""
    assert app.state.last_heartbeat is None  # remis à zéro au démarrage du serveur
    avant = time.monotonic()
    reponse = client.post("/api/system/heartbeat", json={})
    assert reponse.status_code == 204
    assert reponse.content == b""
    assert avant <= app.state.last_heartbeat <= time.monotonic()
    # Corps non JSON (anti-CSRF) : 415, horodatage inchangé.
    precedent = app.state.last_heartbeat
    refus = client.post("/api/system/heartbeat", content=b"{}", headers={"Content-Type": "text/plain"})
    assert refus.status_code == 415
    assert app.state.last_heartbeat == precedent
    # Le lanceur lit aussi les scans en cours dans l'état de l'application.
    assert app.state.job_manager is jobs_routes.manager


def test_battement_exige_le_jeton(client, monkeypatch):
    monkeypatch.setattr(config, "API_TOKEN", "s3cret-jeton")
    refus = client.post("/api/system/heartbeat", json={})
    assert refus.status_code == 401
    assert app.state.last_heartbeat is None
    accepte = client.post("/api/system/heartbeat", json={}, headers={"X-API-Token": "s3cret-jeton"})
    assert accepte.status_code == 204
    assert app.state.last_heartbeat is not None


def test_requetes_de_l_api_comptees_comme_activite(client, monkeypatch):
    """Revue : une interface sans battement (ancienne, en cache) arrêtée en pleine utilisation.

    Toute requête /api acceptée est notée pour le lanceur (app.state.last_api_activity),
    sauf la sonde de santé (le lanceur l'appelle lui-même au démarrage) ; une requête
    refusée faute de jeton ne compte pas.
    """
    assert app.state.last_api_activity is None  # remis à zéro au démarrage du serveur
    client.get("/api/health")
    client.get("/")
    assert app.state.last_api_activity is None
    avant = time.monotonic()
    assert client.get("/api/history").status_code == 200
    assert avant <= app.state.last_api_activity <= time.monotonic()
    monkeypatch.setattr(app.state, "last_api_activity", None)
    monkeypatch.setattr(config, "API_TOKEN", "s3cret-jeton")
    assert client.get("/api/history").status_code == 401
    assert app.state.last_api_activity is None
    assert client.get("/api/history", headers={"X-API-Token": "s3cret-jeton"}).status_code == 200
    assert app.state.last_api_activity is not None


@pytest.mark.parametrize(
    ("erreur", "langue", "detail"),
    [
        (
            FileNotFoundError(2, "No such file or directory: 'xdg-open'"),
            "en",
            "Cannot open the data folder (no file manager available or access denied). Folder: ",
        ),
        (
            PermissionError(13, "Permission denied"),
            "fr",
            "Impossible d'ouvrir le dossier des données (aucun gestionnaire de fichiers disponible ou accès refusé). Dossier : ",
        ),
    ],
    ids=["xdg-open-absent", "acces-refuse"],
)
def test_ouverture_du_dossier_impossible_explique(monkeypatch, erreur, langue, detail):
    """Revue finale : gestionnaire de fichiers absent ou accès refusé = 500 explicite, pas générique."""

    def echec(path):
        raise erreur

    monkeypatch.setattr(system_routes, "_open_folder", echec)
    with TestClient(app, client=("127.0.0.1", 50000)) as local:
        response = local.post(f"/api/system/open-data-dir?lang={langue}", json={})
    assert response.status_code == 500
    assert response.json() == {
        "detail": detail + str(config.DATA_DIR),
        "code": "api.open_failed",
        "params": {"path": str(config.DATA_DIR)},
    }


def test_open_folder_sans_xdg_open(monkeypatch, tmp_path):
    """Linux sans xdg-open : Popen lève FileNotFoundError, que la route convertit en api.open_failed."""

    def sans_xdg_open(*args, **kwargs):
        raise FileNotFoundError(2, "No such file or directory", "xdg-open")

    monkeypatch.setattr(system_routes.sys, "platform", "linux")
    monkeypatch.setattr(system_routes.subprocess, "Popen", sans_xdg_open)
    monkeypatch.setattr(config, "DATA_DIR", tmp_path / "donnees")
    with pytest.raises(FileNotFoundError):
        system_routes._open_folder(config.DATA_DIR)
    with TestClient(app, client=("127.0.0.1", 50000)) as local:
        response = local.post("/api/system/open-data-dir", json={})
    assert response.status_code == 500
    assert response.json()["code"] == "api.open_failed"
    assert (tmp_path / "donnees").is_dir()  # le dossier a bien été créé avant l'échec d'ouverture
