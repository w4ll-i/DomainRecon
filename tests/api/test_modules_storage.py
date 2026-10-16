# =============================================================================
# DomainRecon - Tests du stockage générique des modules (colonne `modules`)
# =============================================================================
# `modules` : {nom_module: {status, data, duration, error}}, réservé aux modules
# du registre. Les anciennes colonnes (dns_records, tls_certificate…) restent
# écrites et lues comme avant ; `modules` vaut None pour un scan d'avant la v2.
# La migration de la base existante est testée dans tests/core/test_database.py.
# =============================================================================

import logging

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import delete

from domainrecon.api import storage
from domainrecon.api.app import app
from domainrecon.api.routes import scans as scans_routes
from domainrecon.core.database import Base, SessionLocal, engine
from domainrecon.core.models import Scan
from domainrecon.i18n import msg, render

# Comportement des 18 modules historiques : registre ramené à eux (tests/conftest.py).
pytestmark = pytest.mark.usefixtures("registre_historique")

MODULES = {
    "virustotal": {
        "status": "ok",
        "data": {"malicious": 0, "harmless": 61},
        "duration": 1.84,
        "error": None,
    },
    "shodan": {
        "status": "timeout",
        "data": {},
        "duration": 10.0,
        # Message traduisible, comme dans module_status : rendu à la lecture.
        "error": msg("orchestrator.timeout", seconds=10),
    },
}

DNS = {"A": ["93.184.216.34"]}


@pytest.fixture
def client():
    with TestClient(app) as c:
        yield c


@pytest.fixture
def scans_crees():
    """Identifiants des scans créés par un test, supprimés ensuite de la base des tests."""
    # Les tables existent déjà si l'application a démarré avant (sinon, ce test seul les crée).
    Base.metadata.create_all(bind=engine)
    ids: list[int] = []
    yield ids
    with SessionLocal() as db:
        db.execute(delete(Scan).where(Scan.id.in_(ids)))
        db.commit()


def _resultat(domain: str, **overrides) -> dict:
    """Résultat minimal d'un scan, dans la forme que renvoie l'orchestrateur."""
    result = {
        "domain": domain,
        "ip_address": "93.184.216.34",
        "dns_records": DNS,
        "tls_certificate": {"measured": True, "protocol": "TLSv1.3"},
        "module_status": {"dns_records": {"status": "ok", "error": None}},
        "scan_duration": 3.2,
        "status": "success",
        "error_message": None,
    }
    result.update(overrides)
    return result


def _modules_null_en_sql(scan_id: int) -> bool:
    """Vrai si la colonne `modules` vaut NULL en SQL (et non le JSON « null »)."""
    with SessionLocal() as db:
        return db.query(Scan.id).filter(Scan.id == scan_id, Scan.modules.is_(None)).first() is not None


def _modules_lus(scan_id: int):
    with SessionLocal() as db:
        return db.query(Scan.modules).filter(Scan.id == scan_id).scalar()


def _modules_attendus_en(lang: str) -> dict:
    """MODULES tel que l'API le rend : messages remplacés par leur texte."""
    return render(MODULES, lang)


# =============================================================================
# Écriture : save_scan
# =============================================================================


def test_save_scan_ecrit_les_modules_et_les_anciennes_colonnes(scans_crees):
    scan_id = storage.save_scan(_resultat("v2.modules.example", modules=MODULES))
    scans_crees.append(scan_id)

    assert _modules_lus(scan_id) == MODULES
    # Les anciennes colonnes ne sont pas retirées : elles restent écrites comme avant.
    with SessionLocal() as db:
        scan = db.get(Scan, scan_id)
        assert scan.dns_records == DNS
        assert scan.tls_certificate == {"measured": True, "protocol": "TLSv1.3"}
        assert scan.module_status == {"dns_records": {"status": "ok", "error": None}}


def test_save_scan_sans_modules_laisse_la_colonne_vide(scans_crees):
    """Résultat de l'orchestrateur actuel (sans clé `modules`) : NULL, comme un ancien scan."""
    scan_id = storage.save_scan(_resultat("sans.modules.example"))
    scans_crees.append(scan_id)

    assert _modules_lus(scan_id) is None
    assert _modules_null_en_sql(scan_id)


def test_save_scan_modules_none_est_enregistre_en_null(scans_crees, caplog):
    with caplog.at_level(logging.WARNING, logger="domainrecon.api.storage"):
        scan_id = storage.save_scan(_resultat("none.modules.example", modules=None))
    scans_crees.append(scan_id)

    assert _modules_null_en_sql(scan_id)  # NULL SQL, pas le JSON « null »
    assert "ignorés" not in caplog.text


@pytest.mark.parametrize("valeur", [[], ["shodan"], "shodan", 42])
def test_save_scan_ecarte_des_modules_qui_ne_sont_pas_un_dictionnaire(scans_crees, caplog, valeur):
    """Le scan est enregistré quand même : une collecte entière ne se perd pas pour un champ annexe."""
    with caplog.at_level(logging.WARNING, logger="domainrecon.api.storage"):
        scan_id = storage.save_scan(_resultat("invalide.modules.example", modules=valeur))
    scans_crees.append(scan_id)

    assert _modules_null_en_sql(scan_id)
    assert "invalide.modules.example" in caplog.text
    assert "ignorés" in caplog.text
    with SessionLocal() as db:
        assert db.get(Scan, scan_id).dns_records == DNS


# =============================================================================
# Lecture : ScanResponse, /api/scan/{id}
# =============================================================================


def test_ancien_scan_a_modules_none(client, scans_crees):
    """Scan d'avant la v2 : `modules` vaut null ; ses résultats restent dans les anciens champs."""
    with SessionLocal() as db:
        scan = Scan(
            domain="ancien.modules.example",
            status="success",
            dns_records={"A": ["192.0.2.1"]},
            module_status={"dns_records": {"status": "ok", "error": None}},
        )
        db.add(scan)
        db.commit()
        scan_id = scan.id
    scans_crees.append(scan_id)

    body = client.get(f"/api/scan/{scan_id}").json()

    assert "modules" in body
    assert body["modules"] is None
    assert body["dns_records"] == {"A": ["192.0.2.1"]}
    assert body["module_status"] == {"dns_records": {"status": "ok", "error": None}}


def test_nouveau_scan_expose_ses_modules(client, scans_crees):
    scan_id = storage.save_scan(_resultat("nouveau.modules.example", modules=MODULES))
    scans_crees.append(scan_id)

    body = client.get(f"/api/scan/{scan_id}?lang=en").json()

    assert body["modules"] == _modules_attendus_en("en")
    assert body["modules"]["shodan"]["error"] == "Timed out (10 s)"
    # Les anciens champs sont lus comme avant.
    assert body["dns_records"] == DNS
    assert body["tls_certificate"]["protocol"] == "TLSv1.3"
    # Les listes ne transportent pas les blobs des modules.
    (entree,) = client.get("/api/history?domain=nouveau.modules.example").json()["scans"]
    assert "modules" not in entree

    assert client.get(f"/api/scan/{scan_id}?lang=fr").json()["modules"] == _modules_attendus_en("fr")


def test_les_anciennes_colonnes_restent_lues_en_priorite(client, scans_crees):
    """Même nom dans les deux : le champ historique n'est jamais remplacé par `modules`."""
    modules = {
        "dns_records": {"status": "ok", "data": {"A": ["198.51.100.9"]}, "duration": 0.1, "error": None}
    }
    scan_id = storage.save_scan(_resultat("priorite.modules.example", modules=modules))
    scans_crees.append(scan_id)

    body = client.get(f"/api/scan/{scan_id}").json()

    assert body["dns_records"] == DNS
    assert body["modules"] == modules


def test_modules_vide_n_est_pas_un_ancien_scan(client, scans_crees):
    """{} (scan récent sans résultat générique) se distingue de null (ancien scan)."""
    scan_id = storage.save_scan(_resultat("vide.modules.example", modules={}))
    scans_crees.append(scan_id)

    assert client.get(f"/api/scan/{scan_id}").json()["modules"] == {}


def test_modules_inattendu_en_base_est_lu_comme_absent(client, scans_crees):
    """Valeur qui n'est pas un dictionnaire (base modifiée à la main) : le scan reste lisible."""
    with SessionLocal() as db:
        scan = Scan(domain="inattendu.modules.example", status="success", modules=["pas", "un", "dict"])
        db.add(scan)
        db.commit()
        scan_id = scan.id
    scans_crees.append(scan_id)

    response = client.get(f"/api/scan/{scan_id}")

    assert response.status_code == 200
    assert response.json()["modules"] is None


def test_post_scan_enregistre_et_renvoie_les_modules(client, monkeypatch, scans_crees):
    """De bout en bout : résultat du scanner, enregistrement, réponse de l'API."""

    async def faux_scan(domain):
        return _resultat(domain, modules=MODULES)

    monkeypatch.setattr(scans_routes, "perform_full_scan", faux_scan)

    response = client.post("/api/scan", json={"domain": "post.modules.example"})
    assert response.status_code == 200, response.text
    body = response.json()
    scans_crees.append(body["id"])

    assert body["modules"] == _modules_attendus_en("fr")
    assert body["dns_records"] == DNS
    assert _modules_lus(body["id"]) == MODULES


def test_openapi_declare_modules_facultatif():
    schema = app.openapi()["components"]["schemas"]["ScanResponse"]

    assert "modules" in schema["properties"]
    assert "modules" not in schema.get("required", [])
