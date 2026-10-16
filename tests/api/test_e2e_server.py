# =============================================================================
# DomainRecon - Tests du serveur E2E (tests/e2e_server.py)
# =============================================================================
# Le seed est vérifié sur une base à part (la base des tests reste intacte) ;
# le faux scanner est vérifié de bout en bout à travers l'API des tâches, avec
# un remplacement annulé en fin de test (monkeypatch). Les résultats simulés
# doivent avoir la forme de ceux du vrai scanner, messages traduisibles compris.
# =============================================================================

import json
import os
import time
from concurrent.futures import ThreadPoolExecutor
from concurrent.futures import TimeoutError as FutureTimeout

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, delete, func, select
from sqlalchemy.orm import sessionmaker

from domainrecon.api import storage
from domainrecon.api.app import app
from domainrecon.api.routes import jobs as job_routes
from domainrecon.core.database import Base, SessionLocal
from domainrecon.core.models import Scan
from domainrecon.i18n import catalog, is_msg, placeholders
from domainrecon.scanner import registry
from tests import e2e_server as e2e

# Comportement des 18 modules historiques : registre ramené à eux (tests/conftest.py).
pytestmark = pytest.mark.usefixtures("registre_historique")

COLUMNS = {attr.key for attr in Scan.__mapper__.column_attrs}
# Colonnes d'un résultat de scan (storage._RESULT_COLUMNS) : tout sauf ce que la base ou l'utilisateur pose,
# `modules` (modules du registre), que l'orchestrateur actuel ne produit pas, et le profil et les modules
# lancés, que le gestionnaire de tâches ajoute au résultat avant de l'enregistrer (api/jobs.py).
RESULT_COLUMNS = COLUMNS - {"id", "scan_timestamp", "tags", "notes", "modules", "profile", "modules_launched"}

# Délai maximal de lecture d'un flux d'événements, en secondes.
EVENTS_TIMEOUT = 15.0


def _read_events(client: TestClient, job_id: str) -> list[tuple[str, dict]]:
    events: list[tuple[str, dict]] = []
    name = None
    with client.stream("GET", f"/api/scans/{job_id}/events") as response:
        assert response.status_code == 200
        assert response.headers["content-type"].startswith("text/event-stream")
        for line in response.iter_lines():
            if line.startswith("event:"):
                name = line.split(":", 1)[1].strip()
            elif line.startswith("data:") and name:
                events.append((name, json.loads(line.split(":", 1)[1])))
                if name in ("done", "failed", "cancelled"):
                    break
    return events


def _events(client: TestClient, job_id: str, timeout: float = EVENTS_TIMEOUT) -> list[tuple[str, dict]]:
    """Événements SSE d'une tâche, jusqu'à l'événement final ; échec si le flux dépasse `timeout`."""
    pool = ThreadPoolExecutor(max_workers=1)
    try:
        return pool.submit(_read_events, client, job_id).result(timeout=timeout)
    except FutureTimeout:
        pytest.fail(f"Flux d'événements de la tâche {job_id} sans fin après {timeout:g} s")
    finally:
        pool.shutdown(wait=False, cancel_futures=True)


def _messages(value):
    """Tous les messages traduisibles d'une valeur (imbriqués compris)."""
    if is_msg(value):
        yield value
        yield from _messages(value["p"])
    elif isinstance(value, dict):
        for item in value.values():
            yield from _messages(item)
    elif isinstance(value, list):
        for item in value:
            yield from _messages(item)


@pytest.fixture
def saved_scans():
    """Identifiants des scans enregistrés par un test, supprimés ensuite de la base des tests."""
    ids: list[int] = []
    yield ids
    with SessionLocal() as db:
        db.execute(delete(Scan).where(Scan.id.in_(ids)))
        db.commit()


@pytest.mark.parametrize("variant", ["good", "weak", "partial", "live", "legacy"])
def test_les_resultats_simules_ont_la_forme_d_un_scan(variant):
    result = e2e.build_scan_result("example.com", variant=variant)
    if variant == "legacy":
        assert set(result) <= COLUMNS
    else:
        assert set(result) == RESULT_COLUMNS
        assert set(result["module_status"]) == set(e2e.MODULE_NAMES)


def test_les_variantes_portent_les_verdicts_attendus():
    good = e2e.build_scan_result("example.com")
    weak = e2e.build_scan_result("shop.example.com", variant="weak")
    assert (good["security_score"]["score"], good["security_score"]["grade"]) == (84, "B")
    assert (weak["security_score"]["score"], weak["security_score"]["grade"]) == (34, "F")
    assert {p["key"] for p in weak["security_score"]["penalties"]} == {"port_21", "port_3306"}
    assert e2e.build_scan_result("x.example.net", variant="partial")["status"] == "partial"
    live = e2e.build_scan_result("live.example.com", variant="live")
    assert live["module_status"]["network_extended"]["status"] == "timeout"
    overridden = e2e.build_scan_result("example.com", a_records=["10.0.0.1"], score=(62, "C"))
    assert overridden["dns_records"]["A"] == ["10.0.0.1"]
    assert overridden["security_score"]["grade"] == "C"


@pytest.mark.parametrize(
    ("variant", "score"),
    [
        ("good", None),
        ("weak", None),
        ("partial", None),
        ("live", None),
        ("good", (62, "C")),
        ("good", (71, "C")),
    ],
)
def test_la_note_simulee_concorde_avec_son_detail(variant, score):
    """Score, points mesurés et pénalités se recoupent : la note vient du vrai barème."""
    result = e2e.build_scan_result("example.com", variant=variant, score=score)
    rating = result["security_score"]
    counted = [item for item in rating["breakdown"].values() if item["counted"]]
    assert rating["measured_points"] == sum(item["score"] for item in counted)
    assert rating["measured_max"] == sum(item["max"] for item in counted)
    # Arrondi à l'entier le plus proche (moitié vers le haut), puis pénalités de ports.
    base = (200 * rating["measured_points"] + rating["measured_max"]) // (2 * rating["measured_max"])
    assert rating["score"] == base - sum(p["points"] for p in rating["penalties"])
    if score is not None:
        assert (rating["score"], rating["grade"]) == score
    # Variante « partial » : WHOIS en échec, son critère (5 points sur 105) n'est pas mesuré.
    assert rating["coverage"] == (95 if variant == "partial" else 100)
    assert all(is_msg(item["detail"]) for item in rating["breakdown"].values())


def test_une_note_hors_de_portee_est_refusee():
    with pytest.raises(ValueError, match="hors de portée"):
        e2e.build_scan_result("example.com", score=(3, "F"))
    with pytest.raises(ValueError, match="weak"):
        e2e.build_scan_result("shop.example.com", variant="weak", score=(34, "F"))


def test_le_statut_des_sous_domaines_est_celui_de_l_orchestrateur():
    good = e2e.build_scan_result("example.com")
    status = good["module_status"]["subdomains"]
    assert status["total_found"] == len(good["subdomains"])
    assert (status["source"], status["partial"]) == ("crt.sh", False)
    partial = e2e.build_scan_result("partial.example.net", variant="partial")["module_status"]["subdomains"]
    assert (partial["source"], partial["partial"]) == ("certspotter", True)


@pytest.mark.parametrize("variant", ["good", "weak", "partial", "live"])
def test_les_textes_simules_sont_des_messages_du_catalogue(variant):
    result = e2e.build_scan_result("example.com", variant=variant)
    messages = list(_messages(result))
    assert messages
    for message in messages:
        code, params = message["$t"], message["p"]
        for lang in ("fr", "en"):
            assert code in catalog(lang), f"{code} absent du catalogue {lang}"
            assert placeholders(catalog(lang)[code]) <= set(params), f"paramètre manquant pour {code}"
    # Les champs textuels que le vrai scanner émet en messages.
    for state in result["module_status"].values():
        assert state["error"] is None or is_msg(state["error"])
    assert result["error_message"] is None or is_msg(result["error_message"])
    assert all(is_msg(p["label"]) for p in result["security_score"]["penalties"])
    assert all(is_msg(r) for r in result["email_security"]["recommendations"])
    assert all(is_msg(d) for d in result["cors"]["details"])
    assert all(is_msg(t["evidence"]) for t in result["subdomain_takeover"])
    assert all(
        is_msg(check["detail"]) or isinstance(check["detail"], str)
        for check in result["security_headers"]["checks"].values()
    )


def test_seul_le_scan_legacy_garde_des_textes_bruts():
    legacy = e2e.build_scan_result("legacy.example.org", variant="legacy")
    assert not list(_messages(legacy))
    assert isinstance(legacy["tls_certificate"]["error"], str)


def test_l_api_rend_les_messages_dans_la_langue_demandee(saved_scans):
    with TestClient(app) as client:
        partial = storage.save_scan(e2e.build_scan_result("partial.example.net", variant="partial"))
        weak = storage.save_scan(e2e.build_scan_result("shop.example.com", variant="weak"))
        legacy = storage.save_scan(e2e.build_scan_result("legacy.example.org", variant="legacy"))
        saved_scans.extend([partial, weak, legacy])

        english = client.get(f"/api/scan/{partial}?lang=en").json()
        french = client.get(f"/api/scan/{partial}?lang=fr").json()
        assert english["module_status"]["whois_data"]["error"] == "WHOIS unavailable: server unreachable"
        assert french["module_status"]["whois_data"]["error"] == "WHOIS indisponible : serveur injoignable"
        assert english["module_status"]["network_extended"]["error"] == "Timed out (60 s)"
        assert french["module_status"]["network_extended"]["error"] == "Délai dépassé (60 s)"
        assert (
            english["module_status"]["screenshot"]["error"]
            == "Playwright or its Chromium browser is not installed"
        )
        assert english["error_message"] == "2 module(s) failed: whois_data, network_extended (timed out)"
        assert (
            french["error_message"] == "2 module(s) en échec : whois_data, network_extended (délai dépassé)"
        )
        assert english["whois_data"]["error"] == english["module_status"]["whois_data"]["error"]
        assert "$t" not in json.dumps(english) and "$t" not in json.dumps(french)

        shop = client.get(f"/api/scan/{weak}?lang=en").json()
        assert [p["label"] for p in shop["security_score"]["penalties"]] == [
            "Port 21 (FTP) exposed",
            "Port 3306 (MySQL) exposed",
        ]
        assert (
            shop["subdomain_takeover"][0]["evidence"]
            == "CNAME to Heroku but no HTTP(S) response: verify manually"
        )
        assert shop["cors"]["details"] == [
            "Origin https://evil.com is reflected without credentials: a third-party site can read unauthenticated responses"
        ]

        # Ancien scan : textes bruts rendus tels quels, quelle que soit la langue.
        for lang in ("fr", "en"):
            old = client.get(f"/api/scan/{legacy}?lang={lang}").json()
            assert old["tls_certificate"]["error"] == "certificate verify failed: self signed certificate"


def test_le_seed_remplit_une_base_a_part(tmp_path):
    engine = create_engine(f"sqlite:///{(tmp_path / 'seed.db').as_posix()}")
    Base.metadata.create_all(bind=engine)
    factory = sessionmaker(bind=engine)
    try:
        ids = e2e.seed_database(factory, tmp_path / "screenshots")
        assert len(ids["example.com"]) == 3
        assert len(ids["shop.example.com"]) == 1
        assert len([d for d in ids if d.startswith("filler-")]) == e2e.FILLER_COUNT
        shot = tmp_path / "screenshots" / e2e.SCREENSHOT_NAME
        assert shot.read_bytes().startswith(b"\x89PNG\r\n\x1a\n")
        with factory() as db:
            assert db.scalar(select(func.count(Scan.id))) == e2e.FILLER_COUNT + 7
            latest = db.get(Scan, ids["example.com"][-1])
            assert latest.tags == ["prod"]
            assert latest.screenshot_path == e2e.SCREENSHOT_NAME
            # error_message (colonne TEXT) est rangé en JSON, comme save_scan() : l'API en refait un message.
            partial = db.get(Scan, ids["partial.example.net"][0])
            assert is_msg(json.loads(partial.error_message))
    finally:
        engine.dispose()


def test_le_faux_scanner_passe_par_l_api_des_taches(monkeypatch):
    with TestClient(app) as client:
        patched = e2e.install_fake_scanner(step_delay=0.01, slow_delay=0.3, setter=monkeypatch.setattr)
        assert "domainrecon.api.routes.jobs.manager.runner" in patched
        assert "domainrecon.api.routes.jobs.ensure_target_allowed" in patched
        assert "domainrecon.scanner.orchestrator" in patched
        response = client.post("/api/scans", json={"domain": "live-demo.example.com"})
        assert response.status_code == 202, response.text
        events = _events(client, response.json()["id"])
        assert [name for name, _ in events].count("module") == 16
        assert events[-1][0] == "done"
        scan = client.get(f"/api/scan/{events[-1][1]['scan_id']}").json()
        assert scan["domain"] == "live-demo.example.com"
        assert scan["module_status"]["network_extended"]["status"] == "timeout"
        # Le texte enregistré est un message rendu à la lecture, pas du français figé.
        english = client.get(f"/api/scan/{scan['id']}?lang=en").json()
        assert english["module_status"]["network_extended"]["error"] == "Timed out (60 s)"


def test_le_faux_scanner_annonce_les_modules_du_profil(monkeypatch):
    """Le faux scanner suit le plan de la tâche : modules annoncés et total de la progression concordent."""
    with TestClient(app) as client:
        e2e.install_fake_scanner(step_delay=0.01, slow_delay=0.3, setter=monkeypatch.setattr)
        response = client.post("/api/scans", json={"domain": "rapide-demo.example.com", "profile": "rapide"})
        assert response.status_code == 202, response.text
        events = _events(client, response.json()["id"])
        expected = [spec.name for spec in registry.get_modules("rapide")]
        assert 0 < len(expected) < len(e2e.MODULE_NAMES)
        assert [data["name"] for name, data in events if name == "module"] == expected
        assert [data for name, data in events if name == "progress"][-1] == {
            "done": len(expected),
            "total": len(expected),
        }
        assert events[-1][0] == "done"


def test_le_faux_scanner_simule_panne_et_annulation(monkeypatch):
    with TestClient(app) as client:
        e2e.install_fake_scanner(step_delay=0.01, slow_delay=0.3, setter=monkeypatch.setattr)
        boom = client.post("/api/scans", json={"domain": "boom.example.com"}).json()["id"]
        assert _events(client, boom)[-1][0] == "failed"
        slow = client.post("/api/scans", json={"domain": "slow.example.com"}).json()["id"]
        assert client.post(f"/api/scans/{slow}/cancel", json={}).status_code == 202
        assert _events(client, slow)[-1][0] == "cancelled"


def test_un_crochet_disparu_fait_echouer_l_installation(monkeypatch):
    monkeypatch.delattr(job_routes, "ensure_target_allowed")
    with pytest.raises(AttributeError, match="ensure_target_allowed"):
        e2e.install_fake_scanner(setter=monkeypatch.setattr)


def test_l_environnement_e2e_ignore_le_env_du_developpeur(monkeypatch, tmp_path):
    fake_environ = {"ALLOWED_HOSTS": "evil.example", "CORS_ORIGINS": "https://evil.example", "API_DOCS": "0"}
    monkeypatch.setattr(os, "environ", fake_environ)
    e2e.configure_environment(tmp_path / "data", 9876)
    # Une valeur vide vaut « réglage absent » : les défauts de config.py s'appliquent.
    for name in ("ALLOWED_HOSTS", "CORS_ORIGINS", "API_DOCS", "API_TOKEN"):
        assert fake_environ[name] == ""
    assert fake_environ["PORT"] == "9876"
    assert fake_environ["DATA_DIR"] == str(tmp_path / "data")


def test_les_dossiers_de_donnees_abandonnes_sont_purges(tmp_path):
    old = tmp_path / f"{e2e.DATA_DIR_PREFIX}ancien"
    recent = tmp_path / f"{e2e.DATA_DIR_PREFIX}recent"
    other = tmp_path / "autre-dossier"
    stray_file = tmp_path / f"{e2e.DATA_DIR_PREFIX}fichier"
    for folder in (old, recent, other):
        folder.mkdir()
        (folder / "e2e.db").write_bytes(b"x")
    stray_file.write_bytes(b"x")
    two_hours_ago = time.time() - 2 * 3600
    for path in (old, other, stray_file):
        os.utime(path, (two_hours_ago, two_hours_ago))

    assert e2e.purge_stale_data_dirs(root=tmp_path) == 1
    assert not old.exists()
    # Dossier récent (serveur peut-être en cours), autre nom, simple fichier : intacts.
    assert recent.exists() and other.exists() and stray_file.exists()
    assert e2e.purge_stale_data_dirs(root=tmp_path) == 0
    assert e2e.purge_stale_data_dirs(root=tmp_path / "absent") == 0
