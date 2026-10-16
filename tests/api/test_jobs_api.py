# =============================================================================
# DomainRecon - Tests des routes /api/scans (tâches, SSE, annulation, 429)
# =============================================================================
# Le scanner est remplacé par des faux (JobManager.runner) ; l'enregistrement
# est réel (base de test). Aucune résolution DNS : ensure_target_allowed est
# remplacé.
# =============================================================================

import asyncio
import json
import threading
import time

import pytest
from fastapi.testclient import TestClient

from domainrecon.api import storage
from domainrecon.api.app import app
from domainrecon.api.jobs import JobManager
from domainrecon.api.routes import jobs as jobs_routes
from domainrecon.api.routes import scans as scans_routes
from domainrecon.api.schemas import ScanJobRequest
from domainrecon.i18n import msg
from domainrecon.scanner import MODULE_NAMES, registry
from domainrecon.scanner.errors import TargetNotAllowedError

# Comportement des 18 modules historiques : registre ramené à eux (tests/conftest.py).
pytestmark = pytest.mark.usefixtures("registre_historique")

INCONNUE = "0" * 32


def _resultat(domain: str) -> dict:
    return {
        "domain": domain,
        "ip_address": "93.184.216.34",
        "module_status": {name: {"status": "ok", "error": None} for name in MODULE_NAMES},
        "security_score": {"score": 90, "max_score": 100, "grade": "A", "breakdown": {}},
        "status": "success",
    }


# Les faux scanners ont la forme de perform_full_scan : le gestionnaire leur transmet
# aussi le plan du scan (profile, authorized_target, selected, available_keys).
_MODULES_COMPLET = tuple(spec.name for spec in registry.get_modules("complet") if spec.name in MODULE_NAMES)


async def _scan_rapide(domain, on_module, **plan):
    # Profil « complet » : les modules actifs (ports, takeover) n'y sont pas.
    for name in _MODULES_COMPLET:
        on_module(name, "ok", 0.01)
    return _resultat(domain)


async def _scan_bloque(domain, on_module, **plan):
    on_module("dns_records", "ok", 0.01)
    await asyncio.Event().wait()


@pytest.fixture
def cible_publique(monkeypatch):
    """Contrôle de cible sans DNS réel : toute cible résout vers une adresse publique."""

    async def resoudre(host):
        return ["93.184.216.34"]

    monkeypatch.setattr(jobs_routes, "ensure_target_allowed", resoudre)


@pytest.fixture
def client_avec():
    """Fabrique un TestClient dont les routes utilisent un gestionnaire de test."""

    def fabriquer(runner, max_concurrent=2):
        gestionnaire = JobManager(max_concurrent, runner=runner)  # enregistrement réel
        app.dependency_overrides[jobs_routes.get_job_manager] = lambda: gestionnaire
        return TestClient(app)

    yield fabriquer
    app.dependency_overrides.pop(jobs_routes.get_job_manager, None)


def _evenements(client, job_id, **params) -> list[tuple[str, dict]]:
    with client.stream("GET", f"/api/scans/{job_id}/events", params=params) as response:
        assert response.status_code == 200
        assert response.headers["content-type"].startswith("text/event-stream")
        assert response.headers["cache-control"] == "no-cache"
        texte = "".join(response.iter_text())
    evenements = []
    for bloc in texte.strip().split("\n\n"):
        ligne_evenement, ligne_donnees = bloc.split("\n")
        evenements.append(
            (ligne_evenement.removeprefix("event: "), json.loads(ligne_donnees.removeprefix("data: ")))
        )
    return evenements


def _attendre(client, job_id, condition, delai=5.0) -> dict:
    fin = time.monotonic() + delai
    while True:
        etat = client.get(f"/api/scans/{job_id}").json()
        if condition(etat):
            return etat
        if time.monotonic() > fin:
            raise AssertionError(f"état jamais atteint : {etat}")
        time.sleep(0.02)


def test_scan_en_tache_jusqu_au_resultat(client_avec, cible_publique):
    with client_avec(_scan_rapide) as client:
        response = client.post("/api/scans", json={"domain": "Tache.Example.com"})
        assert response.status_code == 202
        corps = response.json()
        assert set(corps) == {"id", "status"} and corps["status"] == "running"

        evenements = _evenements(client, corps["id"])
        assert [nom for nom, _ in evenements].count("module") == len(_MODULES_COMPLET)
        assert evenements[-2] == ("progress", {"done": 16, "total": 16})
        nom, donnees = evenements[-1]
        assert nom == "done"

        assert client.get(f"/api/scans/{corps['id']}").json() == {
            "id": corps["id"],
            "domain": "tache.example.com",
            "status": "done",
            "scan_id": donnees["scan_id"],
            "done": 16,
            "total": 16,
        }
        scan = client.get(f"/api/scan/{donnees['scan_id']}")
        assert scan.status_code == 200 and scan.json()["domain"] == "tache.example.com"
        # Reconnexion : mêmes événements, rejoués depuis le début.
        assert _evenements(client, corps["id"]) == evenements


def test_cible_invalide_ou_refusee_400(client_avec, cible_publique, monkeypatch):
    with client_avec(_scan_rapide) as client:
        response = client.post("/api/scans?lang=en", json={"domain": "pas une cible"})
        assert response.status_code == 400
        assert response.json()["code"] == "target.invalid"
        assert response.json()["detail"] == "Invalid target: 'pas une cible'"

        async def refuser(host):
            raise TargetNotAllowedError(msg("target.not_allowed_host", host=host))

        monkeypatch.setattr(jobs_routes, "ensure_target_allowed", refuser)
        response = client.post("/api/scans", json={"domain": "intranet.example.com"})
        assert response.status_code == 400
        assert response.json()["code"] == "target.not_allowed_host"
        assert response.json()["params"] == {"host": "intranet.example.com"}


def test_json_exige_et_identifiants(client_avec, cible_publique):
    with client_avec(_scan_rapide) as client:
        refus = client.post(
            "/api/scans", content=b'{"domain": "a.example.com"}', headers={"Content-Type": "text/plain"}
        )
        assert refus.status_code == 415
        for chemin in (f"/api/scans/{INCONNUE}", f"/api/scans/{INCONNUE}/events"):
            response = client.get(chemin)
            assert response.status_code == 404
            assert response.json()["code"] == "api.job_not_found"
        assert client.post(f"/api/scans/{INCONNUE}/cancel", json={}).status_code == 404
        assert client.get("/api/scans/pas-un-identifiant").status_code == 422


def test_annulation_et_429(client_avec, cible_publique):
    with client_avec(_scan_bloque, max_concurrent=1) as client:
        premier = client.post("/api/scans", json={"domain": "long.example.com"}).json()
        _attendre(client, premier["id"], lambda etat: etat["done"] == 1)
        refus = client.post("/api/scans?lang=en", json={"domain": "autre.example.com"})
        assert refus.status_code == 429
        assert refus.headers["retry-after"] == "30"
        assert refus.json()["code"] == "api.too_many_scans"

        annule = client.post(f"/api/scans/{premier['id']}/cancel", json={})
        assert annule.status_code == 202
        assert annule.json() == {"id": premier["id"], "status": "cancelled"}
        assert [nom for nom, _ in _evenements(client, premier["id"])] == ["module", "progress", "cancelled"]
        deja = client.post(f"/api/scans/{premier['id']}/cancel", json={})
        assert deja.status_code == 409
        assert deja.json()["code"] == "api.job_not_running"

        suivant = client.post("/api/scans", json={"domain": "autre.example.com"})
        assert suivant.status_code == 202
        client.post(f"/api/scans/{suivant.json()['id']}/cancel", json={})


def test_evenement_d_echec_traduit(client_avec, cible_publique):
    async def refuse(domain, on_module, **plan):
        raise TargetNotAllowedError(msg("target.not_allowed_host", host=domain))

    with client_avec(refuse) as client:
        job_id = client.post("/api/scans", json={"domain": "refus.example.com"}).json()["id"]
        ((nom, donnees),) = _evenements(client, job_id, lang="en")
        assert nom == "failed"
        assert donnees == {
            "code": "target.not_allowed_host",
            "params": {"host": "refus.example.com"},
            "detail": (
                "Target not allowed: “refus.example.com” resolves to a private, local or reserved address. "
                "To scan your own network, set ALLOW_PRIVATE_TARGETS=1."
            ),
        }
        assert client.get(f"/api/scans/{job_id}").json()["status"] == "failed"


@pytest.fixture
def gestionnaire_isole():
    """Gestionnaire de test pour POST /api/scan et /api/scans, lisible par le test (busy())."""
    gestionnaire = JobManager(2, runner=_scan_rapide)
    app.dependency_overrides[jobs_routes.get_job_manager] = lambda: gestionnaire
    yield gestionnaire
    app.dependency_overrides.pop(jobs_routes.get_job_manager, None)


def test_scan_synchrone_occupe_le_serveur_jusqu_a_l_enregistrement(gestionnaire_isole, monkeypatch):
    """Revue : POST /api/scan ignoré par busy(), le mode navigateur s'arrêtait en plein scan synchrone."""
    scan_libre, enregistrement_libre = threading.Event(), threading.Event()
    en_scan, en_enregistrement = threading.Event(), threading.Event()

    async def faux_scan(domain):
        en_scan.set()
        await asyncio.to_thread(scan_libre.wait, 10)
        return _resultat(domain)

    vrai_enregistrement = storage.save_scan

    def enregistrement_lent(result):
        en_enregistrement.set()
        enregistrement_libre.wait(10)
        return vrai_enregistrement(result)

    monkeypatch.setattr(scans_routes, "perform_full_scan", faux_scan)
    monkeypatch.setattr(storage, "save_scan", enregistrement_lent)
    reponses = []
    try:
        with TestClient(app) as client:
            requete = threading.Thread(
                target=lambda: reponses.append(
                    client.post("/api/scan", json={"domain": "synchrone.example.com"})
                )
            )
            requete.start()
            assert en_scan.wait(5)
            assert gestionnaire_isole.busy() is True  # scan en cours
            scan_libre.set()
            assert en_enregistrement.wait(5)
            assert gestionnaire_isole.busy() is True  # enregistrement en cours : résultat pas encore sauvé
            enregistrement_libre.set()
            requete.join(timeout=10)
    finally:
        scan_libre.set()
        enregistrement_libre.set()
    assert reponses[0].status_code == 200
    assert gestionnaire_isole.busy() is False
    gestionnaire_isole.reserve_slot()  # emplacements tous rendus
    gestionnaire_isole.reserve_slot()


def test_resolution_avant_la_tache_occupe_le_serveur(gestionnaire_isole, monkeypatch):
    """Entre la réservation de l'emplacement et la création de la tâche (contrôle DNS de la cible)."""
    libre, en_resolution = threading.Event(), threading.Event()

    async def resolution_lente(host):
        en_resolution.set()
        await asyncio.to_thread(libre.wait, 10)
        return ["93.184.216.34"]

    monkeypatch.setattr(jobs_routes, "ensure_target_allowed", resolution_lente)
    reponses = []
    try:
        with TestClient(app) as client:
            requete = threading.Thread(
                target=lambda: reponses.append(
                    client.post("/api/scans", json={"domain": "lente.example.com"})
                )
            )
            requete.start()
            assert en_resolution.wait(5)
            assert gestionnaire_isole._jobs == {}  # aucune tâche encore
            assert gestionnaire_isole.busy() is True
            libre.set()
            requete.join(timeout=10)
    finally:
        libre.set()
    assert reponses[0].status_code == 202


def test_limite_partagee_entre_scan_synchrone_et_taches(cible_publique, monkeypatch):
    """Review Focus n° 5 : un seul jeu d'emplacements pour /api/scan et /api/scans."""
    slots = threading.BoundedSemaphore(1)
    monkeypatch.setattr(jobs_routes.manager, "slots", slots)

    async def faux_scan(domain):
        raise AssertionError("le scan ne doit pas démarrer")

    monkeypatch.setattr(scans_routes, "perform_full_scan", faux_scan)
    assert slots.acquire(blocking=False)  # un scan « en cours »
    try:
        with TestClient(app) as client:
            synchrone = client.post("/api/scan", json={"domain": "occupe.example.com"})
            tache = client.post("/api/scans", json={"domain": "occupe.example.com"})
    finally:
        slots.release()
    for response in (synchrone, tache):
        assert response.status_code == 429
        assert response.json()["code"] == "api.too_many_scans"
        assert response.headers["retry-after"] == "30"


# --- Emplacement vérifié avant la résolution DNS (revue finale M5) ----------------------


def test_429_sans_resolution_dns(client_avec, monkeypatch):
    """Aucun emplacement libre : 429 aussitôt, sans occuper un thread de l'exécuteur à résoudre le nom."""
    resolutions = []

    async def resoudre(host):
        resolutions.append(host)
        return ["93.184.216.34"]

    monkeypatch.setattr(jobs_routes, "ensure_target_allowed", resoudre)
    with client_avec(_scan_bloque, max_concurrent=1) as client:
        premier = client.post("/api/scans", json={"domain": "long.example.com"}).json()
        assert resolutions == ["long.example.com"]
        for _ in range(3):  # rafale : le client réessaie
            refus = client.post("/api/scans?lang=en", json={"domain": "lent.example.com"})
            assert refus.status_code == 429
            assert refus.json()["code"] == "api.too_many_scans"
        assert resolutions == ["long.example.com"]  # pas une résolution de plus
        client.post(f"/api/scans/{premier['id']}/cancel", json={})


def test_cible_refusee_ne_garde_pas_l_emplacement(client_avec, monkeypatch):
    """La résolution échoue (cible refusée) : l'emplacement réservé pendant ce temps est rendu."""

    async def refuser(host):
        raise TargetNotAllowedError(msg("target.not_allowed_host", host=host))

    monkeypatch.setattr(jobs_routes, "ensure_target_allowed", refuser)
    with client_avec(_scan_bloque, max_concurrent=1) as client:
        for _ in range(3):  # une seule place : si elle était gardée, la 2e réponse serait un 429
            response = client.post("/api/scans", json={"domain": "intranet.example.com"})
            assert response.status_code == 400
            assert response.json()["code"] == "target.not_allowed_host"
        response = client.post("/api/scans", json={"domain": "pas une cible"})
        assert response.status_code == 400
        assert response.json()["code"] == "target.invalid"

        async def resoudre(host):
            return ["93.184.216.34"]

        monkeypatch.setattr(jobs_routes, "ensure_target_allowed", resoudre)
        reussi = client.post("/api/scans", json={"domain": "public.example.com"})
        assert reussi.status_code == 202
        client.post(f"/api/scans/{reussi.json()['id']}/cancel", json={})


def test_resolution_interrompue_rend_l_emplacement(monkeypatch):
    """Requête interrompue pendant la résolution (CancelledError) : l'emplacement n'est pas perdu."""

    async def interrompue(host):
        raise asyncio.CancelledError

    monkeypatch.setattr(jobs_routes, "ensure_target_allowed", interrompue)

    async def scenario():
        gestionnaire = JobManager(1, runner=_scan_bloque)
        with pytest.raises(asyncio.CancelledError):
            await jobs_routes.start_scan(ScanJobRequest(domain="interrompu.example.com"), gestionnaire)
        assert gestionnaire.slots.acquire(blocking=False)

    asyncio.run(scenario())


# --- Arrêt du serveur et échec du démarrage (revue finale M2, M3) ---------------------------


def test_arret_du_serveur_annule_les_scans_en_cours(cible_publique, monkeypatch):
    """Fermer la fenêtre en plein scan : les tâches sont annulées par le lifespan, emplacements rendus."""
    gestionnaire = JobManager(2, runner=_scan_bloque)
    monkeypatch.setattr(jobs_routes, "manager", gestionnaire)
    annulees = []
    cancel_all = gestionnaire.cancel_all

    async def espion(*args, **kwargs):
        annulees.append(await cancel_all(*args, **kwargs))
        return annulees[-1]

    gestionnaire.cancel_all = espion
    with TestClient(app) as client:
        job_id = client.post("/api/scans", json={"domain": "long.example.com"}).json()["id"]
        _attendre(client, job_id, lambda etat: etat["done"] == 1)
        assert gestionnaire._jobs[job_id].status == "running"
        assert annulees == []
    # Sortie du `with` : arrêt de l'application (lifespan), qui annule la tâche en cours.
    assert annulees == [1]
    job = gestionnaire._jobs[job_id]
    assert job.status == "cancelled" and job.finished_at is not None
    assert gestionnaire.slots.acquire(blocking=False) and gestionnaire.slots.acquire(blocking=False)


def test_echec_du_demarrage_note_sa_cause(monkeypatch):
    """Base illisible, schéma à migrer… : le lanceur affiche cette cause (app.state.startup_error)."""
    from domainrecon.api import storage
    from domainrecon.core.database import SchemaMigrationError

    def echec():
        raise SchemaMigrationError("La colonne scans.x est obligatoire : migration manuelle requise.")

    monkeypatch.setattr(storage, "prepare_storage", echec)
    with pytest.raises(SchemaMigrationError):
        with TestClient(app):
            pass
    assert isinstance(app.state.startup_error, SchemaMigrationError)
    monkeypatch.undo()
    with TestClient(app):  # un démarrage réussi efface la cause
        pass
    assert app.state.startup_error is None
