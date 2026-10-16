# =============================================================================
# DomainRecon - Tests des profils de scan et de l'autorisation des modules actifs
# =============================================================================
# POST /api/scans accepte `profile` (rapide, complet, personnalise), `selected` et
# `authorized_target` ; api/jobs.py arrête le plan du scan (plan_scan) et le
# transmet au scanner ; api/storage.py enregistre le profil et les modules lancés.
#
# Le registre réel ne compte que des modules passifs et sans clé API : les modules
# actif, sensible ou à clé que ces tests exigent y sont ajoutés le temps d'un test
# (fixture modules_demo). Deux scanners :
#   - un faux, qui note les arguments reçus et annonce les modules du plan ;
#   - le vrai orchestrateur, dont les modules sont remplacés par des faux sans
#     réseau, pour vérifier de bout en bout que le plan de la tâche (le total de la
#     progression) et ce qui est lancé concordent.
# L'enregistrement est réel (base de test) ; aucune résolution DNS.
# =============================================================================

import asyncio
import dataclasses
import json
import logging
import time
import typing

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import delete, func

from domainrecon.api import schemas, storage
from domainrecon.api.app import app
from domainrecon.api.jobs import JobManager, ScanPlan, plan_scan
from domainrecon.api.routes import jobs as jobs_routes
from domainrecon.core.database import Base, SessionLocal, engine
from domainrecon.core.models import Scan, Settings
from domainrecon.i18n import msg
from domainrecon.scanner import MODULE_NAMES, orchestrator, registry
from domainrecon.scanner.errors import message_of
from domainrecon.scanner.registry import ModuleSpec

# Comportement des 18 modules historiques : registre ramené à eux (tests/conftest.py).
pytestmark = pytest.mark.usefixtures("registre_historique")

CLE_VT = "vt-abcdefghijklmnop1234"
NOTE = {"score": 90, "max_score": 100, "grade": "A", "breakdown": {}, "coverage": 100}
# Modules d'origine dont le résultat est une liste (les autres rendent un dict).
MODULES_LISTE = frozenset({"subdomains", "technologies", "open_ports", "subdomain_takeover"})


def _noms(specs) -> list[str]:
    return [spec.name for spec in specs]


def _complet(*cles) -> list[str]:
    """Modules du profil « complet » pour ces clés API, sans autorisation : les modules passifs, et ceux à clé disponible."""
    return _noms(registry.get_modules("complet", cles))


class FauxScanner:
    """Faux perform_full_scan : note ses arguments, annonce les modules du plan, rend un résultat minimal."""

    def __init__(self):
        self.appels: list[dict] = []

    async def __call__(
        self,
        domain,
        on_module,
        profile="complet",
        authorized_target=False,
        *,
        selected=None,
        available_keys=(),
    ):
        self.appels.append(
            {
                "domain": domain,
                "profile": profile,
                "authorized_target": authorized_target,
                "selected": None if selected is None else list(selected),
                "available_keys": sorted(available_keys),
            }
        )
        specs = registry.get_modules(profile, available_keys, authorized_target, selected)
        for spec in specs:
            on_module(spec.name, "ok", 0.01)
        return {
            "domain": domain,
            "ip_address": "93.184.216.34",
            "module_status": {spec.name: {"status": "ok", "error": None} for spec in specs},
            "security_score": dict(NOTE),
            "status": "success",
        }


# =============================================================================
# Fixtures
# =============================================================================


@pytest.fixture(autouse=True)
def base_propre():
    """Aucune clé API avant et après chaque test ; les scans enregistrés par le test sont supprimés ensuite."""
    Base.metadata.create_all(bind=engine)
    with SessionLocal() as db:
        db.query(Settings).delete()
        avant = db.query(func.max(Scan.id)).scalar() or 0
        db.commit()
    yield
    with SessionLocal() as db:
        db.query(Settings).delete()
        db.execute(delete(Scan).where(Scan.id > avant))
        db.commit()


@pytest.fixture
def cible_publique(monkeypatch):
    """Contrôle de cible sans DNS réel : toute cible résout vers une adresse publique."""

    async def resoudre(host):
        return ["93.184.216.34"]

    monkeypatch.setattr(jobs_routes, "ensure_target_allowed", resoudre)


@pytest.fixture
def faux_scanner():
    return FauxScanner()


@pytest.fixture
def gestionnaire(faux_scanner, cible_publique):
    """Gestionnaire de test (faux scanner, enregistrement réel), à une seule place : une place gardée à tort se verrait."""
    jobs = JobManager(1, runner=faux_scanner)
    app.dependency_overrides[jobs_routes.get_job_manager] = lambda: jobs
    yield jobs
    app.dependency_overrides.pop(jobs_routes.get_job_manager, None)


@pytest.fixture
def client(gestionnaire):
    with TestClient(app) as c:
        yield c


async def _module_demo(context):
    return {"measured": True, "error": None}


def _spec(name, **champs) -> ModuleSpec:
    return ModuleSpec(name=name, **{"family": "web", "category": "passif", "run": _module_demo, **champs})


@pytest.fixture
def modules_demo(monkeypatch):
    """Registre réel complété de quatre modules qu'il n'a pas encore : actif, passif qui en dépend, à clé API, sensible à clé."""
    registre = dict(registry.MODULES)
    for spec in (
        _spec("nuclei", category="actif", wave=3),
        _spec("apres_nuclei", wave=3, depends_on=("nuclei",)),
        _spec("virustotal", category="api_key", api_key="virustotal_key", wave=2),
        _spec("intelx", category="sensible", api_key="intelx_key", wave=3),
    ):
        registre[spec.name] = spec
    monkeypatch.setattr(registry, "MODULES", registre)
    registry.validate_registry()
    return registre


# =============================================================================
# Aides
# =============================================================================


def _evenements(client, job_id) -> list[tuple[str, dict]]:
    """Événements SSE d'une tâche (lus jusqu'au dernier)."""
    with client.stream("GET", f"/api/scans/{job_id}/events") as response:
        assert response.status_code == 200
        texte = "".join(response.iter_text())
    evenements = []
    for bloc in texte.strip().split("\n\n"):
        ligne_evenement, ligne_donnees = bloc.split("\n")
        evenements.append(
            (ligne_evenement.removeprefix("event: "), json.loads(ligne_donnees.removeprefix("data: ")))
        )
    return evenements


def _attendre_libre(gestionnaire, delai=5.0) -> None:
    """Attend que la tâche terminée ait rendu sa place (le gestionnaire n'en a qu'une)."""
    fin = time.monotonic() + delai
    while gestionnaire.busy():
        assert time.monotonic() < fin, "la tâche n'a pas rendu sa place"
        time.sleep(0.01)


def _lancer(client, gestionnaire, domain="profil.example.com", **options):
    """POST /api/scans, puis lecture du flux jusqu'à la fin de la tâche.

    Renvoie (réponse, événements, état de la tâche) ; sans 202, ni événements ni état.
    """
    response = client.post("/api/scans", json={"domain": domain, **options})
    if response.status_code != 202:
        return response, [], None
    job_id = response.json()["id"]
    evenements = _evenements(client, job_id)
    _attendre_libre(gestionnaire)
    return response, evenements, client.get(f"/api/scans/{job_id}").json()


def _modules_annonces(evenements) -> list[str]:
    return [donnees["name"] for nom, donnees in evenements if nom == "module"]


def _progressions(evenements) -> list[dict]:
    return [donnees for nom, donnees in evenements if nom == "progress"]


def _scan(client, etat) -> dict:
    """Scan enregistré par la tâche terminée."""
    assert etat["status"] == "done", etat
    response = client.get(f"/api/scan/{etat['scan_id']}")
    assert response.status_code == 200, response.text
    return response.json()


def _rien_lance(gestionnaire, faux_scanner) -> None:
    """Requête refusée : le scanner n'a pas servi, aucune tâche n'existe et la place n'est pas gardée."""
    assert faux_scanner.appels == []
    assert gestionnaire._jobs == {}
    assert gestionnaire.slots.acquire(blocking=False)
    gestionnaire.slots.release()


# =============================================================================
# Profils : rapide, complet (défaut), personnalisé
# =============================================================================


def test_profil_par_defaut_complet(client, gestionnaire, faux_scanner):
    attendus = _complet()
    # Les 16 modules d'origine passifs ; ports et takeover (actifs) ne sont pas du profil complet.
    assert set(MODULE_NAMES) - {"open_ports", "subdomain_takeover"} <= set(attendus)
    assert {"open_ports", "subdomain_takeover"}.isdisjoint(attendus)

    response, evenements, etat = _lancer(client, gestionnaire)

    assert response.status_code == 202
    assert set(response.json()) == {"id", "status"}
    assert faux_scanner.appels == [
        {
            "domain": "profil.example.com",
            "profile": "complet",
            "authorized_target": False,
            "selected": [],
            "available_keys": [],
        }
    ]
    assert _modules_annonces(evenements) == attendus
    assert (etat["done"], etat["total"]) == (len(attendus), len(attendus))
    scan = _scan(client, etat)
    assert scan["profile"] == "complet"
    assert scan["modules_launched"] == attendus


def test_profil_rapide_lance_moins_de_modules_et_la_progression_suit(client, gestionnaire, faux_scanner):
    attendus = _noms(registry.get_modules("rapide"))
    assert 0 < len(attendus) < len(_complet())

    response, evenements, etat = _lancer(client, gestionnaire, profile="rapide")

    assert response.status_code == 202
    # Le total est celui du plan, pas celui du profil complet.
    assert etat["total"] == etat["done"] == len(attendus)
    assert _modules_annonces(evenements) == attendus
    assert _progressions(evenements) == [
        {"done": i, "total": len(attendus)} for i in range(1, len(attendus) + 1)
    ]
    assert evenements[-1][0] == "done"
    assert faux_scanner.appels[0]["profile"] == "rapide"
    scan = _scan(client, etat)
    assert scan["profile"] == "rapide"
    assert scan["modules_launched"] == attendus


def test_le_total_est_connu_des_la_creation_de_la_tache(client, gestionnaire):
    """GET /api/scans/{id} annonce le nombre de modules du plan avant le premier événement."""
    attendus = _noms(registry.get_modules("rapide"))

    job_id = client.post("/api/scans", json={"domain": "total.example.com", "profile": "rapide"}).json()["id"]

    assert client.get(f"/api/scans/{job_id}").json()["total"] == len(attendus)
    _evenements(client, job_id)
    _attendre_libre(gestionnaire)


def test_profil_personnalise_lance_la_selection_et_ses_dependances(client, gestionnaire, faux_scanner):
    selection = ["waf", "dns_records", "subdomain_takeover", "inexistant", "waf"]

    _, evenements, etat = _lancer(
        client, gestionnaire, profile="personnalise", selected=selection, authorized_target=True
    )

    # Ordre du registre ; le takeover entraîne l'énumération des sous-domaines ; le nom inconnu est ignoré.
    attendus = ["dns_records", "subdomains", "waf", "subdomain_takeover"]
    assert _modules_annonces(evenements) == attendus
    assert _progressions(evenements)[-1] == {"done": 4, "total": 4}
    assert faux_scanner.appels[0]["profile"] == "personnalise"
    assert faux_scanner.appels[0]["selected"] == ["waf", "dns_records", "subdomain_takeover"]
    scan = _scan(client, etat)
    assert scan["profile"] == "personnalise"
    assert scan["modules_launched"] == attendus


@pytest.mark.parametrize("profil", ["rapide", "complet"])
def test_la_selection_est_ignoree_hors_du_profil_personnalise(client, gestionnaire, faux_scanner, profil):
    attendus = _noms(registry.get_modules(profil))

    _, evenements, etat = _lancer(client, gestionnaire, profile=profil, selected=["subdomains", "inexistant"])

    assert _modules_annonces(evenements) == attendus
    assert faux_scanner.appels[0]["selected"] == []
    assert _scan(client, etat)["modules_launched"] == attendus


# =============================================================================
# Clés API : lues dans les réglages au lancement du scan
# =============================================================================


def test_les_cles_api_sont_lues_dans_les_reglages_au_lancement(
    client, gestionnaire, faux_scanner, modules_demo
):
    sans_cle, avec_cle = _complet(), _complet("virustotal_key")
    assert set(avec_cle) - set(sans_cle) == {"virustotal"}

    _, evenements, etat = _lancer(client, gestionnaire)
    assert _modules_annonces(evenements) == sans_cle
    assert etat["total"] == len(sans_cle)
    assert faux_scanner.appels[-1]["available_keys"] == []

    assert client.put("/api/settings", json={"virustotal_key": CLE_VT}).status_code == 200
    _, evenements, etat = _lancer(client, gestionnaire)

    # Le module à clé rejoint le profil « complet » : une clé de plus, un module de plus.
    assert _modules_annonces(evenements) == avec_cle
    assert etat["total"] == len(sans_cle) + 1
    assert faux_scanner.appels[-1]["available_keys"] == ["virustotal_key"]
    # Seul le nom de la clé voyage : ni la valeur, ni le scan enregistré ne la portent.
    scan = _scan(client, etat)
    assert scan["modules_launched"] == avec_cle
    assert CLE_VT not in json.dumps(faux_scanner.appels) + json.dumps(scan)


def test_module_a_cle_choisi_sans_sa_cle_est_un_plan_vide(client, gestionnaire, faux_scanner, modules_demo):
    corps = {"profile": "personnalise", "selected": ["virustotal"]}

    refus = client.post("/api/scans", json={"domain": "cle.example.com", **corps})
    assert refus.status_code == 400
    assert refus.json()["code"] == "api.no_modules"
    _rien_lance(gestionnaire, faux_scanner)

    assert client.put("/api/settings", json={"virustotal_key": CLE_VT}).status_code == 200
    _, evenements, etat = _lancer(client, gestionnaire, domain="cle.example.com", **corps)
    assert _modules_annonces(evenements) == ["virustotal"]
    assert etat["total"] == 1


# =============================================================================
# Autorisation de tester la cible : modules actifs et sensibles
# =============================================================================


@pytest.mark.parametrize("autorisation", [{}, {"authorized_target": False}], ids=["absente", "fausse"])
@pytest.mark.parametrize(
    ("selection", "concernes"),
    [
        (["nuclei"], ["nuclei"]),
        (["waf", "nuclei"], ["nuclei"]),  # rien ne part, même la partie passive
        (["apres_nuclei"], ["nuclei"]),  # un module passif qui dépend d'un module actif
        (["intelx"], ["intelx"]),  # sensible : exigée même sans sa clé
        (["virustotal", "nuclei", "intelx"], ["nuclei", "intelx"]),
    ],
    ids=["actif", "actif-et-passif", "dependance-active", "sensible", "plusieurs"],
)
def test_module_actif_ou_sensible_sans_autorisation_refuse(
    client, gestionnaire, faux_scanner, modules_demo, selection, concernes, autorisation
):
    response = client.post(
        "/api/scans?lang=en",
        json={
            "domain": "actif.example.com",
            "profile": "personnalise",
            "selected": selection,
            **autorisation,
        },
    )

    assert response.status_code == 400
    corps = response.json()
    assert corps["code"] == "api.authorization_required"
    assert corps["params"]["modules"] == concernes
    assert ", ".join(concernes) in corps["detail"]
    assert corps["detail"].startswith("Active or sensitive modules")
    assert "authorized_target" in corps["detail"]
    _rien_lance(gestionnaire, faux_scanner)


def test_message_d_autorisation_en_francais(client, modules_demo):
    response = client.post(
        "/api/scans?lang=fr",
        json={"domain": "actif.example.com", "profile": "personnalise", "selected": ["nuclei"]},
    )

    assert response.status_code == 400
    assert response.json()["detail"].startswith(
        "Les modules actifs ou sensibles (nuclei) exigent l'autorisation"
    )


def test_module_actif_avec_autorisation_est_lance(client, gestionnaire, faux_scanner, modules_demo):
    _, evenements, etat = _lancer(
        client,
        gestionnaire,
        profile="personnalise",
        selected=["apres_nuclei", "waf"],
        authorized_target=True,
    )

    # Vague 1, puis vague 3 : le module actif d'abord, son dépendant ensuite.
    attendus = ["waf", "nuclei", "apres_nuclei"]
    assert _modules_annonces(evenements) == attendus
    assert _progressions(evenements)[-1] == {"done": 3, "total": 3}
    assert faux_scanner.appels[0]["authorized_target"] is True
    assert _scan(client, etat)["modules_launched"] == attendus


def test_module_sensible_avec_autorisation_et_cle_est_lance(client, gestionnaire, modules_demo):
    assert client.put("/api/settings", json={"intelx_key": CLE_VT}).status_code == 200

    _, evenements, _ = _lancer(
        client, gestionnaire, profile="personnalise", selected=["intelx"], authorized_target=True
    )

    assert _modules_annonces(evenements) == ["intelx"]


def test_autorisation_sans_cle_pour_un_module_sensible_est_un_plan_vide(
    client, gestionnaire, faux_scanner, modules_demo
):
    response = client.post(
        "/api/scans",
        json={
            "domain": "sensible.example.com",
            "profile": "personnalise",
            "selected": ["intelx"],
            "authorized_target": True,
        },
    )

    assert response.status_code == 400
    assert response.json()["code"] == "api.no_modules"
    _rien_lance(gestionnaire, faux_scanner)


@pytest.mark.parametrize("profil", ["rapide", "complet"])
def test_l_autorisation_n_ouvre_pas_les_modules_actifs_hors_du_profil_personnalise(
    client, gestionnaire, modules_demo, profil
):
    attendus = _noms(registry.get_modules(profil))

    _, _, etat = _lancer(client, gestionnaire, profile=profil, authorized_target=True)

    lances = _scan(client, etat)["modules_launched"]
    assert lances == attendus
    assert {"nuclei", "apres_nuclei", "intelx"}.isdisjoint(lances)


# =============================================================================
# Plan vide
# =============================================================================


@pytest.mark.parametrize(
    "corps",
    [
        {"profile": "personnalise"},
        {"profile": "personnalise", "selected": []},
        {"profile": "personnalise", "selected": None},
        {"profile": "personnalise", "selected": ["inexistant", "autre"]},
    ],
    ids=["sans-selection", "selection-vide", "selection-nulle", "noms-inconnus"],
)
def test_plan_vide_refuse(client, gestionnaire, faux_scanner, corps):
    response = client.post("/api/scans?lang=en", json={"domain": "vide.example.com", **corps})

    assert response.status_code == 400
    assert response.json()["code"] == "api.no_modules"
    assert response.json()["detail"].startswith("No module to run")
    _rien_lance(gestionnaire, faux_scanner)
    francais = client.post("/api/scans?lang=fr", json={"domain": "vide.example.com", **corps})
    assert francais.json()["detail"].startswith("Aucun module à lancer")


def test_plan_vide_ne_garde_pas_la_place(client, gestionnaire):
    """Une seule place : si les refus la gardaient, la requête valide qui suit serait un 429."""
    for _ in range(3):
        refus = client.post("/api/scans", json={"domain": "vide.example.com", "profile": "personnalise"})
        assert refus.status_code == 400

    response, _, etat = _lancer(client, gestionnaire, profile="personnalise", selected=["waf"])

    assert response.status_code == 202
    assert etat["total"] == 1


def test_cible_invalide_prime_sur_le_plan(client):
    """La cible est jugée avant le plan : un plan vide sur une cible invalide est d'abord une cible invalide."""
    response = client.post("/api/scans", json={"domain": "pas une cible", "profile": "personnalise"})

    assert response.status_code == 400
    assert response.json()["code"] == "target.invalid"


def test_lecture_des_cles_en_echec_rend_la_place(monkeypatch, cible_publique):
    def panne():
        raise RuntimeError("base illisible")

    monkeypatch.setattr(jobs_routes, "load_secrets", panne)

    async def scenario():
        jobs = JobManager(1, runner=FauxScanner())
        with pytest.raises(RuntimeError, match="base illisible"):
            await jobs_routes.start_scan(schemas.ScanJobRequest(domain="panne.example.com"), jobs)
        assert jobs.slots.acquire(blocking=False)

    asyncio.run(scenario())


# =============================================================================
# Corps de la requête : validation
# =============================================================================


@pytest.mark.parametrize(
    ("corps", "champ"),
    [
        ({"profile": "agressif"}, "profile"),
        ({"profile": "RAPIDE"}, "profile"),
        ({"profile": None}, "profile"),
        ({"authorized_target": "true"}, "authorized_target"),
        ({"authorized_target": 1}, "authorized_target"),
        ({"authorized_target": None}, "authorized_target"),
        ({"profile": "personnalise", "selected": "waf"}, "selected"),
        ({"profile": "personnalise", "selected": [1, 2]}, "selected"),
        ({"profile": "personnalise", "selected": ["a" * 65]}, "selected"),
        ({"profile": "personnalise", "selected": ["waf"] * 101}, "selected"),
    ],
    ids=repr,
)
def test_corps_invalide_refuse_en_422(client, gestionnaire, faux_scanner, corps, champ):
    response = client.post("/api/scans?lang=en", json={"domain": "valide.example.com", **corps})

    assert response.status_code == 422
    assert response.json()["code"] == "api.validation_error"
    # Le champ en cause (avec l'indice de l'élément pour une liste : « selected.0 »).
    assert response.json()["params"]["fields"].startswith(champ)
    _rien_lance(gestionnaire, faux_scanner)


def test_les_profils_du_schema_sont_ceux_du_registre():
    assert typing.get_args(schemas.ScanProfile) == registry.PROFILES


def test_openapi_decrit_le_profil_et_l_autorisation():
    composants = app.openapi()["components"]["schemas"]

    corps = composants["ScanJobRequest"]
    assert set(corps["properties"]) == {"domain", "profile", "selected", "authorized_target"}
    assert corps["required"] == ["domain"]
    assert corps["properties"]["profile"]["default"] == "complet"
    assert corps["properties"]["profile"]["enum"] == list(registry.PROFILES)
    assert corps["properties"]["authorized_target"]["default"] is False
    # POST /api/scan (synchrone) garde son corps : la cible seule.
    assert set(composants["ScanRequest"]["properties"]) == {"domain"}
    reponse = composants["ScanResponse"]
    assert {"profile", "modules_launched"} <= set(reponse["properties"])
    assert {"profile", "modules_launched"}.isdisjoint(reponse.get("required", []))


# =============================================================================
# plan_scan et gestionnaire de tâches
# =============================================================================


def test_plan_par_defaut():
    plan = plan_scan()

    assert plan == ScanPlan("complet", (), False, frozenset(), tuple(_complet()))
    assert set(MODULE_NAMES) - {"open_ports", "subdomain_takeover"} <= set(plan.modules)
    assert {"open_ports", "subdomain_takeover"}.isdisjoint(plan.modules)


def test_le_plan_ne_garde_que_les_noms_des_cles():
    plan = plan_scan("complet", available_keys={"virustotal_key": "secret-valeur"})

    assert plan.available_keys == frozenset({"virustotal_key"})
    assert "secret-valeur" not in repr(plan)


def test_plan_personnalise_ignore_noms_inconnus_et_doublons():
    plan = plan_scan("personnalise", ["waf", "inconnu", "dns_records", "waf"])

    assert plan.selected == ("waf", "dns_records")
    assert plan.modules == ("dns_records", "waf")
    assert plan.profile == "personnalise" and plan.authorized_target is False


def test_plan_refuse_porte_un_message_traduisible(modules_demo):
    with pytest.raises(ValueError) as vide:
        plan_scan("personnalise", [])
    assert message_of(vide.value) == msg("api.no_modules")

    with pytest.raises(ValueError) as sans_autorisation:
        plan_scan("personnalise", ["intelx", "nuclei"], authorized_target=False)
    assert message_of(sans_autorisation.value) == msg(
        "api.authorization_required", modules=["nuclei", "intelx"], sep=", "
    )

    assert plan_scan("personnalise", ["nuclei"], authorized_target=True).modules == ("nuclei",)


def test_profil_inconnu_refuse():
    with pytest.raises(ValueError, match="Profil inconnu"):
        plan_scan("agressif")


async def _bloque(domain, on_module, **plan):
    await asyncio.Event().wait()


def test_le_total_de_la_tache_est_le_nombre_de_modules_du_plan():
    async def scenario():
        manager = JobManager(1, runner=_bloque, saver=lambda result: 1)
        plan = plan_scan("rapide")
        job = manager.start("example.com", plan=plan)
        assert job.plan is plan
        assert job.total == len(plan.modules) < len(_complet())
        manager.cancel(job.id)
        await manager.wait(job.id, timeout=5)

    asyncio.run(scenario())


def test_le_gestionnaire_transmet_le_plan_au_scanner_et_a_l_enregistrement():
    recus, enregistres = [], []

    async def scanner(domain, on_module, **plan):
        recus.append(plan)
        return {"domain": domain}

    def enregistrer(result):
        enregistres.append(result)
        return 7

    async def scenario():
        manager = JobManager(1, runner=scanner, saver=enregistrer)
        job = manager.start("example.com", plan=plan_scan("personnalise", ["waf"], False, ["shodan_key"]))
        await manager.wait(job.id, timeout=5)
        return job

    job = asyncio.run(scenario())

    assert (job.status, job.scan_id, job.total) == ("done", 7, 1)
    assert recus == [
        {
            "profile": "personnalise",
            "authorized_target": False,
            "selected": ("waf",),
            "available_keys": frozenset({"shodan_key"}),
        }
    ]
    assert enregistres == [{"profile": "personnalise", "modules_launched": ["waf"], "domain": "example.com"}]


def test_le_profil_du_resultat_prime_sur_celui_du_plan():
    enregistres = []

    async def scanner(domain, on_module, **plan):
        return {"domain": domain, "profile": "rapide", "modules_launched": ["dns_records"]}

    def enregistrer(result):
        enregistres.append(result)
        return 1

    async def scenario():
        manager = JobManager(1, runner=scanner, saver=enregistrer)
        job = manager.start("example.com", plan=plan_scan("complet"))
        await manager.wait(job.id, timeout=5)

    asyncio.run(scenario())

    assert enregistres[0]["profile"] == "rapide"
    assert enregistres[0]["modules_launched"] == ["dns_records"]


# =============================================================================
# Le vrai orchestrateur, de bout en bout (modules remplacés par des faux sans réseau)
# =============================================================================


def _module_factice(name):
    async def run(context):
        return [] if name in MODULES_LISTE else {"measured": True, "error": None}

    return run


@pytest.fixture
def vrai_scanner(monkeypatch, modules_demo, cible_publique):
    """perform_full_scan réel et enregistrement réel, sur un registre dont les modules ne touchent pas au réseau."""
    registre = {
        name: dataclasses.replace(spec, run=_module_factice(name)) for name, spec in registry.MODULES.items()
    }
    monkeypatch.setattr(registry, "MODULES", registre)

    async def resoudre(host):
        return ["93.184.216.34"]

    monkeypatch.setattr(orchestrator, "ensure_target_allowed", resoudre)
    monkeypatch.setattr(orchestrator, "compute_security_score", lambda data: dict(NOTE))
    jobs = JobManager(1)
    app.dependency_overrides[jobs_routes.get_job_manager] = lambda: jobs
    yield jobs
    app.dependency_overrides.pop(jobs_routes.get_job_manager, None)


def test_profil_rapide_de_bout_en_bout(client, vrai_scanner):
    attendus = _noms(registry.get_modules("rapide"))

    response, evenements, etat = _lancer(client, vrai_scanner, profile="rapide")

    assert response.status_code == 202
    assert len(attendus) < len(_complet())
    # Les modules d'une vague tournent en parallèle : l'ordre d'arrivée des issues n'est pas garanti.
    assert sorted(_modules_annonces(evenements)) == sorted(attendus)
    assert _progressions(evenements) == [
        {"done": i, "total": len(attendus)} for i in range(1, len(attendus) + 1)
    ]
    assert evenements[-1][0] == "done"
    assert (etat["done"], etat["total"]) == (len(attendus), len(attendus))
    scan = _scan(client, etat)
    assert scan["profile"] == "rapide"
    assert scan["modules_launched"] == attendus
    # Ce que l'orchestrateur a réellement lancé est ce que le plan annonçait.
    assert list(scan["module_status"]) == attendus


def test_module_actif_autorise_de_bout_en_bout(client, vrai_scanner):
    _, evenements, etat = _lancer(
        client, vrai_scanner, profile="personnalise", selected=["waf", "nuclei"], authorized_target=True
    )

    assert sorted(_modules_annonces(evenements)) == ["nuclei", "waf"]
    assert (etat["done"], etat["total"]) == (2, 2)
    scan = _scan(client, etat)
    assert scan["modules_launched"] == ["waf", "nuclei"]
    assert list(scan["module_status"]) == ["waf", "nuclei"]
    # Hors des 18 modules d'origine : le résultat est dans `modules`.
    assert scan["modules"]["nuclei"]["status"] == "ok"


def test_module_actif_sans_autorisation_ne_part_jamais_de_bout_en_bout(client, vrai_scanner):
    response = client.post(
        "/api/scans",
        json={"domain": "actif.example.com", "profile": "personnalise", "selected": ["waf", "nuclei"]},
    )

    assert response.status_code == 400
    assert response.json()["code"] == "api.authorization_required"
    assert vrai_scanner._jobs == {}


# =============================================================================
# Enregistrement et lecture : profile et modules_launched
# =============================================================================


def _colonnes_nulles(scan_id: int) -> tuple[bool, bool]:
    """(profile, modules_launched) valent-ils NULL en SQL ?"""
    with SessionLocal() as db:
        profil, modules = (
            db.query(Scan.profile.is_(None), Scan.modules_launched.is_(None)).filter(Scan.id == scan_id).one()
        )
    return bool(profil), bool(modules)


def test_save_scan_enregistre_le_profil_et_les_modules_lances():
    scan_id = storage.save_scan(
        {
            "domain": "profil.storage.example",
            "status": "success",
            "profile": "rapide",
            "modules_launched": ("dns_records", "waf"),
        }
    )

    with SessionLocal() as db:
        scan = db.get(Scan, scan_id)
        assert (scan.profile, scan.modules_launched) == ("rapide", ["dns_records", "waf"])


def test_save_scan_sans_profil_laisse_les_colonnes_vides():
    """Résultat sans ces clés (POST /api/scan, anciens appelants) : NULL, comme un scan d'avant la v2."""
    scan_id = storage.save_scan({"domain": "sans.profil.example", "status": "success"})

    assert _colonnes_nulles(scan_id) == (True, True)


def test_save_scan_none_est_enregistre_en_null(caplog):
    with caplog.at_level(logging.WARNING, logger="domainrecon.api.storage"):
        scan_id = storage.save_scan(
            {"domain": "none.profil.example", "status": "success", "profile": None, "modules_launched": None}
        )

    assert _colonnes_nulles(scan_id) == (True, True)  # NULL SQL, pas le JSON « null »
    assert "ignoré" not in caplog.text


@pytest.mark.parametrize(
    ("profil", "modules"),
    [(5, "waf"), ({"a": 1}, ["waf", 3]), (["rapide"], {"waf": 1}), (3.5, 42)],
    ids=repr,
)
def test_save_scan_ecarte_un_profil_ou_des_modules_inattendus(caplog, profil, modules):
    """Le scan est enregistré quand même : une collecte entière ne se perd pas pour un champ annexe."""
    with caplog.at_level(logging.WARNING, logger="domainrecon.api.storage"):
        scan_id = storage.save_scan(
            {
                "domain": "invalide.profil.example",
                "status": "success",
                "profile": profil,
                "modules_launched": modules,
            }
        )

    assert _colonnes_nulles(scan_id) == (True, True)
    assert "invalide.profil.example" in caplog.text
    assert "Profil du scan" in caplog.text and "Modules lancés du scan" in caplog.text


def test_l_api_expose_le_profil_et_les_modules_lances(client):
    scan_id = storage.save_scan(
        {
            "domain": "api.profil.example",
            "status": "success",
            "profile": "personnalise",
            "modules_launched": ["dns_records", "waf"],
        }
    )

    corps = client.get(f"/api/scan/{scan_id}").json()

    assert corps["profile"] == "personnalise"
    assert corps["modules_launched"] == ["dns_records", "waf"]
    # Les listes ne transportent ni l'un ni l'autre.
    (entree,) = client.get("/api/history?domain=api.profil.example").json()["scans"]
    assert "profile" not in entree and "modules_launched" not in entree


def test_ancien_scan_sans_profil_ni_modules_lances(client):
    """Scan d'avant la v2 : les deux champs valent null (liste des modules lancés inconnue)."""
    with SessionLocal() as db:
        scan = Scan(domain="ancien.profil.example", status="success")
        db.add(scan)
        db.commit()
        scan_id = scan.id

    corps = client.get(f"/api/scan/{scan_id}").json()

    assert "profile" in corps and corps["profile"] is None
    assert "modules_launched" in corps and corps["modules_launched"] is None


@pytest.mark.parametrize(
    ("stocke", "lu"),
    [({"waf": 1}, None), ("waf", None), (["waf", 3, None, "cors"], ["waf", "cors"]), ([], [])],
    ids=repr,
)
def test_modules_lances_inattendus_en_base_sont_lus_prudemment(client, stocke, lu):
    """Valeur modifiée à la main en base : le scan reste lisible."""
    with SessionLocal() as db:
        scan = Scan(domain="inattendu.profil.example", status="success", modules_launched=stocke)
        db.add(scan)
        db.commit()
        scan_id = scan.id

    response = client.get(f"/api/scan/{scan_id}")

    assert response.status_code == 200
    assert response.json()["modules_launched"] == lu
