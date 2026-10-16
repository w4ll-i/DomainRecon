# =============================================================================
# DomainRecon - Tests du catalogue des modules (GET /api/modules) et des clés
# API déclarées par les modules (Réglages, test de clé fourni par un module)
# =============================================================================
# Un module de démonstration est ajouté au registre réel le temps du test ;
# aucun accès réseau (le test de clé sur mesure ne fait aucune requête).
# =============================================================================

import json
import logging
import shutil

import pytest
from fastapi.testclient import TestClient

from domainrecon.api.app import app
from domainrecon.core import paths
from domainrecon.core.database import Base, SessionLocal, engine
from domainrecon.core.models import Settings
from domainrecon.core.settings_store import load_secrets, read_secret
from domainrecon.i18n import catalog, msg
from domainrecon.i18n.fix import FIX_PARTS, fix_texts, is_https_url
from domainrecon.scanner import registry
from domainrecon.scanner.keys import ApiKey, CheckOutcome, KeyTest
from domainrecon.scanner.registry import ModuleSpec

SECRET = "hibp-0123456789abcdefghij"


@pytest.fixture
def client():
    with TestClient(app) as c:
        yield c


@pytest.fixture(autouse=True)
def reglages_vierges():
    Base.metadata.create_all(bind=engine)
    with SessionLocal() as db:
        db.query(Settings).delete()
        db.commit()
    yield
    with SessionLocal() as db:
        db.query(Settings).delete()
        db.commit()


async def _run(context):
    return {"measured": True, "error": None}


async def _test_hibp(secrets, client):
    if secrets["hibp_key"] == SECRET:
        return CheckOutcome(True, msg("api.settings_test_ok", service="Have I Been Pwned"))
    raise RuntimeError(f"clé refusée : {secrets['hibp_key']}")


@pytest.fixture
def module_a_cles(monkeypatch):
    """Module de fuites à deux identifiants (dont un mot de passe) et son test de clé, ajouté au registre."""
    spec = ModuleSpec(
        name="demo_fuites",
        family="leaks",
        category="cle_api",
        run=_run,
        wave=2,
        keys=(
            ApiKey(name="hibp_key", service="hibp", label="Have I Been Pwned"),
            ApiKey(
                name="hibp_motdepasse", service="hibp", label="Have I Been Pwned", hidden=True, free_text=True
            ),
            ApiKey(
                name="hibp_compte", service="hibp", label="Have I Been Pwned", required=False, free_text=True
            ),
        ),
        key_tests={"hibp": KeyTest("Have I Been Pwned", ("hibp_key",), run=_test_hibp)},
    )
    monkeypatch.setitem(registry.MODULES, spec.name, spec)
    return spec


def test_catalogue_des_modules(client):
    response = client.get("/api/modules")

    assert response.status_code == 200
    body = response.json()
    names = [module["name"] for module in body["modules"]]
    assert names == list(registry.MODULES)
    assert body["families"] == list(registry.FAMILIES) and "leaks" in body["families"]
    assert body["categories"] == ["passif", "actif", "cle_api", "sensible"]
    assert body["unavailable"] == []
    email = next(module for module in body["modules"] if module["name"] == "email_security")
    assert email["family"] == "email" and email["category"] == "passif" and email["quick"] is True
    assert email["criteria"] == [{"criterion": "email", "weight": 15}]
    assert email["help"]["title"] == "Sécurité e-mail"
    assert email["help"]["checks"] and email["help"]["why"]
    for module in body["modules"]:
        assert all(module["help"][part] for part in ("title", "checks", "why")), module["name"]


def test_catalogue_en_anglais(client):
    body = client.get("/api/modules?lang=en").json()
    email = next(module for module in body["modules"] if module["name"] == "email_security")
    assert email["help"]["title"] == "Email security"


def test_module_a_cles_dans_le_catalogue(client, module_a_cles):
    body = client.get("/api/modules").json()
    demo = next(module for module in body["modules"] if module["name"] == "demo_fuites")

    assert demo["category"] == "cle_api" and demo["requires_authorization"] is False
    assert [(key["name"], key["required"], key["configured"]) for key in demo["keys"]] == [
        ("hibp_key", True, False),
        ("hibp_motdepasse", True, False),
        ("hibp_compte", False, False),
    ]
    assert demo["key_tests"] == ["hibp"]


def test_cles_declarees_enregistrees_chiffrees_et_masquees(client, module_a_cles):
    response = client.put(
        "/api/settings",
        json={
            "api_keys": {"hibp_key": SECRET, "hibp_motdepasse": "mot de passe long", "hibp_compte": "alice"}
        },
    )

    assert response.status_code == 200
    keys = response.json()["api_keys"]
    assert keys["hibp_key"] == "hib…ghij"
    assert keys["hibp_motdepasse"] == "****"  # caché : jamais un fragment
    assert keys["shodan_key"] == ""  # les 14 clés historiques y figurent aussi
    with SessionLocal() as db:
        row = db.get(Settings, 1)
        assert SECRET not in str(row.extra_secrets)
        assert read_secret(row, "hibp_key") == SECRET
    assert load_secrets()["hibp_motdepasse"] == "mot de passe long"
    body = client.get("/api/modules").json()
    demo = next(module for module in body["modules"] if module["name"] == "demo_fuites")
    assert all(key["configured"] for key in demo["keys"])


def test_cle_declaree_supprimee_ou_inchangee(client, module_a_cles):
    client.put("/api/settings", json={"api_keys": {"hibp_key": SECRET}})
    # Valeur masquée renvoyée : inchangée ; null : inchangée ; « » : supprimée.
    client.put("/api/settings", json={"api_keys": {"hibp_key": "hib…ghij", "hibp_compte": None}})
    assert load_secrets()["hibp_key"] == SECRET
    client.put("/api/settings", json={"api_keys": {"hibp_key": ""}})
    assert "hibp_key" not in load_secrets()


def test_cle_historique_par_api_keys(client):
    client.put("/api/settings", json={"api_keys": {"shodan_key": "abcdefghijklmnop1234"}})
    assert client.get("/api/settings").json()["shodan_key"] == "abc…1234"


@pytest.mark.parametrize(
    "keys",
    [
        {"inconnue_key": "x"},
        {"hibp_key": "avec espace"},
        {"hibp_compte": "texte libre mais pas d'espace"},
        {"hibp_key": "x" * 513},
    ],
)
def test_cle_refusee(client, module_a_cles, keys):
    response = client.put("/api/settings", json={"api_keys": keys})
    assert response.status_code == 422
    assert "x" * 20 not in response.text


def test_test_de_cle_fourni_par_le_module(client, module_a_cles):
    client.put("/api/settings", json={"api_keys": {"hibp_key": SECRET}})

    response = client.post("/api/settings/test/hibp", json={})

    assert response.status_code == 200
    assert response.json()["success"] is True


def test_test_de_cle_sur_mesure_sans_fuite_de_la_cle(client, module_a_cles):
    autre = "autre-cle-0123456789abcdef"
    client.put("/api/settings", json={"api_keys": {"hibp_key": autre}})

    body = client.post("/api/settings/test/hibp", json={}).json()

    assert body["success"] is False
    assert autre not in body["message"]


def test_test_de_cle_sans_cle(client, module_a_cles):
    body = client.post("/api/settings/test/hibp", json={}).json()
    assert body["success"] is False


# =============================================================================
# « Comment corriger » : fix, fix_snippet, fix_ref (i18n/fix.py)
# =============================================================================

CONSEIL_FR = {
    "fix": "Ajoutez l'en-tête `X-Frame-Options: DENY` à toutes les réponses.\nRechargez le serveur.",
    "fix_snippet": (
        '# nginx\nlocation / {\n  add_header X-Frame-Options "DENY" always;\n}\n\n'
        '# Apache\nHeader always set X-Frame-Options "DENY"'
    ),
    "fix_ref": "https://developer.mozilla.org/fr/docs/Web/HTTP/Headers/X-Frame-Options",
}
CONSEIL_EN = {
    "fix": "Add the `X-Frame-Options: DENY` header to every response.\nReload the server.",
    "fix_snippet": CONSEIL_FR["fix_snippet"],
    "fix_ref": "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options",
}


@pytest.fixture
def module_demo(monkeypatch):
    """Module de démonstration sans clé ni texte de correction, ajouté au registre le temps du test."""
    spec = ModuleSpec(name="demo_conseil", family="web", category="passif", run=_run)
    monkeypatch.setitem(registry.MODULES, spec.name, spec)
    return spec


@pytest.fixture
def ecrire_fragment(tmp_path, monkeypatch):
    """Catalogues réels copiés dans un dossier temporaire ; renvoie ecrire(module, langue, textes).

    `ecrire` complète le fragment i18n/modules/<module>.<langue>.json (créé au besoin) avec les
    parties du « Comment corriger » données : les vrais fragments ne sont jamais touchés.
    """
    dossier = tmp_path / "i18n"
    shutil.copytree(paths.i18n_dir(), dossier, ignore=shutil.ignore_patterns("__pycache__", "*.py"))
    monkeypatch.setattr(paths, "i18n_dir", lambda: dossier)
    catalog.cache_clear()

    def ecrire(module: str, lang: str, textes: dict[str, str]) -> None:
        fichier = dossier / "modules" / f"{module}.{lang}.json"
        donnees = json.loads(fichier.read_text(encoding="utf-8")) if fichier.exists() else {}
        donnees.update({f"module.{module}.{part}": texte for part, texte in textes.items()})
        fichier.write_text(json.dumps(donnees, ensure_ascii=False), encoding="utf-8")
        catalog.cache_clear()

    yield ecrire
    catalog.cache_clear()


def _entree(client, nom, lang="fr"):
    modules = client.get(f"/api/modules?lang={lang}").json()["modules"]
    return next(module for module in modules if module["name"] == nom)


def _conseil(entree):
    return {part: entree[part] for part in FIX_PARTS if part in entree}


def test_conseil_absent_quand_le_module_n_en_a_pas(client, module_demo):
    entree = _entree(client, "demo_conseil")

    assert not set(FIX_PARTS) & set(entree)  # absents, pas null
    # Les champs existants ne bougent pas, null compris.
    assert entree["timeout"] is None and entree["criteria"] == [] and "help" in entree


def test_conseil_dans_la_langue_demandee(client, module_demo, ecrire_fragment):
    ecrire_fragment("demo_conseil", "fr", CONSEIL_FR)
    ecrire_fragment("demo_conseil", "en", CONSEIL_EN)

    assert _conseil(_entree(client, "demo_conseil")) == CONSEIL_FR
    assert _conseil(_entree(client, "demo_conseil", "en")) == CONSEIL_EN
    # La langue se négocie comme pour l'aide : ?lang= puis Accept-Language, sinon le français.
    modules = client.get("/api/modules", headers={"Accept-Language": "en-US,en;q=0.9"}).json()["modules"]
    assert _conseil(next(m for m in modules if m["name"] == "demo_conseil")) == CONSEIL_EN
    assert _conseil(_entree(client, "demo_conseil", "de")) == CONSEIL_FR


def test_extrait_avec_accolades_et_deux_points_inchange(client, module_demo, ecrire_fragment):
    """Un extrait nginx ou JSON n'est pas un gabarit : accolades et « : » arrivent tels quels."""
    extrait = '# nginx\nserver {\n  add_header A "b: c" always;\n}\n\n# JSON\n{"Version": "2012-10-17"}\n\n# Helm\n{{ .Values.x }}'
    ecrire_fragment("demo_conseil", "fr", {"fix": "Faire ceci avec `{ }`", "fix_snippet": extrait})

    entree = _entree(client, "demo_conseil")

    assert entree["fix_snippet"] == extrait
    assert entree["fix"] == "Faire ceci avec `{ }`"


def test_conseil_partiel(client, module_demo, ecrire_fragment):
    ecrire_fragment("demo_conseil", "fr", {"fix": CONSEIL_FR["fix"]})
    ecrire_fragment("demo_conseil", "en", {"fix": CONSEIL_EN["fix"], "fix_ref": CONSEIL_EN["fix_ref"]})

    assert _conseil(_entree(client, "demo_conseil")) == {"fix": CONSEIL_FR["fix"]}
    assert _conseil(_entree(client, "demo_conseil", "en")) == {
        "fix": CONSEIL_EN["fix"],
        "fix_ref": CONSEIL_EN["fix_ref"],
    }


def test_conseil_repli_sur_le_francais_par_partie(client, module_demo, ecrire_fragment):
    ecrire_fragment("demo_conseil", "fr", CONSEIL_FR)
    ecrire_fragment("demo_conseil", "en", {"fix": CONSEIL_EN["fix"]})

    assert _conseil(_entree(client, "demo_conseil", "en")) == {**CONSEIL_FR, "fix": CONSEIL_EN["fix"]}


def test_documentation_hors_https_ecartee(client, module_demo, ecrire_fragment, caplog):
    ecrire_fragment("demo_conseil", "fr", {**CONSEIL_FR, "fix_ref": "javascript:alert(1)"})

    with caplog.at_level(logging.WARNING, logger="domainrecon.api.routes.modules"):
        entree = _entree(client, "demo_conseil")

    assert _conseil(entree) == {"fix": CONSEIL_FR["fix"], "fix_snippet": CONSEIL_FR["fix_snippet"]}
    assert any(
        "demo_conseil" in record.getMessage() and "fix_ref" in record.getMessage()
        for record in caplog.records
    )


def test_module_historique_conseil_dans_son_fragment(client, ecrire_fragment):
    """Les 18 modules historiques ont leur aide dans des fragments : les clés s'y ajoutent comme pour les autres."""
    assert registry.MODULES["security_headers"].column is not None
    aide = _entree(client, "security_headers")["help"]
    ecrire_fragment("security_headers", "fr", CONSEIL_FR)
    ecrire_fragment("security_headers", "en", CONSEIL_EN)

    entree = _entree(client, "security_headers")
    assert _conseil(entree) == CONSEIL_FR and entree["help"] == aide
    assert _conseil(_entree(client, "security_headers", "en")) == CONSEIL_EN


@pytest.mark.parametrize("lang", ["fr", "en"])
def test_catalogue_reel_expose_les_conseils_ecrits(client, lang):
    """Chaque module expose exactement les parties renseignées dans son fragment (aucune, tant que rien n'est écrit)."""
    for module in client.get(f"/api/modules?lang={lang}").json()["modules"]:
        attendu = fix_texts(module["name"], lang)
        if "fix_ref" in attendu and not is_https_url(attendu["fix_ref"]):
            del attendu["fix_ref"]
        assert _conseil(module) == attendu, module["name"]


def test_openapi_declare_le_conseil_facultatif():
    schema = app.openapi()["components"]["schemas"]["ModuleInfo"]

    assert set(FIX_PARTS) <= set(schema["properties"])
    assert not set(FIX_PARTS) & set(schema["required"])
    assert "help" in schema["required"]
