# =============================================================================
# DomainRecon - Tests du package (version, pyproject, fichiers du projet)
# =============================================================================

import os
import re
import subprocess
import sys
from pathlib import Path

import domainrecon

ROOT = Path(__file__).resolve().parents[2]
PYPROJECT = (ROOT / "pyproject.toml").read_text(encoding="utf-8")


def _section(name: str) -> str:
    """Contenu d'une section [name] de pyproject.toml, jusqu'à la section suivante.

    Lecture par expression régulière : tomllib n'existe qu'à partir de Python 3.11.
    """
    match = re.search(rf"^\[{re.escape(name)}\]\n(.*?)(?=^\[|\Z)", PYPROJECT, re.M | re.S)
    assert match, f"section [{name}] absente"
    return match.group(1)


def test_version_unique():
    assert domainrecon.__version__ == "1.0.0"
    version = re.search(r'^version = "([^"]+)"', _section("project"), re.M)
    assert version and version.group(1) == domainrecon.__version__


def test_metadonnees_du_projet():
    project = _section("project")
    assert re.search(r'^name = "domainrecon"', project, re.M)
    assert 'requires-python = ">=3.10"' in project
    assert '"pywebview>=6.2,<7"' in project
    assert 'domainrecon = "domainrecon.__main__:main"' in _section("project.scripts")
    extras = _section("project.optional-dependencies")
    assert '"pyinstaller>=6.22,<7"' in extras
    assert '"ruff>=0.16.0,<0.17"' in extras
    package_data = _section("tool.setuptools.package-data")
    assert '"i18n/*.json"' in package_data
    assert '"web/**/*"' in package_data


def test_dependances_reprises_de_requirements():
    project = _section("project")
    for dependance in (
        "fastapi>=0.133.0,<1.0",
        "starlette>=1.7.0,<2.0",
        "uvicorn[standard]>=0.32.0,<1.0",
        "sqlalchemy>=2.0.36,<3.0",
        "pydantic>=2.10.0,<3.0",
        "python-dotenv>=1.2.3,<2.0",
        "httpx>=0.28.0,<1.0",
        "idna>=3.18,<4.0",
        "tldextract>=5.1.1,<6.0",
        "python-whois>=0.9.6,<1.0",
        "dnspython>=2.7.0,<3.0",
        "playwright>=1.53.0,<2.0",
    ):
        assert f'"{dependance}"' in project, dependance


def test_fichiers_supprimes():
    for nom in (
        "requirements.txt",
        "requirements-dev.txt",
        "Dockerfile",
        "docker-compose.yml",
        "entrypoint.sh",
        ".dockerignore",
    ):
        assert not (ROOT / nom).exists(), nom


def test_ci_sans_docker_et_installation_par_pyproject():
    ci = (ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
    assert 'pip install -e ".[dev]"' in ci
    for absent in ("docker", "hadolint", "shellcheck", "requirements"):
        assert absent not in ci.lower(), absent


def test_ancien_code_supprime():
    assert not (ROOT / "backend").exists()


def test_cible_uvicorn_et_configuration():
    from domainrecon.api.app import app
    from domainrecon.core import config, paths

    assert app.version == domainrecon.__version__
    assert config.APP_VERSION == domainrecon.__version__
    assert config.ROOT_DIR == paths.app_dir()
    assert config.DATA_DIR == paths.data_dir()
    assert config.SCREENSHOTS_DIR == config.DATA_DIR / "screenshots"


def test_fichiers_env_charges_dans_l_ordre(monkeypatch, tmp_path):
    """Le premier fichier qui définit une variable l'emporte ; l'environnement prime sur tous."""
    from domainrecon.core import config, paths

    donnees, depot = tmp_path / "donnees.env", tmp_path / "depot.env"
    donnees.write_text("DOMAINRECON_TEST_ORDRE=donnees\n", encoding="utf-8")
    depot.write_text("DOMAINRECON_TEST_ORDRE=depot\nDOMAINRECON_TEST_SECOND=oui\n", encoding="utf-8")
    for name in ("DOMAINRECON_TEST_ORDRE", "DOMAINRECON_TEST_SECOND"):
        # setenv puis delenv : la variable posée par le chargement est retirée en fin de test.
        monkeypatch.setenv(name, "")
        monkeypatch.delenv(name)
    monkeypatch.setattr(paths, "env_files", lambda: [donnees, tmp_path / "absent.env", depot])

    assert config.load_env_files() == [donnees, depot]
    assert os.environ["DOMAINRECON_TEST_ORDRE"] == "donnees"
    assert os.environ["DOMAINRECON_TEST_SECOND"] == "oui"


def test_database_url_prioritaire_sur_la_base_par_defaut(tmp_path):
    """DATABASE_URL l'emporte sur la base SQLite du dossier de données ; vide, elle est ignorée."""
    donnees = tmp_path / "donnees"
    script = "from domainrecon.core import config; print(config.DATABASE_URL)"

    def database_url(valeur: str) -> str:
        # Processus neuf : config lit DATABASE_URL une seule fois, à l'import. Une valeur
        # vide (et non retirée) empêche aussi le .env du développeur de la définir.
        env = {**os.environ, "DATA_DIR": str(donnees), "DATABASE_URL": valeur, "PYTHONIOENCODING": "utf-8"}
        resultat = subprocess.run(
            [sys.executable, "-c", script],
            cwd=ROOT,
            env=env,
            capture_output=True,
            encoding="utf-8",
            timeout=60,
        )
        assert resultat.returncode == 0, resultat.stderr
        return resultat.stdout.strip()

    postgres = "postgresql+psycopg://recon:secret@db/recon"
    assert database_url(postgres) == postgres
    assert database_url("") == f"sqlite:///{donnees / 'domainrecon.db'}"


def test_api_decoupee_en_modules():
    import importlib

    for name in (
        "domainrecon.api.schemas",
        "domainrecon.api.storage",
        "domainrecon.api.jobs",
        "domainrecon.api.security",
        "domainrecon.api.spa",
        "domainrecon.api.routes.system",
        "domainrecon.api.routes.scans",
        "domainrecon.api.routes.history",
        "domainrecon.api.routes.jobs",
    ):
        importlib.import_module(name)


def test_routes_conservees():
    """Mêmes routes qu'avant le découpage (lues dans le schéma OpenAPI : FastAPI >= 0.140
    n'aplatit plus les routeurs inclus dans app.routes)."""
    from fastapi.testclient import TestClient

    from domainrecon.api.app import app

    chemins = app.openapi()["paths"]
    routes = {(chemin, methode.upper()) for chemin, operations in chemins.items() for methode in operations}
    assert {
        ("/api/health", "GET"),
        ("/api/scan", "POST"),
        ("/api/history", "GET"),
        ("/api/scan/{scan_id}", "GET"),
        ("/api/scan/{scan_id}", "DELETE"),
        ("/api/scan/{scan_id}/meta", "PATCH"),
        ("/api/screenshot/{filename}", "GET"),
        ("/api/dns-timeline/{domain}", "GET"),
    } <= routes
    # « / » (hors schéma) répond en GET comme en HEAD.
    with TestClient(app) as client:
        assert client.get("/").status_code == 200
        assert client.head("/").status_code == 200


def test_ancienne_page_remplacee():
    """L'ancienne page (gros script en ligne, CDN) n'existe plus : `frontend/index.html` est le point
    d'entrée Vite (un seul script, module, servi par l'application elle-même)."""
    page = ROOT / "frontend" / "index.html"
    if not page.exists():
        return
    texte = page.read_text(encoding="utf-8")
    assert "cdn.jsdelivr.net" not in texte
    assert not re.search(r"https?://", texte.replace("http://www.w3.org", ""))
    # Aucun script en ligne : seulement des scripts avec « src » (CSP stricte).
    assert not re.search(r"<script(?![^>]*\bsrc=)[^>]*>", texte)


def test_documentation_sans_ancienne_organisation():
    """Plus de commande ni de chemin disparus dans la documentation (la phase 3 la réécrit ensuite)."""
    for nom in ("README.md", ".env.example"):
        texte = (ROOT / nom).read_text(encoding="utf-8")
        for ancien in ("run.py", "requirements.txt", "requirements-dev.txt", "backend/app", "backend.app"):
            assert ancien not in texte, f"{nom} : {ancien}"
