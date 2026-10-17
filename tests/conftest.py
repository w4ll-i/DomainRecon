# =============================================================================
# DomainRecon - Configuration pytest
# =============================================================================
# Isole les tests :
#   - des données réelles du projet (private/data/domainrecon.db et private/data/screenshots) :
#     base et dossier de données pointent vers un dossier temporaire, supprimé
#     en fin de session ;
#   - du .env et de l'environnement du développeur : réglages de l'application
#     et proxys sortants ramenés à des valeurs neutres.
# En CI, DOMAINRECON_REQUIRE_CHROMIUM=1 (job qui installe Chromium) fait échouer
# un test de capture sauté faute de navigateur au lieu de le laisser passer.
# =============================================================================

import asyncio
import importlib
import os
import shutil
import sys
import tempfile
import warnings
from pathlib import Path

import pytest

_TMP_DIR = Path(tempfile.mkdtemp(prefix="domainrecon-tests-"))

# Doit être défini avant tout import de domainrecon : config.py lit ces
# variables au moment de l'import (base, captures, hôtes autorisés). Affectation
# forcée : ni l'environnement du développeur ni son .env (chargé avec
# override=False) ne doivent faire écrire les tests dans les vraies données.
os.environ["DATABASE_URL"] = f"sqlite:///{(_TMP_DIR / 'test.db').as_posix()}"
os.environ["DATA_DIR"] = str(_TMP_DIR / "data")
# Le TestClient envoie `Host: testserver`.
os.environ["ALLOWED_HOSTS"] = "*"
# Réglages neutres, quel que soit le .env local : pas de jeton d'API (une
# valeur vide vaut « non défini ») et cibles privées refusées par défaut (les
# tests qui en ont besoin font monkeypatch.setenv("ALLOW_PRIVATE_TARGETS", "1")).
os.environ["API_TOKEN"] = ""
os.environ["ALLOW_PRIVATE_TARGETS"] = "0"
# Autres réglages de l'application et de la commande domainrecon : valeur par
# défaut. Une variable vide vaut « non définie » (config.env_str) et
# load_dotenv ne remplace pas une variable déjà présente : un .env avec
# HOST=0.0.0.0 ne change plus le résultat des tests.
_DEFAULT_SETTINGS = (
    "HOST",
    "PORT",
    "LOG_LEVEL",
    "CORS_ORIGINS",
    "MAX_CONCURRENT_SCANS",
    "API_DOCS",
)
for _name in _DEFAULT_SETTINGS:
    os.environ[_name] = ""
# Proxys sortants (lus par httpx et scanner/common.py) : aucun, sinon les
# requêtes vers les serveurs de test locaux partiraient vers le proxy du
# développeur. NO_PROXY=* empêche aussi getproxies() de se rabattre sur le
# registre Windows. Les tests de proxy fixent eux-mêmes ces variables.
for _name in ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY"):
    os.environ[_name] = os.environ[_name.lower()] = ""
os.environ["NO_PROXY"] = os.environ["no_proxy"] = "*"

# Configuration chargée dès maintenant, avec les valeurs ci-dessus : sinon, un
# test qui retire l'une d'elles (monkeypatch.delenv) avant le premier import de
# config la verrait réinjectée par le .env (test_main.py lancé seul, par exemple).
importlib.import_module("domainrecon.core.config")

# Tests de capture d'écran (vrai Chromium derrière le proxy filtrant) : sautés
# si Playwright ou Chromium manque. Motifs des raisons de ces sauts.
_CHROMIUM_SKIP_REASONS = ("Chromium indisponible", "could not import 'playwright")
_REQUIRE_CHROMIUM = os.environ.get("DOMAINRECON_REQUIRE_CHROMIUM", "").strip() == "1"


@pytest.fixture
def registre_historique():
    """Registre ramené aux 18 modules historiques (ceux à colonne dédiée) le temps du test.

    Pour les tests du comportement de ces modules (profils, statut global, barème,
    familles) : ils ne dépendent pas des modules ajoutés depuis. Le dictionnaire
    du registre est modifié sur place (toutes ses références voient le même
    contenu) puis rétabli, dans le même ordre.
    """
    from domainrecon.scanner import registry

    real = registry.MODULES
    saved = dict(real)
    for name, spec in saved.items():
        if spec.column is None:
            del real[name]
    yield real
    real.clear()
    real.update(saved)


@pytest.fixture(autouse=True)
def _cache_ttl_vide():
    """Caches de @cached (scanner/cache.py) vidés entre les tests : chacun simule sa propre réponse pour les mêmes arguments.

    Ce sont aussi ceux des journaux CT (crt.sh, Cert Spotter), d'ipinfo.io et de HackerTarget.
    """
    from domainrecon.scanner import cache

    cache.clear_cache()
    yield
    cache.clear_cache()


@pytest.fixture(autouse=True)
def _politique_asyncio_par_defaut():
    """Politique asyncio par défaut rétablie après chaque test.

    D'anciennes versions d'uvicorn installent uvloop comme politique
    globale en démarrant un serveur réel : les tests suivants résolvaient alors
    les noms par uvloop, sans passer par un socket.getaddrinfo simulé.
    """
    yield
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", DeprecationWarning)  # API dépréciée en 3.14
        if type(asyncio.get_event_loop_policy()) is not asyncio.DefaultEventLoopPolicy:
            asyncio.set_event_loop_policy(None)


@pytest.hookimpl(wrapper=True)
def pytest_runtest_makereport(item, call):
    """Avec DOMAINRECON_REQUIRE_CHROMIUM=1, un test de capture sauté est un échec.

    Sans cela, une CI privée de navigateur resterait verte sans jamais
    vérifier que Chromium ne peut pas joindre le réseau interne.
    """
    report = yield
    if _REQUIRE_CHROMIUM and report.skipped and isinstance(report.longrepr, tuple):
        reason = str(report.longrepr[2])
        if any(marker in reason for marker in _CHROMIUM_SKIP_REASONS):
            report.outcome = "failed"
            report.longrepr = f"Chromium requis (DOMAINRECON_REQUIRE_CHROMIUM=1) : {reason}"
    return report


def pytest_sessionfinish(session, exitstatus):
    """Supprime le dossier temporaire des tests."""
    # Sous Windows, le fichier SQLite reste verrouillé tant que le pool de
    # connexions de l'engine est ouvert.
    database = sys.modules.get("domainrecon.core.database")
    if database is not None:
        database.engine.dispose()
    shutil.rmtree(_TMP_DIR, ignore_errors=True)


@pytest.fixture
def web_build(tmp_path, monkeypatch):
    """Interface construite factice à la place de domainrecon/web (index.html, assets/, fichiers publics)."""
    from domainrecon.core import paths

    web = tmp_path / "web"
    (web / "assets").mkdir(parents=True)
    (web / "index.html").write_text(
        '<!doctype html><html lang="fr"><head><meta charset="utf-8">'
        '<script type="module" crossorigin src="/assets/index-1a2b3c4d.js"></script>'
        '<link rel="stylesheet" crossorigin href="/assets/index-1a2b3c4d.css">'
        '<link rel="icon" href="/favicon.svg"></head>'
        '<body><div id="root"></div></body></html>',
        encoding="utf-8",
    )
    (web / "assets" / "index-1a2b3c4d.js").write_text("console.log('DomainRecon');", encoding="utf-8")
    (web / "assets" / "index-1a2b3c4d.css").write_text("body{margin:0}", encoding="utf-8")
    (web / "assets" / "inter-latin-400.woff2").write_bytes(b"wOF2")
    (web / "assets" / "inter-latin-400-normal-C38fXH4l.woff2").write_bytes(b"wOF2")
    (web / "assets" / ".hidden").write_text("SECRET", encoding="utf-8")
    (web / "favicon.svg").write_text("<svg xmlns='http://www.w3.org/2000/svg'/>", encoding="utf-8")
    (web / ".env").write_text("SECRET=1", encoding="utf-8")
    # Hors de web/ : atteint seulement par une traversée de dossier réussie.
    (web.parent / "secret.txt").write_text("SECRET", encoding="utf-8")
    monkeypatch.setattr(paths, "web_dir", lambda: web)
    return web
