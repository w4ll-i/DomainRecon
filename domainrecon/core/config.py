# =============================================================================
# DomainRecon - Configuration centralisée
# =============================================================================
# Toutes les variables d'environnement sont lues ici. Les fichiers de réglages
# existants sont chargés dans l'ordre de paths.env_files() : <dossier de
# données>/.env, puis ./.env depuis les sources. Les variables réellement
# définies dans l'environnement ont toujours priorité, puis le premier
# fichier qui définit une variable. Un DATA_DIR défini seulement dans ./.env
# fixe bien le dossier de données, mais le .env de ce dossier n'est pas relu.
#
# Une valeur vide (`VAR=`) équivaut à une variable absente : la valeur par
# défaut s'applique. Une valeur invalide ne fait jamais planter l'application :
# elle est signalée dans les logs et remplacée par la valeur par défaut. Seul
# un fichier .env illisible (ni UTF-8 ni UTF-16) arrête le démarrage.
# =============================================================================

import codecs
import logging
import os
from pathlib import Path

from dotenv import load_dotenv

from .. import __version__
from . import paths

logger = logging.getLogger(__name__)

# Dossier de l'application : racine du dépôt (sources) ou dossier de l'exécutable.
ROOT_DIR = paths.app_dir()


def load_env_file(path: Path) -> None:
    """Charge un fichier .env, en UTF-8 (BOM accepté) ou en UTF-16 avec BOM.

    Sous Windows PowerShell 5.1, `>` et Out-File écrivent en UTF-16. Tout
    autre encodage (ANSI…) arrête le démarrage avec un message clair :
    ignorer le fichier ferait perdre API_TOKEN et laisserait l'outil ouvert.
    """
    try:
        load_dotenv(path, override=False)
    except UnicodeDecodeError as exc:
        with path.open("rb") as f:
            bom = f.read(2)
        if bom not in (codecs.BOM_UTF16_LE, codecs.BOM_UTF16_BE):
            raise RuntimeError(
                f"Fichier {path} illisible : enregistrez-le en UTF-8 (octet invalide en position {exc.start})."
            ) from exc
        load_dotenv(path, override=False, encoding="utf-16")


def load_env_files() -> list[Path]:
    """Charge les fichiers de réglages existants (paths.env_files()) ; renvoie ceux chargés."""
    loaded = []
    for path in paths.env_files():
        if path.is_file():
            load_env_file(path)
            loaded.append(path)
    return loaded


load_env_files()

# Version unique de l'application (API, /api/health, documentation OpenAPI).
APP_VERSION = __version__

_TRUE_VALUES = {"1", "true", "yes", "on"}
_FALSE_VALUES = {"0", "false", "no", "off"}


# =============================================================================
# Lecture des variables
# =============================================================================


def env_str(name: str, default: str | None = None) -> str | None:
    """Valeur texte (sans espaces autour), ou `default` si absente ou vide."""
    value = os.getenv(name)
    if value is None or not value.strip():
        return default
    return value.strip()


def env_bool(name: str, default: bool) -> bool:
    """Booléen : 1/true/yes/on pour vrai, 0/false/no/off pour faux."""
    value = env_str(name)
    if value is None:
        return default
    lowered = value.lower()
    if lowered in _TRUE_VALUES:
        return True
    if lowered in _FALSE_VALUES:
        return False
    logger.warning("%s invalide (%r) : valeur par défaut %s utilisée", name, value, default)
    return default


def env_int(name: str, default: int, minimum: int | None = None) -> int:
    """Entier, ramené à `minimum` s'il est plus petit."""
    value = env_str(name)
    if value is None:
        result = default
    else:
        try:
            result = int(value)
        except ValueError:
            logger.warning("%s invalide (%r) : valeur par défaut %s utilisée", name, value, default)
            result = default
    if minimum is not None and result < minimum:
        logger.warning("%s trop petit (%s) : minimum %s appliqué", name, result, minimum)
        result = minimum
    return result


def env_list(name: str, default: list[str]) -> list[str]:
    """Liste séparée par des virgules, éléments nettoyés, éléments vides ignorés."""
    value = env_str(name)
    if value is None:
        return list(default)
    return [item.strip() for item in value.split(",") if item.strip()]


def _log_level(default: str = "INFO") -> str:
    """Niveau de log validé : un nom inconnu retombe sur `default`."""
    value = env_str("LOG_LEVEL", default)
    name = value.upper()
    if isinstance(logging.getLevelName(name), int):
        return name
    logger.warning("LOG_LEVEL invalide (%r) : niveau %s utilisé", value, default)
    return default


# =============================================================================
# Valeurs lues au démarrage
# =============================================================================

# Dossier des données (base SQLite, captures) : voir paths.data_dir().
DATA_DIR = paths.data_dir()
SCREENSHOTS_DIR = DATA_DIR / "screenshots"

# SQLite (défaut, zéro config) ou PostgreSQL, par exemple :
# postgresql+psycopg://user:password@localhost/domainrecon
DATABASE_URL = env_str("DATABASE_URL") or f"sqlite:///{DATA_DIR / 'domainrecon.db'}"

LOG_LEVEL = _log_level()

# Outil local : le frontend est servi par cette même application (même origine,
# donc sans CORS) : par défaut, aucune origine n'est autorisée. Une origine
# par défaut (localhost:8000…) laisserait une autre application locale du
# même port lire et supprimer l'historique sans jeton. À renseigner seulement
# si le frontend est servi ailleurs.
CORS_ORIGINS = env_list("CORS_ORIGINS", [])

# Jeton d'accès à l'API (optionnel) : None = pas d'authentification. Défini,
# il est exigé partout sauf sur le frontend (/), /api/health et la
# documentation (voir api/app.py, PUBLIC_PATHS).
API_TOKEN = env_str("API_TOKEN")

# Valeurs acceptées pour l'en-tête Host ; `*` désactive le contrôle.
ALLOWED_HOSTS = env_list("ALLOWED_HOSTS", ["localhost", "127.0.0.1", "::1"])

# Nombre maximal de scans exécutés en même temps.
MAX_CONCURRENT_SCANS = env_int("MAX_CONCURRENT_SCANS", 2, minimum=1)

# Documentation interactive (/api/docs, /api/redoc, /api/openapi.json).
# Accessible sans jeton même si API_TOKEN est défini : elle ne contient aucune
# donnée de scan (le schéma de l'API est public, comme le code du projet).
# Pour y essayer les routes protégées, bouton « Authorize » (en-tête
# X-API-Token ou Authorization: Bearer). Désactivable en déploiement exposé.
API_DOCS_ENABLED = env_bool("API_DOCS", True)


def configure_logging() -> None:
    """Configure les journaux de l'application selon LOG_LEVEL.

    Défini explicitement, LOG_LEVEL s'applique aussi aux journaux d'uvicorn
    (erreurs et accès), qu'uvicorn configure lui-même ; sinon, l'option
    `--log-level` d'uvicorn garde la main sur ses propres journaux.
    """
    level = logging.getLevelName(LOG_LEVEL)
    logging.basicConfig(
        level=level,
        format="%(asctime)s %(levelname)-8s %(name)s — %(message)s",
    )
    if env_str("LOG_LEVEL") is not None:
        for name in ("uvicorn", "uvicorn.error", "uvicorn.access"):
            logging.getLogger(name).setLevel(level)
    # En DEBUG, httpcore trace chaque événement de chaque connexion : illisible.
    logging.getLogger("httpcore").setLevel(max(level, logging.INFO))
    # httpx écrit chaque requête (INFO) avec son URL complète, paramètres compris :
    # certaines API tierces reçoivent leur clé dans l'URL (?key=…), qui ne doit
    # jamais aller dans les journaux (console, fichier des journaux).
    logging.getLogger("httpx").setLevel(max(level, logging.WARNING))


# Test de relais SMTP ouvert du module smtp_security : désactivé par défaut (il
# envoie MAIL FROM / RCPT TO vers des domaines réservés, jamais de DATA).
SMTP_RELAY_TEST_ENV = "DOMAINRECON_SMTP_RELAY_TEST"


# Chemin du binaire Nuclei pour le module « nuclei » (vide : cherché dans le PATH).
NUCLEI_PATH_ENV = "DOMAINRECON_NUCLEI_PATH"


def nuclei_path() -> str | None:
    """Chemin du binaire Nuclei déclaré dans les Réglages, ou None (recherche dans le PATH)."""
    return env_str(NUCLEI_PATH_ENV)


# Dossier des modèles Nuclei embarqués (vide : ceux du dossier de config de Nuclei).
NUCLEI_TEMPLATES_ENV = "DOMAINRECON_NUCLEI_TEMPLATES"


def nuclei_templates() -> str | None:
    """Dossier des modèles Nuclei déclaré dans les Réglages, ou None."""
    return env_str(NUCLEI_TEMPLATES_ENV)


def smtp_relay_test_enabled() -> bool:
    """Le module smtp_security doit-il tester le relais ouvert ? Relue à chaque appel."""
    return env_bool(SMTP_RELAY_TEST_ENV, False)


def private_targets_allowed() -> bool:
    """Autorise les cibles non publiques (réseau privé, loopback…).

    Relue à chaque appel, pour que les tests puissent la changer à la volée.
    """
    return env_bool("ALLOW_PRIVATE_TARGETS", False)
