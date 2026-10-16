# =============================================================================
# DomainRecon - API : stockage des scans et des captures d'écran
# =============================================================================
# Enregistrement d'un scan terminé, fichiers de capture (confinés au dossier
# des captures), nettoyage des captures orphelines, normalisation des
# domaines des anciens scans et préparation de la base au démarrage.
# =============================================================================

import hashlib
import logging
import os
import re
import time
from pathlib import Path

from sqlalchemy import func
from sqlalchemy.engine import URL
from sqlalchemy.exc import OperationalError, SQLAlchemyError
from sqlalchemy.orm import Session

from ..core.config import SCREENSHOTS_DIR
from ..core.database import Base, SessionLocal, engine, sync_schema
from ..core.models import Scan
from ..core.settings_store import prepare_settings
from ..i18n import dumps_message
from ..scanner import SCREENSHOT_NAME_RE, is_valid_target, normalize_target
from .schemas import as_utc

logger = logging.getLogger(__name__)

# Enregistrement d'un scan terminé : une seconde tentative si la base est
# momentanément verrouillée, plutôt que de perdre une minute de collecte.
SAVE_ATTEMPTS = 2
SAVE_RETRY_DELAY = 1.0

# Une capture non référencée n'est supprimée au démarrage qu'au-delà de cet âge
# (secondes) : elle peut appartenir au scan en cours d'un autre processus.
ORPHAN_SCREENSHOT_MIN_AGE = 30 * 60
# Marge entre la capture (pendant le scan) et l'horodatage du scan en base.
ORPHAN_SCREENSHOT_MARGIN = 10 * 60
# Registre des bases qui ont utilisé le dossier des captures (une empreinte
# par ligne, dans ce dossier) : voir cleanup_orphan_screenshots().
SCREENSHOT_OWNERS_FILE = ".databases"

# Noms de capture servis et supprimés (à tester avec fullmatch) : large, pour
# les captures de toutes les versions, y compris les anciens noms qui gardaient
# la casse et l'Unicode de la saisie (« Example_COM_1700000000.png »). `\w`
# exclut les séparateurs (/, \, :) et le point : le nom désigne toujours un
# fichier du dossier des captures, ce que _screenshot_file() vérifie en plus.
# Le nettoyage des orphelines, qui supprime sans demande explicite, s'en tient
# au motif exact des noms générés (`scanner.SCREENSHOT_NAME_RE`).
_SCREENSHOT_NAME_RE = re.compile(r"[\w-]+\.png")

# Colonnes remplies telles quelles depuis le résultat de perform_full_scan :
# une colonne ajoutée au modèle (même nom que la clé du résultat) est
# enregistrée sans autre modification ici.
_RESULT_COLUMNS = tuple(
    attr.key
    for attr in Scan.__mapper__.column_attrs
    if attr.key not in {"id", "scan_timestamp", "tags", "notes"}
)


def _screenshot_file(name: str | None) -> Path | None:
    """Chemin d'une capture, confiné au dossier des captures ; None si le nom est suspect."""
    if not name or not _SCREENSHOT_NAME_RE.fullmatch(name):
        return None
    base = SCREENSHOTS_DIR.resolve()
    candidate = (base / name).resolve()
    if candidate.parent != base:
        return None
    return candidate


def _delete_screenshot_file(name: str | None) -> None:
    """Supprime un fichier de capture, s'il existe."""
    if not name:
        return
    path = _screenshot_file(name)
    if path is None:
        logger.warning("Nom de capture invalide, suppression ignorée : %r", name)
        return
    try:
        path.unlink(missing_ok=True)
    except OSError as e:
        logger.warning("Suppression de la capture %s impossible : %s", path.name, e)


def _screenshot_in_use(db: Session, name: str) -> bool:
    return db.query(Scan.id).filter(Scan.screenshot_path == name).first() is not None


def _database_fingerprint(url: URL) -> str:
    """Empreinte courte d'une base, calculée sans son mot de passe.

    Une base SQLite rangée dans le dossier de données y est désignée par son
    chemin relatif : l'empreinte ne change pas si ce dossier est déplacé.
    """
    ident = url.render_as_string(hide_password=True)
    if url.get_backend_name() == "sqlite" and url.database not in (None, "", ":memory:"):
        path = Path(url.database).resolve()
        data_dir = SCREENSHOTS_DIR.parent.resolve()
        if path.is_relative_to(data_dir):
            path = path.relative_to(data_dir)
        ident = f"sqlite:{path.as_posix()}"
    return hashlib.sha256(ident.encode("utf-8")).hexdigest()[:16]


def _screenshots_dir_owned_by(fingerprint: str) -> bool:
    """Inscrit la base au registre du dossier des captures.

    Vrai si ce dossier n'a jamais servi qu'à cette base. Registre illisible
    ou impossible à compléter : faux, dans le doute.
    """
    registry = SCREENSHOTS_DIR / SCREENSHOT_OWNERS_FILE
    try:
        owners = set(registry.read_text(encoding="ascii").split()) if registry.is_file() else set()
        if fingerprint not in owners:
            with registry.open("a", encoding="ascii") as f:
                f.write(f"{fingerprint}\n")
            owners.add(fingerprint)
    except (OSError, UnicodeDecodeError) as e:
        logger.warning("Registre %s inaccessible : captures orphelines conservées (%s)", registry, e)
        return False
    if owners != {fingerprint}:
        logger.info("Dossier des captures partagé avec une autre base : captures orphelines conservées")
        return False
    return True


def cleanup_orphan_screenshots(min_age: float = ORPHAN_SCREENSHOT_MIN_AGE) -> int:
    """Supprime les captures qu'aucun scan ne référence ; renvoie leur nombre.

    Seuls les fichiers nommés comme les captures générées sont concernés, et
    seulement au-delà de `min_age` secondes. Après un changement de
    DATABASE_URL avec le même DATA_DIR, une capture non référencée ici peut
    appartenir à l'autre base : chaque base s'inscrit donc au registre du
    dossier (SCREENSHOT_OWNERS_FILE), et rien n'est supprimé dès qu'une autre
    base y figure. Pour un dossier partagé avant l'existence du registre, les
    fichiers antérieurs au plus ancien scan de la base restent aussi intouchés.
    """
    if not SCREENSHOTS_DIR.is_dir():
        return 0
    with SessionLocal() as db:
        fingerprint = _database_fingerprint(db.get_bind().url)
        oldest = db.query(func.min(Scan.scan_timestamp)).scalar()
        referenced = {
            name for (name,) in db.query(Scan.screenshot_path).filter(Scan.screenshot_path.isnot(None))
        }
    # Inscription avant tout : une base encore vide doit protéger ses futures
    # captures du nettoyage des autres bases.
    if not _screenshots_dir_owned_by(fingerprint) or oldest is None:
        return 0
    # La capture est prise pendant le scan, avant l'horodatage de la ligne.
    not_before = as_utc(oldest).timestamp() - ORPHAN_SCREENSHOT_MARGIN
    cutoff = time.time() - min_age
    removed = 0
    for path in SCREENSHOTS_DIR.iterdir():
        if path.name in referenced or not SCREENSHOT_NAME_RE.fullmatch(path.name):
            continue
        try:
            if not path.is_file() or not not_before <= path.stat().st_mtime <= cutoff:
                continue
            path.unlink()
            removed += 1
        except OSError as e:
            logger.warning("Capture orpheline %s non supprimée : %s", path.name, e)
    return removed


def normalize_legacy_domains() -> int:
    """Normalise les domaines des scans des anciennes versions ; renvoie le nombre de scans modifiés.

    Ces versions gardaient la casse et l'Unicode de la saisie (« Example.COM »,
    « bücher.de ») : la timeline, qui cherche le domaine normalisé (minuscules,
    punycode), ne trouvait pas ces scans. Une valeur que normalize_target() ne
    rend pas valide est laissée telle quelle.
    """
    with SessionLocal() as db:
        renames = {}
        for (domain,) in db.query(Scan.domain).distinct():
            target = normalize_target(domain)
            if target != domain and is_valid_target(target):
                renames[domain] = target
        updated = 0
        for old, new in renames.items():
            updated += (
                db.query(Scan)
                .filter(Scan.domain == old)
                .update({Scan.domain: new}, synchronize_session=False)
            )
        if renames:
            db.commit()
    return updated


def _commit_new_scan(db: Session, values: dict) -> Scan:
    """Insère un scan ; nouvelle tentative si la base est momentanément verrouillée."""
    attempt = 1
    while True:
        scan = Scan(**values)
        db.add(scan)
        try:
            db.commit()
            return scan
        except OperationalError:
            db.rollback()
            if attempt >= SAVE_ATTEMPTS:
                raise
        attempt += 1
        logger.warning(
            "Base occupée à l'enregistrement du scan de %r : nouvelle tentative", values.get("domain")
        )
        time.sleep(SAVE_RETRY_DELAY)


class ScanSaveError(RuntimeError):
    """Scan terminé mais impossible à enregistrer (détail dans les journaux)."""


def _clean_modules(value: object, domain: str | None) -> dict | None:
    """Résultats génériques à enregistrer (colonne `modules`) : un dictionnaire, ou None.

    Toute autre valeur est écartée avec un avertissement : la lecture de la
    colonne n'accepte qu'un dictionnaire, et le scan, lui, doit être enregistré.
    """
    if value is None or isinstance(value, dict):
        return value
    logger.warning(
        "Résultats génériques du scan de %r ignorés : dictionnaire attendu, %s reçu",
        domain,
        type(value).__name__,
    )
    return None


def _clean_profile(value: object, domain: str | None) -> str | None:
    """Profil à enregistrer (colonne `profile`) : un texte, ou None.

    Toute autre valeur est écartée avec un avertissement, pour la même raison
    que les résultats génériques : le scan doit être enregistré.
    """
    if value is None or isinstance(value, str):
        return value
    logger.warning(
        "Profil du scan de %r ignoré : texte attendu, %s reçu",
        domain,
        type(value).__name__,
    )
    return None


def _clean_modules_launched(value: object, domain: str | None) -> list[str] | None:
    """Noms des modules lancés à enregistrer (colonne `modules_launched`) : une liste de textes, ou None.

    Toute autre valeur est écartée avec un avertissement (voir _clean_profile).
    """
    if value is None:
        return None
    if isinstance(value, (list, tuple)) and all(isinstance(name, str) for name in value):
        return list(value)
    logger.warning(
        "Modules lancés du scan de %r ignorés : liste de noms attendue, %s reçu",
        domain,
        type(value).__name__,
    )
    return None


def save_scan(result: dict) -> int:
    """Enregistre un scan terminé et renvoie son identifiant.

    Les résultats des modules du registre (clé `modules` : {nom: {status, data,
    duration, error}}) vont dans la colonne du même nom ; sans cette clé, elle
    reste NULL, comme pour un scan d'avant la v2. Les autres résultats vont dans
    leurs colonnes historiques. Le profil du scan (clé `profile`) et les noms des
    modules lancés (clé `modules_launched`, dans l'ordre d'exécution) sont
    enregistrés de la même façon, NULL quand ils manquent.

    La session ne vit que le temps de l'écriture. Lève ScanSaveError si
    l'enregistrement échoue ; la capture du scan est alors supprimée (sans
    ligne en base, elle serait orpheline).
    """
    values = {key: result[key] for key in _RESULT_COLUMNS if key in result}
    if "modules" in values:
        values["modules"] = _clean_modules(values["modules"], values.get("domain"))
    if "profile" in values:
        values["profile"] = _clean_profile(values["profile"], values.get("domain"))
    if "modules_launched" in values:
        values["modules_launched"] = _clean_modules_launched(values["modules_launched"], values.get("domain"))
    if "error_message" in values:
        # Colonne TEXT : un message y est rangé en JSON (voir schemas.StoredMessage).
        values["error_message"] = dumps_message(values["error_message"])
    with SessionLocal() as db:
        try:
            scan = _commit_new_scan(db, values)
        except Exception as e:
            logger.exception("Enregistrement du scan de %r échoué", values.get("domain"))
            _delete_screenshot_file(values.get("screenshot_path"))
            raise ScanSaveError(values.get("domain")) from e
        return scan.id


def _database_writable() -> bool:
    """Pour SQLite : le fichier de base et son dossier sont-ils accessibles en écriture ?

    `SELECT 1` réussit sur une base en lecture seule, alors que chaque scan
    échouera à l'enregistrement.
    """
    if engine.url.get_backend_name() != "sqlite" or engine.url.database in (None, "", ":memory:"):
        return True
    database = Path(engine.url.database)
    if database.exists() and not os.access(database, os.W_OK):
        return False
    return os.access(database.parent, os.W_OK)


def prepare_storage() -> None:
    """Tables, schéma, réglages, domaines des anciens scans, dossier des captures et nettoyage des orphelins."""
    Base.metadata.create_all(bind=engine)
    added = sync_schema(Scan)
    if added:
        logger.info("Colonnes ajoutées à la base existante : %s", ", ".join(added))
    prepare_settings()
    try:
        normalized = normalize_legacy_domains()
    except SQLAlchemyError as e:
        # Base en lecture seule, par exemple : l'application démarre quand même.
        logger.warning("Normalisation des domaines des anciens scans impossible : %s", e)
    else:
        if normalized:
            logger.info("Domaines des anciens scans normalisés : %s scan(s)", normalized)
    SCREENSHOTS_DIR.mkdir(parents=True, exist_ok=True)
    removed = cleanup_orphan_screenshots()
    if removed:
        logger.info("%s capture(s) orpheline(s) supprimée(s)", removed)
