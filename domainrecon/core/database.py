# =============================================================================
# DomainRecon - Configuration Base de Données (SQLite par défaut)
# =============================================================================

import logging

from sqlalchemy import create_engine, inspect
from sqlalchemy.engine import make_url
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import declarative_base, sessionmaker
from sqlalchemy.schema import CreateColumn

from .config import DATA_DIR, DATABASE_URL

logger = logging.getLogger(__name__)

# Support SQLite (défaut, zéro config) et PostgreSQL (via DATABASE_URL, voir
# config.py). La base SQLite par défaut vit dans DATA_DIR : le dossier doit
# exister avant la première connexion.
DATA_DIR.mkdir(parents=True, exist_ok=True)

# Attente maximale d'une connexion libre du pool, en secondes. Au-delà, la
# requête échoue (l'API répond 503) au lieu de rester bloquée 30 s.
POOL_TIMEOUT = 10


def _engine_options(url: str) -> dict:
    """Options de create_engine selon le moteur de base."""
    parsed = make_url(url)
    options: dict = {"pool_pre_ping": True}
    if parsed.get_backend_name() == "sqlite":
        # Les endpoints tournent dans le threadpool de FastAPI : une connexion
        # du pool peut servir successivement plusieurs threads.
        options["connect_args"] = {"check_same_thread": False}
        if parsed.database in (None, "", ":memory:"):
            # Base en mémoire : pool à connexion unique, sans pool_timeout.
            return options
    options["pool_timeout"] = POOL_TIMEOUT
    return options


try:
    engine = create_engine(DATABASE_URL, **_engine_options(DATABASE_URL))
except ModuleNotFoundError as exc:
    # Pilote absent (psycopg pour PostgreSQL) : message clair au démarrage.
    raise RuntimeError(
        "Pilote de base de données absent pour DATABASE_URL (PostgreSQL : "
        "python -m pip install --group postgres, pip >= 25.1)"
    ) from exc
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()


def get_db():
    """Fournit une session de BDD pour chaque requête."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


class SchemaMigrationError(RuntimeError):
    """Évolution du schéma impossible sans migration manuelle."""


def _column_names(target_engine, table_name: str) -> set[str]:
    """Colonnes actuelles d'une table (nouvel inspecteur : pas de cache)."""
    return {col["name"] for col in inspect(target_engine).get_columns(table_name)}


def sync_schema(model, target_engine=None) -> list[str]:
    """Ajoute les colonnes et index du modèle absents de la table existante.

    `create_all()` ne modifie jamais une table déjà créée : sans cela, une base
    créée par une version antérieure fait échouer chaque requête dès qu'une
    colonne est ajoutée au modèle. Seul l'ajout est géré : une colonne
    obligatoire sans valeur par défaut côté base bloque le démarrage
    (SchemaMigrationError) plutôt que de laisser l'application démarrer avec
    une table inutilisable. Renvoie les colonnes ajoutées.
    """
    target_engine = target_engine or engine
    table = model.__table__
    if not inspect(target_engine).has_table(table.name):
        return []

    existing = _column_names(target_engine, table.name)
    missing = [column for column in table.columns if column.name not in existing]

    # Tout vérifier avant de modifier quoi que ce soit.
    for column in missing:
        if not column.nullable and column.server_default is None:
            raise SchemaMigrationError(
                f"La colonne {table.name}.{column.name} est obligatoire (NOT NULL) sans "
                "valeur par défaut côté base : migration manuelle requise."
            )

    dialect = target_engine.dialect
    table_sql = dialect.identifier_preparer.format_table(table)
    added = []
    for column in missing:
        # CreateColumn produit le nom quoté, le type, le DEFAULT et le NOT NULL.
        column_sql = CreateColumn(column).compile(dialect=dialect)
        try:
            with target_engine.begin() as conn:
                conn.exec_driver_sql(f"ALTER TABLE {table_sql} ADD COLUMN {column_sql}")
        except SQLAlchemyError:
            # Un autre processus (second worker uvicorn) a pu l'ajouter entre
            # l'inspection et l'ALTER : ce n'est pas une erreur.
            if column.name in _column_names(target_engine, table.name):
                logger.info("Colonne %s.%s déjà ajoutée par un autre processus", table.name, column.name)
                continue
            raise
        added.append(column.name)

    _create_missing_indexes(table, target_engine)
    return added


def _create_missing_indexes(table, target_engine) -> None:
    """Crée les index du modèle absents de la base (optimisation : jamais bloquant)."""
    for index in table.indexes:
        try:
            index.create(bind=target_engine, checkfirst=True)
        except SQLAlchemyError as e:
            logger.warning("Index %s non créé : %s", index.name, e)
