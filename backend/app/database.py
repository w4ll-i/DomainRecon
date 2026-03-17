# =============================================================================
# DomainRecon - Configuration Base de Données (SQLite par défaut)
# =============================================================================

import os
from pathlib import Path
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, declarative_base

# Support SQLite (défaut, zéro config) et PostgreSQL (via variable d'env)
DATABASE_URL = os.getenv("DATABASE_URL", None)

if not DATABASE_URL:
    DB_DIR = Path(__file__).resolve().parent.parent.parent / "data"
    DB_DIR.mkdir(parents=True, exist_ok=True)
    DATABASE_URL = f"sqlite:///{DB_DIR / 'domainrecon.db'}"

# SQLite nécessite check_same_thread=False pour FastAPI
connect_args = {}
if DATABASE_URL.startswith("sqlite"):
    connect_args["check_same_thread"] = False

engine = create_engine(DATABASE_URL, connect_args=connect_args, pool_pre_ping=True)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()


def get_db():
    """Fournit une session de BDD pour chaque requête."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
