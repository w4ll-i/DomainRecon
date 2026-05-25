# backend/alembic/env.py
"""Alembic environment - imports the app's engine + metadata so that
autogenerate sees the real ORM models without duplicating the DB URL.
"""
from logging.config import fileConfig

from alembic import context

# Import the app's DB engine and Base. `prepend_sys_path` in alembic.ini
# makes `backend/` importable as `backend.app`.
from backend.app.database import engine as app_engine
from backend.app.models import Base  # noqa: F401 - populates Base.metadata

config = context.config

if config.config_file_name is not None:
    fileConfig(config.config_file_name)

target_metadata = Base.metadata


def run_migrations_offline() -> None:
    """Emit SQL without a live connection."""
    context.configure(
        url=str(app_engine.url),
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
        render_as_batch=app_engine.dialect.name == "sqlite",
    )
    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    """Run migrations against the live engine."""
    with app_engine.connect() as connection:
        context.configure(
            connection=connection,
            target_metadata=target_metadata,
            render_as_batch=app_engine.dialect.name == "sqlite",
        )
        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
