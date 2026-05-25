"""baseline - empty revision that stamps the current schema.

Revision ID: 0001_baseline
Revises:
Create Date: 2026-04-18

This revision is intentionally empty. It marks the state of the schema
as it existed before Alembic was introduced. Existing databases should
be stamped with it using:

    alembic -c backend/alembic.ini stamp head

Fresh databases are built by `Base.metadata.create_all()` at app startup
(which matches the current `models.py`); the legacy idempotent migrator
in `backend/app/migrations.py` catches up any pre-Alembic schema gaps.

New schema changes go in a new revision after this one, created via
`alembic revision --autogenerate -m "..."`.
"""
from typing import Sequence, Union


revision: str = "0001_baseline"
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    pass


def downgrade() -> None:
    pass
