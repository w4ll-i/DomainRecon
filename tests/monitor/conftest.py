import pytest
from surveillance import reset_tables


@pytest.fixture(autouse=True)
def tables_vides():
    """Chaque test repart de tables vides (scans, surveillances, notifications, canaux)."""
    reset_tables()
    yield
    reset_tables()
