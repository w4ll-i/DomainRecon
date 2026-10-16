"""Tests du packaging : dossiers de sortie par défaut, quel que soit l'environnement du développeur."""

import pytest


@pytest.fixture(autouse=True)
def dossiers_de_sortie_par_defaut(monkeypatch):
    """DOMAINRECON_BUILD_DIR / DOMAINRECON_RELEASE_DIR du poste ignorés : private/build et release/."""
    for name in ("DOMAINRECON_BUILD_DIR", "DOMAINRECON_RELEASE_DIR"):
        monkeypatch.delenv(name, raising=False)
