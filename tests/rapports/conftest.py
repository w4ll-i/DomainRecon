# =============================================================================
# DomainRecon - Fixtures des tests des rapports et de la ligne de commande
# =============================================================================

import pytest

from domainrecon.api import storage

from .rapports_aides import build_result, unique_domain


@pytest.fixture
def stockage():
    storage.prepare_storage()


@pytest.fixture
def scan_id(stockage):
    return storage.save_scan(build_result(unique_domain()))


@pytest.fixture
def payload(scan_id):
    from domainrecon import reports

    return reports.load_payload(scan_id)
