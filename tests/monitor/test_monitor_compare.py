# =============================================================================
# DomainRecon - Tests de la comparaison de deux scans et de l'affichage des notes
# =============================================================================

import pytest
from fastapi.testclient import TestClient
from surveillance import add_scan

from domainrecon.api.app import app
from domainrecon.core import database
from domainrecon.core.models import Scan
from domainrecon.monitor.compare import _finding_key, _findings_diff, diff_scans
from domainrecon.monitor.scorefmt import display_score, grade_rank


def _diff(a: int, b: int) -> dict:
    with database.SessionLocal() as db:
        return diff_scans(db.get(Scan, a), db.get(Scan, b))


# --- Note affichée ------------------------------------------------------------


def test_display_score_note_mesuree():
    assert display_score({"score": 82.5, "grade": "B", "coverage": 100, "measured_max": 100}) == {
        "score": 82.5,
        "grade": "B",
        "coverage": 100,
    }


def test_display_score_couverture_insuffisante_sans_criteres_comptes():
    shown = display_score({"score": 70, "grade": "C", "coverage": 30, "measured_max": 0})
    assert shown["score"] is None and shown["grade"] == "N/A"


def test_display_score_couverture_faible_mais_indicative():
    shown = display_score({"score": 60, "grade": "D", "coverage": 30, "measured_max": 20})
    assert shown["score"] == 60 and shown["grade"] == "N/A"


def test_display_score_absent_ou_invalide():
    for value in (None, {}, "x", {"score": True, "grade": "A"}):
        assert display_score(value)["grade"] == "N/A"


def test_grade_rank():
    assert grade_rank("A") < grade_rank("C") < grade_rank("F")
    assert grade_rank("N/A") is None and grade_rank(None) is None


# --- Différences ----------------------------------------------------------------


def test_scans_identiques_aucun_changement():
    a = add_scan(minutes=0, ports=(443,), subdomains=("www.exemple.test",), technologies=("nginx",))
    b = add_scan(minutes=10, ports=(443,), subdomains=("www.exemple.test",), technologies=("nginx",))
    diff = _diff(a, b)
    assert diff["comparable"] is True
    assert diff["changes"] == []
    assert diff["score"]["delta"] == 0 and diff["score"]["grade_changed"] is False
    assert diff["ports"] == {"opened": [], "closed": []}
    assert diff["subdomains"] == {"added": [], "removed": []}
    assert diff["technologies"] == {"added": [], "removed": []}
    assert diff["certificate"]["changed"] is False
    assert diff["dns"] == {}
    assert diff["findings"]["new"] == [] and diff["findings"]["resolved"] == []


def test_changements_structures():
    a = add_scan(
        minutes=0,
        grade="A",
        score=95,
        ports=(443, 80),
        subdomains=("www.exemple.test", "old.exemple.test"),
        technologies=("nginx", "php"),
        cert_serial="01",
        cert_days=80,
        dns={"A": ["1.1.1.1"], "MX": ["mx1"], "measured": True},
    )
    b = add_scan(
        minutes=60,
        grade="C",
        score=70,
        ports=(443, 3306),
        subdomains=("www.exemple.test", "new.exemple.test"),
        technologies=("nginx", "react"),
        cert_serial="02",
        cert_days=88,
        dns={"A": ["2.2.2.2"], "MX": ["mx1"], "measured": True},
    )
    diff = _diff(a, b)
    assert diff["score"]["a"]["grade"] == "A" and diff["score"]["b"]["grade"] == "C"
    assert diff["score"]["delta"] == -25 and diff["score"]["grade_changed"] is True
    assert diff["ports"]["opened"] == [{"port": 3306, "service": "svc"}]
    assert diff["ports"]["closed"] == [{"port": 80, "service": "svc"}]
    assert diff["subdomains"] == {"added": ["new.exemple.test"], "removed": ["old.exemple.test"]}
    assert diff["technologies"] == {"added": ["react"], "removed": ["php"]}
    assert diff["certificate"]["changed"] is True
    assert diff["certificate"]["fields"]["serial_number"] == {"a": "01", "b": "02"}
    assert diff["certificate"]["days_remaining"] == {"a": 80, "b": 88}
    assert diff["dns"] == {"A": {"added": ["2.2.2.2"], "removed": ["1.1.1.1"]}}
    # Un port sensible (3306) apparaît comme nouveau constat.
    codes = [f["message"]["$t"] for f in diff["findings"]["new"]]
    assert "finding.port_exposed" in codes
    summary = [m["$t"] for m in diff["changes"]]
    assert summary == [
        "compare.summary_score",
        "compare.summary_new_findings",
        "compare.summary_dns",
        "compare.summary_ports_opened",
        "compare.summary_ports_closed",
        "compare.summary_subdomains_added",
        "compare.summary_subdomains_removed",
        "compare.summary_certificate",
        "compare.summary_technologies",
    ]


def test_constat_resolu():
    a = add_scan(minutes=0, ports=(3306,))
    b = add_scan(minutes=5, ports=())
    diff = _diff(a, b)
    assert [f["message"]["$t"] for f in diff["findings"]["resolved"]] == ["finding.port_exposed"]
    assert diff["findings"]["new"] == []
    assert "compare.summary_resolved_findings" in [m["$t"] for m in diff["changes"]]


def test_constat_non_resolu_si_le_module_na_pas_tourne_dans_b():
    """Profil rapide après un scan complet : un module non lancé ou en échec ne « résout » rien."""
    finding = {"module": "open_ports", "message": {"$t": "finding.port_exposed", "p": {"port": 3306}}}
    a = {"findings": [finding], "module_status": {"open_ports": {"status": "ok"}}}
    non_lance = {"findings": [], "modules_launched": ["dns_records"], "module_status": {"dns_records": {}}}
    en_echec = {"findings": [], "module_status": {"open_ports": {"status": "failed"}}}
    mesure = {"findings": [], "module_status": {"open_ports": {"status": "ok"}}}
    assert _findings_diff(a, non_lance)["resolved"] == []
    assert _findings_diff(a, en_echec)["resolved"] == []
    assert _findings_diff(a, mesure)["resolved"] == [finding]


def test_deux_ports_sensibles_differents_sont_deux_constats():
    a = add_scan(minutes=0, ports=(3306,))
    b = add_scan(minutes=5, ports=(6379,))
    diff = _diff(a, b)
    assert len(diff["findings"]["new"]) == 1 and len(diff["findings"]["resolved"]) == 1


def test_jours_restants_ne_creent_pas_de_nouveau_constat():
    # finding.tls_expires_soon porte le paramètre « days » : volatile.
    a = add_scan(minutes=0, cert_days=20)
    b = add_scan(minutes=5, cert_days=19)
    diff = _diff(a, b)
    assert diff["findings"]["new"] == [] and diff["findings"]["resolved"] == []
    assert diff["findings"]["unchanged"] >= 1


def test_identite_du_constat_ignore_les_parametres_volatils():
    one = {"module": "m", "message": {"$t": "finding.x", "p": {"days": 5, "port": 80}}}
    two = {"module": "m", "message": {"$t": "finding.x", "p": {"days": 4, "port": 80}}}
    other = {"module": "m", "message": {"$t": "finding.x", "p": {"days": 4, "port": 81}}}
    assert _finding_key(one) == _finding_key(two) != _finding_key(other)


def test_rubrique_non_mesuree_vaut_none():
    a = add_scan(minutes=0, ports=(443,), measured=("dns_records", "subdomains", "tls_certificate"))
    b = add_scan(minutes=5, ports=(80,))
    diff = _diff(a, b)
    assert diff["ports"] is None
    assert diff["subdomains"] is not None


def test_scan_en_erreur_non_comparable():
    a = add_scan(minutes=0)
    b = add_scan(minutes=5, status="error", measured=())
    diff = _diff(a, b)
    assert diff["comparable"] is False
    assert diff["findings"] is None and diff["ports"] is None and diff["changes"] == []


# --- Route --------------------------------------------------------------------


@pytest.fixture
def client():
    with TestClient(app) as c:
        yield c


def test_route_compare_rend_les_messages_dans_la_langue(client):
    a = add_scan(minutes=0, ports=())
    b = add_scan(minutes=5, ports=(3306,))
    fr = client.get(f"/api/compare?a={a}&b={b}&lang=fr").json()
    en = client.get(f"/api/compare?a={a}&b={b}&lang=en").json()
    assert fr["domain"] == "exemple.test"
    assert fr["a"]["id"] == a and fr["b"]["id"] == b
    assert any("Ports ouverts" in line for line in fr["changes"])
    assert any("Opened ports" in line for line in en["changes"])
    assert "3306" in fr["changes"][-1] or any("3306" in line for line in fr["changes"])
    assert fr["findings"]["new"][0]["severity"] in ("critical", "high", "medium", "low")
    assert isinstance(fr["findings"]["new"][0]["message"], str)


def test_route_compare_domaines_differents(client):
    a = add_scan("un.test")
    b = add_scan("deux.test")
    response = client.get(f"/api/compare?a={a}&b={b}")
    assert response.status_code == 400
    assert response.json()["code"] == "compare.different_domains"


def test_route_compare_scan_inconnu_et_parametres_invalides(client):
    a = add_scan()
    assert client.get(f"/api/compare?a={a}&b=999999").status_code == 404
    assert client.get("/api/compare?a=0&b=1").status_code == 422
    assert client.get(f"/api/compare?a={a}").status_code == 422
