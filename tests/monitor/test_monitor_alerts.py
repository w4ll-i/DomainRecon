# =============================================================================
# DomainRecon - Tests des règles d'alerte (changement d'état seulement)
# =============================================================================

from surveillance import add_scan

from domainrecon.core import database
from domainrecon.core.models import Scan
from domainrecon.monitor.alerts import AlertRules, evaluate, rules_of
from domainrecon.monitor.compare import diff_scans, scan_view


def _evaluate(before: int | None, after: int, rules: AlertRules | None = None, state: dict | None = None):
    with database.SessionLocal() as db:
        current = db.get(Scan, after)
        view = scan_view(current)
        diff = diff_scans(db.get(Scan, before), current, view_b=view) if before else None
    return evaluate(rules or AlertRules(), state or {}, "exemple.test", view, diff)


def _rules(alerts) -> list[str]:
    return [a.rule for a in alerts]


def test_regles_par_defaut():
    rules = AlertRules()
    assert rules.grade_drop and rules.new_findings and rules.new_port and rules.new_subdomain
    assert rules.cert_expiry_days == 14


def test_regles_invalides_reviennent_aux_valeurs_par_defaut():
    assert rules_of({"cert_expiry_days": 0}) == AlertRules()
    assert rules_of({"inconnue": True}) == AlertRules()
    assert rules_of(None) == AlertRules()
    assert rules_of({"new_port": False}).new_port is False


def test_premier_scan_sans_reference_aucune_alerte_de_comparaison():
    only = add_scan(grade="F", score=20, ports=(3306,), subdomains=("a.exemple.test",))
    alerts, state = _evaluate(None, only)
    assert alerts == []
    assert state == {"cert_expiring": False}


def test_baisse_de_note():
    a = add_scan(minutes=0, grade="A", score=95)
    b = add_scan(minutes=5, grade="B", score=80)
    alerts, _ = _evaluate(a, b)
    (alert,) = [x for x in alerts if x.rule == "grade_drop"]
    assert alert.severity == "medium"
    assert alert.message["p"]["before"] == "A" and alert.message["p"]["after"] == "B"


def test_forte_baisse_de_note_gravite_elevee():
    a = add_scan(minutes=0, grade="A", score=95)
    b = add_scan(minutes=5, grade="D", score=50)
    (alert,) = [x for x in _evaluate(a, b)[0] if x.rule == "grade_drop"]
    assert alert.severity == "high"


def test_amelioration_ou_stabilite_sans_alerte():
    a = add_scan(minutes=0, grade="C", score=65)
    b = add_scan(minutes=5, grade="A", score=95)
    c = add_scan(minutes=6, grade="A", score=95)
    assert "grade_drop" not in _rules(_evaluate(a, b)[0])
    assert _evaluate(b, c)[0] == []


def test_nouveau_constat_eleve_alerte_une_seule_fois():
    a = add_scan(minutes=0)
    b = add_scan(minutes=5, ports=(3306,))
    alerts, _ = _evaluate(a, b)
    findings = [x for x in alerts if x.rule == "new_finding"]
    assert findings and findings[0].severity in ("critical", "high")
    assert findings[0].message["$t"] == "alert.new_finding"
    # Le constat persiste au scan suivant : pas de nouvelle alerte.
    c = add_scan(minutes=10, ports=(3306,))
    assert "new_finding" not in _rules(_evaluate(b, c)[0])


def test_regles_desactivees():
    a = add_scan(minutes=0, grade="A", score=95)
    b = add_scan(minutes=5, grade="D", score=50, ports=(3306, 8080), subdomains=("x.exemple.test",))
    rules = AlertRules(grade_drop=False, new_findings=False, new_port=False, new_subdomain=False)
    alerts, _ = _evaluate(a, b, rules)
    assert alerts == []


def test_nouveau_port_et_nouveau_sous_domaine():
    a = add_scan(minutes=0, ports=(443,), subdomains=("www.exemple.test",))
    b = add_scan(minutes=5, ports=(443, 8080), subdomains=("www.exemple.test", "dev.exemple.test"))
    alerts, _ = _evaluate(a, b)
    by_rule = {x.rule: x for x in alerts}
    assert by_rule["new_port"].data == {"ports": [8080]}
    assert by_rule["new_subdomain"].data["subdomains"] == ["dev.exemple.test"]
    assert by_rule["new_subdomain"].severity == "low"
    # Ports et sous-domaines inchangés : rien.
    c = add_scan(minutes=9, ports=(443, 8080), subdomains=("www.exemple.test", "dev.exemple.test"))
    assert _evaluate(b, c)[0] == []


def test_sous_domaines_cites_plafonnes():
    names = tuple(f"s{i}.exemple.test" for i in range(25))
    a = add_scan(minutes=0, subdomains=())
    b = add_scan(minutes=5, subdomains=names)
    (alert,) = [x for x in _evaluate(a, b)[0] if x.rule == "new_subdomain"]
    assert alert.data["count"] == 25 and len(alert.data["subdomains"]) == 10


def test_expiration_du_certificat_alerte_sur_changement_d_etat():
    soon = add_scan(minutes=0, cert_days=10)
    alerts, state = _evaluate(None, soon)
    (alert,) = alerts
    assert alert.rule == "cert_expiry" and alert.severity == "medium"
    assert alert.message["p"]["days"] == 10 and alert.message["p"]["threshold"] == 14
    assert state["cert_expiring"] is True
    # Toujours sous le seuil au scan suivant : pas de répétition.
    later = add_scan(minutes=10, cert_days=9)
    alerts, state = _evaluate(soon, later, state=state)
    assert alerts == [] and state["cert_expiring"] is True
    # Certificat renouvelé : l'état se réarme...
    renewed = add_scan(minutes=20, cert_days=85)
    alerts, state = _evaluate(later, renewed, state=state)
    assert alerts == [] and state["cert_expiring"] is False
    # ... et une nouvelle approche de l'échéance alerte de nouveau.
    again = add_scan(minutes=30, cert_days=5)
    alerts, state = _evaluate(renewed, again, state=state)
    assert [a.rule for a in alerts] == ["cert_expiry"] and alerts[0].severity == "high"


def test_expiration_seuil_personnalise_et_desactive():
    scan = add_scan(cert_days=25)
    assert _evaluate(None, scan)[0] == []
    assert _rules(_evaluate(None, scan, AlertRules(cert_expiry_days=30))[0]) == ["cert_expiry"]
    assert _evaluate(None, add_scan(cert_days=1), AlertRules(cert_expiry_days=None))[0] == []


def test_certificat_non_mesure_ne_modifie_pas_l_etat():
    scan = add_scan(cert_days=3, measured=("dns_records",))
    alerts, state = _evaluate(None, scan, state={"cert_expiring": True})
    assert alerts == [] and state == {"cert_expiring": True}


def test_scan_en_erreur_non_comparable_sans_alerte_de_comparaison():
    a = add_scan(minutes=0)
    b = add_scan(minutes=5, status="error", grade="F", score=0, measured=())
    assert _evaluate(a, b)[0] == []
