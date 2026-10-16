# =============================================================================
# DomainRecon - Tests du scan de ports fusionné (impl/open_ports.py), sans réseau
# =============================================================================
# Le module « open_ports » est historique : son adaptateur (modules/open_ports.py)
# est un fichier partagé. Ces tests couvrent la logique fusionnée qu'il doit
# brancher (51 ports, niveaux de risque, constats et pénalités).
# =============================================================================

import asyncio

import pytest

from domainrecon.i18n import catalog, msg
from domainrecon.scanner import network
from domainrecon.scanner.errors import ModuleError, TargetNotAllowedError
from domainrecon.scanner.impl import open_ports
from domainrecon.scanner.rules import FindingInput, Hit
from domainrecon.scanner.score import SENSITIVE_PORTS

# Ports courants de référence : aucun ne doit se perdre.
PORTS_REFERENCE = [
    21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 465, 587, 993, 995, 1433, 1521, 2375, 2376, 3000, 3001, 3306,
    3389, 4848, 5000, 5001, 5432, 5900, 6379, 6380, 7001, 7002, 8000, 8001, 8080, 8081, 8443, 8888, 8500, 9000,
    9200, 9300, 11211, 27017, 27018, 50000,
]  # fmt: skip
RISQUES = {"critical", "high", "medium", "low", "info"}


def test_liste_fusionnee_ne_perd_aucun_port():
    assert len(open_ports.PORTS) == 51
    assert set(PORTS_REFERENCE) <= set(open_ports.PORTS)
    assert set(network.COMMON_PORTS) <= set(open_ports.PORTS)
    # Tout service pénalisé par le score est sondé (sinon sa pénalité serait inatteignable).
    assert set(SENSITIVE_PORTS) <= set(open_ports.PORTS)
    assert {risk for _, risk in open_ports.PORTS.values()} <= RISQUES


def test_risque_coherent_avec_le_bareme():
    for port, (_, severity) in SENSITIVE_PORTS.items():
        assert open_ports.risk_of(port) == severity
    assert open_ports.risk_of(6379) == "critical" and open_ports.risk_of(8500) == "high"
    assert open_ports.risk_of(22) == "info" and open_ports.risk_of(65000) == "info"
    assert open_ports.service_name(2375) == "Docker API" and open_ports.service_name(65000) == "unknown"


def faux_sondes(monkeypatch, etats: dict, defaut=("filtered", None)):
    appels: list[int] = []

    async def check(ip, port, timeout=3.0):
        appels.append(port)
        etat = etats.get(port, defaut)
        return etat(port) if callable(etat) else etat

    monkeypatch.setattr(network, "_check_port", check)
    return appels


def test_scan_ports_ouverts_avec_service_et_risque(monkeypatch):
    appels = faux_sondes(
        monkeypatch,
        {22: ("open", None), 8500: ("open", None), 6379: ("open", None), 3306: ("refused", None)},
    )
    result = asyncio.run(open_ports.scan_ports("93.184.216.34"))

    assert result == [
        {"port": 22, "state": "open", "service": "SSH", "risk": "info"},
        {"port": 6379, "state": "open", "service": "Redis", "risk": "critical"},
        {"port": 8500, "state": "open", "service": "Consul", "risk": "high"},
    ]
    assert sorted(appels) == sorted(open_ports.PORTS)


def test_sonde_bloquee_est_refaite(monkeypatch):
    essais: dict[int, int] = {}

    def check(port):
        essais[port] = essais.get(port, 0) + 1
        if port == 443:
            return ("stalled", None) if essais[port] == 1 else ("open", None)
        return ("refused", None)

    faux_sondes(monkeypatch, {}, defaut=check)
    result = asyncio.run(open_ports.scan_ports("93.184.216.34"))
    assert [e["port"] for e in result] == [443] and essais[443] == 2 and essais[22] == 1


def test_hote_injoignable_ou_filtre(monkeypatch):
    faux_sondes(monkeypatch, {})
    with pytest.raises(ModuleError) as erreur:
        asyncio.run(open_ports.scan_ports("93.184.216.34"))
    assert erreur.value.message == msg("network.ports_filtered", count=len(open_ports.PORTS))

    faux_sondes(monkeypatch, {}, defaut=("error", "réseau inaccessible"))
    with pytest.raises(ModuleError) as erreur:
        asyncio.run(open_ports.scan_ports("93.184.216.34"))
    assert erreur.value.message == msg("network.ports_failed", error="réseau inaccessible")


def test_adresses_refusees_ou_absentes(monkeypatch):
    appels = faux_sondes(monkeypatch, {22: ("open", None)})
    with pytest.raises(TargetNotAllowedError):
        asyncio.run(open_ports.scan_ports("10.0.0.5"))
    with pytest.raises(ValueError):
        asyncio.run(
            open_ports.scan_ports("example.com")
        )  # jamais de nom : la connexion le résoudrait sans contrôle
    assert asyncio.run(open_ports.scan_ports("")) == []
    assert appels == []


def test_ports_choisis(monkeypatch):
    appels = faux_sondes(monkeypatch, {80: ("open", None)})
    assert [e["port"] for e in asyncio.run(open_ports.scan_ports("93.184.216.34", [80, 80, 8080]))] == [80]
    assert sorted(appels) == [80, 8080]


# --- Constats et pénalités ------------------------------------------------------


def entree(data) -> FindingInput:
    return FindingInput({}, "open_ports", lambda scan, module: data, lambda scan, module: True)


def test_services_sensibles_du_bareme_et_ajoutes():
    ouverts = [
        {"port": 22, "state": "open"},
        {"port": 6379, "state": "open"},
        {"port": 8500, "state": "open"},
        {"port": 9000, "state": "open"},
    ]
    assert open_ports.exposed_sensitive_ports(ouverts) == [
        (6379, "Redis", "critical"),
        (8500, "Consul", "high"),
        (9000, "PHP-FPM", "medium"),
    ]
    # Formats enregistrés tolérés ; ports fermés et valeurs inattendues ignorés.
    assert open_ports.exposed_sensitive_ports(
        [2375, "27018", {"port": 5900, "state": "closed"}, None, "x"]
    ) == [
        (2375, "API Docker", "critical"),
        (27018, "MongoDB", "high"),
    ]
    assert (
        open_ports.exposed_sensitive_ports("inattendu") == []
        and open_ports.exposed_sensitive_ports(None) == []
    )


def test_constat_port_expose():
    (regle,) = open_ports.PORT_FINDINGS
    assert (
        regle.code == "finding.port_exposed" and regle.code in catalog("fr") and regle.code in catalog("en")
    )
    hits = regle.check(
        entree(
            [{"port": 6379, "state": "open"}, {"port": 8500, "state": "open"}, {"port": 80, "state": "open"}]
        )
    )
    assert all(isinstance(h, Hit) for h in hits)
    assert [(h.params, h.severity) for h in hits] == [
        ({"port": 6379, "service": "Redis"}, "critical"),
        ({"port": 8500, "service": "Consul"}, "high"),
    ]
    assert regle.check(entree([{"port": 22, "state": "open"}, {"port": 443, "state": "open"}])) == []


def test_penalites_au_meme_bareme_que_le_score():
    penalites = open_ports.PORT_PENALTY_RULE.evaluate(
        {"open_ports": [{"port": 6379}, {"port": 8500}, {"port": 3000}, {"port": 22}]}
    )
    assert [(p["key"], p["points"], p["severity"]) for p in penalites] == [
        ("port_3000", 5, "medium"),
        ("port_6379", 15, "critical"),
        ("port_8500", 10, "high"),
    ]
    assert penalites[0]["label"] == msg("score.penalty_port", port=3000, service="Node/Grafana")
    assert open_ports.PORT_PENALTY_RULE.evaluate({"open_ports": "x"}) == []
    assert open_ports.PORT_PENALTY_RULE.evaluate({}) == []
