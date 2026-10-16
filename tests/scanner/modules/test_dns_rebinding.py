# =============================================================================
# DomainRecon - Tests du module « dns_rebinding » : IP privée exposée en DNS (sans réseau)
# =============================================================================

import dns.exception
import pytest

from domainrecon.scanner.errors import ModuleError
from domainrecon.scanner.modules import dns_rebinding
from domainrecon.scanner.rules import FindingInput

SPEC = dns_rebinding.SPEC


def _finding(data):
    return FindingInput({}, "dns_rebinding", lambda scan, name: data, lambda scan, name: True)


def _regle():
    return SPEC.findings[0]


def test_adresses_publiques_rien_a_signaler(contexte, outils, dns_simule):
    dns_simule(
        {
            ("example.com", "A"): [outils.rdata("A", "93.184.216.34")],
            ("example.com", "AAAA"): [outils.rdata("AAAA", "2606:2800:21f:cb07:6820:80da:af6b:8b2c")],
        }
    )
    sortie = outils.executer(SPEC, contexte())
    outils.verifier_sortie(sortie)
    assert sortie["exposed"] is False and sortie["count"] == 0
    assert _regle().check(_finding(sortie)) is None
    assert SPEC.score_rules[0].evaluate({"dns_rebinding": sortie}).points == 3


def test_a_et_aaaa_prives_detectes(contexte, outils, dns_simule):
    """Les motifs IPv6 se déclenchent comme les motifs IPv4."""
    dns_simule(
        {
            ("example.com", "A"): [outils.rdata("A", "10.1.2.3"), outils.rdata("A", "93.184.216.34")],
            ("example.com", "AAAA"): [
                outils.rdata("AAAA", "fd12:3456::1"),
                outils.rdata("AAAA", "::ffff:192.168.0.9"),
            ],
        }
    )
    sortie = outils.executer(SPEC, contexte())
    outils.verifier_sortie(sortie)
    assert sortie["exposed"] is True and sortie["count"] == 3
    assert {(p["address"], p["kind"]) for p in sortie["private_addresses"]} == {
        ("10.1.2.3", "private"),
        ("fd12:3456::1", "private"),
        ("::ffff:192.168.0.9", "private"),
    }
    constat = _regle().check(_finding(sortie))
    assert constat[0].severity == "medium" and constat[0].params["host"] == "example.com"
    assert SPEC.score_rules[0].evaluate({"dns_rebinding": sortie}).points == 0


def test_bouclage_gravite_faible(contexte, outils, dns_simule):
    dns_simule({("example.com", "A"): [outils.rdata("A", "127.0.0.1")]})
    sortie = outils.executer(SPEC, contexte())
    assert _regle().check(_finding(sortie))[0].severity == "low"


def test_messagerie_interne_publiee(contexte, outils, dns_simule):
    dns_simule(
        {
            ("example.com", "A"): [outils.rdata("A", "93.184.216.34")],
            ("example.com", "MX"): [outils.rdata("MX", "10 mx.example.com.")],
            ("mx.example.com", "A"): [outils.rdata("A", "172.16.4.2")],
        }
    )
    sortie = outils.executer(SPEC, contexte())
    assert [h["host"] for h in sortie["hosts"]] == ["example.com", "mx.example.com"]
    assert sortie["private_addresses"] == [
        {"host": "mx.example.com", "address": "172.16.4.2", "kind": "private"}
    ]


def test_plages_voisines_non_privees(contexte, outils, dns_simule):
    """Faux positifs évités : 172.32.x, 100.128.x et 192.169.x sont publiques."""
    dns_simule(
        {
            ("example.com", "A"): [
                outils.rdata("A", "172.32.0.1"),
                outils.rdata("A", "100.128.0.1"),
                outils.rdata("A", "192.169.0.1"),
            ]
        }
    )
    assert outils.executer(SPEC, contexte())["exposed"] is False


def test_sous_domaine_cible_et_site(contexte, outils, dns_simule):
    dns_simule(
        {
            ("app.example.com", "A"): [outils.rdata("A", "93.184.216.34")],
            ("example.com", "A"): [outils.rdata("A", "10.0.0.8")],
        }
    )
    sortie = outils.executer(SPEC, contexte(domain="app.example.com", site="example.com", apex="example.com"))
    assert [h["host"] for h in sortie["hosts"]] == ["app.example.com", "example.com"]
    assert sortie["count"] == 1


def test_requetes_en_echec(contexte, outils, dns_simule):
    dns_simule(
        {
            ("example.com", "MX"): dns.exception.Timeout,
            ("example.com", "A"): dns.exception.Timeout,
            ("example.com", "AAAA"): dns.exception.Timeout,
        }
    )
    with pytest.raises(ModuleError) as erreur:
        outils.executer(SPEC, contexte())
    assert erreur.value.message["$t"] == "dns_rebinding.query_failed"


def test_donnees_inattendues_ne_levent_pas():
    for data in (None, [], "x", {"hosts": "oops"}, {"hosts": [None, {"private": [None, 3]}]}):
        _regle().check(_finding(data))
    assert SPEC.score_rules[0].evaluate({"dns_rebinding": None}).points == 3


def test_adresse_ip_sans_objet(contexte):
    assert SPEC.skip_reason(contexte(domain="93.184.216.34")) is not None
