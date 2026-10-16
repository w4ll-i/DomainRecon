# =============================================================================
# DomainRecon - Tests du module « wildcard_dns » (sans réseau)
# =============================================================================

import dns.exception
import dns.resolver
import pytest

from domainrecon.scanner import dns as scanner_dns
from domainrecon.scanner.errors import ModuleError
from domainrecon.scanner.modules import wildcard_dns
from domainrecon.scanner.rules import FindingInput

SPEC = wildcard_dns.SPEC


class Joker:
    """Résolveur simulé : un joker sous example.com. `positives` : réponses successives (True : résout)."""

    timeout = None
    lifetime = None

    def __init__(self, outils, *, cname=None, profondeur=True, positives=None):
        self.outils = outils
        self.cname = cname
        self.profondeur = profondeur
        self.positives = list(positives) if positives is not None else None
        self.rang = 0

    def resolve(self, qname, rdtype, lifetime=None, **kwargs):
        name = str(qname).rstrip(".").lower()
        if not name.endswith(".example.com") or not name.startswith("dr-"):
            raise dns.resolver.NXDOMAIN
        if self.positives is not None and rdtype == "A":
            positif = self.positives[self.rang % len(self.positives)]
            self.rang += 1
            if not positif:
                raise dns.resolver.NXDOMAIN
        if not self.profondeur and name.count(".") > 2:
            raise dns.resolver.NXDOMAIN
        if rdtype == "A":
            return [self.outils.rdata("A", "198.51.100.7" if name.count(".") == 2 else "198.51.100.8")]
        if rdtype == "CNAME" and self.cname:
            return [self.outils.rdata("CNAME", self.cname)]
        if rdtype == "CNAME":
            raise dns.resolver.NoAnswer
        raise dns.resolver.NoAnswer


def _installer(monkeypatch, resolveur):
    monkeypatch.setattr(scanner_dns, "_make_resolver", lambda: resolveur)


def _finding(data):
    return FindingInput({}, "wildcard_dns", lambda scan, name: data, lambda scan, name: True)


def test_joker_detecte(contexte, outils, monkeypatch):
    _installer(monkeypatch, Joker(outils))
    sortie = outils.executer(SPEC, contexte())
    outils.verifier_sortie(sortie)
    assert sortie["wildcard"] is True and sortie["intermittent"] is False
    assert sortie["addresses"] == ["198.51.100.7", "198.51.100.8"] and sortie["deep"] is True
    assert sortie["probes"] == 3 and sortie["positives"] == 3 and len(sortie["test_names"]) == 4
    assert SPEC.findings[0].check(_finding(sortie)) is None


def test_joker_a_un_seul_niveau(contexte, outils, monkeypatch):
    _installer(monkeypatch, Joker(outils, profondeur=False))
    sortie = outils.executer(SPEC, contexte())
    assert sortie["wildcard"] is True and sortie["deep"] is False


def test_pas_de_joker(contexte, outils, dns_simule):
    dns_simule({})
    sortie = outils.executer(SPEC, contexte())
    outils.verifier_sortie(sortie)
    assert sortie["wildcard"] is False and sortie["addresses"] == [] and sortie["deep"] is None
    assert sortie["probes"] == 3 and sortie["positives"] == 0


def test_reponses_intermittentes(contexte, outils, monkeypatch):
    """Une seule sonde sur trois résout : joker partiel ou instable, signalé comme tel."""
    _installer(monkeypatch, Joker(outils, positives=[True, False, False]))
    sortie = outils.executer(SPEC, contexte())
    assert sortie["wildcard"] is True and sortie["intermittent"] is True and sortie["positives"] == 1


def test_joker_vers_un_service_tiers_donne_un_constat(contexte, outils, monkeypatch):
    _installer(monkeypatch, Joker(outils, cname="monsite.github.io."))
    sortie = outils.executer(SPEC, contexte())
    assert sortie["cname"] == "monsite.github.io" and sortie["cname_external"] is True
    assert SPEC.findings[0].check(_finding(sortie)) == {"zone": "example.com", "cname": "monsite.github.io"}


def test_joker_vers_le_meme_site_sans_constat(contexte, outils, monkeypatch):
    """Faux positif évité : un joker dont le CNAME reste dans le site n'ouvre aucun service tiers."""
    _installer(monkeypatch, Joker(outils, cname="origine.example.com."))
    sortie = outils.executer(SPEC, contexte())
    assert sortie["cname_external"] is False and SPEC.findings[0].check(_finding(sortie)) is None


def test_requetes_toutes_en_echec(contexte, outils, monkeypatch):
    class Panne:
        timeout = None
        lifetime = None

        def resolve(self, *args, **kwargs):
            raise dns.exception.Timeout

    _installer(monkeypatch, Panne())
    with pytest.raises(ModuleError) as erreur:
        outils.executer(SPEC, contexte())
    assert erreur.value.message["$t"] == "wildcard_dns.query_failed"


def test_donnees_inattendues_ne_levent_pas():
    for data in (
        None,
        [],
        "x",
        {"wildcard": True},
        {"wildcard": True, "cname_external": True, "cname": None},
    ):
        SPEC.findings[0].check(_finding(data))


def test_adresse_ip_sans_objet(contexte):
    assert SPEC.skip_reason(contexte(domain="93.184.216.34")) is not None
