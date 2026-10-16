# =============================================================================
# DomainRecon - Tests du module « subdomain_bruteforce » (sans réseau)
# =============================================================================

import dns.exception
import dns.resolver
import pytest

from domainrecon.scanner import dns as scanner_dns
from domainrecon.scanner.errors import ModuleError
from domainrecon.scanner.impl import dns_tools, subdomain_bruteforce, subdomain_wordlist
from domainrecon.scanner.modules import subdomain_bruteforce as module
from domainrecon.scanner.rules import FindingInput

SPEC = module.SPEC


def _finding(data):
    return FindingInput({}, "subdomain_bruteforce", lambda scan, name: data, lambda scan, name: True)


def _regle(code):
    return next(rule for rule in SPEC.findings if rule.code == code)


def test_liste_de_mots():
    mots = subdomain_wordlist.WORDS
    assert len(mots) == len(set(mots)) >= 749
    assert subdomain_wordlist.BASE_COUNT == 746
    assert all(m == m.lower() and 0 < len(m) <= 63 for m in mots)
    assert {"www", "vpn", "jenkins", "staging", "autodiscover"} <= set(mots)


def test_noms_derives_du_domaine_ont_le_suffixe():
    """Défaut historique : les dix noms dérivés (api-<nom>, <nom>-dev…) n'avaient pas le suffixe du domaine."""
    noms = subdomain_bruteforce.candidates("example.com")
    assert "api-example.example.com" in noms and "example-dev.example.com" in noms
    assert all(n.endswith(".example.com") for n in noms) and len(noms) == len(set(noms))


def test_succes_et_adresses_non_publiques(contexte, outils, dns_simule):
    dns_simule(
        {
            ("www.example.com", "A"): [outils.rdata("A", "93.184.216.34")],
            ("vpn.example.com", "A"): [
                outils.rdata("A", "93.184.216.35"),
                outils.rdata("A", "93.184.216.36"),
            ],
            ("jenkins.example.com", "A"): [outils.rdata("A", "10.0.0.5")],
            ("home.example.com", "A"): [outils.rdata("A", "127.0.0.1")],
            ("blog.example.com", "A"): [outils.rdata("A", "93.184.216.40")],
            ("blog.example.com", "CNAME"): [outils.rdata("CNAME", "web.example.com.")],
        }
    )
    sortie = outils.executer(SPEC, contexte())
    outils.verifier_sortie(sortie)
    trouves = {e["subdomain"]: e for e in sortie["subdomains_found"]}
    assert set(trouves) == {
        "www.example.com",
        "vpn.example.com",
        "jenkins.example.com",
        "home.example.com",
        "blog.example.com",
    }
    assert trouves["vpn.example.com"]["ips"] == ["93.184.216.35", "93.184.216.36"]
    assert trouves["jenkins.example.com"]["private"] == ["private"]
    assert trouves["home.example.com"]["private"] == ["loopback"]
    assert trouves["blog.example.com"]["cname"] == "web.example.com"
    assert sortie["count"] == 5 and sortie["wildcard_detected"] is False and sortie["incomplete"] is False
    assert sortie["tested"] == sortie["wordlist_size"] >= 749
    # Constats : outil interne exposé, adresses internes publiées.
    sensible = _regle("finding.subdomain_bruteforce.sensitive").check(_finding(sortie))
    assert sensible[0].params["count"] == 1 and sensible[0].params["names"] == ["jenkins.example.com"]
    prive = _regle("finding.subdomain_bruteforce.private_ip").check(_finding(sortie))
    assert prive[0].params["count"] == 2


def test_rien_trouve(contexte, outils, dns_simule):
    dns_simule({})
    sortie = outils.executer(SPEC, contexte())
    outils.verifier_sortie(sortie)
    assert sortie["subdomains_found"] == [] and sortie["count"] == 0
    assert _regle("finding.subdomain_bruteforce.sensitive").check(_finding(sortie)) is None
    assert _regle("finding.subdomain_bruteforce.private_ip").check(_finding(sortie)) is None


class Joker:
    """Résolveur simulé avec joker : tout nom sous example.com résout vers 198.51.100.7 (sauf exceptions)."""

    timeout = None
    lifetime = None

    def __init__(self, outils, exceptions=None):
        self.outils = outils
        self.exceptions = exceptions or {}

    def resolve(self, qname, rdtype, lifetime=None, **kwargs):
        name = str(qname).rstrip(".").lower()
        if rdtype == "A" and name in self.exceptions:
            return [self.outils.rdata("A", ip) for ip in self.exceptions[name]]
        if rdtype == "A" and name.endswith(".example.com"):
            return [self.outils.rdata("A", "198.51.100.7")]
        if rdtype == "CNAME" and name.endswith(".example.com"):
            raise dns.resolver.NoAnswer
        raise dns.resolver.NXDOMAIN


def test_joker_dns_reponses_ecartees_sans_faux_positifs(contexte, outils, monkeypatch):
    """Sous un joker, la liste entière « résout » : seules les réponses différentes du joker comptent."""
    monkeypatch.setattr(
        scanner_dns, "_make_resolver", lambda: Joker(outils, {"vpn.example.com": ["93.184.216.35"]})
    )
    sortie = outils.executer(SPEC, contexte())
    assert sortie["wildcard_detected"] is True and sortie["wildcard_addresses"] == ["198.51.100.7"]
    assert [e["subdomain"] for e in sortie["subdomains_found"]] == ["vpn.example.com"]
    assert sortie["wildcard_filtered"] >= 749


def test_resolveur_muet_echec_propre(contexte, outils, monkeypatch):
    class Muet:
        timeout = None
        lifetime = None

        def resolve(self, *args, **kwargs):
            raise dns.exception.Timeout

    monkeypatch.setattr(scanner_dns, "_make_resolver", lambda: Muet())
    with pytest.raises(ModuleError) as erreur:
        outils.executer(SPEC, contexte())
    assert erreur.value.message["$t"] == "subdomain_bruteforce.resolver_failed"


def test_donnees_inattendues_ne_levent_pas():
    for data in (
        None,
        [],
        "x",
        {"subdomains_found": "oops"},
        {"subdomains_found": [None, 3, {"subdomain": 5}]},
    ):
        for regle in SPEC.findings:
            regle.check(_finding(data))


def test_classement_des_adresses():
    assert dns_tools.classify_address("10.1.2.3") == "private"
    assert dns_tools.classify_address("172.20.0.1") == "private"
    assert dns_tools.classify_address("192.168.1.1") == "private"
    assert dns_tools.classify_address("127.0.0.1") == "loopback"
    assert dns_tools.classify_address("::1") == "loopback"
    assert dns_tools.classify_address("169.254.1.1") == "link_local"
    assert dns_tools.classify_address("100.64.0.1") == "shared"
    assert dns_tools.classify_address("fd00::1") == "private"
    assert dns_tools.classify_address("::ffff:10.0.0.1") == "private"
    assert dns_tools.classify_address("8.8.8.8") is None
    assert dns_tools.classify_address("2606:4700::1") is None
    assert dns_tools.classify_address("pas une adresse") is None


def test_adresse_ip_sans_objet_et_declaration(contexte):
    assert SPEC.skip_reason(contexte(domain="93.184.216.34")) is not None
    assert SPEC.category == "actif" and SPEC.requires_authorization and SPEC.wave == 2
