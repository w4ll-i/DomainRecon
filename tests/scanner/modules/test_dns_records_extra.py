# =============================================================================
# DomainRecon - Tests du module « dns_records_extra » : CAA, SRV, TLSA (sans réseau)
# =============================================================================

import dns.exception
import pytest

from domainrecon.scanner.errors import ModuleError
from domainrecon.scanner.impl import dns_extra
from domainrecon.scanner.modules import dns_records_extra
from domainrecon.scanner.rules import FindingInput

SPEC = dns_records_extra.SPEC
HASH = "ab" * 32


def _finding(data):
    return FindingInput({}, "dns_records_extra", lambda scan, name: data, lambda scan, name: True)


def _caa_missing(data):
    return SPEC.findings[0].check(_finding(data))


def test_caa_srv_tlsa_releves(contexte, outils, dns_simule):
    dns_simule(
        {
            ("example.com", "MX"): [outils.rdata("MX", "10 mx.example.com.")],
            ("example.com", "CAA"): [
                outils.rdata("CAA", '0 issue "letsencrypt.org"'),
                outils.rdata("CAA", '0 iodef "mailto:sec@example.com"'),
            ],
            ("_sip._tcp.example.com", "SRV"): [outils.rdata("SRV", "10 5 5060 sip.example.com.")],
            ("_443._tcp.example.com", "TLSA"): [outils.rdata("TLSA", f"3 1 1 {HASH}")],
            ("_25._tcp.mx.example.com", "TLSA"): [outils.rdata("TLSA", f"3 1 1 {HASH}")],
        }
    )
    sortie = outils.executer(SPEC, contexte())
    outils.verifier_sortie(sortie)
    assert sortie["CAA"] == [
        {"flags": 0, "tag": "iodef", "value": "mailto:sec@example.com"},
        {"flags": 0, "tag": "issue", "value": "letsencrypt.org"},
    ]
    assert sortie["caa_source"] == "example.com" and sortie["caa_issuers"] == ["letsencrypt.org"]
    assert sortie["SRV"] == [
        {
            "name": "_sip._tcp.example.com",
            "priority": 10,
            "weight": 5,
            "port": 5060,
            "target": "sip.example.com",
        }
    ]
    assert [t["name"] for t in sortie["TLSA"]] == ["_443._tcp.example.com", "_25._tcp.mx.example.com"]
    assert sortie["TLSA"][0]["usage_name"] == "DANE-EE" and sortie["TLSA"][0]["data"] == HASH
    assert sortie["errors"] == {} and sortie["domain_exists"] is True
    assert not _caa_missing(sortie)  # un CAA présent : pas de constat


def test_caa_cherche_en_remontant_au_domaine_organisationnel(contexte, outils, dns_simule):
    dns_simule({("example.com", "CAA"): [outils.rdata("CAA", '0 issue "pki.goog"')]})
    sortie = outils.executer(SPEC, contexte(domain="www.example.com", apex="example.com"))
    assert sortie["caa_source"] == "example.com" and sortie["caa_issuers"] == ["pki.goog"]
    assert sortie["domain_exists"] is False  # www.example.com lui-même n'existe pas : pas de constat
    assert not _caa_missing(sortie)


def test_aucun_caa_donne_un_constat(contexte, outils, dns_simule):
    dns_simule(
        {
            ("example.com", "A"): [outils.rdata("A", "93.184.216.34")],
            ("example.com", "CAA"): dns.resolver.NoAnswer,
        }
    )
    sortie = outils.executer(SPEC, contexte())
    assert (
        sortie["CAA"] == []
        and sortie["SRV"] == []
        and sortie["TLSA"] == []
        and sortie["domain_exists"] is True
    )
    assert _caa_missing(sortie) is True


def test_faux_positif_evite_caa_non_mesure(contexte, outils, dns_simule):
    """Une requête CAA en échec (délai) ne prouve pas l'absence de CAA : pas de constat."""
    dns_simule({("example.com", "CAA"): dns.exception.Timeout})
    sortie = outils.executer(SPEC, contexte())
    assert "CAA" in sortie["errors"] and sortie["measured"] is True
    assert not _caa_missing(sortie)


def test_domaine_inexistant_pas_de_constat(contexte, outils, dns_simule):
    dns_simule({})
    sortie = outils.executer(SPEC, contexte())
    assert sortie["domain_exists"] is False and not _caa_missing(sortie)


def test_toutes_les_requetes_en_echec(contexte, outils, monkeypatch):
    from domainrecon.scanner import dns as scanner_dns

    class Panne:
        timeout = None
        lifetime = None

        def resolve(self, *args, **kwargs):
            raise dns.exception.Timeout

    monkeypatch.setattr(scanner_dns, "_make_resolver", lambda: Panne())
    with pytest.raises(ModuleError) as erreur:
        outils.executer(SPEC, contexte())
    assert erreur.value.message["$t"] == "dns_records_extra.query_failed"


def test_donnee_inattendue_ne_leve_pas():
    for data in (None, [], "texte", {"CAA": "oops"}, {"domain_exists": True, "CAA": "oops", "errors": []}):
        _caa_missing(data)


def test_noms_caa_remontent_sans_depasser_le_domaine_organisationnel():
    assert dns_extra.caa_names("a.b.example.com") == ["a.b.example.com", "b.example.com", "example.com"]
    assert dns_extra.caa_names("example.com") == ["example.com"]


def test_services_srv_sont_des_noms_de_service():
    assert all(name.startswith("_") and name.count(".") == 1 for name in dns_extra.SRV_SERVICES)


def test_adresse_ip_sans_objet(contexte):
    assert SPEC.skip_reason(contexte(domain="93.184.216.34")) is not None
