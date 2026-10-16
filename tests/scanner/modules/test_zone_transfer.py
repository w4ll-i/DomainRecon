# =============================================================================
# DomainRecon - Tests du module « zone_transfer » (sans réseau)
# =============================================================================

import dns.exception
import dns.message
import dns.rcode
import dns.xfr
import pytest

from domainrecon.scanner.errors import ModuleError, ModuleSkipped
from domainrecon.scanner.impl import zone_transfer as engine
from domainrecon.scanner.modules import zone_transfer
from domainrecon.scanner.rules import FindingInput

SPEC = zone_transfer.SPEC
NS1, NS2 = "8.8.8.8", "1.1.1.1"

SOA = "example.com. 300 IN SOA ns1.example.com. admin.example.com. 1 7200 900 1209600 300"
MESSAGE = f"""id 1
opcode QUERY
rcode NOERROR
flags QR AA
;QUESTION
example.com. IN AXFR
;ANSWER
{SOA}
example.com. 300 IN NS ns1.example.com.
www.example.com. 300 IN A 93.184.216.34
www.example.com. 300 IN A 93.184.216.35
internal.example.com. 300 IN A 10.0.0.9
mail.example.com. 300 IN MX 10 mx.example.com.
{SOA}
"""


def _zone(outils, ns=None):
    ns = ns or {"ns1.example.com": NS1, "ns2.example.com": NS2}
    zone = {("example.com", "NS"): [outils.rdata("NS", f"{name}.") for name in ns]}
    for name, address in ns.items():
        zone[(name, "A")] = [outils.rdata("A", address)]
    return zone


def _transfert(par_adresse):
    """Remplace dns.query.xfr : chaque adresse a son comportement (messages, exception ou classe d'exception)."""

    def xfr(address, zone, **kwargs):
        action = par_adresse[address]
        if isinstance(action, BaseException):
            raise action
        yield dns.message.from_text(action)

    return xfr


def _finding(data):
    return FindingInput({}, "zone_transfer", lambda scan, name: data, lambda scan, name: True)


def test_transfert_ouvert_detecte(contexte, outils, dns_simule, monkeypatch):
    """Le serveur est interrogé par son ADRESSE (par son nom, rien ne serait jamais détecté)."""
    dns_simule(_zone(outils))
    monkeypatch.setattr(
        engine, "_xfr", _transfert({NS1: MESSAGE, NS2: dns.xfr.TransferError(dns.rcode.REFUSED)})
    )
    sortie = outils.executer(SPEC, contexte())
    outils.verifier_sortie(sortie)
    assert sortie["vulnerable"] is True and sortie["vulnerable_servers"] == ["ns1.example.com"]
    etats = {s["nameserver"]: s["status"] for s in sortie["servers"]}
    assert etats == {"ns1.example.com": "transferred", "ns2.example.com": "refused"}
    assert (
        sortie["record_count"] == 6
        and sortie["record_types"]["A"] == 3
        and sortie["record_types"]["SOA"] == 1
    )
    assert sortie["names"] == ["example.com", "internal.example.com", "mail.example.com", "www.example.com"]
    assert {"name": "internal.example.com", "type": "A", "ttl": 300, "value": "10.0.0.9"} in sortie["records"]
    constat = SPEC.findings[0].check(_finding(sortie))
    assert constat[0].params["servers"] == ["ns1.example.com"] and constat[0].params["count"] == 6
    assert SPEC.score_rules[0].evaluate({"zone_transfer": sortie}).points == 0


def test_transfert_refuse_partout(contexte, outils, dns_simule, monkeypatch):
    dns_simule(_zone(outils))
    refus = dns.xfr.TransferError(dns.rcode.REFUSED)
    monkeypatch.setattr(engine, "_xfr", _transfert({NS1: refus, NS2: dns.exception.FormError()}))
    sortie = outils.executer(SPEC, contexte())
    assert sortie["vulnerable"] is False and sortie["attempted"] == ["ns1.example.com", "ns2.example.com"]
    assert [s["status"] for s in sortie["servers"]] == ["refused", "refused"]
    assert SPEC.findings[0].check(_finding(sortie)) is None
    resultat = SPEC.score_rules[0].evaluate({"zone_transfer": sortie})
    assert resultat.points == 10 and resultat.measured is True


def test_delai_depasse_sur_un_serveur_l_autre_repond(contexte, outils, dns_simule, monkeypatch):
    dns_simule(_zone(outils))
    monkeypatch.setattr(
        engine,
        "_xfr",
        _transfert({NS1: dns.exception.Timeout(), NS2: dns.xfr.TransferError(dns.rcode.REFUSED)}),
    )
    sortie = outils.executer(SPEC, contexte())
    assert {s["status"] for s in sortie["servers"]} == {"timeout", "refused"} and sortie[
        "vulnerable"
    ] is False


def test_aucun_serveur_joignable_echec(contexte, outils, dns_simule, monkeypatch):
    dns_simule(_zone(outils))
    monkeypatch.setattr(
        engine, "_xfr", _transfert({NS1: ConnectionRefusedError(), NS2: dns.exception.Timeout()})
    )
    with pytest.raises(ModuleError) as erreur:
        outils.executer(SPEC, contexte())
    assert erreur.value.message["$t"] == "zone_transfer.unreachable"


def test_reponse_vide_n_est_pas_un_transfert(contexte, outils, dns_simule, monkeypatch):
    """Faux positif évité : une réponse sans SOA en tête n'est pas un transfert de zone."""
    dns_simule(_zone(outils, {"ns1.example.com": NS1}))
    vide = "id 1\nopcode QUERY\nrcode NOERROR\nflags QR AA\n;QUESTION\nexample.com. IN AXFR\n"
    monkeypatch.setattr(engine, "_xfr", _transfert({NS1: vide}))
    sortie = outils.executer(SPEC, contexte())
    assert sortie["vulnerable"] is False and sortie["servers"][0]["status"] == "refused"


def test_serveur_a_adresse_privee_jamais_contacte(contexte, outils, dns_simule, monkeypatch):
    dns_simule(_zone(outils, {"ns1.example.com": "10.0.0.1"}))

    def jamais(*args, **kwargs):
        raise AssertionError("connexion à une adresse privée")

    monkeypatch.setattr(engine, "_xfr", jamais)
    with pytest.raises(ModuleError):
        outils.executer(SPEC, contexte())


def test_aucun_serveur_de_noms_sans_objet(contexte, outils, dns_simule):
    dns_simule({})
    with pytest.raises(ModuleSkipped):
        outils.executer(SPEC, contexte())


def test_donnees_inattendues_ne_levent_pas():
    for data in (None, [], "x", {"vulnerable": True}, {"vulnerable": True, "vulnerable_servers": 5}):
        SPEC.findings[0].check(_finding(data))
    assert SPEC.score_rules[0].evaluate({"zone_transfer": None}).points == 10


def test_declaration(contexte):
    assert SPEC.category == "actif" and SPEC.requires_authorization
    assert SPEC.skip_reason(contexte(domain="93.184.216.34")) is not None
