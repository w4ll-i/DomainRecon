# =============================================================================
# DomainRecon - Tests du module « dnsbl » (sans réseau : résolveur DNS simulé)
# =============================================================================

import dns.exception
import pytest

from domainrecon.scanner.errors import ModuleError, ModuleSkipped
from domainrecon.scanner.modules import dnsbl
from domainrecon.scanner.rules import FindingInput

SPEC = dnsbl.SPEC
INVERSE = "34.216.184.93"
MAIL_IP = "52.1.2.25"
MAIL_INVERSE = "25.2.1.52"


@pytest.fixture(autouse=True)
def _etat_vide():
    dnsbl.clear_state()
    yield
    dnsbl.clear_state()


@pytest.fixture
def zone_vivante(outils):
    """Zone de base : chaque zone répond à son point de test, rien n'est listé."""

    def build():
        zone = {}
        for z in dnsbl.ZONES:
            code = "127.0.0.17" if z.kind == dnsbl.KIND_WHITELIST else "127.0.0.2"
            zone[(f"{dnsbl.IP_TEST_POINT}.{z.name}", "A")] = [outils.rdata("A", code)]
        for z in dnsbl.DOMAIN_ZONES:
            code = "127.0.1.2" if z.name.startswith("dbl") else "127.0.0.254"
            zone[(f"{z.canary}.{z.name}", "A")] = [outils.rdata("A", code)]
        return zone

    return build


def _a(outils, code):
    return [outils.rdata("A", code)]


def _lancer(contexte, outils, dns_simule, zone, **champs):
    dns_simule(zone)
    return outils.executer(SPEC, contexte(**champs))


def test_propre(contexte, outils, dns_simule, zone_vivante):
    sortie = _lancer(contexte, outils, dns_simule, zone_vivante())
    outils.verifier_sortie(sortie)
    assert sortie["listed_count"] == 0 and sortie["severity"] == "clean"
    assert sortie["checked_count"] == len(dnsbl.ZONES) and sortie["refused_zones"] == []
    assert sortie["domain"]["checked"] == len(dnsbl.DOMAIN_ZONES) and sortie["mail"] == []
    assert SPEC.score_rules[0].evaluate({"dnsbl": sortie}).points == 5


def test_adresse_listee(contexte, outils, dns_simule, zone_vivante):
    zone = zone_vivante()
    zone[(f"{INVERSE}.bl.spamcop.net", "A")] = _a(outils, "127.0.0.2")
    zone[(f"{INVERSE}.dnsbl.kempt.net", "A")] = _a(outils, "127.0.0.2")
    sortie = _lancer(contexte, outils, dns_simule, zone)
    assert sortie["listed_count"] == 2 and sortie["severity"] == "medium"
    assert {entree["dnsbl"] for entree in sortie["listings"]} == {"bl.spamcop.net", "dnsbl.kempt.net"}
    assert sortie["listings"][0]["response"] == "127.0.0.2"
    assert SPEC.score_rules[0].evaluate({"dnsbl": sortie}).points == 1


def test_refus_des_resolveurs_publics_n_est_pas_un_listage(contexte, outils, dns_simule, zone_vivante):
    """Cloudflare répond 127.255.255.254 à toute requête Spamhaus : refus, ni « listé » ni « propre »."""
    zone = zone_vivante()
    for nom in (f"{dnsbl.IP_TEST_POINT}.zen.spamhaus.org", f"{INVERSE}.zen.spamhaus.org"):
        zone[(nom, "A")] = _a(outils, "127.255.255.254")
    zone[("dbltest.com.dbl.spamhaus.org", "A")] = _a(outils, "127.255.255.254")
    zone[("example.com.dbl.spamhaus.org", "A")] = _a(outils, "127.255.255.254")
    sortie = _lancer(contexte, outils, dns_simule, zone)
    assert sortie["listed_count"] == 0 and sortie["domain_listed_count"] == 0
    assert sortie["refused_zones"] == ["dbl.spamhaus.org", "zen.spamhaus.org"]
    assert sortie["checked_count"] == len(dnsbl.ZONES) - 1


def test_refus_silencieux_nxdomain_sans_point_de_test(contexte, outils, dns_simule, zone_vivante):
    """Résolveur d'entreprise : Spamhaus répond NXDOMAIN à tout, point de test compris -> zone inexploitable."""
    zone = zone_vivante()
    del zone[(f"{dnsbl.IP_TEST_POINT}.zen.spamhaus.org", "A")]
    sortie = _lancer(contexte, outils, dns_simule, zone)
    assert "zen.spamhaus.org" in sortie["refused_zones"] and sortie["listed_count"] == 0


def test_listages_collateraux_non_comptes(contexte, outils, dns_simule, zone_vivante):
    zone = zone_vivante()
    zone[(f"{INVERSE}.dnsbl-3.uceprotect.net", "A")] = _a(outils, "127.0.0.2")
    zone[(f"{INVERSE}.zen.spamhaus.org", "A")] = _a(outils, "127.0.0.10")
    sortie = _lancer(contexte, outils, dns_simule, zone)
    assert sortie["listed_count"] == 0 and sortie["collateral_count"] == 2
    resultat = SPEC.score_rules[0].evaluate({"dnsbl": sortie})
    assert resultat.points == 4
    assert SPEC.findings[0].check(_entree(sortie)) == []


def test_codes_mailspike_et_liste_blanche(contexte, outils, dns_simule, zone_vivante):
    zone = zone_vivante()
    zone[(f"{INVERSE}.bl.mailspike.net", "A")] = _a(outils, "127.0.0.14")
    zone[(f"{INVERSE}.wl.mailspike.net", "A")] = _a(outils, "127.0.0.18")
    sortie = _lancer(contexte, outils, dns_simule, zone)
    assert sortie["listed_count"] == 0 and sortie["whitelisted"] is True
    zone[(f"{INVERSE}.bl.mailspike.net", "A")] = _a(outils, "127.0.0.11")
    dnsbl.clear_state()
    assert _lancer(contexte, outils, dns_simule, zone)["listed_count"] == 1


def test_serveur_de_messagerie_liste(contexte, outils, dns_simule, zone_vivante):
    zone = zone_vivante()
    zone[("example.com", "MX")] = [outils.rdata("MX", "10 mail.example.com.")]
    zone[("mail.example.com", "A")] = _a(outils, MAIL_IP)
    zone[(f"{MAIL_INVERSE}.b.barracudacentral.org", "A")] = _a(outils, "127.0.0.2")
    sortie = _lancer(contexte, outils, dns_simule, zone)
    assert sortie["listed_count"] == 0 and sortie["mail_listed_count"] == 1
    assert sortie["mail"][0]["host"] == "mail.example.com" and sortie["mail"][0]["ip"] == MAIL_IP
    constats = SPEC.findings[1].check(_entree(sortie))
    assert constats == [
        {"host": "mail.example.com", "ip": MAIL_IP, "count": 1, "zones": "b.barracudacentral.org"}
    ]


def test_domaine_liste_hameconnage(contexte, outils, dns_simule, zone_vivante):
    zone = zone_vivante()
    zone[("example.com.dbl.spamhaus.org", "A")] = _a(outils, "127.0.1.4")
    sortie = _lancer(contexte, outils, dns_simule, zone)
    assert sortie["domain_listed_count"] == 1 and sortie["domain"]["listings"][0]["category"] == "phishing"
    assert SPEC.findings[2].check(_entree(sortie)).severity == "critical"
    assert SPEC.score_rules[0].evaluate({"dnsbl": sortie}).points == 0


def test_resolveur_qui_reecrit_les_nxdomain(contexte, outils, dns_simule, zone_vivante):
    """Un résolveur qui renvoie une IP publique pour tout nom ne doit rien faire « lister »."""
    zone = {}
    for z in (*dnsbl.ZONES, *dnsbl.DOMAIN_ZONES):
        zone[(f"{dnsbl.IP_TEST_POINT}.{z.name}", "A")] = _a(outils, "203.0.113.9")
        zone[(f"{INVERSE}.{z.name}", "A")] = _a(outils, "203.0.113.9")
    with pytest.raises(ModuleError) as erreur:
        _lancer(contexte, outils, dns_simule, zone)
    assert erreur.value.message["$t"] == "dnsbl.no_usable_zone"


def test_hors_ligne_nxdomain_partout(contexte, outils, dns_simule):
    with pytest.raises(ModuleError) as erreur:
        _lancer(contexte, outils, dns_simule, {})
    assert erreur.value.message["$t"] == "dnsbl.no_usable_zone"


def test_delai_depasse_partout(contexte, outils, dns_simule):
    zone = {}
    for z in (*dnsbl.ZONES, *dnsbl.DOMAIN_ZONES):
        for nom in (
            f"{dnsbl.IP_TEST_POINT}.{z.name}",
            f"{INVERSE}.{z.name}",
            f"{z.canary}.{z.name}",
            f"example.com.{z.name}",
        ):
            zone[(nom, "A")] = dns.exception.Timeout
    with pytest.raises(ModuleError) as erreur:
        _lancer(contexte, outils, dns_simule, zone)
    assert erreur.value.message["$t"] == "dnsbl.unreachable"


def test_zone_en_delai_n_est_pas_comptee_propre(contexte, outils, dns_simule, zone_vivante):
    zone = zone_vivante()
    zone[(f"{INVERSE}.psbl.surriel.com", "A")] = dns.exception.Timeout
    sortie = _lancer(contexte, outils, dns_simule, zone)
    assert sortie["failed_zones"] == ["psbl.surriel.com"] and sortie["checked_count"] == len(dnsbl.ZONES) - 1


def test_cible_ip_sans_domaine_ni_mx(contexte, outils, dns_simule, zone_vivante):
    resolveur = dns_simule(zone_vivante())
    resultat = outils.executer(SPEC, contexte(domain="93.184.216.34"))
    assert resultat["domain"] is None and resultat["listed_count"] == 0
    assert not any(type_ == "MX" for _, type_ in resolveur.queries)


def test_sans_ipv4_sans_objet(contexte):
    assert SPEC.skip_reason(contexte(addresses=["2606:2800:220:1::1"])) is not None
    assert SPEC.skip_reason(contexte(addresses=["10.0.0.5"])) is not None
    assert SPEC.skip_reason(contexte()) is None


def test_run_sans_ipv4_leve_sans_objet(contexte, outils, dns_simule):
    dns_simule({})
    with pytest.raises(ModuleSkipped):
        outils.executer(SPEC, contexte(addresses=["2606:2800:220:1::1"]))


def test_classify():
    zen = dnsbl.ZONES[0]
    assert dnsbl.classify(zen, ["127.0.0.2"]) == ("listed", "spam")
    assert dnsbl.classify(zen, ["127.0.0.4"]) == ("listed", "exploits")
    assert dnsbl.classify(zen, ["127.0.0.10", "127.0.0.11"]) == ("info", "policy")
    assert dnsbl.classify(zen, ["127.255.255.252"])[0] == "refused"
    assert dnsbl.classify(zen, ["8.8.8.8"])[0] == "invalid"
    assert dnsbl.classify(zen, ["pas une ip"])[0] == "invalid"
    surbl = dnsbl.DOMAIN_ZONES[1]
    assert dnsbl.classify(surbl, ["127.0.0.8"]) == ("listed", "phishing")
    assert dnsbl.classify(surbl, ["127.0.0.16"]) == ("listed", "malware")
    assert dnsbl.classify(surbl, ["127.0.0.254"])[0] == "none"
    assert dnsbl.classify(surbl, ["127.0.0.1"])[0] == "refused"


def test_declaration():
    assert SPEC.keys == () and SPEC.category == "passif" and SPEC.verdict is True
    noms = [z.name for z in (*dnsbl.ZONES, *dnsbl.DOMAIN_ZONES)]
    assert len(noms) == len(set(noms))
    # Zones retirées : mortes, hors sujet ou source de faux positifs.
    for morte in (
        "dnsbl.sorbs.net",
        "cbl.abuseat.org",
        "korea.services.net",
        "all.s5h.net",
        "dnsbl.spfbl.net",
    ):
        assert morte not in noms
    # dbl.spamhaus.org n'est interrogé qu'avec des domaines.
    assert "dbl.spamhaus.org" not in [z.name for z in dnsbl.ZONES]


def _entree(donnees):
    scan = {"modules": {"dnsbl": {"data": donnees}}}
    return FindingInput(scan, "dnsbl", lambda s, m: s["modules"][m]["data"], lambda s, m: True)


def test_constats_defensifs():
    for regle in SPEC.findings:
        assert not regle.check(_entree("illisible")) and not regle.check(_entree(None))
    mineur = {"web": [{"ip": "1.2.3.4", "listings": [{"dnsbl": "dnsbl.kempt.net", "major": False}]}]}
    assert SPEC.findings[0].check(_entree(mineur))[0].severity == "medium"
    majeur = {"web": [{"ip": "1.2.3.4", "listings": [{"dnsbl": "bl.spamcop.net", "major": True}]}]}
    assert SPEC.findings[0].check(_entree(majeur))[0].severity == "high"
