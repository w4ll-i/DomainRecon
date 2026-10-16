# =============================================================================
# DomainRecon - Tests des modules email, DNS, sous-domaines et WHOIS
# =============================================================================
# Aucun accès réseau : résolveur DNS simulé (zone en mémoire), crt.sh servi par
# httpx.MockTransport, python-whois remplacé par une fonction factice.
# =============================================================================

import asyncio
import gzip
import json
import socket
import tracemalloc
import types
from datetime import datetime

import dns.exception
import dns.rdata
import dns.rdataclass
import dns.rdatatype
import dns.resolver
import httpx
import pytest

from domainrecon.scanner import ModuleError, whois_lookup
from domainrecon.scanner import cache as scanner_cache
from domainrecon.scanner import dns as scanner_dns
from domainrecon.scanner import email_security as email
from rendu import fr

# Comportement des 18 modules historiques : registre ramené à eux (tests/conftest.py).
pytestmark = pytest.mark.usefixtures("registre_historique")

TIMEOUT = dns.exception.Timeout
SERVFAIL = dns.resolver.NoNameservers
NXDOMAIN = dns.resolver.NXDOMAIN
NOANSWER = dns.resolver.NoAnswer

DKIM_KEY = "v=DKIM1; k=rsa; p=MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQC"
DMARC_REJECT = "v=DMARC1; p=reject; rua=mailto:dmarc@example.com"


def txt(*strings: str):
    """Enregistrement TXT dnspython, éventuellement découpé en plusieurs chaînes."""
    text = " ".join('"' + s.replace('"', '\\"') + '"' for s in strings)
    return dns.rdata.from_text(dns.rdataclass.IN, dns.rdatatype.TXT, text)


def rdata(rtype: str, text: str):
    return dns.rdata.from_text(dns.rdataclass.IN, dns.rdatatype.from_text(rtype), text)


class FakeResolver:
    """Résolveur simulé : zone {(nom, type): [rdata ou texte TXT] | exception}.

    Un nom absent de la zone répond NXDOMAIN.
    """

    def __init__(self, zone: dict):
        self.zone = {(name.lower(), rtype): value for (name, rtype), value in zone.items()}
        self.queries: list[tuple[str, str]] = []
        self.timeout = None

    def resolve(self, qname, rdtype, lifetime=None, **kwargs):
        key = (str(qname).rstrip(".").lower(), rdtype)
        self.queries.append(key)
        value = self.zone.get(key, NXDOMAIN)
        if isinstance(value, type) and issubclass(value, Exception):
            raise value()
        return [txt(v) if isinstance(v, str) else v for v in value]


@pytest.fixture
def fake_dns(monkeypatch):
    """Installe un résolveur simulé pour tous les modules DNS du scanner."""

    def install(zone: dict) -> FakeResolver:
        resolver = FakeResolver(zone)
        monkeypatch.setattr(scanner_dns, "_make_resolver", lambda: resolver)
        return resolver

    return install


@pytest.fixture(autouse=True)
def no_wildcard_probe(monkeypatch):
    """Sonde du joker DNS des sous-domaines sans réseau : aucun joker, sauf mention contraire."""

    async def no_addresses(host, timeout=None):
        return []

    monkeypatch.setattr(scanner_dns, "resolve_addresses", no_addresses)


def analyze(fake_dns, zone: dict, domain: str = "example.com") -> dict:
    """Analyse email de `domain` ; sauf mention contraire, le domaine existe sans TXT."""
    fake_dns({(domain, "TXT"): NOANSWER, **zone})
    return email._analyze_email_security_sync(domain)


# =============================================================================
# SPF
# =============================================================================


@pytest.mark.parametrize(
    "record, grade, all_mechanism",
    [
        ("v=spf1 -all", "A", "-all"),
        ("v=spf1 ip4:192.0.2.0/24 ~all", "B", "~all"),
        ("v=spf1 ?all", "D", "?all"),
        # `all` sans qualificatif vaut +all (RFC 7208 §4.6.2).
        ("v=spf1 a mx all", "F", "+all"),
        ("v=spf1 +all", "F", "+all"),
        # Sans mécanisme all : résultat neutre par défaut, non protecteur.
        ("v=spf1 ip4:192.0.2.1", "D", None),
        ("V=SPF1 IP4:192.0.2.1 -ALL", "A", "-all"),
        # Les termes après all ne sont jamais évalués.
        ("v=spf1 -all +all", "A", "-all"),
        # … mais une erreur de syntaxe, même après all, est un permerror (RFC 7208 §4.6).
        ("v=spf1 -all foo:bar", "F", "-all"),
        ("v=spf1 -all include:", "F", "-all"),
    ],
)
def test_spf_note_selon_le_mecanisme_all(fake_dns, record, grade, all_mechanism):
    result = analyze(fake_dns, {("example.com", "TXT"): [record]})
    assert result["spf"]["found"] is True
    assert result["spf"]["grade"] == grade
    assert result["spf"]["all"] == all_mechanism


def test_spf_sans_all_est_signale(fake_dns):
    result = analyze(
        fake_dns,
        {
            ("example.com", "TXT"): ["v=spf1 include:_spf.example.net"],
            ("_spf.example.net", "TXT"): ["v=spf1 ip4:192.0.2.0/24 -all"],
        },
    )
    assert result["spf"]["grade"] == "D"
    assert any("all" in issue for issue in fr(result["spf"]["issues"]))
    assert any("-all" in r for r in fr(result["recommendations"]))


def test_spf_absent_malgre_des_txt(fake_dns):
    result = analyze(fake_dns, {("example.com", "TXT"): ["google-site-verification=abc"]})
    assert result["spf"]["found"] is False
    assert result["spf"]["grade"] == "F"
    assert fr(result["spf"]["issues"]) == ["Aucun enregistrement SPF trouvé"]
    assert any("SPF" in r for r in fr(result["recommendations"]))


def test_spf_enregistrements_multiples_permerror(fake_dns):
    result = analyze(
        fake_dns,
        {
            ("example.com", "TXT"): [
                "v=spf1 -all",
                "v=spf1 include:_spf.example.net -all",
            ]
        },
    )
    assert result["spf"]["found"] is True
    assert result["spf"]["grade"] == "F"
    assert len(result["spf"]["records"]) == 2
    assert any("permerror" in issue for issue in fr(result["spf"]["issues"]))


def test_spf_multi_chaines_recolle_sans_artefact(fake_dns):
    # Le -all est coupé entre deux chaînes : il doit être reconnu après recollage.
    result = analyze(
        fake_dns,
        {
            ("example.com", "TXT"): [txt("v=spf1 include:_spf.example.net -a", "ll")],
            ("_spf.example.net", "TXT"): ["v=spf1 ip4:192.0.2.0/24 -all"],
        },
    )
    assert result["spf"]["record"] == "v=spf1 include:_spf.example.net -all"
    assert result["spf"]["grade"] == "A"
    assert result["spf"]["dns_lookups"] == 1


def _spf_with_a_terms(count: int) -> str:
    return "v=spf1 " + " ".join(f"a:h{i}.example.net" for i in range(count)) + " -all"


def test_spf_limite_de_10_requetes_comptee_recursivement(fake_dns):
    result = analyze(
        fake_dns,
        {
            ("example.com", "TXT"): ["v=spf1 include:one.example.net include:two.example.net -all"],
            ("one.example.net", "TXT"): [_spf_with_a_terms(5)],
            ("two.example.net", "TXT"): [_spf_with_a_terms(5)],
        },
    )
    assert result["spf"]["dns_lookups"] == 12
    assert result["spf"]["grade"] == "F"
    assert any("12 > 10" in issue for issue in fr(result["spf"]["issues"]))


def test_spf_exactement_10_requetes_accepte(fake_dns):
    result = analyze(
        fake_dns,
        {
            ("example.com", "TXT"): ["v=spf1 include:one.example.net include:two.example.net -all"],
            ("one.example.net", "TXT"): [_spf_with_a_terms(4)],
            ("two.example.net", "TXT"): [_spf_with_a_terms(4)],
        },
    )
    assert result["spf"]["dns_lookups"] == 10
    assert result["spf"]["grade"] == "A"


def test_spf_include_sans_enregistrement_spf_permerror(fake_dns):
    result = analyze(fake_dns, {("example.com", "TXT"): ["v=spf1 include:absent.example.net -all"]})
    assert result["spf"]["grade"] == "F"
    assert any("absent.example.net" in issue for issue in fr(result["spf"]["issues"]))


def test_spf_boucle_d_include_detectee(fake_dns):
    result = analyze(fake_dns, {("example.com", "TXT"): ["v=spf1 include:example.com -all"]})
    assert result["spf"]["grade"] == "F"
    assert any("Boucle" in issue for issue in fr(result["spf"]["issues"]))


def test_spf_redirect_suivi_pour_le_qualificatif(fake_dns):
    result = analyze(
        fake_dns,
        {
            ("example.com", "TXT"): ["v=spf1 redirect=_spf.example.net"],
            ("_spf.example.net", "TXT"): ["v=spf1 ip4:192.0.2.1 -all"],
        },
    )
    assert result["spf"]["grade"] == "A"
    assert result["spf"]["all"] == "-all"
    assert result["spf"]["dns_lookups"] == 1


def test_spf_redirect_en_echec_non_mesure(fake_dns):
    result = analyze(
        fake_dns,
        {
            ("example.com", "TXT"): ["v=spf1 redirect=_spf.example.net"],
            ("_spf.example.net", "TXT"): TIMEOUT,
            ("_dmarc.example.com", "TXT"): [DMARC_REJECT],
        },
    )
    assert result["spf"]["grade"] is None
    assert "redirect" in fr(result["spf"]["error"])
    assert result["measured"] is True
    assert result["partial"] is True


def test_spf_redirect_en_echec_dans_un_include_sans_effet_sur_all(fake_dns):
    result = analyze(
        fake_dns,
        {
            ("example.com", "TXT"): ["v=spf1 include:_spf.example.net -all"],
            ("_spf.example.net", "TXT"): ["v=spf1 redirect=_inner.example.net"],
            ("_inner.example.net", "TXT"): TIMEOUT,
        },
    )
    assert result["spf"]["error"] is None
    assert result["spf"]["grade"] == "A"


def test_spf_terme_invalide_apres_all_signale(fake_dns):
    result = analyze(fake_dns, {("example.com", "TXT"): ["v=spf1 -all foo:bar"]})
    assert "Terme SPF invalide : foo:bar" in fr(result["spf"]["issues"])
    assert any("Corriger l'enregistrement SPF" in r for r in fr(result["recommendations"]))


@pytest.mark.parametrize(
    "zone",
    [
        {("partner.example", "TXT"): ["v=spf1 +all"]},
        # all sans qualificatif vaut +all.
        {("partner.example", "TXT"): ["v=spf1 ip4:192.0.2.1 all"]},
        # +all atteint par un redirect= de l'include.
        {
            ("partner.example", "TXT"): ["v=spf1 redirect=_spf.partner.example"],
            ("_spf.partner.example", "TXT"): ["v=spf1 +all"],
        },
        # +all atteint par un include imbriqué.
        {
            ("partner.example", "TXT"): ["v=spf1 include:_spf.partner.example -all"],
            ("_spf.partner.example", "TXT"): ["v=spf1 +all"],
        },
    ],
)
def test_spf_include_qui_autorise_tout_serveur(fake_dns, zone):
    """Un include qui se termine par +all fait passer tout expéditeur, malgré le -all final."""
    result = analyze(fake_dns, {("example.com", "TXT"): ["v=spf1 include:partner.example -all"], **zone})
    assert result["spf"]["all"] == "-all"
    assert result["spf"]["grade"] == "F"
    assert any(
        "include:partner.example" in issue and "+all" in issue for issue in fr(result["spf"]["issues"])
    )
    assert any("+all" in r for r in fr(result["recommendations"]))


@pytest.mark.parametrize(
    "outer, inner",
    [
        # Un include ne correspond que si l'enregistrement inclus renvoie pass.
        ("v=spf1 include:partner.example -all", "v=spf1 ~all"),
        ("v=spf1 include:partner.example -all", "v=spf1 ?all"),
        ("v=spf1 include:partner.example -all", "v=spf1 ip4:192.0.2.0/24"),
        # Qualificatif « - » : l'include qui correspond donne fail, pas pass.
        ("v=spf1 -include:partner.example -all", "v=spf1 +all"),
        # Include imbriqué « ~ » vers +all : l'include intermédiaire rend softfail.
        ("v=spf1 include:partner.example -all", "v=spf1 ~include:_spf.partner.example -all"),
    ],
)
def test_spf_include_sans_pass_general_non_penalise(fake_dns, outer, inner):
    result = analyze(
        fake_dns,
        {
            ("example.com", "TXT"): [outer],
            ("partner.example", "TXT"): [inner],
            ("_spf.partner.example", "TXT"): ["v=spf1 +all"],
        },
    )
    assert result["spf"]["grade"] == "A"
    assert result["spf"]["issues"] == []


def test_spf_mecanisme_ptr_signale_sans_changer_la_note(fake_dns):
    """RFC 7208 §5.5 : ptr ne devrait pas être utilisé (SPF de nmap.org)."""
    assert email.parse_spf("v=spf1 a mx ptr ip4:192.0.2.1 ~all")["ptr"] is True
    assert email.parse_spf("v=spf1 a mx -all")["ptr"] is False
    result = analyze(fake_dns, {("example.com", "TXT"): ["v=spf1 a mx ptr ip4:192.0.2.1 ~all"]})
    assert result["spf"]["grade"] == "B"
    assert result["spf"]["dns_lookups"] == 3
    assert any("ptr déconseillé (RFC 7208 §5.5)" in issue for issue in fr(result["spf"]["issues"]))


@pytest.mark.parametrize(
    "record",
    [
        # ptr d'un include tiers : hors du ressort du domaine.
        "v=spf1 include:_spf.example.net -all",
        # Terme après all : jamais évalué.
        "v=spf1 -all ptr",
    ],
)
def test_spf_ptr_hors_enregistrement_evalue_non_signale(fake_dns, record):
    result = analyze(
        fake_dns,
        {
            ("example.com", "TXT"): [record],
            ("_spf.example.net", "TXT"): ["v=spf1 ptr -all"],
        },
    )
    assert not any("ptr" in issue for issue in fr(result["spf"]["issues"]))


def test_spf_evalue_sur_l_hote_scanne_sans_heritage_de_l_apex(fake_dns):
    """Régression : le « v=spf1 ~all » de vulnweb.com était noté B pour testphp.vulnweb.com."""
    fake_dns(
        {
            ("vulnweb.com", "TXT"): ["v=spf1 ~all"],
            ("testphp.vulnweb.com", "TXT"): ["google-site-verification:abc"],
        }
    )
    result = email._analyze_email_security_sync("vulnweb.com", dmarc_domain="testphp.vulnweb.com")
    spf = result["spf"]
    assert spf["domain"] == "testphp.vulnweb.com"
    assert spf["found"] is False
    assert spf["record"] is None
    assert spf["grade"] == "F"
    # Le SPF de l'apex reste visible, à titre d'information seulement.
    assert spf["apex_domain"] == "vulnweb.com"
    assert spf["apex_record"] == "v=spf1 ~all"
    assert any("ne s'applique pas à testphp.vulnweb.com" in issue for issue in fr(spf["issues"]))
    assert result["overall_grade"] == "F"


def test_spf_hote_sans_txt_protection_par_dmarc_herite(fake_dns):
    """www.example.com : aucun TXT, SPF « none » ; DMARC sp=reject hérité de l'apex."""
    fake_dns(
        {
            ("example.com", "TXT"): ["v=spf1 -all"],
            ("www.example.com", "TXT"): NOANSWER,
            ("_dmarc.example.com", "TXT"): ["v=DMARC1;p=reject;sp=reject;adkim=s;aspf=s"],
        }
    )
    result = email._analyze_email_security_sync("example.com", dmarc_domain="www.example.com")
    assert result["spf"]["domain"] == "www.example.com"
    assert result["spf"]["found"] is False
    assert result["spf"]["apex_record"] == "v=spf1 -all"
    assert result["dmarc"]["inherited"] is True
    assert result["dmarc"]["grade"] == "A"


def test_spf_apex_non_interroge_pour_l_apex_lui_meme(fake_dns):
    resolver = fake_dns({("example.com", "TXT"): ["v=spf1 -all"]})
    result = email._analyze_email_security_sync("example.com")
    assert result["spf"]["domain"] == "example.com"
    assert result["spf"]["apex_domain"] is None
    assert result["spf"]["apex_record"] is None
    assert resolver.queries.count(("example.com", "TXT")) == 1


# =============================================================================
# Échecs DNS : jamais présentés comme une absence (SCAN-V1, SCORE-7)
# =============================================================================


def test_timeout_spf_ne_signifie_pas_absent(fake_dns):
    result = analyze(
        fake_dns,
        {
            ("example.com", "TXT"): TIMEOUT,
            ("_dmarc.example.com", "TXT"): [DMARC_REJECT],
            ("google._domainkey.example.com", "TXT"): [DKIM_KEY],
        },
    )
    assert result["measured"] is True
    assert result["partial"] is True
    assert result["spf"]["found"] is None
    assert result["spf"]["grade"] is None
    assert "délai" in fr(result["spf"]["error"])
    assert "Aucun enregistrement SPF trouvé" not in fr(result["spf"]["issues"])
    assert not any("SPF" in r for r in fr(result["recommendations"]))
    # Note calculée sur DMARC (A) et DKIM, sans le SPF non mesuré.
    assert result["overall_grade"] == "A"


def test_timeout_spf_et_dmarc_absent_note_sur_dmarc_seul(fake_dns):
    result = analyze(fake_dns, {("example.com", "TXT"): TIMEOUT})
    assert result["measured"] is True
    assert result["partial"] is True
    assert result["spf"]["grade"] is None
    assert result["dmarc"]["grade"] == "F"
    assert result["overall_grade"] == "F"


def test_spf_et_dmarc_en_echec_non_mesure(fake_dns):
    resolver = fake_dns(
        {
            ("example.com", "TXT"): TIMEOUT,
            ("_dmarc.example.com", "TXT"): SERVFAIL,
        }
    )
    result = email._analyze_email_security_sync("example.com")
    assert result["measured"] is False
    # Les deux échecs, dans l'ordre SPF puis DMARC, joints par « ; ».
    assert fr(result["error"]) == (
        "Analyse email impossible : Requête SPF échouée : délai dépassé ; "
        "Requête DMARC échouée : _dmarc.example.com : "
        "aucun serveur DNS n'a répondu (SERVFAIL ou REFUSED)"
    )
    assert result["overall_grade"] == "N/A"
    assert result["recommendations"] == []
    # Résolveur indisponible : DKIM n'est pas interrogé.
    assert not any("_domainkey" in name for name, _ in resolver.queries)


def test_domaine_inexistant_non_mesure(fake_dns):
    result = analyze(fake_dns, {("example.com", "TXT"): NXDOMAIN})
    assert result["measured"] is False
    assert fr(result["error"]) == "Domaine inexistant (NXDOMAIN) : example.com"
    assert result["overall_grade"] == "N/A"


def test_cible_ip_non_applicable_sans_requete(fake_dns):
    resolver = fake_dns({})
    result = email._analyze_email_security_sync("93.184.216.34")
    assert result["measured"] is False
    assert fr(result["error"]) == "Analyse email non applicable à une adresse IP"
    assert resolver.queries == []


def test_budget_dns_epuise_sans_requete(fake_dns):
    resolver = fake_dns({})
    lookup = scanner_dns.DnsQuerier(query_timeout=3, budget=0).lookup("example.com", "TXT")
    assert lookup.status == "error"
    assert resolver.queries == []


# =============================================================================
# DMARC
# =============================================================================


@pytest.mark.parametrize(
    "record, policy, grade",
    [
        # sp= placé avant p= ne doit pas être pris pour la politique.
        ("v=DMARC1; sp=none; p=reject; rua=mailto:d@example.com", "reject", "A"),
        ("v=DMARC1; p=Reject; rua=mailto:d@example.com", "reject", "A"),
        ("v=DMARC1 ; p = quarantine ; rua = mailto:d@example.com", "quarantine", "B"),
        ("v=DMARC1; p=none; rua=mailto:d@example.com", "none", "D"),
        ("V=dmarc1; P=REJECT; rua=mailto:d@example.com", "reject", "A"),
    ],
)
def test_dmarc_politique_extraite_par_tags(fake_dns, record, policy, grade):
    result = analyze(
        fake_dns,
        {
            ("example.com", "TXT"): ["v=spf1 -all"],
            ("_dmarc.example.com", "TXT"): [record],
        },
    )
    assert result["dmarc"]["found"] is True
    assert result["dmarc"]["policy"] == policy
    assert result["dmarc"]["grade"] == grade


def test_dmarc_alignements_et_ruf(fake_dns):
    record = "v=DMARC1; p=reject; adkim=s; aspf=r; rua=mailto:d@example.com; ruf=mailto:f@example.com"
    result = analyze(
        fake_dns,
        {("example.com", "TXT"): ["v=spf1 -all"], ("_dmarc.example.com", "TXT"): [record]},
    )
    dmarc = result["dmarc"]
    assert (dmarc["adkim"], dmarc["aspf"], dmarc["ruf"]) == ("s", "r", ["mailto:f@example.com"])
    # Valeurs par défaut (RFC 7489) : alignement relâché, aucun rapport d'échec.
    result = analyze(fake_dns, {("_dmarc.example.com", "TXT"): ["v=DMARC1; p=none"]})
    assert (result["dmarc"]["adkim"], result["dmarc"]["aspf"], result["dmarc"]["ruf"]) == ("r", "r", [])


def test_dmarc_sp_none_signale(fake_dns):
    result = analyze(
        fake_dns,
        {
            ("example.com", "TXT"): ["v=spf1 -all"],
            ("_dmarc.example.com", "TXT"): ["v=DMARC1; sp=none; p=reject; rua=mailto:d@example.com"],
        },
    )
    assert result["dmarc"]["subdomain_policy"] == "none"
    assert any("sp=none" in issue for issue in fr(result["dmarc"]["issues"]))
    assert result["overall_grade"] == "A"


@pytest.mark.parametrize(
    "record, grade",
    [
        ("v=DMARC1; rua=mailto:d@example.com", "D"),  # traité comme p=none (RFC 7489 §6.6.3)
        ("v=DMARC1; p=invalide", "F"),
    ],
)
def test_dmarc_politique_absente_ou_invalide(fake_dns, record, grade):
    result = analyze(fake_dns, {("_dmarc.example.com", "TXT"): [record]})
    assert result["dmarc"]["policy"] is None
    assert result["dmarc"]["grade"] == grade
    assert any("absente ou invalide" in issue for issue in fr(result["dmarc"]["issues"]))


def test_dmarc_enregistrements_multiples(fake_dns):
    result = analyze(fake_dns, {("_dmarc.example.com", "TXT"): [DMARC_REJECT, "v=DMARC1; p=none"]})
    assert result["dmarc"]["grade"] == "F"
    assert any("Plusieurs" in issue for issue in fr(result["dmarc"]["issues"]))


def test_dmarc_txt_non_dmarc_ignore(fake_dns):
    result = analyze(fake_dns, {("_dmarc.example.com", "TXT"): ["verification=xyz"]})
    assert result["dmarc"]["found"] is False
    assert fr(result["dmarc"]["issues"]) == ["Aucun enregistrement DMARC trouvé"]


def test_dmarc_pct_partiel(fake_dns):
    result = analyze(
        fake_dns,
        {
            ("_dmarc.example.com", "TXT"): ["v=DMARC1; p=reject; pct=50; rua=mailto:d@example.com"],
        },
    )
    assert result["dmarc"]["pct"] == 50
    assert any("50%" in issue for issue in fr(result["dmarc"]["issues"]))


@pytest.mark.parametrize(
    "policy, pct, grade, applied",
    [
        # RFC 7489 §6.6.4 : hors échantillon, reject devient quarantine…
        ("reject", 50, "B", "quarantine"),
        # … et quarantine devient none : pct=0 n'applique rien.
        ("quarantine", 0, "D", "none"),
        ("quarantine", 99, "D", "none"),
    ],
)
def test_dmarc_pct_partiel_note_la_politique_hors_echantillon(fake_dns, policy, pct, grade, applied):
    result = analyze(
        fake_dns,
        {
            ("example.com", "TXT"): ["v=spf1 -all"],
            ("_dmarc.example.com", "TXT"): [f"v=DMARC1; p={policy}; pct={pct}; rua=mailto:d@example.com"],
        },
    )
    dmarc = result["dmarc"]
    # La politique publiée reste affichée ; la note suit la part non couverte.
    assert dmarc["policy"] == policy
    assert dmarc["pct"] == pct
    assert dmarc["grade"] == grade
    assert any(f"relèvent de la politique '{applied}'" in issue for issue in fr(dmarc["issues"]))
    assert any("pct=100" in r for r in fr(result["recommendations"]))


def test_dmarc_quarantine_pct_0_ne_donne_pas_a(fake_dns):
    """Régression : p=quarantine; pct=0 et SPF -all donnaient A et 15/15."""
    result = analyze(
        fake_dns,
        {
            ("example.com", "TXT"): ["v=spf1 -all"],
            ("_dmarc.example.com", "TXT"): ["v=DMARC1; p=quarantine; pct=0; rua=mailto:d@example.com"],
        },
    )
    assert result["dmarc"]["grade"] == "D"
    assert result["overall_grade"] == "C"


@pytest.mark.parametrize("pct", ["100", None])
def test_dmarc_pct_complet_inchange(fake_dns, pct):
    record = "v=DMARC1; p=reject; rua=mailto:d@example.com" + (f"; pct={pct}" if pct else "")
    result = analyze(fake_dns, {("_dmarc.example.com", "TXT"): [record]})
    assert result["dmarc"]["grade"] == "A"
    assert not any("pct" in issue for issue in fr(result["dmarc"]["issues"]))


@pytest.mark.parametrize(
    "record, grade",
    [
        # RFC 7489 §6.6.3 : un sp= invalide rend l'enregistrement invalide, comme
        # un p= invalide : p=none avec rua=, aucun traitement DMARC sinon.
        ("v=DMARC1; p=reject; sp=bogus; rua=mailto:d@example.com", "D"),
        ("v=DMARC1; p=reject; sp=bogus", "F"),
    ],
)
def test_dmarc_sp_invalide_rend_l_enregistrement_invalide(fake_dns, record, grade):
    result = analyze(
        fake_dns,
        {
            ("example.com", "TXT"): ["v=spf1 -all"],
            ("_dmarc.example.com", "TXT"): [record],
        },
    )
    dmarc = result["dmarc"]
    assert dmarc["found"] is True
    assert dmarc["grade"] == grade
    assert dmarc["policy"] is None
    assert dmarc["subdomain_policy"] is None
    assert "Valeur sp= invalide : bogus (enregistrement DMARC invalide)" in fr(dmarc["issues"])
    assert any("sp=" in r for r in fr(result["recommendations"]))
    assert result["overall_grade"] == "C"


def test_dmarc_herite_du_domaine_organisationnel(fake_dns):
    result = analyze(
        fake_dns,
        {
            ("blog.example.com", "TXT"): ["v=spf1 -all"],
            ("_dmarc.example.com", "TXT"): ["v=DMARC1; p=reject; sp=quarantine; rua=mailto:d@example.com"],
        },
        domain="blog.example.com",
    )
    dmarc = result["dmarc"]
    assert dmarc["inherited"] is True
    assert dmarc["source"] == "_dmarc.example.com"
    # Pour un sous-domaine, c'est sp= qui s'applique.
    assert dmarc["policy"] == "quarantine"
    assert dmarc["grade"] == "B"


def test_dmarc_propre_au_sous_domaine_prioritaire(fake_dns):
    result = analyze(
        fake_dns,
        {
            ("blog.example.com", "TXT"): ["v=spf1 -all"],
            ("_dmarc.blog.example.com", "TXT"): ["v=DMARC1; p=none; rua=mailto:d@example.com"],
            ("_dmarc.example.com", "TXT"): [DMARC_REJECT],
        },
        domain="blog.example.com",
    )
    assert result["dmarc"]["inherited"] is False
    assert result["dmarc"]["source"] == "_dmarc.blog.example.com"
    assert result["dmarc"]["policy"] == "none"


NEWS_ZONE = {
    ("example.com", "TXT"): ["v=spf1 -all"],
    ("news.example.com", "TXT"): ["v=spf1 include:_spf.example.net -all"],
    ("_spf.example.net", "TXT"): ["v=spf1 ip4:192.0.2.0/24 -all"],
    ("_dmarc.news.example.com", "TXT"): ["v=DMARC1; p=none; rua=mailto:d@example.com"],
    ("_dmarc.example.com", "TXT"): [DMARC_REJECT],
}


def test_dmarc_evalue_pour_l_hote_scanne(fake_dns):
    """DKIM sur l'apex, SPF et DMARC sur le sous-domaine scanné (ses propres enregistrements)."""
    fake_dns(NEWS_ZONE)
    result = email._analyze_email_security_sync("example.com", dmarc_domain="news.example.com")
    assert result["domain"] == "example.com"
    assert result["dmarc_domain"] == "news.example.com"
    assert result["spf"]["domain"] == "news.example.com"
    assert result["spf"]["record"] == "v=spf1 include:_spf.example.net -all"
    assert result["spf"]["grade"] == "A"
    assert result["dmarc"]["source"] == "_dmarc.news.example.com"
    assert result["dmarc"]["policy"] == "none"
    assert result["dmarc"]["grade"] == "D"


def test_dmarc_onglets_dns_et_email_concordent(fake_dns):
    fake_dns(NEWS_ZONE)
    records = scanner_dns._scan_dns_sync("news.example.com")
    result = email._analyze_email_security_sync("example.com", dmarc_domain="news.example.com")
    assert records["DMARC"] == [result["dmarc"]["record"]]
    assert records["dmarc_source"] == result["dmarc"]["source"]


def test_dmarc_herite_sp_applique_a_l_hote_scanne(fake_dns):
    """Apex « p=reject; sp=none » : un sous-domaine scanné relève de sp=none."""
    fake_dns(
        {
            ("example.com", "TXT"): ["v=spf1 -all"],
            ("blog.example.com", "TXT"): ["v=spf1 -all"],
            ("_dmarc.example.com", "TXT"): ["v=DMARC1; p=reject; sp=none; rua=mailto:d@example.com"],
        }
    )
    result = email._analyze_email_security_sync("example.com", dmarc_domain="blog.example.com")
    assert result["dmarc"]["inherited"] is True
    assert result["dmarc"]["policy"] == "none"
    assert result["dmarc"]["grade"] == "D"
    # Le même enregistrement, pour l'apex lui-même, vaut A.
    assert email._analyze_email_security_sync("example.com")["dmarc"]["grade"] == "A"


def test_dmarc_domain_par_defaut_le_domaine_analyse(fake_dns):
    fake_dns(NEWS_ZONE)
    result = email._analyze_email_security_sync("example.com")
    assert result["dmarc_domain"] == "example.com"
    assert result["dmarc"]["source"] == "_dmarc.example.com"


def test_dmarc_domain_transmis_par_l_api_asynchrone(fake_dns):
    fake_dns(NEWS_ZONE)
    result = asyncio.run(email.analyze_email_security("example.com", dmarc_domain="News.Example.com."))
    assert result["dmarc_domain"] == "news.example.com"
    assert result["dmarc"]["source"] == "_dmarc.news.example.com"


# =============================================================================
# DKIM, MTA-STS, TLS-RPT, note globale
# =============================================================================


def test_dkim_txt_joker_n_est_pas_une_cle(fake_dns):
    zone = {
        (f"{sel}._domainkey.example.com", "TXT"): ["some-verification=abc"] for sel in email.DKIM_SELECTORS
    }
    result = analyze(fake_dns, zone)
    assert result["dkim"]["found"] is False
    assert result["dkim"]["selectors_found"] == []


def test_dkim_cle_revoquee_signalee(fake_dns):
    result = analyze(fake_dns, {("google._domainkey.example.com", "TXT"): ["v=DKIM1; p="]})
    assert result["dkim"]["found"] is False
    assert result["dkim"]["revoked_selectors"] == ["google"]
    assert any("révoquée" in issue for issue in fr(result["dkim"]["issues"]))


def test_dkim_cle_multi_chaines_valide(fake_dns):
    result = analyze(
        fake_dns,
        {
            ("selector1._domainkey.example.com", "TXT"): [txt("v=DKIM1; k=rsa; p=MIGfMA0G", "CSqGSIb3DQEB")],
        },
    )
    assert result["dkim"]["found"] is True
    assert result["dkim"]["selectors_found"] == ["selector1"]


def test_dkim_non_trouve_ne_penalise_pas(fake_dns):
    result = analyze(
        fake_dns,
        {
            ("example.com", "TXT"): ["v=spf1 -all"],
            ("_dmarc.example.com", "TXT"): [DMARC_REJECT],
        },
    )
    assert result["dkim"]["found"] is False
    assert result["overall_grade"] == "A"
    assert result["partial"] is False


def test_dkim_toutes_requetes_en_echec(fake_dns):
    zone = {(f"{sel}._domainkey.example.com", "TXT"): TIMEOUT for sel in email.DKIM_SELECTORS}
    zone[("example.com", "TXT")] = ["v=spf1 -all"]
    result = analyze(fake_dns, zone)
    assert result["dkim"]["found"] is None
    assert fr(result["dkim"]["error"]) == "Requêtes DKIM échouées : délai dépassé"
    assert result["measured"] is True


DKIM_PROBE = "sonde-aleatoire"
DKIM_REVOKED_WILDCARD = "v=DKIM1; p="


@pytest.fixture
def dkim_probe(monkeypatch):
    """Sélecteur aléatoire fixé : sa zone simule (ou non) un joker *._domainkey."""
    monkeypatch.setattr(email, "_random_dkim_selector", lambda: DKIM_PROBE)


def _dkim_wildcard_zone(domain: str, record: str) -> dict:
    """Joker *._domainkey : même réponse pour la sonde et pour chaque sélecteur courant."""
    names = [DKIM_PROBE, *email.DKIM_SELECTORS]
    return {(f"{sel}._domainkey.{domain}", "TXT"): [record] for sel in names}


# Configuration d'example.com : MX nul, SPF -all, DMARC reject, joker DKIM révoqué.
NO_MAIL_ZONE = {
    ("example.com", "TXT"): ["v=spf1 -all", "_k2n1y4vw3qtb4skdx9e7dxt97qrmmq9"],
    ("example.com", "MX"): [rdata("MX", "0 .")],
    ("_dmarc.example.com", "TXT"): ["v=DMARC1;p=reject;sp=reject;adkim=s;aspf=s"],
    **_dkim_wildcard_zone("example.com", DKIM_REVOKED_WILDCARD),
}


def test_domaine_sans_messagerie_mx_nul(fake_dns, dkim_probe):
    """Régression : 12 avertissements DKIM et une recommandation DKIM pour example.com."""
    result = analyze(fake_dns, NO_MAIL_ZONE)
    assert result["null_mx"] is True
    assert result["overall_grade"] == "A"
    dkim = result["dkim"]
    # Joker révoqué détecté une fois, et non comme 11 clés révoquées.
    assert dkim["wildcard"] == "revoked"
    assert dkim["revoked_selectors"] == []
    assert dkim["found"] is False
    assert dkim["issues"] == []
    assert result["recommendations"] == []
    assert fr(result["notes"]) == [
        "Domaine sans messagerie (RFC 7505) : MX nul, SPF -all et DMARC reject, aucune signature DKIM attendue"
    ]


def test_joker_dkim_revoque_signale_une_fois(fake_dns, dkim_probe):
    zone = {
        ("example.com", "TXT"): ["v=spf1 -all"],
        ("example.com", "MX"): [rdata("MX", "10 mx.example.com.")],
        ("_dmarc.example.com", "TXT"): [DMARC_REJECT],
        **_dkim_wildcard_zone("example.com", DKIM_REVOKED_WILDCARD),
        # Sélecteur publié explicitement : il prime sur le joker.
        ("google._domainkey.example.com", "TXT"): [DKIM_KEY],
    }
    result = analyze(fake_dns, zone)
    dkim = result["dkim"]
    assert result["null_mx"] is False
    assert dkim["wildcard"] == "revoked"
    assert dkim["found"] is True
    assert dkim["selectors_found"] == ["google"]
    assert dkim["revoked_selectors"] == []
    assert not any("révoquée" in issue for issue in fr(dkim["issues"]))
    assert len(result["notes"]) == 1
    assert "Joker DKIM révoqué" in fr(result["notes"][0])


def test_joker_dkim_avec_cle_valide(fake_dns, dkim_probe):
    result = analyze(fake_dns, _dkim_wildcard_zone("example.com", DKIM_KEY))
    dkim = result["dkim"]
    assert dkim["wildcard"] == "valid"
    assert dkim["found"] is True
    assert dkim["selectors_found"] == []
    assert sum("joker" in issue for issue in fr(dkim["issues"])) == 1


def test_sonde_dkim_en_echec_sans_conclusion_sur_le_joker(fake_dns, dkim_probe):
    zone = {
        **_dkim_wildcard_zone("example.com", DKIM_REVOKED_WILDCARD),
        (f"{DKIM_PROBE}._domainkey.example.com", "TXT"): TIMEOUT,
    }
    result = analyze(fake_dns, zone)
    # Joker inconnu : chaque sélecteur révoqué reste signalé.
    assert result["dkim"]["wildcard"] is None
    assert result["dkim"]["revoked_selectors"] == list(email.DKIM_SELECTORS)


@pytest.mark.parametrize(
    "overrides",
    [
        # SPF ~all : le domaine ne déclare pas n'envoyer aucun courrier.
        {("example.com", "TXT"): ["v=spf1 ~all"]},
        # DMARC p=none : aucune politique appliquée.
        {("_dmarc.example.com", "TXT"): ["v=DMARC1; p=none; rua=mailto:d@example.com"]},
        # MX nul accompagné d'un autre MX : ce n'est pas un MX nul (RFC 7505 §3).
        {("example.com", "MX"): [rdata("MX", "0 ."), rdata("MX", "10 mx.example.com.")]},
    ],
)
def test_mx_nul_incomplet_garde_la_recommandation_dkim(fake_dns, dkim_probe, overrides):
    result = analyze(fake_dns, {**NO_MAIL_ZONE, **overrides})
    assert not any("sans messagerie" in note for note in fr(result["notes"]))
    assert any("DKIM" in r for r in fr(result["recommendations"]))
    assert any("Aucune clé DKIM" in issue for issue in fr(result["dkim"]["issues"]))


@pytest.mark.parametrize(
    "mx, expected",
    [
        (NOANSWER, False),
        (NXDOMAIN, False),
        (TIMEOUT, None),
    ],
)
def test_mx_nul_mesure_ou_non(fake_dns, mx, expected):
    result = analyze(fake_dns, {("example.com", "TXT"): ["v=spf1 -all"], ("example.com", "MX"): mx})
    assert result["null_mx"] is expected


def test_mx_nul_cherche_sur_l_hote_scanne(fake_dns):
    resolver = fake_dns({**NO_MAIL_ZONE, ("www.example.com", "TXT"): NOANSWER})
    result = email._analyze_email_security_sync("example.com", dmarc_domain="www.example.com")
    assert ("www.example.com", "MX") in resolver.queries
    assert result["null_mx"] is False


def test_mta_sts_et_tls_rpt_informatifs(fake_dns):
    result = analyze(
        fake_dns,
        {
            ("example.com", "TXT"): ["v=spf1 -all"],
            ("_mta-sts.example.com", "TXT"): ["v=STSv1; id=20240101"],
            ("_smtp._tls.example.com", "TXT"): ["v=TLSRPTv1; rua=mailto:tls@example.com"],
        },
    )
    assert result["mta_sts"] == {"found": True, "record": "v=STSv1; id=20240101", "error": None}
    assert result["tls_rpt"]["found"] is True


def test_configuration_complete_note_a(fake_dns):
    result = analyze(
        fake_dns,
        {
            ("example.com", "TXT"): ["v=spf1 include:_spf.example.net -all"],
            ("_spf.example.net", "TXT"): ["v=spf1 ip4:192.0.2.0/24 -all"],
            ("_dmarc.example.com", "TXT"): [DMARC_REJECT],
            ("google._domainkey.example.com", "TXT"): [DKIM_KEY],
        },
    )
    assert result["measured"] is True
    assert result["error"] is None
    assert result["overall_grade"] == "A"
    assert result["recommendations"] == []


@pytest.mark.parametrize(
    "spf, dmarc",
    [
        # Configuration Workspace / Microsoft 365 courante, sans DMARC.
        ("v=spf1 include:_spf.example.net -all", None),
        ("v=spf1 include:_spf.example.net -all", "v=DMARC1; p=none; rua=mailto:d@example.com"),
        ("v=spf1 include:_spf.example.net ~all", "v=DMARC1; p=none; rua=mailto:d@example.com"),
    ],
)
def test_note_globale_plafonnee_sans_dmarc_applique(fake_dns, spf, dmarc):
    """Régression : SPF + DKIM sans DMARC appliqué donnaient B (« protection solide ») et 12/15."""
    zone = {
        ("example.com", "TXT"): [spf],
        ("_spf.example.net", "TXT"): ["v=spf1 ip4:192.0.2.0/24 -all"],
        ("google._domainkey.example.com", "TXT"): [DKIM_KEY],
    }
    if dmarc:
        zone[("_dmarc.example.com", "TXT")] = [dmarc]
    result = analyze(fake_dns, zone)
    assert result["dkim"]["found"] is True
    assert result["dmarc"]["grade"] in ("D", "F")
    assert result["overall_grade"] == "C"


def test_note_globale_dmarc_quarantine_non_plafonnee(fake_dns):
    result = analyze(
        fake_dns,
        {
            ("example.com", "TXT"): ["v=spf1 -all"],
            ("_dmarc.example.com", "TXT"): ["v=DMARC1; p=quarantine; rua=mailto:d@example.com"],
            ("google._domainkey.example.com", "TXT"): [DKIM_KEY],
        },
    )
    assert result["dmarc"]["grade"] == "B"
    assert result["overall_grade"] == "A"


def test_analyze_email_security_asynchrone(fake_dns):
    fake_dns({("example.com", "TXT"): ["v=spf1 -all"]})
    result = asyncio.run(email.analyze_email_security("Example.COM."))
    assert result["domain"] == "example.com"
    assert result["spf"]["grade"] == "A"


# =============================================================================
# Enregistrements DNS (onglet DNS)
# =============================================================================


def test_dns_records_txt_multi_chaines_et_erreur_par_type(fake_dns):
    fake_dns(
        {
            ("example.com", "A"): [rdata("A", "93.184.216.34")],
            ("example.com", "AAAA"): NOANSWER,
            ("example.com", "MX"): TIMEOUT,
            ("example.com", "TXT"): [txt("v=spf1 include:_spf.example.net ", "include:mailgun.org -all")],
            ("example.com", "SOA"): [
                rdata("SOA", "ns1.example.com. hostmaster.example.com. 2024010101 7200 3600 1209600 3600")
            ],
        }
    )
    records = scanner_dns._scan_dns_sync("example.com")
    assert records["A"] == ["93.184.216.34"]
    assert records["TXT"] == ["v=spf1 include:_spf.example.net include:mailgun.org -all"]
    assert records["SOA"][0]["mname"] == "ns1.example.com"
    # Un délai dépassé n'est pas une absence : il est signalé par type.
    assert records["MX"] == []
    assert fr(records["errors"]["MX"]) == "délai dépassé"
    assert "AAAA" not in records["errors"]
    assert records["measured"] is True
    assert records["error"] is None


def test_dns_records_toutes_requetes_en_echec(fake_dns):
    fake_dns(
        {
            (name, rtype): SERVFAIL
            for name in ("example.com", "_dmarc.example.com")
            for rtype in [*scanner_dns.DNS_RECORD_TYPES]
        }
    )
    records = scanner_dns._scan_dns_sync("example.com")
    assert records["measured"] is False
    assert records["error"]


def test_dns_records_dmarc_aligne_sur_l_analyse_email(fake_dns):
    fake_dns({("_dmarc.example.com", "TXT"): [DMARC_REJECT]})
    records = scanner_dns._scan_dns_sync("blog.example.com")
    assert records["DMARC"] == [DMARC_REJECT]
    assert records["dmarc_source"] == "_dmarc.example.com"


def test_dns_records_mx_nul_conserve(fake_dns):
    """Régression : « 0 . » (RFC 7505) devenait {"priority": 0, "value": ""}."""
    fake_dns({("example.com", "MX"): [rdata("MX", "0 .")]})
    records = scanner_dns._scan_dns_sync("example.com")
    assert records["MX"] == [{"priority": 0, "value": ".", "null_mx": True}]
    assert scanner_dns.has_null_mx([rdata("MX", "0 .")]) is True
    assert scanner_dns.has_null_mx([rdata("MX", "10 mx.example.com.")]) is False


def test_dns_records_mx_tries_par_priorite(fake_dns):
    fake_dns(
        {
            ("badssl.com", "MX"): [
                rdata("MX", "40 alt4.gmr-smtp-in.l.google.com."),
                rdata("MX", "10 alt1.gmr-smtp-in.l.google.com."),
                rdata("MX", "5 gmr-smtp-in.l.google.com."),
                rdata("MX", "10 alt0.gmr-smtp-in.l.google.com."),
            ]
        }
    )
    records = scanner_dns._scan_dns_sync("badssl.com")
    # Clés inchangées pour un MX ordinaire (comparaison de la timeline).
    assert records["MX"] == [
        {"priority": 5, "value": "gmr-smtp-in.l.google.com"},
        {"priority": 10, "value": "alt0.gmr-smtp-in.l.google.com"},
        {"priority": 10, "value": "alt1.gmr-smtp-in.l.google.com"},
        {"priority": 40, "value": "alt4.gmr-smtp-in.l.google.com"},
    ]


def test_dns_records_nxdomain_signale(fake_dns):
    """Régression : un domaine inexistant ressemblait à un domaine sans enregistrement."""
    fake_dns({})
    records = scanner_dns._scan_dns_sync("this-does-not-exist-dr-test-9f3k2.com")
    assert records["nxdomain"] is True
    # Réponse définitive : une mesure, pas un échec.
    assert records["measured"] is True
    assert records["error"] is None
    assert fr(records["notes"]) == ["Domaine inexistant (NXDOMAIN) : this-does-not-exist-dr-test-9f3k2.com"]


@pytest.mark.parametrize(
    "zone",
    [
        # Le nom existe sans aucune donnée : réponse vide, pas NXDOMAIN.
        {("example.com", "A"): NOANSWER},
        # CNAME pendant : A en NXDOMAIN, mais le nom lui-même existe.
        {("example.com", "CNAME"): [rdata("CNAME", "gone.example.net.")]},
        # Toutes les requêtes en échec : rien n'est établi.
        {("example.com", rtype): SERVFAIL for rtype in scanner_dns.DNS_RECORD_TYPES},
    ],
)
def test_dns_records_nxdomain_seulement_si_toutes_les_reponses_le_disent(fake_dns, zone):
    fake_dns(zone)
    records = scanner_dns._scan_dns_sync("example.com")
    assert records["nxdomain"] is False
    assert not any("NXDOMAIN" in note for note in fr(records["notes"]))


@pytest.fixture
def dns_probe(monkeypatch):
    """Label aléatoire fixé : « sonde.<site> »."""
    monkeypatch.setattr(scanner_dns, "_wildcard_probe_name", lambda domain: f"sonde.{domain}")


def test_dns_records_joker_detecte_sur_le_site(fake_dns, dns_probe):
    """Régression : *.badssl.com rendait « résolu » n'importe quel sous-domaine."""
    resolver = fake_dns(
        {
            ("expired.badssl.com", "A"): [rdata("A", "104.154.89.105")],
            ("sonde.badssl.com", "A"): [rdata("A", "104.154.89.105")],
        }
    )
    records = scanner_dns._scan_dns_sync("expired.badssl.com")
    assert records["wildcard"] is True
    assert ("sonde.badssl.com", "A") in resolver.queries
    assert any(
        "Joker DNS (*.badssl.com)" in note and "104.154.89.105" in note for note in fr(records["notes"])
    )


@pytest.mark.parametrize(
    "probe, expected",
    [
        (NXDOMAIN, False),
        (TIMEOUT, None),
    ],
)
def test_dns_records_sans_joker_ou_sonde_en_echec(fake_dns, dns_probe, probe, expected):
    fake_dns({("example.com", "A"): [rdata("A", "192.0.2.1")], ("sonde.example.com", "A"): probe})
    records = scanner_dns._scan_dns_sync("example.com")
    assert records["wildcard"] is expected
    assert records["notes"] == []


def test_dns_records_joker_aaaa_seul(fake_dns, dns_probe):
    fake_dns(
        {
            ("sonde.example.com", "A"): NOANSWER,
            ("sonde.example.com", "AAAA"): [rdata("AAAA", "2001:db8::1")],
        }
    )
    assert scanner_dns._scan_dns_sync("example.com")["wildcard"] is True


# =============================================================================
# Sous-domaines (crt.sh simulé)
# =============================================================================


def _serve_crtsh(monkeypatch, handler):
    def client(**kwargs):
        return httpx.AsyncClient(transport=httpx.MockTransport(handler))

    monkeypatch.setattr(scanner_dns, "_api_client", client)


def _serve_names(monkeypatch, names: list[str]) -> list:
    requests = []

    def handler(request):
        requests.append(request)
        return httpx.Response(200, json=[{"name_value": "\n".join(names)}])

    _serve_crtsh(monkeypatch, handler)
    return requests


def test_sous_domaines_frontiere_de_label_et_noms_invalides(monkeypatch):
    requests = _serve_names(
        monkeypatch,
        [
            "www.example.com",
            "admin@example.com",
            "*.example.com",
            "myexample.com",
            "shop.notexample.com",
            "API.example.com.",
            "example.com",
            "bad..example.com",
            "exa mple.example.com",
        ],
    )

    async def fake_resolve(host):
        return "192.0.2.10" if host == "www.example.com" else None

    monkeypatch.setattr(scanner_dns, "resolve_ip", fake_resolve)
    result = asyncio.run(scanner_dns.find_subdomains("example.com"))

    assert [s["subdomain"] for s in result] == ["api.example.com", "www.example.com"]
    assert result[0] == {"subdomain": "api.example.com", "ip": None, "resolution": "unresolved"}
    assert result[1] == {"subdomain": "www.example.com", "ip": "192.0.2.10", "resolution": "resolved"}
    assert requests[0].url.params["q"] == "%.example.com"


def test_sous_domaines_jokers_ramenes_au_nom_de_base():
    """Un certificat *.staging.example.com est souvent la seule trace CT de staging.example.com."""
    entries = [
        {"name_value": "*.staging.example.com\n*.example.com"},
        {"name_value": "*.dev.example.com"},
        {"name_value": "www.example.com"},
        # Joker sur un autre domaine, joker double : écartés.
        {"name_value": "*.notexample.com\n*.*.example.com"},
    ]
    assert scanner_dns._extract_ct_names(entries, "example.com") == {
        "staging.example.com",
        "dev.example.com",
        "www.example.com",
    }


def test_sous_domaines_resolution_limitee_et_signalee(monkeypatch):
    names = [f"host{i:02d}.example.com" for i in range(40)] + ["vpn.example.com"]
    _serve_names(monkeypatch, names)
    resolved = []

    async def fake_resolve(host):
        resolved.append(host)
        return "192.0.2.1"

    monkeypatch.setattr(scanner_dns, "resolve_ip", fake_resolve)
    result = asyncio.run(scanner_dns.find_subdomains("example.com"))

    # Liste complète, et non tronquée aux 30 premiers.
    assert len(result) == 41
    # Les noms sensibles passent en tête, donc dans la part résolue.
    assert result[0]["subdomain"] == "vpn.example.com"
    statuses = [s["resolution"] for s in result]
    assert statuses.count("resolved") == scanner_dns.SUBDOMAIN_RESOLVE_LIMIT
    assert statuses.count("not_tested") == 41 - scanner_dns.SUBDOMAIN_RESOLVE_LIMIT
    assert len(resolved) == scanner_dns.SUBDOMAIN_RESOLVE_LIMIT


def test_sous_domaines_plafond_de_la_liste(monkeypatch):
    """Régression : la coupe à SUBDOMAIN_MAX_RESULTS n'était signalée que dans les journaux."""
    _serve_names(monkeypatch, [f"h{i}.example.com" for i in range(10)])
    monkeypatch.setattr(scanner_dns, "SUBDOMAIN_MAX_RESULTS", 4)

    async def fake_resolve(host):
        return None

    monkeypatch.setattr(scanner_dns, "resolve_ip", fake_resolve)
    result = asyncio.run(scanner_dns.find_subdomains("example.com"))
    assert isinstance(result, list)
    assert len(result) == 4
    assert result.total_found == 10


def test_sous_domaines_total_sans_troncature(monkeypatch):
    _serve_names(monkeypatch, ["www.example.com", "api.example.com"])
    _no_resolution(monkeypatch)
    result = asyncio.run(scanner_dns.find_subdomains("example.com"))
    assert result.total_found == len(result) == 2
    assert asyncio.run(scanner_dns.find_subdomains("192.0.2.1")).total_found == 0


def test_sous_domaines_resolution_par_joker_signalee(monkeypatch):
    """Sous *.example.com, un nom qui résout vers une adresse du joker n'est pas prouvé."""
    _serve_names(monkeypatch, ["www.example.com", "ghost.example.com", "api.example.com"])
    monkeypatch.setattr(scanner_dns, "_wildcard_probe_name", lambda domain: f"sonde.{domain}")
    probes = []

    async def fake_addresses(host, timeout=None):
        probes.append(host)
        return ["192.0.2.80", "192.0.2.81"] if host == "sonde.example.com" else []

    async def fake_resolve(host):
        return {"www.example.com": "192.0.2.10", "ghost.example.com": "192.0.2.81"}.get(host)

    monkeypatch.setattr(scanner_dns, "resolve_addresses", fake_addresses)
    monkeypatch.setattr(scanner_dns, "resolve_ip", fake_resolve)
    result = {s["subdomain"]: s for s in asyncio.run(scanner_dns.find_subdomains("example.com"))}
    assert probes == ["sonde.example.com"]
    assert result["ghost.example.com"] == {
        "subdomain": "ghost.example.com",
        "ip": "192.0.2.81",
        "resolution": "resolved",
        "wildcard": True,
    }
    # Adresse propre : la résolution n'est pas celle du joker.
    assert "wildcard" not in result["www.example.com"]
    assert result["api.example.com"]["resolution"] == "unresolved"


def test_sous_domaines_sans_nom_sans_sonde(monkeypatch):
    _serve_crtsh(monkeypatch, lambda request: httpx.Response(200, json=[]))
    probes = []

    async def fake_addresses(host, timeout=None):
        probes.append(host)
        return []

    monkeypatch.setattr(scanner_dns, "resolve_addresses", fake_addresses)
    assert asyncio.run(scanner_dns.find_subdomains("example.com")) == []
    assert probes == []


def test_sous_domaines_une_resolution_en_erreur_n_interrompt_pas(monkeypatch):
    _serve_names(monkeypatch, ["good.example.com", "weird.example.com"])

    async def fake_resolve(host):
        if host.startswith("weird"):
            raise UnicodeError("label vide")
        return "192.0.2.1"

    monkeypatch.setattr(scanner_dns, "resolve_ip", fake_resolve)
    result = {s["subdomain"]: s for s in asyncio.run(scanner_dns.find_subdomains("example.com"))}
    assert result["good.example.com"]["resolution"] == "resolved"
    assert result["weird.example.com"]["resolution"] == "unresolved"


@pytest.mark.parametrize(
    "response",
    [
        httpx.Response(502, text="Bad Gateway"),
        httpx.Response(200, text="<html>erreur</html>"),
        httpx.Response(200, json={"error": "quota"}),
    ],
)
def test_sous_domaines_echec_crtsh_leve_module_error(monkeypatch, response):
    monkeypatch.setattr(scanner_dns, "CRTSH_RETRY_DELAY", 0)
    # Réponse recréée à chaque requête : une erreur passagère est retentée une fois.
    _serve_crtsh(
        monkeypatch,
        lambda request: httpx.Response(
            response.status_code, content=response.content, headers=response.headers
        ),
    )
    with pytest.raises(ModuleError):
        asyncio.run(scanner_dns.find_subdomains("example.com"))


@pytest.mark.parametrize("status", [404, 429, 502, 503])
def test_crtsh_erreur_passagere_retentee_une_fois(monkeypatch, status):
    monkeypatch.setattr(scanner_dns, "CRTSH_RETRY_DELAY", 0)
    responses = [httpx.Response(status), httpx.Response(200, json=[{"name_value": "www.example.com"}])]
    requests = []

    def handler(request):
        requests.append(request)
        return responses.pop(0)

    _serve_crtsh(monkeypatch, handler)
    _no_resolution(monkeypatch)
    result = asyncio.run(scanner_dns.find_subdomains("example.com"))
    assert [entry["subdomain"] for entry in result] == ["www.example.com"]
    assert len(requests) == 2


def test_crtsh_erreur_definitive_non_retentee(monkeypatch):
    monkeypatch.setattr(scanner_dns, "CRTSH_RETRY_DELAY", 0)
    requests = []

    def handler(request):
        requests.append(request)
        return httpx.Response(400)

    _serve_crtsh(monkeypatch, handler)
    with pytest.raises(ModuleError, match="HTTP 400"):
        asyncio.run(scanner_dns.find_subdomains("example.com"))
    # Une seule requête à crt.sh ; la suivante va à la source de secours.
    assert [r.url.host for r in requests] == ["crt.sh", "api.certspotter.com"]


def test_sous_domaines_delai_crtsh_leve_module_error(monkeypatch):
    def handler(request):
        raise httpx.ConnectTimeout("délai", request=request)

    _serve_crtsh(monkeypatch, handler)
    with pytest.raises(ModuleError, match="délai"):
        asyncio.run(scanner_dns.find_subdomains("example.com"))


def test_crtsh_passe_par_le_client_des_api_tierces(monkeypatch):
    """SSRF-7 : crt.sh est interrogé par _api_client (TLS vérifié, redirections non suivies)."""
    from domainrecon.scanner import common

    # Politique de cibles désactivée : le hook ne fait alors aucune résolution DNS réelle.
    monkeypatch.setenv("ALLOW_PRIVATE_TARGETS", "1")
    requests = []

    def handler(request):
        requests.append(request)
        return httpx.Response(302, headers={"Location": "https://attaquant.test/faux.json"})

    def factory(timeout=10.0):
        return common._api_client(timeout, transport=httpx.MockTransport(handler))

    # raising=True (défaut) : échoue si dns.py n'utilise plus _api_client.
    monkeypatch.setattr(scanner_dns, "_api_client", factory)
    assert not hasattr(scanner_dns, "_http_client")

    with pytest.raises(ModuleError, match="HTTP 302"):
        asyncio.run(scanner_dns.find_subdomains("example.com"))
    # Source de secours comprise : même client, redirection non suivie non plus.
    assert [r.url.host for r in requests] == ["crt.sh", "api.certspotter.com"]


def test_sous_domaines_cible_ip_sans_requete(monkeypatch):
    requests = _serve_names(monkeypatch, ["www.example.com"])
    assert asyncio.run(scanner_dns.find_subdomains("192.0.2.1")) == []
    assert requests == []


def test_sous_domaines_reponse_vide(monkeypatch):
    _serve_crtsh(monkeypatch, lambda request: httpx.Response(200, json=[]))
    assert asyncio.run(scanner_dns.find_subdomains("example.com")) == []


class _StreamedBody(httpx.AsyncByteStream):
    """Corps brut livré en streaming, par morceaux de 64 Kio (non lu d'avance)."""

    def __init__(self, data: bytes) -> None:
        self._data = data

    async def __aiter__(self):
        for start in range(0, len(self._data), 65536):
            yield self._data[start : start + 65536]


def _serve_gzip_crtsh(monkeypatch, raw: bytes) -> list:
    requests = []

    def handler(request):
        requests.append(request)
        return httpx.Response(
            200, headers={"Content-Encoding": "gzip"}, stream=_StreamedBody(gzip.compress(raw))
        )

    _serve_crtsh(monkeypatch, handler)
    return requests


def test_crtsh_compresse_decode_en_streaming(monkeypatch):
    names = json.dumps([{"name_value": "www.example.com"}]).encode()
    requests = _serve_gzip_crtsh(monkeypatch, names)

    async def fake_resolve(host):
        return None

    monkeypatch.setattr(scanner_dns, "resolve_ip", fake_resolve)
    result = asyncio.run(scanner_dns.find_subdomains("example.com"))
    assert [s["subdomain"] for s in result] == ["www.example.com"]
    # Seuls les encodages que read_body_limited() décode avec une sortie bornée.
    assert requests[0].headers["accept-encoding"] == "gzip, deflate"


def test_crtsh_bombe_de_decompression_bornee(monkeypatch):
    """La limite de taille porte sur le corps décompressé, sans jamais le décompresser en entier."""
    monkeypatch.setattr(scanner_dns, "CRTSH_MAX_BYTES", 1024 * 1024)
    # La même bombe est servie à la source de secours, bornée elle aussi.
    monkeypatch.setattr(scanner_dns, "CERTSPOTTER_MAX_BYTES", 1024 * 1024)
    # 64 Mio de zéros : environ 64 Kio une fois compressés, un seul morceau lu.
    _serve_gzip_crtsh(monkeypatch, bytes(64 * 1024 * 1024))

    tracemalloc.start()
    try:
        with pytest.raises(ModuleError, match="trop volumineuse"):
            asyncio.run(scanner_dns.find_subdomains("example.com"))
        _, peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()
    assert peak < 16 * 1024 * 1024


def _no_resolution(monkeypatch):
    async def fake_resolve(host):
        return None

    monkeypatch.setattr(scanner_dns, "resolve_ip", fake_resolve)


def test_crtsh_mis_en_cache_par_domaine(monkeypatch):
    """Plusieurs cibles d'un même domaine : une seule requête crt.sh."""
    requests = _serve_names(monkeypatch, ["www.example.com"])
    _no_resolution(monkeypatch)

    async def two_scans():
        first = await scanner_dns.find_subdomains("example.com")
        second = await scanner_dns.find_subdomains("example.com")
        return first, second

    first, second = asyncio.run(two_scans())
    assert first == second
    assert len(requests) == 1
    # Un autre domaine n'utilise pas le cache du premier.
    asyncio.run(scanner_dns.find_subdomains("example.org"))
    assert len(requests) == 2


def test_crtsh_requetes_simultanees_mutualisees(monkeypatch):
    requests = _serve_names(monkeypatch, ["www.example.com", "api.example.com"])
    _no_resolution(monkeypatch)

    async def concurrent_scans():
        return await asyncio.gather(*(scanner_dns.find_subdomains("example.com") for _ in range(3)))

    results = asyncio.run(concurrent_scans())
    assert len(requests) == 1
    assert all(result == results[0] for result in results)


def test_crtsh_echec_non_mis_en_cache(monkeypatch):
    monkeypatch.setattr(scanner_dns, "CRTSH_RETRY_DELAY", 0)
    # crt.sh : deux 503 (tentative et nouvelle tentative), puis la source de
    # secours échoue aussi ; au scan suivant, crt.sh répond.
    responses = [
        httpx.Response(503),
        httpx.Response(503),
        httpx.Response(503),
        httpx.Response(200, json=[{"name_value": "www.example.com"}]),
    ]
    _serve_crtsh(monkeypatch, lambda request: responses.pop(0))
    _no_resolution(monkeypatch)

    with pytest.raises(ModuleError, match="HTTP 503"):
        asyncio.run(scanner_dns.find_subdomains("example.com"))
    result = asyncio.run(scanner_dns.find_subdomains("example.com"))
    assert [entry["subdomain"] for entry in result] == ["www.example.com"]
    assert (result.source, result.partial) == ("crt.sh", False)


def _simulated_clock(monkeypatch):
    """Horloge du cache (cache.cached) simulée ; renvoie la fonction qui l'avance, en secondes."""
    now = [1000.0]
    monkeypatch.setattr(scanner_cache, "_clock", lambda: now[0])

    def advance(seconds):
        now[0] += seconds

    return advance


def test_crtsh_cache_expire(monkeypatch):
    advance = _simulated_clock(monkeypatch)
    requests = _serve_names(monkeypatch, ["www.example.com"])
    _no_resolution(monkeypatch)
    asyncio.run(scanner_dns.find_subdomains("example.com"))
    # Une heure (sous-domaines : MEDIUM_TTL) : encore valable une seconde avant l'échéance.
    assert scanner_dns.CT_CACHE_TTL == scanner_cache.MEDIUM_TTL
    advance(scanner_dns.CT_CACHE_TTL - 1)
    asyncio.run(scanner_dns.find_subdomains("example.com"))
    assert len(requests) == 1
    advance(2)
    asyncio.run(scanner_dns.find_subdomains("example.com"))
    assert len(requests) == 2


# =============================================================================
# Source de secours : Cert Spotter
# =============================================================================


def _serve_ct(monkeypatch, crtsh, certspotter) -> list:
    """crt.sh et Cert Spotter simulés séparément (handlers par hôte) ; renvoie les requêtes."""
    monkeypatch.setattr(scanner_dns, "CRTSH_RETRY_DELAY", 0)
    requests = []

    def handler(request):
        requests.append(request)
        return (crtsh if request.url.host == "crt.sh" else certspotter)(request)

    _serve_crtsh(monkeypatch, handler)
    _no_resolution(monkeypatch)
    return requests


def _issuances(*names_per_cert) -> list:
    return [{"id": str(i), "dns_names": list(names)} for i, names in enumerate(names_per_cert)]


def test_certspotter_prend_le_relais_si_crtsh_echoue(monkeypatch):
    requests = _serve_ct(
        monkeypatch,
        crtsh=lambda request: httpx.Response(502),
        certspotter=lambda request: httpx.Response(
            200, json=_issuances(["example.com", "*.example.com"], ["api.example.com", "mail.example.org"])
        ),
    )
    result = asyncio.run(scanner_dns.find_subdomains("example.com"))
    # Filtrage identique à crt.sh : joker ramené à sa base, autres domaines écartés.
    assert [entry["subdomain"] for entry in result] == ["api.example.com"]
    assert (result.source, result.partial) == ("certspotter", True)
    certspotter = [r for r in requests if r.url.host == "api.certspotter.com"]
    assert len(certspotter) == 1
    params = certspotter[0].url.params
    assert (params["domain"], params["include_subdomains"], params["expand"]) == (
        "example.com",
        "true",
        "dns_names",
    )


def test_certspotter_pagination_bornee(monkeypatch):
    pages = []

    def certspotter(request):
        pages.append(request.url.params.get("after"))
        after = str(100 + len(pages))
        return httpx.Response(
            200,
            json=_issuances([f"n{len(pages)}.example.com"]),
            # URL de la page suivante fournie par le serveur : seul le curseur est repris.
            headers={"Link": f'<https://attaquant.test/issuances?after={after}>; rel="next"'},
        )

    requests = _serve_ct(monkeypatch, crtsh=lambda request: httpx.Response(503), certspotter=certspotter)
    result = asyncio.run(scanner_dns.find_subdomains("example.com"))
    assert pages == [None, "101"][: scanner_dns.CERTSPOTTER_MAX_PAGES]
    assert len(result) == scanner_dns.CERTSPOTTER_MAX_PAGES
    assert {r.url.host for r in requests} == {"crt.sh", "api.certspotter.com"}


def test_certspotter_quota_et_echec_des_deux_sources(monkeypatch):
    _serve_ct(
        monkeypatch,
        crtsh=lambda request: httpx.Response(502),
        certspotter=lambda request: httpx.Response(429),
    )
    with pytest.raises(ModuleError) as excinfo:
        asyncio.run(scanner_dns.find_subdomains("example.com"))
    message = str(excinfo.value)
    assert "crt.sh a répondu HTTP 502" in message
    assert "Cert Spotter : quota de requêtes atteint" in message


def test_certspotter_budget_de_temps(monkeypatch):
    monkeypatch.setattr(scanner_dns, "CERTSPOTTER_BUDGET", 0.05)

    async def slow_certspotter(domain):
        await asyncio.sleep(1)
        return set()

    _serve_ct(monkeypatch, crtsh=lambda request: httpx.Response(502), certspotter=None)
    monkeypatch.setattr(scanner_dns, "_fetch_certspotter_names", slow_certspotter)
    with pytest.raises(ModuleError, match="Cert Spotter : délai dépassé"):
        asyncio.run(scanner_dns.find_subdomains("example.com"))


def test_certspotter_resultat_garde_moins_longtemps(monkeypatch):
    advance = _simulated_clock(monkeypatch)
    requests = _serve_ct(
        monkeypatch,
        crtsh=lambda request: httpx.Response(502),
        certspotter=lambda request: httpx.Response(200, json=_issuances(["www.example.com"])),
    )

    def count(host):
        return sum(1 for request in requests if request.url.host == host)

    result = asyncio.run(scanner_dns.find_subdomains("example.com"))
    assert result.source == "certspotter"
    assert (count("crt.sh"), count("api.certspotter.com")) == (
        2,
        1,
    )  # crt.sh : tentative et nouvelle tentative

    # La source de secours est plus courte que crt.sh : ses résultats, partiels, ne tiennent pas une heure.
    assert scanner_dns.CT_FALLBACK_CACHE_TTL < scanner_dns.CT_CACHE_TTL
    # Dans son délai, Cert Spotter n'est pas réinterrogé ; crt.sh, dont l'échec n'est jamais gardé, l'est.
    advance(scanner_dns.CT_FALLBACK_CACHE_TTL - 1)
    asyncio.run(scanner_dns.find_subdomains("example.com"))
    assert (count("crt.sh"), count("api.certspotter.com")) == (4, 1)
    # Passé son délai, il l'est de nouveau.
    advance(2)
    asyncio.run(scanner_dns.find_subdomains("example.com"))
    assert count("api.certspotter.com") == 2


# =============================================================================
# DNS inverse
# =============================================================================

REVERSE_NAME = "34.216.184.93.in-addr.arpa"


def test_reverse_dns_ptr_trouve(fake_dns):
    fake_dns({(REVERSE_NAME, "PTR"): [rdata("PTR", "host.example.com."), rdata("PTR", "alias.example.com.")]})
    result = asyncio.run(scanner_dns.reverse_dns("93.184.216.34"))
    assert result == {
        "ptr": "host.example.com",
        "aliases": ["alias.example.com"],
        "measured": True,
        "error": None,
    }


def test_reverse_dns_sans_ptr_est_une_mesure(fake_dns):
    fake_dns({})
    result = asyncio.run(scanner_dns.reverse_dns("93.184.216.34"))
    assert result["ptr"] is None
    assert result["measured"] is True
    assert result["error"] is None


def test_reverse_dns_echec_non_mesure(fake_dns):
    fake_dns({(REVERSE_NAME, "PTR"): TIMEOUT})
    result = asyncio.run(scanner_dns.reverse_dns("93.184.216.34"))
    assert result["measured"] is False
    assert fr(result["error"]) == "Requête PTR échouée : délai dépassé"


def test_reverse_dns_sans_ip():
    result = asyncio.run(scanner_dns.reverse_dns(None))
    assert result["measured"] is False
    assert result["error"]


# =============================================================================
# WHOIS
# =============================================================================


@pytest.fixture
def fake_whois(monkeypatch):
    """Remplace python-whois ; `install(réponse ou exception)` renvoie la liste des appels."""

    def install(outcome):
        calls = []

        def fake(domain, **kwargs):
            calls.append((domain, kwargs))
            if isinstance(outcome, BaseException):
                raise outcome
            return outcome

        monkeypatch.setattr(whois_lookup.whois, "whois", fake)
        return calls

    return install


def test_whois_reponse_complete(fake_whois):
    calls = fake_whois(
        types.SimpleNamespace(
            registrar="Registrar SA",
            creation_date=[datetime(2000, 1, 1), datetime(2000, 1, 2)],
            expiration_date=datetime(2030, 1, 1),
            updated_date=None,
            name_servers=["ns1.example.com", "ns2.example.com"],
            status="clientTransferProhibited",
            dnssec="unsigned",
            org=None,
            emails="abuse@registrar.example",
        )
    )
    result = asyncio.run(whois_lookup.get_whois_data("example.com"))
    assert result["measured"] is True
    assert result["registered"] is True
    assert result["error"] is None
    assert result["creation_date"] == "2000-01-01 00:00:00"
    assert result["status"] == ["clientTransferProhibited"]
    assert result["emails"] == ["abuse@registrar.example"]
    # Erreurs réseau non levées (défaut de python-whois) : une erreur sur le
    # second serveur ne doit pas faire perdre la réponse du registre.
    assert "ignore_socket_errors" not in calls[0][1]
    if "timeout" in whois_lookup._WHOIS_PARAMS:
        assert calls[0][1]["timeout"] == whois_lookup.WHOIS_TIMEOUT


@pytest.mark.parametrize(
    "error, message",
    [
        (ConnectionRefusedError("refusé"), "indisponible"),
        (TimeoutError("timed out"), "délai"),
    ],
)
def test_whois_erreur_reseau_non_mesuree(fake_whois, error, message):
    fake_whois(error)
    result = whois_lookup._get_whois_sync("example.com")
    assert result["measured"] is False
    assert message in fr(result["error"])


def test_whois_domaine_non_enregistre(fake_whois):
    fake_whois(whois_lookup.WhoisDomainNotFoundError('No match for "EXAMPLE-LIBRE.COM".'))
    result = whois_lookup._get_whois_sync("example-libre.com")
    assert result["measured"] is True
    assert result["registered"] is False


def test_whois_extension_sans_serveur(fake_whois):
    fake_whois(
        whois_lookup.WhoisDomainNotFoundError(
            "This TLD has no whois server, but you can access the whois database at https://nic.example"
        )
    )
    result = whois_lookup._get_whois_sync("example.zz")
    assert result["measured"] is False
    assert result["error"]


def test_whois_reponse_vide_non_mesuree(fake_whois):
    fake_whois(types.SimpleNamespace())
    result = whois_lookup._get_whois_sync("example.com")
    assert result["measured"] is False
    assert "vide" in fr(result["error"])


def test_whois_cible_ip_sans_requete(fake_whois):
    calls = fake_whois(types.SimpleNamespace(registrar="X"))
    result = whois_lookup._get_whois_sync("93.184.216.34")
    assert result["measured"] is False
    assert result["queried_domain"] is None
    assert calls == []


def test_whois_statuts_epp_dedoublonnes(fake_whois):
    """Régression : registre et bureau d'enregistrement donnaient 6 statuts pour 3 (badssl.com)."""
    fake_whois(
        types.SimpleNamespace(
            registrar="MarkMonitor, Inc.",
            status=[
                "clientDeleteProhibited https://icann.org/epp#clientDeleteProhibited",
                "clientTransferProhibited https://icann.org/epp#clientTransferProhibited",
                "clientUpdateProhibited https://icann.org/epp#clientUpdateProhibited",
                "clientUpdateProhibited (https://www.icann.org/epp#clientUpdateProhibited)",
                "clientTransferProhibited (https://www.icann.org/epp#clientTransferProhibited)",
                "clientDeleteProhibited (https://www.icann.org/epp#clientDeleteProhibited)",
                "client delete prohibited",
                "Registered until expiry date.",
            ],
        )
    )
    result = whois_lookup._get_whois_sync("badssl.com")
    assert result["status"] == [
        "clientDeleteProhibited",
        "clientTransferProhibited",
        "clientUpdateProhibited",
        "Registered until expiry date.",
    ]


def test_whois_domaine_interroge_expose(fake_whois):
    """octocat.github.io : le WHOIS est celui de github.io, le nom interrogé le dit."""
    calls = fake_whois(types.SimpleNamespace(registrar="MarkMonitor, Inc."))
    result = asyncio.run(whois_lookup.get_whois_data("github.io"))
    assert calls[0][0] == "github.io"
    assert result["queried_domain"] == "github.io"


# Réponse du registre .io (github.io) : le parseur WhoisIo range l'organisation
# sous registrant_name et n'extrait ni DNSSEC ni e-mails.
IO_RESPONSE = """Domain Name: github.io
Registrar WHOIS Server: whois.markmonitor.com
Updated Date: 2026-08-12T09:08:04Z
Creation Date: 2013-03-08T19:12:48Z
Registry Expiry Date: 2027-03-08T19:12:48Z
Registrar: MarkMonitor, Inc.
Registrar Abuse Contact Email: abusecomplaints@markmonitor.com
Domain Status: clientDeleteProhibited https://icann.org/epp#clientDeleteProhibited
Registrant Organization: GitHub, Inc.
Registrant Country: US
Name Server: dns1.p05.nsone.net
DNSSEC: unsigned
"""


def test_whois_io_organisation_dnssec_et_emails(fake_whois):
    """Régression : registrant, dnssec et emails vides pour github.io."""
    entry = whois_lookup.whois.parser.WhoisEntry.load("github.io", IO_RESPONSE)
    assert entry.get("org") is None and entry.get("dnssec") is None
    fake_whois(entry)
    result = whois_lookup._get_whois_sync("github.io")
    assert result["measured"] is True
    assert result["registrant"] == "GitHub, Inc."
    assert result["dnssec"] == "unsigned"
    assert result["emails"] == ["abusecomplaints@markmonitor.com"]
    assert result["status"] == ["clientDeleteProhibited"]


@pytest.mark.parametrize("key", ["org", "registrant_org", "registrant_organization"])
def test_whois_organisation_selon_le_parseur(fake_whois, key):
    fake_whois(types.SimpleNamespace(registrar="Registrar SA", **{key: ["Titulaire SA", "Autre"]}))
    assert whois_lookup._get_whois_sync("example.fr")["registrant"] == "Titulaire SA"


def test_whois_reponse_brute_non_exploitable_reste_non_mesuree(fake_whois):
    """Une adresse dans un message de quota ne fait pas d'une réponse vide une mesure."""
    fake_whois(types.SimpleNamespace(text="Quota exceeded, contact abuse@registry.example"))
    result = whois_lookup._get_whois_sync("example.com")
    assert result["measured"] is False
    assert result["emails"] == []


# Réponse « thin » du registre (.com) : désigne le serveur WHOIS du bureau
# d'enregistrement, interrogé en second.
REGISTRY_RESPONSE = """   Domain Name: EXAMPLE.COM
   Registrar WHOIS Server: whois.registrar.test
   Updated Date: 2024-08-14T07:01:34Z
   Creation Date: 1995-08-14T04:00:00Z
   Registry Expiry Date: 2026-08-13T04:00:00Z
   Registrar: Example Registrar, Inc.
   Domain Status: clientTransferProhibited https://icann.org/epp#clientTransferProhibited
   Name Server: A.IANA-SERVERS.NET
   Name Server: B.IANA-SERVERS.NET
   DNSSEC: signedDelegation
"""


@pytest.fixture
def whois_servers(monkeypatch):
    """Serveurs WHOIS simulés au niveau des sockets de python-whois.

    `install({hôte: texte | exception})` ; le registre est whois.registry.test.
    """
    from whois.whois import NICClient

    def install(servers: dict) -> list:
        connected = []

        class FakeSocket:
            host = None
            answered = False

            def settimeout(self, timeout):
                pass

            def connect(self, address):
                self.host = address[0]
                connected.append(self.host)
                outcome = servers[self.host]
                if isinstance(outcome, BaseException):
                    raise outcome

            def send(self, data):
                pass

            def recv(self, size):
                if self.answered:
                    return b""
                self.answered = True
                return servers[self.host].encode()

            def close(self):
                pass

        monkeypatch.setattr(NICClient, "get_socket", staticmethod(FakeSocket))
        monkeypatch.setattr(NICClient, "choose_server", lambda self, domain: "whois.registry.test")
        return connected

    return install


@pytest.mark.parametrize(
    "error",
    [
        socket.gaierror(11001, "getaddrinfo failed"),
        TimeoutError("timed out"),
        ConnectionResetError(10054, "reset"),
    ],
)
def test_whois_second_serveur_injoignable_garde_le_registre(whois_servers, error):
    """Le port 43 du bureau d'enregistrement en panne ne fait pas perdre la réponse du registre."""
    connected = whois_servers({"whois.registry.test": REGISTRY_RESPONSE, "whois.registrar.test": error})
    result = whois_lookup._get_whois_sync("example.com")
    assert connected == ["whois.registry.test", "whois.registrar.test"]
    assert result["measured"] is True
    assert result["registered"] is True
    assert result["error"] is None
    assert result["registrar"] == "Example Registrar, Inc."
    assert result["creation_date"] == "1995-08-14 04:00:00+00:00"
    assert [ns.lower() for ns in result["name_servers"]] == ["a.iana-servers.net", "b.iana-servers.net"]


@pytest.mark.parametrize(
    "error, message",
    [
        (socket.gaierror(11001, "getaddrinfo failed"), "WHOIS indisponible : serveur injoignable"),
        (TimeoutError("timed out"), f"WHOIS : délai dépassé ({whois_lookup.WHOIS_TIMEOUT} s)"),
    ],
)
def test_whois_registre_injoignable_non_mesure(whois_servers, error, message):
    whois_servers({"whois.registry.test": error})
    result = whois_lookup._get_whois_sync("example.com")
    assert result["measured"] is False
    assert result["registered"] is None
    assert fr(result["error"]) == message
