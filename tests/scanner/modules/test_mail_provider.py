# =============================================================================
# DomainRecon - Tests du module « mail_provider » (sans réseau)
# =============================================================================

import dns.exception
import pytest

from domainrecon.i18n import render
from domainrecon.scanner.errors import ModuleError
from domainrecon.scanner.impl import mail_provider as impl
from domainrecon.scanner.modules.mail_provider import SPEC
from domainrecon.scanner.rules import FindingInput


def _mx(outils, *valeurs):
    return [outils.rdata("MX", valeur) for valeur in valeurs]


def _a(outils, *noms):
    """Hôtes qui résolvent (adresse A) : sans quoi ils seraient signalés comme MX orphelins."""
    return {(nom, "A"): [outils.rdata("A", "93.184.216.34")] for nom in noms}


def _lancer(outils, contexte, dns_simule, zone, **champs):
    dns_simule(zone)
    resultat = outils.executer(SPEC, contexte(**champs))
    outils.verifier_sortie(resultat)
    return resultat


def _constat(data):
    rule = SPEC.findings[0]
    return rule.check(
        FindingInput({"mail_provider": data}, "mail_provider", lambda s, m: s[m], lambda s, m: True)
    )


def test_declaration():
    assert SPEC.family == "email" and SPEC.category == "passif" and SPEC.keys == ()
    assert SPEC.depends_on == ("email_security",) and SPEC.wave == 2


def test_catalogue_sans_doublon_de_cle():
    assert len(impl.PROVIDERS) == len(impl.PROVIDERS_BY_KEY)


@pytest.mark.parametrize(
    ("hote", "cle"),
    [
        ("aspmx.l.google.com", "google"),
        ("alt1.aspmx.l.google.com", "google"),
        ("gmr-smtp-in.l.google.com", "google"),
        ("exemple-com.mail.protection.outlook.com", "microsoft365"),
        ("mail.protonmail.ch", "proton"),
        ("us-smtp-inbound-1.mimecast.com", "mimecast"),
        ("mx0a-0012345.pphosted.com", "proofpoint"),
        ("d123456a.ess.barracudanetworks.com", "barracuda"),
        ("mxa.global.inbound.cf-emailsecurity.net", "cloudflare_email_security"),
        ("route1.mx.cloudflare.net", "cloudflare_routing"),
    ],
)
def test_reconnaissance_des_mx(hote, cle):
    assert impl.provider_of_mx(hote).key == cle


def test_un_nom_qui_ressemble_n_est_pas_un_fournisseur():
    """Faux positif évité : seul le suffixe de domaine compte, pas une sous-chaîne."""
    assert impl.provider_of_mx("google.com.pirate.example.net") is None
    assert impl.provider_of_mx("notgoogle.com") is None
    assert impl.provider_of_mx("mail.example.com") is None


def test_cibles_spf():
    record = (
        "v=spf1 ip4:1.2.3.4 include:_spf.google.com -include:Hors.Example.Net redirect=autre.example.org ~all"
    )
    assert impl.spf_targets(record) == ["_spf.google.com", "hors.example.net", "autre.example.org"]
    assert impl.spf_targets("v=spf1 include:%{d}.example.com -all") == []


def test_fournisseur_direct(outils, contexte, dns_simule):
    zone = {
        ("example.com", "MX"): _mx(outils, "1 aspmx.l.google.com.", "5 alt1.aspmx.l.google.com."),
        ("example.com", "TXT"): ["v=spf1 include:_spf.google.com include:sendgrid.net ~all"],
        **_a(outils, "aspmx.l.google.com", "alt1.aspmx.l.google.com"),
    }
    resultat = _lancer(outils, contexte, dns_simule, zone)
    assert resultat["mx_provider"]["key"] == "google" and resultat["gateway"] is None
    assert resultat["real_provider"]["key"] == "google" and resultat["confidence"] == "high"
    assert resultat["sending_services"] == [{"key": "sendgrid", "name": "SendGrid"}]
    assert resultat["unresolved_mx"] == []
    assert not _constat(resultat)


def test_passerelle_et_fournisseur_reel_derriere(outils, contexte, dns_simule):
    zone = {
        ("example.com", "MX"): _mx(
            outils, "10 eu-smtp-inbound-1.mimecast.com.", "10 eu-smtp-inbound-2.mimecast.com."
        ),
        ("example.com", "TXT"): [
            "v=spf1 include:eu._netblocks.mimecast.com include:spf.protection.outlook.com -all",
            "MS=ms12345678",
        ],
        ("autodiscover.example.com", "CNAME"): [outils.rdata("CNAME", "autodiscover.outlook.com.")],
        **_a(outils, "eu-smtp-inbound-1.mimecast.com", "eu-smtp-inbound-2.mimecast.com"),
    }
    resultat = _lancer(outils, contexte, dns_simule, zone)
    assert resultat["gateway"]["key"] == "mimecast"
    assert resultat["real_provider"]["key"] == "microsoft365" and resultat["confidence"] == "high"
    types = {e["type"] for e in resultat["evidence"] if e["provider"] == "microsoft365"}
    assert types == {"spf_include", "txt_verification", "autodiscover"}


def test_spf_reutilise_depuis_email_security(outils, contexte, dns_simule):
    """Le SPF déjà lu par email_security évite de le relire (et sert si le TXT est illisible)."""
    zone = {("example.com", "MX"): _mx(outils, "10 mx.mimecast.com."), **_a(outils, "mx.mimecast.com")}
    email = {"spf": {"record": "v=spf1 include:spf.protection.outlook.com ~all"}}
    resultat = _lancer(outils, contexte, dns_simule, zone, results={"email_security": email})
    assert resultat["real_provider"]["key"] == "microsoft365"
    assert impl.spf_from_email_security({"spf": {"record": "pas un spf"}}) is None
    assert impl.spf_from_email_security(None) is None


def test_verification_google_seule_ne_prouve_rien(outils, contexte, dns_simule):
    """Faux positif évité : google-site-verification sert aussi à la Search Console, pas seulement à la messagerie."""
    zone = {
        ("example.com", "MX"): _mx(outils, "10 mx.example.org."),
        ("example.com", "TXT"): ["google-site-verification=abcdef", "yandex-verification=123"],
        **_a(outils, "mx.example.org"),
    }
    resultat = _lancer(outils, contexte, dns_simule, zone)
    assert resultat["real_provider"] is None


def test_auto_heberge(outils, contexte, dns_simule):
    zone = {("example.com", "MX"): _mx(outils, "10 mail.example.com."), **_a(outils, "mail.example.com")}
    resultat = _lancer(outils, contexte, dns_simule, zone)
    assert resultat["self_hosted"] is True and resultat["real_provider"] is None
    assert resultat["confidence"] == "medium"


def test_mx_orphelin(outils, contexte, dns_simule):
    zone = {
        ("example.com", "MX"): _mx(outils, "10 mail.example.com.", "20 disparu.example.net."),
        **_a(outils, "mail.example.com"),
    }
    resultat = _lancer(outils, contexte, dns_simule, zone)
    assert resultat["unresolved_mx"] == ["disparu.example.net"]
    assert _constat(resultat) == {"hosts": ["disparu.example.net"], "count": 1}


def test_mx_nul_et_absence_de_mx(outils, contexte, dns_simule):
    resultat = _lancer(outils, contexte, dns_simule, {("example.com", "MX"): _mx(outils, "0 .")})
    assert resultat["null_mx"] is True and resultat["mx"] == [] and resultat["real_provider"] is None
    resultat = _lancer(outils, contexte, dns_simule, {})
    assert resultat["mx"] == [] and resultat["measured"] is True


def test_repli_sur_le_domaine_enregistrable(outils, contexte, dns_simule):
    zone = {("example.com", "MX"): _mx(outils, "10 aspmx.l.google.com."), **_a(outils, "aspmx.l.google.com")}
    resultat = _lancer(outils, contexte, dns_simule, zone, domain="www.example.com", apex="example.com")
    assert resultat["mail_domain"] == "example.com" and resultat["real_provider"]["key"] == "google"


def test_echec_dns_leve_module_error(outils, contexte, dns_simule):
    """Délai dépassé sur la requête MX : on ne conclut pas à « aucun MX »."""
    dns_simule({("example.com", "MX"): dns.exception.Timeout})
    with pytest.raises(ModuleError) as erreur:
        outils.executer(SPEC, contexte())
    assert "DNS" in render(erreur.value.message, "fr")


def test_sans_objet(contexte):
    assert SPEC.skip_reason(contexte(domain="93.184.216.34")) is not None
    assert (
        SPEC.skip_reason(contexte(domain="mon-site.github.io", apex="github.io", site="mon-site.github.io"))
        is not None
    )
    assert SPEC.skip_reason(contexte()) is None


def test_regles_resistent_aux_donnees_inattendues():
    for data in (None, [], "x", {"unresolved_mx": "a"}, {"unresolved_mx": [1, None]}):
        assert not _constat(data)
