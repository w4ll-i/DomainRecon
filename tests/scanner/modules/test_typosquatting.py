# =============================================================================
# DomainRecon - Tests du module « typosquatting » (sans réseau)
# =============================================================================

from datetime import datetime, timedelta, timezone

import dns.exception
import pytest

from domainrecon.scanner import whois_lookup
from domainrecon.scanner.errors import ModuleError
from domainrecon.scanner.impl import typosquatting as gen
from domainrecon.scanner.modules import typosquatting
from domainrecon.scanner.rules import FindingInput

SPEC = typosquatting.SPEC


# --- Génération --------------------------------------------------------------


def test_decoupage_du_suffixe_public():
    assert gen.split_domain("example.com") == ("example", "com")
    assert gen.split_domain("www.example.co.uk") == ("example", "co.uk")
    assert gen.split_domain("blog.example.com.au") == ("example", "com.au")
    assert gen.split_domain("localhost") is None and gen.split_domain("") is None


def test_variantes_de_example_co_uk():
    variantes = dict(gen.generate("example.co.uk"))
    # Le nom est « example », jamais « example.co » ; le suffixe est conservé.
    assert variantes["exmaple.co.uk"] == "transposition"
    assert variantes["examle.co.uk"] == "omission"
    assert variantes["example.com"] == "tld_swap" and variantes["example.uk"] == "tld_swap"
    assert not any(domaine.startswith("example.co.co") or domaine == "example.co.uk" for domaine in variantes)
    assert "example.co.uk" not in variantes


def test_types_de_variantes():
    variantes = dict(gen.generate("example.com", limit=10**6))
    assert variantes["exampel.com"] == "transposition"
    assert variantes["examplle.com"] == "repetition"
    assert variantes["exarnple.com"] == "ascii_homoglyph"
    assert variantes["ex-ample.com"] == "hyphenation"
    assert variantes["login-example.com"] == "affix"
    assert variantes["examples.com"] == "plural"
    assert variantes["exomple.com"] == "vowel_swap"
    assert variantes["examplr.com"] == "replacement"
    assert variantes["dxample.com"] == "bitsquat"
    assert any(t == "idn_homoglyph" and d.split(".")[0].startswith("xn--") for d, t in variantes.items())


def test_plafond_alterne_les_types_et_est_deterministe():
    premier = gen.generate("example.com", limit=60)
    assert premier == gen.generate("example.com", limit=60)
    assert len({t for _, t in premier}) == len(gen.TYPES)
    assert len(premier) == 60 and len({d for d, _ in premier}) == 60
    assert gen.generate("example.com", limit=10**6)[:60] == premier


def test_aucun_domaine_invalide():
    for domaine, _ in gen.generate("a-b.com", limit=10**6):
        label = domaine.split(".")[0]
        assert not label.startswith("-") and not label.endswith("-") and len(label) <= 63


# --- Classement --------------------------------------------------------------


def _variante(**champs):
    return {
        "domain": "exmaple.com",
        "type": "transposition",
        "ips": ["8.8.8.8"],
        "nameservers": [],
        "has_mx": False,
        **champs,
    }


def test_classement():
    cible = {"target_ips": {"93.184.216.34"}, "target_ns": {"a.iana-servers.net"}}
    assert typosquatting.classify(_variante(ips=["93.184.216.34"]), **cible) == ("defensive", ["same_ip"])
    assert typosquatting.classify(_variante(nameservers=["a.iana-servers.net"]), **cible)[0] == "defensive"
    assert (
        typosquatting.classify(_variante(nameservers=["ns1.sedoparking.com"], has_mx=True), **cible)[0]
        == "parked"
    )
    assert typosquatting.classify(_variante(), **cible) == ("registered", [])
    assert typosquatting.classify(_variante(has_mx=True), **cible) == ("watch", ["mail_capable"])
    assert typosquatting.classify(_variante(recently_registered=True), **cible) == (
        "threat",
        ["recently_registered"],
    )
    assert typosquatting.classify(_variante(type="idn_homoglyph"), **cible)[1] == ["idn_homoglyph"]


def test_cdn_parking_et_age():
    assert typosquatting.is_cdn_address("104.16.1.1") and not typosquatting.is_cdn_address("8.8.8.8")
    assert typosquatting.is_parking_nameserver(
        "NS1.SedoParking.com."
    ) and not typosquatting.is_parking_nameserver("ns.sedo.com")
    maintenant = datetime(2026, 10, 15, tzinfo=timezone.utc)
    assert typosquatting.age_in_days("2026-10-01 00:00:00+00:00", maintenant) == 14
    assert typosquatting.age_in_days(None) is None and typosquatting.age_in_days("inconnu") is None
    assert typosquatting.age_in_days("2099-01-01") is None


# --- Exécution ---------------------------------------------------------------


@pytest.fixture
def fausse_whois(monkeypatch):
    dates = {}

    async def get_whois_data(domaine):
        if domaine not in dates:
            raise OSError("pas de serveur WHOIS")
        return {"creation_date": dates[domaine]}

    monkeypatch.setattr(whois_lookup, "get_whois_data", get_whois_data)
    return dates


def _zone(outils, extra=None):
    a = lambda *ips: [outils.rdata("A", ip) for ip in ips]  # noqa: E731
    zone = {
        ("example.com", "A"): a("93.184.216.34"),
        ("example.com", "NS"): [outils.rdata("NS", "a.iana-servers.net.")],
        ("exmaple.com", "A"): a("8.8.8.8"),
        ("exmaple.com", "NS"): [outils.rdata("NS", "ns1.autre.net.")],
        ("exmaple.com", "MX"): [outils.rdata("MX", "10 mail.autre.net.")],
        ("example.net", "A"): a("93.184.216.34"),
        ("examle.com", "A"): a("1.1.1.1"),
        ("examle.com", "NS"): [outils.rdata("NS", "ns1.sedoparking.com.")],
        ("example.org", "A"): a("104.16.1.1"),
        ("example.org", "NS"): [outils.rdata("NS", "ns1.autre.net.")],
    }
    zone.update(extra or {})
    return zone


def test_succes_et_faux_positifs_evites(contexte, outils, dns_simule, fausse_whois):
    recent = (datetime.now(timezone.utc) - timedelta(days=10)).strftime("%Y-%m-%d %H:%M:%S")
    fausse_whois["exmaple.com"] = recent
    fausse_whois["example.org"] = "2001-01-01 00:00:00"
    idn = next(d for d, t in gen.generate("example.com", limit=10**6) if t == "idn_homoglyph")
    zone = _zone(outils, {(idn, "A"): [outils.rdata("A", "8.8.4.4")]})
    dns_simule(zone)
    sortie = outils.executer(SPEC, contexte())
    outils.verifier_sortie(sortie)
    par_domaine = {v["domain"]: v for v in sortie["variants"]}
    assert par_domaine["exmaple.com"]["status"] == "threat"
    assert (
        par_domaine["exmaple.com"]["reasons"] == ["recently_registered"]
        and par_domaine["exmaple.com"]["has_mx"]
    )
    assert (
        par_domaine["example.net"]["status"] == "defensive" and par_domaine["example.net"]["same_ip"] is True
    )
    assert par_domaine["examle.com"]["status"] == "parked"
    # Adresse de CDN et ancien domaine : enregistré, pas une menace.
    assert par_domaine["example.org"]["status"] == "registered" and par_domaine["example.org"]["cdn"] is True
    assert par_domaine["example.org"]["age_days"] > 365
    assert par_domaine[idn]["status"] == "threat" and par_domaine[idn]["reasons"] == ["idn_homoglyph"]
    assert sortie["threat_count"] == 2 and sortie["active_count"] == 5
    assert (sortie["defensive_count"], sortie["parked_count"], sortie["registered_count"]) == (1, 1, 1)
    assert [v["status"] for v in sortie["variants"]][:2] == ["threat", "threat"]
    assert sortie["variants_checked"] == sortie["variants_generated"] > 100 and sortie["truncated"] is False


def test_rien_trouve(contexte, outils, dns_simule, fausse_whois):
    dns_simule({("example.com", "A"): [outils.rdata("A", "93.184.216.34")]})
    sortie = outils.executer(SPEC, contexte())
    assert sortie["threat_count"] == 0 and sortie["active_count"] == 0 and sortie["variants"] == []
    assert SPEC.score_rules[0].evaluate({"typosquatting": sortie}).points == 3


def test_domaine_co_uk(contexte, outils, dns_simule, fausse_whois):
    dns_simule(
        {
            ("example.co.uk", "A"): [outils.rdata("A", "93.184.216.34")],
            ("exmaple.co.uk", "A"): [outils.rdata("A", "8.8.8.8")],
        }
    )
    sortie = outils.executer(SPEC, contexte(domain="www.example.co.uk", apex="example.co.uk"))
    assert sortie["domain"] == "example.co.uk" and sortie["suffix"] == "co.uk"
    assert [v["domain"] for v in sortie["variants"]] == ["exmaple.co.uk"]


def test_resolveur_qui_reecrit_les_nxdomain(contexte, outils, dns_simule, fausse_whois, monkeypatch):
    class Reecrit:
        timeout = lifetime = None

        def resolve(self, qname, rdtype, lifetime=None, **kwargs):
            return [outils.rdata("A", "8.8.8.8")] if rdtype == "A" else []

    from domainrecon.scanner import dns as scanner_dns

    monkeypatch.setattr(scanner_dns, "_make_resolver", lambda: Reecrit())
    with pytest.raises(ModuleError) as erreur:
        outils.executer(SPEC, contexte())
    assert erreur.value.message["$t"] == "typosquatting.resolver_rewrites"


def test_dns_indisponible(contexte, outils, dns_simule, fausse_whois):
    from domainrecon.scanner.impl import typosquatting as impl

    zone = {("example.com", "A"): dns.exception.Timeout}
    for domaine, _ in impl.generate("example.com", limit=typosquatting.MAX_VARIANTS):
        zone[(domaine, "A")] = dns.exception.Timeout
    dns_simule(zone)
    # Le nom aléatoire de contrôle est en NXDOMAIN, mais toutes les variantes échouent.
    with pytest.raises(ModuleError) as erreur:
        outils.executer(SPEC, contexte())
    assert erreur.value.message["$t"] == "typosquatting.dns_unavailable"


def test_sans_objet_ip_et_plateforme(contexte):
    assert SPEC.skip_reason(contexte(domain="93.184.216.34")) is not None
    assert (
        SPEC.skip_reason(contexte(domain="alice.github.io", apex="github.io", site="alice.github.io"))
        is not None
    )
    assert SPEC.skip_reason(contexte()) is None


def _entree(donnees):
    scan = {"modules": {"typosquatting": {"data": donnees}}}
    return FindingInput(scan, "typosquatting", lambda s, m: s["modules"][m]["data"], lambda s, m: True)


def test_constats_et_score():
    regle = SPEC.findings[0]
    dangereux = {
        "threat_count": 1,
        "variants": [
            {"domain": "exmaple.com", "status": "threat", "reasons": ["recently_registered"], "has_mx": True}
        ],
    }
    moyen = {
        "threat_count": 1,
        "variants": [{"domain": "exmaple.com", "status": "threat", "reasons": ["idn_homoglyph"]}],
    }
    assert regle.check(_entree(dangereux)).severity == "high"
    assert regle.check(_entree(moyen)).severity == "medium"
    assert regle.check(_entree({"threat_count": 0, "variants": [{"status": "registered"}]})) is None
    assert regle.check(_entree("illisible")) is None
    veille = {
        "watch_count": 2,
        "variants": [{"domain": "a.com", "status": "watch"}, {"domain": "b.com", "status": "watch"}],
    }
    assert SPEC.findings[1].check(_entree(veille)) == {"count": 2, "examples": "a.com, b.com"}
    assert (
        SPEC.findings[1].check(_entree(dangereux)) is None and SPEC.findings[1].check(_entree(None)) is None
    )
    assert SPEC.score_rules[0].evaluate({"typosquatting": {"threat_count": 6}}).points == 0
    assert SPEC.score_rules[0].evaluate({"typosquatting": {"threat_count": 1}}).points == 2
