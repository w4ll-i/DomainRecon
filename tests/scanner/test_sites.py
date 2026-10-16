# =============================================================================
# DomainRecon - Tests du site d'une cible (PSL, section privée comprise)
# =============================================================================
# site_domain() : domaine enregistrable au sens de la PSL complète. L'hôte d'une
# plateforme mutualisée (alice.github.io, x.herokuapp.com) n'est pas confondu
# avec la plateforme, contrairement à registrable_domain() (section ICANN).
# La sonde de joker DNS de l'onglet DNS vise ce site, comme l'énumération crt.sh.
# Liste PSL embarquée et résolveur simulé : aucun accès réseau.
# =============================================================================

import socket

import dns.resolver
import pytest

from domainrecon.scanner import dns as scanner_dns
from domainrecon.scanner import registrable_domain, site_domain, targets
from domainrecon.scanner.http_utils import site_of


@pytest.fixture(autouse=True)
def no_network(monkeypatch):
    """La PSL embarquée suffit : tout accès réseau fait échouer le test."""

    def refuse(*args, **kwargs):
        raise AssertionError("Accès réseau interdit : la PSL doit être lue hors ligne")

    for name in ("getaddrinfo", "create_connection"):
        monkeypatch.setattr(socket, name, refuse)


@pytest.mark.parametrize(
    "host, site, apex",
    [
        ("alice.github.io", "alice.github.io", "github.io"),
        ("www.alice.github.io", "alice.github.io", "github.io"),
        ("myapp.herokuapp.com", "myapp.herokuapp.com", "herokuapp.com"),
        ("foo.netlify.app", "foo.netlify.app", "netlify.app"),
        ("x.pages.dev", "x.pages.dev", "pages.dev"),
        ("site.azurewebsites.net", "site.azurewebsites.net", "azurewebsites.net"),
        ("foo.s3.amazonaws.com", "foo.s3.amazonaws.com", "amazonaws.com"),
        ("d111.cloudfront.net", "d111.cloudfront.net", "cloudfront.net"),
        ("foo.bar.blogspot.com", "bar.blogspot.com", "blogspot.com"),
    ],
)
def test_hote_d_une_plateforme_mutualisee(host, site, apex):
    """Section privée de la PSL : le site est le compte hébergé, pas la plateforme."""
    assert site_domain(host) == site
    # Le WHOIS garde le nom connu du registre.
    assert registrable_domain(host) == apex
    # Même notion de site que le suivi des redirections (http_utils).
    assert site_of(host) == site


@pytest.mark.parametrize(
    "host, expected",
    [
        ("example.com", "example.com"),
        ("blog.example.com", "example.com"),
        ("a.b.example.co.uk", "example.co.uk"),
        ("xn--bcher-kva.example.com", "example.com"),
    ],
)
def test_domaine_ordinaire_site_egal_a_l_apex(host, expected):
    assert site_domain(host) == registrable_domain(host) == expected


@pytest.mark.parametrize(
    "host, expected",
    [
        # Suffixe privé d'un seul niveau : la plateforme elle-même.
        ("github.io", "github.io"),
        # Hôte qui est lui-même un suffixe privé : il appartient à la plateforme.
        ("s3.amazonaws.com", "amazonaws.com"),
    ],
)
def test_plateforme_elle_meme(host, expected):
    assert site_domain(host) == registrable_domain(host) == expected


@pytest.mark.parametrize("host", ["localhost", "93.184.216.34", "2001:db8::1", "co.uk"])
def test_ip_ou_nom_sans_domaine_enregistrable_rendu_tel_quel(host):
    """Même convention que registrable_domain()."""
    assert site_domain(host) == registrable_domain(host) == host


def test_extracteur_hors_ligne_avec_section_privee():
    assert targets._SITE_EXTRACT.suffix_list_urls == ()
    assert targets._SITE_EXTRACT.include_psl_private_domains is True
    # L'extracteur historique reste limité à la section ICANN.
    assert targets._TLD_EXTRACT.include_psl_private_domains is False


@pytest.mark.parametrize(
    "host, probe",
    [
        # *.github.io répond pour tout compte : seul un joker du site hébergé compte.
        ("www.alice.github.io", "sonde.alice.github.io"),
        ("expired.badssl.com", "sonde.badssl.com"),
    ],
)
def test_joker_dns_sonde_sur_le_site(monkeypatch, host, probe):
    queries = []

    class NxdomainResolver:
        timeout = None

        def resolve(self, qname, rdtype, lifetime=None, **kwargs):
            queries.append(str(qname))
            raise dns.resolver.NXDOMAIN()

    monkeypatch.setattr(scanner_dns, "_make_resolver", NxdomainResolver)
    monkeypatch.setattr(scanner_dns, "_wildcard_probe_name", lambda domain: f"sonde.{domain}")
    records = scanner_dns._scan_dns_sync(host)
    assert [q for q in queries if q.startswith("sonde.")] == [probe]
    assert records["wildcard"] is False
