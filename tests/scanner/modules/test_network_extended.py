# =============================================================================
# DomainRecon - Tests du réseau étendu fusionné (impl/network_extended.py), sans réseau
# =============================================================================
# Le module « network_extended » est historique (il absorbe « reverse_ip ») : son
# adaptateur est un fichier partagé. Ces tests couvrent la logique qu'il doit brancher.
# =============================================================================

import asyncio

import pytest

from domainrecon.i18n import msg
from domainrecon.scanner import cache
from domainrecon.scanner.impl import network_extended

IP = "93.184.216.34"
IPINFO = f"https://ipinfo.io/{IP}/json"
ORIGINE = "https://stat.ripe.net/data/prefix-overview/data.json"
HACKERTARGET = "https://api.hackertarget.com/reverseiplookup/"
ROBTEX = f"https://freeapi.robtex.com/ipquery/{IP}"
CYMRU = "34.216.184.93.origin.asn.cymru.com"


@pytest.fixture(autouse=True)
def cache_vide(dns_simule):
    cache.clear_cache()
    dns_simule({(CYMRU, "TXT"): ["15133 | 93.184.216.0/24 | EU | ripencc | 2012-06-22"]})
    yield
    cache.clear_cache()


def ripe() -> dict:
    return {
        "status": "ok",
        "data_call_status": "supported",
        "data": {
            "announced": True,
            "asns": [{"asn": 15133, "holder": "EDGECAST"}],
            "resource": "93.184.216.0/24",
        },
    }


def scan(domain="example.com", **kwargs):
    return asyncio.run(network_extended.extended_network_scan(IP, domain, **kwargs))


def texte(*lignes) -> tuple:
    return (200, {}, "\n".join(lignes))


def test_succes_asn_et_voisins_filtres(http_simule):
    http_simule(
        {
            IPINFO: {"ip": IP, "hostname": "Edge.Example.NET.", "anycast": True, "country": "US"},
            ORIGINE: ripe(),
            HACKERTARGET: texte(
                "blog.example.org",
                "Blog.Example.org",
                "example.com",
                "0.d.5.9.ip6.arpa",
                "ni un nom !",
                "shop.example.net",
            ),
        }
    )
    result = scan()

    assert result["measured"] is True and result["error"] is None and result["asn_error"] is None
    assert result["asn_info"] == {
        "asn": "AS15133",
        "org": "EDGECAST",
        "hostname": "edge.example.net",
        "anycast": True,
        "prefix": "93.184.216.0/24",
        "country": "EU",
        "rir": "ripencc",
    }
    # Voisins : doublons, noms invalides, bruit .arpa et domaine scanné écartés.
    assert result["reverse_ip_neighbors"] == ["blog.example.org", "shop.example.net"]
    assert result["neighbors_total"] == 2 and result["neighbors_truncated"] is False
    assert result["neighbors_source"] == "hackertarget"


def test_asn_sans_ipinfo(http_simule):
    http_simule({IPINFO: (403, {}, "{}"), ORIGINE: ripe(), HACKERTARGET: texte("a.example.org")})
    result = scan()
    assert result["asn_info"]["asn"] == "AS15133" and result["asn_info"]["hostname"] is None
    assert result["asn_error"] is None and result["measured"] is True


def test_quota_hackertarget_repli_robtex(http_simule):
    http_simule(
        {
            IPINFO: {"ip": IP},
            ORIGINE: ripe(),
            HACKERTARGET: texte("API count exceeded - Increase Quota with Membership"),
            ROBTEX: {
                "status": "ok",
                "pas": [{"o": "vieux.example.org", "t": 1}, {"o": "1.0.0.127.in-addr.arpa", "t": 2}],
            },
        }
    )
    result = scan()
    assert result["reverse_ip_neighbors"] == ["vieux.example.org"] and result["neighbors_source"] == "robtex"
    assert result["neighbors_error"] is None


def test_voisins_indisponibles_l_asn_suffit(http_simule):
    http_simule(
        {
            IPINFO: {"ip": IP},
            ORIGINE: ripe(),
            HACKERTARGET: (500, {}, "panne"),
            ROBTEX: (429, {}, "limite"),
        }
    )
    result = scan()
    assert result["measured"] is True and result["error"] is None
    # L'erreur rendue est celle de la première source (HackerTarget).
    assert result["neighbors_error"] == msg(
        "network.service_error",
        context=msg("network.reverse_ip_unavailable"),
        detail=msg("network.http_status", status=500, service="HackerTarget"),
    )
    assert result["reverse_ip_neighbors"] == [] and result["asn_info"]["asn"] == "AS15133"


def test_rien_ne_repond(http_simule, dns_simule):
    http_simule({})
    dns_simule({(CYMRU, "TXT"): TimeoutError})
    result = scan()
    assert result["measured"] is False and result["error"]["$t"] == "common.join"
    assert result["asn_error"] is not None and result["neighbors_error"] is not None


def test_liste_de_voisins_bornee(http_simule):
    noms = [f"site{i}.example.org" for i in range(75)]
    http_simule({IPINFO: {"ip": IP}, ORIGINE: ripe(), HACKERTARGET: texte(*noms)})
    result = scan()
    assert len(result["reverse_ip_neighbors"]) == 50 and result["neighbors_total"] == 75
    assert result["neighbors_truncated"] is True


def test_adresse_non_publique_ou_absente(http_simule):
    requetes = http_simule({})
    prive = asyncio.run(network_extended.extended_network_scan("10.0.0.1", "x.example.com"))
    assert prive["skipped"] is True and prive["measured"] is False and requetes == []
    absente = asyncio.run(network_extended.extended_network_scan("", "x.example.com"))
    assert absente["skipped"] is True and absente["error"] == msg(
        "network.no_ip", what=msg("network.what_extended")
    )
