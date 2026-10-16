# =============================================================================
# DomainRecon - Tests de la géolocalisation fusionnée (impl/geo_data.py), sans réseau
# =============================================================================
# Le module « geo_data » est historique : son adaptateur (modules/geo_data.py) est
# un fichier partagé. Ces tests couvrent la logique qu'il doit brancher.
# =============================================================================

import asyncio

import httpx
import pytest

from domainrecon.i18n import msg
from domainrecon.scanner import cache
from domainrecon.scanner.impl import geo_data

IPINFO = "https://ipinfo.io/93.184.216.34/json"
GEOLOC = "https://stat.ripe.net/data/geoloc/data.json"
ORIGINE = "https://stat.ripe.net/data/prefix-overview/data.json"
CYMRU = "34.216.184.93.origin.asn.cymru.com"
JETON = "ipinfo-jeton-secret-0123456789"


@pytest.fixture(autouse=True)
def cache_vide(dns_simule):
    cache.clear_cache()
    # Team Cymru : NXDOMAIN par défaut (adresse non annoncée) ; un test peut réinstaller sa zone.
    dns_simule({})
    yield
    cache.clear_cache()


def ipinfo(**plus) -> dict:
    """Réponse anonyme d'ipinfo.io en octobre 2026 : position, mais sans « org »."""
    return {
        "ip": "93.184.216.34",
        "city": "Phoenix",
        "region": "Arizona",
        "country": "US",
        "loc": "33.5851,-112.0087",
        "postal": "85028",
        "timezone": "America/Phoenix",
        "readme": "https://ipinfo.io/missingauth",
        **plus,
    }


def ripe(data: dict) -> dict:
    return {"status": "ok", "data_call_status": "supported", "data": data}


def annonce() -> dict:
    return ripe(
        {"announced": True, "asns": [{"asn": 15133, "holder": "EDGECAST"}], "resource": "93.184.216.0/24"}
    )


def geo(ip="93.184.216.34", **kwargs):
    return asyncio.run(geo_data.get_geo_data(ip, **kwargs))


def test_position_ipinfo_et_asn_complete_par_ripestat(http_simule):
    http_simule({IPINFO: ipinfo(), ORIGINE: annonce()})
    result = geo()

    assert result["measured"] is True and result["error"] is None and result["source"] == "ipinfo"
    assert (result["country"], result["country_code"], result["city"], result["zip"]) == (
        "US",
        "US",
        "Phoenix",
        "85028",
    )
    assert (result["lat"], result["lon"]) == (33.5851, -112.0087) and result["timezone"] == "America/Phoenix"
    # L'organisation absente de la réponse anonyme vient de RIPEstat.
    assert (
        result["as_info"] == "AS15133 EDGECAST"
        and result["org"] == "EDGECAST"
        and result["isp"] == "EDGECAST"
    )


def test_jeton_envoye_en_bearer_et_jamais_rendu(http_simule):
    requetes = http_simule(
        {IPINFO: ipinfo(org="AS15133 Edgecast Networks, Inc.", anycast=True), ORIGINE: annonce()}
    )
    result = geo(token=JETON)

    assert (
        result["as_info"] == "AS15133 Edgecast Networks, Inc." and result["org"] == "Edgecast Networks, Inc."
    )
    assert result["anycast"] is True
    assert requetes[0].headers["authorization"] == f"Bearer {JETON}" and JETON not in str(requetes[0].url)
    assert JETON not in str(result)


def test_ipinfo_en_echec_repli_ripestat(http_simule):
    for reponse in (
        (403, {}, '{"status":403,"error":{"title":"Unknown token"}}'),
        (429, {}, "limite"),
        httpx.ReadTimeout("lent"),
    ):
        cache.clear_cache()
        http_simule(
            {
                IPINFO: reponse,
                GEOLOC: ripe(
                    {
                        "located_resources": [
                            {
                                "resource": "93.184.216.34/32",
                                "locations": [
                                    {"country": "US", "city": "", "latitude": 37.751, "longitude": -97.822}
                                ],
                            }
                        ]
                    }
                ),
                ORIGINE: annonce(),
            }
        )
        result = geo()
        assert result["measured"] is True and result["source"] == "ripestat" and result["error"] is None
        assert (result["country"], result["city"], result["lat"], result["lon"]) == (
            "US",
            "",
            37.751,
            -97.822,
        )
        assert result["as_info"] == "AS15133 EDGECAST"


def test_aucune_source_ne_repond(http_simule, dns_simule):
    http_simule({IPINFO: (503, {}, "panne")})
    dns_simule({(CYMRU, "TXT"): TimeoutError})
    result = geo()
    assert result["measured"] is False and result["source"] is None and result["country"] == ""
    assert result["error"] == msg("network.http_status", status=503, service="ipinfo.io")


def test_erreur_ipinfo_dans_le_corps(http_simule):
    http_simule(
        {
            IPINFO: {"error": {"title": "Wrong ip"}},
            GEOLOC: ripe({"located_resources": []}),
            ORIGINE: annonce(),
        }
    )
    result = geo()
    assert result["measured"] is False and result["error"] == msg("network.ipinfo_error")


def test_adresse_non_publique_sans_objet(http_simule):
    requetes = http_simule({})
    result = geo("192.168.1.10")
    assert result["measured"] is False and result["skipped"] is True and requetes == []
    assert result["error"] == msg("network.not_public", what=msg("network.what_geo"))
    assert geo(None)["skipped"] is True
    assert geo("pas-une-ip")["skipped"] is False


def test_une_requete_par_adresse_grace_au_cache(http_simule):
    requetes = http_simule({IPINFO: ipinfo(), ORIGINE: annonce()})
    geo()
    geo()
    assert [r.url.host for r in requetes].count("ipinfo.io") == 1
