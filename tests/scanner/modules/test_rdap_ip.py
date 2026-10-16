# =============================================================================
# DomainRecon - Tests du module « rdap_ip » (RDAP des registres), sans réseau
# =============================================================================

import json

import httpx
import pytest

from domainrecon.i18n import msg
from domainrecon.scanner import cache
from domainrecon.scanner.errors import ModuleError, ModuleSkipped
from domainrecon.scanner.modules import rdap_ip

BOOTSTRAP = "https://data.iana.org/rdap/ipv4.json"
RIPE_URL = "https://rdap.db.ripe.net/ip/93.184.216.34"
HEADERS = {"content-type": "application/rdap+json"}


@pytest.fixture(autouse=True)
def cache_vide():
    cache.clear_cache()
    yield
    cache.clear_cache()


def amorcage() -> dict:
    """Table d'amorçage de l'IANA (https://data.iana.org/rdap/ipv4.json), abrégée."""
    return {
        "description": "RDAP bootstrap file for IPv4 address allocations",
        "services": [
            [
                ["41.0.0.0/8", "102.0.0.0/8"],
                ["https://rdap.afrinic.net/rdap/", "http://rdap.afrinic.net/rdap/"],
            ],
            [["93.0.0.0/8"], ["http://rdap.db.ripe.net/", "https://rdap.db.ripe.net/"]],
            ["pas", "une", "entrée"],
        ],
    }


def objet_ripe() -> dict:
    """Réponse RDAP de RIPE NCC (forme réelle : une personne physique, un mainteneur, un contact abuse)."""
    return {
        "objectClassName": "ip network",
        "handle": "93.184.216.0 - 93.184.216.255",
        "startAddress": "93.184.216.0",
        "endAddress": "93.184.216.255",
        "ipVersion": "v4",
        "name": "EDGECAST-NETBLK-03",
        "type": "ASSIGNED PA",
        "country": "EU",
        "parentHandle": "93.184.208.0 - 93.184.223.255",
        "cidr0_cidrs": [{"v4prefix": "93.184.216.0", "length": 24}],
        "status": ["active"],
        "events": [
            {"eventAction": "registration", "eventDate": "2012-06-22T21:48:41Z"},
            {"eventAction": "last changed", "eventDate": "2013-01-01T00:00:00Z"},
        ],
        "entities": [
            {
                "handle": "DS7892-RIPE",
                "roles": ["administrative", "technical"],
                "vcardArray": [
                    "vcard",
                    [["fn", {}, "text", "Jean Dupont"], ["kind", {}, "text", "individual"]],
                ],
            },
            {
                "handle": "AR13582-RIPE",
                "roles": ["abuse"],
                "vcardArray": [
                    "vcard",
                    [
                        ["fn", {}, "text", "Abuse-C Role"],
                        ["kind", {}, "text", "group"],
                        ["email", {"type": "abuse"}, "text", "abuse@example.net"],
                    ],
                ],
            },
            {
                "handle": "ORG-EDGE1-RIPE",
                "roles": ["registrant"],
                "vcardArray": [
                    "vcard",
                    [
                        ["fn", {}, "text", "Edgio"],
                        ["org", {}, "text", "Edgio, Inc."],
                        ["kind", {}, "text", "org"],
                    ],
                ],
            },
        ],
    }


def test_succes_via_le_registre_de_l_amorcage(http_simule, contexte, outils):
    requetes = http_simule({BOOTSTRAP: amorcage(), RIPE_URL: (200, HEADERS, json.dumps(objet_ripe()))})
    result = outils.executer(rdap_ip.SPEC, contexte())

    outils.verifier_sortie(result)
    assert result["found"] is True and result["source"] == "rdap.db.ripe.net"
    assert result["name"] == "EDGECAST-NETBLK-03" and result["country"] == "EU"
    assert result["cidrs"] == ["93.184.216.0/24"] and result["start"] == "93.184.216.0"
    assert result["registered"] == "2012-06-22T21:48:41Z" and result["last_changed"] == "2013-01-01T00:00:00Z"
    assert result["organization"] == "Edgio, Inc." and result["abuse_email"] == "abuse@example.net"
    # Aucune donnée personnelle : le nom de la personne physique n'est nulle part.
    assert "Jean Dupont" not in str(result)
    # L'URL de base https de l'amorçage est utilisée (pas l'URL http).
    assert [str(r.url) for r in requetes] == [BOOTSTRAP, RIPE_URL]


def test_amorcage_indisponible_agregateur_et_redirection(http_simule, contexte, outils):
    redirection = (302, {"location": RIPE_URL}, "")
    requetes = http_simule(
        {
            BOOTSTRAP: (503, {}, "panne"),
            "https://rdap.org/ip/93.184.216.34": redirection,
            RIPE_URL: objet_ripe(),
        }
    )
    result = outils.executer(rdap_ip.SPEC, contexte())

    assert result["found"] is True and result["name"] == "EDGECAST-NETBLK-03"
    assert [r.url.host for r in requetes] == ["data.iana.org", "rdap.org", "rdap.db.ripe.net"]


def test_redirection_vers_http_refusee(http_simule, contexte, outils):
    http_simule(
        {
            BOOTSTRAP: (503, {}, "panne"),
            "https://rdap.org/ip/93.184.216.34": (
                302,
                {"location": "http://rdap.db.ripe.net/ip/93.184.216.34"},
                "",
            ),
        }
    )
    with pytest.raises(ModuleError) as erreur:
        outils.executer(rdap_ip.SPEC, contexte())
    assert erreur.value.message == msg("rdap_ip.unreadable", service="RDAP")


def test_adresse_inconnue_du_registre(http_simule, contexte, outils):
    http_simule({BOOTSTRAP: amorcage(), RIPE_URL: (404, HEADERS, "{}")})
    result = outils.executer(rdap_ip.SPEC, contexte())
    outils.verifier_sortie(result)
    assert result["measured"] is True and result["found"] is False


def test_echec_http_quota_et_delai(http_simule, contexte, outils):
    for reponse, attendu in (
        ((500, {}, "erreur"), msg("network.http_status", status=500, service="RDAP")),
        ((429, {}, "limite"), msg("network.quota", service="RDAP")),
        (httpx.ReadTimeout("lent"), msg("net.timeout")),
    ):
        cache.clear_cache()
        http_simule({BOOTSTRAP: amorcage(), RIPE_URL: reponse})
        with pytest.raises(ModuleError) as erreur:
            outils.executer(rdap_ip.SPEC, contexte())
        assert erreur.value.message == attendu


def test_reponse_illisible(http_simule, contexte, outils):
    for corps in ("<html>pas du JSON</html>", "[1, 2]", '{"objectClassName": "domain"}'):
        cache.clear_cache()
        http_simule({BOOTSTRAP: amorcage(), RIPE_URL: (200, HEADERS, corps)})
        with pytest.raises(ModuleError) as erreur:
            outils.executer(rdap_ip.SPEC, contexte())
        assert erreur.value.message == msg("rdap_ip.unreadable", service="RDAP")


def test_sans_objet(contexte, http_simule, outils):
    http_simule({})
    assert rdap_ip.SPEC.skip_reason(contexte(addresses=[])) == msg("orchestrator.no_address")
    with pytest.raises(ModuleSkipped):
        outils.executer(rdap_ip.SPEC, contexte(addresses=["10.0.0.5"]))


def test_ipv6_utilise_la_table_ipv6(http_simule, contexte, outils):
    ipv6 = "2606:4700:4700::1111"
    arin = "https://rdap.arin.net/registry/ip/" + ipv6
    requetes = http_simule(
        {
            "https://data.iana.org/rdap/ipv6.json": {
                "services": [[["2600::/12"], ["https://rdap.arin.net/registry/"]]]
            },
            arin: {
                "objectClassName": "ip network",
                "name": "CLOUDFLARENET",
                "ipVersion": "v6",
                "cidr0_cidrs": [{"v6prefix": "2606:4700::", "length": 32}],
            },
        }
    )
    result = outils.executer(rdap_ip.SPEC, contexte(addresses=[ipv6]))
    assert result["cidrs"] == ["2606:4700::/32"] and result["name"] == "CLOUDFLARENET"
    assert requetes[0].url.path == "/rdap/ipv6.json"
