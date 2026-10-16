# =============================================================================
# DomainRecon - Tests du module « bgp » (RIPEstat + Team Cymru), sans réseau
# =============================================================================

import httpx
import pytest

from domainrecon.i18n import msg, render
from domainrecon.scanner import cache
from domainrecon.scanner.errors import ModuleError, ModuleSkipped
from domainrecon.scanner.modules import bgp

RIPE = "https://stat.ripe.net/data/{}/data.json"
CYMRU_ORIGIN = "34.216.184.93.origin.asn.cymru.com"


@pytest.fixture(autouse=True)
def cache_vide():
    cache.clear_cache()
    yield
    cache.clear_cache()


def ripe(data: dict, **top) -> dict:
    return {"status": "ok", "data_call_status": "supported", "data": data, **top}


def routes(**overrides) -> dict:
    """Réponses RIPEstat conformes à la documentation (https://stat.ripe.net/docs/02.data-api/)."""
    table = {
        RIPE.format("prefix-overview"): ripe(
            {
                "announced": True,
                "asns": [{"asn": 15133, "holder": "EDGECAST - Edgecast Networks, Inc."}],
                "resource": "93.184.216.0/24",
                "block": {"desc": "RIPE NCC (Status: ALLOCATED)"},
            }
        ),
        RIPE.format("announced-prefixes"): ripe(
            {
                "prefixes": [
                    {"prefix": "93.184.216.0/24"},
                    {"prefix": "93.184.208.0/20"},
                    {"prefix": "2606:2800::/32"},
                    {"prefix": "pas-un-prefixe"},
                ]
            }
        ),
        RIPE.format("asn-neighbours"): ripe(
            {
                "neighbours": [
                    {"asn": 701, "type": "left", "power": 120, "v4_peers": 30, "v6_peers": 10},
                    {"asn": 64500, "type": "right", "power": 40, "v4_peers": 5, "v6_peers": 0},
                    {"asn": 64501, "type": "bizarre", "power": "x"},
                ]
            }
        ),
        RIPE.format("as-overview"): ripe({"holder": "EDGECAST"}),
    }
    table.update(overrides)
    return table


def zone() -> dict:
    return {
        (CYMRU_ORIGIN, "TXT"): ["15133 | 93.184.216.0/24 | EU | ripencc | 2012-06-22"],
        ("AS15133.asn.cymru.com", "TXT"): ["15133 | US | arin | 2008-12-04 | EDGECAST, US"],
    }


def test_succes_asn_prefixes_et_pairs(http_simule, dns_simule, contexte, outils):
    http_simule(routes())
    dns_simule(zone())
    result = outils.executer(bgp.SPEC, contexte())

    outils.verifier_sortie(result)
    assert result["announced"] is True and result["asn"] == "AS15133"
    assert result["prefix"] == "93.184.216.0/24" and result["country"] == "EU" and result["rir"] == "ripencc"
    assert result["sources"] == ["ripestat", "cymru"]
    # Préfixes : les plus larges d'abord, entrée invalide écartée, IPv4 et IPv6 séparées.
    assert result["prefixes_v4"] == ["93.184.208.0/20", "93.184.216.0/24"]
    assert result["prefixes_v6"] == ["2606:2800::/32"] and result["prefixes_total"] == 3
    # Pairs : triés par puissance ; type inconnu ramené à « uncertain », nombre invalide à 0.
    assert [p["asn"] for p in result["peers"]] == ["AS701", "AS64500", "AS64501"]
    assert result["peers"][2] == {"asn": "AS64501", "type": "uncertain", "power": 0, "v4": 0, "v6": 0}
    assert (result["upstreams"], result["downstreams"], result["peers_total"]) == (1, 1, 3)
    assert result["prefixes_error"] is None and result["peers_error"] is None


def test_adresse_non_annoncee_n_est_pas_une_erreur(http_simule, dns_simule, contexte, outils):
    http_simule(
        routes(
            **{
                RIPE.format("prefix-overview"): ripe(
                    {"announced": False, "asns": [], "resource": "93.184.216.34", "block": {"desc": "RIPE"}}
                )
            }
        )
    )
    dns_simule({})  # Team Cymru : NXDOMAIN
    result = outils.executer(bgp.SPEC, contexte())

    outils.verifier_sortie(result)
    assert result["measured"] is True and result["announced"] is False
    assert result["asn"] is None and result["prefix"] is None and result["peers"] == []


def test_ripestat_en_panne_team_cymru_suffit(http_simule, dns_simule, contexte, outils):
    http_simule(
        routes(
            **{
                RIPE.format("prefix-overview"): (503, {}, "indisponible"),
                RIPE.format("announced-prefixes"): (503, {}, "indisponible"),
                RIPE.format("asn-neighbours"): (503, {}, "indisponible"),
                RIPE.format("as-overview"): (503, {}, "indisponible"),
            }
        )
    )
    dns_simule(zone())
    result = outils.executer(bgp.SPEC, contexte())

    outils.verifier_sortie(result)
    assert result["asn"] == "AS15133" and result["sources"] == ["cymru"]
    assert result["holder"] == "EDGECAST, US"
    # Préfixes et pairs en échec : l'ASN établi est gardé, les erreurs sont détaillées.
    assert result["prefixes_error"] == msg("network.http_status", status=503, service="RIPEstat")
    assert result["peers_error"] == msg("network.http_status", status=503, service="RIPEstat")


def test_aucune_source_ne_repond(http_simule, dns_simule, contexte, outils):
    http_simule({})  # connexion refusée
    dns_simule({("34.216.184.93.origin.asn.cymru.com", "TXT"): TimeoutError})
    with pytest.raises(ModuleError):
        outils.executer(bgp.SPEC, contexte())


def test_delai_depasse(http_simule, dns_simule, contexte, outils):
    http_simule(routes(**{RIPE.format("prefix-overview"): httpx.ReadTimeout("lent")}))
    dns_simule({("34.216.184.93.origin.asn.cymru.com", "TXT"): TimeoutError})
    with pytest.raises(ModuleError) as erreur:
        outils.executer(bgp.SPEC, contexte())
    assert erreur.value.message == msg("net.timeout")


def test_quota_ripestat(http_simule, dns_simule, contexte, outils):
    http_simule(routes(**{RIPE.format("prefix-overview"): (429, {}, "trop de requêtes")}))
    dns_simule({("34.216.184.93.origin.asn.cymru.com", "TXT"): TimeoutError})
    with pytest.raises(ModuleError) as erreur:
        outils.executer(bgp.SPEC, contexte())
    assert erreur.value.message == msg("network.quota", service="RIPEstat")


def test_reponse_illisible_ou_depreciee(http_simule, dns_simule, contexte, outils):
    for corps in (
        (200, {}, "<html>pas du JSON</html>"),
        ripe({"announced": True}, data_call_status="deprecated"),
    ):
        cache.clear_cache()
        http_simule(routes(**{RIPE.format("prefix-overview"): corps}))
        dns_simule({("34.216.184.93.origin.asn.cymru.com", "TXT"): TimeoutError})
        with pytest.raises(ModuleError) as erreur:
            outils.executer(bgp.SPEC, contexte())
        assert erreur.value.message == msg("bgp.unreadable", service="RIPEstat")


def test_sans_objet(contexte, http_simule, outils):
    http_simule({})
    assert bgp.SPEC.skip_reason(contexte(addresses=[])) == msg("orchestrator.no_address")
    with pytest.raises(ModuleSkipped):
        outils.executer(bgp.SPEC, contexte(addresses=["192.168.1.10"]))


def test_adresse_ipv6_nom_cymru():
    from domainrecon.scanner.impl import bgp_sources

    assert bgp_sources.cymru_name("8.8.8.8") == "8.8.8.8.origin.asn.cymru.com"
    assert bgp_sources.cymru_name("2001:4860:4860::8888").endswith(".origin6.asn.cymru.com")
    assert bgp_sources.cymru_name("2001:4860:4860::8888").startswith("8.8.8.8.0.0.0.0")


def test_declaration():
    assert bgp.SPEC.family == "network" and bgp.SPEC.category == "passif" and not bgp.SPEC.keys
    assert render(msg("bgp.not_public"), "en").startswith("Non-public address")
