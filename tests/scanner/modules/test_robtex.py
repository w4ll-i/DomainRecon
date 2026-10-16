# =============================================================================
# DomainRecon - Tests du module « robtex » (DNS passif), sans réseau
# =============================================================================

import json

import httpx
import pytest

from domainrecon.i18n import msg
from domainrecon.scanner import cache
from domainrecon.scanner.errors import ModuleError
from domainrecon.scanner.modules import robtex

FORWARD = "https://freeapi.robtex.com/pdns/forward/example.com"
IPQUERY = "https://freeapi.robtex.com/ipquery/93.184.216.34"


@pytest.fixture(autouse=True)
def cache_vide():
    cache.clear_cache()
    yield
    cache.clear_cache()


def lignes(*rows: dict) -> tuple:
    """Réponse NDJSON de /pdns/forward (une ligne JSON par enregistrement)."""
    return (200, {"content-type": "application/x-ndjson"}, "\n".join(json.dumps(r) for r in rows) + "\n")


def row(rtype: str, data: str, first=1433818966, last=1792067214, count=2) -> dict:
    return {
        "rrname": "example.com",
        "rrdata": data,
        "rrtype": rtype,
        "time_first": first,
        "time_last": last,
        "count": count,
    }


def test_succes_enregistrements_et_adresses_historiques(http_simule, contexte, outils):
    http_simule(
        {
            FORWARD: lignes(
                row("A", "93.184.216.34"),
                row("A", "198.51.100.7"),
                row("A", "198.51.100.7"),  # doublon
                row("MX", "Mail.Example.COM."),
                row("NS", "a.iana-servers.net"),
                {"rrname": "example.com"},  # ligne invalide : ignorée
            )
        }
    )
    result = outils.executer(robtex.SPEC, contexte())

    outils.verifier_sortie(result)
    assert result["mode"] == "domain" and result["total"] == 4
    assert result["by_type"] == {"A": 2, "MX": 1, "NS": 1}
    # L'adresse actuelle de la cible n'est pas « historique » ; l'ancienne l'est.
    assert result["historical_ips"] == ["198.51.100.7"]
    mx = next(r for r in result["records"] if r["type"] == "MX")
    assert mx["data"] == "mail.example.com" and mx["first_seen"] == "2015-06-09"


def test_cible_ip_utilise_ipquery(http_simule, contexte, outils):
    http_simule(
        {
            "https://freeapi.robtex.com/ipquery/93.184.216.34": {
                "status": "ok",
                "as": 15133,
                "bgproute": "93.184.216.0/24",
                "asname": "EDGECAST",
                "country": "US",
                "pas": [{"o": "Blogs.Example.org", "t": 1}, {"o": "blogs.example.org", "t": 2}],
                "act": [{"o": "autre.example.net", "t": 3}],
            }
        }
    )
    result = outils.executer(robtex.SPEC, contexte(domain="93.184.216.34"))

    outils.verifier_sortie(result)
    assert result["mode"] == "ip" and result["asn"] == "AS15133" and result["network"] == "93.184.216.0/24"
    assert result["names"] == ["blogs.example.org", "autre.example.net"]


def test_rien_trouve(http_simule, contexte, outils):
    http_simule({FORWARD: (200, {}, "")})
    result = outils.executer(robtex.SPEC, contexte())
    outils.verifier_sortie(result)
    assert result["measured"] is True and result["records"] == [] and result["historical_ips"] == []


def test_quota_http_429_et_corps_ratelimited(http_simule, contexte, outils):
    for reponse in ((429, {}, '{"status":"ratelimited"}'), (200, {}, '{"status":"ratelimited"}')):
        cache.clear_cache()
        http_simule({FORWARD: reponse})
        with pytest.raises(ModuleError) as erreur:
            outils.executer(robtex.SPEC, contexte())
        assert erreur.value.message == msg("network.quota", service="Robtex")


def test_echec_http_et_delai(http_simule, contexte, outils):
    for reponse, attendu in (
        ((502, {}, "x"), msg("network.http_status", status=502, service="Robtex")),
        (httpx.ConnectTimeout("lent"), msg("net.timeout")),
        (httpx.ConnectError("refusé"), msg("network.service_error", context="Robtex", detail="ConnectError")),
    ):
        cache.clear_cache()
        http_simule({FORWARD: reponse})
        with pytest.raises(ModuleError) as erreur:
            outils.executer(robtex.SPEC, contexte())
        assert erreur.value.message == attendu


def test_reponse_illisible(http_simule, contexte, outils):
    http_simule({FORWARD: (200, {}, "<html>maintenance</html>\n<p>ok</p>")})
    with pytest.raises(ModuleError) as erreur:
        outils.executer(robtex.SPEC, contexte())
    assert erreur.value.message == msg("robtex.unreadable")

    cache.clear_cache()
    http_simule({IPQUERY: {"status": "error"}})
    with pytest.raises(ModuleError):
        outils.executer(robtex.SPEC, contexte(domain="93.184.216.34"))


def test_une_seule_requete_par_scan(http_simule, contexte, outils):
    requetes = http_simule({FORWARD: lignes(row("A", "93.184.216.34"))})
    outils.executer(robtex.SPEC, contexte())
    outils.executer(robtex.SPEC, contexte())  # même domaine : réponse gardée en cache (quota de 10 par heure)
    assert len(requetes) == 1
