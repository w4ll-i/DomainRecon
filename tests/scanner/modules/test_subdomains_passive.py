# =============================================================================
# DomainRecon - Tests du module « subdomains_passive » : sources complémentaires (sans réseau)
# =============================================================================

import json

import httpx
import pytest

from domainrecon.i18n import render
from domainrecon.scanner import dns as scanner_dns
from domainrecon.scanner.errors import ModuleError
from domainrecon.scanner.impl import subdomain_passive
from domainrecon.scanner.modules import subdomains_passive

SPEC = subdomains_passive.SPEC
CLE = "st-cle-secrete-0123456789abcdef"

HACKERTARGET = "https://api.hackertarget.com/hostsearch/"
RAPIDDNS = "https://rapiddns.io/subdomain/example.com"
ANUBIS = "https://anubisdb.com/anubis/subdomains/example.com"
OTX = "https://otx.alienvault.com/api/v1/indicators/domain/example.com/url_list"
URLSCAN = "https://urlscan.io/api/v1/search/"
WAYBACK = "https://web.archive.org/cdx/search/cdx"
SECURITYTRAILS = "https://api.securitytrails.com/v1/domain/example.com/subdomains"


def _routes(**changes):
    """Réponses conformes aux services (formats vérifiés en direct le 15/10/2026)."""
    routes = {
        HACKERTARGET: (
            200,
            {},
            "vpn.example.com,198.51.100.4\nexample.com,93.184.216.34\nfoo.example.org,1.1.1.1\nMAIL.example.com,1.1.1.2\n",
        ),
        RAPIDDNS: (200, {}, "<table><tr><td>shop.example.com</td><td>CNAME</td></tr></table>"),
        ANUBIS: ["api.example.com", "autre.org", "notexample.com", "*.wild.example.com"],
        OTX: {"url_list": [{"hostname": "blog.example.com", "url": "https://blog.example.com/x"}]},
        URLSCAN: {
            "results": [{"page": {"domain": "app.example.com"}, "task": {"domain": "app.example.com"}}]
        },
        WAYBACK: [["original"], ["https://old.example.com/page"], ["http://www.example.com:80/"]],
    }
    routes.update(changes)
    return routes


@pytest.fixture(autouse=True)
def moteur(monkeypatch):
    """Résolution simulée : tout nom résout, sans joker DNS."""

    async def resolve_ip(name):
        return "93.184.216.34"

    async def no_wildcard(domain):
        return set()

    monkeypatch.setattr(subdomain_passive, "resolve_ip", resolve_ip)
    monkeypatch.setattr(scanner_dns, "_wildcard_addresses", no_wildcard)


def _lancer(contexte, outils, http_simule, routes, secrets=None):
    requetes = http_simule(routes)
    context = contexte(secrets=secrets or {})
    return outils.executer(SPEC, context), requetes


def _noms(sortie):
    return [e["subdomain"] for e in sortie["subdomains"]]


def test_succes_toutes_les_sources(contexte, outils, http_simule):
    sortie, requetes = _lancer(contexte, outils, http_simule, _routes())
    outils.verifier_sortie(sortie)
    assert sorted(_noms(sortie)) == sorted(
        [
            "vpn.example.com",
            "mail.example.com",
            "shop.example.com",
            "api.example.com",
            "wild.example.com",
            "blog.example.com",
            "app.example.com",
            "old.example.com",
            "www.example.com",
        ]
    )
    par_nom = {e["subdomain"]: e for e in sortie["subdomains"]}
    assert par_nom["vpn.example.com"]["sources"] == ["hackertarget"]
    assert par_nom["app.example.com"]["sources"] == ["urlscan"]
    assert all(e["resolution"] == "resolved" and e["ip"] == "93.184.216.34" for e in sortie["subdomains"])
    assert {s["name"]: s["status"] for s in sortie["sources"]} == dict.fromkeys(
        ["hackertarget", "rapiddns", "anubis", "otx", "urlscan", "wayback"], "ok"
    )
    assert sortie["count"] == sortie["total_found"] == 9
    # Aucune requête sans nécessité : pas de SecurityTrails sans clé, pas de crt.sh (module « subdomains »).
    assert {r.url.host for r in requetes} == {
        "api.hackertarget.com",
        "rapiddns.io",
        "anubisdb.com",
        "otx.alienvault.com",
        "urlscan.io",
        "web.archive.org",
    }


def test_faux_positifs_evites(contexte, outils, http_simule):
    """Noms d'un autre domaine, « notexample.com » (pas de frontière de label) et l'apex ne sont jamais des sous-domaines."""
    sortie, _ = _lancer(contexte, outils, http_simule, _routes())
    for faux in ("notexample.com", "foo.example.org", "autre.org", "example.com"):
        assert faux not in _noms(sortie)


def test_rien_trouve(contexte, outils, http_simule):
    routes = {
        HACKERTARGET: (200, {}, "No records found for example.com"),
        RAPIDDNS: (200, {}, "<html></html>"),
        ANUBIS: (404, {}, ""),
        OTX: {"url_list": []},
        URLSCAN: {"results": []},
        WAYBACK: [["original"]],
    }
    sortie, _ = _lancer(contexte, outils, http_simule, routes)
    outils.verifier_sortie(sortie)
    assert sortie["subdomains"] == [] and sortie["count"] == 0 and sortie["measured"] is True


def test_source_en_quota_les_autres_continuent(contexte, outils, http_simule):
    routes = _routes(**{HACKERTARGET: (200, {}, "API count exceeded - Increase Quota with Membership")})
    sortie, _ = _lancer(contexte, outils, http_simule, routes)
    hackertarget = next(s for s in sortie["sources"] if s["name"] == "hackertarget")
    assert hackertarget["status"] == "error" and hackertarget["error"]["$t"] == "network.quota"
    assert "vpn.example.com" not in _noms(sortie) and "shop.example.com" in _noms(sortie)


@pytest.mark.parametrize(
    ("route", "valeur", "source"),
    [
        (RAPIDDNS, httpx.ReadTimeout("lent"), "rapiddns"),
        (URLSCAN, (429, {}, "{}"), "urlscan"),
        (ANUBIS, (200, {}, "pas du json"), "anubis"),
        (OTX, (500, {}, ""), "otx"),
        (WAYBACK, httpx.ConnectError("refusé"), "wayback"),
        (HACKERTARGET, (503, {}, ""), "hackertarget"),
    ],
)
def test_echec_d_une_source_isole(contexte, outils, http_simule, route, valeur, source):
    sortie, _ = _lancer(contexte, outils, http_simule, _routes(**{route: valeur}))
    rapport = next(s for s in sortie["sources"] if s["name"] == source)
    assert rapport["status"] == "error" and rapport["error"] is not None
    assert len(sortie["subdomains"]) >= 4  # les autres sources ont répondu


def test_delai_depasse_d_une_source(contexte, outils, http_simule, monkeypatch):
    """Une source qui traîne est coupée à son délai sans bloquer les autres."""
    import asyncio

    from domainrecon.scanner.impl import subdomain_sources

    async def lente(client, domain):
        await asyncio.sleep(30)
        return set()

    monkeypatch.setattr(
        subdomain_sources,
        "FREE_SOURCES",
        tuple(
            (n, lente if n == "wayback" else f, 0.05 if n == "wayback" else t)
            for n, f, t in subdomain_sources.FREE_SOURCES
        ),
    )
    sortie, _ = _lancer(contexte, outils, http_simule, _routes())
    wayback = next(s for s in sortie["sources"] if s["name"] == "wayback")
    assert wayback["status"] == "error" and wayback["error"]["$t"] == "net.timeout"
    assert "shop.example.com" in _noms(sortie)


def test_toutes_les_sources_en_echec(contexte, outils, http_simule):
    http_simule({})
    with pytest.raises(ModuleError) as erreur:
        outils.executer(SPEC, contexte())
    assert erreur.value.message["$t"] == "subdomains_passive.all_failed"


def test_joker_dns_marque_les_entrees(contexte, outils, http_simule, monkeypatch):
    async def wildcard(domain):
        return {"93.184.216.34"}

    monkeypatch.setattr(scanner_dns, "_wildcard_addresses", wildcard)
    sortie, _ = _lancer(contexte, outils, http_simule, _routes())
    assert sortie["subdomains"] and all(e.get("wildcard") is True for e in sortie["subdomains"])


def test_nombre_de_noms_resolus_borne(contexte, outils, http_simule):
    lignes = chr(10).join(f"h{i}.example.com,198.51.100.1" for i in range(45))
    sortie, _ = _lancer(contexte, outils, http_simule, _routes(**{HACKERTARGET: (200, {}, lignes)}))
    etats = [e["resolution"] for e in sortie["subdomains"]]
    assert etats.count("resolved") == subdomain_passive.RESOLVE_LIMIT
    assert etats.count("not_tested") == len(etats) - subdomain_passive.RESOLVE_LIMIT


def test_cle_securitytrails_facultative(contexte, outils, http_simule):
    """Avec la clé, SecurityTrails s'ajoute : elle voyage en en-tête et n'apparaît nulle part dans le résultat."""
    routes = _routes(
        **{SECURITYTRAILS: {"endpoint": "/v1/domain/example.com/subdomains", "subdomains": ["intranet"]}}
    )
    sortie, requetes = _lancer(contexte, outils, http_simule, routes, {"securitytrails_key": CLE})
    outils.verifier_sortie(sortie, [CLE])
    assert "intranet.example.com" in _noms(sortie)
    appel = next(r for r in requetes if r.url.host == "api.securitytrails.com")
    assert appel.headers["apikey"] == CLE and CLE not in str(appel.url)


def test_securitytrails_cle_refusee_n_est_pas_fatale(contexte, outils, http_simule):
    routes = _routes(**{SECURITYTRAILS: (401, {}, '{"message":"Please check user credentials"}')})
    sortie, _ = _lancer(contexte, outils, http_simule, routes, {"securitytrails_key": CLE})
    rapport = next(s for s in sortie["sources"] if s["name"] == "securitytrails")
    assert rapport["status"] == "error" and CLE not in json.dumps(render(sortie, "fr"))


def test_erreur_inattendue_d_une_source_isolee(contexte, outils, http_simule, monkeypatch):
    from domainrecon.scanner.impl import subdomain_sources

    async def casse(client, domain):
        raise RuntimeError("bogue interne")

    monkeypatch.setattr(
        subdomain_sources,
        "FREE_SOURCES",
        tuple((n, casse if n == "anubis" else f, t) for n, f, t in subdomain_sources.FREE_SOURCES),
    )
    sortie, _ = _lancer(contexte, outils, http_simule, _routes())
    anubis = next(s for s in sortie["sources"] if s["name"] == "anubis")
    assert anubis["status"] == "error" and "bogue interne" not in json.dumps(sortie)
    assert "shop.example.com" in _noms(sortie)


def test_adresse_ip_sans_objet(contexte):
    assert SPEC.skip_reason(contexte(domain="93.184.216.34")) is not None


def test_declaration():
    assert SPEC.family == "dns" and SPEC.category == "passif" and SPEC.optional is True
    assert [k.name for k in SPEC.keys] == ["securitytrails_key"] and SPEC.keys[0].required is False
