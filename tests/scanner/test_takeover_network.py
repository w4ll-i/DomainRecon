# =============================================================================
# DomainRecon - Tests du takeover (exactitude, couverture), du scan de ports et
# du réseau étendu
# =============================================================================
# Aucun trafic réseau réel : DNS simulé pour le takeover, httpx.MockTransport
# pour les pages des fournisseurs et pour les services tiers (ipinfo.io,
# HackerTarget), connexions TCP simulées pour le scan de ports.
# =============================================================================

import asyncio
import time

import httpx
import pytest

from domainrecon.scanner import common, network, targets
from domainrecon.scanner import takeover as takeover_module
from domainrecon.scanner.errors import ModuleError
from domainrecon.scanner.score import compute_security_score
from domainrecon.scanner.takeover import (
    TAKEOVER_MAX_SUBDOMAINS,
    check_subdomain_takeover,
    match_service,
    takeover_candidates,
)
from rendu import fr

# Comportement des 18 modules historiques : registre ramené à eux (tests/conftest.py).
pytestmark = pytest.mark.usefixtures("registre_historique")

PUBLIC_IP = "93.184.216.34"


# =============================================================================
# Outils de test
# =============================================================================


def _scan_parfait() -> dict:
    """Scan au format actuel où tous les critères sont mesurés et conformes."""
    return {
        "security_headers": {"measured": True, "counts": {"ok": 6, "weak": 0, "total": 6}},
        "tls_certificate": {
            "measured": True,
            "https": True,
            "valid": True,
            "days_remaining": 200,
            "protocol": "TLSv1.3",
        },
        "email_security": {"measured": True, "overall_grade": "A"},
        "waf": {"measured": True, "detected": True, "waf_name": "Cloudflare"},
        "cookie_security": {"measured": True, "cookies_present": True, "score": "A"},
        "cors": {"measured": True, "misconfigured": False, "reflects_with_credentials": False},
        "redirect_chain": {"measured": True, "forces_https": True, "final_url": "https://example.com/"},
        "subdomain_takeover": [],
        "subdomains_checked": 15,
        "open_ports": [],
        "module_status": {},
    }


@pytest.fixture
def takeover_env(monkeypatch):
    """DNS et HTTP simulés pour check_subdomain_takeover.

    `cnames` : sous-domaine -> cible du CNAME ; `nxdomain` : cibles
    inexistantes ; `errors` : sous-domaines dont le CNAME est illisible ;
    `pages` : « schéma://hôte/ » -> (statut, corps). `tested` : sous-domaines
    dont le CNAME a été demandé.
    """
    import dns.exception

    state = type("TakeoverEnv", (), {})()
    state.cnames, state.nxdomain, state.errors, state.pages, state.tested = {}, set(), set(), {}, []

    async def resolve_cname(resolver, name):
        state.tested.append(name)
        if name in state.errors:
            raise dns.exception.Timeout()
        return state.cnames.get(name)

    async def target_state(resolver, name):
        return "nxdomain" if name in state.nxdomain else "exists"

    def handler(request: httpx.Request) -> httpx.Response:
        page = state.pages.get(f"{request.url.scheme}://{request.url.host}/")
        if page is None:
            raise httpx.ConnectError("Connexion refusée", request=request)
        status, body = page
        # Corps en flux (non pré-lu) : fetch le lit en streaming, comme sur le réseau.
        return httpx.Response(status, stream=httpx.ByteStream(body))

    def client_factory(timeout=10.0, follow_redirects=True):
        return httpx.AsyncClient(
            transport=httpx.MockTransport(handler), timeout=timeout, follow_redirects=follow_redirects
        )

    monkeypatch.setattr(takeover_module, "_make_resolver", lambda: object())
    monkeypatch.setattr(takeover_module, "_resolve_cname", resolve_cname)
    monkeypatch.setattr(takeover_module, "_cname_target_state", target_state)
    monkeypatch.setattr(takeover_module, "_http_client", client_factory)
    return state


def subs(*names, resolution="resolved"):
    return [{"subdomain": name, "resolution": resolution} for name in names]


def run(coro):
    return asyncio.run(coro)


# =============================================================================
# Takeover : fournisseurs « Edge case » et « Not vulnerable » (can-i-take-over-xyz)
# =============================================================================


@pytest.mark.parametrize(
    "cname, body, provider",
    [
        ("gone.github.io", b"<h1>404</h1><p>There isn't a GitHub Pages site here.</p>", "GitHub Pages"),
        (
            "domains.tumblr.com",
            b"Whatever you were looking for doesn't currently exist at this address.",
            "Tumblr",
        ),
    ],
)
def test_takeover_fournisseur_edge_case_a_verifier(takeover_env, cname, body, provider):
    """GitHub Pages et Tumblr exigent une vérification du domaine : jamais « confirmé »."""
    takeover_env.cnames["docs.example.com"] = cname
    takeover_env.pages["https://docs.example.com/"] = (404, body)

    result = run(check_subdomain_takeover(subs("docs.example.com")))

    assert len(result) == 1
    entry = result[0]
    assert entry["provider"] == provider
    assert entry["fingerprint_matched"] is True
    assert entry["confirmed"] is False
    assert entry["risk"] == "medium"
    assert "preuve de propriété" in fr(entry["evidence"])

    # Score : « à vérifier », sans plafond de grade.
    scan = _scan_parfait()
    scan["subdomain_takeover"] = result
    score = compute_security_score(scan)
    assert score["breakdown"]["takeover"]["score"] == 2
    assert score["grade_cap"] is None
    assert score["grade"] == "A"


@pytest.mark.parametrize(
    "cname, body",
    [
        ("site.kinsta.cloud", b"No Site For Domain"),
        ("feedback.uservoice.com", b"This UserVoice subdomain is currently available!"),
        ("support.zendesk.com", b"Help Center Closed"),
        ("prod.global.ssl.fastly.net", b"Fastly error: unknown domain: help.example.com"),
    ],
)
def test_takeover_fournisseurs_non_vulnerables_ignores(takeover_env, cname, body):
    """Kinsta, UserVoice, Zendesk et Fastly sont « Not vulnerable » : rien à signaler."""
    takeover_env.cnames["help.example.com"] = cname
    takeover_env.pages["https://help.example.com/"] = (404, body)

    assert match_service(cname) is None
    assert run(check_subdomain_takeover(subs("help.example.com"))) == []


def test_takeover_azure_static_web_apps_non_reclamable(takeover_env):
    """Les noms azurestaticapps.net sont tirés au hasard : un NXDOMAIN n'est pas confirmé."""
    takeover_env.cnames["app.example.com"] = "polite-sea-0a1b2c3d4.azurestaticapps.net"
    takeover_env.nxdomain.add("polite-sea-0a1b2c3d4.azurestaticapps.net")

    result = run(check_subdomain_takeover(subs("app.example.com")))

    assert [(e["risk"], e["confirmed"], e["provider"]) for e in result] == [("medium", False, None)]
    # Les ressources Azure réclamables par leur nom restent confirmées.
    assert match_service("old-app.azurewebsites.net")[1]["service"] == "Microsoft Azure"


# =============================================================================
# Takeover : CNAME pendant dans le même site
# =============================================================================


def test_takeover_cname_pendant_dans_la_meme_zone_ignore(takeover_env):
    """Une cible NXDOMAIN du même site ne peut être enregistrée par un tiers."""
    takeover_env.cnames["a.example.com"] = "old.example.com"
    takeover_env.cnames["b.example.co.uk"] = "gone.intra.example.co.uk"
    takeover_env.nxdomain.update({"old.example.com", "gone.intra.example.co.uk"})

    result = run(check_subdomain_takeover(subs("a.example.com", "b.example.co.uk")))

    assert result == []
    # Régression : l'entrée « à vérifier » coûtait 3 points sur 5.
    scan = _scan_parfait()
    scan["subdomain_takeover"] = result
    assert compute_security_score(scan)["breakdown"]["takeover"]["score"] == 5


def test_takeover_cname_pendant_vers_un_autre_site_signale(takeover_env):
    """Autre domaine, ou autre locataire d'une plateforme (suffixe privé de la PSL)."""
    takeover_env.cnames["a.example.com"] = "old.example-legacy.net"
    takeover_env.cnames["b.alice.pages.dev"] = "old-project.pages.dev"
    takeover_env.nxdomain.update({"old.example-legacy.net", "old-project.pages.dev"})

    result = run(check_subdomain_takeover(subs("a.example.com", "b.alice.pages.dev")))

    assert sorted(e["subdomain"] for e in result) == ["a.example.com", "b.alice.pages.dev"]
    assert all(e["risk"] == "medium" and e["confirmed"] is False for e in result)


# =============================================================================
# Takeover : couverture
# =============================================================================


def test_candidats_non_resolus_en_tete():
    """Les noms sans adresse (signe d'un CNAME pendant) passent avant la limite."""
    resolved = subs(*(f"app{i:02d}.example.com" for i in range(38)))
    entries = [
        {"subdomain": "www.example.com", "resolution": "resolved"},
        *resolved,
        {"subdomain": "old.example.com", "resolution": "not_tested"},
        {"subdomain": "promo2019.example.com", "resolution": "unresolved"},
        {"subdomain": "PROMO2019.example.com.", "resolution": "unresolved"},  # doublon
        {"subdomain": "*.example.com", "resolution": "unresolved"},  # invalide
    ]

    names = takeover_candidates(entries)

    assert len(names) == TAKEOVER_MAX_SUBDOMAINS
    assert names[0] == "promo2019.example.com"
    # Les autres gardent l'ordre de priorité de find_subdomains.
    assert names[1:3] == ["www.example.com", "app00.example.com"]
    assert len(set(names)) == len(names)


def test_takeover_teste_le_sous_domaine_non_resolu(takeover_env):
    """Régression : seuls les 15 premiers noms par priorité étaient testés."""
    names = [f"app{i:02d}.example.com" for i in range(39)]
    entries = [*subs(*names), {"subdomain": "promo2019.example.com", "resolution": "unresolved"}]
    takeover_env.cnames["promo2019.example.com"] = "promo2019.s3.amazonaws.com"
    takeover_env.pages["https://promo2019.example.com/"] = (404, b"<Code>NoSuchBucket</Code>")

    result = run(check_subdomain_takeover(entries))

    assert "promo2019.example.com" in takeover_env.tested
    assert len(takeover_env.tested) == TAKEOVER_MAX_SUBDOMAINS
    assert [(e["subdomain"], e["confirmed"]) for e in result] == [("promo2019.example.com", True)]


def test_takeover_dns_majoritairement_en_echec_leve_module_error(takeover_env):
    """Régression : 14 CNAME illisibles sur 15 donnaient « Aucun takeover » 5/5."""
    names = [f"s{i:02d}.example.com" for i in range(15)]
    takeover_env.errors.update(names[1:])

    with pytest.raises(ModuleError) as excinfo:
        run(check_subdomain_takeover(subs(*names)))

    assert "14 des 15" in str(excinfo.value)


def test_takeover_dns_minoritairement_en_echec_reste_mesure(takeover_env):
    names = [f"s{i:02d}.example.com" for i in range(15)]
    takeover_env.errors.update(names[:7])

    assert run(check_subdomain_takeover(subs(*names))) == []


def test_takeover_trouve_malgre_un_dns_en_echec_est_conserve(takeover_env):
    """Un takeover avéré n'est jamais masqué par l'échec DNS des autres noms."""
    names = [f"s{i:02d}.example.com" for i in range(4)]
    takeover_env.errors.update(names[1:])
    takeover_env.cnames[names[0]] = "old-app.azurewebsites.net"
    takeover_env.nxdomain.add("old-app.azurewebsites.net")

    result = run(check_subdomain_takeover(subs(*names)))

    assert [(e["subdomain"], e["confirmed"]) for e in result] == [(names[0], True)]


# =============================================================================
# Réseau étendu : échec d'une des deux sources
# =============================================================================


@pytest.fixture
def api_dns(monkeypatch):
    """Résolution simulée des services tiers (aucun paquet DNS ne sort)."""
    table = {"ipinfo.io": ["34.117.59.81"], "api.hackertarget.com": ["172.67.75.1"]}

    async def fake_resolve(host, timeout=targets.RESOLVE_TIMEOUT):
        literal = targets._parse_ip(host)
        if literal is not None:
            return [str(literal)]
        return list(table.get(host, []))

    monkeypatch.setattr(targets, "resolve_addresses", fake_resolve)


def _api_transport(monkeypatch, handler):
    def factory(timeout=10.0):
        return common._api_client(timeout, transport=httpx.MockTransport(handler))

    monkeypatch.setattr(network, "_api_client", factory)


def test_reseau_etendu_echec_asn_detaille(monkeypatch, api_dns):
    """ipinfo.io en échec, HackerTarget répond : la cause reste lisible dans asn_error."""

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.host == "ipinfo.io":
            return httpx.Response(429, text="Too Many Requests")
        return httpx.Response(200, text="www.example.com\nvoisin.example.net\n")

    _api_transport(monkeypatch, handler)
    result = asyncio.run(network.extended_network_scan(PUBLIC_IP, "example.com"))

    assert result["measured"] is True and result["error"] is None
    assert result["asn_info"] == {}
    assert fr(result["asn_error"]) == "Quota du service ipinfo.io dépassé (HTTP 429)"
    assert result["reverse_ip_neighbors"] == ["www.example.com", "voisin.example.net"]
    assert result["neighbors_error"] is None


def test_reseau_etendu_quota_distinct_d_une_liste_vide(monkeypatch, api_dns):
    """Quota HackerTarget : `neighbors_error` renseigné, contrairement à « aucun voisin »."""

    def handler_for(text):
        def handler(request: httpx.Request) -> httpx.Response:
            if request.url.host == "ipinfo.io":
                return httpx.Response(200, json={"org": "AS15133 Edgecast Inc."})
            return httpx.Response(200, text=text)

        return handler

    _api_transport(monkeypatch, handler_for("API count exceeded - Increase Quota with Membership"))
    quota = asyncio.run(network.extended_network_scan(PUBLIC_IP, "example.com"))
    _api_transport(monkeypatch, handler_for(f"No DNS A records found for {PUBLIC_IP}"))
    empty = asyncio.run(network.extended_network_scan(PUBLIC_IP, "example.com"))

    assert quota["reverse_ip_neighbors"] == empty["reverse_ip_neighbors"] == []
    assert fr(quota["neighbors_error"]) == "Quota de l'API HackerTarget dépassé"
    assert empty["neighbors_error"] is None


def test_reseau_etendu_voisins_tronques_signales(monkeypatch, api_dns):
    """IP anycast de CDN : les 50 premiers voisins seulement, coupe et total indiqués."""

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.host == "ipinfo.io":
            return httpx.Response(200, json={"org": "AS13335 Cloudflare, Inc.", "anycast": True})
        return httpx.Response(200, text="\n".join(f"site{i:02d}.example.net" for i in range(60)))

    _api_transport(monkeypatch, handler)
    result = asyncio.run(network.extended_network_scan(PUBLIC_IP, "example.com"))

    assert len(result["reverse_ip_neighbors"]) == network.REVERSE_IP_MAX_NEIGHBORS
    assert result["neighbors_total"] == 60
    assert result["neighbors_truncated"] is True
    assert result["asn_info"]["anycast"] is True


# =============================================================================
# ipinfo.io : une seule requête par IP
# =============================================================================


def test_ipinfo_partage_entre_geolocalisation_et_reseau_etendu(monkeypatch, api_dns):
    """Régression : ipinfo.io (sans jeton, débit limité) était interrogé deux fois par scan pour la même IP."""
    hosts = []

    def handler(request: httpx.Request) -> httpx.Response:
        hosts.append(request.url.host)
        if request.url.host == "ipinfo.io":
            return httpx.Response(
                200, json={"country": "US", "org": "AS13335 Cloudflare, Inc.", "anycast": True}
            )
        return httpx.Response(200, text="voisin.example.net\n")

    _api_transport(monkeypatch, handler)

    async def scans():
        geo, extended = await asyncio.gather(
            network.get_geo_data(PUBLIC_IP), network.extended_network_scan(PUBLIC_IP, "example.com")
        )
        # Second scan de la même IP, lancé peu après.
        return geo, extended, await network.get_geo_data(PUBLIC_IP)

    geo, extended, again = asyncio.run(scans())

    assert hosts.count("ipinfo.io") == 1
    assert geo["measured"] is True and again == geo
    assert geo["anycast"] is True
    assert extended["asn_info"]["asn"] == "AS13335"


def test_ipinfo_echec_non_conserve(monkeypatch, api_dns):
    statuses = [429, 200]

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(statuses.pop(0), json={"country": "FR"})

    _api_transport(monkeypatch, handler)

    async def scans():
        return await network.get_geo_data(PUBLIC_IP), await network.get_geo_data(PUBLIC_IP)

    first, second = asyncio.run(scans())

    assert first["measured"] is False and "429" in fr(first["error"])
    assert second["measured"] is True and second["country_code"] == "FR"
    assert statuses == []


# =============================================================================
# Scan de ports : boucle d'événements bloquée, hôte sans réponse
# =============================================================================


class _Writer:
    """StreamWriter minimal renvoyé par une connexion simulée."""

    def close(self) -> None:
        pass

    async def wait_closed(self) -> None:
        pass


def test_scan_ports_boucle_bloquee_resonde_les_ports_sans_reponse(monkeypatch):
    """Régression : boucle bloquée par un travail synchrone au démarrage du scan (création
    des clients d'API), le délai du port 80 ouvert expirait avant que sa connexion ne soit
    traitée : port signalé filtré."""
    monkeypatch.setattr(network, "COMMON_PORTS", {80: "HTTP"})
    monkeypatch.setattr(network, "PORT_TIMEOUT", 0.2)
    calls = []

    async def scenario():
        connecting = asyncio.Event()

        async def open_connection(host, port):
            calls.append(port)
            connecting.set()
            await asyncio.sleep(0.02)  # aller-retour réseau
            return None, _Writer()

        async def blocking_work():
            await connecting.wait()
            time.sleep(0.4)  # boucle bloquée au-delà de l'échéance de la sonde

        monkeypatch.setattr(asyncio, "open_connection", open_connection)
        ports, _ = await asyncio.gather(network.scan_ports(PUBLIC_IP), blocking_work())
        return ports

    assert asyncio.run(scenario()) == [{"port": 80, "state": "open", "service": "HTTP"}]
    assert calls == [80, 80]  # sonde non concluante, refaite une fois


def test_scan_ports_aucune_reponse_n_est_pas_aucun_port_ouvert(monkeypatch):
    """Régression : 22 sondes expirées sur 22 étaient rapportées « ok, aucun port ouvert »."""
    monkeypatch.setattr(network, "COMMON_PORTS", {21: "FTP", 23: "Telnet", 80: "HTTP"})
    monkeypatch.setattr(network, "PORT_TIMEOUT", 0.05)
    # Marge large : ce test ne doit pas dépendre de la charge de la machine.
    monkeypatch.setattr(network, "PORT_STALL_TOLERANCE", 1.0)
    calls = []

    async def open_connection(host, port):
        calls.append(port)
        await asyncio.sleep(10)

    monkeypatch.setattr(asyncio, "open_connection", open_connection)
    with pytest.raises(ModuleError, match="aucun des 3 ports testés n'a répondu"):
        asyncio.run(network.scan_ports(PUBLIC_IP))
    # Sans blocage de la boucle, une expiration est une mesure : pas de seconde sonde.
    assert sorted(calls) == [21, 23, 80]


def test_scan_ports_port_refuse_est_une_reponse(monkeypatch):
    """Un refus (RST) prouve que l'hôte répond : « aucun port ouvert » est alors mesuré."""
    monkeypatch.setattr(network, "COMMON_PORTS", {22: "SSH", 80: "HTTP"})
    monkeypatch.setattr(network, "PORT_TIMEOUT", 0.05)

    async def open_connection(host, port):
        if port == 22:
            raise ConnectionRefusedError()
        await asyncio.sleep(10)

    monkeypatch.setattr(asyncio, "open_connection", open_connection)
    assert asyncio.run(network.scan_ports(PUBLIC_IP)) == []
