# =============================================================================
# DomainRecon - Tests : messages traduisibles du DNS, du réseau, du takeover,
# du WHOIS et de la capture d'écran
# =============================================================================
# Un rendu anglais (et, au besoin, le français) pour chaque module converti en
# codes de message ; les tests propres à chaque module vérifient le français
# au moyen de rendu.fr.
# =============================================================================

import asyncio
import sys
import types

import dns.exception
import dns.resolver
import pytest

from domainrecon.i18n import msg
from domainrecon.scanner import dns as scanner_dns
from domainrecon.scanner import network, screenshot, whois_lookup
from domainrecon.scanner import takeover as takeover_module
from domainrecon.scanner.errors import ModuleError
from rendu import en, fr

# --- dns.py -----------------------------------------------------------------------


def test_dns_erreurs_en_anglais(monkeypatch):
    class ResolveurMuet:
        def resolve(self, *args, **kwargs):
            raise dns.exception.Timeout()

    monkeypatch.setattr(scanner_dns, "_make_resolver", lambda: ResolveurMuet())
    querier = scanner_dns.DnsQuerier(5.0, 40.0)
    assert en(querier.lookup("example.com", "A").error) == "timed out"
    assert en(scanner_dns._reverse_dns_sync("pas-une-ip")["error"]) == "Invalid IP address: pas-une-ip"
    assert en(asyncio.run(scanner_dns.reverse_dns(""))["error"]) == "No IP address to query"
    enregistrements = scanner_dns._scan_dns_sync("example.com")
    # Erreurs dédoublonnées, triées sur le texte français, séparées par « ; ».
    assert fr(enregistrements["error"]) == (
        "Aucune réponse DNS : _dmarc.example.com : délai dépassé; délai dépassé"
    )
    assert en(enregistrements["error"]) == "No DNS answer: _dmarc.example.com: timed out; timed out"


def test_dns_dmarc_en_echec_est_un_message(monkeypatch):
    """L'erreur de find_dmarc imbrique le message de la requête (pas sa représentation)."""

    class ResolveurMuet:
        def resolve(self, *args, **kwargs):
            raise dns.exception.Timeout()

    monkeypatch.setattr(scanner_dns, "_make_resolver", lambda: ResolveurMuet())
    dmarc = scanner_dns.find_dmarc(scanner_dns.DnsQuerier(5.0, 40.0), "example.com")
    assert fr(dmarc.error) == "_dmarc.example.com : délai dépassé"
    assert en(dmarc.error) == "_dmarc.example.com: timed out"


def test_dns_joker_en_anglais(monkeypatch):
    class ResolveurVide:
        def resolve(self, *args, **kwargs):
            raise dns.resolver.NoAnswer()

    monkeypatch.setattr(scanner_dns, "_make_resolver", lambda: ResolveurVide())
    monkeypatch.setattr(scanner_dns, "_probe_wildcard", lambda querier, site: ["192.0.2.1", "192.0.2.2"])
    notes = scanner_dns._scan_dns_sync("example.com")["notes"]
    assert en(notes) == [
        "DNS wildcard (*.example.com): every name under example.com resolves (192.0.2.1, 192.0.2.2), "
        "so resolving a subdomain does not prove it exists"
    ]


def test_dns_sources_ct_en_echec_en_anglais(monkeypatch):
    async def crtsh_en_erreur(domain):
        raise ModuleError(msg("dns.crtsh_http", status=502))

    async def certspotter_en_quota(domain):
        raise ModuleError(msg("dns.certspotter_quota"))

    async def certspotter_lent(domain):
        await asyncio.sleep(5)

    monkeypatch.setattr(scanner_dns, "_fetch_crtsh_names", crtsh_en_erreur)
    monkeypatch.setattr(scanner_dns, "_fetch_certspotter_names", certspotter_en_quota)
    with pytest.raises(ModuleError) as excinfo:
        asyncio.run(scanner_dns._fetch_ct_names("example.com"))
    assert fr(excinfo.value.message) == "crt.sh a répondu HTTP 502 ; Cert Spotter : quota de requêtes atteint"
    assert en(excinfo.value.message) == "crt.sh answered HTTP 502; Cert Spotter: request quota reached"

    monkeypatch.setattr(scanner_dns, "_fetch_certspotter_names", certspotter_lent)
    monkeypatch.setattr(scanner_dns, "CERTSPOTTER_BUDGET", 0.01)
    with pytest.raises(ModuleError) as excinfo:
        asyncio.run(scanner_dns._fetch_ct_names("example.com"))
    assert en(excinfo.value.message) == "crt.sh answered HTTP 502; Cert Spotter: timed out (0 s)"


# --- network.py, takeover.py, whois_lookup.py ----------------------------------------


def test_reseau_messages_en_anglais():
    message, sans_objet = network._third_party_refusal(None, msg("network.what_geo"))
    assert sans_objet is True
    assert en(message) == "No IP address: geolocation not applicable"
    assert fr(message) == "Aucune adresse IP : géolocalisation sans objet"
    assert en(network._http_error_message("ipinfo.io", 429)) == "ipinfo.io quota exceeded (HTTP 429)"
    assert en(network._describe(RuntimeError(), msg("network.asn_unavailable"))) == (
        "ASN information unavailable: RuntimeError"
    )


def test_whois_message_en_anglais():
    assert en(whois_lookup._get_whois_sync("93.184.216.34")["error"]) == (
        "Domain WHOIS not applicable to an IP address"
    )


def test_takeover_resolveur_indisponible_en_anglais(monkeypatch):
    def en_panne():
        raise dns.exception.DNSException("pas de resolv.conf")

    monkeypatch.setattr(takeover_module, "_make_resolver", en_panne)
    with pytest.raises(ModuleError) as excinfo:
        asyncio.run(
            takeover_module.check_subdomain_takeover(
                [{"subdomain": "www.example.com", "resolution": "resolved"}]
            )
        )
    assert en(excinfo.value.message) == "DNS resolver unavailable: pas de resolv.conf"


def test_reseau_etendu_deux_sources_en_echec_en_anglais(monkeypatch):
    async def ipinfo_en_quota(ip):
        raise ModuleError(network._http_error_message("ipinfo.io", 429))

    async def voisins_en_panne(ip, domain):
        raise RuntimeError("boom")

    monkeypatch.setattr(network, "_ipinfo_lookup", ipinfo_en_quota)
    monkeypatch.setattr(network, "_reverse_ip_neighbors", voisins_en_panne)
    result = asyncio.run(network.extended_network_scan("93.184.216.34", "example.com"))
    assert result["measured"] is False
    assert en(result["asn_error"]) == "ipinfo.io quota exceeded (HTTP 429)"
    assert en(result["neighbors_error"]) == "Reverse IP unavailable: boom"
    # Les deux causes, jointes selon la typographie de la langue.
    assert en(result["error"]) == "ipinfo.io quota exceeded (HTTP 429); Reverse IP unavailable: boom"
    assert (
        fr(result["error"])
        == "Quota du service ipinfo.io dépassé (HTTP 429) ; Reverse IP indisponible : boom"
    )


def test_geolocalisation_refus_et_echec_en_anglais(monkeypatch):
    geo = asyncio.run(network.get_geo_data("pas-une-ip"))
    assert en(geo["error"]) == "Invalid IP address: geolocation impossible"
    assert asyncio.run(network.get_geo_data("127.0.0.1"))["skipped"] is True

    async def ipinfo_illisible(ip):
        raise ModuleError(msg("network.ipinfo_unreadable"))

    monkeypatch.setattr(network, "_ipinfo_lookup", ipinfo_illisible)
    geo = asyncio.run(network.get_geo_data("93.184.216.34"))
    assert en(geo["error"]) == "Unreadable response from ipinfo.io"


def test_scan_de_ports_echecs_en_anglais(monkeypatch):
    async def reseau_injoignable(host, port, **kwargs):
        raise OSError("Réseau injoignable")

    monkeypatch.setattr(asyncio, "open_connection", reseau_injoignable)
    with pytest.raises(ModuleError) as excinfo:
        asyncio.run(network.scan_ports("93.184.216.34"))
    assert en(excinfo.value.message) == "Port scan failed: Réseau injoignable"

    async def sans_reponse(host, port, **kwargs):
        raise TimeoutError()

    monkeypatch.setattr(asyncio, "open_connection", sans_reponse)
    with pytest.raises(ModuleError) as excinfo:
        asyncio.run(network.scan_ports("93.184.216.34"))
    total = len(network.COMMON_PORTS)
    assert en(excinfo.value.message) == (
        f"Host unreachable or fully filtered: none of the {total} tested ports answered"
    )


@pytest.mark.parametrize(
    "reponse, attendu",
    [
        (TimeoutError("timed out"), "WHOIS: timed out (10 s)"),
        (RuntimeError("boom"), "WHOIS unavailable: boom"),
        (
            whois_lookup.WhoisDomainNotFoundError("This TLD has no whois server"),
            "No known WHOIS server for this extension",
        ),
        (types.SimpleNamespace(), "Empty or unusable WHOIS response"),
        (
            types.SimpleNamespace(text="Socket not responding: timed out"),
            "WHOIS: timed out (10 s)",
        ),
        (
            types.SimpleNamespace(text="Socket not responding: refused"),
            "WHOIS unavailable: server unreachable",
        ),
    ],
)
def test_whois_echecs_en_anglais(monkeypatch, reponse, attendu):
    def whois_simule(domain, **kwargs):
        if isinstance(reponse, Exception):
            raise reponse
        return reponse

    monkeypatch.setattr(whois_lookup.whois, "whois", whois_simule)
    result = whois_lookup._get_whois_sync("example.com")
    assert result["measured"] is False
    assert en(result["error"]) == attendu


@pytest.mark.parametrize(
    "cname, etat, page, attendu_fr, attendu_en",
    [
        (
            "monsite.blob.core.windows.net",
            "nxdomain",
            None,
            "La cible du CNAME n'existe pas (NXDOMAIN) : le nom peut être réclamé chez Microsoft Azure",
            "The CNAME target does not exist (NXDOMAIN): the name can be claimed at Microsoft Azure",
        ),
        (
            "inconnu.example.net",
            "nxdomain",
            None,
            "CNAME pendant : inconnu.example.net n'existe pas (NXDOMAIN). "
            "À vérifier : la cible peut-elle être enregistrée par un tiers ?",
            "Dangling CNAME: inconnu.example.net does not exist (NXDOMAIN). "
            "To verify: can a third party register the target?",
        ),
        (
            "monsite.ghost.io",
            "exists",
            (True, True, 404),
            "Page « site inexistant » de Ghost servie par le sous-domaine",
            "Ghost “site not found” page served by the subdomain",
        ),
        (
            "gone.github.io",
            "exists",
            (True, True, 404),
            "Page « site inexistant » de GitHub Pages servie par le sous-domaine "
            "(GitHub Pages exige une preuve de propriété : exploitation à vérifier)",
            "GitHub Pages “site not found” page served by the subdomain "
            "(GitHub Pages requires proof of ownership: exploitation to be verified)",
        ),
        (
            "monsite.ghost.io",
            "exists",
            (False, False, None),
            "CNAME vers Ghost mais aucune réponse HTTP(S) : à vérifier manuellement",
            "CNAME to Ghost but no HTTP(S) response: verify manually",
        ),
    ],
)
def test_takeover_preuves_en_anglais(monkeypatch, cname, etat, page, attendu_fr, attendu_en):
    async def resoudre_cname(resolver, name):
        return cname

    async def etat_cible(resolver, name):
        return etat

    async def empreinte(client, sub, fingerprint_re):
        return page

    monkeypatch.setattr(takeover_module, "_resolve_cname", resoudre_cname)
    monkeypatch.setattr(takeover_module, "_cname_target_state", etat_cible)
    monkeypatch.setattr(takeover_module, "_fingerprint_check", empreinte)
    entry = asyncio.run(takeover_module._check_one("www.example.com", None, None))
    assert fr(entry["evidence"]) == attendu_fr
    assert en(entry["evidence"]) == attendu_en


def test_takeover_dns_illisible_en_anglais(monkeypatch):
    async def cname_illisible(resolver, name):
        raise dns.exception.Timeout()

    monkeypatch.setattr(takeover_module, "_make_resolver", lambda: object())
    monkeypatch.setattr(takeover_module, "_resolve_cname", cname_illisible)
    sous_domaines = [{"subdomain": f"s{i}.example.com", "resolution": "resolved"} for i in range(3)]
    with pytest.raises(ModuleError) as excinfo:
        asyncio.run(takeover_module.check_subdomain_takeover(sous_domaines))
    assert en(excinfo.value.message) == (
        "DNS resolution failed for 3 of the 3 tested subdomain(s) (s0.example.com: Timeout)"
    )
    assert fr(excinfo.value.message) == (
        "Résolution DNS impossible pour 3 des 3 sous-domaine(s) testé(s) (s0.example.com : Timeout)"
    )


# --- screenshot.py ---------------------------------------------------------------


def test_capture_raisons_en_anglais():
    proxy = screenshot._FilteringProxy(screenshot._NetworkGuard())
    refus = Exception("net::ERR_CONNECTION_REFUSED at https://example.com/")
    assert en(screenshot._navigation_failure(refus, "https://example.com/", proxy)) == "connection refused"
    delai = Exception("Timeout 15000ms exceeded.")
    assert en(screenshot._navigation_failure(delai, "https://example.com/", proxy)) == (
        "navigation timed out (15 s)"
    )
    assert en(screenshot._connect_error_text(TimeoutError())) == "timed out"
    assert en(screenshot._connect_error_text(None)) == "no address"
    assert "domainrecon --server" in fr(screenshot._NO_SUBPROCESS_MESSAGE)


@pytest.mark.parametrize(
    "code, attendu",
    [
        ("ERR_EMPTY_RESPONSE", "connection closed without a response"),
        (
            "ERR_TUNNEL_CONNECTION_FAILED",
            "HTTPS connection refused by the capture proxy (host blocked or unreachable)",
        ),
        ("ERR_CONNECTION_REFUSED", "connection refused"),
        ("ERR_CONNECTION_RESET", "connection reset by the server"),
        ("ERR_CONNECTION_CLOSED", "connection closed by the server"),
        ("ERR_CONNECTION_TIMED_OUT", "connection timed out"),
        ("ERR_TIMED_OUT", "timed out"),
        ("ERR_NAME_NOT_RESOLVED", "domain name not found"),
        ("ERR_ADDRESS_UNREACHABLE", "address unreachable"),
        ("ERR_BLOCKED_BY_CLIENT", "request blocked by the target policy"),
        ("ERR_ABORTED", "navigation aborted"),
        ("ERR_TOO_MANY_REDIRECTS", "too many redirects"),
        ("ERR_INVALID_RESPONSE", "invalid response from the server"),
        ("ERR_SSL_PROTOCOL_ERROR", "TLS protocol error"),
        ("ERR_SSL_VERSION_OR_CIPHER_MISMATCH", "no TLS version or cipher suite in common with the server"),
    ],
)
def test_capture_codes_chromium_en_anglais(code, attendu):
    assert en(screenshot._net_error_reason(code)) == attendu
    assert screenshot._net_error_reason("ERR_INCONNU") is None


def test_capture_raison_du_proxy_et_site_injoignable_en_anglais():
    proxy = screenshot._FilteringProxy(screenshot._NetworkGuard())
    raison = msg("screenshot.connect_failed", port=443, error=screenshot._connect_error_text(TimeoutError()))
    proxy._upstream_errors[("example.com", 443)] = raison
    assert en(proxy.upstream_error("https://example.com/")) == "connection to port 443 failed (timed out)"
    assert proxy.upstream_error("https://autre.example/") is None
    # Réponse 502 du proxy : la cause (ou « site injoignable ») sert de message à l'exception.
    echec = screenshot._UpstreamUnreachable(raison)
    assert en(screenshot._navigation_failure(echec, "https://example.com/", proxy)) == (
        "connection to port 443 failed (timed out)"
    )
    assert fr(screenshot._navigation_failure(echec, "https://example.com/", proxy)) == (
        "connexion impossible au port 443 (délai dépassé)"
    )
    inconnu = Exception("Page.goto: net::ERR_INCONNU at https://example.com/\nCall log:")
    assert screenshot._navigation_failure(inconnu, "https://example.com/", proxy) == (
        "Page.goto: net::ERR_INCONNU at https://example.com/"
    )


class _FausseCapture:
    """Module playwright.async_api simulé : chaque navigation échoue avec l'erreur donnée."""

    def __init__(self, monkeypatch, erreurs, lancement=None):
        self.erreurs = list(erreurs)
        self.lancement = lancement
        fausse = self

        class Page:
            async def goto(self, url, **kwargs):
                raise fausse.erreurs.pop(0)

            async def close(self):
                pass

        class Context:
            async def route(self, *args):
                pass

            async def new_page(self):
                return Page()

        class Browser:
            async def new_context(self, **kwargs):
                return Context()

            async def close(self):
                pass

        class Chromium:
            async def launch(self, **kwargs):
                if fausse.lancement is not None:
                    raise fausse.lancement
                return Browser()

        class Manager:
            async def __aenter__(self):
                return types.SimpleNamespace(chromium=Chromium())

            async def __aexit__(self, *exc_info):
                return False

        module = types.ModuleType("playwright.async_api")
        module.async_playwright = Manager
        monkeypatch.setitem(sys.modules, "playwright.async_api", module)

        async def autorisee(host):
            return ["93.184.216.34"]

        monkeypatch.setattr(screenshot, "ensure_target_allowed", autorisee)


def test_capture_echec_de_toutes_les_tentatives_en_anglais(monkeypatch, tmp_path):
    _FausseCapture(
        monkeypatch,
        [
            Exception("Page.goto: net::ERR_CONNECTION_REFUSED at https://example.com/"),
            Exception("Page.goto: Timeout 15000ms exceeded.\nCall log:"),
        ],
    )
    with pytest.raises(ModuleError) as excinfo:
        asyncio.run(screenshot.capture_screenshot("example.com", str(tmp_path)))
    assert fr(excinfo.value.message) == (
        "Capture d'écran impossible : https://example.com/ : connexion refusée"
        " ; http://example.com/ : délai de navigation dépassé (15 s)"
    )
    assert en(excinfo.value.message) == (
        "Screenshot impossible: https://example.com/: connection refused;"
        " http://example.com/: navigation timed out (15 s)"
    )
    assert str(excinfo.value) == fr(excinfo.value.message)


def test_capture_requetes_bloquees_en_anglais(monkeypatch, tmp_path):
    class GardeAvecHotesBloques(screenshot._NetworkGuard):
        def __init__(self):
            super().__init__()
            self.blocked.extend(["intranet.example", "127.0.0.1"])

    monkeypatch.setattr(screenshot, "_NetworkGuard", GardeAvecHotesBloques)
    _FausseCapture(monkeypatch, [Exception("net::ERR_BLOCKED_BY_CLIENT at http://intranet.example/")] * 2)
    with pytest.raises(ModuleError) as excinfo:
        asyncio.run(screenshot.capture_screenshot("example.com", str(tmp_path)))
    message = excinfo.value.message
    assert en(message) == (
        "Screenshot impossible (requests blocked by the target policy: intranet.example, 127.0.0.1):"
        " https://example.com/: request blocked by the target policy;"
        " http://example.com/: request blocked by the target policy"
    )
    assert fr(message).startswith(
        "Capture d'écran impossible (requêtes bloquées par la politique de cibles : intranet.example, 127.0.0.1) : "
    )


def test_capture_sans_adresse_et_chromium_inlancable_en_anglais(monkeypatch, tmp_path):
    _FausseCapture(
        monkeypatch, [], lancement=Exception("BrowserType.launch: Host system is missing dependencies")
    )
    with pytest.raises(ModuleError) as excinfo:
        asyncio.run(screenshot.capture_screenshot("example.com", str(tmp_path)))
    assert (
        en(excinfo.value.message)
        == "Chromium could not start: screenshot impossible (details in the server logs)"
    )

    async def aucune_adresse(host):
        return []

    monkeypatch.setattr(screenshot, "ensure_target_allowed", aucune_adresse)
    with pytest.raises(ModuleError) as excinfo:
        asyncio.run(screenshot.capture_screenshot("example.com", str(tmp_path)))
    assert en(excinfo.value.message) == "Screenshot impossible: no IP address for example.com"
