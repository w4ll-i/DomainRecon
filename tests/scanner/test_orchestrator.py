# =============================================================================
# DomainRecon - Tests de l'orchestrateur (perform_full_scan)
# =============================================================================
# L'orchestrateur exécute les modules du registre (registry.py) : chaque module
# est remplacé par un faux, dans le module du scanner qui définit sa fonction
# (domainrecon.scanner.dns.scan_dns_records, par exemple), là où l'adaptateur de
# modules/ la cherche à chaque appel. Aucun accès réseau : les fonctions de
# résolution et de connexion de `socket` sont bloquées.
# Les vagues, les profils et les modules ajoutés au registre sont éprouvés en
# fin de fichier, sur un registre de démonstration qui remplace MODULES.
# =============================================================================

import asyncio
import copy
import dataclasses
import inspect
import logging
import socket
import sys
import threading
import time
from types import SimpleNamespace

import pytest

from domainrecon.core.settings_store import ScanSettings
from domainrecon.i18n import msg
from domainrecon.scanner import common, orchestrator, registry
from domainrecon.scanner.errors import ModuleError, TargetNotAllowedError, message_of
from domainrecon.scanner.headers import SECURITY_HEADERS, empty_headers_result
from domainrecon.scanner.registry import ModuleSpec
from domainrecon.scanner.takeover import TAKEOVER_MAX_SUBDOMAINS
from rendu import en, fr

# Comportement des 18 modules historiques : registre ramené à eux (tests/conftest.py).
pytestmark = pytest.mark.usefixtures("registre_historique")

PUBLIC_IP = "93.184.216.34"
PUBLIC_IPV6 = "2606:2800:220:1:248:1893:25c8:1946"

# Nom du module (clé de module_status) -> fonction appelée par son adaptateur
# (module du scanner, puis nom de la fonction).
MODULE_FUNCTIONS = {
    "dns_records": "dns.scan_dns_records",
    "subdomains": "dns.find_subdomains",
    "security_headers": "headers.check_security_headers",
    "tls_certificate": "tls.check_tls_certificate",
    "technologies": "technologies.detect_technologies",
    "geo_data": "impl.geo_data.get_geo_data",
    "whois_data": "whois_lookup.get_whois_data",
    "open_ports": "impl.open_ports.scan_ports",
    "email_security": "email_security.analyze_email_security",
    "waf": "waf.detect_waf",
    "redirect_chain": "redirects.trace_redirects",
    "web_files": "web_files.check_web_files",
    "cookie_security": "cookies.analyze_cookies",
    "cors": "cors.check_cors",
    "reverse_dns": "dns.reverse_dns",
    "network_extended": "impl.network_extended.extended_network_scan",
    "screenshot": "screenshot.capture_screenshot",
    "subdomain_takeover": "takeover.check_subdomain_takeover",
}

# Résultats conformes au contrat : dict avec measured/error, listes, capture.
HEALTHY = {
    "dns_records": {"A": [PUBLIC_IP], "MX": [], "measured": True, "error": None},
    "subdomains": [{"subdomain": "www.example.com", "ip": PUBLIC_IP}],
    "security_headers": {
        "headers_found": {"X-Frame-Options": "DENY"},
        "headers_missing": [],
        "score": "7/7",
        "url": "https://example.com/",
        "measured": True,
        "error": None,
    },
    "tls_certificate": {
        "measured": True,
        "https": True,
        "valid": True,
        "verify_error": None,
        "error": None,
        "protocol": "TLSv1.3",
        "days_remaining": 90,
    },
    "technologies": [{"name": "nginx", "category": "Serveur web"}],
    "geo_data": {"ip": PUBLIC_IP, "country": "United States", "measured": True, "error": None},
    "whois_data": {"registrar": "Registrar Inc.", "measured": True, "error": None},
    "open_ports": [{"port": 443, "state": "open", "service": "HTTPS"}],
    "email_security": {"overall_grade": "A", "measured": True, "error": None},
    "waf": {"detected": False, "waf_name": None, "measured": True, "error": None},
    "redirect_chain": {
        "chain": [{"url": "http://example.com", "status_code": 301}],
        "forces_https": True,
        "measured": True,
        "error": None,
    },
    "web_files": {"robots_txt": {"found": True}, "measured": True, "error": None},
    "cookie_security": {
        "cookies": [],
        "cookies_present": False,
        "score": "N/A",
        "measured": True,
        "error": None,
    },
    "cors": {"misconfigured": False, "allows_any_origin": False, "measured": True, "error": None},
    "reverse_dns": {"ptr": "example.com", "aliases": [], "measured": True, "error": None},
    "network_extended": {"asn_info": {}, "reverse_ip_neighbors": [], "measured": True, "error": None},
    "screenshot": "example_com_1700000000_0a1b2c3d.png",
    "subdomain_takeover": [],
}

HTTP_MODULES = ("security_headers", "redirect_chain", "waf", "cookie_security", "cors")
IP_MODULES = ("geo_data", "open_ports", "reverse_dns", "network_extended")
# Modules sans objet sur une IP littérale (contrat §4).
NOT_FOR_IP = ("dns_records", "subdomains", "whois_data", "email_security", "subdomain_takeover")

FAKE_SCORE = {
    "score": 100,
    "max_score": 100,
    "grade": "A",
    "breakdown": {},
    "coverage": 100,
    "measured_points": 100,
    "measured_max": 100,
    "confidence": "high",
}


class FakeScan:
    """Remplace tous les modules de l'orchestrateur par des faux configurables.

    `behaviors[nom]` vaut une valeur (renvoyée telle quelle), une exception
    (levée) ou une coroutine (appelée avec les arguments du module).
    """

    def __init__(self, monkeypatch):
        self.calls: list[tuple[str, tuple]] = []
        # Arguments nommés du dernier appel de chaque module.
        self.kwargs: dict[str, dict] = {}
        self.behaviors = copy.deepcopy(HEALTHY)
        self.addresses: object = [PUBLIC_IP]
        self.score_input: dict | None = None

        for name, func in MODULE_FUNCTIONS.items():
            monkeypatch.setattr(f"domainrecon.scanner.{func}", self._fake(name))
        monkeypatch.setattr(orchestrator, "ensure_target_allowed", self._fake_ensure)
        monkeypatch.setattr(orchestrator, "compute_security_score", self._fake_score)

    def _fake(self, name):
        async def fake(*args, **kwargs):
            self.calls.append((name, args))
            self.kwargs[name] = kwargs
            return await self._apply(self.behaviors[name], args, kwargs)

        return fake

    async def _fake_ensure(self, host):
        self.calls.append(("ensure_target_allowed", (host,)))
        return await self._apply(self.addresses, (host,))

    def _fake_score(self, scan_data):
        self.score_input = scan_data
        return dict(FAKE_SCORE)

    @staticmethod
    async def _apply(behavior, args, kwargs=None):
        if isinstance(behavior, BaseException):
            raise behavior
        if inspect.iscoroutinefunction(behavior):
            return await behavior(*args, **(kwargs or {}))
        return copy.deepcopy(behavior)

    def called(self, name) -> bool:
        return any(call_name == name for call_name, _ in self.calls)

    def args_of(self, name) -> tuple:
        return next(args for call_name, args in self.calls if call_name == name)


@pytest.fixture(autouse=True)
def no_network(monkeypatch):
    """Tout accès réseau réel fait échouer le test au lieu de partir sur Internet."""

    def refuse(*args, **kwargs):
        raise AssertionError("Accès réseau interdit dans les tests de l'orchestrateur")

    for name in ("getaddrinfo", "gethostbyname", "gethostbyname_ex", "gethostbyaddr", "create_connection"):
        monkeypatch.setattr(socket, name, refuse)


@pytest.fixture
def fake(monkeypatch):
    return FakeScan(monkeypatch)


# Les 18 modules historiques : « open_ports » et « subdomain_takeover » sont actifs, donc hors du profil
# « complet » ; on les lance par le profil « personnalise » avec l'autorisation de tester la cible.
TOUS_LES_MODULES = {
    "profile": "personnalise",
    "selected": tuple(MODULE_FUNCTIONS),
    "authorized_target": True,
}


def run_scan(target="example.com"):
    """Scan des 18 modules historiques (ou, avec un registre de démonstration, du profil « complet »)."""
    options = TOUS_LES_MODULES if set(MODULE_FUNCTIONS) <= registry.MODULES.keys() else {}
    return asyncio.run(orchestrator.perform_full_scan(target, **options))


def statuses(result):
    return {name: st["status"] for name, st in result["module_status"].items()}


def unreachable(message):
    return {"measured": False, "error": message}


def set_timeout(monkeypatch, seconds, *names):
    """Délai des modules (par défaut, tous les 18) : celui du registre, que l'orchestrateur lit à chaque scan."""
    for name in names or MODULE_FUNCTIONS:
        spec = registry.MODULES[name]
        monkeypatch.setitem(registry.MODULES, name, dataclasses.replace(spec, timeout=seconds))


# =============================================================================
# Cas nominal et contrat de sortie
# =============================================================================


def test_scan_nominal(fake):
    result = run_scan("https://Example.com/chemin?q=1")

    assert result["domain"] == "example.com"
    assert result["ip_address"] == PUBLIC_IP
    assert result["status"] == "success"
    assert result["error_message"] is None
    # Un statut par module, dans l'ordre de référence, tous « ok ».
    assert list(result["module_status"]) == list(orchestrator.MODULE_NAMES)
    assert set(orchestrator.MODULE_NAMES) == set(MODULE_FUNCTIONS)
    assert all(st == {"status": "ok", "error": None} for st in result["module_status"].values())
    # Les résultats des modules sont transmis tels quels.
    assert result["waf"] == HEALTHY["waf"]
    assert result["subdomains"] == HEALTHY["subdomains"]
    assert result["screenshot_path"] == HEALTHY["screenshot"]
    assert result["security_score"] == FAKE_SCORE
    assert isinstance(result["scan_duration"], float)


def test_cles_de_sortie_lues_par_l_api(fake):
    """Toutes les clés que main.scan_domain enregistre sont présentes."""
    result = run_scan()
    expected = {
        "domain",
        "ip_address",
        "dns_records",
        "subdomains",
        "security_headers",
        "tls_certificate",
        "technologies",
        "geo_data",
        "whois_data",
        "open_ports",
        "email_security",
        "waf",
        "redirect_chain",
        "web_files",
        "cookie_security",
        "cors",
        "reverse_dns",
        "subdomain_takeover",
        "network_extended",
        "security_score",
        "module_status",
        "scan_duration",
        "screenshot_path",
        "status",
        "error_message",
    }
    assert expected <= set(result)


def test_entrees_transmises_au_score(fake):
    run_scan()
    data = fake.score_input
    assert data["open_ports"] == HEALTHY["open_ports"]
    assert data["is_ip_target"] is False
    assert data["module_status"]["waf"] == {"status": "ok", "error": None}
    assert data["subdomain_takeover"] == []
    assert data["subdomains_checked"] == 1
    for key in (
        "security_headers",
        "tls_certificate",
        "email_security",
        "waf",
        "cookie_security",
        "cors",
        "redirect_chain",
    ):
        assert data[key] == HEALTHY[key]


def test_sous_domaines_testes_comptes_comme_le_takeover(fake):
    """Le score annonce le nombre de noms réellement testés : sans doublon ni nom invalide, 15 au plus."""
    fake.behaviors["subdomains"] = [
        {"subdomain": "www.example.com", "resolution": "resolved"},
        {"subdomain": "WWW.example.com.", "resolution": "resolved"},
        {"subdomain": "bad..example.com", "resolution": "unresolved"},
        {"subdomain": "", "resolution": "unresolved"},
        {"subdomain": "api.example.com", "resolution": "unresolved"},
    ]
    run_scan()
    assert fake.score_input["subdomains_checked"] == 2

    fake.behaviors["subdomains"] = [{"subdomain": f"h{i}.example.com"} for i in range(40)]
    run_scan()
    assert fake.score_input["subdomains_checked"] == TAKEOVER_MAX_SUBDOMAINS


class _CappedList(list):
    """Comme dns.SubdomainList : liste plafonnée qui retient le nombre de noms trouvés."""

    total_found: int


async def _capped_subdomains(site):
    """Faux find_subdomains : 3 noms gardés sur 9974 trouvés."""
    names = _CappedList({"subdomain": f"h{i}.{site}"} for i in range(3))
    names.total_found = 9974
    return names


def test_nombre_de_sous_domaines_trouves_avant_la_coupe(fake):
    """Liste tronquée à SUBDOMAIN_MAX_RESULTS : le total trouvé est dans module_status."""
    fake.behaviors["subdomains"] = _capped_subdomains
    result = run_scan()
    assert result["module_status"]["subdomains"] == {"status": "ok", "error": None, "total_found": 9974}
    assert len(result["subdomains"]) == 3
    assert fake.called("subdomain_takeover")


async def _fallback_subdomains(site):
    """Faux find_subdomains servi par la source de secours (Cert Spotter)."""
    names = _CappedList([{"subdomain": f"www.{site}"}])
    names.total_found = 1
    names.source = "certspotter"
    names.partial = True
    return names


def test_source_de_secours_des_sous_domaines_signalee(fake):
    fake.behaviors["subdomains"] = _fallback_subdomains
    status = run_scan()["module_status"]["subdomains"]
    assert status == {
        "status": "ok",
        "error": None,
        "total_found": 1,
        "source": "certspotter",
        "partial": True,
    }


def test_pas_de_total_sans_liste_plafonnee_ni_en_cas_d_echec(fake):
    # Liste ordinaire (module antérieur) : aucune clé ajoutée.
    assert run_scan()["module_status"]["subdomains"] == {"status": "ok", "error": None}

    fake.behaviors["subdomains"] = ModuleError("crt.sh indisponible (HTTP 502)")
    assert "total_found" not in run_scan()["module_status"]["subdomains"]


def test_modules_appeles_avec_la_cible_et_l_apex(fake):
    run_scan("blog.example.com")
    # Les modules web visent l'hôte demandé, WHOIS / email / crt.sh l'apex.
    assert fake.args_of("security_headers") == ("blog.example.com",)
    assert fake.args_of("tls_certificate") == ("blog.example.com",)
    assert fake.args_of("whois_data") == ("example.com",)
    assert fake.args_of("email_security") == ("example.com",)
    assert fake.args_of("subdomains") == ("example.com",)
    assert fake.args_of("subdomain_takeover") == (HEALTHY["subdomains"],)
    assert fake.args_of("network_extended") == (PUBLIC_IP, "blog.example.com")


def test_dmarc_evalue_pour_l_hote_scanne(fake):
    """SPF et DKIM sur l'apex, DMARC sur la cible : les onglets DNS et Email concordent."""
    run_scan("news.example.com")
    assert fake.args_of("email_security") == ("example.com",)
    assert fake.kwargs["email_security"] == {"dmarc_domain": "news.example.com"}
    assert fake.args_of("dns_records") == ("news.example.com",)


@pytest.mark.parametrize(
    "target, site, apex",
    [
        ("alice.github.io", "alice.github.io", "github.io"),
        ("www.alice.github.io", "alice.github.io", "github.io"),
        ("myapp.herokuapp.com", "myapp.herokuapp.com", "herokuapp.com"),
        ("evil-login.pages.dev", "evil-login.pages.dev", "pages.dev"),
    ],
)
def test_hote_d_une_plateforme_mutualisee(fake, target, site, apex):
    """Suffixe privé de la PSL : la plateforme n'est pas la cible."""
    result = run_scan(target)
    # Énumération CT (puis takeover) sur le site, pas sur toute la plateforme.
    assert fake.args_of("subdomains") == (site,)
    assert fake.called("subdomain_takeover")
    # WHOIS : seul le nom enregistré au registre existe.
    assert fake.args_of("whois_data") == (apex,)
    # L'email de la plateforme n'est pas celui de la cible : ni analysé, ni noté.
    assert not fake.called("email_security")
    assert result["module_status"]["email_security"] == {
        "status": "skipped",
        "error": orchestrator._SKIP_SHARED_PLATFORM,
    }
    assert "plateforme mutualisée" in fr(result["module_status"]["email_security"]["error"])
    assert result["email_security"] == {"measured": False, "error": None, "overall_grade": "N/A"}
    assert result["status"] == "success"
    # Les modules web visent toujours l'hôte demandé.
    assert fake.args_of("security_headers") == (target,)


def test_plateforme_mutualisee_email_non_note(fake, monkeypatch):
    """Le critère email d'un hôte mutualisé est « non applicable », pas noté sur la plateforme."""
    from domainrecon.scanner.score import compute_security_score

    monkeypatch.setattr(orchestrator, "compute_security_score", compute_security_score)
    result = run_scan("alice.github.io")
    email = result["security_score"]["breakdown"]["email"]
    assert email["measured"] is False
    assert "plateforme mutualisée" in fr(email["detail"])


@pytest.mark.parametrize("target", ["github.io", "s3.amazonaws.com", "example.co.uk", "blog.example.co.uk"])
def test_domaine_ordinaire_ou_plateforme_elle_meme_inchange(fake, target):
    """Hors hébergement mutualisé (ou pour la plateforme elle-même), comportement inchangé."""
    run_scan(target)
    assert fake.called("email_security")
    assert fake.args_of("subdomains") == fake.args_of("whois_data") == fake.args_of("email_security")


# =============================================================================
# Politique de cibles : contrôle préalable, erreurs propagées
# =============================================================================


def test_controle_de_la_cible_avant_tout_module(fake):
    run_scan()
    assert fake.calls[0] == ("ensure_target_allowed", ("example.com",))
    assert [name for name, _ in fake.calls].count("ensure_target_allowed") == 1


def test_cible_refusee_propage_target_not_allowed(fake):
    fake.addresses = TargetNotAllowedError("Cible refusée : adresse non publique")
    with pytest.raises(TargetNotAllowedError, match="adresse non publique"):
        run_scan()
    # Aucun module n'a été lancé.
    assert [name for name, _ in fake.calls] == ["ensure_target_allowed"]


def test_cible_invalide_leve_valueerror_sans_resolution(fake):
    with pytest.raises(ValueError, match="Cible invalide"):
        run_scan("exa mple.com")
    assert fake.calls == []


def test_ports_et_reseau_sur_l_adresse_validee(fake):
    """Les modules par IP utilisent l'adresse contrôlée, sans nouvelle résolution."""
    fake.addresses = [PUBLIC_IPV6, "198.51.100.7"]
    result = run_scan()
    # Première IPv4, sinon première IPv6.
    assert result["ip_address"] == "198.51.100.7"
    for name in ("open_ports", "geo_data", "reverse_dns"):
        assert fake.args_of(name) == ("198.51.100.7",)


def test_ipv6_seule(fake):
    fake.addresses = [PUBLIC_IPV6]
    result = run_scan()
    assert result["ip_address"] == PUBLIC_IPV6
    assert fake.args_of("open_ports") == (PUBLIC_IPV6,)


def test_module_bloque_par_la_politique_de_cibles(fake):
    """Une redirection refusée en cours de module fait échouer le module, pas le scan."""
    fake.behaviors["cors"] = TargetNotAllowedError("Redirection vers une adresse non publique refusée")
    result = run_scan()
    assert result["module_status"]["cors"] == {
        "status": "failed",
        "error": "Redirection vers une adresse non publique refusée",
    }
    assert result["status"] == "partial"


# =============================================================================
# Traduction des issues des modules en module_status
# =============================================================================


def test_module_qui_leve_une_exception(fake):
    fake.behaviors["waf"] = RuntimeError("boom")
    result = run_scan()

    assert fr(result["module_status"]["waf"]) == {"status": "failed", "error": "RuntimeError: boom"}
    assert fr(result["waf"]) == {"measured": False, "error": "RuntimeError: boom"}
    assert result["status"] == "partial"
    assert fr(result["error_message"]) == "1 module(s) en échec : waf"
    # Les autres modules ne sont pas affectés.
    assert statuses(result)["cors"] == "ok"


def test_module_error_sur_un_module_liste(fake):
    fake.behaviors["technologies"] = ModuleError("Page d'accueil injoignable")
    result = run_scan()
    assert result["module_status"]["technologies"] == {
        "status": "failed",
        "error": "Page d'accueil injoignable",
    }
    # Une liste reste une liste.
    assert result["technologies"] == []
    assert result["status"] == "partial"


def test_module_error_sans_message(fake):
    """Une ModuleError sans texte : message générique d'échec du module."""
    fake.behaviors["waf"] = ModuleError()
    result = run_scan()
    assert fr(result["module_status"]["waf"]) == {"status": "failed", "error": "Échec du module"}
    assert result["status"] == "partial"


def test_en_tetes_en_echec_gardent_leur_structure(fake):
    fake.behaviors["security_headers"] = ModuleError("Site injoignable")
    result = run_scan()
    headers = result["security_headers"]
    assert headers["measured"] is False and headers["error"] == "Site injoignable"
    assert headers["headers_found"] == {}
    assert headers["headers_missing"] == list(SECURITY_HEADERS)
    # Même forme que le résultat « non mesuré » du module lui-même.
    assert headers == empty_headers_result("Site injoignable")


def test_dict_non_mesure_compte_comme_echec(fake):
    fake.behaviors["cors"] = {"measured": False, "error": "Connexion refusée", "misconfigured": False}
    result = run_scan()
    assert result["module_status"]["cors"] == {"status": "failed", "error": "Connexion refusée"}
    # Le dict renvoyé par le module est conservé.
    assert result["cors"] == fake.behaviors["cors"]
    assert result["status"] == "partial"


def test_dict_non_mesure_sans_message(fake):
    fake.behaviors["web_files"] = {"measured": False, "error": None}
    result = run_scan()
    assert fr(result["module_status"]["web_files"]) == {"status": "failed", "error": "Mesure impossible"}


def test_dict_sans_objet_signale_par_le_module(fake):
    """Un module peut se déclarer sans objet (skipped) : pas un échec."""
    reason = "Adresse non publique : géolocalisation sans objet (aucun service tiers interrogé)"
    fake.behaviors["geo_data"] = {"measured": False, "error": reason, "skipped": True}
    result = run_scan()
    assert result["module_status"]["geo_data"] == {"status": "skipped", "error": reason}
    assert result["geo_data"]["skipped"] is True
    assert result["status"] == "success"


def test_dict_sans_objet_sans_message(fake):
    """Un module sans objet qui ne dit pas pourquoi : raison générique, statut global intact."""
    fake.behaviors["geo_data"] = {"measured": False, "error": None, "skipped": True}
    result = run_scan()
    assert fr(result["module_status"]["geo_data"]) == {
        "status": "skipped",
        "error": "Sans objet pour cette cible",
    }
    assert result["status"] == "success"


def test_dict_skipped_mais_mesure_reste_ok(fake):
    fake.behaviors["geo_data"] = {"measured": True, "error": None, "skipped": True}
    assert statuses(run_scan())["geo_data"] == "ok"


def test_dict_sans_drapeau_juge_sur_error(fake):
    fake.behaviors["whois_data"] = {"registrar": None, "error": "Serveur WHOIS injoignable"}
    result = run_scan()
    assert result["module_status"]["whois_data"]["status"] == "failed"


def test_resultat_vide_mais_mesure_reste_ok(fake):
    """« Rien trouvé » n'est pas un échec : liste vide ou dict mesuré sans donnée."""
    fake.behaviors["technologies"] = []
    fake.behaviors["waf"] = {"detected": False, "measured": True, "error": None}
    result = run_scan()
    assert statuses(result)["technologies"] == "ok"
    assert statuses(result)["waf"] == "ok"
    assert result["status"] == "success"


def test_module_hors_delai(fake, monkeypatch):
    set_timeout(monkeypatch, 0.05)
    state = {"cancelled": False}

    async def slow(domain):
        try:
            await asyncio.sleep(30)
        except asyncio.CancelledError:
            state["cancelled"] = True
            raise

    fake.behaviors["web_files"] = slow
    started = time.monotonic()
    result = run_scan()

    assert time.monotonic() - started < 5
    assert fr(result["module_status"]["web_files"]) == {
        "status": "timeout",
        "error": "Délai dépassé (0.05 s)",
    }
    assert fr(result["web_files"]) == {"measured": False, "error": "Délai dépassé (0.05 s)"}
    assert result["status"] == "partial"
    assert fr(result["error_message"]) == "1 module(s) en échec : web_files (délai dépassé)"
    # Le module a bien été interrompu, pas abandonné en arrière-plan.
    assert state["cancelled"] is True


def test_timeout_interne_d_un_module(fake):
    fake.behaviors["tls_certificate"] = TimeoutError("timed out")
    result = run_scan()
    assert fr(result["module_status"]["tls_certificate"]) == {
        "status": "timeout",
        "error": "Délai dépassé : timed out",
    }


def test_capture_impossible(fake):
    fake.behaviors["screenshot"] = ModuleError("Capture d'écran impossible : délai de navigation dépassé")
    result = run_scan()
    assert result["module_status"]["screenshot"] == {
        "status": "failed",
        "error": "Capture d'écran impossible : délai de navigation dépassé",
    }
    assert result["screenshot_path"] is None
    assert result["status"] == "partial"


def test_capture_sans_playwright_ignoree(fake):
    """capture_screenshot renvoie None seulement si Playwright ou Chromium est absent."""
    fake.behaviors["screenshot"] = None
    result = run_scan()
    assert fr(result["module_status"]["screenshot"]) == {
        "status": "skipped",
        "error": "Playwright ou son navigateur Chromium n'est pas installé",
    }
    assert result["screenshot_path"] is None
    # « skipped » ne dégrade pas le statut global.
    assert result["status"] == "success"


def test_module_qui_ne_renvoie_rien(fake):
    fake.behaviors["web_files"] = None
    result = run_scan()
    assert fr(result["module_status"]["web_files"]) == {
        "status": "failed",
        "error": "Aucun résultat renvoyé par le module",
    }
    assert result["web_files"]["measured"] is False


def test_journaux_des_modules_en_francais(fake, monkeypatch, caplog):
    """Les journaux restent lisibles : les messages y sont rendus en français, jamais bruts."""
    set_timeout(monkeypatch, 0.05)

    async def slow(domain):
        await asyncio.sleep(30)

    fake.behaviors["waf"] = RuntimeError("boom")
    fake.behaviors["web_files"] = slow
    fake.behaviors["cors"] = {"measured": False, "error": None}
    fake.behaviors["screenshot"] = None
    with caplog.at_level(logging.DEBUG, logger="domainrecon.scanner"):
        run_scan()

    assert "Module waf en échec sur example.com — RuntimeError: boom" in caplog.messages
    assert "Module web_files hors délai sur example.com — Délai dépassé (0.05 s)" in caplog.messages
    assert "Module cors non mesuré sur example.com — Mesure impossible" in caplog.messages
    assert (
        "Module screenshot sans objet sur example.com — Playwright ou son navigateur Chromium n'est pas installé"
        in caplog.messages
    )
    assert not any("$t" in message for message in caplog.messages)


# =============================================================================
# Cible IP littérale (CRIT-1)
# =============================================================================


def test_cible_ip_litterale(fake):
    result = run_scan(f"http://{PUBLIC_IP}/")

    assert result["domain"] == PUBLIC_IP
    assert result["ip_address"] == PUBLIC_IP
    for name in NOT_FOR_IP:
        assert result["module_status"][name]["status"] == "skipped", name
        assert fr(result["module_status"][name]["error"]) == "Sans objet pour une adresse IP"
        assert not fake.called(name), name
    for name in IP_MODULES:
        assert fake.args_of(name)[0] == PUBLIC_IP
    assert fake.args_of("security_headers") == (PUBLIC_IP,)

    # Les critères sans objet sont non mesurés, pas notés 0.
    assert result["email_security"] == {"measured": False, "error": None, "overall_grade": "N/A"}
    assert result["subdomains"] == [] and result["subdomain_takeover"] == []
    assert fake.score_input["is_ip_target"] is True
    assert fake.score_input["subdomains_checked"] == 0
    assert result["status"] == "success"
    assert result["error_message"] is None


def test_hsts_sans_effet_avec_certificat_invalide(fake):
    """Régression : un HSTS servi avec un certificat invalide restait « Conforme »."""
    fake.behaviors["security_headers"] = {
        "checks": {"Strict-Transport-Security": {"value": "max-age=31536000", "status": "ok", "detail": ""}},
        "score": "1/6",
        "url": "https://example.com/",
        "https": True,
        "measured": True,
        "error": None,
    }
    fake.behaviors["tls_certificate"] = {
        **HEALTHY["tls_certificate"],
        "valid": False,
        "verify_error": "expiré",
    }
    result = run_scan()

    hsts = result["security_headers"]["checks"]["Strict-Transport-Security"]
    assert hsts["status"] == "invalid"
    assert "Certificat TLS invalide" in fr(hsts["detail"])
    # Le score reçoit les en-têtes réévalués.
    assert fake.score_input["security_headers"]["checks"]["Strict-Transport-Security"]["status"] == "invalid"


def test_hsts_intact_avec_certificat_valide(fake):
    fake.behaviors["security_headers"] = {
        "checks": {"Strict-Transport-Security": {"value": "max-age=31536000", "status": "ok", "detail": ""}},
        "url": "https://example.com/",
        "https": True,
        "measured": True,
        "error": None,
    }
    result = run_scan()

    assert result["security_headers"]["checks"]["Strict-Transport-Security"]["status"] == "ok"


def test_cible_ip_score_reel_exclut_email_et_takeover(fake, monkeypatch):
    """Régression CRIT-1 : le critère email d'une IP n'est plus compté 0/15."""
    from domainrecon.scanner.score import compute_security_score

    monkeypatch.setattr(orchestrator, "compute_security_score", compute_security_score)
    result = run_scan(PUBLIC_IP)
    breakdown = result["security_score"]["breakdown"]
    # Ni mesurés ni comptés : ils n'entrent pas dans le score.
    for key in ("email", "takeover"):
        assert breakdown[key]["measured"] is False
        assert breakdown[key]["counted"] is False


# =============================================================================
# Cible injoignable et délai de résolution (SSRF-6)
# =============================================================================


def _web_down(fake, message="Nom de domaine introuvable"):
    for name in HTTP_MODULES + ("tls_certificate", "web_files"):
        fake.behaviors[name] = unreachable(message)
    fake.behaviors["technologies"] = ModuleError("Page d'accueil injoignable")
    fake.behaviors["screenshot"] = ModuleError("Capture d'écran impossible")


def test_cible_injoignable(fake):
    fake.addresses = []
    _web_down(fake)
    result = run_scan("absent.example.com")

    assert result["status"] == "error"
    assert fr(result["error_message"]) == "Cible injoignable : aucune résolution DNS ni réponse HTTP"
    assert result["ip_address"] is None
    # Pas d'adresse : les modules par IP ne sont pas lancés.
    for name in IP_MODULES:
        assert fr(result["module_status"][name]) == {
            "status": "skipped",
            "error": "Aucune adresse IP résolue pour la cible",
        }
        assert not fake.called(name)
    for name in HTTP_MODULES:
        assert result["module_status"][name] == {"status": "failed", "error": "Nom de domaine introuvable"}
    # Capture : sans objet faute d'adresse, comme les modules par IP (pas un échec).
    assert fr(result["module_status"]["screenshot"]) == {
        "status": "skipped",
        "error": "Aucune adresse IP résolue pour la cible",
    }
    assert not fake.called("screenshot")
    # Le scan reste complet et enregistrable.
    assert list(result["module_status"]) == list(orchestrator.MODULE_NAMES)
    assert result["open_ports"] == [] and result["geo_data"]["measured"] is False


def test_domaine_inexistant_nxdomain(fake):
    """Régression : un NXDOMAIN était résumé en « Cible injoignable »."""
    fake.addresses = []
    _web_down(fake)
    fake.behaviors["dns_records"] = {
        "A": [],
        "nxdomain": True,
        "notes": ["Domaine inexistant (NXDOMAIN) : absent.example.com"],
        "measured": True,
        "error": None,
    }
    result = run_scan("absent.example.com")

    assert result["status"] == "error"
    assert fr(result["error_message"]) == "Domaine inexistant (NXDOMAIN)"


def test_nxdomain_ignore_si_le_module_dns_n_est_pas_ok(fake):
    """Un indicateur nxdomain dans un résultat non mesuré ne fait pas foi."""
    fake.addresses = []
    _web_down(fake)
    fake.behaviors["dns_records"] = {"nxdomain": True, "measured": False, "error": "Délai dépassé"}
    result = run_scan("absent.example.com")

    assert fr(result["error_message"]) == "Cible injoignable : aucune résolution DNS ni réponse HTTP"


def test_sans_resolution_mais_reponse_http(fake):
    fake.addresses = []
    result = run_scan()
    assert result["status"] == "partial"
    assert fr(result["error_message"]) == "Aucune adresse IP résolue pour la cible"


def test_ip_resolue_mais_web_injoignable_reste_partial(fake):
    """DNS, WHOIS, ports… mesurés : partial, mais le résumé dit d'abord que le site est injoignable."""
    _web_down(fake, "Connexion refusée")
    result = run_scan()
    assert result["status"] == "partial"
    assert fr(result["error_message"]).startswith(
        "Site injoignable en HTTP et en HTTPS depuis le scanner ; 9 module(s) en échec : "
    )


def test_un_seul_module_http_joint_suffit_a_ecarter_site_injoignable(fake):
    _web_down(fake, "Connexion refusée")
    fake.behaviors["cors"] = HEALTHY["cors"]
    result = run_scan()
    assert result["status"] == "partial"
    message = fr(result["error_message"])
    assert message.startswith("8 module(s) en échec : ")
    assert "injoignable" not in message


def test_resolution_hors_delai(fake, monkeypatch):
    monkeypatch.setattr(orchestrator, "TARGET_RESOLVE_TIMEOUT", 0.05)

    async def slow_resolution(host):
        await asyncio.sleep(30)

    fake.addresses = slow_resolution
    _web_down(fake)
    started = time.monotonic()
    result = run_scan()

    assert time.monotonic() - started < 5
    assert result["status"] == "error"
    assert fr(result["error_message"]) == (
        "Cible injoignable : résolution DNS hors délai (0.05 s) et aucune réponse HTTP"
    )
    assert not any(fake.called(name) for name in (*IP_MODULES, "screenshot"))


def test_resolution_hors_delai_mais_reponse_http(fake, monkeypatch):
    monkeypatch.setattr(orchestrator, "TARGET_RESOLVE_TIMEOUT", 0.05)

    async def slow_resolution(host):
        await asyncio.sleep(30)

    fake.addresses = slow_resolution
    result = run_scan()
    assert result["status"] == "partial"
    # La capture, sans adresse validée, est sans objet : elle ne gonfle pas la liste des échecs.
    assert fr(result["error_message"]) == "Résolution DNS de la cible hors délai (0.05 s)"
    assert result["module_status"]["screenshot"]["status"] == "skipped"
    assert result["ip_address"] is None


# =============================================================================
# Takeover : dépendance aux sous-domaines et budget (ARCH-3, SCAN-3)
# =============================================================================


def test_takeover_hors_delai(fake, monkeypatch):
    set_timeout(monkeypatch, 0.05, "subdomain_takeover")

    async def slow_takeover(subdomains):
        await asyncio.sleep(30)

    fake.behaviors["subdomain_takeover"] = slow_takeover
    started = time.monotonic()
    result = run_scan()

    assert time.monotonic() - started < 5
    assert fr(result["module_status"]["subdomain_takeover"]) == {
        "status": "timeout",
        "error": "Délai dépassé (0.05 s)",
    }
    assert result["subdomain_takeover"] == []
    assert fake.score_input["subdomains_checked"] == 0
    assert result["status"] == "partial"


def test_takeover_ignore_sans_sous_domaine(fake):
    fake.behaviors["subdomains"] = []
    result = run_scan()
    assert fr(result["module_status"]["subdomain_takeover"]) == {
        "status": "skipped",
        "error": "Aucun sous-domaine à tester",
    }
    assert not fake.called("subdomain_takeover")
    assert fake.score_input["subdomains_checked"] == 0
    assert result["status"] == "success"


@pytest.mark.parametrize(
    "failure, subdomains_status",
    [
        (
            ModuleError("crt.sh indisponible (HTTP 502)"),
            {"status": "failed", "error": "crt.sh indisponible (HTTP 502)"},
        ),
        (
            TimeoutError("crt.sh : délai dépassé (30 s)"),
            {"status": "timeout", "error": "Délai dépassé : crt.sh : délai dépassé (30 s)"},
        ),
    ],
)
def test_takeover_non_verifie_si_enumeration_en_echec(fake, failure, subdomains_status):
    """Le takeover s'applique à la cible : non vérifié faute de sous-domaines, c'est un échec,
    pas un module « sans objet » (skipped)."""
    fake.behaviors["subdomains"] = failure
    result = run_scan()
    assert fr(result["module_status"]["subdomains"]) == subdomains_status
    assert fr(result["module_status"]["subdomain_takeover"]) == {
        "status": "failed",
        "error": "Non vérifié : énumération des sous-domaines en échec",
    }
    assert result["subdomain_takeover"] == []
    assert not fake.called("subdomain_takeover")
    assert fake.score_input["subdomains_checked"] == 0
    assert result["status"] == "partial"
    label = "subdomains (délai dépassé)" if subdomains_status["status"] == "timeout" else "subdomains"
    assert fr(result["error_message"]) == f"2 module(s) en échec : {label}, subdomain_takeover"


def test_takeover_non_verifie_non_note_comme_sans_objet(fake, monkeypatch):
    """Score réel : le critère takeover est non mesuré (échec), pas « Non applicable »."""
    from domainrecon.scanner.score import compute_security_score

    monkeypatch.setattr(orchestrator, "compute_security_score", compute_security_score)
    fake.behaviors["subdomains"] = ModuleError("crt.sh : délai dépassé (30 s)")
    takeover = run_scan()["security_score"]["breakdown"]["takeover"]
    assert takeover["measured"] is False
    assert "Non applicable" not in fr(takeover["detail"])


def test_takeover_n_attend_pas_les_autres_modules(fake, monkeypatch):
    """Le takeover démarre dès la fin de l'énumération, pendant les autres modules."""
    set_timeout(monkeypatch, 5)

    async def run():
        takeover_started = asyncio.Event()

        async def takeover(subdomains):
            takeover_started.set()
            return []

        async def web_files(domain):
            # Ne se termine que si le takeover démarre pendant son exécution.
            await takeover_started.wait()
            return HEALTHY["web_files"]

        fake.behaviors["subdomain_takeover"] = takeover
        fake.behaviors["web_files"] = web_files
        return await orchestrator.perform_full_scan("example.com", **TOUS_LES_MODULES)

    result = asyncio.run(run())
    assert statuses(result)["web_files"] == "ok"
    assert statuses(result)["subdomain_takeover"] == "ok"


# =============================================================================
# Annulation : jamais avalée (SCAN-3, ARCH-3)
# =============================================================================


def _cancel_while_running(fake, module_name):
    state = {"cancelled": False}

    async def run():
        running = asyncio.Event()

        async def slow(*args):
            running.set()
            try:
                await asyncio.sleep(30)
            except asyncio.CancelledError:
                state["cancelled"] = True
                raise

        fake.behaviors[module_name] = slow
        task = asyncio.ensure_future(orchestrator.perform_full_scan("example.com", **TOUS_LES_MODULES))
        await asyncio.wait_for(running.wait(), timeout=5)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
        return task

    started = time.monotonic()
    task = asyncio.run(run())
    assert time.monotonic() - started < 5
    assert task.cancelled()
    assert state["cancelled"] is True


def test_un_module_ne_capture_jamais_l_annulation():
    """L'enveloppe d'un module relaie CancelledError au lieu d'en faire un statut."""

    async def run():
        running = asyncio.Event()

        async def slow():
            running.set()
            await asyncio.sleep(30)

        task = asyncio.ensure_future(orchestrator._run_module("waf", slow, 10, "example.com"))
        await asyncio.wait_for(running.wait(), timeout=5)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task

    asyncio.run(run())


def test_annulation_pendant_les_modules(fake):
    _cancel_while_running(fake, "whois_data")


def test_annulation_pendant_le_takeover(fake):
    _cancel_while_running(fake, "subdomain_takeover")


def test_annulation_pendant_la_resolution(fake):
    state = {"cancelled": False}

    async def run():
        running = asyncio.Event()

        async def slow_resolution(host):
            running.set()
            try:
                await asyncio.sleep(30)
            except asyncio.CancelledError:
                state["cancelled"] = True
                raise

        fake.addresses = slow_resolution
        task = asyncio.ensure_future(orchestrator.perform_full_scan("example.com"))
        await asyncio.wait_for(running.wait(), timeout=5)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task

    asyncio.run(run())
    assert state["cancelled"] is True
    assert [name for name, _ in fake.calls] == ["ensure_target_allowed"]


# =============================================================================
# Bout en bout : le résultat réel de l'orchestrateur passe par l'API
# =============================================================================


def test_resultat_enregistre_par_l_api(fake, monkeypatch):
    from fastapi.testclient import TestClient

    from domainrecon.api import app as main

    # Si l'API contrôle elle-même la cible, elle utilise le même faux.
    if hasattr(main, "ensure_target_allowed"):
        monkeypatch.setattr(main, "ensure_target_allowed", fake._fake_ensure)
    fake.behaviors["waf"] = ModuleError("Page d'accueil injoignable")

    with TestClient(main.app) as client:
        response = client.post("/api/scan", json={"domain": "example.com"})
        assert response.status_code == 200, response.text
        body = response.json()
        assert body["status"] == "partial"
        assert body["module_status"]["waf"] == {"status": "failed", "error": "Page d'accueil injoignable"}

        stored = client.get(f"/api/scan/{body['id']}").json()
        assert stored["module_status"] == body["module_status"]
        assert stored["error_message"] == "1 module(s) en échec : waf"


def test_messages_de_l_orchestrateur_rendus_par_l_api(fake, monkeypatch):
    """Les messages du résultat réel sont enregistrés tels quels, puis rendus dans la langue demandée."""
    from fastapi.testclient import TestClient

    from domainrecon.api import app as main

    if hasattr(main, "ensure_target_allowed"):
        monkeypatch.setattr(main, "ensure_target_allowed", fake._fake_ensure)
    fake.addresses = []
    fake.behaviors["waf"] = RuntimeError("boom")

    with TestClient(main.app) as client:
        response = client.post("/api/scan", json={"domain": "example.com"})
        assert response.status_code == 200, response.text
        scan_id = response.json()["id"]
        francais = client.get(f"/api/scan/{scan_id}").json()
        anglais = client.get(f"/api/scan/{scan_id}?lang=en").json()

    assert francais["error_message"] == "Aucune adresse IP résolue pour la cible ; 1 module(s) en échec : waf"
    assert anglais["error_message"] == "No IP address resolved for the target; 1 module(s) failed: waf"
    assert francais["module_status"]["geo_data"]["error"] == "Aucune adresse IP résolue pour la cible"
    assert anglais["module_status"]["geo_data"]["error"] == "No IP address resolved for the target"
    assert anglais["module_status"]["waf"]["error"] == "RuntimeError: boom"


def test_cible_invalide_traduite_par_l_api(fake):
    """Le message de la ValueError de l'orchestrateur est rendu dans la langue demandée, avec son code."""
    from fastapi.testclient import TestClient

    from domainrecon.api import app as main

    with TestClient(main.app) as client:
        francais = client.post("/api/scan", json={"domain": "pas une cible"})
        anglais = client.post("/api/scan?lang=en", json={"domain": "pas une cible"})

    assert francais.status_code == anglais.status_code == 400
    assert francais.json()["detail"] == "Cible invalide : 'pas une cible'"
    assert anglais.json() == {
        "detail": "Invalid target: 'pas une cible'",
        "code": "target.invalid",
        "params": {"target": "'pas une cible'"},
    }
    assert fake.calls == []


def test_liste_plafonnee_enregistree_par_l_api(fake, monkeypatch):
    """La liste de sous-domaines (sous-classe de list) s'enregistre en JSON, total compris."""
    from fastapi.testclient import TestClient

    from domainrecon.api import app as main

    fake.behaviors["subdomains"] = _capped_subdomains
    with TestClient(main.app) as client:
        response = client.post("/api/scan", json={"domain": "plafond.example.com"})
        assert response.status_code == 200, response.text
        stored = client.get(f"/api/scan/{response.json()['id']}").json()
    assert stored["module_status"]["subdomains"]["total_found"] == 9974
    # Énumération sur le site (example.com), pas sur l'hôte scanné.
    assert [s["subdomain"] for s in stored["subdomains"]] == [f"h{i}.example.com" for i in range(3)]


# =============================================================================
# Rappel on_module (avancement en direct)
# =============================================================================


def _scan_avec_rappel(target="example.com", rappel=None):
    appels = []

    def enregistrer(name, status, duration):
        appels.append((name, status, duration))

    result = asyncio.run(
        orchestrator.perform_full_scan(target, on_module=rappel or enregistrer, **TOUS_LES_MODULES)
    )
    return result, appels


def test_rappel_une_fois_par_module(fake):
    result, appels = _scan_avec_rappel()
    assert sorted(name for name, _, _ in appels) == sorted(orchestrator.MODULE_NAMES)
    assert {name: status for name, status, _ in appels} == statuses(result)
    assert all(isinstance(duration, float) and duration >= 0 for _, _, duration in appels)


def test_rappel_takeover_apres_les_sous_domaines(fake):
    _, appels = _scan_avec_rappel()
    noms = [name for name, _, _ in appels]
    assert noms.index("subdomains") < noms.index("subdomain_takeover")


def test_rappel_modules_sans_objet_sur_une_ip(fake):
    result, appels = _scan_avec_rappel(PUBLIC_IP)
    rapportes = {name: status for name, status, _ in appels}
    for name in NOT_FOR_IP:
        assert rapportes[name] == "skipped"
    assert rapportes == statuses(result)


def test_rappel_en_echec_n_interrompt_pas_le_scan(fake):
    def casse(name, status, duration):
        raise RuntimeError("rappel cassé")

    result, _ = _scan_avec_rappel(rappel=casse)
    assert set(result["module_status"]) == set(orchestrator.MODULE_NAMES)
    assert result["status"] == "success"


def test_rappel_statut_hors_delai(fake):
    fake.behaviors["waf"] = asyncio.TimeoutError()
    _, appels = _scan_avec_rappel()
    assert ("waf", "timeout") in {(name, status) for name, status, _ in appels}


def test_cible_invalide_aucun_rappel(fake):
    appels = []
    with pytest.raises(ValueError):
        asyncio.run(
            orchestrator.perform_full_scan("pas une cible", on_module=lambda *args: appels.append(args))
        )
    assert appels == []


# =============================================================================
# Vagues, profils, autorisation et clés API (registre de démonstration)
# =============================================================================

# Profil « rapide » : sans l'énumération des sous-domaines, le WHOIS, les voisins réseau et la
# capture d'écran, trop lents, ni les modules actifs (ports, takeover).
QUICK_MODULES = (
    "dns_records",
    "security_headers",
    "tls_certificate",
    "technologies",
    "geo_data",
    "email_security",
    "waf",
    "redirect_chain",
    "web_files",
    "cookie_security",
    "cors",
    "reverse_dns",
)

# Modules actifs : seulement en profil « personnalise » et avec l'autorisation de tester la cible.
ACTIVE_MODULES = ("open_ports", "subdomain_takeover")
# Profil « complet » : les 16 modules passifs.
COMPLETE_MODULES = tuple(name for name in orchestrator.MODULE_NAMES if name not in ACTIVE_MODULES)

OK = {"measured": True, "error": None}


def demo_spec(name, run=None, **fields) -> ModuleSpec:
    """Module de démonstration ; sans `run`, il réussit sans rien dire."""

    async def succeed(context):
        return dict(OK)

    fields = {"family": "web", "category": "passif", **fields}
    return ModuleSpec(name=name, run=run or succeed, **fields)


@pytest.fixture
def demo(fake, monkeypatch):
    """Registre de démonstration à la place de MODULES (get_modules le lit à chaque scan).

    Aucun des 18 modules d'origine n'y figure. Renvoie la fonction qui enregistre les modules donnés.
    """
    monkeypatch.setattr(registry, "MODULES", {})

    def add(*specs):
        for spec in specs:
            registry.register(spec)
        registry.validate_registry()

    return add


def run_scan_with(target="example.com", **options):
    """Scan avec options (profil, autorisation, clés…) : renvoie le résultat et les appels du rappel."""
    calls = []
    result = asyncio.run(
        orchestrator.perform_full_scan(target, on_module=lambda *args: calls.append(args), **options)
    )
    return result, calls


def test_parametres_du_profil_et_de_l_autorisation():
    parameters = inspect.signature(orchestrator.perform_full_scan).parameters

    assert parameters["profile"].default == "complet"
    assert parameters["authorized_target"].default is False


def test_scan_des_18_modules_sans_resultat_generique(fake):
    """`modules` vaut {} (et non NULL, qui désigne un scan d'avant la v2) sans module propre au registre."""
    assert run_scan()["modules"] == {}


# --- Vagues ---------------------------------------------------------------------


def test_vagues_dans_l_ordre_et_modules_d_une_vague_en_parallele(demo):
    journal = []
    a_started, b_started = asyncio.Event(), asyncio.Event()

    async def a(context):
        journal.append("a début")
        a_started.set()
        # Ne se termine que si b démarre pendant son exécution : a et b tournent ensemble.
        await b_started.wait()
        journal.append("a fin")
        return dict(OK)

    async def b(context):
        journal.append("b début")
        b_started.set()
        await a_started.wait()
        await asyncio.sleep(0.05)
        journal.append("b fin")
        return dict(OK)

    def step(name):
        async def run(context):
            journal.append(f"{name} début")
            await asyncio.sleep(0.02)
            journal.append(f"{name} fin")
            return dict(OK)

        return run

    # Enregistrés dans le désordre des vagues.
    demo(
        demo_spec("tard", step("tard"), wave=3, timeout=5),
        demo_spec("milieu", step("milieu"), wave=2, timeout=5),
        demo_spec("a", a, timeout=5),
        demo_spec("b", b, timeout=5),
    )
    result, calls = run_scan_with()

    assert statuses(result) == {"a": "ok", "b": "ok", "milieu": "ok", "tard": "ok"}
    # La vague 1 (a, b) est finie avant le départ de la vague 2, elle-même finie avant la 3e.
    assert journal.index("milieu début") > max(journal.index("a fin"), journal.index("b fin"))
    assert journal.index("tard début") > journal.index("milieu fin")
    # module_status suit l'ordre d'exécution : vague, puis enregistrement.
    assert list(result["module_status"]) == ["a", "b", "milieu", "tard"]
    assert [name for name, _, _ in calls][2:] == ["milieu", "tard"]


def test_chaque_module_recoit_les_resultats_des_vagues_precedentes(demo):
    seen = {}

    async def reussit(context):
        return {**OK, "valeur": 1}

    async def echoue(context):
        raise ModuleError("indisponible")

    def observe(name):
        async def run(context):
            seen[name] = {
                "cible": (context.domain, context.apex, context.site),
                "adresses": list(context.addresses),
                "resultats": dict(context.results),
            }
            return {**OK, "de": name}

        return run

    demo(
        demo_spec("reussit", reussit),
        demo_spec("echoue", echoue),
        demo_spec("sans_objet", skip_reason=lambda context: msg("orchestrator.skip_generic")),
        demo_spec("deux", observe("deux"), wave=2, depends_on=("reussit", "echoue")),
        demo_spec("trois", observe("trois"), wave=3, depends_on=("deux",)),
    )
    result, _ = run_scan_with("blog.example.com")

    assert statuses(result) == {
        "reussit": "ok",
        "echoue": "failed",
        "sans_objet": "skipped",
        "deux": "ok",
        "trois": "ok",
    }
    assert seen["deux"]["cible"] == ("blog.example.com", "example.com", "example.com")
    assert seen["deux"]["adresses"] == [PUBLIC_IP]
    # Un module en échec ou sans objet ne figure pas dans les résultats : sa dépendance le voit absent.
    assert seen["deux"]["resultats"] == {"reussit": {**OK, "valeur": 1}}
    # Les résultats s'accumulent d'une vague à l'autre.
    assert seen["trois"]["resultats"] == {"reussit": {**OK, "valeur": 1}, "deux": {**OK, "de": "deux"}}
    assert fr(result["error_message"]) == "1 module(s) en échec : echoue"


def test_le_contexte_d_un_module_ne_change_pas_pendant_son_execution(demo):
    seen = {}

    async def lent(context):
        # « rapide » se termine pendant cette attente : son résultat n'est pas celui d'une vague précédente.
        await asyncio.sleep(0.1)
        seen["resultats"] = dict(context.results)
        return dict(OK)

    demo(demo_spec("lent", lent), demo_spec("rapide"))
    run_scan_with()

    assert seen["resultats"] == {}


def test_dependance_de_la_meme_vague_part_sans_attendre_les_autres_modules(demo):
    suite_started = asyncio.Event()

    async def enum(context):
        return {**OK, "noms": ["www"]}

    async def suite(context):
        suite_started.set()
        return dict(OK)

    async def lent(context):
        # Ne se termine que si « suite » démarre pendant son exécution, avant la fin de la vague.
        await suite_started.wait()
        return dict(OK)

    # « suite » est enregistré avant la dépendance qu'il attend.
    demo(
        demo_spec("lent", lent, timeout=2),
        demo_spec("suite", suite, depends_on=("enum",)),
        demo_spec("enum", enum),
    )
    result, calls = run_scan_with()

    assert statuses(result) == {"lent": "ok", "suite": "ok", "enum": "ok"}
    names = [name for name, _, _ in calls]
    assert names.index("enum") < names.index("suite")


def test_delai_propre_a_chaque_module(demo):
    state = {"cancelled": False}

    async def lent(context):
        try:
            await asyncio.sleep(30)
        except asyncio.CancelledError:
            state["cancelled"] = True
            raise

    async def patient(context):
        await asyncio.sleep(0.2)
        return dict(OK)

    demo(
        demo_spec("lent", lent, timeout=0.05),
        demo_spec("patient", patient, timeout=5),
        demo_spec("suite", wave=2),
    )
    started = time.monotonic()
    result, _ = run_scan_with()

    assert time.monotonic() - started < 5
    assert fr(result["module_status"]["lent"]) == {"status": "timeout", "error": "Délai dépassé (0.05 s)"}
    # Le délai d'un module n'est pas celui des autres, et son échec n'arrête pas les vagues suivantes.
    assert statuses(result)["patient"] == statuses(result)["suite"] == "ok"
    assert state["cancelled"] is True
    assert result["status"] == "partial"
    assert fr(result["error_message"]) == "1 module(s) en échec : lent (délai dépassé)"


def test_annulation_pendant_une_vague_ulterieure(demo):
    state = {"cancelled": False, "troisieme_vague": False}

    async def run():
        running = asyncio.Event()

        async def bloque(context):
            running.set()
            try:
                await asyncio.sleep(30)
            except asyncio.CancelledError:
                state["cancelled"] = True
                raise

        async def jamais(context):
            state["troisieme_vague"] = True
            return dict(OK)

        demo(demo_spec("debut"), demo_spec("bloque", bloque, wave=2), demo_spec("jamais", jamais, wave=3))
        task = asyncio.ensure_future(orchestrator.perform_full_scan("example.com"))
        await asyncio.wait_for(running.wait(), timeout=5)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
        return task

    started = time.monotonic()
    task = asyncio.run(run())

    assert time.monotonic() - started < 5
    assert task.cancelled()
    assert state == {"cancelled": True, "troisieme_vague": False}


# --- Modules sans objet ---------------------------------------------------------


def test_skip_reason_evalue_au_depart_du_module(demo):
    launched = []

    async def never(context):
        launched.append(context.domain)
        return dict(OK)

    async def first(context):
        return {**OK, "rien_a_faire": True}

    def not_for_ip(context):
        return msg("orchestrator.skip_ip_target") if context.is_ip_target else None

    def nothing_to_do(context):
        # Évaluée au départ du module : le résultat de la vague 1 est déjà connu.
        return msg("orchestrator.skip_generic") if context.results["first"]["rien_a_faire"] else None

    demo(
        demo_spec("first", first),
        demo_spec("ip", never, skip_reason=not_for_ip),
        demo_spec("suite", never, wave=2, depends_on=("first",), skip_reason=nothing_to_do),
    )
    result, calls = run_scan_with(PUBLIC_IP)

    assert launched == []
    assert result["module_status"]["ip"] == {"status": "skipped", "error": msg("orchestrator.skip_ip_target")}
    assert fr(result["module_status"]["suite"]) == {
        "status": "skipped",
        "error": "Sans objet pour cette cible",
    }
    # Chaque module annoncé une fois, sans objet compris ; le statut global n'en souffre pas.
    assert sorted((name, status) for name, status, _ in calls) == [
        ("first", "ok"),
        ("ip", "skipped"),
        ("suite", "skipped"),
    ]
    assert all(isinstance(duration, float) and duration >= 0 for _, _, duration in calls)
    assert result["status"] == "success" and result["error_message"] is None
    # Un module du registre sans objet : raison dans `modules`, valeur de repli des modules à dict.
    skipped = result["modules"]["ip"]
    assert (skipped["status"], skipped["data"]) == ("skipped", {"measured": False, "error": None})
    assert skipped["error"] == msg("orchestrator.skip_ip_target")

    # Un nom d'hôte : « ip » s'exécute.
    run_scan_with("example.com")
    assert launched == ["example.com"]


def test_skip_reason_qui_leve_une_exception_fait_echouer_le_module_seul(demo):
    launched = []

    def broken(context):
        raise RuntimeError("boom")

    async def never(context):
        launched.append(context.domain)
        return dict(OK)

    demo(demo_spec("fragile", never, skip_reason=broken), demo_spec("sain"))
    result, calls = run_scan_with()

    assert fr(result["module_status"]["fragile"]) == {"status": "failed", "error": "RuntimeError: boom"}
    assert statuses(result)["sain"] == "ok"
    assert launched == []
    assert {name: status for name, status, _ in calls} == {"fragile": "failed", "sain": "ok"}
    assert result["status"] == "partial"


# --- Résultats des modules du registre ------------------------------------------


def test_resultats_des_modules_du_registre_dans_modules(demo):
    async def extra(context):
        return {**OK, "x": 1}

    async def panne(context):
        raise ModuleError("service indisponible")

    demo(demo_spec("extra", extra), demo_spec("panne", panne, wave=2))
    result, _ = run_scan_with()

    ok = result["modules"]["extra"]
    assert (ok["status"], ok["data"], ok["error"]) == ("ok", {**OK, "x": 1}, None)
    assert isinstance(ok["duration"], float) and ok["duration"] >= 0
    failed = result["modules"]["panne"]
    assert (failed["status"], failed["error"]) == ("failed", "service indisponible")
    assert failed["data"] == {"measured": False, "error": "service indisponible"}
    assert set(failed) == set(ok) == {"status", "data", "duration", "error"}
    # Leur statut est aussi dans module_status, et un échec dégrade le statut global.
    assert result["module_status"] == {
        "extra": {"status": "ok", "error": None},
        "panne": {"status": "failed", "error": "service indisponible"},
    }
    assert result["status"] == "partial"
    assert fr(result["error_message"]) == "1 module(s) en échec : panne"
    # Les 18 modules d'origine, non lancés ici, gardent leur clé avec la valeur d'un module sans résultat.
    assert result["dns_records"] == {"measured": False, "error": None}
    assert result["subdomains"] == [] and result["subdomain_takeover"] == [] and result["open_ports"] == []
    assert result["screenshot_path"] is None
    assert result["email_security"] == {"measured": False, "error": None, "overall_grade": "N/A"}
    assert result["security_headers"] == empty_headers_result(None)


# --- Profils --------------------------------------------------------------------


def test_profil_rapide_ne_lance_que_les_modules_rapides(fake):
    result, calls = run_scan_with(profile="rapide")

    assert list(result["module_status"]) == list(QUICK_MODULES)
    assert all(status == {"status": "ok", "error": None} for status in result["module_status"].values())
    for name in set(MODULE_FUNCTIONS) - set(QUICK_MODULES):
        assert not fake.called(name), name
    # Un module non lancé garde sa clé, avec la valeur d'un module sans résultat.
    assert result["subdomains"] == [] and result["subdomain_takeover"] == []
    assert result["whois_data"] == {"measured": False, "error": None}
    assert result["network_extended"] == {"measured": False, "error": None}
    assert result["screenshot_path"] is None
    # Un rappel par module lancé : le total annoncé est celui de la liste réelle.
    assert sorted(name for name, _, _ in calls) == sorted(QUICK_MODULES)
    assert set(fake.score_input["module_status"]) == set(QUICK_MODULES)
    assert result["status"] == "success" and result["modules"] == {}


def test_profil_complet_par_defaut(fake):
    result, calls = run_scan_with(profile="complet")

    assert list(result["module_status"]) == list(COMPLETE_MODULES)
    assert len(calls) == len(COMPLETE_MODULES)
    for name in ACTIVE_MODULES:
        assert not fake.called(name), name


def test_profil_complet_n_ajoute_pas_les_modules_actifs_meme_autorise(fake):
    result, _ = run_scan_with(profile="complet", authorized_target=True)

    assert list(result["module_status"]) == list(COMPLETE_MODULES)
    assert not any(fake.called(name) for name in ACTIVE_MODULES)


def test_modules_lances_transmis_au_score(fake):
    """Le barème ne lit pas un module non lancé comme réussi : il reçoit la liste des modules lancés."""
    run_scan_with(profile="rapide")
    assert fake.score_input["modules_launched"] == list(QUICK_MODULES)

    run_scan_with(profile="complet")
    assert fake.score_input["modules_launched"] == list(COMPLETE_MODULES)

    # Sans autorisation, les modules actifs ne sont pas lancés, même sélectionnés.
    run_scan_with(profile="personnalise", selected=["subdomain_takeover", "open_ports"])
    assert fake.score_input["modules_launched"] == []

    run_scan_with(profile="personnalise", selected=["subdomain_takeover"], authorized_target=True)
    assert fake.score_input["modules_launched"] == ["subdomains", "subdomain_takeover"]


def test_profil_rapide_note_au_bareme_v4_avec_couverture_moindre(fake, monkeypatch):
    """Score réel : les 18 modules lancés gardent la forme du barème v3, le profil rapide baisse la couverture."""
    from domainrecon.scanner.score import compute_security_score

    monkeypatch.setattr(orchestrator, "compute_security_score", compute_security_score)

    complet = run_scan_with(profile="complet")[0]["security_score"]
    rapide = run_scan_with(profile="rapide")[0]["security_score"]

    assert complet["version"] == rapide["version"] == 4
    assert all("launched" not in criterion for criterion in complet["breakdown"].values())
    # Les modules actifs (takeover, ports) ne sont ni du profil rapide ni du complet : leur critère est omis,
    # ils ne comptent ni comme réussis ni comme échoués, et ne font pas baisser la couverture.
    for breakdown in (rapide["breakdown"], complet["breakdown"]):
        assert "takeover" not in breakdown and "open_ports" not in breakdown
    # Le whois (passif, hors profil rapide) est « non lancé » : non mesuré, jamais « réussi ».
    whois = rapide["breakdown"]["whois"]
    assert (whois["measured"], whois["counted"], whois["applicable"], whois["launched"]) == (
        False,
        False,
        True,
        False,
    )
    assert rapide["coverage"] < complet["coverage"]
    # Le whois simulé ne compte pas dans le barème : le total de points mesurés ne baisse pas.
    assert rapide["measured_max"] <= complet["measured_max"]


def test_profil_personnalise_lance_la_selection_et_ses_dependances(fake):
    result, _ = run_scan_with(profile="personnalise", selected=["subdomain_takeover"], authorized_target=True)

    assert list(result["module_status"]) == ["subdomains", "subdomain_takeover"]
    assert [name for name, _ in fake.calls] == ["ensure_target_allowed", "subdomains", "subdomain_takeover"]
    assert fake.args_of("subdomain_takeover") == (HEALTHY["subdomains"],)
    assert fake.score_input["subdomains_checked"] == 1
    # Aucun module HTTP lancé : rien à dire de la joignabilité du site.
    assert result["status"] == "success" and result["error_message"] is None


def test_selection_sans_module_http_ne_dit_rien_de_la_joignabilite_du_site(fake):
    fake.addresses = []
    result, _ = run_scan_with(profile="personnalise", selected=["whois_data"])

    assert statuses(result) == {"whois_data": "ok"}
    # Sans adresse, mais sans module HTTP lancé : ni « cible injoignable » ni « site injoignable ».
    assert result["status"] == "partial"
    assert fr(result["error_message"]) == "Aucune adresse IP résolue pour la cible"


def test_nxdomain_declare_sans_module_http(fake):
    fake.addresses = []
    fake.behaviors["dns_records"] = {"A": [], "nxdomain": True, "measured": True, "error": None}
    result, _ = run_scan_with("absent.example.com", profile="personnalise", selected=["dns_records"])

    assert result["status"] == "error"
    assert fr(result["error_message"]) == "Domaine inexistant (NXDOMAIN)"


def test_profil_ou_module_inconnu_refuse_avant_toute_resolution(fake):
    with pytest.raises(ValueError, match="Profil inconnu"):
        asyncio.run(orchestrator.perform_full_scan("example.com", profile="agressif"))
    with pytest.raises(ValueError, match="inexistant"):
        asyncio.run(
            orchestrator.perform_full_scan(
                "example.com", profile="personnalise", selected=["waf", "inexistant"]
            )
        )

    # Ni résolution de la cible ni module.
    assert fake.calls == []


def test_module_actif_lance_seulement_avec_l_autorisation(demo):
    launched = []

    async def probe(context):
        launched.append(context.domain)
        return dict(OK)

    demo(demo_spec("passif"), demo_spec("sonde", probe, category="actif", wave=3))
    options = {"profile": "personnalise", "selected": ["passif", "sonde"]}

    result, _ = run_scan_with(**options)
    assert list(result["module_status"]) == ["passif"] and launched == []

    result, _ = run_scan_with(authorized_target=True, **options)
    assert list(result["module_status"]) == ["passif", "sonde"] and launched == ["example.com"]

    # Le profil complet ne lance jamais de module actif, même avec l'autorisation.
    result, _ = run_scan_with(authorized_target=True)
    assert list(result["module_status"]) == ["passif"]


def test_module_a_cle_lance_seulement_avec_sa_cle(demo):
    demo(
        demo_spec("passif"),
        demo_spec("reputation", category="api_key", api_key="virustotal", wave=2, family="reputation"),
    )

    assert list(run_scan_with()[0]["module_status"]) == ["passif"]
    assert list(run_scan_with(available_keys=["shodan"])[0]["module_status"]) == ["passif"]
    assert list(run_scan_with(available_keys=["virustotal"])[0]["module_status"]) == ["passif", "reputation"]


# =============================================================================
# Réglages câblés au scan : proxy sortant, délais par profil, capture d'écran
# =============================================================================

PROXY = "http://alice:mdp-secret@proxy.local:3128"


@pytest.fixture
def reglages(monkeypatch):
    """Proxy et Réglages du scan remplacés par des valeurs fixes ; `reads` note chaque lecture (quoi, thread)."""
    state = SimpleNamespace(proxy=None, settings=ScanSettings(), reads=[])

    def read_proxy():
        state.reads.append(("proxy", threading.current_thread()))
        return state.proxy

    def read_settings():
        state.reads.append(("settings", threading.current_thread()))
        return state.settings

    monkeypatch.setattr(orchestrator, "get_proxy_url", read_proxy)
    monkeypatch.setattr(orchestrator, "load_scan_settings", read_settings)
    return state


def slow(seconds):
    async def run(context):
        await asyncio.sleep(seconds)
        return dict(OK)

    return run


# --- Proxy sortant --------------------------------------------------------------


def test_proxy_et_reglages_lus_une_fois_par_scan_hors_de_la_boucle(demo, reglages):
    demo(demo_spec("a"), demo_spec("b", wave=2), demo_spec("c", wave=3))
    loop_thread = []

    async def scan():
        loop_thread.append(threading.current_thread())
        return await orchestrator.perform_full_scan("example.com")

    result = asyncio.run(scan())

    assert statuses(result) == {"a": "ok", "b": "ok", "c": "ok"}
    # Une lecture de chacun pour tout le scan (et non une par module), dans un thread à part.
    assert sorted(kind for kind, _ in reglages.reads) == ["proxy", "settings"]
    assert all(thread is not loop_thread[0] for _, thread in reglages.reads)


def test_clients_http_et_api_des_modules_montent_le_proxy(demo, reglages):
    reglages.proxy = PROXY
    seen = {}

    async def sonde(context):
        http, api = common._http_client(), common._api_client()
        try:
            seen["http"], seen["api"] = dict(http._transport._proxies), dict(api._transport._proxies)
            seen["scan"] = common.current_scan_proxy().url
        finally:
            await http.aclose()
            await api.aclose()
        seen["context"] = (context.proxy, context.http)
        return dict(OK)

    demo(demo_spec("sonde", sonde))
    result = run_scan()

    assert statuses(result) == {"sonde": "ok"}
    assert seen["http"] == seen["api"] == {"all": PROXY}
    assert seen["scan"] == PROXY
    # ScanContext peuplé pour les nouveaux modules : proxy et client partagé qui l'emprunte.
    proxy, shared = seen["context"]
    assert proxy == PROXY
    assert shared._transport._proxies == {"all": PROXY}
    assert shared.is_closed  # fermé à la fin du scan


def test_sans_proxy_clients_directs_comme_avant(demo, reglages):
    reglages.proxy = None
    seen = {}

    async def sonde(context):
        http, api = common._http_client(), common._api_client()
        try:
            seen["via"] = (dict(http._transport._via_proxy), dict(api._transport._via_proxy))
            seen["scan"] = common.current_scan_proxy()
        finally:
            await http.aclose()
            await api.aclose()
        seen["context"] = (context.proxy, context.http)
        return dict(OK)

    demo(demo_spec("sonde", sonde))
    run_scan()

    assert seen["via"] == ({}, {})
    assert seen["scan"] == common.ScanProxy(None)
    proxy, shared = seen["context"]
    assert proxy is None and shared._transport._via_proxy == {}


def test_proxy_du_scan_retire_a_la_fin_meme_si_un_module_echoue(demo, reglages):
    reglages.proxy = PROXY

    async def casse(context):
        raise RuntimeError("boom")

    demo(demo_spec("casse", casse), demo_spec("sain"))
    after = []

    async def scan():
        assert common.current_scan_proxy() is None
        result = await orchestrator.perform_full_scan("example.com")
        after.append(common.current_scan_proxy())
        return result

    result = asyncio.run(scan())

    assert statuses(result) == {"casse": "failed", "sain": "ok"}
    assert after == [None]


def test_cible_interne_toujours_refusee_avec_un_proxy(fake, reglages):
    """Le contrôle de la cible précède les modules : avec un proxy configuré, rien ne part vers une IP privée."""
    reglages.proxy = PROXY
    fake.addresses = TargetNotAllowedError(msg("target.not_allowed"))

    with pytest.raises(TargetNotAllowedError):
        run_scan("intranet.example")

    assert [name for name, _ in fake.calls] == ["ensure_target_allowed"]
    assert reglages.reads == []  # refusée avant même la lecture des Réglages


@pytest.mark.parametrize(
    ("proxy", "socks_absent"),
    [
        ("ftp://alice:mdp-secret@proxy.local:21", False),
        ("socks5://alice:mdp-secret@127.0.0.1:1080", True),
    ],
)
def test_proxy_inutilisable_empeche_le_scan_sans_repli_direct(
    fake, reglages, monkeypatch, caplog, proxy, socks_absent
):
    reglages.proxy = proxy
    if socks_absent:
        monkeypatch.setitem(sys.modules, "socksio", None)  # « import socksio » échoue

    with caplog.at_level(logging.DEBUG):
        with pytest.raises(ValueError) as excinfo:
            run_scan()

    assert fr(message_of(excinfo.value)).startswith("Proxy sortant inutilisable")
    assert en(message_of(excinfo.value)).startswith("Outbound proxy unusable")
    # Aucun module lancé (donc aucune requête directe) et aucun identifiant dans l'erreur ni les journaux.
    assert not any(fake.called(name) for name in MODULE_FUNCTIONS)
    assert "mdp-secret" not in str(excinfo.value) and "mdp-secret" not in caplog.text
    assert excinfo.value.__cause__ is None


def test_proxy_du_contexte_absent_de_son_repr():
    assert "mdp-secret" not in repr(registry.ScanContext(domain="example.com", proxy=PROXY))


# --- Délais par profil ----------------------------------------------------------


def test_delai_du_profil_complet_est_scan_timeout(demo, reglages):
    reglages.settings = ScanSettings(scan_timeout=0.05, quick_timeout=30)
    demo(demo_spec("lent", slow(1)), demo_spec("vif", slow(0)))

    result = run_scan()

    assert fr(result["module_status"]["lent"]) == {"status": "timeout", "error": "Délai dépassé (0.05 s)"}
    assert result["module_status"]["vif"]["status"] == "ok"


def test_delai_du_profil_rapide_est_quick_timeout(demo, reglages):
    reglages.settings = ScanSettings(scan_timeout=30, quick_timeout=0.05)
    demo(demo_spec("lent", slow(1), quick=True))

    result, _ = run_scan_with(profile="rapide")

    assert fr(result["module_status"]["lent"]) == {"status": "timeout", "error": "Délai dépassé (0.05 s)"}


def test_chaque_profil_a_son_delai(demo, reglages):
    """Le délai de l'autre profil est sans effet : « rapide » ne lit pas scan_timeout, ni les autres quick_timeout."""
    reglages.settings = ScanSettings(scan_timeout=0.05, quick_timeout=5)
    demo(demo_spec("moyen", slow(0.3), quick=True))

    assert statuses(run_scan_with(profile="rapide")[0]) == {"moyen": "ok"}
    assert statuses(run_scan_with(profile="complet")[0]) == {"moyen": "timeout"}
    # Personnalisé : le délai du profil complet.
    custom, _ = run_scan_with(profile="personnalise", selected=["moyen"])
    assert statuses(custom) == {"moyen": "timeout"}


def test_delai_du_module_borne_celui_du_profil(demo, reglages):
    """Un profil plus patient n'allonge jamais le délai propre d'un module."""
    reglages.settings = ScanSettings(scan_timeout=600, quick_timeout=600)
    demo(demo_spec("court", slow(1), timeout=0.05))

    result = run_scan()

    assert fr(result["module_status"]["court"]) == {"status": "timeout", "error": "Délai dépassé (0.05 s)"}


def test_module_hors_delai_n_interrompt_que_lui(demo, reglages):
    reglages.settings = ScanSettings(scan_timeout=0.2, quick_timeout=0.2)
    demo(demo_spec("lent", slow(5)), demo_spec("bref", slow(0.02)), demo_spec("suite", wave=2))

    result = run_scan()

    assert statuses(result) == {"lent": "timeout", "bref": "ok", "suite": "ok"}


def test_delai_propre_des_modules_jamais_ecrase_par_les_reglages(demo, reglages, monkeypatch):
    """Délais par défaut des Réglages (60 s et 30 s) : un module qui déclare son délai le garde, plus long
    ou plus court ; un module sans délai propre prend celui du profil."""
    reglages.settings = ScanSettings()
    seen = []
    original = orchestrator._run_module

    async def spy(name, factory, timeout, target):
        seen.append((name, timeout))
        return await original(name, factory, timeout, target)

    monkeypatch.setattr(orchestrator, "_run_module", spy)
    demo(
        demo_spec("a", timeout=120),
        demo_spec("b", timeout=60),
        demo_spec("c", timeout=5),
        demo_spec("d"),
    )

    run_scan()

    assert seen == [("a", 120), ("b", 60), ("c", 5), ("d", 60)]


# --- Capture d'écran ------------------------------------------------------------


def test_capture_desactivee_module_sans_objet(fake, reglages):
    reglages.settings = ScanSettings(screenshot_enabled=False)

    result, calls = run_scan_with()

    assert not fake.called("screenshot")
    status = result["module_status"]["screenshot"]
    assert status["status"] == "skipped"
    assert fr(status["error"]) == "Capture d'écran désactivée dans les Réglages"
    assert en(status["error"]) == "Screenshot turned off in Settings"
    assert result["screenshot_path"] is None
    # Sans objet n'est pas un échec : le statut global n'est pas dégradé, les autres modules tournent.
    assert result["status"] == "success" and result["error_message"] is None
    assert fake.called("dns_records") and fake.called("waf")
    # La progression l'annonce comme les autres modules lancés.
    assert [(name, state) for name, state, _ in calls if name == "screenshot"] == [("screenshot", "skipped")]


def test_capture_activee_module_lance(fake, reglages):
    reglages.settings = ScanSettings(screenshot_enabled=True)

    result = run_scan()

    assert fake.called("screenshot")
    assert result["module_status"]["screenshot"] == {"status": "ok", "error": None}
    assert result["screenshot_path"] == HEALTHY["screenshot"]


def test_capture_desactivee_aussi_dans_un_profil_personnalise(fake, reglages):
    reglages.settings = ScanSettings(screenshot_enabled=False)

    result, _ = run_scan_with(profile="personnalise", selected=["screenshot", "waf"])

    assert statuses(result) == {"waf": "ok", "screenshot": "skipped"}
    assert not fake.called("screenshot")


# =============================================================================
# Plateforme des modules : contexte enrichi (clés, page partagée, concurrence),
# sorties non sérialisables, modules facultatifs, sans objet en cours de route
# =============================================================================


def test_resultat_non_serialisable_le_module_echoue_le_scan_est_garde(demo, reglages):
    async def ensemble(context):
        return {**OK, "valeurs": {1, 2}}

    demo(demo_spec("fautif", ensemble), demo_spec("sain"))
    result, _ = run_scan_with()

    fautif = result["modules"]["fautif"]
    assert fautif["status"] == "failed"
    assert fr(fautif["error"]) == "Résultat du module non enregistrable (TypeError) : donnée non JSON écartée"
    # La valeur gardée est celle d'un module sans résultat : le scan entier reste enregistrable.
    assert fautif["data"] == {"measured": False, "error": fautif["error"]}
    assert result["modules"]["sain"]["status"] == "ok"
    import json

    json.dumps(result["modules"])


def test_module_facultatif_en_echec_ne_degrade_pas_le_statut_global(demo, reglages):
    async def panne(context):
        raise ModuleError("quota du service dépassé")

    demo(demo_spec("tiers", panne, optional=True), demo_spec("sain"))
    result, _ = run_scan_with()

    assert result["module_status"]["tiers"]["status"] == "failed"
    assert result["status"] == "success" and result["error_message"] is None


def test_module_obligatoire_en_echec_degrade_toujours_le_statut(demo, reglages):
    async def panne(context):
        raise ModuleError("panne")

    demo(demo_spec("tiers", panne), demo_spec("facultatif", panne, optional=True))
    result, _ = run_scan_with()

    assert result["status"] == "partial"
    assert fr(result["error_message"]) == "1 module(s) en échec : tiers"


def test_module_sans_objet_en_cours_de_route(demo, reglages):
    from domainrecon.scanner.errors import ModuleSkipped

    async def rien_a_faire(context):
        raise ModuleSkipped(msg("orchestrator.skip_generic"))

    demo(demo_spec("vide", rien_a_faire))
    result, _ = run_scan_with()

    assert result["module_status"]["vide"] == {"status": "skipped", "error": msg("orchestrator.skip_generic")}
    assert result["status"] == "success"


def test_concurrence_bornee(demo, reglages, monkeypatch):
    monkeypatch.setattr(orchestrator, "MAX_PARALLEL_MODULES", 3)
    state = {"en_cours": 0, "max": 0}

    async def compte(context):
        state["en_cours"] += 1
        state["max"] = max(state["max"], state["en_cours"])
        await asyncio.sleep(0.02)
        state["en_cours"] -= 1
        return dict(OK)

    demo(*(demo_spec(f"m{i}", compte) for i in range(10)))
    result, _ = run_scan_with()

    assert all(status == "ok" for status in statuses(result).values())
    assert state["max"] == 3


def test_attente_d_une_place_hors_du_delai_du_module(demo, reglages, monkeypatch):
    """Un module qui attend une place libre n'est pas compté hors délai pour autant."""
    monkeypatch.setattr(orchestrator, "MAX_PARALLEL_MODULES", 1)
    demo(demo_spec("a", slow(0.15), timeout=0.3), demo_spec("b", slow(0.15), timeout=0.3))

    result, _ = run_scan_with()

    assert statuses(result) == {"a": "ok", "b": "ok"}


def test_chaque_module_ne_recoit_que_ses_cles(demo, reglages, monkeypatch):
    from domainrecon.scanner.keys import ApiKey

    vus = {}

    def recorder(name):
        async def run(context):
            vus[name] = dict(context.secrets)
            return dict(OK)

        return run

    monkeypatch.setattr(
        orchestrator, "load_secrets", lambda: {"hibp_key": "secret-hibp", "autre_key": "secret-autre"}
    )
    hibp = ApiKey(name="hibp_key", service="hibp", label="Have I Been Pwned")
    facultative = ApiKey(name="autre_key", service="autre", label="Autre", required=False)
    demo(
        demo_spec("fuites", recorder("fuites"), category="cle_api", keys=(hibp,)),
        demo_spec("mixte", recorder("mixte"), keys=(facultative,)),
        demo_spec("sans_cle", recorder("sans_cle")),
    )

    result, _ = run_scan_with(available_keys=["hibp_key", "autre_key"])

    assert vus == {
        "fuites": {"hibp_key": "secret-hibp"},
        "mixte": {"autre_key": "secret-autre"},
        "sans_cle": {},
    }
    # Jamais dans le résultat ni dans le repr du contexte.
    assert "secret-hibp" not in repr(result)
    assert "secret-hibp" not in repr(
        registry.ScanContext(domain="example.com", secrets={"hibp_key": "secret-hibp"})
    )


def test_cles_non_lues_si_aucun_module_n_en_declare(demo, reglages, monkeypatch):
    def interdit():
        raise AssertionError("clés lues sans module à clé")

    monkeypatch.setattr(orchestrator, "load_secrets", interdit)
    demo(demo_spec("simple"))

    result, _ = run_scan_with()

    assert result["module_status"]["simple"]["status"] == "ok"


def test_page_d_accueil_recuperee_une_seule_fois(demo, reglages, monkeypatch):
    from domainrecon.scanner import page

    appels = []

    async def fausse_page(domain):
        appels.append(domain)
        await asyncio.sleep(0.01)
        return page.HomePage(url=f"https://{domain}/", status_code=200, text="<html>bonjour</html>")

    monkeypatch.setattr(page, "fetch_homepage", fausse_page)

    def lecteur(name, vus):
        async def run(context):
            home = await context.homepage()
            vus.append((name, home.status_code, home.text))
            return dict(OK)

        return run

    vus = []
    demo(
        demo_spec("lecteur_a", lecteur("a", vus)),
        demo_spec("lecteur_b", lecteur("b", vus)),
        demo_spec("lecteur_c", lecteur("c", vus), wave=2),
    )

    run_scan_with()

    assert appels == ["example.com"]
    assert sorted(vus) == [
        ("a", 200, "<html>bonjour</html>"),
        ("b", 200, "<html>bonjour</html>"),
        ("c", 200, "<html>bonjour</html>"),
    ]


def test_page_d_accueil_survit_au_delai_d_un_module(demo, reglages, monkeypatch):
    """Le module qui a lancé la récupération est interrompu : les autres reçoivent quand même la page."""
    from domainrecon.scanner import page

    async def lente(domain):
        await asyncio.sleep(0.2)
        return page.HomePage(url="https://example.com/", status_code=200)

    monkeypatch.setattr(page, "fetch_homepage", lente)

    async def lit(context):
        await context.homepage()
        return dict(OK)

    demo(demo_spec("presse", lit, timeout=0.05), demo_spec("patient", lit, timeout=5))
    result, _ = run_scan_with()

    assert statuses(result) == {"presse": "timeout", "patient": "ok"}


def test_finalize_et_extras_en_echec_n_empechent_pas_le_scan(demo, reglages, caplog):
    def casse(*args):
        raise RuntimeError("boum")

    demo(demo_spec("fragile", finalize=casse, status_extras=casse, score_extras=casse, nxdomain=casse))
    with caplog.at_level(logging.ERROR, logger="domainrecon.scanner"):
        result, _ = run_scan_with()

    assert result["modules"]["fragile"]["data"] == OK
    assert result["module_status"]["fragile"] == {"status": "ok", "error": None}
    assert "finalize en échec" in caplog.text


def test_finalize_recoit_les_valeurs_de_tous_les_modules(demo, reglages):
    def enrichit(value, values, context):
        return {**value, "voisin": values["voisin"]["measured"], "cible": context.domain}

    demo(demo_spec("voisin"), demo_spec("enrichi", finalize=enrichit))
    result, _ = run_scan_with()

    assert result["modules"]["enrichi"]["data"] == {**OK, "voisin": True, "cible": "example.com"}


def test_colonnes_historiques_toujours_presentes(demo, reglages):
    """Registre sans les 18 modules : le résultat garde leurs colonnes (valeur d'un module sans résultat)."""
    demo(demo_spec("seul"))
    result, _ = run_scan_with()

    for name in orchestrator.MODULE_NAMES:
        column = registry.COLUMN_MODULES[name].column
        assert column in result, column
