# =============================================================================
# DomainRecon - Tests : messages traduisibles produits par le scanner
# =============================================================================
# Exceptions porteuses de message, puis, pour chaque module converti en codes
# de message, au moins un rendu anglais (les tests existants vérifient le
# français au moyen de rendu.fr).
# =============================================================================

import asyncio
import copy
import logging
import pickle
import socket
import ssl

import httpcore
import httpx
import pytest

from domainrecon.core import paths
from domainrecon.i18n import catalog, is_msg, msg
from domainrecon.scanner import common, orchestrator, targets
from domainrecon.scanner import cookies as cookies_module
from domainrecon.scanner import cors as cors_module
from domainrecon.scanner import email_security as email_module
from domainrecon.scanner import headers as headers_module
from domainrecon.scanner import redirects as redirects_module
from domainrecon.scanner import tls as tls_module
from domainrecon.scanner import waf as waf_module
from domainrecon.scanner.cookies import analyze_cookie_headers
from domainrecon.scanner.dns import DmarcLookup, DnsLookup
from domainrecon.scanner.errors import (
    ModuleError,
    TargetNotAllowedError,
    exception_text,
    message_exception,
    message_of,
)
from domainrecon.scanner.headers import evaluate_security_headers
from domainrecon.scanner.http_utils import FetchResult, describe_error, fetch, fetch_first
from domainrecon.scanner.score import compute_security_score
from domainrecon.scanner.technologies import (
    TECH_BODY_SIGS,
    TECH_CATEGORIES,
    TECH_INFRA_SIGS,
    _category,
    analyze_page,
)
from domainrecon.scanner.waf import analyze_waf_responses
from domainrecon.scanner.web_files import _gather_within, _unanswered_reason
from rendu import en, fr

# Comportement des 18 modules historiques : registre ramené à eux (tests/conftest.py).
pytestmark = pytest.mark.usefixtures("registre_historique")


@pytest.fixture
def catalogue_test(tmp_path, monkeypatch):
    """Catalogues minimaux, indépendants des vrais catalogues."""
    (tmp_path / "fr.json").write_text('{"t.echec": "Échec : {cause}"}', encoding="utf-8")
    (tmp_path / "en.json").write_text('{"t.echec": "Failure: {cause}"}', encoding="utf-8")
    monkeypatch.setattr(paths, "i18n_dir", lambda: tmp_path)
    catalog.cache_clear()
    yield
    catalog.cache_clear()


def test_module_error_porte_un_message(catalogue_test):
    erreur = ModuleError(msg("t.echec", cause="réseau"))
    assert erreur.message == msg("t.echec", cause="réseau")
    assert str(erreur) == "Échec : réseau"  # journaux : français
    assert en(erreur.message) == "Failure: réseau"


def test_texte_brut_accepte():
    erreur = TargetNotAllowedError("Cible refusée")
    assert isinstance(erreur, ValueError)
    assert erreur.message == "Cible refusée" and str(erreur) == "Cible refusée"
    assert ModuleError().message == "" and str(ModuleError()) == ""


def test_copie_et_pickle_gardent_le_message(catalogue_test):
    erreur = ModuleError(msg("t.echec", cause="x"))
    assert copy.deepcopy(erreur).message == erreur.message
    # Aller-retour sur une exception créée ici : aucune donnée non fiable.
    assert pickle.loads(pickle.dumps(erreur)).message == erreur.message


def test_message_exception_et_message_of(catalogue_test):
    message = msg("t.echec", cause="dns")
    interne = message_exception(httpcore.ConnectError, message)
    assert str(interne) == "Échec : dns"
    try:
        try:
            raise interne
        except httpcore.ConnectError as exc:
            # Comme httpx : l'exception de httpcore devient la cause.
            raise httpx.ConnectError(str(exc)) from exc
    except httpx.ConnectError as enveloppe:
        assert message_of(enveloppe) == message
        assert exception_text(enveloppe) == message
    assert message_of(RuntimeError("brut")) is None
    assert exception_text(RuntimeError("brut")) == "brut"
    assert exception_text(RuntimeError()) == ""


def test_message_exception_transmet_les_arguments(catalogue_test):
    requete = httpx.Request("GET", "https://example.com")
    erreur = message_exception(httpx.ConnectError, msg("t.echec", cause="x"), request=requete)
    assert erreur.request is requete
    assert erreur.message == msg("t.echec", cause="x")


# --- score.py ----------------------------------------------------------------


def test_score_details_et_raisons_en_anglais():
    result = compute_security_score({"is_ip_target": True, "open_ports": [6379]})
    breakdown = result["breakdown"]
    assert en(breakdown["email"]["detail"]) == "Not applicable (IP target)"
    assert fr(breakdown["email"]["detail"]) == "Non applicable (cible IP)"
    assert en(breakdown["headers"]["detail"]) == "Not measured"
    assert en(result["grade_reason"]) == "Insufficient coverage: 0 % of the scale measured"
    assert en(result["penalties"][0]["label"]) == "Port 6379 (Redis) exposed"


def test_score_detail_tls_imbrique():
    tls = {"measured": True, "https": True, "valid": False, "verify_error": "Certificat expiré"}
    detail = compute_security_score({"tls_certificate": tls})["breakdown"]["tls"]["detail"]
    assert en(detail) == "Invalid: Certificat expiré"
    assert fr(detail) == "Invalide : Certificat expiré"


# --- orchestrator.py -----------------------------------------------------------


def _statuts_ok() -> dict:
    return {name: {"status": "ok", "error": None} for name in orchestrator.MODULE_NAMES}


def test_orchestrateur_statut_global_en_anglais():
    statuts = _statuts_ok()
    statuts["waf"] = {"status": "timeout", "error": None}
    statuts["cors"] = {"status": "failed", "error": None}
    status, message = orchestrator._global_status(statuts, ["93.184.216.34"], False)
    assert status == "partial"
    assert fr(message) == "2 module(s) en échec : waf (délai dépassé), cors"
    assert en(message) == "2 module(s) failed: waf (timed out), cors"

    status, message = orchestrator._global_status(statuts, [], True)
    assert fr(message) == (
        "Résolution DNS de la cible hors délai (15 s) ; 2 module(s) en échec : waf (délai dépassé), cors"
    )
    assert en(message) == "Target DNS resolution timed out (15 s); 2 module(s) failed: waf (timed out), cors"

    for name in ("security_headers", "redirect_chain", "waf", "cookie_security", "cors"):
        statuts[name] = {"status": "failed", "error": None}
    assert en(orchestrator._global_status(statuts, [], False)[1]) == (
        "Target unreachable: no DNS resolution and no HTTP response"
    )


def test_orchestrateur_cible_invalide_traduite():
    with pytest.raises(ValueError) as excinfo:
        asyncio.run(orchestrator.perform_full_scan("pas une cible"))
    assert str(excinfo.value) == "Cible invalide : 'pas une cible'"
    assert en(excinfo.value.message) == "Invalid target: 'pas une cible'"


# Messages de l'orchestrateur : (message, texte français d'origine, texte anglais).
_MESSAGES_ORCHESTRATEUR = [
    (orchestrator._SKIP_IP_TARGET, "Sans objet pour une adresse IP", "Not applicable to an IP address"),
    (
        orchestrator._SKIP_NO_ADDRESS,
        "Aucune adresse IP résolue pour la cible",
        "No IP address resolved for the target",
    ),
    (orchestrator._SKIP_NO_SUBDOMAINS, "Aucun sous-domaine à tester", "No subdomain to test"),
    (
        orchestrator._SKIP_NO_PLAYWRIGHT,
        "Playwright ou son navigateur Chromium n'est pas installé",
        "Playwright or its Chromium browser is not installed",
    ),
    (
        orchestrator._SKIP_SCREENSHOT_DISABLED,
        "Capture d'écran désactivée dans les Réglages",
        "Screenshot turned off in Settings",
    ),
    (
        orchestrator._PROXY_UNUSABLE,
        "Proxy sortant inutilisable : corrigez-le dans les Réglages "
        "(le scan n'est pas lancé, pour ne pas exposer l'adresse de cette machine)",
        "Outbound proxy unusable: fix it in Settings "
        "(the scan was not started, so that this machine's address is not exposed)",
    ),
    (
        orchestrator._SKIP_SHARED_PLATFORM,
        "Hôte d'une plateforme mutualisée (suffixe privé de la PSL) : "
        "la sécurité email relève de la plateforme, pas de la cible",
        "Host on a shared platform (PSL private suffix): "
        "e-mail security belongs to the platform, not to the target",
    ),
    (
        orchestrator._TAKEOVER_NOT_CHECKED,
        "Non vérifié : énumération des sous-domaines en échec",
        "Not checked: subdomain enumeration failed",
    ),
    (
        orchestrator._HTTP_UNREACHABLE,
        "Site injoignable en HTTP et en HTTPS depuis le scanner",
        "Site unreachable over HTTP and HTTPS from the scanner",
    ),
    (orchestrator._NXDOMAIN, "Domaine inexistant (NXDOMAIN)", "Non-existent domain (NXDOMAIN)"),
    (
        msg("orchestrator.no_result"),
        "Aucun résultat renvoyé par le module",
        "No result returned by the module",
    ),
    (msg("orchestrator.skip_generic"), "Sans objet pour cette cible", "Not applicable to this target"),
    (
        msg("orchestrator.not_serializable", error="TypeError"),
        "Résultat du module non enregistrable (TypeError) : donnée non JSON écartée",
        "Module result cannot be stored (TypeError): non-JSON data discarded",
    ),
    (msg("orchestrator.measure_failed"), "Mesure impossible", "Measurement failed"),
    (msg("orchestrator.module_failed"), "Échec du module", "Module failed"),
    (msg("orchestrator.timeout", seconds="0.05"), "Délai dépassé (0.05 s)", "Timed out (0.05 s)"),
    (
        msg("orchestrator.timeout_detail", detail="timed out"),
        "Délai dépassé : timed out",
        "Timed out: timed out",
    ),
    (
        msg("common.exception", error="RuntimeError", detail="boom"),
        "RuntimeError: boom",
        "RuntimeError: boom",
    ),
    (
        msg("orchestrator.unreachable"),
        "Cible injoignable : aucune résolution DNS ni réponse HTTP",
        "Target unreachable: no DNS resolution and no HTTP response",
    ),
    (
        msg("orchestrator.unreachable_resolve_timeout", seconds="15"),
        "Cible injoignable : résolution DNS hors délai (15 s) et aucune réponse HTTP",
        "Target unreachable: DNS resolution timed out (15 s) and no HTTP response",
    ),
    (
        msg("orchestrator.resolve_timeout", seconds="15"),
        "Résolution DNS de la cible hors délai (15 s)",
        "Target DNS resolution timed out (15 s)",
    ),
    (msg("orchestrator.problem_timeout", name="waf"), "waf (délai dépassé)", "waf (timed out)"),
    (
        msg("orchestrator.modules_failed", count=2, modules=["waf", "cors"], sep=", "),
        "2 module(s) en échec : waf, cors",
        "2 module(s) failed: waf, cors",
    ),
    (msg("common.join", items=["a", "b"]), "a ; b", "a; b"),
    (msg("target.invalid", target="'x'"), "Cible invalide : 'x'", "Invalid target: 'x'"),
]


@pytest.mark.parametrize(
    ("message", "francais", "anglais"),
    _MESSAGES_ORCHESTRATEUR,
    ids=[message["$t"] for message, _, _ in _MESSAGES_ORCHESTRATEUR],
)
def test_orchestrateur_messages_en_francais_et_en_anglais(message, francais, anglais):
    """Le français rendu est le texte d'origine de l'orchestrateur, l'anglais son équivalent."""
    assert fr(message) == francais
    assert en(message) == anglais


def test_orchestrateur_tous_les_codes_ont_leur_rendu_epingle():
    epingles = {message["$t"] for message, _, _ in _MESSAGES_ORCHESTRATEUR}
    assert {code for code in catalog("fr") if code.startswith("orchestrator.")} <= epingles


def test_orchestrateur_conserve_les_messages_des_modules():
    """Le message porté par un module (exception ou dict) est transmis tel quel, non réécrit."""
    propre = msg("score.tls_no_https")

    def run(module):
        return asyncio.run(orchestrator._run_module("tls_certificate", module, 5, "example.com"))

    async def erreur_de_module():
        raise ModuleError(propre)

    async def dict_non_mesure():
        return {"measured": False, "error": propre}

    async def dict_sans_objet():
        return {"measured": False, "error": propre, "skipped": True}

    for module, statut in (
        (erreur_de_module, "failed"),
        (dict_non_mesure, "failed"),
        (dict_sans_objet, "skipped"),
    ):
        resultat = run(module)
        assert (resultat.status, resultat.error) == (statut, propre)
    assert run(erreur_de_module).value == {"measured": False, "error": propre}

    # Un délai interne au module garde son message ; une exception tierce qui l'enveloppe
    # (raise … from) aussi : il devient le détail du message générique.
    async def delai_interne():
        raise message_exception(TimeoutError, propre)

    async def erreur_enveloppee():
        try:
            raise message_exception(OSError, propre)
        except OSError as e:
            raise RuntimeError("enveloppe") from e

    delai = run(delai_interne)
    assert delai.status == "timeout"
    assert delai.error == msg("orchestrator.timeout_detail", detail=propre)
    assert en(delai.error) == "Timed out: HTTPS unavailable"
    enveloppee = run(erreur_enveloppee)
    assert enveloppee.status == "failed"
    assert enveloppee.error == msg("common.exception", error="RuntimeError", detail=propre)
    assert fr(enveloppee.error) == "RuntimeError: HTTPS indisponible"


# --- headers.py, cookies.py, cors.py -------------------------------------------


def test_entetes_details_en_anglais():
    checks = evaluate_security_headers(
        {"Strict-Transport-Security": "max-age=100", "X-Content-Type-Options": "nosniff"}, https=True
    )["checks"]
    assert en(checks["Strict-Transport-Security"]["detail"]) == (
        "max-age too short (100 s, recommended ≥ 15552000 s)"
    )
    assert en(checks["Content-Security-Policy"]["detail"]) == "Missing"
    assert fr(checks["Permissions-Policy"]["detail"]) == "Absent"
    # Valeur protectrice : donnée brute, identique dans toutes les langues.
    assert checks["X-Content-Type-Options"]["detail"] == "nosniff"


def test_cookies_problemes_en_anglais():
    cookie = analyze_cookie_headers(["sid=1; SameSite=None"])["cookies"][0]
    assert en(cookie["issues"]) == ["No Secure flag", "No HttpOnly flag", "SameSite=None without Secure"]


def test_cors_details_en_anglais(monkeypatch):
    # Transport simulé : aucune résolution DNS (cibles privées permises).
    monkeypatch.setenv("ALLOW_PRIVATE_TARGETS", "1")

    def repondre(request):
        origin = request.headers.get("origin")
        return httpx.Response(200, headers={"access-control-allow-origin": origin} if origin else {})

    monkeypatch.setattr(
        cors_module,
        "_http_client",
        lambda timeout=8.0: common._http_client(timeout, transport=httpx.MockTransport(repondre)),
    )
    result = asyncio.run(cors_module.check_cors("example.com"))
    assert result["measured"] is True
    assert en(result["details"]) == [
        "Origin https://evil.com is reflected without credentials: "
        "a third-party site can read unauthenticated responses"
    ]


def test_entetes_site_injoignable_en_anglais(monkeypatch):
    """Un échec par schéma (doublons HEAD/GET fusionnés), séparés selon la typographie de la langue."""
    monkeypatch.setenv("ALLOW_PRIVATE_TARGETS", "1")

    def echouer(request):
        raise httpx.ReadTimeout("", request=request)

    monkeypatch.setattr(
        headers_module,
        "_http_client",
        lambda timeout=10.0: common._http_client(timeout, transport=httpx.MockTransport(echouer)),
    )
    result = asyncio.run(headers_module.check_security_headers("example.com"))
    assert result["measured"] is False
    error = result["error"]
    assert fr(error).startswith("Site injoignable (HTTPS : ") and fr(error).count("HTTPS") == 1
    assert en(error).startswith("Site unreachable (HTTPS: ") and en(error).count("HTTPS") == 1
    assert "; HTTP: " in en(error)


# --- redirects.py, web_files.py, waf.py, technologies.py -----------------------


def test_waf_inconnu_en_anglais():
    result = analyze_waf_responses([httpx.Response(200, headers={"x-waf-event": "1"})])
    assert en(result["waf_name"]) == "Unknown WAF"
    assert fr(result["waf_name"]) == "WAF inconnu"


def test_categories_de_technologies_en_anglais():
    techs = analyze_page(
        [httpx.Headers({"server": "nginx", "x-powered-by": "PHP/8"})],
        '<script src="/wp-includes/js/x.js"></script>',
    )
    assert en(techs) == [
        {"name": "Nginx", "category": "Web server"},
        {"name": "PHP", "category": "Framework"},
        {"name": "WordPress", "category": "CMS"},
    ]
    assert fr(techs)[0] == {"name": "Nginx", "category": "Serveur Web"}


def test_categories_des_signatures_de_technologies_sont_des_cles_traduites():
    """Chaque catégorie des tables de signatures est une clé connue de _category, non un libellé."""
    cles = {
        *TECH_CATEGORIES.values(),
        *(categorie for _, categorie, _ in TECH_INFRA_SIGS),
        *(categorie for _, categorie, _ in TECH_BODY_SIGS),
    }
    assert cles
    for cle in cles:
        assert is_msg(_category(cle)), cle


def test_fichier_web_non_verifie_en_anglais():
    reponse = httpx.Response(503, request=httpx.Request("GET", "https://example.com/robots.txt"))
    assert en(_unanswered_reason(FetchResult(reponse))) == "HTTP response 503"


def test_redirection_https_vers_http_en_anglais(monkeypatch):
    monkeypatch.setenv("ALLOW_PRIVATE_TARGETS", "1")

    def repondre(request):
        if request.url.scheme == "https":
            return httpx.Response(302, headers={"location": "http://example.com/"})
        return httpx.Response(200)

    monkeypatch.setattr(
        redirects_module,
        "_http_client",
        lambda timeout=10.0, follow_redirects=False: common._http_client(
            timeout, follow_redirects, transport=httpx.MockTransport(repondre)
        ),
    )
    result = asyncio.run(redirects_module.trace_redirects("example.com"))
    assert en(result["warnings"]) == [
        "HTTPS redirects to HTTP (https://example.com → http://example.com/): the encrypted connection is dropped"
    ]


def test_redirection_site_injoignable_sans_motif(monkeypatch):
    """Sans motif d'échec exploitable, chaque schéma est rapporté « sans réponse »."""
    monkeypatch.setenv("ALLOW_PRIVATE_TARGETS", "1")

    def refuser(request):
        raise httpx.ConnectError("refus", request=request)

    monkeypatch.setattr(redirects_module, "describe_error", lambda exc: "")
    monkeypatch.setattr(
        redirects_module,
        "_http_client",
        lambda timeout=10.0, follow_redirects=False: common._http_client(
            timeout, follow_redirects, transport=httpx.MockTransport(refuser)
        ),
    )
    error = asyncio.run(redirects_module.trace_redirects("example.com"))["error"]
    assert (
        fr(error) == "Site injoignable en HTTP et en HTTPS (HTTP : aucune réponse ; HTTPS : aucune réponse)"
    )
    assert en(error) == "Site unreachable over HTTP and HTTPS (HTTP: no response; HTTPS: no response)"


def test_budget_des_fichiers_web_depasse_porte_un_message():
    """Une tentative annulée par le budget d'une vague est une erreur de délai qui porte son message."""

    async def lent():
        await asyncio.sleep(5)

    (erreur,) = asyncio.run(_gather_within([lent()], 0.01))
    assert isinstance(erreur, httpx.TimeoutException)
    assert str(erreur) == "budget de 0.01 s dépassé"  # journaux : français
    assert en(message_of(erreur)) == "0.01 s budget exceeded"


# --- targets.py, common.py, http_utils.py --------------------------------------


def test_describe_error_en_anglais():
    requete = httpx.Request("GET", "https://example.com")
    assert en(describe_error(httpx.ConnectTimeout("x", request=requete))) == "timed out"
    assert en(describe_error(httpx.ConnectError("refus", request=requete))) == "connection failed (refus)"
    assert en(describe_error(httpx.ReadError("", request=requete))) == "connection interrupted"


def test_site_injoignable_en_anglais(monkeypatch):
    monkeypatch.setenv("ALLOW_PRIVATE_TARGETS", "1")

    def refuser(request):
        raise httpx.ConnectError("boom", request=request)

    async def scenario():
        async with common._http_client(transport=httpx.MockTransport(refuser)) as client:
            return await fetch_first(client, "example.com")

    fetched, error = asyncio.run(scenario())
    assert fetched is None
    assert en(error) == "Site unreachable (HTTPS: connection failed (boom); HTTP: connection failed (boom))"
    assert (
        fr(error)
        == "Site injoignable (HTTPS : connexion impossible (boom) ; HTTP : connexion impossible (boom))"
    )


def test_politique_de_cibles_en_anglais(monkeypatch):
    monkeypatch.setenv("ALLOW_PRIVATE_TARGETS", "0")
    with pytest.raises(TargetNotAllowedError) as excinfo:
        targets.ensure_ip_allowed("10.0.0.1")
    assert en(excinfo.value.message) == (
        "Address not allowed: private, local or reserved address. "
        "To scan your own network, set ALLOW_PRIVATE_TARGETS=1."
    )
    assert en(targets._not_allowed_message("intranet.example")) == (
        "Target not allowed: “intranet.example” resolves to a private, local or reserved address. "
        "To scan your own network, set ALLOW_PRIVATE_TARGETS=1."
    )
    hooks = common._target_guard_hooks(real_network=False)
    with pytest.raises(TargetNotAllowedError) as excinfo:
        asyncio.run(hooks["request"][0](httpx.Request("GET", "ftp://example.com/")))
    assert en(excinfo.value.message) == "Scheme not allowed: ftp"


# Messages de targets.py, common.py et http_utils.py : (message, texte français d'origine, texte anglais).
_MESSAGES_CIBLES_ET_HTTP = [
    (
        msg("http.bad_compressed_body", detail="Error -3 while decompressing data"),
        "Corps compressé invalide : Error -3 while decompressing data",
        "Invalid compressed body: Error -3 while decompressing data",
    ),
    (msg("http.connect_failed"), "connexion impossible", "connection failed"),
    (
        msg("http.connect_failed_detail", detail="refus"),
        "connexion impossible (refus)",
        "connection failed (refus)",
    ),
    (msg("http.connection_interrupted"), "connexion interrompue", "connection interrupted"),
    (msg("http.decompression_stuck"), "décompression bloquée", "decompression stalled"),
    (
        msg("http.invalid_location"),
        "Redirection vers une URL invalide ou un schéma non pris en charge",
        "Redirect to an invalid URL or an unsupported scheme",
    ),
    (msg("http.protocol_error"), "réponse HTTP non conforme", "non-compliant HTTP response"),
    (
        msg("http.protocol_error_detail", detail="illegal header line"),
        "réponse HTTP non conforme (illegal header line)",
        "non-compliant HTTP response (illegal header line)",
    ),
    (
        msg("http.redirect_not_followed", url="http://www.example.com/", error="boom"),
        "Redirection non suivie (http://www.example.com/) : boom",
        "Redirect not followed (http://www.example.com/): boom",
    ),
    (msg("http.scheme_error", scheme="HTTPS", error="boom"), "HTTPS : boom", "HTTPS: boom"),
    (
        msg("http.server_disconnected"),
        "connexion fermée par le serveur sans réponse",
        "connection closed by the server without a response",
    ),
    (msg("http.target_refused"), "cible non autorisée", "target not allowed"),
    (
        msg("http.too_many_redirects", max=10),
        "Trop de redirections (plus de 10)",
        "Too many redirects (more than 10)",
    ),
    (msg("http.unreachable", errors=["a", "b"]), "Site injoignable (a ; b)", "Site unreachable (a; b)"),
    (
        msg("net.no_reachable_address", host="example.com"),
        "Aucune adresse joignable pour example.com",
        "No reachable address for example.com",
    ),
    (
        msg("net.resolve_failed", host="example.com"),
        "Résolution DNS impossible pour example.com",
        "DNS resolution failed for example.com",
    ),
    (msg("net.timeout"), "délai dépassé", "timed out"),
    (msg("target.invalid_ip", ip="'x'"), "Adresse IP invalide : 'x'", "Invalid IP address: 'x'"),
    (
        msg("target.ip_not_allowed"),
        "Adresse non autorisée : adresse privée, locale ou réservée. "
        "Pour analyser votre propre réseau, définissez ALLOW_PRIVATE_TARGETS=1.",
        "Address not allowed: private, local or reserved address. "
        "To scan your own network, set ALLOW_PRIVATE_TARGETS=1.",
    ),
    (
        msg("target.not_allowed"),
        "Cible non autorisée : la cible correspond à une adresse privée, locale ou réservée. "
        "Pour analyser votre propre réseau, définissez ALLOW_PRIVATE_TARGETS=1.",
        "Target not allowed: the target resolves to a private, local or reserved address. "
        "To scan your own network, set ALLOW_PRIVATE_TARGETS=1.",
    ),
    (
        msg("target.not_allowed_host", host="intranet.example"),
        "Cible non autorisée : « intranet.example » correspond à une adresse privée, locale ou réservée. "
        "Pour analyser votre propre réseau, définissez ALLOW_PRIVATE_TARGETS=1.",
        "Target not allowed: “intranet.example” resolves to a private, local or reserved address. "
        "To scan your own network, set ALLOW_PRIVATE_TARGETS=1.",
    ),
    (
        msg("target.peer_not_public"),
        "Cible non autorisée : la connexion a abouti sur une adresse privée, locale ou réservée.",
        "Target not allowed: the connection reached a private, local or reserved address.",
    ),
    (msg("target.scheme_not_allowed", scheme="ftp"), "Schéma non autorisé : ftp", "Scheme not allowed: ftp"),
]


@pytest.mark.parametrize(
    ("message", "francais", "anglais"),
    _MESSAGES_CIBLES_ET_HTTP,
    ids=[message["$t"] for message, _, _ in _MESSAGES_CIBLES_ET_HTTP],
)
def test_cibles_et_http_messages_en_francais_et_en_anglais(message, francais, anglais):
    """Le français rendu est le texte d'origine du scanner, l'anglais son équivalent."""
    assert fr(message) == francais
    assert en(message) == anglais


def test_cibles_et_http_tous_les_codes_ont_leur_rendu_epingle():
    epingles = {
        message["$t"] for message, _, _ in _MESSAGES_CIBLES_ET_HTTP + _MESSAGES_ORCHESTRATEUR + _MESSAGES_TLS
    }
    assert {code for code in catalog("fr") if code.startswith(("http.", "net.", "target."))} <= epingles


def test_describe_error_autres_cas_en_anglais():
    requete = httpx.Request("GET", "https://example.com")
    # Cible refusée : le message de l'erreur est repris tel quel, à défaut un message par défaut.
    refus = msg("target.scheme_not_allowed", scheme="ftp")
    assert describe_error(TargetNotAllowedError(refus)) == refus
    assert en(describe_error(TargetNotAllowedError())) == "target not allowed"
    deconnecte = httpx.RemoteProtocolError("Server disconnected without sending a response.", request=requete)
    assert en(describe_error(deconnecte)) == "connection closed by the server without a response"
    illegal = httpx.RemoteProtocolError("illegal header line", request=requete)
    assert en(describe_error(illegal)) == "non-compliant HTTP response (illegal header line)"
    assert en(describe_error(httpx.RemoteProtocolError("", request=requete))) == "non-compliant HTTP response"
    assert en(describe_error(httpx.ConnectError("", request=requete))) == "connection failed"
    # Autre erreur : nom du type et texte (identiques dans toutes les langues), ou le nom seul.
    assert en(describe_error(httpx.InvalidURL("URL illisible"))) == "InvalidURL: URL illisible"
    assert describe_error(RuntimeError()) == "RuntimeError"


def test_redirections_interrompues_en_anglais(monkeypatch):
    """Boucle, hôte refusé, Location inexploitable : le suivi s'arrête sur un message traduisible."""
    monkeypatch.setenv("ALLOW_PRIVATE_TARGETS", "1")

    def repondre(request):
        if request.url.path == "/boucle":
            return httpx.Response(302, headers={"location": "/boucle"})
        if request.url.path == "/invalide":
            return httpx.Response(302, headers={"location": "javascript:alert(1)"})
        if request.url.host == "www.example.com":
            raise TargetNotAllowedError(msg("target.peer_not_public"))
        return httpx.Response(302, headers={"location": "http://www.example.com/suite"})

    def suivre(chemin, **kwargs):
        async def scenario():
            async with common._http_client(transport=httpx.MockTransport(repondre)) as client:
                return await fetch(client, f"http://example.com{chemin}", site="example.com", **kwargs)

        return asyncio.run(scenario())

    boucle = suivre("/boucle", max_redirects=2)
    assert fr(boucle.redirect_error) == "Trop de redirections (plus de 2)"
    assert en(boucle.redirect_error) == "Too many redirects (more than 2)"

    # L'erreur de la requête suivante est un message : traduite dans celui qui l'enveloppe.
    refusee = suivre("/depart")
    assert fr(refusee.redirect_error) == (
        "Redirection non suivie (http://www.example.com/suite) : "
        "Cible non autorisée : la connexion a abouti sur une adresse privée, locale ou réservée."
    )
    assert en(refusee.redirect_error) == (
        "Redirect not followed (http://www.example.com/suite): "
        "Target not allowed: the connection reached a private, local or reserved address."
    )

    invalide = suivre("/invalide")
    assert en(invalide.redirect_error) == "Redirect to an invalid URL or an unsupported scheme"


def test_pair_non_public_refuse_en_anglais(monkeypatch):
    """Second rempart : la réponse d'un pair à l'adresse non publique est refusée avec un message."""
    monkeypatch.setenv("ALLOW_PRIVATE_TARGETS", "0")

    class Flux:
        def get_extra_info(self, nom):
            return ("10.0.0.5", 80) if nom == "server_addr" else None

    reponse = httpx.Response(
        200,
        request=httpx.Request("GET", "http://example.com/"),
        extensions={"network_stream": Flux()},
    )
    hooks = common._target_guard_hooks(real_network=False)
    with pytest.raises(TargetNotAllowedError) as excinfo:
        asyncio.run(hooks["response"][0](reponse))
    assert fr(excinfo.value.message) == (
        "Cible non autorisée : la connexion a abouti sur une adresse privée, locale ou réservée."
    )
    assert en(excinfo.value.message) == (
        "Target not allowed: the connection reached a private, local or reserved address."
    )


def test_resolution_impossible_a_la_connexion_en_anglais(monkeypatch):
    """Nom résolu par la garde puis sans adresse à la connexion : le message traverse httpx (raise … from)."""
    monkeypatch.setenv("ALLOW_PRIVATE_TARGETS", "0")
    reponses = iter([["93.184.216.34"]])

    async def resoudre(host, timeout=targets.RESOLVE_TIMEOUT):
        # Première résolution (la garde) : adresse publique ; ensuite (la connexion) : plus rien.
        return next(reponses, [])

    monkeypatch.setattr(targets, "resolve_addresses", resoudre)

    async def requete():
        async with common._http_client() as client:
            await client.get("http://instable.example/")

    with pytest.raises(httpx.ConnectError) as excinfo:
        asyncio.run(requete())
    assert str(excinfo.value) == "Résolution DNS impossible pour instable.example"  # journaux : français
    assert en(describe_error(excinfo.value)) == (
        "connection failed (DNS resolution failed for instable.example)"
    )
    assert fr(describe_error(excinfo.value)) == (
        "connexion impossible (Résolution DNS impossible pour instable.example)"
    )


def test_garde_sans_resolution_en_anglais(monkeypatch):
    """Sans adresse pour le nom, la garde d'un client réel échoue tout de suite, avec un message."""
    monkeypatch.setenv("ALLOW_PRIVATE_TARGETS", "0")

    async def resoudre(host, timeout=targets.RESOLVE_TIMEOUT):
        return []

    monkeypatch.setattr(targets, "resolve_addresses", resoudre)

    async def requete():
        async with common._http_client() as client:
            await client.get("http://introuvable.example/")

    with pytest.raises(httpx.ConnectError) as excinfo:
        asyncio.run(requete())
    assert str(excinfo.value) == "Résolution DNS impossible pour introuvable.example"
    assert en(message_of(excinfo.value)) == "DNS resolution failed for introuvable.example"


def test_connexion_epinglee_sans_adresse_en_anglais(monkeypatch):
    """Sans adresse à joindre, la connexion épinglée échoue avec une erreur httpcore qui porte un message."""
    monkeypatch.setenv("ALLOW_PRIVATE_TARGETS", "0")
    adresses: list[str] = []

    async def autoriser(host):
        return adresses

    monkeypatch.setattr(common, "ensure_target_allowed", autoriser)
    backend = common._PinnedBackend()
    with pytest.raises(httpcore.ConnectError) as excinfo:
        asyncio.run(backend.connect_tcp("introuvable.example", 80))
    assert str(excinfo.value) == "Résolution DNS impossible pour introuvable.example"
    assert en(message_of(excinfo.value)) == "DNS resolution failed for introuvable.example"

    # Aucune adresse essayée (borne ramenée à 0) : l'erreur par défaut de la connexion.
    adresses.append("93.184.216.34")
    monkeypatch.setattr(common, "MAX_CONNECT_ADDRESSES", 0)
    with pytest.raises(httpcore.ConnectError) as excinfo:
        asyncio.run(backend.connect_tcp("introuvable.example", 80))
    assert str(excinfo.value) == "Aucune adresse joignable pour introuvable.example"
    assert en(message_of(excinfo.value)) == "No reachable address for introuvable.example"


def test_cible_resolue_vers_une_adresse_interne_en_anglais(monkeypatch):
    monkeypatch.setenv("ALLOW_PRIVATE_TARGETS", "0")

    async def resoudre(host, timeout=targets.RESOLVE_TIMEOUT):
        return ["10.1.2.3"]

    monkeypatch.setattr(targets, "resolve_addresses", resoudre)
    with pytest.raises(TargetNotAllowedError) as excinfo:
        asyncio.run(targets.ensure_target_allowed("intranet.example"))
    assert str(excinfo.value) == fr(excinfo.value.message)  # journaux : français
    assert en(excinfo.value.message) == (
        "Target not allowed: “intranet.example” resolves to a private, local or reserved address. "
        "To scan your own network, set ALLOW_PRIVATE_TARGETS=1."
    )
    # Nom qui n'est pas une cible valide (forme numérique lue par le résolveur) : il n'est pas repris.
    with pytest.raises(TargetNotAllowedError) as excinfo:
        asyncio.run(targets.ensure_target_allowed("0x7f000001"))
    assert en(excinfo.value.message) == (
        "Target not allowed: the target resolves to a private, local or reserved address. "
        "To scan your own network, set ALLOW_PRIVATE_TARGETS=1."
    )


def test_ip_invalide_en_anglais():
    with pytest.raises(ValueError) as excinfo:
        targets.ensure_ip_allowed("pas-une-ip")
    assert not isinstance(excinfo.value, TargetNotAllowedError)
    assert str(excinfo.value) == "Adresse IP invalide : 'pas-une-ip'"  # journaux : français
    assert en(message_of(excinfo.value)) == "Invalid IP address: 'pas-une-ip'"


@pytest.mark.parametrize(
    ("module", "fonction", "debut"),
    [
        (cookies_module, "analyze_cookies", "Analyse des cookies impossible sur example.com: "),
        (cors_module, "check_cors", "Analyse CORS impossible sur example.com: "),
        (waf_module, "detect_waf", "Détection WAF impossible sur example.com: "),
    ],
    ids=["cookies", "cors", "waf"],
)
def test_site_injoignable_journalise_en_francais(monkeypatch, caplog, module, fonction, debut):
    """Le journal de débogage reçoit le texte français de l'erreur, non la structure du message."""
    monkeypatch.setenv("ALLOW_PRIVATE_TARGETS", "1")

    def refuser(request):
        raise httpx.ConnectError("boom", request=request)

    monkeypatch.setattr(
        module,
        "_http_client",
        lambda timeout=10.0: common._http_client(timeout, transport=httpx.MockTransport(refuser)),
    )
    caplog.set_level(logging.DEBUG, logger="domainrecon.scanner")
    result = asyncio.run(getattr(module, fonction)("example.com"))
    assert result["measured"] is False
    assert debut + fr(result["error"]) in caplog.text
    assert "'$t'" not in caplog.text


# --- tls.py ------------------------------------------------------------------------


def test_tls_raisons_en_anglais():
    erreur = ssl.SSLCertVerificationError("certificate verify failed")
    erreur.verify_code = 10
    erreur.verify_message = "certificate has expired"
    assert en(tls_module._describe_verify_error(erreur)) == "Certificate expired"
    assert fr(tls_module._describe_verify_error(erreur)) == "Certificat expiré"
    erreur.verify_code = 999
    assert en(tls_module._describe_verify_error(erreur)) == "Invalid certificate: certificate has expired"
    assert en(tls_module._describe_network_error(ConnectionRefusedError())) == "connection refused"
    assert en(tls_module._describe_network_error(TimeoutError())) == "timed out"


def test_tls_autres_erreurs_de_verification_et_reseau():
    """Sans message OpenSSL, le texte de l'erreur ; sans texte, le nom de son type (données brutes)."""
    erreur = ssl.SSLCertVerificationError(1, "certificate verify failed")
    erreur.verify_code = 999
    erreur.verify_message = ""
    assert en(tls_module._describe_verify_error(erreur)) == "Invalid certificate: certificate verify failed"
    assert tls_module._verify_reason(None) is None and tls_module._verify_reason(999) is None
    assert tls_module._describe_network_error(OSError()) == "OSError"
    assert tls_module._describe_network_error(OSError(5, "boom")) == "[Errno 5] boom"
    assert en(tls_module._describe_network_error(ConnectionResetError())) == "connection reset by the host"
    assert en(tls_module._describe_network_error(socket.gaierror(-2, "inconnu"))) == "name not found"
    assert fr(tls_module._describe_network_error(socket.gaierror(-2, "inconnu"))) == "nom introuvable"


# Messages de tls.py : (message, texte français d'origine, texte anglais).
_MESSAGES_TLS = [
    (msg("net.connection_refused"), "connexion refusée", "connection refused"),
    (
        msg("net.connection_reset_by_host"),
        "connexion réinitialisée par l'hôte",
        "connection reset by the host",
    ),
    (msg("net.name_not_found"), "nom introuvable", "name not found"),
    (
        msg("tls.analysis_failed", detail="nom refusé"),
        "Analyse TLS impossible : nom refusé",
        "TLS analysis failed: nom refusé",
    ),
    (
        msg("tls.handshake_failed", detail="WRONG_VERSION_NUMBER"),
        "Poignée de main TLS impossible : WRONG_VERSION_NUMBER",
        "TLS handshake failed: WRONG_VERSION_NUMBER",
    ),
    (
        msg("tls.host_unreachable", port=443, error=msg("net.timeout")),
        "Hôte injoignable sur le port 443 : délai dépassé",
        "Host unreachable on port 443: timed out",
    ),
    (
        msg("tls.host_unreachable", port=8443, error="[Errno 5] boom"),
        "Hôte injoignable sur le port 8443 : [Errno 5] boom",
        "Host unreachable on port 8443: [Errno 5] boom",
    ),
    (
        msg("tls.https_closed", port=443),
        "HTTPS indisponible : port 443 fermé ou filtré",
        "HTTPS unavailable: port 443 closed or filtered",
    ),
    (msg("tls.verify_10"), "Certificat expiré", "Certificate expired"),
    (msg("tls.verify_18"), "Certificat auto-signé", "Self-signed certificate"),
    (
        msg("tls.verify_19"),
        "Chaîne signée par une autorité racine non reconnue (auto-signée)",
        "Chain signed by an untrusted (self-signed) root authority",
    ),
    (
        msg("tls.verify_2"),
        "Certificat de l'autorité émettrice introuvable (chaîne incomplète)",
        "Issuer certificate not found (incomplete chain)",
    ),
    (
        msg("tls.verify_20"),
        "Autorité de certification inconnue ou chaîne incomplète",
        "Unknown certificate authority or incomplete chain",
    ),
    (
        msg("tls.verify_21"),
        "Signature du certificat invérifiable (chaîne incomplète)",
        "Certificate signature cannot be verified (incomplete chain)",
    ),
    (msg("tls.verify_23"), "Certificat révoqué", "Certificate revoked"),
    (msg("tls.verify_24"), "Autorité de certification invalide", "Invalid certificate authority"),
    (
        msg("tls.verify_26"),
        "Certificat non prévu pour l'authentification d'un serveur",
        "Certificate not intended for server authentication",
    ),
    (
        msg("tls.verify_62"),
        "Nom d'hôte non concordant avec le certificat",
        "Hostname does not match the certificate",
    ),
    (
        msg("tls.verify_64"),
        "Adresse IP non concordante avec le certificat",
        "IP address does not match the certificate",
    ),
    (msg("tls.verify_66"), "Clé du certificat trop faible", "Certificate key too weak"),
    (
        msg("tls.verify_67"),
        "Clé de l'autorité de certification trop faible",
        "Certificate authority key too weak",
    ),
    (msg("tls.verify_68"), "Algorithme de signature trop faible", "Signature algorithm too weak"),
    (msg("tls.verify_7"), "Signature du certificat invalide", "Invalid certificate signature"),
    (msg("tls.verify_9"), "Certificat pas encore valide", "Certificate not yet valid"),
    (
        msg("tls.verify_other", detail="erreur exotique"),
        "Certificat non valide : erreur exotique",
        "Invalid certificate: erreur exotique",
    ),
]


@pytest.mark.parametrize(
    ("message", "francais", "anglais"),
    _MESSAGES_TLS,
    ids=[f"{message['$t']}-{numero}" for numero, (message, _, _) in enumerate(_MESSAGES_TLS)],
)
def test_tls_messages_en_francais_et_en_anglais(message, francais, anglais):
    """Le français rendu est le texte d'origine du module TLS, l'anglais son équivalent."""
    assert fr(message) == francais
    assert en(message) == anglais


def test_tls_tous_les_codes_ont_leur_rendu_epingle():
    epingles = {message["$t"] for message, _, _ in _MESSAGES_TLS}
    assert {code for code in catalog("fr") if code.startswith("tls.")} <= epingles
    assert {"net.connection_refused", "net.connection_reset_by_host", "net.name_not_found"} <= epingles


def test_tls_chaque_code_de_verification_openssl_est_traduit():
    """Les 16 codes X509_V_ERR_* reconnus donnent une raison ; les autres, aucune."""
    codes = (2, 7, 9, 10, 18, 19, 20, 21, 23, 24, 26, 62, 64, 66, 67, 68)
    for code in codes:
        assert tls_module._verify_reason(code) == msg(f"tls.verify_{code}"), code
    assert not any(tls_module._verify_reason(code) for code in (0, 1, 3, 100, -1, None))


def _lever(erreur):
    """Fonction de remplacement qui lève toujours `erreur` (poignée de main ou connexion simulée)."""

    def lever(*args, **kwargs):
        raise erreur

    return lever


def _analyser(monkeypatch, erreur, http_repond=False, **kwargs):
    """_check_tls_sync quand la poignée de main échoue avec `erreur` (ni réseau ni magasin de certificats)."""
    monkeypatch.setattr(tls_module, "_verified_context", lambda: None)
    monkeypatch.setattr(tls_module, "_unverified_context", lambda: None)
    monkeypatch.setattr(tls_module, "_handshake", _lever(erreur))
    monkeypatch.setattr(tls_module, "_http_port_responds", lambda *args, **kw: http_repond)
    return tls_module._check_tls_sync("example.com", addresses=["203.0.113.10"], **kwargs)


def test_tls_verification_en_echec_en_anglais(monkeypatch):
    """Certificat invalide : mesure valable, raison traduisible, reprise telle quelle par le score."""
    erreur = ssl.SSLCertVerificationError(1, "certificate verify failed")
    erreur.verify_code = 62
    erreur.verify_message = "Hostname mismatch"
    result = _analyser(monkeypatch, erreur)
    assert result["measured"] is True and result["https"] is True and result["valid"] is False
    assert result["error"] is None
    assert result["verify_code"] == 62
    assert fr(result["verify_error"]) == "Nom d'hôte non concordant avec le certificat"
    assert en(result["verify_error"]) == "Hostname does not match the certificate"
    detail = compute_security_score({"tls_certificate": result})["breakdown"]["tls"]["detail"]
    assert en(detail) == "Invalid: Hostname does not match the certificate"
    assert fr(detail) == "Invalide : Nom d'hôte non concordant avec le certificat"


def test_tls_poignee_de_main_refusee_en_anglais(monkeypatch):
    erreur = ssl.SSLError(1, "[SSL: WRONG_VERSION_NUMBER] wrong version number")
    erreur.reason = "WRONG_VERSION_NUMBER"
    result = _analyser(monkeypatch, erreur)
    assert (result["measured"], result["https"], result["error"]) == (True, False, None)
    assert fr(result["verify_error"]) == "Poignée de main TLS impossible : WRONG_VERSION_NUMBER"
    assert en(result["verify_error"]) == "TLS handshake failed: WRONG_VERSION_NUMBER"
    # Sans raison OpenSSL : le texte de l'erreur.
    erreur.reason = None
    result = _analyser(monkeypatch, erreur)
    assert (
        en(result["verify_error"]) == "TLS handshake failed: [SSL: WRONG_VERSION_NUMBER] wrong version number"
    )


def test_tls_https_ferme_mais_site_http_en_anglais(monkeypatch):
    result = _analyser(monkeypatch, ConnectionRefusedError(), http_repond=True, port=8443)
    assert (result["measured"], result["https"], result["error"]) == (True, False, None)
    assert fr(result["verify_error"]) == "HTTPS indisponible : port 8443 fermé ou filtré"
    assert en(result["verify_error"]) == "HTTPS unavailable: port 8443 closed or filtered"


@pytest.mark.parametrize(
    ("erreur", "francais", "anglais"),
    [
        (TimeoutError("timed out"), "délai dépassé", "timed out"),
        (ConnectionRefusedError(10061, "refused"), "connexion refusée", "connection refused"),
        (
            ConnectionResetError(10054, "reset"),
            "connexion réinitialisée par l'hôte",
            "connection reset by the host",
        ),
        (socket.gaierror(-2, "inconnu"), "nom introuvable", "name not found"),
        (OSError(5, "boom"), "[Errno 5] boom", "[Errno 5] boom"),
    ],
    ids=["delai", "refusee", "reinitialisee", "nom", "autre"],
)
def test_tls_hote_injoignable_en_anglais(monkeypatch, erreur, francais, anglais):
    result = _analyser(monkeypatch, erreur)
    assert (result["measured"], result["https"], result["verify_error"]) == (False, False, None)
    assert fr(result["error"]) == f"Hôte injoignable sur le port 443 : {francais}"
    assert en(result["error"]) == f"Host unreachable on port 443: {anglais}"


def test_tls_analyse_impossible_en_anglais(monkeypatch):
    result = _analyser(monkeypatch, ValueError("nom refusé"))
    assert result["measured"] is False
    assert fr(result["error"]) == "Analyse TLS impossible : nom refusé"
    assert en(result["error"]) == "TLS analysis failed: nom refusé"
    # Sans texte : le nom du type de l'erreur.
    assert en(_analyser(monkeypatch, ValueError())["error"]) == "TLS analysis failed: ValueError"


def test_tls_aucune_adresse_joignable_en_anglais(monkeypatch, caplog):
    """Aucune adresse à essayer : l'erreur de connexion porte un message, repris dans « hôte injoignable »."""
    monkeypatch.setattr(tls_module, "_verified_context", lambda: None)
    monkeypatch.setattr(tls_module, "MAX_ADDRESSES", 0)
    with pytest.raises(OSError) as excinfo:
        tls_module._connect("example.com", 443, 1.0, ["203.0.113.10"])
    assert str(excinfo.value) == "Aucune adresse joignable pour example.com"  # journaux : français
    assert en(message_of(excinfo.value)) == "No reachable address for example.com"

    caplog.set_level(logging.DEBUG, logger="domainrecon.scanner")
    result = tls_module._check_tls_sync("example.com", addresses=["203.0.113.10"])
    assert result["measured"] is False
    assert (
        fr(result["error"]) == "Hôte injoignable sur le port 443 : Aucune adresse joignable pour example.com"
    )
    assert en(result["error"]) == "Host unreachable on port 443: No reachable address for example.com"
    # Le journal de débogage reçoit le texte français de l'erreur, non la structure du message.
    assert (
        "Connexion TLS impossible pour example.com: Aucune adresse joignable pour example.com" in caplog.text
    )
    assert "'$t'" not in caplog.text


def test_tls_resolution_impossible_en_anglais(monkeypatch):
    async def aucune_adresse(host):
        return []

    monkeypatch.setattr(tls_module, "ensure_target_allowed", aucune_adresse)
    result = asyncio.run(tls_module.check_tls_certificate("example.com"))
    assert result["measured"] is False and result["https"] is False
    assert fr(result["error"]) == "Résolution DNS impossible pour example.com"
    assert en(result["error"]) == "DNS resolution failed for example.com"


# --- email_security.py -------------------------------------------------------------


def test_email_messages_en_anglais():
    assert en(email_module.parse_spf("v=spf1 foo -all")["errors"]) == ["Invalid SPF term: foo"]

    recommandations = []
    spf = email_module._analyze_spf(None, DnsLookup("error", [], "délai dépassé"), recommandations)
    assert en(spf["error"]) == "SPF query failed: délai dépassé"
    assert fr(spf["error"]) == "Requête SPF échouée : délai dépassé"

    vide = email_module._analyze_spf(None, DnsLookup("ok", []), recommandations)
    assert en(vide["issues"]) == ["No SPF record found"]
    assert en(recommandations) == ["Add an SPF record ending with -all"]

    ip = email_module._analyze_email_security_sync("93.184.216.34")
    assert en(ip["error"]) == "E-mail analysis not applicable to an IP address"


class _ZoneDns:
    """Interrogateur DNS simulé : {(nom, type): DnsLookup} ; un nom absent répond « aucune donnée »."""

    def __init__(self, zone=None):
        self.zone = zone or {}

    def lookup(self, name, rtype):
        return self.zone.get((name, rtype), DnsLookup("noanswer", []))


def _ok(*textes):
    return DnsLookup("ok", list(textes))


def _delai_depasse():
    """Échec DNS dont l'erreur est déjà un message (et non plus un texte)."""
    return DnsLookup("error", [], msg("net.timeout"))


def _joker_dkim(cle):
    """Zone d'un joker *._domainkey : même réponse pour la sonde et pour chaque sélecteur courant."""
    noms = ["sonde", *email_module.DKIM_SELECTORS]
    return {(f"{nom}._domainkey.example.com", "TXT"): _ok(cle) for nom in noms}


@pytest.fixture
def sonde_dkim(monkeypatch):
    """Sélecteur DKIM aléatoire fixé : sa zone simule (ou non) un joker *._domainkey."""
    monkeypatch.setattr(email_module, "_random_dkim_selector", lambda: "sonde")


def test_email_spf_problemes_en_francais_et_en_anglais():
    zone = _ZoneDns(
        {
            ("loop.example", "TXT"): _ok("v=spf1 include:loop.example -all"),
            ("many.example", "TXT"): _ok("v=spf1 -all", "v=spf1 ~all"),
            ("open.example", "TXT"): _ok("v=spf1 +all"),
        }
    )
    record = (
        "v=spf1 ptr foo include:loop.example include:none.example include:many.example "
        "include:open.example ~all"
    )
    recommandations = []
    spf = email_module._analyze_spf(zone, _ok(record), recommandations)
    assert spf["grade"] == "F"
    assert fr(spf["issues"]) == [
        "Terme SPF invalide : foo",
        "Boucle SPF : include:loop.example s'inclut lui-même",
        "include:none.example : aucun enregistrement SPF (permerror)",
        "include:many.example : plusieurs enregistrements SPF (permerror)",
        "SPF softfail (~all) — préférer -all",
        "include:open.example autorise tout serveur (+all) : tout serveur peut envoyer",
        "Mécanisme ptr déconseillé (RFC 7208 §5.5) : lent, peu fiable, ignoré par certains serveurs",
    ]
    assert en(spf["issues"]) == [
        "Invalid SPF term: foo",
        "SPF loop: include:loop.example includes itself",
        "include:none.example: no SPF record (permerror)",
        "include:many.example: several SPF records (permerror)",
        "SPF softfail (~all) — prefer -all",
        "include:open.example allows any server (+all): any server can send",
        "ptr mechanism discouraged (RFC 7208 §5.5): slow, unreliable, ignored by some servers",
    ]
    assert en(recommandations) == ["Fix the SPF record (syntax, resolvable includes, at most 10 DNS lookups)"]


def test_email_spf_nombres_en_anglais():
    recommandations = []
    publies = _ok("v=spf1 -all", "v=spf1 ~all", "v=spf1 ?all")
    multiple = email_module._analyze_spf(_ZoneDns(), publies, recommandations)
    assert en(multiple["issues"]) == ["3 SPF records published: permerror, SPF is ignored"]
    assert en(recommandations) == ["Publish a single SPF record"]
    trop = "v=spf1 " + " ".join(f"a:h{i}.example" for i in range(11)) + " -all"
    spf = email_module._analyze_spf(_ZoneDns(), _ok(trop), [])
    assert fr(spf["issues"]) == ["Trop de requêtes DNS SPF (11 > 10) : permerror"]
    assert en(spf["issues"]) == ["Too many SPF DNS lookups (11 > 10): permerror"]


@pytest.mark.parametrize(
    ("record", "probleme", "recommandation"),
    [
        ("v=spf1 ?all", "SPF neutral (?all) — not protective", "End the SPF record with -all (or ~all)"),
        (
            "v=spf1 +all",
            "SPF with +all (or all without qualifier): any server can send",
            "End the SPF record with -all (or ~all)",
        ),
        (
            "v=spf1 ip4:192.0.2.1",
            "SPF without an “all” mechanism: neutral result by default, not protective",
            "End the SPF record with -all (or ~all)",
        ),
        (
            "v=spf1 include:open.example -all",
            "include:open.example allows any server (+all): any server can send",
            "Remove from SPF the includes that allow any server (+all)",
        ),
    ],
    ids=["neutre", "pass_all", "sans_all", "include_ouvert"],
)
def test_email_spf_qualificatif_et_recommandation_en_anglais(record, probleme, recommandation):
    zone = _ZoneDns({("open.example", "TXT"): _ok("v=spf1 +all")})
    recommandations = []
    spf = email_module._analyze_spf(zone, _ok(record), recommandations)
    assert en(spf["issues"]) == [probleme]
    assert en(recommandations) == [recommandation]


def test_email_spf_erreur_dns_message_rendue_a_chaque_niveau():
    """Une erreur DNS déjà traduisible est reprise dans la langue demandée, même sous deux messages."""
    spf = email_module._analyze_spf(None, _delai_depasse(), [])
    assert fr(spf["error"]) == "Requête SPF échouée : délai dépassé"
    assert en(spf["error"]) == "SPF query failed: timed out"

    zone = _ZoneDns({("_spf.example.net", "TXT"): _delai_depasse()})
    spf = email_module._analyze_spf(zone, _ok("v=spf1 redirect=_spf.example.net"), [])
    assert spf["grade"] is None
    assert fr(spf["error"]) == "Requête SPF échouée : redirect=_spf.example.net : délai dépassé"
    assert en(spf["error"]) == "SPF query failed: redirect=_spf.example.net: timed out"


def _dmarc(enregistrement):
    zone = _ZoneDns({("_dmarc.example.com", "TXT"): _ok(*enregistrement)})
    recommandations = []
    dmarc = email_module._analyze_dmarc(zone, "example.com", recommandations)
    return dmarc, recommandations


def test_email_dmarc_en_anglais():
    dmarc, recommandations = _dmarc(["v=DMARC1; p=reject; sp=none; pct=50"])
    assert en(dmarc["issues"]) == [
        "Subdomains not protected (sp=none)",
        "Only 50% of mail covered (pct=50): the rest falls under the 'quarantine' policy",
        "No aggregate reports (rua= missing)",
    ]
    assert en(recommandations) == ["Apply the DMARC policy to all mail (pct=100 or no pct=)"]
    assert fr(dmarc["issues"])[1] == (
        "Seulement 50% des mails couverts (pct=50) : les autres relèvent de la politique 'quarantine'"
    )

    # Politique none : la part non couverte relève de la même politique, sans la précision.
    dmarc, recommandations = _dmarc(["v=DMARC1; p=none; pct=50; rua=mailto:d@example.com"])
    assert en(dmarc["issues"]) == ["DMARC policy 'none' — no protection", "Only 50% of mail covered (pct=50)"]
    assert en(recommandations) == ["Change the DMARC policy from 'none' to 'quarantine' or 'reject'"]

    dmarc, recommandations = _dmarc(["v=DMARC1; p=reject; sp=bogus; pct=abc; rua=mailto:d@example.com"])
    assert en(dmarc["issues"]) == [
        "Invalid sp= value: bogus (invalid DMARC record)",
        "Invalid pct= value: abc",
    ]
    assert en(recommandations) == ["Fix the DMARC sp= value: none, quarantine or reject"]

    dmarc, recommandations = _dmarc(["v=DMARC1; p=bogus"])
    assert en(dmarc["issues"]) == [
        "DMARC policy (p=) missing or invalid",
        "No aggregate reports (rua= missing)",
    ]
    assert en(recommandations) == ["Fix the DMARC policy: p=quarantine or p=reject"]


def test_email_dmarc_absent_multiple_et_en_echec_en_anglais(monkeypatch):
    dmarc, recommandations = _dmarc(["verification=xyz"])
    assert en(dmarc["issues"]) == ["No DMARC record found"]
    assert en(recommandations) == ["Add a DMARC record"]

    dmarc, recommandations = _dmarc(["v=DMARC1; p=reject", "v=DMARC1; p=none"])
    assert en(dmarc["issues"]) == ["Several DMARC records: none is applied (RFC 7489 §6.6.3)"]
    assert en(recommandations) == ["Publish a single DMARC record"]

    # L'erreur de la recherche (message) est reprise dans la langue demandée.
    monkeypatch.setattr(
        email_module, "find_dmarc", lambda querier, domain: DmarcLookup([], None, False, msg("net.timeout"))
    )
    dmarc = email_module._analyze_dmarc(_ZoneDns(), "example.com", [])
    assert fr(dmarc["error"]) == "Requête DMARC échouée : délai dépassé"
    assert en(dmarc["error"]) == "DMARC query failed: timed out"


def test_email_dkim_en_anglais(sonde_dkim):
    recommandations = []
    dkim = email_module._analyze_dkim(_ZoneDns(), "example.com", recommandations)
    assert en(dkim["issues"]) == ["No DKIM key found among common selectors (another selector may be in use)"]
    assert en(recommandations) == ["Check the DKIM setup (no key on common selectors)"]

    revoquee = _ZoneDns({("google._domainkey.example.com", "TXT"): _ok("v=DKIM1; p=")})
    dkim = email_module._analyze_dkim(revoquee, "example.com", [])
    assert fr(dkim["issues"])[1] == "Clé DKIM révoquée (p= vide) : sélecteur google"
    assert en(dkim["issues"])[1] == "Revoked DKIM key (empty p=): selector google"

    joker = _ZoneDns(_joker_dkim("v=DKIM1; k=rsa; p=MIGfMA0GCSqGSIb3DQEB"))
    dkim = email_module._analyze_dkim(joker, "example.com", [])
    assert en(dkim["issues"]) == ["Wildcard DKIM key (*._domainkey): the same key answers for every selector"]

    en_echec = _ZoneDns(
        {(f"{nom}._domainkey.example.com", "TXT"): _delai_depasse() for nom in email_module.DKIM_SELECTORS}
    )
    dkim = email_module._analyze_dkim(en_echec, "example.com", [])
    assert dkim["found"] is None
    assert fr(dkim["error"]) == "Requêtes DKIM échouées : délai dépassé"
    assert en(dkim["error"]) == "DKIM queries failed: timed out"


@pytest.fixture
def analyse(monkeypatch):
    """_analyze_email_security_sync sur une zone DNS simulée (aucun accès réseau)."""

    def analyser(zone, *args):
        monkeypatch.setattr(email_module, "DnsQuerier", lambda timeout, budget: _ZoneDns(zone))
        return email_module._analyze_email_security_sync(*args)

    return analyser


def test_email_analyse_erreurs_du_module_en_anglais(analyse, monkeypatch):
    resultat = analyse({("example.com", "TXT"): DnsLookup("nxdomain", [])}, "example.com")
    assert fr(resultat["error"]) == "Domaine inexistant (NXDOMAIN) : example.com"
    assert en(resultat["error"]) == "Non-existent domain (NXDOMAIN): example.com"
    # C'est l'hôte scanné qui est signalé.
    zone = {("www.example.com", "TXT"): DnsLookup("nxdomain", [])}
    resultat = analyse(zone, "example.com", "www.example.com")
    assert en(resultat["error"]) == "Non-existent domain (NXDOMAIN): www.example.com"

    assert en(analyse({}, "")["error"]) == "No domain to analyze"
    assert fr(analyse({}, "")["error"]) == "Aucun domaine à analyser"

    # Ni SPF ni DMARC mesurés : les deux erreurs, jointes selon la typographie de la langue.
    monkeypatch.setattr(
        email_module, "find_dmarc", lambda querier, domain: DmarcLookup([], None, False, msg("net.timeout"))
    )
    resultat = analyse({("example.com", "TXT"): _delai_depasse()}, "example.com")
    assert resultat["measured"] is False and resultat["recommendations"] == []
    assert fr(resultat["error"]) == (
        "Analyse email impossible : Requête SPF échouée : délai dépassé ; Requête DMARC échouée : délai dépassé"
    )
    assert en(resultat["error"]) == (
        "E-mail analysis failed: SPF query failed: timed out; DMARC query failed: timed out"
    )


def test_email_analyse_notes_et_enregistrements_de_politique_en_anglais(analyse, sonde_dkim, monkeypatch):
    zone = {
        ("example.com", "TXT"): _ok("v=spf1 -all"),
        ("_dmarc.example.com", "TXT"): _ok("v=DMARC1; p=reject; rua=mailto:d@example.com"),
        ("_mta-sts.example.com", "TXT"): _delai_depasse(),
        **_joker_dkim("v=DKIM1; p="),
    }
    resultat = analyse(zone, "example.com")
    assert resultat["measured"] is True
    assert en(resultat["notes"]) == [
        "Revoked DKIM wildcard (*._domainkey, empty p=): no key for unpublished selectors"
    ]
    assert fr(resultat["notes"]) == [
        "Joker DKIM révoqué (*._domainkey, p= vide) : aucune clé pour les sélecteurs non publiés"
    ]
    assert fr(resultat["mta_sts"]["error"]) == "Requête _mta-sts.example.com échouée : délai dépassé"
    assert en(resultat["mta_sts"]["error"]) == "_mta-sts.example.com query failed: timed out"
    assert resultat["tls_rpt"]["error"] is None

    # MX nul, SPF -all et DMARC reject : le domaine n'envoie ni ne reçoit aucun courrier.
    monkeypatch.setattr(email_module, "has_null_mx", lambda answers: True)
    resultat = analyse(zone, "example.com")
    assert en(resultat["notes"]) == [
        "Domain without e-mail (RFC 7505): null MX, SPF -all and DMARC reject, no DKIM signature expected"
    ]
    assert resultat["recommendations"] == []


def test_email_spf_de_l_apex_non_herite_en_anglais(analyse):
    zone = {
        ("www.example.com", "TXT"): _ok("google-site-verification=abc"),
        ("example.com", "TXT"): _ok("v=spf1 ~all"),
    }
    resultat = analyse(zone, "example.com", "www.example.com")
    assert en(resultat["spf"]["issues"]) == [
        "No SPF record found",
        "The SPF of example.com does not apply to www.example.com: SPF is not inherited",
    ]
    assert fr(resultat["spf"]["issues"])[1] == (
        "Le SPF de example.com ne s'applique pas à www.example.com : un SPF ne s'hérite pas"
    )
