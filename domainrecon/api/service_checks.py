# =============================================================================
# DomainRecon - API : test des clés API (un appel minimal par service)
# =============================================================================
# POST /api/settings/test/{service} (routes/settings.py) vérifie qu'une clé
# enregistrée est acceptée par son service, par une requête qui ne consomme
# (presque) rien. Les URL sont fixes : aucune adresse ne vient du client. Le
# client HTTP est celui des API tierces du scanner : TLS vérifié, politique de
# cibles appliquée, aucune redirection suivie (la clé n'est jamais envoyée
# ailleurs que chez son service).
#
# Les services sont ceux de SERVICES (plus bas) et ceux dont un module fournit
# le test (ModuleSpec.key_tests, voir scanner/keys.py) : all_services().
#
# Les clés ne sortent jamais dans un message ni dans les journaux : seuls le
# nom du service, le code HTTP et la classe de l'erreur y figurent. Le journal
# d'httpx, qui écrit l'URL complète des requêtes (clé comprise pour les services
# qui la reçoivent en paramètre), est coupé par core/config.configure_logging().
# =============================================================================

import asyncio
import json
import logging
from collections.abc import Mapping

import httpx

from ..core.crypto import MASK
from ..i18n import msg
from ..scanner import _api_client, registry
from ..scanner.errors import TargetNotAllowedError, message_of
from ..scanner.http_utils import read_body_limited
from ..scanner.keys import ERROR, QUOTA, REJECTED, CheckOutcome, KeyTest, Probe

__all__ = [
    "ERROR",
    "QUOTA",
    "REJECTED",
    "SERVICES",
    "CheckOutcome",
    "Probe",
    "ServiceCheck",
    "all_services",
    "run_check",
]

logger = logging.getLogger(__name__)

# Délai d'une requête (connexion, lecture…) et de l'ensemble du test, en secondes.
PROBE_TIMEOUT = 10.0
TOTAL_TIMEOUT = 20.0

# Taille maximale lue dans la réponse d'un service qui signale ses erreurs dans le corps.
MAX_BODY_BYTES = 256 * 1024

# Longueur maximale du détail d'une erreur réseau rendu à l'utilisateur ; les secrets de moins de
# 6 caractères ne sont pas masqués dans ce détail (ils en défigureraient le texte).
MAX_DETAIL_LENGTH = 200
MIN_REDACTED_LENGTH = 6

# Service testable (nom historique) : nom affiché, clés requises, requêtes ou test sur mesure.
ServiceCheck = KeyTest


def _client() -> httpx.AsyncClient:
    """Client HTTP des tests (remplacé dans les tests par un client sur transport simulé)."""
    return _api_client(timeout=PROBE_TIMEOUT)


def _detail(exc: BaseException, secrets: Mapping[str, str]) -> object:
    """Cause d'un échec réseau pour l'utilisateur : message porté par l'exception, sinon son texte, sans les clés."""
    carried = message_of(exc)
    if carried is not None:
        return carried
    text = str(exc) or type(exc).__name__
    for secret in secrets.values():
        if len(secret) >= MIN_REDACTED_LENGTH:
            text = text.replace(secret, MASK)
    return text[:MAX_DETAIL_LENGTH]


def _outcome(label: str, probe: Probe, status: int, verdict: str | None = None) -> CheckOutcome:
    """Issue d'une réponse : code HTTP, et verdict tiré du corps pour les services qui y signalent leurs erreurs."""
    if verdict is None and (200 <= status < 300 or status in probe.accepted):
        return CheckOutcome(True, msg("api.settings_test_ok", service=label))
    if verdict == REJECTED or status in probe.rejected:
        return CheckOutcome(False, msg("api.settings_test_rejected", service=label, status=status))
    if verdict == QUOTA or status == 429:
        return CheckOutcome(False, msg("api.settings_test_quota", service=label))
    return CheckOutcome(False, msg("api.settings_test_http_error", service=label, status=status))


def _json_or_none(body: bytes) -> object:
    try:
        return json.loads(body)
    except (ValueError, RecursionError):
        return None


async def _run_probe(
    client: httpx.AsyncClient, label: str, probe: Probe, secrets: Mapping[str, str]
) -> CheckOutcome:
    """Envoie une requête de test. Le corps n'est lu que pour les services qui y signalent leurs erreurs."""
    try:
        async with client.stream(
            "GET", probe.url, params=probe.params, headers=probe.headers, auth=probe.auth
        ) as response:
            status = response.status_code
            verdict = None
            if probe.body_error is not None and 200 <= status < 300:
                body, _ = await read_body_limited(response, MAX_BODY_BYTES)
                verdict = probe.body_error(_json_or_none(body))
            return _outcome(label, probe, status, verdict)
    except httpx.TimeoutException:
        return CheckOutcome(
            False, msg("api.settings_test_timeout", service=label, seconds=f"{PROBE_TIMEOUT:g}")
        )
    except (httpx.HTTPError, httpx.InvalidURL, TargetNotAllowedError, OSError, ValueError) as exc:
        # La classe seule dans les journaux : le texte d'une erreur d'URL ou d'en-tête peut citer la clé.
        logger.warning("Test de la clé %s impossible : %s", label, type(exc).__name__)
        return CheckOutcome(
            False, msg("api.settings_test_unreachable", service=label, error=_detail(exc, secrets))
        )


async def _run_custom(check: ServiceCheck, secrets: Mapping[str, str]) -> CheckOutcome:
    """Test sur mesure fourni par un module (KeyTest.run) ; ses erreurs deviennent un échec sans clé dans le texte."""
    async with _client() as client:
        try:
            outcome = await check.run(secrets, client)
        except httpx.TimeoutException:
            return CheckOutcome(
                False, msg("api.settings_test_timeout", service=check.label, seconds=f"{PROBE_TIMEOUT:g}")
            )
        except Exception as exc:
            logger.warning("Test de la clé %s impossible : %s", check.label, type(exc).__name__)
            return CheckOutcome(
                False, msg("api.settings_test_unreachable", service=check.label, error=_detail(exc, secrets))
            )
    if not isinstance(outcome, CheckOutcome):
        logger.error("Test de la clé %s : CheckOutcome attendu, %s reçu", check.label, type(outcome).__name__)
        return CheckOutcome(False, msg("api.settings_test_http_error", service=check.label, status="?"))
    return outcome


async def _run_probes(check: ServiceCheck, secrets: Mapping[str, str]) -> CheckOutcome:
    """Essaie les requêtes du service dans l'ordre : la première réussie l'emporte, sinon le premier échec est rendu."""
    if check.run is not None:
        return await _run_custom(check, secrets)
    first_failure: CheckOutcome | None = None
    async with _client() as client:
        for probe in check.probes(secrets):
            outcome = await _run_probe(client, check.label, probe, secrets)
            if outcome.success:
                return outcome
            first_failure = first_failure or outcome
    return first_failure or CheckOutcome(False, msg("api.settings_test_no_key", service=check.label))


async def run_check(check: ServiceCheck, secrets: Mapping[str, str]) -> CheckOutcome:
    """Teste les clés `secrets` (en clair, par nom de colonne) auprès du service."""
    if any(not secrets.get(field) for field in check.fields):
        return CheckOutcome(False, msg("api.settings_test_no_key", service=check.label))
    try:
        return await asyncio.wait_for(_run_probes(check, secrets), timeout=TOTAL_TIMEOUT)
    except (asyncio.TimeoutError, TimeoutError):
        return CheckOutcome(
            False, msg("api.settings_test_timeout", service=check.label, seconds=f"{TOTAL_TIMEOUT:g}")
        )


# =============================================================================
# Services : une requête minimale chacun (documentation de leur API en commentaire)
# =============================================================================
# La clé voyage dans un en-tête quand le service le documente ; Shodan, Google et
# BuiltWith la reçoivent dans l'URL (?key=…), d'où la coupure du journal d'httpx.

_JSON = {"Accept": "application/json"}


def _shodan(s: Mapping[str, str]) -> list[Probe]:
    # https://developer.shodan.io/api : /api-info, offre et crédits de la clé.
    return [Probe("https://api.shodan.io/api-info", params={"key": s["shodan_key"]})]


def _virustotal(s: Mapping[str, str]) -> list[Probe]:
    # https://docs.virustotal.com/reference/domain-info : rapport d'un domaine, clé dans x-apikey.
    return [
        Probe(
            "https://www.virustotal.com/api/v3/domains/example.com",
            headers={"x-apikey": s["virustotal_key"]},
        )
    ]


def _censys(s: Mapping[str, str]) -> list[Probe]:
    # API « Platform » (https://docs.censys.com/reference/get-started) : jeton d'accès personnel (PAT) en Bearer,
    # ici le « secret ». L'ancienne API de recherche (identifiant d'API + secret) est retirée en 2026.
    # Solde de crédits d'un compte gratuit, sans consommation ; 404 « User not found » : jeton reconnu, mais
    # compte d'organisation (401 pour un jeton invalide).
    return [
        Probe(
            "https://api.platform.censys.io/v3/accounts/users/credits",
            headers={"Authorization": f"Bearer {s['censys_secret']}"},
            accepted=frozenset({404}),
        )
    ]


def _abuseipdb(s: Mapping[str, str]) -> list[Probe]:
    # https://docs.abuseipdb.com/#check-endpoint : une adresse publique et connue.
    return [
        Probe(
            "https://api.abuseipdb.com/api/v2/check",
            params={"ipAddress": "8.8.8.8", "maxAgeInDays": "1"},
            headers={**_JSON, "Key": s["abuseipdb_key"]},
        )
    ]


def _urlscan_verdict(data: object) -> str | None:
    """urlscan répond 200 même sans clé valide, avec les quotas de l'adresse IP (portée « ip-address ») :
    seule la portée « user » ou « team » prouve que la clé est reconnue."""
    if isinstance(data, dict) and data.get("scope") in ("user", "team"):
        return None
    return REJECTED


def _urlscan(s: Mapping[str, str]) -> list[Probe]:
    # https://docs.urlscan.io/apis/urlscan-openapi/generic : quotas de l'utilisateur.
    return [
        Probe(
            "https://urlscan.io/api/v1/quotas",
            headers={"API-Key": s["urlscan_key"]},
            body_error=_urlscan_verdict,
        )
    ]


def _otx(s: Mapping[str, str]) -> list[Probe]:
    # https://otx.alienvault.com/api : profil de l'utilisateur de la clé.
    return [Probe("https://otx.alienvault.com/api/v1/user/me", headers={"X-OTX-API-KEY": s["otx_key"]})]


def _safebrowsing(s: Mapping[str, str]) -> list[Probe]:
    # https://developers.google.com/safe-browsing/reference/rest/v5/hashLists/list : métadonnées d'une liste
    # (l'API v4 est dépréciée).
    return [
        Probe(
            "https://safebrowsing.googleapis.com/v5/hashLists",
            params={"key": s["safebrowsing_key"], "pageSize": "1"},
            # Google signale une clé invalide par un 400 (API_KEY_INVALID).
            rejected=frozenset({400, 401, 403}),
        )
    ]


def _securitytrails(s: Mapping[str, str]) -> list[Probe]:
    # https://docs.securitytrails.com/reference/ping : sonde de la clé.
    return [Probe("https://api.securitytrails.com/v1/ping", headers={"APIKEY": s["securitytrails_key"]})]


def _builtwith_verdict(data: object) -> str | None:
    """BuiltWith signale ses erreurs dans le JSON (Errors), pas toujours par un code HTTP d'erreur.

    Codes : -2 « API Key is wrong », -3 « out of API credits » (https://api.builtwith.com/errorCodes).
    Une réponse sans erreur doit décrire le compte (account, credits) : sinon, la clé n'est pas prouvée.
    """
    if not isinstance(data, dict):
        return ERROR
    errors = data.get("Errors")
    if errors:
        codes = {error.get("Code") for error in errors if isinstance(error, dict)}
        if -2 in codes:
            return REJECTED
        if -3 in codes:
            return QUOTA
        return ERROR
    return None if "account" in data or "credits" in data else ERROR


def _builtwith(s: Mapping[str, str]) -> list[Probe]:
    # https://api.builtwith.com/llms-full.txt : WhoAmI, le compte de la clé, sans crédit consommé.
    # (L'en-tête « Authorization: API <clé> » est aussi accepté ; le paramètre KEY est l'exemple documenté.)
    return [
        Probe(
            "https://api.builtwith.com/whoamiv1/api.json",
            params={"KEY": s["builtwith_key"]},
            body_error=_builtwith_verdict,
        )
    ]


def _circl(s: Mapping[str, str]) -> list[Probe]:
    # https://www.circl.lu/services/passive-dns/ : DNS passif, HTTP Basic ; 404 : identifiants reconnus, sans résultat.
    return [
        Probe(
            "https://www.circl.lu/pdns/query/circl.lu",
            auth=(s["circl_user"], s["circl_password"]),
            accepted=frozenset({404}),
        )
    ]


def _intelx(s: Mapping[str, str]) -> list[Probe]:
    # https://github.com/IntelligenceX/SDK : capacités de la clé ; l'offre gratuite a sa propre racine.
    headers = {"x-key": s["intelx_key"]}
    return [
        Probe("https://2.intelx.io/authenticate/info", headers=headers),
        Probe("https://free.intelx.io/authenticate/info", headers=headers),
    ]


def _github(s: Mapping[str, str]) -> list[Probe]:
    # https://docs.github.com/rest/users/users#get-the-authenticated-user
    return [
        Probe(
            "https://api.github.com/user",
            headers={
                "Authorization": f"Bearer {s['github_token']}",
                "Accept": "application/vnd.github+json",
                "X-GitHub-Api-Version": "2022-11-28",
            },
        )
    ]


# Identifiant de service (celui de l'URL) : nom affiché, colonnes de clés requises, requêtes à essayer.
SERVICES: dict[str, ServiceCheck] = {
    "shodan": ServiceCheck("Shodan", ("shodan_key",), _shodan),
    "virustotal": ServiceCheck("VirusTotal", ("virustotal_key",), _virustotal),
    "censys": ServiceCheck("Censys", ("censys_secret",), _censys),
    "abuseipdb": ServiceCheck("AbuseIPDB", ("abuseipdb_key",), _abuseipdb),
    "urlscan": ServiceCheck("urlscan.io", ("urlscan_key",), _urlscan),
    "otx": ServiceCheck("AlienVault OTX", ("otx_key",), _otx),
    "safebrowsing": ServiceCheck("Google Safe Browsing", ("safebrowsing_key",), _safebrowsing),
    "securitytrails": ServiceCheck("SecurityTrails", ("securitytrails_key",), _securitytrails),
    "builtwith": ServiceCheck("BuiltWith", ("builtwith_key",), _builtwith),
    "circl": ServiceCheck("CIRCL", ("circl_user", "circl_password"), _circl),
    "intelx": ServiceCheck("Intelligence X", ("intelx_key",), _intelx),
    "github": ServiceCheck("GitHub", ("github_token",), _github),
}


def all_services() -> dict[str, ServiceCheck]:
    """Services testables : ceux ci-dessus, puis ceux dont un module du registre fournit le test.

    Un module ne remplace pas un service de SERVICES (le test de contrat le refuse) :
    en cas de doublon, celui de SERVICES l'emporte.
    """
    services = dict(SERVICES)
    for spec in registry.MODULES.values():
        for service, test in spec.key_tests.items():
            if service in SERVICES:
                if test is not SERVICES[service]:
                    logger.warning(
                        "Test de clé %s du module %s ignoré : service déjà défini", service, spec.name
                    )
                continue
            services.setdefault(service, test)
    return services
