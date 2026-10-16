# =============================================================================
# DomainRecon - Scanner : orchestrateur du scan
# =============================================================================
# L'orchestrateur ne connaît aucun module : il demande au registre
# (registry.get_modules) ceux que le profil, l'autorisation de tester la cible
# et les clés API disponibles permettent de lancer, puis les exécute par vagues.
#   - vague 1, puis 2, puis 3 : les modules d'une vague tournent en parallèle,
#     la suivante ne démarre qu'à la fin de la précédente ;
#   - chaque module reçoit un ScanContext qui porte le résultat des modules déjà
#     terminés avec succès. Dans une même vague, un module qui dépend d'un autre
#     (depends_on) part dès que celui-ci est terminé, sans attendre le reste de
#     la vague : le takeover suit l'énumération des sous-domaines ;
#   - au plus MAX_PARALLEL_MODULES modules tournent à la fois (tous scans
#     confondus dans le scan courant) : une vague de 40 modules ne lance pas 40
#     requêtes et threads d'un coup ;
#   - chaque module a son délai : le sien (ModuleSpec.timeout), jamais écrasé,
#     ou à défaut celui que les Réglages fixent au profil (complet :
#     scan_timeout, rapide : quick_timeout) ; à son échéance, lui seul est
#     interrompu. L'attente d'une place (concurrence) ne compte pas ;
#   - ModuleSpec.skip_reason est évaluée au départ du module : une raison (non
#     None) le déclare « sans objet » (statut skipped) sans l'exécuter. Il en va
#     de même d'un module que les Réglages écartent (capture d'écran désactivée) ;
#   - chaque module reçoit dans son contexte (ScanContext.secrets) les clés API
#     qu'il a déclarées, et la page d'accueil de la cible partagée (homepage()) ;
#   - le proxy sortant, les clés API et les Réglages du scan sont lus UNE fois, au
#     départ et hors de la boucle d'événements. Le proxy est posé pour tout le scan (common.scan_proxy) :
#     les clients HTTP des modules (common._http_client, common._api_client) le
#     lisent, sans que les modules aient rien à transmettre ; le DNS, le WHOIS, le
#     scan de ports et la sonde TLS restent directs. Un proxy inutilisable
#     empêche le scan, jamais un repli vers une connexion directe.
#
# Résultat : les 18 premiers modules (MODULE_NAMES : ceux qui déclarent une
# colonne historique, ModuleSpec.column) gardent leur clé et leur colonne ; les
# autres modules du registre vont dans `modules`, sous la forme
# {nom: {status, data, duration, error}}. `module_status` donne le statut de
# chaque module lancé, dans l'ordre d'exécution : un module du registre qui n'y
# figure pas n'a pas été lancé (hors profil), et la clé de son résultat porte
# alors la valeur d'un module sans résultat (ModuleSpec.placeholder).
#
# Contrat des modules :
#   - un module qui renvoie un dict y place `measured` (bool) et `error` :
#     measured=False signifie que la mesure n'a pas pu être faite, sauf si le
#     dict porte aussi `skipped: True` (module sans objet pour cette cible,
#     par exemple un service tiers non interrogé pour une adresse privée) ;
#   - un module qui renvoie une liste lève ModuleError en cas d'échec réel ;
#   - ModuleSkipped(message) : le module découvre en route qu'il est sans objet ;
#   - le résultat ne contient que des types JSON : sinon le module est en échec
#     (orchestrator.not_serializable), et le scan, lui, est enregistré ;
#   - un module facultatif (ModuleSpec.optional) en échec ne dégrade pas le
#     statut global du scan ;
#   - aucun module n'avale asyncio.CancelledError ;
#   - `error` est un texte ou un message traduisible (voir domainrecon.i18n) :
#     l'orchestrateur le transmet tel quel, et rédige lui-même les siens.
# L'orchestrateur en déduit `module_status` et le statut global du scan : un
# module en échec n'est jamais présenté comme un module qui n'a rien trouvé.
# =============================================================================

import asyncio
import json
from collections.abc import Awaitable, Callable, Iterable, Mapping
from dataclasses import dataclass, field, replace
from datetime import datetime, timezone
from types import MappingProxyType

import httpx

from ..core.settings_store import ScanSettings, load_scan_settings, load_secrets
from ..i18n import msg, render
from . import registry
from .common import _verified_ssl_context, logger, scan_proxy
from .errors import ModuleError, ModuleSkipped, TargetNotAllowedError, exception_text, message_exception
from .proxy import get_proxy_url, make_http_client
from .registry import (
    DEFAULT_TIMEOUT,
    PROFILE_FULL,
    PROFILE_QUICK,
    WAVES,
    ModuleSpec,
    ScanContext,
    default_placeholder,
    get_modules,
)
from .score import compute_security_score
from .targets import (
    ensure_target_allowed,
    is_valid_target,
    normalize_target,
    registrable_domain,
    site_domain,
)

# =============================================================================
# Scan Complet (Orchestrateur)
# =============================================================================

# Budgets de temps, en secondes : délai d'un module sans délai propre quand les
# Réglages n'en donnent pas, délai propre du takeover (qui démarre dès la fin de
# l'énumération des sous-domaines) et résolution et contrôle de la cible,
# préalables à tout module.
MODULE_TIMEOUT = DEFAULT_TIMEOUT
TAKEOVER_TIMEOUT = 30
TARGET_RESOLVE_TIMEOUT = 15

# Nombre maximal de modules qui s'exécutent en même temps dans un scan. L'attente
# d'une place ne compte pas dans le délai du module.
MAX_PARALLEL_MODULES = 8


def legacy_module_names() -> tuple[str, ...]:
    """Modules à colonne historique (ModuleSpec.column, registry.COLUMN_MODULES) : les 18 premiers, dans l'ordre."""
    return tuple(registry.COLUMN_MODULES)


def __getattr__(name: str):
    # MODULE_NAMES : noms des modules à colonne historique, dans l'ordre de
    # `module_status` (calculé à la lecture, à partir du registre).
    if name == "MODULE_NAMES":
        return legacy_module_names()
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


# Rappel d'avancement : (module, statut, durée en secondes), appelé dès que
# l'issue d'un module est connue (voir perform_full_scan).
OnModule = Callable[[str, str, float], None]

_FAILURE_STATUSES = frozenset({"failed", "timeout"})

# Raisons d'un statut « skipped » (module sans objet, statut global intact).
# Celles qui tiennent à la cible (adresse IP, plateforme mutualisée, aucun
# sous-domaine) et le « non vérifié » du takeover sont rédigés par les modules
# eux-mêmes (registry.py, modules/), avec les mêmes messages : ces constantes
# en restent la référence, que les tests rapprochent des leurs.
_SKIP_IP_TARGET = msg("orchestrator.skip_ip_target")
_SKIP_NO_ADDRESS = msg("orchestrator.no_address")
_SKIP_NO_SUBDOMAINS = msg("orchestrator.skip_no_subdomains")
_SKIP_NO_PLAYWRIGHT = msg("orchestrator.skip_no_playwright")
_SKIP_SHARED_PLATFORM = msg("orchestrator.skip_shared_platform")

# Capture d'écran désactivée dans les Réglages (screenshot_enabled), et proxy
# sortant que le scan ne peut pas utiliser (le scan n'est alors pas lancé).
_SKIP_SCREENSHOT_DISABLED = msg("orchestrator.skip_screenshot_disabled")
_PROXY_UNUSABLE = msg("orchestrator.proxy_unusable")

# Takeover non vérifié faute de sous-domaines : il s'applique à la cible,
# c'est donc un échec (« failed »), pas un module sans objet.
_TAKEOVER_NOT_CHECKED = msg("orchestrator.takeover_not_checked")

# Tête du résumé quand l'hôte résout mais qu'aucun module HTTP ne l'a joint.
_HTTP_UNREACHABLE = msg("orchestrator.http_unreachable")

# Résumé d'un domaine que le DNS déclare inexistant (dns_records.nxdomain).
_NXDOMAIN = msg("orchestrator.nxdomain")


@dataclass
class _Outcome:
    """Résultat d'un module : statut pour `module_status`, valeur enregistrée et durée."""

    status: str  # ok | failed | timeout | skipped
    error: object  # texte, message traduisible ou None
    value: object
    # Secondes, du départ du module (ses dépendances terminées) à son issue.
    duration: float = 0.0


@dataclass(frozen=True)
class _ScanOptions:
    """Ce que les Réglages et le profil imposent à un scan, lus une fois au départ."""

    # Proxy sortant (Réglages, sinon environnement) ; None : aucun. Peut porter
    # des identifiants : jamais journalisé.
    proxy_url: str | None = field(default=None, repr=False)
    # Délai du profil, en secondes : celui des modules sans délai propre (None : MODULE_TIMEOUT).
    timeout: float | None = None
    # Modules que les Réglages écartent : nom -> raison (message traduisible).
    skipped: Mapping[str, object] = field(default_factory=dict)
    # Modules exécutés en même temps, au plus.
    max_parallel: int = MAX_PARALLEL_MODULES

    def module_timeout(self, spec: ModuleSpec) -> float:
        """Délai d'un module : le sien s'il en déclare un (jamais écrasé), sinon celui du profil."""
        if spec.timeout is not None:
            return spec.timeout
        return self.timeout if self.timeout is not None else MODULE_TIMEOUT


# Aucune contrainte : délais propres des modules, aucun module écarté.
_NO_OPTIONS = _ScanOptions()


def _scan_options(profile: str, proxy_url: str | None, settings: ScanSettings) -> _ScanOptions:
    """Options d'un scan : délai du profil (rapide : quick_timeout, sinon scan_timeout) et modules écartés."""
    timeout = settings.quick_timeout if profile == PROFILE_QUICK else settings.scan_timeout
    skipped = {} if settings.screenshot_enabled else {"screenshot": _SKIP_SCREENSHOT_DISABLED}
    return _ScanOptions(
        proxy_url=proxy_url or None, timeout=timeout, skipped=skipped, max_parallel=MAX_PARALLEL_MODULES
    )


def _open_shared_client(proxy_url: str | None) -> httpx.AsyncClient:
    """Client HTTP partagé du scan (ScanContext.http), derrière le proxy s'il y en a un.

    Même mécanisme que proxy.make_http_client : politique de cibles appliquée à
    chaque requête, proxy qui résout le nom lui-même. Une URL de proxy
    invalide, ou SOCKS sans le paquet socksio, empêche le scan : jamais de repli
    silencieux vers une connexion directe qui exposerait l'adresse de cette machine.
    """
    try:
        return make_http_client(proxy_url)
    except Exception as e:
        if not proxy_url:
            raise
        # Ni l'URL ni son texte d'erreur (qui peut la citer) ne vont dans le journal.
        logger.warning("Proxy sortant inutilisable (%s) : scan non lancé", type(e).__name__)
        raise message_exception(ValueError, _PROXY_UNUSABLE) from None


def _placeholder(name: str, error: object) -> object:
    """Valeur enregistrée pour un module sans résultat exploitable (ModuleSpec.placeholder).

    Même forme que le résultat « non mesuré » du module : le frontend lit ainsi
    toujours les mêmes clés. Par défaut : {measured: False, error}.
    """
    spec = registry.MODULES.get(name) or registry.COLUMN_MODULES.get(name)
    if spec is None:
        return default_placeholder(error)
    try:
        return spec.placeholder(error)
    except Exception:
        logger.exception("Valeur de repli du module %s en échec", name)
        return default_placeholder(error)


def _skipped(name: str, reason: object) -> _Outcome:
    return _Outcome("skipped", reason, _placeholder(name, None))


def _failed(name: str, status: str, message: object) -> _Outcome:
    return _Outcome(status, message, _placeholder(name, message))


def _not_serializable(value: object) -> str | None:
    """Nom de l'erreur si `value` ne s'enregistre pas en JSON (set, datetime, bytes, objet…), sinon None."""
    try:
        json.dumps(value)
    except (TypeError, ValueError, RecursionError) as e:
        return type(e).__name__
    return None


def _outcome_from_value(name: str, value: object) -> _Outcome:
    """Statut d'un module qui a rendu une valeur sans lever d'exception."""
    if value is None:
        return _failed(name, "failed", msg("orchestrator.no_result"))
    if (error := _not_serializable(value)) is not None:
        # Un résultat non enregistrable ferait perdre tout le scan : seul le module échoue.
        logger.error("Module %s : résultat non sérialisable en JSON (%s), écarté", name, error)
        return _failed(name, "failed", msg("orchestrator.not_serializable", error=error))
    if isinstance(value, dict):
        # measured=False : la mesure n'a pas pu être faite, ou le module est
        # sans objet (skipped). Un dict sans drapeau est jugé sur son champ error.
        if not value.get("measured", not value.get("error")):
            if value.get("skipped"):
                return _Outcome("skipped", value.get("error") or msg("orchestrator.skip_generic"), value)
            return _Outcome("failed", value.get("error") or msg("orchestrator.measure_failed"), value)
    return _Outcome("ok", None, value)


async def _run_module(
    name: str, factory: Callable[[], Awaitable[object]], timeout: float, target: str
) -> _Outcome:
    """Exécute un module sous délai et traduit son issue en statut.

    asyncio.CancelledError n'est jamais interceptée (BaseException) : une
    annulation du scan traverse l'orchestrateur.
    """
    try:
        value = await asyncio.wait_for(factory(), timeout=timeout)
    # asyncio.TimeoutError n'est fusionnée avec TimeoutError qu'à partir de
    # Python 3.11 : les deux sont nécessaires pour rester compatible 3.10.
    except (asyncio.TimeoutError, TimeoutError) as e:
        # wait_for lève une TimeoutError sans message ; un délai interne au
        # module garde le sien.
        message = (
            msg("orchestrator.timeout_detail", detail=exception_text(e))
            if str(e)
            else msg("orchestrator.timeout", seconds=f"{timeout:g}")
        )
        logger.warning("Module %s hors délai sur %s — %s", name, target, render(message, "fr"))
        return _failed(name, "timeout", message)
    # Messages déjà rédigés pour l'utilisateur. TargetNotAllowedError vient
    # d'une requête du module refusée en cours de route (redirection vers une
    # adresse interne, par exemple) : le module échoue, pas le scan.
    except (ModuleError, TargetNotAllowedError) as e:
        message = e.message or msg("orchestrator.module_failed")
        logger.warning("Module %s en échec sur %s — %s", name, target, render(message, "fr"))
        return _failed(name, "failed", message)
    except ModuleSkipped as e:
        reason = e.message or msg("orchestrator.skip_generic")
        logger.debug("Module %s sans objet sur %s — %s", name, target, render(reason, "fr"))
        return _skipped(name, reason)
    except Exception as e:
        message = msg("common.exception", error=type(e).__name__, detail=exception_text(e))
        logger.warning("Module %s en échec sur %s — %s", name, target, render(message, "fr"), exc_info=True)
        return _failed(name, "failed", message)

    outcome = _outcome_from_value(name, value)
    if outcome.status in _FAILURE_STATUSES:
        logger.warning("Module %s non mesuré sur %s — %s", name, target, render(outcome.error, "fr"))
    elif outcome.status == "skipped":
        logger.debug("Module %s sans objet sur %s — %s", name, target, render(outcome.error, "fr"))
    return outcome


async def _run_spec(spec: ModuleSpec, context: ScanContext, options: _ScanOptions = _NO_OPTIONS) -> _Outcome:
    """Issue d'un module : sans objet si les Réglages l'écartent ou si son skip_reason donne une raison, sinon son exécution sous délai."""
    # Un module que les Réglages écartent n'est même pas évalué.
    if (disabled := options.skipped.get(spec.name)) is not None:
        return _skipped(spec.name, disabled)
    try:
        reason = spec.skip_reason(context)
    except Exception as e:
        # Un module mal écrit échoue seul, comme s'il avait levé l'exception en s'exécutant.
        message = msg("common.exception", error=type(e).__name__, detail=exception_text(e))
        logger.warning(
            "Module %s : évaluation de skip_reason en échec sur %s — %s",
            spec.name,
            context.domain,
            render(message, "fr"),
            exc_info=True,
        )
        return _failed(spec.name, "failed", message)
    if reason is not None:
        return _skipped(spec.name, reason)
    return await _run_module(
        spec.name, lambda: spec.run(context), options.module_timeout(spec), context.domain
    )


async def _gather(coros: list[Awaitable]) -> list:
    """asyncio.gather qui annule les tâches restantes si l'une est interrompue.

    Les modules traduisent déjà leurs exceptions en statut : seule une
    annulation (ou une BaseException) peut remonter ici. gather ne propage
    l'annulation aux autres tâches que si c'est lui qui est annulé.
    """
    tasks = [asyncio.ensure_future(coro) for coro in coros]
    try:
        return await asyncio.gather(*tasks)
    except BaseException:
        for task in tasks:
            task.cancel()
        raise


def _module_context(context: ScanContext, spec: ModuleSpec, secrets: Mapping[str, str]) -> ScanContext:
    """Contexte d'un module : résultats connus à son départ et ses seules clés API déclarées."""
    own = {name: secrets[name] for name in spec.key_names if secrets.get(name)}
    return replace(context, results=dict(context.results), secrets=MappingProxyType(own))


async def _run_wave(
    batch: list[ModuleSpec],
    context: ScanContext,
    notify: Callable[[str, _Outcome], None],
    options: _ScanOptions = _NO_OPTIONS,
    secrets: Mapping[str, str] | None = None,
    limit: asyncio.Semaphore | None = None,
) -> list[_Outcome]:
    """Exécute en parallèle les modules d'une vague ; renvoie leur issue, dans l'ordre de `batch`.

    Un module qui dépend d'un autre module de la vague attend la fin de celui-ci
    (et de lui seul). Chacun reçoit son propre ScanContext, qui porte les
    résultats connus à son départ et ses clés API ; `context.results` reçoit
    ensuite le sien s'il a réussi, avant que ses dépendants ne partent. `limit`
    borne le nombre de modules en cours ; `notify` signale chaque issue.
    """
    loop = asyncio.get_running_loop()
    finished = {spec.name: asyncio.Event() for spec in batch}
    secrets = secrets or {}
    limit = limit or asyncio.Semaphore(options.max_parallel)

    async def run(spec: ModuleSpec) -> _Outcome:
        try:
            for name in spec.depends_on:
                # Hors de la vague (vague précédente), la dépendance est déjà terminée.
                if name in finished:
                    await finished[name].wait()
            async with limit:
                started = loop.time()
                outcome = await _run_spec(spec, _module_context(context, spec, secrets), options)
                outcome.duration = max(0.0, loop.time() - started)
            if outcome.status == "ok":
                context.results[spec.name] = outcome.value
            notify(spec.name, outcome)
            return outcome
        finally:
            finished[spec.name].set()

    return await _gather([run(spec) for spec in batch])


async def _run_waves(
    specs: list[ModuleSpec],
    context: ScanContext,
    notify: Callable[[str, _Outcome], None],
    options: _ScanOptions = _NO_OPTIONS,
    secrets: Mapping[str, str] | None = None,
) -> dict[str, _Outcome]:
    """Exécute les modules vague après vague ; renvoie leur issue par nom, dans l'ordre d'exécution."""
    outcomes: dict[str, _Outcome] = {}
    limit = asyncio.Semaphore(max(1, options.max_parallel))
    for wave in WAVES:
        batch = [spec for spec in specs if spec.wave == wave]
        if batch:
            results = await _run_wave(batch, context, notify, options, secrets, limit)
            for spec, outcome in zip(batch, results, strict=True):
                outcomes[spec.name] = outcome
    return outcomes


async def _resolve_target(domain: str) -> tuple[list[str], bool]:
    """Résout et contrôle la cible (anti-SSRF), sous délai.

    TargetNotAllowedError remonte telle quelle. Renvoie les adresses validées
    et un indicateur de dépassement du délai de résolution.
    """
    try:
        addresses = await asyncio.wait_for(ensure_target_allowed(domain), timeout=TARGET_RESOLVE_TIMEOUT)
    except (asyncio.TimeoutError, TimeoutError):
        logger.warning("Résolution de %s hors délai (%g s)", domain, TARGET_RESOLVE_TIMEOUT)
        return [], True
    return list(addresses or []), False


def _global_status(
    module_status: dict[str, dict],
    addresses: list[str],
    resolve_timed_out: bool,
    nxdomain: bool = False,
    *,
    http_probes: Iterable[str] | None = None,
    optional: Iterable[str] | None = None,
) -> tuple[str, object | None]:
    """Statut global du scan et résumé lisible (message traduisible, ou None).

    `nxdomain` : le module DNS a établi que le domaine n'existe pas ; ce n'est
    pas une cible injoignable, et le résumé le dit. Un scan qui n'a lancé aucun
    module HTTP (profil personnalisé) ne dit rien de la joignabilité du site :
    seule la résolution de la cible, ou le NXDOMAIN, peut alors la déclarer perdue.
    """
    if http_probes is None:
        http_probes = [spec.name for spec in registry.MODULES.values() if spec.http_probe]
    if optional is None:
        optional = [spec.name for spec in registry.MODULES.values() if spec.optional]
    http_probes, optional = tuple(http_probes), frozenset(optional)
    http_probed = any(name in module_status for name in http_probes)
    http_responded = any(module_status.get(name, {}).get("status") == "ok" for name in http_probes)
    seconds = f"{TARGET_RESOLVE_TIMEOUT:g}"
    if not addresses and not http_responded and (http_probed or nxdomain):
        if nxdomain:
            return "error", _NXDOMAIN
        if resolve_timed_out:
            return "error", msg("orchestrator.unreachable_resolve_timeout", seconds=seconds)
        return "error", msg("orchestrator.unreachable")

    notes: list[object] = []
    if not addresses:
        notes.append(
            msg("orchestrator.resolve_timeout", seconds=seconds) if resolve_timed_out else _SKIP_NO_ADDRESS
        )
    elif http_probed and not http_responded:
        # L'hôte résout (DNS, WHOIS, ports… mesurés) mais aucun module HTTP ne
        # l'a joint : dit en tête, pour ne pas passer pour un audit web partiel.
        notes.append(_HTTP_UNREACHABLE)
    # Un module facultatif en échec reste signalé dans module_status, sans dégrader le statut global.
    problems = [
        msg("orchestrator.problem_timeout", name=name) if st["status"] == "timeout" else name
        for name, st in module_status.items()
        if st["status"] in _FAILURE_STATUSES and name not in optional
    ]
    if problems:
        notes.append(msg("orchestrator.modules_failed", count=len(problems), modules=problems, sep=", "))
    if len(notes) == 1:
        return "partial", notes[0]
    if notes:
        return "partial", msg("common.join", items=notes)
    return "success", None


async def perform_full_scan(
    url_or_domain: str,
    on_module: OnModule | None = None,
    profile: str = PROFILE_FULL,
    authorized_target: bool = False,
    *,
    selected: Iterable[str] | None = None,
    available_keys: Iterable[str] = (),
) -> dict:
    """Effectue le scan d'une cible : les modules du profil, exécutés par vagues.

    `profile` : « rapide », « complet » (par défaut) ou « personnalise » (les
    modules de `selected`, avec leurs dépendances). `authorized_target` :
    l'utilisateur déclare avoir l'autorisation de tester la cible ; sans elle,
    aucun module actif ou sensible n'est lancé. `available_keys` : noms des clés
    API renseignées ; un module à clé n'est lancé qu'avec la sienne. La liste
    des modules est celle de registry.get_modules (mêmes arguments).

    Les Réglages sont lus au départ : le délai de chaque module est borné par
    celui du profil (« rapide » : quick_timeout, sinon scan_timeout), le module
    de capture d'écran est sans objet si elle est désactivée, et le proxy
    sortant s'applique aux modules HTTP, aux API tierces et à la capture.

    Lève ValueError (porteuse d'un message : `.message`) si la cible est
    invalide, ValueError si le profil ou un module de `selected` est inconnu,
    TargetNotAllowedError si la politique de cibles la refuse, et ValueError
    (message « proxy inutilisable ») si le proxy sortant ne peut pas servir ;
    aucun module n'est alors lancé.
    `on_module(nom, statut, durée)` est appelé, de façon synchrone, une fois par
    module lancé, dès que son issue est connue (ok, failed, timeout, skipped) ;
    une exception du rappel est journalisée et n'interrompt pas le scan.
    """
    domain = normalize_target(url_or_domain)
    if not is_valid_target(domain):
        raise message_exception(ValueError, msg("target.invalid", target=repr(url_or_domain)))

    # Modules à lancer : avant toute résolution, pour qu'un profil ou une
    # sélection invalide n'en coûte aucune.
    specs = get_modules(profile, available_keys, bool(authorized_target), selected)

    # WHOIS et DKIM (avec MTA-STS et TLS-RPT) s'interrogent sur le domaine
    # racine, pas sur le sous-domaine ciblé. SPF (et MX nul) s'évalue sur la
    # cible elle-même, sans héritage (RFC 7208) ; DMARC aussi, avec repli sur
    # ce domaine racine.
    apex = registrable_domain(domain)
    # Énumération CT sur le site, domaine enregistrable au sens de la PSL
    # complète : un hébergement mutualisé n'est pas la cible. Pour
    # alice.github.io, crt.sh cherche %.alice.github.io et non %.github.io ;
    # l'email, qui relève de la plateforme, n'est pas analysé. Le WHOIS reste
    # sur l'apex, seul nom connu du registre. Domaine ordinaire : site == apex.
    site = site_domain(domain)

    started_at = datetime.now(timezone.utc)
    logger.info(
        "Scan de %s (apex=%s, site=%s, profil=%s, %d module(s)) démarré",
        domain,
        apex,
        site,
        profile,
        len(specs),
    )

    # Contrôle anti-SSRF avant tout module. Les modules qui travaillent sur une
    # adresse IP (ports, géolocalisation, DNS inverse…) reçoivent l'adresse
    # validée : une seconde résolution pourrait en renvoyer une autre.
    addresses, resolve_timed_out = await _resolve_target(domain)

    # Proxy sortant, clés API (si un module en déclare) et Réglages du scan (délais par
    # profil, capture d'écran) : lus UNE fois, hors de la boucle d'événements (lecture
    # de la base). Le contexte TLS vérifiant des clients d'API, une demi-seconde de
    # calcul au premier usage, est construit là aussi : sans cela il bloquerait la
    # boucle au départ du scan.
    proxy_url, stored_settings, _, secrets = await asyncio.gather(
        asyncio.to_thread(get_proxy_url),
        asyncio.to_thread(load_scan_settings),
        asyncio.to_thread(_verified_ssl_context),
        asyncio.to_thread(_scan_secrets, specs),
    )
    options = _scan_options(profile, proxy_url, stored_settings)
    if options.proxy_url:
        logger.info("Scan de %s : requêtes HTTP, API tierces et capture via le proxy sortant", domain)
    # Client partagé du scan, pour les nouveaux modules (ScanContext.http) ; refusé
    # avant tout module si le proxy est inutilisable.
    http = _open_shared_client(options.proxy_url)
    context = ScanContext(
        domain=domain, apex=apex, site=site, addresses=addresses, proxy=options.proxy_url, http=http
    )
    ip_address = context.ip_address
    if not ip_address:
        logger.warning("Aucune adresse IP résolue pour %s", domain)

    def notify(name: str, outcome: _Outcome) -> None:
        if on_module is None:
            return
        try:
            on_module(name, outcome.status, outcome.duration)
        except Exception:
            logger.exception("Rappel d'avancement en échec pour le module %s", name)

    try:
        # Les clients de collecte ouverts par les modules (common._http_client,
        # common._api_client) lisent ce proxy ; DNS, WHOIS, ports et sonde TLS restent directs.
        with scan_proxy(options.proxy_url):
            outcomes = await _run_waves(specs, context, notify, options, secrets)
    finally:
        await http.aclose()
        context.shared.close()

    launched_specs = {spec.name: spec for spec in specs}
    every_spec = {**registry.COLUMN_MODULES, **registry.MODULES, **launched_specs}
    # Valeur de chaque module du registre : son résultat, ou la valeur d'un module sans
    # résultat s'il n'a pas été lancé (hors profil).
    values: dict[str, object] = {
        name: outcomes[name].value if name in outcomes else _placeholder(name, None) for name in every_spec
    }
    _finalize(outcomes, values, launched_specs, context)

    module_status = {name: {"status": out.status, "error": out.error} for name, out in outcomes.items()}
    for name, out in outcomes.items():
        if out.status == "ok" and launched_specs[name].status_extras is not None:
            module_status[name].update(
                _extras(name, "status_extras", launched_specs[name].status_extras, out.value)
            )
    # Les modules sans colonne historique : tout est dans `modules`.
    modules = {
        name: {
            "status": out.status,
            "data": out.value,
            "duration": round(out.duration, 3),
            "error": out.error,
        }
        for name, out in outcomes.items()
        if launched_specs[name].column is None
    }

    nxdomain = any(
        out.status == "ok" and spec.nxdomain is not None and _hook(name, "nxdomain", spec.nxdomain, out.value)
        for name, out in outcomes.items()
        for spec in (launched_specs[name],)
    )
    status, error_message = _global_status(
        module_status,
        addresses,
        resolve_timed_out,
        nxdomain,
        http_probes=[name for name, spec in every_spec.items() if spec.http_probe],
        optional=[name for name, spec in every_spec.items() if spec.optional],
    )

    score_data: dict[str, object] = dict(values)
    for name, spec in every_spec.items():
        if spec.score_extras is not None:
            measured = name in outcomes and outcomes[name].status == "ok"
            score_data.update(_extras(name, "score_extras", spec.score_extras, values, measured))
    score_data.update(
        is_ip_target=context.is_ip_target,
        module_status=module_status,
        # Un critère dont le module n'a pas été lancé (profil) n'est pas mesuré :
        # jamais compté comme réussi, et la couverture baisse.
        modules_launched=list(module_status),
    )
    security_score = compute_security_score(score_data)

    duration = (datetime.now(timezone.utc) - started_at).total_seconds()
    logger.info(
        "Scan de %s terminé en %.1fs — statut=%s score=%s/%s (couverture %s%%)",
        domain,
        duration,
        status,
        security_score["score"],
        security_score["max_score"],
        security_score["coverage"],
    )

    result: dict = {"domain": domain, "ip_address": ip_address}
    # Colonnes historiques (ModuleSpec.column) : dns_records…, screenshot_path.
    result.update((spec.column, values[name]) for name, spec in every_spec.items() if spec.column is not None)
    result.update(
        security_score=security_score,
        module_status=module_status,
        modules=modules,
        scan_duration=round(duration, 1),
        status=status,
        error_message=error_message,
    )
    return result


def _scan_secrets(specs: list[ModuleSpec]) -> dict[str, str]:
    """Clés API renseignées, lues seulement si un module du scan en déclare (synchrone : à lancer en thread).

    Une base illisible n'empêche pas le scan : les modules à clé facultative
    tournent sans, ceux à clé requise ont déjà été écartés faute de clé.
    """
    if not any(spec.keys for spec in specs):
        return {}
    try:
        return load_secrets()
    except Exception as e:
        logger.warning("Clés API illisibles (%s) : scan sans clé", type(e).__name__)
        return {}


def _hook(name: str, hook: str, function: Callable, *args) -> object:
    """Appelle un point d'accroche d'un module ; une erreur est journalisée, jamais propagée."""
    try:
        return function(*args)
    except Exception:
        logger.exception("Module %s : %s en échec", name, hook)
        return None


def _extras(name: str, hook: str, function: Callable, *args) -> dict:
    """Champs ajoutés par un point d'accroche : un dict sérialisable en JSON, sinon rien."""
    extras = _hook(name, hook, function, *args)
    if not isinstance(extras, Mapping) or _not_serializable(dict(extras)) is not None:
        if extras is not None:
            logger.error("Module %s : %s doit rendre un dict JSON, ignoré", name, hook)
        return {}
    return dict(extras)


def _finalize(
    outcomes: dict[str, _Outcome],
    values: dict[str, object],
    specs: Mapping[str, ModuleSpec],
    context: ScanContext,
) -> None:
    """Applique ModuleSpec.finalize aux modules réussis, une fois toutes les vagues finies."""
    for name, out in outcomes.items():
        finalize = specs[name].finalize
        if out.status != "ok" or finalize is None:
            continue
        try:
            value = finalize(out.value, MappingProxyType(values), context)
        except Exception:
            logger.exception("Module %s : finalize en échec, résultat gardé tel quel", name)
            continue
        if _not_serializable(value) is not None:
            logger.error("Module %s : finalize rend une valeur non sérialisable, ignorée", name)
            continue
        out.value = values[name] = value
