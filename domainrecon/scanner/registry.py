# =============================================================================
# DomainRecon - Scanner : registre des modules
# =============================================================================
# Un module de scan = UN fichier domainrecon/scanner/modules/<clé>.py qui
# définit `SPEC = ModuleSpec(...)` (register() est facultatif). Le package
# modules/ découvre et importe seul tous ses fichiers : aucune liste centrale à
# compléter. Tout ce que le reste de l'application sait d'un module vient de ce
# ModuleSpec : famille, constats, score, clés API, catalogue de l'interface.
# Les textes du module (titre, aide, messages) vont dans ses fragments de
# catalogue domainrecon/i18n/modules/<clé>.fr.json et <clé>.en.json, avec son
# « Comment corriger » (fix, fix_snippet, fix_ref : voir i18n/fix.py).
#
# Procédure complète et règles : docs/contrat-modules.md.
#
# Champs d'un ModuleSpec (voir la classe) :
#   - name, family, category, run : clé, famille de l'écran « Résultat »,
#     catégorie (passif | actif | cle_api | sensible) et coroutine run(contexte) ;
#   - keys, key_tests : identifiants de services tiers (ApiKey, requis ou
#     facultatifs) et tests de clé (KeyTest) ; `api_key` (un nom) reste accepté ;
#   - wave, depends_on, timeout, skip_reason, quick, optional, order : exécution ;
#   - findings, score_rules, verdict : constats, critères du score, poids du
#     module dans le verdict de sa famille ;
#   - http_probe, finalize, status_extras, score_extras, nxdomain, column,
#     placeholder, legacy_measured : points d'accroche des 18 modules
#     historiques (inutiles à un nouveau module).
#
# Importer ce fichier charge aussi domainrecon.scanner.modules (voir la fin) :
# MODULES contient alors tous les modules.
# =============================================================================

import logging
import re
from collections.abc import Awaitable, Callable, Iterable, Mapping
from dataclasses import dataclass, field
from types import MappingProxyType

import httpx

from ..i18n import msg
from ..i18n.fix import fix_codes as _fix_codes
from .common import logger as _scanner_logger
from .keys import ApiKey, KeyTest
from .page import HomePage, SharedScanState
from .rules import FindingRule, PenaltyRule, ScoreRule
from .targets import is_ip_literal, primary_address

# Familles de l'écran « Résultat » (families.FAMILY_KEYS) : la 8e, « leaks »
# (fuites de données : identifiants, dépôts de code, documents exposés), suit
# la réputation.
FAMILIES = ("web", "tls", "email", "dns", "network", "identity", "reputation", "leaks")
CATEGORY_PASSIVE = "passif"
CATEGORY_ACTIVE = "actif"
CATEGORY_API_KEY = "cle_api"
CATEGORY_SENSITIVE = "sensible"
CATEGORIES = (CATEGORY_PASSIVE, CATEGORY_ACTIVE, CATEGORY_API_KEY, CATEGORY_SENSITIVE)
# Ancien nom de la catégorie à clé, encore accepté (ramené à « cle_api »).
_CATEGORY_ALIASES = {"api_key": CATEGORY_API_KEY}
WAVES = (1, 2, 3)

# Catégories dont les modules exigent l'autorisation de tester la cible.
AUTHORIZATION_CATEGORIES = frozenset({CATEGORY_ACTIVE, CATEGORY_SENSITIVE})

# Profils de scan : modules passifs essentiels (rapide), tous les modules passifs
# et ceux dont la clé API est renseignée (complet), choix module par module
# (personnalise).
PROFILE_QUICK = "rapide"
PROFILE_FULL = "complet"
PROFILE_CUSTOM = "personnalise"
PROFILES = (PROFILE_QUICK, PROFILE_FULL, PROFILE_CUSTOM)

# Délai par défaut d'un module, en secondes, quand les Réglages n'en donnent pas
# (orchestrator.MODULE_TIMEOUT). Un module sans délai propre (timeout=None) prend
# celui du profil (Réglages : scan_timeout, quick_timeout).
DEFAULT_TIMEOUT = 60
# Délai propre maximal d'un module, en secondes.
MAX_TIMEOUT = 900

# Ordre d'un module sans ordre déclaré : après les 18 historiques, puis par nom.
DEFAULT_ORDER = 1000

_NAME_RE = re.compile(r"[a-z][a-z0-9_]*")
# Noms réservés : champs du résultat d'un scan, qu'une clé de module masquerait.
RESERVED_NAMES = frozenset(
    {
        "id",
        "domain",
        "ip_address",
        "status",
        "notes",
        "tags",
        "profile",
        "modules",
        "modules_launched",
        "module_status",
        "security_score",
        "scan_duration",
        "scan_timestamp",
        "screenshot_path",
        "error_message",
        "families",
        "findings",
    }
)


# =============================================================================
# Contexte d'un scan
# =============================================================================


@dataclass
class ScanContext:
    """Ce que le scan met à la disposition d'un module (argument de ModuleSpec.run).

    - domain : cible normalisée (nom d'hôte ou adresse IP littérale) ;
    - apex, site : domaine enregistrable (WHOIS, DKIM…) et domaine du site
      (journaux CT, sous-domaines) ; par défaut, la cible ;
    - addresses : adresses de la cible validées par la politique de cibles ;
    - results : résultat des modules déjà terminés avec succès, par nom. Un
      module en échec, hors délai ou sans objet n'y figure pas : un module qui
      en dépend (depends_on) le voit absent ;
    - proxy, http : proxy sortant du scan (Réglages ou environnement, lu une
      fois au départ ; None : aucun) et client HTTP partagé des API tierces qui
      l'emprunte (TLS vérifié, redirections non suivies, anti-SSRF). Pour la
      cible elle-même : common._http_client(). Le DNS, le WHOIS, le scan de
      ports et la sonde TLS restent directs ;
    - secrets : valeurs des clés API que le module a déclarées (ModuleSpec.keys)
      et que l'utilisateur a renseignées, par nom. Jamais dans un message, un
      journal ni un résultat ;
    - logger : journal du scanner ;
    - homepage() : page d'accueil de la cible, récupérée une seule fois par scan
      et partagée par tous les modules (voir page.py).
    """

    domain: str
    apex: str = ""
    site: str = ""
    addresses: list[str] = field(default_factory=list)
    results: dict[str, object] = field(default_factory=dict)
    # Peut porter des identifiants : absent de repr(), jamais journalisé.
    proxy: str | None = field(default=None, repr=False)
    http: httpx.AsyncClient | None = None
    logger: logging.Logger = _scanner_logger
    secrets: Mapping[str, str] = field(default_factory=lambda: MappingProxyType({}), repr=False)
    # État partagé du scan (page d'accueil) : copié par référence entre les contextes des modules.
    shared: SharedScanState = field(default_factory=SharedScanState, repr=False, compare=False)

    def __post_init__(self) -> None:
        self.apex = self.apex or self.domain
        self.site = self.site or self.domain

    @property
    def ip_address(self) -> str | None:
        """Adresse principale de la cible (première IPv4, sinon première IPv6)."""
        return primary_address(self.addresses)

    @property
    def is_ip_target(self) -> bool:
        """La cible est une adresse IP littérale."""
        return is_ip_literal(self.domain)

    @property
    def shared_platform(self) -> bool:
        """La cible est hébergée sur une plateforme mutualisée (suffixe privé de la PSL)."""
        return self.site != self.apex

    async def homepage(self) -> HomePage:
        """Page d'accueil de la cible (https, sinon http), une seule requête par scan."""
        return await self.shared.homepage(self.domain)


RunFunction = Callable[[ScanContext], Awaitable[object]]
SkipFunction = Callable[[ScanContext], object | None]


# Raisons usuelles de ne pas lancer un module (`ModuleSpec.skip_reason`).


def no_skip(context: ScanContext) -> None:
    """Module qui s'applique à toute cible."""
    return None


def skip_for_ip_target(context: ScanContext) -> object | None:
    """Module sans objet pour une adresse IP littérale (DNS, WHOIS, sous-domaines…)."""
    return msg("orchestrator.skip_ip_target") if context.is_ip_target else None


def skip_without_address(context: ScanContext) -> object | None:
    """Module qui travaille sur l'adresse IP de la cible, absente si elle n'a pas résolu."""
    return None if context.ip_address else msg("orchestrator.no_address")


def default_placeholder(error: object) -> dict:
    """Valeur enregistrée d'un module sans résultat exploitable (échec, sans objet, non lancé)."""
    return {"measured": False, "error": error}


# =============================================================================
# Description d'un module
# =============================================================================


@dataclass(frozen=True, kw_only=True)
class ModuleSpec:
    """Déclaration d'un module de scan (voir l'en-tête de ce fichier et docs/contrat-modules.md)."""

    # --- Identité --------------------------------------------------------------
    # Clé du module : nom du fichier, de module_status et des textes i18n.
    name: str
    family: str
    # passif | actif | cle_api | sensible (« api_key » accepté). Un module actif ou
    # sensible n'est lancé qu'avec l'autorisation de tester la cible.
    category: str
    # Coroutine run(contexte) -> dict JSON (avec `measured` et `error`) ; voir orchestrator.py.
    run: RunFunction

    # --- Clés API ----------------------------------------------------------------
    # Ancienne forme : nom d'UNE clé requise (équivaut à keys=(ApiKey(name=..., required=True),)).
    api_key: str | None = None
    # Identifiants de services tiers, requis ou facultatifs (ApiKey).
    keys: tuple[ApiKey, ...] = ()
    # Tests de clé fournis par le module : {service: KeyTest} (POST /api/settings/test/{service}).
    key_tests: Mapping[str, KeyTest] = field(default_factory=dict, hash=False, compare=False)

    # --- Exécution -----------------------------------------------------------------
    wave: int = 1
    depends_on: tuple[str, ...] = ()
    # Délai propre, en secondes (jamais écrasé par le plafond des Réglages) ;
    # None : délai du profil (Réglages scan_timeout / quick_timeout, défaut 60 s).
    timeout: float | None = None
    skip_reason: SkipFunction = no_skip
    # Fait partie du profil « rapide » (modules passifs seulement).
    quick: bool = False
    # Facultatif : son échec ne dégrade pas le statut global du scan (service tiers capricieux).
    optional: bool = False
    # Ordre d'exécution dans la vague et d'affichage (puis le nom) ; les 18 historiques : 10 à 180.
    order: int = DEFAULT_ORDER

    # --- Constats, score, famille ---------------------------------------------------
    findings: tuple[FindingRule, ...] = ()
    score_rules: tuple[ScoreRule | PenaltyRule, ...] = ()
    # Son échec ou son absence, faute de note et de constat, rend sa famille « non mesurée ».
    verdict: bool = False

    # --- Points d'accroche (modules historiques) -------------------------------------
    # Un résultat « ok » prouve que la cible répond en HTTP (statut global du scan).
    http_probe: bool = False
    # Après toutes les vagues : finalize(valeur, valeurs de tous les modules, contexte) -> valeur.
    finalize: Callable[[object, Mapping[str, object], ScanContext], object] | None = None
    # Champs ajoutés à module_status[nom] quand le module a réussi : status_extras(valeur) -> dict.
    status_extras: Callable[[object], Mapping[str, object]] | None = None
    # Entrées ajoutées aux données du score : score_extras(valeurs, mesuré) -> dict (appelé
    # pour chaque module du registre, lancé ou non ; mesuré : statut « ok »).
    score_extras: Callable[[Mapping[str, object], bool], Mapping[str, object]] | None = None
    # Le résultat établit que le domaine n'existe pas (NXDOMAIN) : nxdomain(valeur) -> bool.
    nxdomain: Callable[[object], bool] | None = None
    # Colonne historique du résultat (18 premiers modules) ; None : colonne générique `modules`.
    column: str | None = None
    # Valeur enregistrée sans résultat exploitable : placeholder(erreur) ; défaut {measured: False, error}.
    placeholder: Callable[[object], object] = default_placeholder
    # Scan antérieur à module_status : le résultat enregistré est-il une mesure ? (scan, valeur) -> bool.
    legacy_measured: Callable[[dict, object], bool] | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.name, str) or not _NAME_RE.fullmatch(self.name):
            raise ValueError(f"Nom de module invalide : {self.name!r} (minuscules, chiffres et « _ »)")
        if self.name in RESERVED_NAMES:
            raise ValueError(f"Nom de module réservé (champ du résultat d'un scan) : {self.name}")
        if self.family not in FAMILIES:
            raise ValueError(f"Module {self.name} : famille inconnue {self.family!r} ({', '.join(FAMILIES)})")
        category = _CATEGORY_ALIASES.get(self.category, self.category)
        if category not in CATEGORIES:
            raise ValueError(
                f"Module {self.name} : catégorie inconnue {self.category!r} ({', '.join(CATEGORIES)})"
            )
        object.__setattr__(self, "category", category)
        if self.api_key is not None and (not isinstance(self.api_key, str) or not self.api_key):
            raise ValueError(f"Module {self.name} : nom de clé API invalide ({self.api_key!r})")
        self._check_keys()
        if category == CATEGORY_API_KEY and not self.required_keys:
            raise ValueError(f"Module {self.name} : la catégorie cle_api exige au moins une clé requise")
        if self.quick and category != CATEGORY_PASSIVE:
            raise ValueError(f"Module {self.name} : seul un module passif peut être du profil rapide")
        if type(self.wave) is not int or self.wave not in WAVES:
            raise ValueError(f"Module {self.name} : vague {self.wave!r} invalide (1, 2 ou 3)")
        if isinstance(self.depends_on, str):
            raise ValueError(f"Module {self.name} : depends_on est un tuple de noms, pas un texte")
        # Un tuple, même si l'appelant a passé une liste : le module est immuable.
        object.__setattr__(self, "depends_on", tuple(self.depends_on))
        if self.name in self.depends_on:
            raise ValueError(f"Module {self.name} : dépend de lui-même")
        if self.timeout is not None and (
            isinstance(self.timeout, bool)
            or not isinstance(self.timeout, (int, float))
            or not 0 < self.timeout <= MAX_TIMEOUT
        ):
            raise ValueError(f"Module {self.name} : délai invalide ({self.timeout!r} s, 0 à {MAX_TIMEOUT})")
        if not callable(self.run) or not callable(self.skip_reason) or not callable(self.placeholder):
            raise ValueError(f"Module {self.name} : run, skip_reason et placeholder doivent être appelables")
        for hook in ("finalize", "status_extras", "score_extras", "nxdomain", "legacy_measured"):
            value = getattr(self, hook)
            if value is not None and not callable(value):
                raise ValueError(f"Module {self.name} : {hook} doit être appelable")
        if type(self.order) is not int:
            raise ValueError(f"Module {self.name} : ordre invalide ({self.order!r})")
        for flag in ("quick", "optional", "verdict", "http_probe"):
            if not isinstance(getattr(self, flag), bool):
                raise ValueError(f"Module {self.name} : {flag} est un booléen")
        self._check_rules()

    def _check_keys(self) -> None:
        if isinstance(self.keys, ApiKey):
            raise ValueError(f"Module {self.name} : keys est un tuple d'ApiKey")
        keys = tuple(self.keys)
        if not all(isinstance(key, ApiKey) for key in keys):
            raise ValueError(f"Module {self.name} : keys ne contient que des ApiKey")
        if self.api_key is not None and self.api_key not in {key.name for key in keys}:
            keys = (*keys, ApiKey(name=self.api_key, service=_service_name(self.api_key), label=self.api_key))
        names = [key.name for key in keys]
        if len(names) != len(set(names)):
            raise ValueError(f"Module {self.name} : clé API déclarée deux fois")
        object.__setattr__(self, "keys", keys)
        if not isinstance(self.key_tests, Mapping):
            raise ValueError(f"Module {self.name} : key_tests est un dict {{service: KeyTest}}")
        tests = dict(self.key_tests)
        for service, test in tests.items():
            if not isinstance(test, KeyTest) or not isinstance(service, str):
                raise ValueError(f"Module {self.name} : key_tests[{service!r}] doit être un KeyTest")
            if unknown := set(test.fields) - set(names):
                raise ValueError(
                    f"Module {self.name} : test {service} sur des clés non déclarées {sorted(unknown)}"
                )
        object.__setattr__(self, "key_tests", MappingProxyType(tests))

    def _check_rules(self) -> None:
        for attr, kinds in (("findings", (FindingRule,)), ("score_rules", (ScoreRule, PenaltyRule))):
            rules = getattr(self, attr)
            if isinstance(rules, (str, bytes)) or not isinstance(rules, Iterable):
                raise ValueError(f"Module {self.name} : {attr} est un tuple de règles")
            rules = tuple(rules)
            if not all(isinstance(rule, kinds) for rule in rules):
                raise ValueError(f"Module {self.name} : {attr} contient un élément qui n'est pas une règle")
            object.__setattr__(self, attr, rules)
        criteria = [rule.criterion for rule in self.score_rules if isinstance(rule, ScoreRule)]
        if len(criteria) != len(set(criteria)):
            raise ValueError(f"Module {self.name} : critère de score déclaré deux fois")

    # --- Propriétés dérivées -----------------------------------------------------

    @property
    def requires_authorization(self) -> bool:
        """Module actif ou sensible : exige l'autorisation de tester la cible."""
        return self.category in AUTHORIZATION_CATEGORIES

    @property
    def required_keys(self) -> tuple[str, ...]:
        """Noms des clés sans lesquelles le module n'est pas lancé."""
        return tuple(key.name for key in self.keys if key.required)

    @property
    def optional_keys(self) -> tuple[str, ...]:
        """Noms des clés facultatives (le module tourne sans)."""
        return tuple(key.name for key in self.keys if not key.required)

    @property
    def key_names(self) -> tuple[str, ...]:
        return tuple(key.name for key in self.keys)

    @property
    def criteria(self) -> tuple[ScoreRule, ...]:
        """Critères du barème apportés par le module."""
        return tuple(rule for rule in self.score_rules if isinstance(rule, ScoreRule))

    @property
    def penalties(self) -> tuple[PenaltyRule, ...]:
        return tuple(rule for rule in self.score_rules if isinstance(rule, PenaltyRule))

    @property
    def help_codes(self) -> dict[str, str]:
        """Codes i18n de l'aide du module (fragments i18n/modules/<clé>.<langue>.json)."""
        return {part: f"module.{self.name}.{part}" for part in HELP_PARTS}

    @property
    def fix_codes(self) -> dict[str, str]:
        """Codes i18n du « Comment corriger » : étapes, extrait à copier, documentation (facultatifs).

        Mêmes fragments que l'aide ; textes littéraux (i18n/fix.py), jamais des gabarits.
        """
        return _fix_codes(self.name)


# Parties de l'aide d'un module : titre, ce que le module vérifie, pourquoi c'est important.
HELP_PARTS = ("title", "checks", "why")


def _service_name(value: str) -> str:
    """Service d'une clé donnée par `api_key` : son nom sans le suffixe _key / _token."""
    for suffix in ("_key", "_token", "_secret"):
        if value.endswith(suffix) and len(value) > len(suffix) + 1:
            return value[: -len(suffix)]
    return value


# =============================================================================
# Registre
# =============================================================================

# Modules enregistrés, dans l'ordre d'exécution (ordre déclaré, puis nom).
MODULES: dict[str, ModuleSpec] = {}

# Modules à colonne historique (ModuleSpec.column : les 18 premiers), relevés à la
# découverte des modules : le résultat d'un scan garde toujours leurs colonnes, même
# quand le registre est remplacé (tests) ou qu'ils ne sont pas lancés.
COLUMN_MODULES: dict[str, ModuleSpec] = {}

# Fichiers de modules écartés au chargement (import en échec, déclaration
# invalide, dépendance incohérente) : nom -> raison. L'application démarre sans
# eux ; le test de contrat (tests/scanner/test_contrat_modules.py) exige qu'il soit vide.
BROKEN_MODULES: dict[str, str] = {}


def register(spec: ModuleSpec) -> ModuleSpec:
    """Enregistre un module (une seule fois par nom) et le renvoie."""
    if not isinstance(spec, ModuleSpec):
        raise ValueError(f"register() attend un ModuleSpec, pas {type(spec).__name__}")
    if spec.name in MODULES:
        raise ValueError(f"Module déjà enregistré : {spec.name}")
    MODULES[spec.name] = spec
    return spec


def sort_registry() -> None:
    """Range le registre dans l'ordre d'exécution : ordre déclaré, puis nom."""
    ordered = sorted(MODULES.values(), key=lambda spec: (spec.order, spec.name))
    MODULES.clear()
    MODULES.update((spec.name, spec) for spec in ordered)


def registry_problems() -> dict[str, str]:
    """Défauts de cohérence du registre, par module (vide : registre sain).

    Dépendance inconnue, d'une vague plus tardive ou hors profil rapide pour un
    module rapide, cycle, clé API déclarée différemment par deux modules, critère
    de score ou service de test de clé revendiqué deux fois.
    """
    problems: dict[str, str] = {}
    for spec in MODULES.values():
        for name in spec.depends_on:
            dependency = MODULES.get(name)
            if dependency is None:
                problems.setdefault(spec.name, f"Module {spec.name} : dépendance inconnue {name!r}")
            elif dependency.wave > spec.wave:
                problems.setdefault(
                    spec.name,
                    f"Module {spec.name} (vague {spec.wave}) dépend de {name} (vague {dependency.wave})",
                )
            elif spec.quick and not dependency.quick:
                problems.setdefault(
                    spec.name, f"Module rapide {spec.name} : sa dépendance {name} ne l'est pas"
                )

    done: set[str] = set()

    def visit(name: str, path: tuple[str, ...]) -> None:
        if name in path:
            cycle = path[path.index(name) :]
            for member in cycle:
                problems.setdefault(member, f"Cycle de dépendances : {' -> '.join((*cycle, name))}")
            return
        if name in done or name not in MODULES:
            return
        for dependency in MODULES[name].depends_on:
            visit(dependency, (*path, name))
        done.add(name)

    for name in MODULES:
        visit(name, ())

    keys: dict[str, tuple[str, ApiKey]] = {}
    criteria: dict[str, str] = {}
    services: dict[str, str] = {}
    for spec in MODULES.values():
        for key in spec.keys:
            first = keys.setdefault(key.name, (spec.name, key))
            if not first[1].same_definition(key):
                problems.setdefault(
                    spec.name, f"Module {spec.name} : clé {key.name} déclarée autrement par {first[0]}"
                )
        for rule in spec.criteria:
            owner = criteria.setdefault(rule.criterion, spec.name)
            if owner != spec.name:
                problems.setdefault(
                    spec.name, f"Module {spec.name} : critère {rule.criterion} déjà pris par {owner}"
                )
        for service in spec.key_tests:
            owner = services.setdefault(service, spec.name)
            if owner != spec.name and spec.key_tests[service] != MODULES[owner].key_tests[service]:
                problems.setdefault(
                    spec.name, f"Module {spec.name} : test de clé {service} déjà fourni par {owner}"
                )
    return problems


def validate_registry() -> None:
    """Vérifie la cohérence du registre (voir registry_problems) ; lève ValueError au premier défaut."""
    problems = registry_problems()
    if problems:
        raise ValueError(next(iter(problems.values())))


def prune_registry() -> dict[str, str]:
    """Écarte du registre les modules incohérents (et ceux qui en dépendent) ; renvoie les écartés."""
    removed: dict[str, str] = {}
    while problems := registry_problems():
        for name, reason in problems.items():
            removed[name] = reason
            MODULES.pop(name, None)
    return removed


def declared_keys() -> dict[str, ApiKey]:
    """Clés API déclarées par les modules du registre, par nom (première déclaration)."""
    keys: dict[str, ApiKey] = {}
    for spec in MODULES.values():
        for key in spec.keys:
            keys.setdefault(key.name, key)
    return keys


def _in_profile(spec: ModuleSpec, profile: str, keys: frozenset[str], authorized: bool) -> bool:
    """Le module peut-il tourner dans ce profil, avec ces clés et cette autorisation ?"""
    if not set(spec.required_keys) <= keys:
        return False
    if spec.requires_authorization and not authorized:
        return False
    if profile == PROFILE_QUICK:
        return spec.category == CATEGORY_PASSIVE and spec.quick
    if profile == PROFILE_FULL:
        return spec.category in (CATEGORY_PASSIVE, CATEGORY_API_KEY)
    return True


def get_modules(
    profile: str,
    available_keys: Iterable[str] = (),
    authorized: bool = False,
    selected: Iterable[str] | None = None,
) -> list[ModuleSpec]:
    """Modules à lancer pour un profil, dans l'ordre d'exécution (vague, puis ordre du registre).

    - rapide : modules passifs marqués `quick` ;
    - complet : tous les modules passifs, et ceux à clé API dont les clés
      requises sont dans `available_keys` ; les modules actifs et sensibles n'en
      font pas partie ;
    - personnalise : les modules de `selected` (ValueError si l'un est
      inconnu), plus leurs dépendances. `selected` est ignoré des autres profils.

    Quel que soit le profil, un module n'est retenu que si toutes ses clés API
    requises sont dans `available_keys` et, s'il est actif ou sensible, que si
    `authorized` est vrai : les autres sont écartés sans erreur (voir
    ModuleSpec.requires_authorization pour les signaler à l'utilisateur). Un
    module dont une dépendance ne peut pas tourner (clé absente, autorisation
    refusée, hors profil) est écarté à son tour.
    """
    if profile not in PROFILES:
        raise ValueError(f"Profil inconnu : {profile!r} ({', '.join(PROFILES)})")
    requested = list(selected or ()) if profile == PROFILE_CUSTOM else []
    if unknown := sorted(set(requested) - MODULES.keys()):
        raise ValueError(f"Modules inconnus : {', '.join(unknown)}")
    keys = frozenset(available_keys or ())

    # Modules que le profil permet de lancer, puis ceux dont les dépendances le permettent aussi.
    pool = {name: spec for name, spec in MODULES.items() if _in_profile(spec, profile, keys, authorized)}
    while broken := [name for name, spec in pool.items() if any(d not in pool for d in spec.depends_on)]:
        for name in broken:
            del pool[name]

    if profile == PROFILE_CUSTOM:
        # La sélection et ses dépendances (présentes dans `pool`, sinon le module est déjà écarté).
        wanted = {name for name in requested if name in pool}
        pending = list(wanted)
        while pending:
            for dependency in pool[pending.pop()].depends_on:
                if dependency not in wanted:
                    wanted.add(dependency)
                    pending.append(dependency)
    else:
        wanted = set(pool)

    order = {name: index for index, name in enumerate(MODULES)}
    return sorted((pool[name] for name in wanted), key=lambda spec: (spec.wave, spec.order, order[spec.name]))


# Les modules s'enregistrent à l'import de leur package : placé ici, après les
# définitions dont leurs fichiers ont besoin, pour que MODULES soit rempli dès
# que ce fichier est importé (quel que soit celui des deux importé en premier).
from . import modules  # noqa: E402, F401
