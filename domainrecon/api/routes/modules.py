# =============================================================================
# DomainRecon - API : catalogue des modules de scan
# =============================================================================
# GET /api/modules décrit chaque module du registre, tel que son ModuleSpec le
# déclare : clé, famille, catégorie, clés API (et si elles sont renseignées),
# vague, dépendances, profil rapide, délai propre, critères du score et textes
# d'aide (titre, ce que le module vérifie, pourquoi c'est important) dans la
# langue de la requête. Le « Comment corriger » d'un module (fix, fix_snippet,
# fix_ref : voir i18n/fix.py) figure dans l'entrée, à côté de `help`, dans trois
# champs absents quand le module ne les renseigne pas. L'interface en tire le
# choix des modules (profil personnalisé), l'écran des clés API et l'aide, sans
# liste recopiée à la main.
# =============================================================================

import logging

from fastapi import APIRouter, Request
from fastapi.concurrency import run_in_threadpool
from pydantic import BaseModel, Field

from ...core.settings_store import load_secrets
from ...i18n import message, render
from ...i18n.fix import fix_texts, is_https_url
from ...scanner import registry
from ..errors import request_lang
from ..schemas import LangQuery

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api", tags=["Modules"])


class ModuleKeyInfo(BaseModel):
    """Identifiant d'un service tiers déclaré par un module (jamais sa valeur)."""

    name: str
    service: str
    label: str
    required: bool
    free_text: bool
    hidden: bool
    # La clé est renseignée dans les Réglages.
    configured: bool


class ModuleCriterion(BaseModel):
    criterion: str
    weight: int


class ModuleHelp(BaseModel):
    title: str
    checks: str
    why: str


class ModuleInfo(BaseModel):
    name: str
    family: str
    category: str
    requires_authorization: bool
    keys: list[ModuleKeyInfo] = Field(default_factory=list)
    # Services dont le module fournit le test de clé (POST /api/settings/test/{service}).
    key_tests: list[str] = Field(default_factory=list)
    wave: int
    depends_on: list[str] = Field(default_factory=list)
    quick: bool
    optional: bool
    # Délai propre, en secondes ; null : délai du profil (Réglages).
    timeout: float | None = None
    criteria: list[ModuleCriterion] = Field(default_factory=list)
    help: ModuleHelp
    # « Comment corriger », dans la langue de la requête ; chaque champ est ABSENT (et non null)
    # quand le module ne le renseigne pas. fix : étapes de correction, une par ligne ("\n") ;
    # fix_snippet : extrait prêt à copier, variantes séparées par une ligne « # nginx », « # Apache »… ;
    # fix_ref : URL https de la documentation officielle.
    fix: str | None = None
    fix_snippet: str | None = None
    fix_ref: str | None = None


class ModulesResponse(BaseModel):
    """Catalogue : modules dans l'ordre d'exécution, familles et catégories connues."""

    modules: list[ModuleInfo]
    families: list[str]
    categories: list[str]
    profiles: list[str]
    # Fichiers de modules écartés au chargement (défaut de déclaration) : noms seulement.
    unavailable: list[str] = Field(default_factory=list)


def _configured_keys() -> frozenset[str]:
    """Noms des clés renseignées ; une base illisible n'empêche pas d'afficher le catalogue."""
    try:
        return frozenset(load_secrets())
    except Exception:
        return frozenset()


def _fix_help(spec: registry.ModuleSpec, lang: str) -> dict[str, str]:
    """« Comment corriger » renseigné du module dans `lang` ; une documentation hors https est écartée."""
    texts = fix_texts(spec.name, lang)
    if "fix_ref" in texts and not is_https_url(texts["fix_ref"]):
        logger.warning("Module %s : fix_ref ignorée (URL https attendue)", spec.name)
        del texts["fix_ref"]
    return texts


def module_info(spec: registry.ModuleSpec, lang: str, configured: frozenset[str]) -> dict:
    """Description publique d'un module, textes rendus dans `lang` ; fix* seulement s'ils sont renseignés."""
    return {
        "name": spec.name,
        "family": spec.family,
        "category": spec.category,
        "requires_authorization": spec.requires_authorization,
        "keys": [
            {
                "name": key.name,
                "service": key.service,
                "label": key.label,
                "required": key.required,
                "free_text": key.free_text,
                "hidden": key.hidden,
                "configured": key.name in configured,
            }
            for key in spec.keys
        ],
        "key_tests": sorted(spec.key_tests),
        "wave": spec.wave,
        "depends_on": list(spec.depends_on),
        "quick": spec.quick,
        "optional": spec.optional,
        "timeout": spec.timeout,
        "criteria": [{"criterion": rule.criterion, "weight": rule.weight} for rule in spec.criteria],
        "help": {part: render(message(code), lang) for part, code in spec.help_codes.items()},
        **_fix_help(spec, lang),
    }


# exclude_unset : un « Comment corriger » non renseigné est absent de l'entrée, pas null.
@router.get("/modules", response_model=ModulesResponse, response_model_exclude_unset=True)
async def list_modules(request: Request, lang: LangQuery = None):
    """Catalogue des modules de scan, dans l'ordre d'exécution, avec leurs textes d'aide et de correction."""
    language = request_lang(request)
    # Lecture de la base hors de la boucle d'événements.
    configured = await run_in_threadpool(_configured_keys)
    return {
        "modules": [module_info(spec, language, configured) for spec in registry.MODULES.values()],
        "families": list(registry.FAMILIES),
        "categories": list(registry.CATEGORIES),
        "profiles": list(registry.PROFILES),
        "unavailable": sorted(registry.BROKEN_MODULES),
    }
