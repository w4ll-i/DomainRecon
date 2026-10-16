# =============================================================================
# DomainRecon - Test de contrat : CHAQUE module découvert respecte le contrat
# =============================================================================
# Paramétré sur le registre réel : un module ajouté (scanner/modules/<clé>.py)
# y passe sans rien modifier ici. Vérifie, pour chacun :
#   - un fichier scanner/modules/<clé>.py en UTF-8 sans BOM, chargé sans défaut ;
#   - famille et catégorie valides, run asynchrone, clés API testables ;
#   - textes FR et EN : aide (titre, ce qu'il vérifie, pourquoi) dans ses
#     fragments i18n/modules/<clé>.<langue>.json, codes de ses constats présents ;
#   - « Comment corriger » (fix, fix_snippet, fix_ref, contrat §9.1) : textes écrits
#     cohérents en FR et EN et conformes à la convention ; la présence de `fix`
#     pour chaque module n'est exigée qu'une fois l'interrupteur activé (ci-dessous) ;
#   - règles valides (gravités, codes, critères uniques) et valeur de repli JSON ;
#   - pour un nouveau module : son fichier de tests tests/scanner/modules/test_<clé>.py,
#     et, hors ligne (réseau coupé, HTTP refusé, DNS NXDOMAIN), une sortie
#     conforme (types JSON, measured/error) ou un échec propre (ModuleError,
#     ModuleSkipped), sans blocage ni clé API recopiée.
# Voir docs/contrat-modules.md.
# =============================================================================

import asyncio
import inspect
import json
import os
from pathlib import Path

import pytest

from domainrecon.api.service_checks import all_services
from domainrecon.core.models import Scan
from domainrecon.i18n import catalog, catalog_fragments, is_msg, msg, placeholders, render
from domainrecon.i18n.fix import fix_pair_problems, fix_problems, fix_texts, is_https_url
from domainrecon.scanner import modules, registry
from domainrecon.scanner.errors import ModuleError, ModuleSkipped, TargetNotAllowedError
from domainrecon.scanner.registry import HELP_PARTS
from domainrecon.scanner.rules import SEVERITIES

ALL_MODULES = list(registry.MODULES)
# Modules ajoutés depuis les 18 historiques (sans colonne dédiée).
NEW_MODULES = [name for name, spec in registry.MODULES.items() if spec.column is None]

# Interrupteur du « Comment corriger » : à True, CHAQUE module doit avoir `module.<clé>.fix` en FR et
# en EN (test_conseil_de_correction_obligatoire). Activé depuis que les 84 modules ont leurs textes : un
# module ajouté sans `fix` fait échouer la suite. À False, seule la cohérence des textes déjà écrits serait
# vérifiée ; DOMAINRECON_EXIGER_CONSEILS=1 rétablit alors l'exigence sans modifier ce fichier.
EXIGER_CONSEILS_DE_CORRECTION = True
_CONSEILS_EXIGES = EXIGER_CONSEILS_DE_CORRECTION or os.environ.get("DOMAINRECON_EXIGER_CONSEILS") == "1"

MODULES_DIR = Path(modules.__file__).parent
TESTS_DIR = Path(__file__).parent
SCAN_COLUMNS = {attr.key for attr in Scan.__mapper__.column_attrs}


def test_aucun_fichier_de_module_ecarte():
    """Un fichier défectueux est écarté au chargement (l'application démarre sans lui) : ici, il fait échouer."""
    assert registry.BROKEN_MODULES == {}


def test_un_fichier_par_module_et_un_module_par_fichier():
    assert set(modules.module_files()) == set(registry.MODULES)


def test_registre_coherent():
    assert registry.registry_problems() == {}


@pytest.mark.parametrize("name", ALL_MODULES)
def test_declaration(name):
    spec = registry.MODULES[name]
    source = MODULES_DIR / f"{name}.py"
    assert source.is_file()
    assert not source.read_bytes().startswith(b"\xef\xbb\xbf"), "fichier en UTF-8 SANS BOM"
    assert spec.family in registry.FAMILIES
    assert spec.category in registry.CATEGORIES
    assert inspect.iscoroutinefunction(spec.run), "run doit être une coroutine (async def)"
    assert spec.timeout is None or 0 < spec.timeout <= registry.MAX_TIMEOUT
    if spec.category == registry.CATEGORY_API_KEY:
        assert spec.required_keys
    if spec.quick:
        assert spec.category == registry.CATEGORY_PASSIVE
    # Colonne dédiée : réservée aux 18 modules historiques (colonnes existantes de la table scans).
    assert spec.column is None or spec.column in SCAN_COLUMNS


@pytest.mark.parametrize("name", ALL_MODULES)
def test_textes_fr_et_en(name):
    spec = registry.MODULES[name]
    for lang in ("fr", "en"):
        fragment = catalog_fragments(lang).get(name)
        assert fragment, f"fragment i18n/modules/{name}.{lang}.json absent ou vide"
        for part in HELP_PARTS:
            code = spec.help_codes[part]
            assert fragment.get(code, "").strip(), f"{code} absent de {name}.{lang}.json"
        for rule in spec.findings:
            assert rule.code in catalog(lang), f"{rule.code} absent du catalogue {lang}"
    # Mêmes paramètres dans les deux langues pour les messages des constats.
    for rule in spec.findings:
        assert placeholders(catalog("fr")[rule.code]) == placeholders(catalog("en")[rule.code]), rule.code


@pytest.mark.parametrize("name", ALL_MODULES)
def test_conseil_de_correction_coherent(name):
    """Le « Comment corriger » déjà écrit d'un module est cohérent (contrat §9.1), complet ou non :

    - si `fix` existe en FR il existe en EN, et inversement (de même `fix_snippet` et `fix_ref`) ;
    - `fix_ref` est une URL https ;
    - forme des textes (étapes, variantes d'extrait, bornes), mêmes étapes et mêmes variantes en FR et EN.
    """
    fr, en = (fix_texts(name, lang, fallback=False) for lang in ("fr", "en"))
    assert set(fr) == set(en), f"{name} : {sorted(set(fr) ^ set(en))} renseigné dans une seule langue"
    for lang, textes in (("fr", fr), ("en", en)):
        if "fix_ref" in textes:
            assert is_https_url(textes["fix_ref"]), f"{name}.{lang}.json : fix_ref doit être une URL https"
        problemes = fix_problems(textes)
        assert not problemes, f"{name}.{lang}.json : " + " ; ".join(problemes)
    problemes = fix_pair_problems(fr, en)
    assert not problemes, f"{name} : " + " ; ".join(problemes)


# Tous les modules si l'interrupteur est activé ; sinon un cas unique, ignoré, qui rappelle pourquoi.
_MODULES_A_EXIGER = (
    ALL_MODULES
    if _CONSEILS_EXIGES
    else [
        pytest.param(
            "",
            id="interrupteur-desactive",
            marks=pytest.mark.skip(
                reason="EXIGER_CONSEILS_DE_CORRECTION désactivé : à activer quand tous les modules ont leur fix"
            ),
        )
    ]
)


@pytest.mark.parametrize("name", _MODULES_A_EXIGER)
def test_conseil_de_correction_obligatoire(name):
    """Interrupteur activé : chaque module a ses étapes de correction (`module.<clé>.fix`) en FR et en EN."""
    for lang in ("fr", "en"):
        assert "fix" in fix_texts(name, lang, fallback=False), (
            f"{registry.MODULES[name].fix_codes['fix']} absent de i18n/modules/{name}.{lang}.json (contrat §9.1)"
        )


@pytest.mark.parametrize("name", ALL_MODULES)
def test_regles(name):
    spec = registry.MODULES[name]
    for rule in spec.findings:
        assert rule.severity in SEVERITIES and callable(rule.check)
    for rule in spec.criteria:
        assert isinstance(rule.weight, int) and 0 < rule.weight <= 100
    criteria = [rule.criterion for other in registry.MODULES.values() for rule in other.criteria]
    assert len(criteria) == len(set(criteria)), "critère de score déclaré par deux modules"


@pytest.mark.parametrize("name", ALL_MODULES)
def test_cles_api_testables(name):
    """Chaque clé déclarée appartient à un service testable (SERVICES ou KeyTest fourni par un module)."""
    services = all_services()
    for key in registry.MODULES[name].keys:
        assert key.service in services, f"aucun test de clé pour le service {key.service}"
    for service, test in registry.MODULES[name].key_tests.items():
        assert services[service] is test or service in services


@pytest.mark.parametrize("name", ALL_MODULES)
def test_valeur_de_repli_serialisable(name):
    spec = registry.MODULES[name]
    for error in (None, msg("orchestrator.module_failed"), "texte"):
        json.dumps(spec.placeholder(error))


@pytest.mark.parametrize("name", NEW_MODULES)
def test_fichier_de_tests_du_module(name):
    assert (TESTS_DIR / f"test_{name}.py").is_file(), f"tests/scanner/modules/test_{name}.py manquant"


@pytest.mark.parametrize("name", NEW_MODULES)
def test_hors_ligne_le_module_echoue_proprement(name, contexte, http_simule, dns_simule, reseau_coupe):
    spec = registry.MODULES[name]
    http_simule({})
    dns_simule({})
    secrets = {key: f"cle-secrete-de-test-{key}-0123456789" for key in spec.key_names}
    context = contexte(secrets=secrets)
    reason = spec.skip_reason(context)
    if reason is not None:
        assert is_msg(reason) or isinstance(reason, str)
        return
    timeout = min(spec.timeout or registry.DEFAULT_TIMEOUT, 30)
    try:
        value = asyncio.run(asyncio.wait_for(spec.run(context), timeout=timeout))
    except (ModuleError, ModuleSkipped, TargetNotAllowedError) as error:
        text = json.dumps(render(error.message, "fr"), ensure_ascii=False)
        assert not any(secret in text for secret in secrets.values()), "clé API dans le message"
    except (asyncio.TimeoutError, TimeoutError):
        pytest.fail(f"{name} bloque hors ligne au-delà de {timeout} s : borner ses attentes")
    else:
        json.dumps(value)
        text = json.dumps(render(value, "fr"), ensure_ascii=False)
        assert not any(secret in text for secret in secrets.values()), "clé API dans le résultat"
        if isinstance(value, dict):
            assert isinstance(value.get("measured"), bool) and "error" in value
    # Les accès réseau réels refusés font partie de l'épreuve (module à sockets) : pas une faute ici.
    reseau_coupe.clear()
