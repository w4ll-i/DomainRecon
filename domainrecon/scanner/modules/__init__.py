# =============================================================================
# DomainRecon - Scanner : modules de scan, un fichier par module
# =============================================================================
# Découverte automatique : chaque fichier <clé>.py de ce dossier (hors fichiers
# commençant par « _ ») est importé, et son `SPEC` (ModuleSpec) enregistré dans
# registry.MODULES. Ajouter un module = créer son fichier, rien d'autre ici.
#
# Le registre est ensuite rangé dans l'ordre d'exécution (ModuleSpec.order, puis
# le nom) : les 18 modules historiques gardent leur ordre (celui de module_status).
#
# Un fichier défectueux (import en échec, SPEC absent ou invalide, nom différent
# du fichier, dépendance incohérente) est écarté avec une erreur au journal et
# noté dans registry.BROKEN_MODULES : l'application démarre sans lui, et le test
# de contrat des modules échoue tant qu'il n'est pas corrigé.
# =============================================================================

import importlib
import logging
import pkgutil

from .. import registry

logger = logging.getLogger(__name__)


def _load(name: str, package: str = __name__) -> None:
    """Importe le fichier d'un module et enregistre son SPEC ; en cas de défaut, le note dans BROKEN_MODULES."""
    try:
        module = importlib.import_module(f"{package}.{name}")
        spec = getattr(module, "SPEC", None)
        if not isinstance(spec, registry.ModuleSpec):
            raise ValueError(f"modules/{name}.py ne définit pas SPEC = ModuleSpec(...)")
        if spec.name != name:
            raise ValueError(
                f"modules/{name}.py déclare le module {spec.name!r} : le nom doit être celui du fichier"
            )
        if registry.MODULES.get(name) is not spec:
            registry.register(spec)
    except Exception as e:
        registry.BROKEN_MODULES[name] = f"{type(e).__name__}: {e}"
        registry.MODULES.pop(name, None)
        logger.error("Module de scan %s écarté : %s", name, registry.BROKEN_MODULES[name])


def module_files(path=None) -> list[str]:
    """Noms des fichiers de modules d'un dossier (ce package par défaut), hors fichiers « _* »."""
    found = pkgutil.iter_modules(__path__ if path is None else path)
    return sorted(info.name for info in found if not info.name.startswith("_") and not info.ispkg)


def discover(path=None, package: str = __name__) -> list[str]:
    """Charge tous les fichiers de modules du dossier ; renvoie leurs noms (écartés compris).

    Puis range le registre, en écarte les modules incohérents (dépendance
    inconnue, cycle, clé déclarée autrement…) et relève les modules à colonne
    historique (registry.COLUMN_MODULES). `path` et `package` servent aux tests.
    """
    names = module_files(path)
    for name in names:
        _load(name, package)
    registry.sort_registry()
    for name, reason in registry.prune_registry().items():
        registry.BROKEN_MODULES[name] = reason
        logger.error("Module de scan %s écarté : %s", name, reason)
    registry.COLUMN_MODULES.clear()
    registry.COLUMN_MODULES.update(
        (name, spec) for name, spec in registry.MODULES.items() if spec.column is not None
    )
    return names


discover()
