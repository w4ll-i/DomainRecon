"""Aides de test : chargement des scripts de packaging/ et fichiers factices.

packaging/ n'est pas un paquet Python (pas de __init__.py, qui masquerait la
bibliothèque PyPI « packaging ») : ses scripts sont chargés depuis leur chemin.
"""

import importlib.util
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PACKAGING = ROOT / "packaging"


def load(name: str, relative: str):
    """Exécute packaging/<relative> sous le nom de module « drpkg_<name> » (rechargé à chaque appel)."""
    spec = importlib.util.spec_from_file_location(f"drpkg_{name}", PACKAGING / relative)
    module = importlib.util.module_from_spec(spec)
    # Enregistré avant exécution : dataclasses et annotations retrouvent le module.
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def touch(path: Path, content: str = "x") -> Path:
    """Écrit un fichier factice (dossiers parents créés) et renvoie son chemin."""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")
    return path
