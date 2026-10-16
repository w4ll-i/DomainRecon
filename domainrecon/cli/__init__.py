# =============================================================================
# DomainRecon - Ligne de commande : sous-commandes de `domainrecon`
# =============================================================================
# `domainrecon <commande> …` : scan, batch, history, export, modules, import.
# Sans commande, `domainrecon` garde son comportement (fenêtre, --browser,
# --server : voir __main__.py).
#
# Découverte par module : chaque fichier de ce dossier (hors ceux dont le nom
# commence par « _ ») qui définit `register(subparsers)` apporte ses
# sous-commandes. Il y déclare ses parseurs et attache son traitement :
#
#     def register(subparsers):
#         parser = subparsers.add_parser("monitor", help="…")
#         parser.add_argument(…)
#         parser.set_defaults(handler=run)
#
#     def run(args) -> int | None: …   # code de sortie (None : 0)
#
# Ajouter une commande = ajouter un fichier (par exemple monitor.py), sans
# toucher à celui-ci. Un fichier qui ne s'importe pas est ignoré (avertissement
# sur la sortie d'erreur) : il ne bloque pas les autres commandes. Les imports
# lourds (FastAPI, scanner, base) se font dans les fonctions, pas en tête de
# fichier : `domainrecon --help` reste rapide. Aides communes : cli/_common.py.
# =============================================================================

from __future__ import annotations

import argparse
import importlib
import pkgutil
import sys
from types import ModuleType

from ._common import CliError

__all__ = ["CliError", "build_parser", "command_names", "discover", "run"]


def discover() -> list[ModuleType]:
    """Modules de commandes de ce dossier, par ordre alphabétique (ceux qui définissent `register`)."""
    found = []
    for info in sorted(pkgutil.iter_modules(__path__), key=lambda i: i.name):
        if info.name.startswith("_"):
            continue
        try:
            module = importlib.import_module(f"{__name__}.{info.name}")
        except Exception as exc:  # une commande défectueuse ne doit pas bloquer les autres
            print(f"[!] Commande {info.name!r} ignorée : {type(exc).__name__}: {exc}", file=sys.stderr)
            continue
        if callable(getattr(module, "register", None)):
            found.append(module)
    return found


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="domainrecon",
        description="DomainRecon en ligne de commande : audit de ses propres domaines.",
    )
    subparsers = parser.add_subparsers(dest="command", metavar="<commande>", title="commandes")
    for module in discover():
        module.register(subparsers)
    return parser


def command_names() -> list[str]:
    """Noms des sous-commandes disponibles."""
    parser = build_parser()
    for action in parser._actions:
        if isinstance(action, argparse._SubParsersAction):
            return sorted(action.choices)
    return []


def run(argv: list[str]) -> int:
    """Exécute `domainrecon <commande> …` et renvoie le code de sortie (0 : succès)."""
    parser = build_parser()
    args = parser.parse_args(argv)
    handler = getattr(args, "handler", None)
    if handler is None:
        parser.print_help(sys.stderr)
        return 2
    try:
        return int(handler(args) or 0)
    except CliError as exc:
        print(f"[!] {exc}", file=sys.stderr)
        return exc.code
    except KeyboardInterrupt:
        print("\n[!] Interrompu.", file=sys.stderr)
        return 130
