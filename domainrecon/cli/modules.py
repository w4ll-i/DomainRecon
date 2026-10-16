# =============================================================================
# DomainRecon - Ligne de commande : domainrecon modules
# =============================================================================
# Catalogue des modules du registre (aucune base nécessaire).
# =============================================================================

from __future__ import annotations

import argparse
import json

from ._common import add_lang, table


def register(subparsers) -> None:
    parser = subparsers.add_parser(
        "modules",
        help="catalogue des modules de scan",
        description="Liste les modules du registre, dans l'ordre d'exécution.",
    )
    parser.add_argument("--family", help="ne montre que cette famille (web, tls, email, dns, network, …)")
    parser.add_argument(
        "--format", choices=("text", "json"), default="text", help="présentation (défaut : text)"
    )
    add_lang(parser)
    parser.set_defaults(handler=run)


def run(args: argparse.Namespace) -> int:
    from ..reports.model import module_title
    from ..scanner import registry

    specs = [s for s in registry.MODULES.values() if not args.family or s.family == args.family]
    items = [
        {
            "name": s.name,
            "title": module_title(s.name, args.lang),
            "family": s.family,
            "category": s.category,
            "quick": s.quick,
            "requires_authorization": s.requires_authorization,
            "required_keys": list(s.required_keys),
        }
        for s in specs
    ]
    if args.format == "json":
        print(json.dumps({"modules": items}, ensure_ascii=False, indent=2))
        return 0
    yes = "oui" if args.lang == "fr" else "yes"
    print(
        table(
            ("MODULE", "FAMILLE", "CATÉGORIE", "RAPIDE", "AUTORISATION", "CLÉS API", "TITRE"),
            [
                (
                    i["name"],
                    i["family"],
                    i["category"],
                    yes if i["quick"] else "",
                    yes if i["requires_authorization"] else "",
                    ",".join(i["required_keys"]),
                    i["title"],
                )
                for i in items
            ],
        )
    )
    print(f"\n{len(items)} module(s).")
    return 0
