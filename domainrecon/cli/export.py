# =============================================================================
# DomainRecon - Ligne de commande : domainrecon export <id>
# =============================================================================
# Rapport d'un scan déjà enregistré (voir `domainrecon history`), mêmes formats
# que l'export de l'API.
# =============================================================================

from __future__ import annotations

import argparse

from ._common import CliError, add_lang, open_storage, write_output


def register(subparsers) -> None:
    from ..reports import CLI_FORMATS

    parser = subparsers.add_parser(
        "export",
        help="rapport d'un scan enregistré",
        description="Écrit le rapport d'un scan enregistré (identifiant donné par `domainrecon history`).",
    )
    parser.add_argument("scan_id", metavar="id", type=int, help="identifiant du scan")
    parser.add_argument(
        "--format", choices=CLI_FORMATS, default="html", help="format du rapport (défaut : html)"
    )
    parser.add_argument("-o", "--output", metavar="FICHIER", help="écrit le rapport dans ce fichier")
    add_lang(parser)
    parser.set_defaults(handler=run)


def run(args: argparse.Namespace) -> int:
    from .. import reports

    open_storage()
    payload = reports.load_payload(args.scan_id)
    if payload is None:
        raise CliError(f"Scan n°{args.scan_id} introuvable.")
    try:
        report = reports.generate_sync(payload, args.format, args.lang)
    except reports.PdfUnavailableError as exc:
        raise CliError(f"PDF indisponible ({exc}).") from exc
    write_output(report.content, args.output, args.format)
    return 0
