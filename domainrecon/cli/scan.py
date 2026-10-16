# =============================================================================
# DomainRecon - Ligne de commande : domainrecon scan <domaine>
# =============================================================================
# Lance un scan (enregistré dans l'historique) puis écrit le rapport dans le
# format demandé : texte (défaut), json, md, html, csv, pdf, sarif ou junit.
# Avancement sur la sortie d'erreur, rapport sur la sortie standard (ou -o).
# Code de sortie 1 si la note est sous --fail-under.
# =============================================================================

from __future__ import annotations

import argparse

from ._common import (
    EXIT_BELOW_THRESHOLD,
    CliError,
    add_scan_options,
    below_threshold,
    execute_scan,
    grade_of,
    info,
    open_storage,
    write_output,
)


def register(subparsers) -> None:
    from ..reports import CLI_FORMATS

    parser = subparsers.add_parser(
        "scan",
        help="scanne un domaine et produit un rapport",
        description="Scanne un domaine que vous administrez, l'enregistre dans l'historique et produit un rapport.",
    )
    parser.add_argument("domain", metavar="domaine", help="domaine ou sous-domaine à auditer")
    add_scan_options(parser)
    parser.add_argument(
        "--format", choices=CLI_FORMATS, default="text", help="format du rapport (défaut : text)"
    )
    parser.add_argument("-o", "--output", metavar="FICHIER", help="écrit le rapport dans ce fichier")
    parser.set_defaults(handler=run)


def run(args: argparse.Namespace) -> int:
    from .. import reports

    open_storage()
    scan_id = execute_scan(
        args.domain,
        profile=args.profile,
        modules=args.modules,
        authorized=args.authorized,
        lang=args.lang,
        quiet=args.quiet,
    )
    payload = reports.load_payload(scan_id)
    if payload is None:
        raise CliError(f"Scan n°{scan_id} introuvable après enregistrement.")
    grade = grade_of(payload)
    info(f"Scan n°{scan_id} enregistré : note {grade}")
    try:
        report = reports.generate_sync(payload, args.format, args.lang)
    except reports.PdfUnavailableError as exc:
        raise CliError(
            f"PDF indisponible ({exc}). Le scan n°{scan_id} est enregistré : "
            f"utilisez « domainrecon export {scan_id} --format html »."
        ) from exc
    write_output(report.content, args.output, args.format)
    if below_threshold(grade, args.fail_under):
        info(f"Note {grade} sous le seuil demandé ({args.fail_under}).")
        return EXIT_BELOW_THRESHOLD
    return 0
