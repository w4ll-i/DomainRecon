# =============================================================================
# DomainRecon - Ligne de commande : domainrecon batch <fichier>
# =============================================================================
# Scanne plusieurs domaines à la suite. Fichier .txt : un domaine par ligne
# (lignes vides et commentaires « # » ignorés). Fichier .csv : colonne
# « domain » (ou « domaine », « target », « cible »), sinon la première colonne.
# Un échec sur un domaine n'arrête pas les suivants. Code de sortie : 2 si l'un
# des scans a échoué, sinon 1 si une note est sous --fail-under, sinon 0.
# =============================================================================

from __future__ import annotations

import argparse
import csv
from pathlib import Path

from ._common import (
    EXIT_BELOW_THRESHOLD,
    EXIT_ERROR,
    CliError,
    add_scan_options,
    below_threshold,
    execute_scan,
    grade_of,
    info,
    open_storage,
    table,
)

_HEADER_NAMES = ("domain", "domaine", "target", "cible")


def register(subparsers) -> None:
    from ..reports import CLI_FORMATS

    parser = subparsers.add_parser(
        "batch",
        help="scanne les domaines d'un fichier .txt ou .csv",
        description="Scanne les domaines d'un fichier, un par un, et résume les notes.",
    )
    parser.add_argument("file", metavar="fichier", help="fichier .txt (un domaine par ligne) ou .csv")
    add_scan_options(parser)
    parser.add_argument(
        "--format",
        choices=[f for f in CLI_FORMATS if f != "text"],
        help="écrit aussi un rapport par domaine dans ce format (exige --output-dir)",
    )
    parser.add_argument("--output-dir", metavar="DOSSIER", help="dossier des rapports")
    parser.set_defaults(handler=run)


def read_domains(path: str | Path) -> list[str]:
    """Domaines d'un fichier .txt ou .csv, sans doublon, dans l'ordre du fichier."""
    file = Path(path)
    try:
        text = file.read_text(encoding="utf-8-sig")
    except OSError as exc:
        raise CliError(f"Lecture impossible de {file} : {exc.strerror or exc}") from exc
    except UnicodeDecodeError as exc:
        raise CliError(f"{file} n'est pas un fichier texte UTF-8.") from exc
    if file.suffix.lower() == ".csv":
        rows = [row for row in csv.reader(text.splitlines(), skipinitialspace=True) if row]
        column = 0
        if rows and any(cell.strip().lower() in _HEADER_NAMES for cell in rows[0]):
            header = [cell.strip().lower() for cell in rows[0]]
            column = next(i for i, name in enumerate(header) if name in _HEADER_NAMES)
            rows = rows[1:]
        values = [row[column] for row in rows if len(row) > column]
    else:
        values = text.splitlines()
    domains = []
    for value in values:
        value = value.split("#", 1)[0].strip()
        if value:
            domains.append(value)
    domains = list(dict.fromkeys(domains))
    if not domains:
        raise CliError(f"Aucun domaine dans {file}.")
    return domains


def run(args: argparse.Namespace) -> int:
    from .. import reports

    if args.format and not args.output_dir:
        raise CliError("--format exige --output-dir (un fichier par domaine).")
    domains = read_domains(args.file)
    open_storage()
    out_dir = Path(args.output_dir) if args.output_dir else None
    rows = []
    failed = below = 0
    for number, domain in enumerate(domains, 1):
        info(f"[{number}/{len(domains)}] {domain}")
        try:
            scan_id = execute_scan(
                domain,
                profile=args.profile,
                modules=args.modules,
                authorized=args.authorized,
                lang=args.lang,
                quiet=args.quiet,
            )
            payload = reports.load_payload(scan_id)
            grade = grade_of(payload or {})
            if payload is not None and out_dir is not None and args.format:
                report = reports.generate_sync(payload, args.format, args.lang)
                out_dir.mkdir(parents=True, exist_ok=True)
                (out_dir / reports.export_filename(payload, args.format)).write_bytes(report.content)
        except (CliError, reports.PdfUnavailableError, OSError) as exc:
            failed += 1
            info(f"  [!] {exc}")
            rows.append((domain, "", "", "erreur"))
            continue
        is_below = below_threshold(grade, args.fail_under)
        below += is_below
        rows.append((domain, scan_id, grade, "sous le seuil" if is_below else "ok"))
    print(table(("DOMAINE", "SCAN", "NOTE", "RÉSULTAT"), rows))
    print(f"\n{len(domains)} domaine(s) : {len(domains) - failed} scanné(s), {failed} en erreur.")
    if failed:
        return EXIT_ERROR
    return EXIT_BELOW_THRESHOLD if below else 0
