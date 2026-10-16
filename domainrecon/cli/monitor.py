# =============================================================================
# DomainRecon - Ligne de commande : domainrecon monitor
# =============================================================================
#   domainrecon monitor run-due [--dry-run] [--concurrency N]   lance les scans échus
#   domainrecon monitor list                                    liste les surveillances
#   domainrecon monitor task status|install|uninstall           tâche système (schtasks / systemd --user)
#
# `run-due` est ce qu'exécute la tâche système, application fermée : pour chaque
# surveillance échue, scan, comparaison avec le scan précédent, règles d'alerte et
# envoi aux canaux (centre de notifications, webhooks, e-mail, bureau). Si
# l'application est ouverte au même moment, l'échéance n'est prise que par l'un
# des deux (monitor/schedule.py, claim) et une surveillance dont le scan tourne
# déjà dans l'autre processus est laissée de côté (bail : monitor/lease.py).
# Code de sortie : 0 si tout va bien, 1 si un scan surveillé a échoué, 2 pour une
# erreur d'usage.
#
# Enregistrement : cli/__init__.py découvre ce fichier et appelle register().
# Sans la ligne de commande commune, `python -m domainrecon.cli.monitor <commande>`
# fonctionne seul (main()).
# =============================================================================

from __future__ import annotations

import argparse
import asyncio
import sys

from ..i18n import msg
from ._common import CliError, add_lang, info, open_storage, table


def register(subparsers) -> None:
    parser = subparsers.add_parser(
        "monitor",
        help="surveillance : scans planifiés et alertes",
        description="Surveillance de domaines : lance les scans échus, liste les surveillances, gère la tâche système.",
    )
    configure(parser)


def configure(parser: argparse.ArgumentParser) -> None:
    """Déclare les sous-commandes sur `parser` (celui de « monitor », ou un parseur autonome)."""
    commands = parser.add_subparsers(dest="monitor_command", metavar="<action>", required=True)

    due = commands.add_parser("run-due", help="lance les scans des surveillances échues")
    due.add_argument("--dry-run", action="store_true", help="liste les surveillances échues sans rien lancer")
    due.add_argument(
        "--concurrency", type=int, metavar="N", help="scans simultanés (défaut : MAX_CONCURRENT_SCANS)"
    )
    add_lang(due)
    due.set_defaults(handler=run_due)

    listing = commands.add_parser("list", help="liste les surveillances")
    add_lang(listing)
    listing.set_defaults(handler=run_list)

    task = commands.add_parser("task", help="tâche système qui exécute run-due toutes les heures")
    task.add_argument("action", choices=("status", "install", "uninstall"))
    add_lang(task)
    task.set_defaults(handler=run_task)


def _text(message: dict, lang: str) -> str:
    """Message traduisible rendu dans la langue demandée."""
    from ..i18n import render

    text = render(message, lang)
    return text if isinstance(text, str) else str(text)


def _prepare() -> None:
    """Base prête, tables de la surveillance et des notifications comprises."""
    from ..monitor import models  # noqa: F401 - enregistre la table des surveillances
    from ..notify import models as notify_models  # noqa: F401

    open_storage()


def run_list(args: argparse.Namespace) -> int:
    from ..core.database import SessionLocal
    from ..monitor.models import Watch

    _prepare()
    with SessionLocal() as db:
        watches = db.query(Watch).order_by(Watch.domain).all()
        rows = [
            (
                w.domain,
                w.profile,
                w.frequency,
                "" if w.enabled else _text(msg("monitor.cli_disabled"), args.lang),
                w.next_run_at.strftime("%Y-%m-%d %H:%M UTC"),
                w.last_status or "",
            )
            for w in watches
        ]
    if not rows:
        print(_text(msg("monitor.cli_no_watch"), args.lang))
        return 0
    headers = (
        msg("monitor.cli_col_domain"),
        msg("monitor.cli_col_profile"),
        msg("monitor.cli_col_frequency"),
        msg("monitor.cli_col_state"),
        msg("monitor.cli_col_due"),
        msg("monitor.cli_col_last"),
    )
    print(table(tuple(_text(header, args.lang) for header in headers), rows))
    return 0


def run_due(args: argparse.Namespace) -> int:
    from ..core import config
    from ..core.database import SessionLocal
    from ..core.models import utcnow
    from ..monitor import schedule, service
    from ..monitor.models import Watch

    _prepare()
    now = utcnow()
    if args.dry_run:
        with SessionLocal() as db:
            due = schedule.list_due(db, now)
            names = {w.id: w.domain for w in db.query(Watch).filter(Watch.id.in_([i for i, _ in due] or [0]))}
        if not due:
            print(_text(msg("monitor.cli_none_due"), args.lang))
            return 0
        print(
            table(
                (
                    _text(msg("monitor.cli_col_domain"), args.lang),
                    _text(msg("monitor.cli_col_due"), args.lang),
                ),
                [
                    (names.get(watch_id, "?"), expected.strftime("%Y-%m-%d %H:%M UTC"))
                    for watch_id, expected in due
                ],
            )
        )
        return 0

    concurrency = (
        args.concurrency if args.concurrency and args.concurrency > 0 else config.MAX_CONCURRENT_SCANS
    )
    try:
        results = asyncio.run(service.run_due(service.direct_runner(), concurrency=concurrency))
    except Exception as exc:  # base verrouillée, réglages illisibles…
        raise CliError(_text(msg("monitor.cli_failure", error=type(exc).__name__), args.lang)) from exc
    if not results:
        print(_text(msg("monitor.cli_none_due"), args.lang))
        return 0
    failed = 0
    for result in results:
        if result.status == "done":
            line = _text(
                msg(
                    "monitor.cli_done",
                    domain=result.domain,
                    scan_id=result.scan_id,
                    alerts=len(result.alerts),
                ),
                args.lang,
            )
        elif result.status == "deferred":
            line = _text(msg("monitor.cli_deferred", domain=result.domain), args.lang)
        else:
            failed += 1
            line = _text(
                msg("monitor.cli_failed", domain=result.domain, error=_render(result.error, args.lang)),
                args.lang,
            )
        print(line)
    print(_text(msg("monitor.cli_summary", total=len(results), failed=failed), args.lang))
    return 1 if failed else 0


def _render(value: object, lang: str) -> str:
    from ..i18n import render

    rendered = render(value, lang)
    return rendered if isinstance(rendered, str) else ""


def run_task(args: argparse.Namespace) -> int:
    from ..monitor import systask

    try:
        if args.action == "install":
            state = systask.install()
        elif args.action == "uninstall":
            state = systask.uninstall()
        else:
            state = systask.status()
    except ValueError as exc:
        from ..scanner.errors import message_of

        raise CliError(_render(message_of(exc), args.lang) or str(exc)) from exc
    if not state["supported"]:
        raise CliError(_text(msg("systask.unsupported"), args.lang))
    if state["installed"]:
        print(_text(msg("monitor.cli_task_installed", platform=state["platform"]), args.lang))
    else:
        print(_text(msg("monitor.cli_task_absent", platform=state["platform"]), args.lang))
    if state["installed"] and state.get("command"):
        info(state["command"])
    return 0


def main(argv: list[str] | None = None) -> int:
    """Point d'entrée autonome : python -m domainrecon.cli.monitor <action>."""
    parser = argparse.ArgumentParser(prog="domainrecon monitor")
    configure(parser)
    args = parser.parse_args(argv)
    try:
        return int(args.handler(args) or 0)
    except CliError as exc:
        print(f"[!] {exc}", file=sys.stderr)
        return exc.code


if __name__ == "__main__":
    sys.exit(main())
