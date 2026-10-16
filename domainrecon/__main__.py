# =============================================================================
# DomainRecon - Commande `domainrecon` (et `python -m domainrecon`)
# =============================================================================
# Usage : domainrecon [--browser | --server] [--host HÔTE] [--port PORT] [--no-open]
#   (défaut)   fenêtre native, serveur sur 127.0.0.1 (port 47815 s'il est libre,
#              sinon un port libre : l'origine, donc la langue mémorisée, reste stable) ;
#   --browser  interface dans le navigateur par défaut (version portable) ;
#   --server   serveur seul (HOST et PORT de l'environnement ou du .env,
#              sinon 127.0.0.1:8000).
# Sous-commandes : domainrecon scan|batch|history|export|modules|import … (voir cli/).
# Les réglages réseau (ALLOWED_HOSTS, API_TOKEN, CORS_ORIGINS, API_DOCS) sont
# lus par la configuration (fichier .env du dossier de données).
# =============================================================================

from __future__ import annotations

import argparse
import sys

from . import __version__

MIN_PYTHON = (3, 10)


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="domainrecon",
        description="Lance DomainRecon : fenêtre native (défaut), navigateur ou serveur seul.",
        epilog="Ligne de commande : domainrecon <commande> --help (commandes : scan, batch, history, export, modules, import…).",
    )
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument(
        "--browser", action="store_true", help="interface dans le navigateur (version portable)"
    )
    mode.add_argument(
        "--server",
        action="store_true",
        help="serveur seul, sans interface (défaut : HOST et PORT, sinon 8000)",
    )
    parser.add_argument("--host", help="interface d'écoute (défaut : 127.0.0.1)")
    parser.add_argument(
        "--port",
        type=int,
        help="port d'écoute (défaut : 47815 s'il est libre, sinon un port libre ; --server : PORT, sinon 8000)",
    )
    parser.add_argument("--no-open", action="store_true", help="n'ouvre pas le navigateur (--browser)")
    parser.add_argument("--version", action="store_true", help="affiche la version et quitte")
    return parser.parse_args(argv)


def _load_config():
    """Configuration centralisée (charge les .env ; RuntimeError si l'un est illisible)."""
    from .core import config

    return config


def main(argv: list[str] | None = None) -> int:
    from .desktop import launcher

    # Exécutable fenêtré : ni console ni flux standard ; à régler avant tout affichage.
    launcher.ensure_std_streams()
    launcher.make_console_safe()
    raw = sys.argv[1:] if argv is None else list(argv)
    if raw and not raw[0].startswith("-"):
        # Sous-commande (scan, batch, history, export, modules, import…) : voir cli/.
        from .cli import run as run_cli

        return run_cli(raw)
    args = parse_args(argv)
    if args.version:
        print(f"DomainRecon {__version__}")
        return 0
    if sys.version_info < MIN_PYTHON:
        print(
            f"[!] Python {MIN_PYTHON[0]}.{MIN_PYTHON[1]} ou plus récent est requis "
            f"(version actuelle : {sys.version.split()[0]}).",
            file=sys.stderr,
        )
        return 1
    try:
        config = _load_config()
    except RuntimeError as exc:  # fichier .env illisible : le message est déjà explicite
        launcher.report_failure(str(exc))
        return 1
    except Exception as exc:  # dossier de données inaccessible, base impossible à ouvrir…
        launcher.report_failure(f"Démarrage impossible : {launcher.describe_error(exc)}", exc)
        return 1

    mode = "server" if args.server else "browser" if args.browser else "window"
    if mode == "server":
        host = args.host or config.env_str("HOST", "127.0.0.1")
        port = args.port if args.port is not None else config.env_int("PORT", launcher.DEFAULT_SERVER_PORT)
    else:
        host = args.host or "127.0.0.1"
        port = args.port if args.port is not None else 0
    if not 0 <= port <= 65535:
        print(
            f"[!] Port invalide : {port} (attendu : 1 à 65535, ou 0 pour le port automatique).",
            file=sys.stderr,
        )
        return 2
    if mode != "server":
        # L'application ouvre elle-même cette adresse : elle doit passer le contrôle de Host.
        launcher.allow_app_host(host)
    if not launcher.is_loopback(host):
        launcher.warn_network_exposure(host, config.API_TOKEN, config.ALLOWED_HOSTS)
    return launcher.run(mode, host=host, port=port, open_browser=not args.no_open)


if __name__ == "__main__":
    sys.exit(main())
