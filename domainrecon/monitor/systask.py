# =============================================================================
# DomainRecon - Surveillance : tâche système qui lance `monitor run-due`
# =============================================================================
# Application fermée, le planificateur intégré ne tourne pas : une tâche du
# système exécute chaque heure `domainrecon monitor run-due` (les scans échus
# seulement). Installation facultative, sans droits administrateur :
#   - Windows : Planificateur de tâches, via schtasks, tâche de l'utilisateur
#     (« DomainRecon-Monitor », exécutée quand il est connecté) ;
#   - Linux : minuteur systemd de l'utilisateur (systemd --user) :
#     ~/.config/systemd/user/domainrecon-monitor.{service,timer}.
# Autre système : non pris en charge (lancer la commande à la main ou par cron).
#
# La commande exécutée est celle de l'exécutable installé (`DomainRecon.exe monitor
# run-due`, sous-commande de la ligne de commande) ; depuis les sources, c'est
# `python -m domainrecon monitor run-due`, ce qui suppose le paquet installé
# (pip install -e .). Les processus externes passent par un « runner »
# remplaçable : les tests ne touchent jamais au système.
# =============================================================================

import logging
import os
import subprocess
import sys
from collections.abc import Callable
from pathlib import Path

from ..i18n import msg
from ..scanner.errors import message_exception

logger = logging.getLogger(__name__)

WINDOWS_TASK = "DomainRecon-Monitor"
SYSTEMD_UNIT = "domainrecon-monitor"
RUN_ARGS = ("run-due",)
COMMAND_TIMEOUT = 30

# (code de retour, sortie) d'un processus externe.
Runner = Callable[[list[str]], tuple[int, str]]


def output_encoding() -> str | None:
    """Encodage de la sortie des outils système : page de code OEM de la console sous Windows
    (schtasks écrit « ERREUR : » avec une espace insécable 0xFF en cp850), celui de la locale ailleurs."""
    return "oem" if sys.platform == "win32" else None


def default_runner(args: list[str]) -> tuple[int, str]:
    """Lance un processus sans shell ni fenêtre ; (code, sortie). (127, '') si le programme est absent.

    La sortie ne sert qu'aux journaux : un octet illisible est remplacé, jamais une exception
    (en mode UTF-8 de Python, la sortie OEM de schtasks faisait échouer la lecture).
    """
    flags = getattr(subprocess, "CREATE_NO_WINDOW", 0)
    try:
        done = subprocess.run(
            args,
            capture_output=True,
            text=True,
            encoding=output_encoding(),
            errors="replace",
            timeout=COMMAND_TIMEOUT,
            creationflags=flags,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return 127, ""
    return done.returncode, (done.stdout or "") + (done.stderr or "")


def platform_name() -> str:
    if sys.platform == "win32":
        return "windows"
    if sys.platform.startswith("linux"):
        return "linux"
    return "other"


def command_line() -> list[str]:
    """Commande de la tâche : exécutable installé et sous-commande, ou interpréteur Python depuis les sources."""
    if getattr(sys, "frozen", False):
        return [sys.executable, "monitor", *RUN_ARGS]
    python = Path(sys.executable)
    if sys.platform == "win32":
        # pythonw : pas de fenêtre de console à chaque passage.
        windowless = python.with_name("pythonw.exe")
        if windowless.is_file():
            python = windowless
    return [str(python), "-m", "domainrecon", "monitor", *RUN_ARGS]


def _systemd_quote(arg: str) -> str:
    if arg and not any(c in arg for c in " \t\"'\\%"):
        return arg
    return '"' + arg.replace("\\", "\\\\").replace('"', '\\"').replace("%", "%%") + '"'


def _unit_dir(config_dir: Path | None) -> Path:
    if config_dir is not None:
        return config_dir
    base = os.environ.get("XDG_CONFIG_HOME") or str(Path.home() / ".config")
    return Path(base) / "systemd" / "user"


def _install_error() -> ValueError:
    return message_exception(ValueError, msg("systask.error_install"))


def _uninstall_error() -> ValueError:
    return message_exception(ValueError, msg("systask.error_uninstall"))


def _unsupported_error() -> ValueError:
    return message_exception(ValueError, msg("systask.unsupported"))


def _service_text(command: list[str]) -> str:
    return (
        "[Unit]\n"
        "Description=DomainRecon : scans de surveillance echus\n\n"
        "[Service]\n"
        "Type=oneshot\n"
        f"ExecStart={' '.join(_systemd_quote(a) for a in command)}\n"
    )


_TIMER_TEXT = (
    "[Unit]\n"
    "Description=DomainRecon : surveillance, passage toutes les heures\n\n"
    "[Timer]\n"
    "OnCalendar=hourly\n"
    "Persistent=true\n"
    "RandomizedDelaySec=120\n\n"
    "[Install]\n"
    "WantedBy=timers.target\n"
)


def status(*, runner: Runner = default_runner, config_dir: Path | None = None) -> dict:
    """{supported, platform, installed, command} ; installed : la tâche existe (et, sous Linux, le minuteur est activé)."""
    system = platform_name()
    result = {"supported": system != "other", "platform": system, "installed": False, "command": None}
    if system == "windows":
        code, _ = runner(["schtasks", "/Query", "/TN", WINDOWS_TASK])
        result["installed"] = code == 0
        result["command"] = subprocess.list2cmdline(command_line())
    elif system == "linux":
        timer = _unit_dir(config_dir) / f"{SYSTEMD_UNIT}.timer"
        code, _ = runner(["systemctl", "--user", "is-enabled", f"{SYSTEMD_UNIT}.timer"])
        result["installed"] = timer.is_file() and code == 0
        result["command"] = " ".join(_systemd_quote(a) for a in command_line())
    return result


def install(*, runner: Runner = default_runner, config_dir: Path | None = None) -> dict:
    """Installe (ou remplace) la tâche système ; ValueError (message traduisible) si le système la refuse."""
    system = platform_name()
    command = command_line()
    if system == "windows":
        code, output = runner(
            [
                "schtasks",
                "/Create",
                "/TN",
                WINDOWS_TASK,
                "/TR",
                subprocess.list2cmdline(command),
                "/SC",
                "HOURLY",
                "/MO",
                "1",
                "/F",
            ]
        )
        if code != 0:
            logger.warning("schtasks /Create a échoué (code %s) : %s", code, output.strip()[:300])
            raise _install_error()
    elif system == "linux":
        folder = _unit_dir(config_dir)
        try:
            folder.mkdir(parents=True, exist_ok=True)
            (folder / f"{SYSTEMD_UNIT}.service").write_text(_service_text(command), encoding="utf-8")
            (folder / f"{SYSTEMD_UNIT}.timer").write_text(_TIMER_TEXT, encoding="utf-8")
        except OSError as e:
            logger.warning("Écriture des unités systemd impossible : %s", e)
            raise _install_error() from e
        for args in (
            ["systemctl", "--user", "daemon-reload"],
            ["systemctl", "--user", "enable", "--now", f"{SYSTEMD_UNIT}.timer"],
        ):
            code, output = runner(args)
            if code != 0:
                logger.warning("%s a échoué (code %s) : %s", " ".join(args), code, output.strip()[:300])
                raise _install_error()
    else:
        raise _unsupported_error()
    return status(runner=runner, config_dir=config_dir)


def uninstall(*, runner: Runner = default_runner, config_dir: Path | None = None) -> dict:
    """Supprime la tâche système (sans erreur si elle n'existe pas)."""
    system = platform_name()
    if system == "windows":
        if status(runner=runner)["installed"]:
            code, output = runner(["schtasks", "/Delete", "/TN", WINDOWS_TASK, "/F"])
            if code != 0:
                logger.warning("schtasks /Delete a échoué (code %s) : %s", code, output.strip()[:300])
                raise _uninstall_error()
    elif system == "linux":
        folder = _unit_dir(config_dir)
        runner(["systemctl", "--user", "disable", "--now", f"{SYSTEMD_UNIT}.timer"])
        for suffix in ("timer", "service"):
            try:
                (folder / f"{SYSTEMD_UNIT}.{suffix}").unlink(missing_ok=True)
            except OSError as e:
                logger.warning("Suppression de l'unité systemd impossible : %s", e)
                raise _uninstall_error() from e
        runner(["systemctl", "--user", "daemon-reload"])
    else:
        raise _unsupported_error()
    return status(runner=runner, config_dir=config_dir)
