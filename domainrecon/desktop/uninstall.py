# =============================================================================
# DomainRecon - Désinstallation complète : inventaire, suppression, suite après fermeture
# =============================================================================
# Ce que DomainRecon crée sur la machine, selon le mode de lancement :
#   - dossier de données (paths.data_dir()) : base SQLite domainrecon.db (et ses
#     fichiers -journal, -wal, -shm), captures (screenshots/), journaux (logs/),
#     stockage de la fenêtre native (webview/), réglages (.env), secret de
#     chiffrement des clés API (.secret_key). Clés API et réglages enregistrés
#     sont dans la base (table settings) ;
#   - tâche système de la surveillance (monitor/systask.py) : tâche planifiée
#     « DomainRecon-Monitor » (Windows) ou unités systemd de l'utilisateur
#     domainrecon-monitor.{service,timer} (Linux) ;
#   - fichiers temporaires à préfixe propre (import, sauvegarde, certificat) ;
#   - exécutable Linux : cache de tldextract propre à l'installation
#     (~/.cache/python-tldextract/<identifiant du paquet>) ;
#   - installation Windows (Inno Setup) : programme, raccourcis, entrée du
#     registre « Applications installées » : retirés par son désinstallateur,
#     lancé en silencieux après la fermeture de l'application ;
#   - paquet .deb : /opt/domainrecon, /usr/bin/domainrecon, menu et icônes :
#     `sudo apt remove domainrecon`, à taper par l'utilisateur (jamais de sudo ici).
# Chromium est embarqué dans les exécutables ; depuis les sources, le cache de
# Playwright est partagé avec d'autres outils : jamais supprimé.
#
# Garde-fous : rien n'est supprimé hors des racines vérifiées (dossier de
# données, dossier temporaire, cache propre), un lien symbolique ou une
# jonction est retiré sans jamais être suivi, et un dossier de données qui
# n'appartient pas en propre à DomainRecon (DATA_DIR personnalisé) ne perd que
# les fichiers connus. Un dossier de données dangereux (racine d'un disque,
# dossier personnel, dossier temporaire…) n'est pas touché du tout.
# Les processus externes (tâche système, suite après fermeture) passent par des
# fonctions remplaçables : les tests ne touchent jamais au système.
# =============================================================================

from __future__ import annotations

import base64
import logging
import os
import re
import shlex
import stat
import subprocess
import sys
import tempfile
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from pathlib import Path

from ..core import paths
from ..monitor import systask

logger = logging.getLogger(__name__)

# Mot à taper pour confirmer (interface en français ou en anglais).
CONFIRM_WORDS = frozenset({"SUPPRIMER", "DELETE"})

MODES = (
    "windows_installed",  # installeur Inno Setup
    "deb",  # paquet Debian (/opt/domainrecon)
    "portable_onefile",  # exécutable portable en un seul fichier
    "portable_folder",  # zip portable (portable.flag à côté de l'exécutable)
    "frozen_other",  # exécutable lancé depuis un dossier sans installeur
    "source",  # lancement depuis les sources
)

# Entrées connues du dossier de données : nom -> sorte.
DATA_ENTRIES = {
    "domainrecon.db": "database",
    "screenshots": "screenshots",
    "logs": "logs",
    "webview": "webview",
    ".env": "settings_file",
    ".secret_key": "secret_key",
}
# Fichiers annexes d'une base SQLite.
SQLITE_SIDECARS = ("-journal", "-wal", "-shm")

# Préfixes des fichiers temporaires de DomainRecon (api/routes/importer.py, scanner/tls.py, sauvegarde).
TEMP_PREFIXES = ("domainrecon-import-", "domainrecon-cert-", "domainrecon-backup-")

# Contenu connu d'un dossier portable (zip) ou d'un exécutable de dossier : ce que build.py y place.
PROGRAM_ENTRIES = (
    "DomainRecon.exe",
    "DomainRecon-console.exe",
    "domainrecon",
    "_internal",
    "portable.flag",
    "Lancer DomainRecon.bat",
)

DEB_APP_DIR = Path("/opt/domainrecon")
DEB_LIST_FILE = Path("/var/lib/dpkg/info/domainrecon.list")
APT_REMOVE = "sudo apt remove domainrecon"

# Désinstalleur Inno Setup dans le dossier de l'application (unins000.exe et son .dat).
_UNINSTALLER_RE = re.compile(r"(?i)^unins(\d{3})\.exe$")
# Options du désinstalleur : silencieux, sans boîte, sans redémarrage ; /PURGEDATA
# lui fait supprimer aussi le dossier de données (packaging/windows/installer.iss).
UNINSTALLER_ARGS = ("/VERYSILENT", "/SUPPRESSMSGBOXES", "/NORESTART", "/PURGEDATA")
# Attente maximale de la fin de l'application par la suite après fermeture (secondes).
EXIT_WAIT_SECONDS = 600

_FILE_ATTRIBUTE_REPARSE_POINT = 0x400
_FILE_ATTRIBUTE_DIRECTORY = 0x10

# Lance un processus détaché (suite après fermeture) ; remplacé dans les tests.
Spawner = Callable[[list[str]], None]


class UnsafePath(ValueError):
    """Chemin hors des racines autorisées : jamais supprimé."""


# =============================================================================
# Suppression sans suivre les liens
# =============================================================================


def _is_link(st: os.stat_result) -> bool:
    """Lien symbolique, jonction ou autre point d'analyse (Windows) : à retirer sans le suivre."""
    if stat.S_ISLNK(st.st_mode):
        return True
    return bool(getattr(st, "st_file_attributes", 0) & _FILE_ATTRIBUTE_REPARSE_POINT)


def _remove_link(path: Path, st: os.stat_result) -> None:
    """Retire le lien lui-même ; sous Windows, un lien de dossier ou une jonction part avec rmdir."""
    if sys.platform == "win32" and getattr(st, "st_file_attributes", 0) & _FILE_ATTRIBUTE_DIRECTORY:
        os.rmdir(path)
    else:
        os.unlink(path)


def _unlink_file(path: Path) -> None:
    try:
        os.unlink(path)
    except PermissionError:
        # Fichier en lecture seule (Windows) : droit d'écriture rendu, puis nouvel essai.
        os.chmod(path, stat.S_IWRITE | stat.S_IREAD)
        os.unlink(path)


def _rmtree(path: Path, errors: list[str]) -> None:
    """Supprime un dossier réel et son contenu ; les liens qu'il contient sont retirés, jamais suivis."""
    try:
        with os.scandir(path) as listing:
            entries = list(listing)
    except OSError as e:
        errors.append(f"{path}: {e}")
        return
    for entry in entries:
        child = Path(entry.path)
        try:
            st = entry.stat(follow_symlinks=False)
            if _is_link(st):
                _remove_link(child, st)
            elif stat.S_ISDIR(st.st_mode):
                _rmtree(child, errors)
            else:
                _unlink_file(child)
        except OSError as e:
            errors.append(f"{child}: {e}")
    try:
        os.rmdir(path)
    except OSError as e:
        errors.append(f"{path}: {e}")


def is_inside(root: Path, target: Path) -> bool:
    """Vrai si `target` est dans `root` (strictement), d'après le dossier parent RÉEL de la cible.

    Le parent est résolu (liens suivis) mais pas la cible : une cible qui est elle-même un
    lien reste dans la racine (elle sera retirée sans être suivie), un chemin qui en sort
    par un dossier lien ou par « .. » est refusé.
    """
    if target.name in ("", ".", ".."):
        return False
    try:
        real_root = root.resolve()
        parent = target.parent.resolve()
    except OSError:
        return False
    return parent == real_root or parent.is_relative_to(real_root)


def remove_path(target: Path, root: Path) -> str:
    """Supprime `target` (fichier, dossier, lien) s'il est dans `root` ; « deleted », « missing » ou « failed ».

    Lève UnsafePath si la cible est hors de la racine : rien n'est touché.
    """
    if not is_inside(root, target):
        raise UnsafePath(str(target))
    try:
        st = os.lstat(target)
    except FileNotFoundError:
        return "missing"
    except OSError as e:
        logger.warning("Suppression : %s illisible (%s)", target, e)
        return "failed"
    errors: list[str] = []
    try:
        if _is_link(st):
            _remove_link(target, st)
        elif stat.S_ISDIR(st.st_mode):
            _rmtree(target, errors)
        else:
            _unlink_file(target)
    except OSError as e:
        errors.append(f"{target}: {e}")
    if errors:
        logger.warning("Suppression incomplète de %s : %s", target, "; ".join(errors[:5]))
    return "failed" if os.path.lexists(target) else "deleted"


def path_size(target: Path) -> int:
    """Taille en octets (dossier : total de son contenu, liens non suivis) ; 0 si illisible."""
    try:
        st = os.lstat(target)
    except OSError:
        return 0
    if _is_link(st) or not stat.S_ISDIR(st.st_mode):
        return 0 if _is_link(st) else st.st_size
    total = 0
    try:
        with os.scandir(target) as listing:
            for entry in listing:
                total += path_size(Path(entry.path))
    except OSError:
        pass
    return total


# =============================================================================
# Contexte : ce que la désinstallation sait de cette machine
# =============================================================================


@dataclass
class Target:
    """Élément à supprimer : sorte, chemin et racine qui le contient (garde-fou de remove_path)."""

    kind: str
    path: Path
    root: Path


@dataclass
class Context:
    """Tout ce que la désinstallation lit ou lance ; build_context() pour la machine, un faux dans les tests."""

    mode: str
    platform: str  # "windows", "linux" ou "other" (systask.platform_name)
    data_dir: Path
    owned_data_dir: bool  # dossier propre à DomainRecon : tout son contenu peut partir
    safe_data_dir: bool  # faux pour une racine, le dossier personnel… : rien n'y est touché
    database_files: list[Path]  # base SQLite et ses annexes, quand elles sont dans le dossier de données
    external_database: str | None  # base hors du dossier de données (autre fichier, PostgreSQL) : à la main
    temp_dir: Path
    cache_targets: list[Target]
    app_dir: Path
    executable: Path
    uninstaller: Path | None
    pid: int
    runner: systask.Runner
    systask_config_dir: Path | None = None
    spawn: Spawner | None = None
    # Vrai : contexte de test (serveur E2E) ; la route ne coupe ni la base ni le planificateur.
    isolated: bool = False
    extra: dict = field(default_factory=dict)


def _sqlite_path(database_url: str) -> Path | None:
    """Fichier d'une URL sqlite:/// ; None pour une base en mémoire ou un autre moteur."""
    from sqlalchemy.engine import make_url

    try:
        url = make_url(database_url)
    except Exception:  # URL illisible : traitée comme une base externe
        return None
    if url.get_backend_name() != "sqlite" or url.database in (None, "", ":memory:"):
        return None
    return Path(url.database)


def find_uninstaller(app_dir: Path) -> Path | None:
    """Désinstalleur Inno Setup (unins000.exe accompagné de son .dat) du dossier de l'application."""
    try:
        candidates = sorted(p for p in app_dir.iterdir() if _UNINSTALLER_RE.match(p.name))
    except OSError:
        return None
    for exe in reversed(candidates):
        if exe.is_file() and exe.with_suffix(".dat").is_file():
            return exe
    return None


def detect_mode(app_dir: Path | None = None) -> str:
    """Mode de lancement (voir MODES)."""
    if not paths.is_frozen():
        return "source"
    if paths.is_onefile_portable():
        return "portable_onefile"
    if paths.is_portable():
        return "portable_folder"
    app_dir = app_dir or paths.app_dir()
    if sys.platform == "win32" and find_uninstaller(app_dir) is not None:
        return "windows_installed"
    if sys.platform.startswith("linux") and (app_dir == DEB_APP_DIR or DEB_LIST_FILE.is_file()):
        return "deb"
    return "frozen_other"


def default_data_dirs() -> set[Path]:
    """Dossiers de données par défaut (propres à DomainRecon), tous modes confondus."""
    app = paths.app_dir()
    return {paths._user_data_dir(), app / "data", app / paths.ONEFILE_DATA_DIR, paths.source_data_dir()}


def _same(a: Path, b: Path) -> bool:
    try:
        return a.resolve() == b.resolve()
    except OSError:
        return False


def is_dangerous_dir(path: Path) -> bool:
    """Vrai pour un dossier qu'aucune suppression ne doit viser : racine d'un disque, dossier personnel
    ou l'un de ses parents, dossier temporaire, dossiers système de l'utilisateur, code de l'application."""
    try:
        real = path.resolve()
    except OSError:
        return True
    if real == Path(real.anchor) or len(real.parts) <= 1:
        return True
    home = Path.home().resolve()
    if real == home or home.is_relative_to(real):
        return True
    protected = [Path(tempfile.gettempdir())]
    for name in ("LOCALAPPDATA", "APPDATA", "USERPROFILE", "PROGRAMFILES", "SYSTEMROOT", "XDG_DATA_HOME"):
        value = os.environ.get(name)
        if value:
            protected.append(Path(value))
    protected += [
        home / ".local" / "share",
        home / ".config",
        home / ".cache",
        home / "Desktop",
        home / "Documents",
    ]
    if any(_same(real, other) for other in protected):
        return True
    # Le dossier de données ne doit jamais contenir le code de l'application.
    package = paths.package_dir().resolve()
    return package == real or package.is_relative_to(real)


def _tldextract_cache() -> list[Target]:
    """Cache de tldextract propre à l'exécutable (Linux : ~/.cache/python-tldextract/<id>), s'il existe.

    Son identifiant dépend du chemin du paquet installé : il n'appartient qu'à DomainRecon.
    Sous Windows (pas de HOME), le cache est dans _internal et part avec le programme.
    """
    if not paths.is_frozen():
        return []
    try:
        from tldextract.cache import get_cache_dir
    except Exception:  # tldextract absent ou changé : rien à faire
        return []
    folder = Path(get_cache_dir())
    root = folder.parent
    if root.name != "python-tldextract" or not folder.is_dir():
        return []
    if folder.resolve().is_relative_to(paths.app_dir().resolve()):
        return []
    return [Target("cache", folder, root)]


def build_context() -> Context:
    """Contexte de cette machine (lecture seule)."""
    from ..core import config

    data_dir = Path(config.DATA_DIR)
    app_dir = paths.app_dir()
    database = _sqlite_path(config.DATABASE_URL)
    database_files: list[Path] = []
    external: str | None = None
    if database is None:
        external = "database_url"
    elif is_inside(data_dir, database):
        database_files = [database, *(database.with_name(database.name + s) for s in SQLITE_SIDECARS)]
    else:
        external = str(database)
    return Context(
        mode=detect_mode(app_dir),
        platform=systask.platform_name(),
        data_dir=data_dir,
        owned_data_dir=any(_same(data_dir, d) for d in default_data_dirs()),
        safe_data_dir=not is_dangerous_dir(data_dir),
        database_files=database_files,
        external_database=external,
        temp_dir=Path(tempfile.gettempdir()),
        cache_targets=_tldextract_cache(),
        app_dir=app_dir,
        executable=Path(sys.executable),
        uninstaller=find_uninstaller(app_dir) if sys.platform == "win32" else None,
        pid=os.getpid(),
        # Lu à l'appel : les tests remplacent systask.default_runner.
        runner=systask.default_runner,
        spawn=spawn_detached,
    )


# Fabrique du contexte, lue par la route à chaque appel : le serveur E2E la remplace.
context_factory: Callable[[], Context] = build_context


# =============================================================================
# Inventaire
# =============================================================================


def data_targets(ctx: Context) -> list[Target]:
    """Éléments du dossier de données à supprimer (connus, ou tout le contenu d'un dossier propre)."""
    if not ctx.safe_data_dir:
        return []
    root = ctx.data_dir
    targets: list[Target] = []
    seen: set[str] = set()
    for path in ctx.database_files:
        targets.append(Target("database", path, root))
        seen.add(path.name)
    for name, kind in DATA_ENTRIES.items():
        if name not in seen:
            targets.append(Target(kind, root / name, root))
            seen.add(name)
            if kind == "database":
                for suffix in SQLITE_SIDECARS:
                    targets.append(Target(kind, root / (name + suffix), root))
                    seen.add(name + suffix)
    if ctx.owned_data_dir:
        try:
            others = sorted(p for p in root.iterdir() if p.name not in seen)
        except OSError:
            others = []
        targets += [Target("other_data", p, root) for p in others]
    return [t for t in targets if os.path.lexists(t.path)]


def temp_targets(ctx: Context) -> list[Target]:
    """Fichiers et dossiers temporaires de DomainRecon (préfixes propres)."""
    try:
        entries = sorted(p for p in ctx.temp_dir.iterdir() if p.name.startswith(TEMP_PREFIXES))
    except OSError:
        return []
    return [Target("temp", p, ctx.temp_dir) for p in entries]


def task_state(ctx: Context) -> dict | None:
    """État de la tâche système ({installed, …}) ; None si le système n'en a pas."""
    if ctx.platform == "other":
        return None
    try:
        return systask.status(runner=ctx.runner, config_dir=ctx.systask_config_dir)
    except Exception as e:  # lecture impossible : la désinstallation essaiera quand même
        logger.warning("État de la tâche système illisible : %s", e)
        return {"installed": None}


def program_removal(ctx: Context) -> dict:
    """Suppression du programme après fermeture (versions portables seulement) : {available, paths}."""
    if ctx.mode == "portable_onefile":
        exe = ctx.executable
        ok = exe.is_file() and exe.name.lower().startswith("domainrecon")
        return {"available": ok, "paths": [str(exe)] if ok else []}
    if ctx.mode == "portable_folder":
        folder = ctx.app_dir
        present = [folder / name for name in PROGRAM_ENTRIES if os.path.lexists(folder / name)]
        ok = (
            "domainrecon" in folder.name.lower()
            and (folder / paths.PORTABLE_FLAG).exists()
            and not is_dangerous_dir(folder)
        )
        return {"available": ok, "paths": [str(p) for p in present] if ok else []}
    return {"available": False, "paths": []}


def _item(kind: str, path: Path | str | None, status: str, size: int | None = None) -> dict:
    return {"kind": kind, "path": None if path is None else str(path), "status": status, "size": size}


def plan(ctx: Context) -> dict:
    """Ce que la désinstallation supprimerait, sans rien toucher (mode « à blanc »)."""
    items = [_item(t.kind, t.path, "planned", path_size(t.path)) for t in data_targets(ctx)]
    items += [_item(t.kind, t.path, "planned", path_size(t.path)) for t in ctx.cache_targets]
    items += [_item(t.kind, t.path, "planned", path_size(t.path)) for t in temp_targets(ctx)]
    state = task_state(ctx)
    if state is not None and state.get("installed") is not False:
        items.append(_item("system_task", _task_label(ctx), "planned"))
    return _report(ctx, items, dry_run=True)


def _task_label(ctx: Context) -> str:
    return systask.WINDOWS_TASK if ctx.platform == "windows" else f"{systask.SYSTEMD_UNIT}.timer"


def _remaining(
    ctx: Context, items: list[dict], program: dict, scheduled: bool, remove_program: bool
) -> list[dict]:
    """Étapes qui restent à l'utilisateur, ou que la suite après fermeture fera : {code, path?, command?}."""
    steps: list[dict] = []
    if not ctx.safe_data_dir:
        steps.append({"code": "unsafe_data_dir", "path": str(ctx.data_dir)})
    elif not ctx.owned_data_dir:
        steps.append({"code": "custom_data_dir", "path": str(ctx.data_dir)})
    if ctx.external_database is not None:
        steps.append({"code": "external_database", "path": ctx.external_database})
    if ctx.mode == "windows_installed":
        steps.append({"code": "windows_uninstaller", "path": str(ctx.uninstaller)})
    elif ctx.mode == "deb":
        steps.append({"code": "apt_remove", "command": APT_REMOVE})
    elif ctx.mode in ("portable_onefile", "portable_folder"):
        target = str(ctx.executable if ctx.mode == "portable_onefile" else ctx.app_dir)
        if remove_program and program["available"] and scheduled:
            steps.append({"code": "program_scheduled", "path": target})
        else:
            steps.append({"code": "delete_program", "path": target})
    elif ctx.mode == "frozen_other":
        steps.append({"code": "delete_program", "path": str(ctx.app_dir)})
    else:
        steps.append({"code": "source_tree", "path": str(ctx.app_dir)})
        steps.append({"code": "shared_browsers"})
    if any(item["status"] == "failed" for item in items):
        steps.append({"code": "leftovers_scheduled" if scheduled else "leftovers"})
    return steps


def _report(
    ctx: Context,
    items: list[dict],
    *,
    dry_run: bool,
    scheduled: bool = False,
    remove_program: bool = False,
) -> dict:
    program = program_removal(ctx)
    return {
        "dry_run": dry_run,
        "mode": ctx.mode,
        "platform": ctx.platform,
        "data_dir": str(ctx.data_dir),
        "items": items,
        "total_size": sum(item["size"] or 0 for item in items),
        "program_removal": program,
        "uninstaller": str(ctx.uninstaller) if ctx.mode == "windows_installed" and ctx.uninstaller else None,
        "after_exit_scheduled": scheduled,
        "remaining": _remaining(ctx, items, program, scheduled, remove_program),
    }


# =============================================================================
# Exécution
# =============================================================================


def execute(ctx: Context, *, remove_program: bool = False) -> dict:
    """Désinstalle : tâche système, données, caches, temporaires ; puis prépare la suite après fermeture.

    Ne lève pas : chaque élément porte son état (deleted, missing, failed, skipped).
    """
    items: list[dict] = []
    state = task_state(ctx)
    if state is not None and state.get("installed") is not False:
        try:
            after = systask.uninstall(runner=ctx.runner, config_dir=ctx.systask_config_dir)
            status = "failed" if after.get("installed") else "deleted"
        except Exception as e:  # refus du système : signalé, la suite continue
            logger.warning("Tâche système non retirée : %s", e)
            status = "failed"
        items.append(_item("system_task", _task_label(ctx), status))

    leftovers: list[Target] = []
    for target in [*data_targets(ctx), *ctx.cache_targets, *temp_targets(ctx)]:
        try:
            status = remove_path(target.path, target.root)
        except UnsafePath:
            logger.error("Suppression refusée hors de %s : %s", target.root, target.path)
            status = "skipped"
        if status == "failed":
            leftovers.append(target)
        items.append(_item(target.kind, target.path, status))

    # Dossier de données propre, vidé : il part aussi (son parent est vérifié comme racine).
    if ctx.safe_data_dir and ctx.owned_data_dir and not leftovers:
        try:
            ctx.data_dir.rmdir()
            items.append(_item("data_dir", ctx.data_dir, "deleted"))
        except FileNotFoundError:
            pass
        except OSError as e:
            logger.info("Dossier de données conservé (%s)", e)

    scheduled = False
    actions = after_exit_actions(ctx, leftovers, remove_program=remove_program)
    if actions and ctx.spawn is not None:
        try:
            ctx.spawn(after_exit_command(ctx, actions))
            scheduled = True
        except Exception as e:  # PowerShell ou sh introuvable : étapes laissées à l'utilisateur
            logger.warning("Suite après fermeture impossible à lancer : %s", e)
    return _report(ctx, items, dry_run=False, scheduled=scheduled, remove_program=remove_program)


# Action de la suite après fermeture : (verbe, chemin) ; verbes : rmtree, unlink, rmdir, uninstaller.
Action = tuple[str, Path]


def after_exit_actions(ctx: Context, leftovers: Iterable[Target], *, remove_program: bool) -> list[Action]:
    """Ce qui ne peut se faire qu'une fois l'application fermée (fichiers verrouillés, programme)."""
    actions: list[Action] = []
    for target in leftovers:
        if is_inside(target.root, target.path):
            real_dir = os.path.isdir(target.path) and not os.path.islink(target.path)
            actions.append(("rmtree" if real_dir else "unlink", target.path))
    if ctx.safe_data_dir and ctx.owned_data_dir and leftovers:
        actions.append(("rmdir", ctx.data_dir))
    if ctx.mode == "windows_installed" and ctx.uninstaller is not None:
        actions.append(("uninstaller", ctx.uninstaller))
    program = program_removal(ctx)
    if remove_program and program["available"]:
        for raw in program["paths"]:
            path = Path(raw)
            actions.append(("unlink" if path.is_file() and not path.is_symlink() else "rmtree", path))
        if ctx.mode == "portable_folder":
            if ctx.owned_data_dir and _same(ctx.data_dir, ctx.app_dir / "data"):
                actions.append(("rmdir", ctx.data_dir))
            actions.append(("rmdir", ctx.app_dir))
        elif ctx.owned_data_dir and _same(ctx.data_dir, ctx.app_dir / paths.ONEFILE_DATA_DIR):
            actions.append(("rmdir", ctx.data_dir))
    return actions


def _ps_quote(value: str) -> str:
    return "'" + value.replace("'", "''") + "'"


def _cmd_safe(path: Path) -> bool:
    """Chemin sans caractère spécial pour cmd.exe (guillemets, variables, enchaînement de commandes)."""
    return not any(c in str(path) for c in '"%&|<>^!\r\n')


def after_exit_command(ctx: Context, actions: list[Action]) -> list[str]:
    """Commande détachée qui attend la fin du processus `ctx.pid`, puis exécute `actions`.

    Windows : PowerShell (script encodé, aucun problème de guillemets) ; les dossiers sont
    supprimés par `rmdir /s /q` de cmd.exe, qui retire les jonctions sans les suivre.
    Ailleurs : sh, `rm -rf` (les liens symboliques ne sont jamais suivis).
    """
    if ctx.platform == "windows":
        lines = [
            "$ErrorActionPreference = 'SilentlyContinue'",
            f"$p = Get-Process -Id {int(ctx.pid)}",
            f"if ($p -and -not $p.WaitForExit({EXIT_WAIT_SECONDS * 1000})) {{ exit 1 }}",
            "Start-Sleep -Seconds 2",
        ]
        for verb, path in actions:
            if verb == "uninstaller":
                arguments = ",".join(_ps_quote(a) for a in UNINSTALLER_ARGS)
                lines.append(f"Start-Process -FilePath {_ps_quote(str(path))} -ArgumentList {arguments}")
            elif verb == "unlink":
                lines.append(f"Remove-Item -LiteralPath {_ps_quote(str(path))} -Force")
            elif _cmd_safe(path):
                # Chaîne PowerShell entre apostrophes (aucune expansion), passée à cmd.exe comme
                # un seul argument, entre guillemets s'il contient une espace.
                switch = "/s /q " if verb == "rmtree" else ""
                lines.append(f"& cmd.exe /d /c rmdir {switch}{_ps_quote(str(path))}")
        script = "\r\n".join(lines)
        encoded = base64.b64encode(script.encode("utf-16-le")).decode("ascii")
        return [
            "powershell.exe",
            "-NoProfile",
            "-NonInteractive",
            "-WindowStyle",
            "Hidden",
            "-EncodedCommand",
            encoded,
        ]
    lines = [
        f"i=0; while kill -0 {int(ctx.pid)} 2>/dev/null; do i=$((i+1)); "
        f'[ "$i" -gt {EXIT_WAIT_SECONDS} ] && exit 1; sleep 1; done',
        "sleep 1",
    ]
    for verb, path in actions:
        quoted = shlex.quote(str(path))
        if verb in ("rmtree", "unlink"):
            lines.append(f"rm -rf -- {quoted}")
        elif verb == "rmdir":
            lines.append(f"rmdir -- {quoted} 2>/dev/null")
    return ["/bin/sh", "-c", "\n".join(lines)]


def spawn_detached(args: list[str]) -> None:
    """Lance `args` détaché de l'application : il lui survit (sans fenêtre, sans flux hérités)."""
    options: dict = {
        "stdin": subprocess.DEVNULL,
        "stdout": subprocess.DEVNULL,
        "stderr": subprocess.DEVNULL,
        "close_fds": True,
    }
    if sys.platform == "win32":
        options["creationflags"] = getattr(subprocess, "CREATE_NO_WINDOW", 0) | getattr(
            subprocess, "CREATE_NEW_PROCESS_GROUP", 0
        )
    else:
        options["start_new_session"] = True
    subprocess.Popen(args, **options)  # noqa: S603 - commande construite ici, sans shell ni entrée de l'utilisateur
