#!/usr/bin/env python3
"""Construit les livrables de DomainRecon : dossier PyInstaller, zip portable, exécutable portable
monofichier, installeur, paquet .deb.

Usage :
    python packaging/build.py [--target windows|linux] [--skip-frontend] [--skip-chromium] [--skip-installer] [--skip-onefile]
                              [--build-dir DOSSIER] [--release-dir DOSSIER]
    python packaging/build.py --print-version
    python packaging/build.py --print-paths
    python packaging/build.py --check-tag v1.0.0
    python packaging/build.py --checksums
    python packaging/build.py --lock

Dossiers (ignorés par git) :
    private/build/       travail : PyInstaller, Chromium (ms-playwright),
                         dossier intermédiaire de l'application (dist/DomainRecon) ;
    release/<version>/   livrables finaux, SHA256SUMS et NOTES.md (copie de
                         docs/releases/<version>.md quand elle existe).
--build-dir et --release-dir (ou DOMAINRECON_BUILD_DIR, DOMAINRECON_RELEASE_DIR ;
chemin absolu, ou relatif à la racine du dépôt) les déplacent.

Étapes : interface (npm ci + npm run build), Chromium installé dans
private/build/ms-playwright (PLAYWRIGHT_BROWSERS_PATH) puis embarqué dans
_internal/browsers, PyInstaller, licence et avis de tiers, contrôle du
dossier produit, livrables de la plateforme, puis SHA256SUMS et NOTES.md.
PyInstaller ne fait pas de compilation croisée : chaque plateforme se
construit sur elle-même (Ubuntu 22.04 pour le paquet .deb publié).
"""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
import re
import shutil
import subprocess
import sys
import zipfile
from collections.abc import Mapping, Sequence
from pathlib import Path

PACKAGING_DIR = Path(__file__).resolve().parent
ROOT = PACKAGING_DIR.parent


def _load_sibling(name: str):
    """Charge packaging/<name>.py par son chemin : packaging/ n'est pas un paquet Python."""
    module_name = f"drpkg_{name}"
    module = sys.modules.get(module_name)
    if module is None:
        spec = importlib.util.spec_from_file_location(module_name, PACKAGING_DIR / f"{name}.py")
        module = importlib.util.module_from_spec(spec)
        sys.modules[module_name] = module
        spec.loader.exec_module(module)
    return module


pyi_helpers = _load_sibling("pyi_helpers")


class BuildError(Exception):
    """Échec d'une étape de la construction (message destiné à l'utilisateur)."""


def run(cmd: Sequence[object], cwd: Path | None = None, env: Mapping[str, str] | None = None) -> None:
    """Lance une commande en affichant sa ligne ; BuildError si elle échoue."""
    args = [str(part) for part in cmd]
    line = " ".join(args)
    print(f"\n>>> {line}", flush=True)
    completed = subprocess.run(args, cwd=cwd, env=None if env is None else dict(env), check=False)
    if completed.returncode != 0:
        raise BuildError(f"Échec (code {completed.returncode}) : {line}")


def tool(name: str) -> str:
    """Chemin d'un outil du PATH (npm est npm.cmd sous Windows)."""
    found = shutil.which(name)
    if found is None:
        raise BuildError(f"Outil introuvable dans le PATH : {name}")
    return found


def default_target(platform: str = sys.platform) -> str:
    """Plateforme cible : celle de la machine."""
    if platform == "win32":
        return "windows"
    if platform.startswith("linux"):
        return "linux"
    raise BuildError(f"Plateforme non prise en charge : {platform}")


def check_tag(tag: str, version: str) -> None:
    """Le tag Git d'une release doit valoir « v » suivi de la version du code."""
    if tag != f"v{version}":
        raise BuildError(f"Le tag {tag!r} ne correspond pas à la version du code (attendu : 'v{version}').")


def lock_command(python: str = sys.executable) -> list[str]:
    """Commande uv qui régénère packaging/requirements.lock (toutes plateformes, Python 3.13, hachages)."""
    return [
        python,
        "-m",
        "uv",
        "pip",
        "compile",
        "pyproject.toml",
        "--universal",
        "--python-version",
        "3.13",
        "--extra",
        "build",
        "--generate-hashes",
        "--output-file",
        "packaging/requirements.lock",
    ]


def bundled_browsers_env(root: Path = ROOT, base: Mapping[str, str] | None = None) -> dict[str, str]:
    """Environnement où Playwright installe ses navigateurs dans private/build/ms-playwright."""
    env = dict(os.environ if base is None else base)
    env["PLAYWRIGHT_BROWSERS_PATH"] = str(pyi_helpers.build_browsers_dir(root, env))
    return env


def build_frontend(root: Path = ROOT) -> None:
    """Interface : npm ci puis npm run build (sortie dans domainrecon/web)."""
    npm = tool("npm")
    frontend = root / "frontend"
    run([npm, "ci"], cwd=frontend)
    run([npm, "run", "build"], cwd=frontend)


# Route du battement de l'interface (mode navigateur, desktop/launcher.py) :
# une interface construite avant lui laisserait le serveur s'arrêter seul.
HEARTBEAT_ROUTE = "system/heartbeat"


def web_sends_heartbeat(web: Path) -> bool:
    """Vrai si l'interface construite (`web`, domainrecon/web) envoie le battement du mode navigateur."""
    return any(
        HEARTBEAT_ROUTE in script.read_text(encoding="utf-8", errors="replace")
        for script in web.rglob("*.js")
    )


def install_chromium(root: Path = ROOT) -> None:
    """Headless shell de Chromium installé dans private/build/ms-playwright, embarqué ensuite par la spec.

    Le dossier est vidé d'abord : la spec embarque tout ce qu'il contient, une
    révision plus ancienne laissée par un build précédent partirait dans le paquet.
    """
    shutil.rmtree(pyi_helpers.build_browsers_dir(root), ignore_errors=True)
    run(
        [sys.executable, "-m", "playwright", "install", "--only-shell", "chromium"],
        env=bundled_browsers_env(root),
    )


def run_pyinstaller(root: Path = ROOT) -> None:
    """Dossier de l'application : private/build/dist/DomainRecon (travail dans private/build/pyinstaller)."""
    run(
        [
            sys.executable,
            "-m",
            "PyInstaller",
            "--noconfirm",
            "--clean",
            "--distpath",
            pyi_helpers.build_dist_dir(root),
            "--workpath",
            pyi_helpers.build_dir(root) / "pyinstaller",
            root / "packaging" / "domainrecon.spec",
        ]
    )


ONEFILE_SPEC = "domainrecon-onefile.spec"
# Un onefile embarque Chromium : bien en dessous, un bundle est incomplet.
ONEFILE_MIN_SIZE = 150 * 1024 * 1024


def onefile_name(version: str) -> str:
    return f"DomainRecon-{version}-portable.exe"


def run_pyinstaller_onefile(root: Path = ROOT) -> None:
    """Exécutable portable monofichier (spec séparée, dossier de travail à part du onedir)."""
    run(
        [
            sys.executable,
            "-m",
            "PyInstaller",
            "--noconfirm",
            "--clean",
            "--distpath",
            pyi_helpers.build_dist_dir(root),
            "--workpath",
            pyi_helpers.build_dir(root) / "pyinstaller-onefile",
            root / "packaging" / ONEFILE_SPEC,
        ]
    )


def verify_onefile(exe: Path, min_size: int = ONEFILE_MIN_SIZE) -> list[str]:
    """Contrôle l'exécutable monofichier ; renvoie la liste des problèmes (vide si plausible)."""
    if not exe.is_file():
        return [f"exécutable monofichier manquant : {exe.name}"]
    size = exe.stat().st_size
    if size < min_size:
        return [f"{exe.name} trop petit ({size} octets, attendu au moins {min_size}) : Chromium absent ?"]
    return []


def build_onefile(root: Path, version: str) -> Path:
    """release/<version>/DomainRecon-<version>-portable.exe : construit (private/build/dist), vérifie, range."""
    run_pyinstaller_onefile(root)
    exe = pyi_helpers.build_dist_dir(root) / onefile_name(version)
    problems = verify_onefile(exe)
    if problems:
        raise BuildError("Exécutable portable incomplet :\n  - " + "\n  - ".join(problems))
    target = pyi_helpers.release_dir(root, version) / exe.name
    target.parent.mkdir(parents=True, exist_ok=True)
    target.unlink(missing_ok=True)
    shutil.move(exe, target)
    return target


# Paquets embarqués sous Linux en plus des dépendances de pyproject.toml
# (fenêtre native GTK, installés à part sur la machine de build).
LINUX_EXTRA_NOTICES = ("PyGObject", "pycairo")


def _playwright_dir() -> Path:
    """Paquet Playwright du Python de build (pilote et navigateur embarqués)."""
    import playwright

    return Path(playwright.__file__).resolve().parent


def finalize_app_dir(root: Path, app_dir: Path, version: str, target: str) -> None:
    """Ajoute à côté des exécutables la licence de DomainRecon et THIRD_PARTY_NOTICES.md."""
    shutil.copy2(root / "LICENSE", app_dir / "LICENSE")
    notices = _load_sibling("notices")
    try:
        notices.write_notices(
            app_dir / "THIRD_PARTY_NOTICES.md",
            version,
            pyproject=root / "pyproject.toml",
            frontend_lock=root / "frontend" / "package-lock.json",
            playwright_dir=_playwright_dir(),
            extra_requirements=LINUX_EXTRA_NOTICES if target == "linux" else (),
        )
    except notices.NoticesError as exc:
        raise BuildError(str(exc)) from exc


def expected_headless_shell(internal: Path) -> str:
    """Dossier du headless shell attendu dans browsers/ : celui de la révision du pilote Playwright embarqué.

    La révision se lit dans le browsers.json livré avec le pilote
    (_internal/playwright/driver/package) : c'est la même table que celle
    qu'utilise Playwright pour chercher son navigateur à l'exécution.
    """
    browsers_json = internal / "playwright" / "driver" / "package" / "browsers.json"
    if not browsers_json.is_file():
        raise BuildError(
            "Révision de Chromium attendue introuvable : _internal/playwright/driver/package/browsers.json "
            "absent du dossier de l'application (pilote Playwright non collecté par PyInstaller)."
        )
    data = json.loads(browsers_json.read_text(encoding="utf-8"))
    for browser in data.get("browsers", []):
        if browser.get("name") == "chromium-headless-shell" and browser.get("revision"):
            return f"chromium_headless_shell-{browser['revision']}"
    raise BuildError("Entrée « chromium-headless-shell » absente de _internal/playwright/.../browsers.json.")


def verify_bundle(app_dir: Path, target: str) -> list[str]:
    """Contrôle le dossier produit par PyInstaller ; renvoie la liste des problèmes (vide si complet).

    BuildError seulement si la révision attendue de Chromium est indéterminable (browsers.json absent).
    """
    problems = []
    executables = pyi_helpers.WINDOWS_EXECUTABLES if target == "windows" else (pyi_helpers.LINUX_EXECUTABLE,)
    for name in executables:
        if not (app_dir / name).is_file():
            problems.append(f"exécutable manquant : {name}")
    internal = app_dir / pyi_helpers.CONTENTS_DIR
    required = [
        internal / "domainrecon" / "web" / "index.html",
        internal / "domainrecon" / "i18n" / "fr.json",
        internal / "domainrecon" / "i18n" / "en.json",
        app_dir / "LICENSE",
        app_dir / "THIRD_PARTY_NOTICES.md",
    ]
    for path in required:
        if not path.is_file():
            problems.append(f"fichier manquant : {path.relative_to(app_dir).as_posix()}")
    browsers_dir = internal / pyi_helpers.BROWSERS_DIR_NAME
    expected = expected_headless_shell(internal)
    shells = pyi_helpers.headless_shell_executables(browsers_dir)
    if not shells:
        problems.append("Chromium (headless shell) absent de _internal/browsers")
    else:
        if expected not in {shell.relative_to(browsers_dir).parts[0] for shell in shells}:
            problems.append(
                f"Chromium embarqué à la mauvaise révision : _internal/browsers/{expected} attendu "
                "(révision du pilote Playwright)"
            )
        if target == "linux" and not all(os.access(shell, os.X_OK) for shell in shells):
            problems.append("Chromium embarqué non exécutable (droits)")
    extra = sorted(
        path.name
        for path in browsers_dir.glob("chromium_headless_shell-*")
        if path.is_dir() and path.name != expected
    )
    if extra:
        problems.append(
            f"révision(s) de Chromium en trop dans _internal/browsers : {', '.join(extra)} "
            "(seule la révision du pilote doit être embarquée)"
        )
    if (internal / pyi_helpers.PLAYWRIGHT_LOCAL_BROWSERS).exists():
        problems.append(
            "navigateurs en double dans _internal/playwright (installation avec PLAYWRIGHT_BROWSERS_PATH=0)"
        )
    if (app_dir / "portable.flag").exists():
        problems.append(
            "portable.flag ne doit pas être dans le dossier de l'application (zip portable seulement)"
        )
    return problems


# -----------------------------------------------------------------------------
# Windows : version portable et installeur
# -----------------------------------------------------------------------------

PORTABLE_FLAG = "portable.flag"
LAUNCHER_NAME = "Lancer DomainRecon.bat"
PORTABLE_FLAG_TEXT = (
    "Version portable de DomainRecon.\r\n"
    "Tant que ce fichier est présent, les données (base des scans, captures,\r\n"
    "réglages .env, journaux) sont enregistrées dans le dossier data\\ à côté\r\n"
    "de l'exécutable. Supprimez-le pour utiliser %LOCALAPPDATA%\\DomainRecon.\r\n"
)
# Lanceur de la version portable : ASCII et fins de ligne CRLF (lu par cmd.exe).
LAUNCHER_BAT = (
    "@echo off\r\n"
    "rem DomainRecon, version portable : serveur local et navigateur par defaut.\r\n"
    "rem Fermez cette fenetre pour arreter DomainRecon.\r\n"
    "title DomainRecon\r\n"
    'cd /d "%~dp0"\r\n'
    '"%~dp0DomainRecon-console.exe" --browser\r\n'
    "if errorlevel 1 pause\r\n"
)


def make_portable_zip(app_dir: Path, zip_path: Path) -> Path:
    """Zip portable : dossier de l'application + portable.flag + lanceur .bat, sous DomainRecon/.

    Le marqueur et le lanceur ne sont écrits que dans l'archive : le dossier
    private/build/dist/DomainRecon/ reste celui que l'installeur copie.
    """
    top = app_dir.name
    zip_path.parent.mkdir(parents=True, exist_ok=True)
    partial = zip_path.with_name(zip_path.name + ".part")
    try:
        # strict_timestamps=False : une date antérieure à 1980 (fichier d'une dépendance) ne fait pas échouer l'archive.
        with zipfile.ZipFile(
            partial, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=6, strict_timestamps=False
        ) as archive:
            for path in sorted(app_dir.rglob("*")):
                if path.is_file():
                    archive.write(path, f"{top}/{path.relative_to(app_dir).as_posix()}")
            archive.writestr(f"{top}/{PORTABLE_FLAG}", PORTABLE_FLAG_TEXT.encode("utf-8"))
            archive.writestr(f"{top}/{LAUNCHER_NAME}", LAUNCHER_BAT.encode("ascii"))
        os.replace(partial, zip_path)
    except BaseException:
        # Aucune archive partielle ne reste après un échec.
        partial.unlink(missing_ok=True)
        raise
    return zip_path


def find_iscc(environ: Mapping[str, str] | None = None) -> Path | None:
    """ISCC.exe (compilateur Inno Setup 6 ou 7) : variable ISCC, PATH, puis dossiers d'installation usuels.

    Une variable ISCC qui ne désigne pas un fichier est une erreur (BuildError), pas un repli silencieux.
    """
    env = os.environ if environ is None else environ
    explicit = env.get("ISCC")
    if explicit:
        if not Path(explicit).is_file():
            raise BuildError(f"La variable ISCC pointe vers un fichier inexistant : {explicit}")
        return Path(explicit)
    found = shutil.which("ISCC", path=env.get("PATH"))
    if found:
        return Path(found)
    bases = []
    if env.get("LOCALAPPDATA"):
        bases.append(Path(env["LOCALAPPDATA"]) / "Programs")
    for name in ("ProgramFiles(x86)", "ProgramFiles"):
        if env.get(name):
            bases.append(Path(env[name]))
    for base in bases:
        for folder in ("Inno Setup 6", "Inno Setup 7"):
            candidate = base / folder / "ISCC.exe"
            if candidate.is_file():
                return candidate
    return None


def installer_command(iscc: Path, root: Path, app_dir: Path, version: str, output_dir: Path) -> list[str]:
    """Ligne de commande ISCC (silencieuse avec progression)."""
    return [
        str(iscc),
        "/Qp",
        f"/DAppVersion={version}",
        f"/DSourceDir={app_dir}",
        f"/DOutputDir={output_dir}",
        f"/DRepoRoot={root}",
        str(root / "packaging" / "windows" / "installer.iss"),
    ]


def build_installer(root: Path, app_dir: Path, version: str) -> Path:
    """Installeur Inno Setup : release/<version>/DomainRecon-<version>-setup.exe."""
    iscc = find_iscc()
    if iscc is None:
        raise BuildError(
            "Inno Setup introuvable : installez-le (winget install --id JRSoftware.InnoSetup -e) "
            "ou définissez ISCC=<chemin de ISCC.exe>."
        )
    output_dir = pyi_helpers.release_dir(root, version)
    output_dir.mkdir(parents=True, exist_ok=True)
    run(installer_command(iscc, root, app_dir, version, output_dir))
    setup = output_dir / f"DomainRecon-{version}-setup.exe"
    if not setup.is_file():
        raise BuildError(f"Installeur attendu introuvable : {setup}")
    return setup


# -----------------------------------------------------------------------------
# Linux : paquet .deb
# -----------------------------------------------------------------------------

DEB_PLATFORM_KEY = "ubuntu22.04-x64"
# glibc d'Ubuntu 22.04 : l'exécutable y est construit.
BASE_DEPENDS = ("libc6 (>= 2.35)",)
# Fenêtre native (WebKitGTK 4.1) et navigateur par défaut (repli) : recommandés.
BASE_RECOMMENDS = ("libwebkit2gtk-4.1-0", "gir1.2-webkit2-4.1", "xdg-utils")


def _balanced_block(text: str, open_index: int) -> str:
    depth = 0
    for index in range(open_index, len(text)):
        if text[index] == "{":
            depth += 1
        elif text[index] == "}":
            depth -= 1
            if depth == 0:
                return text[open_index : index + 1]
    raise BuildError("Table des dépendances de Playwright mal formée")


def playwright_native_deps(
    playwright_dir: Path, platform_key: str = DEB_PLATFORM_KEY
) -> dict[str, list[str]]:
    """Paquets apt requis par les navigateurs de Playwright, lus dans la table de son pilote.

    `playwright install-deps --dry-run` ne liste plus que les paquets
    manquants sur la machine (Playwright >= 1.5x) : la table embarquée dans
    le pilote (nativeDeps) est la source qu'utilise `install-deps` lui-même.
    """
    lib_dir = playwright_dir / "driver" / "package" / "lib"
    marker = f'"{platform_key}": {{'
    for path in sorted(lib_dir.rglob("*.js")):
        text = path.read_text(encoding="utf-8", errors="replace")
        start = text.find(marker)
        if start == -1:
            continue
        block = _balanced_block(text, start + len(marker) - 1)
        groups = {
            match.group(1): re.findall(r'"([^"]+)"', match.group(2))
            for match in re.finditer(r"(\w+):\s*\[([^\]]*)\]", block)
        }
        if "chromium" in groups and "tools" in groups:
            return groups
    raise BuildError(f"Table des dépendances de Playwright introuvable pour {platform_key} dans {lib_dir}")


def deb_dependencies(groups: Mapping[str, list[str]]) -> tuple[list[str], list[str]]:
    """Depends : bibliothèques de Chromium (+ celles de la liste « tools ») ; Recommends : polices, fenêtre native.

    Xvfb et les polices X11 de la liste « tools » ne servent qu'aux navigateurs
    affichés sans écran : ignorés (DomainRecon n'utilise que le headless shell).
    """
    depends = list(BASE_DEPENDS)
    recommends = list(BASE_RECOMMENDS)
    for name in groups["chromium"]:
        if name not in depends:
            depends.append(name)
    for name in groups["tools"]:
        if name.startswith("lib") and name not in depends:
            depends.append(name)
        elif name.startswith("fonts-") and name not in recommends:
            recommends.append(name)
    return depends, recommends


def build_deb(root: Path, app_dir: Path, version: str, playwright_dir: Path | None = None) -> Path:
    """Paquet release/<version>/domainrecon_<version>_amd64.deb (à construire sur Ubuntu 22.04)."""
    groups = playwright_native_deps(playwright_dir if playwright_dir is not None else _playwright_dir())
    depends, recommends = deb_dependencies(groups)
    output = pyi_helpers.release_dir(root, version) / deb_name(version)
    env = dict(os.environ, DEB_DEPENDS=", ".join(depends), DEB_RECOMMENDS=", ".join(recommends))
    run(
        ["sh", root / "packaging" / "linux" / "build-deb.sh", app_dir, version, output, root],
        env=env,
    )
    return output


# -----------------------------------------------------------------------------
# Livrables : release/<version>/ (SHA256SUMS, NOTES.md)
# -----------------------------------------------------------------------------

CHECKSUMS_NAME = "SHA256SUMS"
NOTES_NAME = "NOTES.md"


def setup_name(version: str) -> str:
    return f"DomainRecon-{version}-setup.exe"


def portable_zip_name(version: str) -> str:
    return f"DomainRecon-{version}-portable-win64.zip"


def deb_name(version: str) -> str:
    return f"domainrecon_{version}_amd64.deb"


def release_names(version: str) -> tuple[str, ...]:
    """Noms des quatre livrables publiés sur la page Releases (les seuls que couvre SHA256SUMS)."""
    return (setup_name(version), onefile_name(version), portable_zip_name(version), deb_name(version))


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def write_checksums(release: Path, version: str) -> Path:
    """release/<version>/SHA256SUMS : « empreinte, deux espaces, nom » (format de sha256sum), livrables présents.

    Seuls les livrables connus comptent (ni NOTES.md, ni un fichier déposé à côté) ;
    BuildError s'il n'y en a aucun.
    """
    names = sorted(name for name in release_names(version) if (release / name).is_file())
    if not names:
        raise BuildError(f"Aucun livrable de la version {version} dans {release}")
    lines = "".join(f"{sha256_file(release / name)}  {name}\n" for name in names)
    output = release / CHECKSUMS_NAME
    partial = output.with_name(output.name + ".part")
    partial.write_bytes(lines.encode("ascii"))
    os.replace(partial, output)
    return output


def release_notes_source(root: Path, version: str) -> Path:
    """Notes de version rédigées dans le dépôt : docs/releases/<version>.md."""
    return root / "docs" / "releases" / f"{version}.md"


def copy_release_notes(root: Path, release: Path, version: str) -> Path | None:
    """Copie docs/releases/<version>.md en release/<version>/NOTES.md ; None si les notes n'existent pas."""
    source = release_notes_source(root, version)
    if not source.is_file():
        return None
    release.mkdir(parents=True, exist_ok=True)
    target = release / NOTES_NAME
    shutil.copyfile(source, target)
    return target


def finalize_release(root: Path, version: str) -> list[Path]:
    """SHA256SUMS et NOTES.md de release/<version>/ ; renvoie les fichiers écrits."""
    release = pyi_helpers.release_dir(root, version)
    written = [write_checksums(release, version)]
    notes = copy_release_notes(root, release, version)
    if notes is not None:
        written.append(notes)
    return written


def package(
    target: str, root: Path, app_dir: Path, version: str, *, skip_installer: bool, skip_onefile: bool = False
) -> list[Path]:
    """Livrables de la plateforme (release/<version>/), en plus du dossier de l'application."""
    artifacts = [app_dir]
    if target == "windows":
        artifacts.append(
            make_portable_zip(app_dir, pyi_helpers.release_dir(root, version) / portable_zip_name(version))
        )
        if not skip_installer:
            artifacts.append(build_installer(root, app_dir, version))
        if not skip_onefile:
            artifacts.append(build_onefile(root, version))
    else:
        artifacts.append(build_deb(root, app_dir, version))
    return artifacts


def build(
    target: str,
    *,
    skip_frontend: bool = False,
    skip_chromium: bool = False,
    skip_installer: bool = False,
    skip_onefile: bool = False,
    root: Path = ROOT,
) -> list[Path]:
    """Construit les livrables de `target` ; renvoie leurs chemins."""
    if target != default_target():
        raise BuildError(
            f"Cible {target} impossible depuis {sys.platform} : PyInstaller ne fait pas de compilation croisée."
        )
    version = pyi_helpers.read_version(root)
    if not skip_frontend:
        build_frontend(root)
    if not (root / "domainrecon" / "web" / "index.html").is_file():
        raise BuildError(
            "Interface absente (domainrecon/web/index.html) : lancez sans --skip-frontend, "
            "ou récupérez l'artefact « web »."
        )
    if not web_sends_heartbeat(root / "domainrecon" / "web"):
        raise BuildError(
            f"Interface périmée (domainrecon/web sans {HEARTBEAT_ROUTE}) : le mode navigateur "
            "s'arrêterait en pleine utilisation. Lancez sans --skip-frontend."
        )
    if not skip_chromium:
        install_chromium(root)
    run_pyinstaller(root)
    app_dir = pyi_helpers.build_dist_dir(root) / pyi_helpers.APP_NAME
    finalize_app_dir(root, app_dir, version, target)
    problems = verify_bundle(app_dir, target)
    if problems:
        raise BuildError("Dossier de l'application incomplet :\n  - " + "\n  - ".join(problems))
    artifacts = package(
        target, root, app_dir, version, skip_installer=skip_installer, skip_onefile=skip_onefile
    )
    return artifacts + finalize_release(root, version)


def output_paths(root: Path, version: str) -> dict[str, Path]:
    """Dossiers de sortie effectifs (options et variables d'environnement comprises)."""
    return {
        "build": pyi_helpers.build_dir(root),
        "chromium": pyi_helpers.build_browsers_dir(root),
        "app": pyi_helpers.build_dist_dir(root) / pyi_helpers.APP_NAME,
        "release": pyi_helpers.release_dir(root, version),
    }


def apply_dir_options(args: argparse.Namespace, environ: dict[str, str] | None = None) -> None:
    """--build-dir / --release-dir -> DOMAINRECON_BUILD_DIR / DOMAINRECON_RELEASE_DIR.

    Passées par l'environnement, les valeurs atteignent aussi les specs PyInstaller (sous-processus).
    """
    env = os.environ if environ is None else environ
    if args.build_dir:
        env[pyi_helpers.BUILD_DIR_ENV] = str(Path(args.build_dir).expanduser().resolve())
    if args.release_dir:
        env[pyi_helpers.RELEASE_DIR_ENV] = str(Path(args.release_dir).expanduser().resolve())


def parse_args(argv: list[str] | None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(prog="build.py", description="Construit les livrables de DomainRecon.")
    parser.add_argument(
        "--target", choices=("windows", "linux"), help="plateforme cible (défaut : la machine)"
    )
    parser.add_argument(
        "--skip-frontend",
        action="store_true",
        help="réutilise domainrecon/web déjà construit (CI : artefact « web »)",
    )
    parser.add_argument(
        "--skip-chromium",
        action="store_true",
        help="ne réinstalle pas Chromium dans private/build/ms-playwright",
    )
    parser.add_argument(
        "--skip-installer", action="store_true", help="Windows : zip portable seulement, sans Inno Setup"
    )
    parser.add_argument(
        "--skip-onefile", action="store_true", help="Windows : sans l'exécutable portable monofichier"
    )
    parser.add_argument(
        "--build-dir",
        metavar="DOSSIER",
        help=f"dossier de travail (défaut : private/build, ou {pyi_helpers.BUILD_DIR_ENV})",
    )
    parser.add_argument(
        "--release-dir",
        metavar="DOSSIER",
        help=f"dossier des livrables, sans la version (défaut : release, ou {pyi_helpers.RELEASE_DIR_ENV})",
    )
    modes = parser.add_mutually_exclusive_group()
    modes.add_argument(
        "--print-version", action="store_true", help="affiche la version du code, puis s'arrête"
    )
    modes.add_argument(
        "--print-paths",
        action="store_true",
        help="affiche les dossiers de sortie (essai à blanc), puis s'arrête",
    )
    modes.add_argument(
        "--checksums",
        action="store_true",
        help="réécrit SHA256SUMS et NOTES.md de release/<version>, puis s'arrête",
    )
    modes.add_argument("--check-tag", metavar="TAG", help="vérifie que TAG vaut v<version>, puis s'arrête")
    modes.add_argument(
        "--lock", action="store_true", help="régénère packaging/requirements.lock (uv), puis s'arrête"
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    apply_dir_options(args)
    try:
        version = pyi_helpers.read_version(ROOT)
        if args.print_version:
            print(version)
            return 0
        if args.print_paths:
            for name, path in output_paths(ROOT, version).items():
                print(f"{name:<9}{path}")
            return 0
        if args.checksums:
            for path in finalize_release(ROOT, version):
                print(path)
            return 0
        if args.check_tag is not None:
            check_tag(args.check_tag, version)
            print(f"Tag {args.check_tag} conforme à la version {version}.")
            return 0
        if args.lock:
            run(lock_command(), cwd=ROOT)
            return 0
        artifacts = build(
            args.target or default_target(),
            skip_frontend=args.skip_frontend,
            skip_chromium=args.skip_chromium,
            skip_installer=args.skip_installer,
            skip_onefile=args.skip_onefile,
        )
    except BuildError as exc:
        print(f"[!] {exc}", file=sys.stderr)
        return 1
    print("\nLivrables :")
    for path in artifacts:
        print(f"  {path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
