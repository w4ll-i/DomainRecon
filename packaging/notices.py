#!/usr/bin/env python3
"""Génère THIRD_PARTY_NOTICES.md : licences des composants tiers livrés avec DomainRecon.

Appelé par packaging/build.py pour le dossier de l'application ; à la main :
    python packaging/notices.py --output avis.md --version 1.0.0
Sources : métadonnées des paquets Python installés (dépendances de
pyproject.toml, suivies récursivement), frontend/package-lock.json (paquets
npm hors développement, textes lus dans node_modules/) et composants
embarqués (CPython, chargeur PyInstaller, Chromium, Node.js du pilote Playwright).
"""

from __future__ import annotations

import argparse
import json
import platform
import re
import sys
from collections.abc import Iterable
from dataclasses import dataclass, field
from importlib import metadata
from pathlib import Path

from packaging.requirements import Requirement

ROOT = Path(__file__).resolve().parents[1]
LICENSE_FILE_RE = re.compile(r"^(licen[cs]e|copying|notice|authors)([._-].*)?$", re.IGNORECASE)
_SOURCE_LABELS = ("homepage", "home", "source", "source code", "repository")


class NoticesError(Exception):
    """Avis de tiers impossibles à produire correctement (message destiné à l'utilisateur)."""


@dataclass
class Component:
    """Composant tiers : nom, version, licence déclarée, adresse et textes de licence (fichier, contenu)."""

    name: str
    version: str
    license: str
    source: str = ""
    texts: list[tuple[str, str]] = field(default_factory=list)


def normalize(name: str) -> str:
    """Nom de paquet normalisé (PEP 503)."""
    return re.sub(r"[-_.]+", "-", name).lower()


def _license_of(dist: metadata.Distribution) -> str:
    meta = dist.metadata
    expression = (meta.get("License-Expression") or "").strip()
    if expression:
        return expression
    declared = (meta.get("License") or "").strip()
    if declared and "\n" not in declared and len(declared) <= 80:
        return declared
    classifiers = [
        value.split("::")[-1].strip()
        for value in meta.get_all("Classifier") or []
        if value.startswith("License ::")
    ]
    if classifiers:
        return ", ".join(classifiers)
    return "non déclarée (voir le texte de licence)"


def _source_of(dist: metadata.Distribution) -> str:
    meta = dist.metadata
    for entry in meta.get_all("Project-URL") or []:
        label, _, url = entry.partition(",")
        if label.strip().lower() in _SOURCE_LABELS:
            return url.strip()
    return (meta.get("Home-page") or "").strip()


def _license_texts(dist: metadata.Distribution) -> list[tuple[str, str]]:
    texts = []
    for file in dist.files or []:
        parts = file.parts
        if not parts or not parts[0].endswith(".dist-info"):
            continue
        in_licenses_dir = len(parts) > 2 and parts[1] == "licenses"
        if not in_licenses_dir and not LICENSE_FILE_RE.match(file.name):
            continue
        path = Path(dist.locate_file(file))
        if path.is_file():
            texts.append((file.name, path.read_text(encoding="utf-8", errors="replace")))
    return texts


def python_components(requirements: Iterable[str]) -> list[Component]:
    """Paquets Python installés dont dépend l'application, dépendances des dépendances comprises.

    Les marqueurs (plateforme, extras) sont évalués sur la machine courante :
    un paquet d'une autre plateforme (pythonnet sous Linux…) est ignoré.
    """
    components: dict[str, Component] = {}
    visited: set[tuple[str, frozenset[str]]] = set()
    queue = []
    for spec in requirements:
        requirement = Requirement(spec)
        queue.append((requirement.name, frozenset(requirement.extras)))
    while queue:
        name, extras = queue.pop(0)
        key = normalize(name)
        if (key, extras) in visited:
            continue
        visited.add((key, extras))
        try:
            dist = metadata.distribution(name)
        except metadata.PackageNotFoundError:
            continue
        if key not in components:
            components[key] = Component(
                dist.metadata["Name"], dist.version, _license_of(dist), _source_of(dist), _license_texts(dist)
            )
        for spec in dist.requires or []:
            requirement = Requirement(spec)
            marker = requirement.marker
            if marker is not None and not any(
                marker.evaluate({"extra": extra}) for extra in (extras or {""})
            ):
                continue
            queue.append((requirement.name, frozenset(requirement.extras)))
    return sorted(components.values(), key=lambda component: normalize(component.name))


def npm_components(lock_path: Path) -> list[Component]:
    """Paquets npm livrés dans l'interface (hors dépendances de développement) d'après package-lock.json."""
    data = json.loads(lock_path.read_text(encoding="utf-8"))
    components: dict[tuple[str, str], Component] = {}
    for key, entry in (data.get("packages") or {}).items():
        if not key or entry.get("dev") or entry.get("devOptional") or entry.get("link"):
            continue
        name = entry.get("name") or key.rsplit("node_modules/", 1)[-1]
        version = str(entry.get("version", "?"))
        texts = []
        package_dir = lock_path.parent / key
        if package_dir.is_dir():
            for path in sorted(package_dir.iterdir()):
                if path.is_file() and LICENSE_FILE_RE.match(path.name):
                    texts.append((path.name, path.read_text(encoding="utf-8", errors="replace")))
        components[(name, version)] = Component(
            name,
            version,
            str(entry.get("license") or "non déclarée"),
            f"https://www.npmjs.com/package/{name}",
            texts,
        )
    if components and not (lock_path.parent / "node_modules").is_dir():
        raise NoticesError(
            f"{lock_path.parent / 'node_modules'} absent : les textes de licence des paquets npm "
            "seraient perdus. Lancez d'abord « npm ci » dans frontend/."
        )
    return sorted(components.values(), key=lambda component: (component.name.lower(), component.version))


def chromium_version(playwright_dir: Path) -> str:
    """Version du Chromium Headless Shell fourni par cette version de Playwright."""
    data = json.loads((playwright_dir / "driver" / "package" / "browsers.json").read_text(encoding="utf-8"))
    for browser in data.get("browsers", []):
        if browser.get("name") == "chromium-headless-shell":
            return str(browser.get("browserVersion") or browser.get("revision") or "?")
    return "?"


def embedded_components(playwright_dir: Path | None) -> list[Component]:
    """Composants embarqués qui ne sont pas des paquets Python ou npm."""
    try:
        pyinstaller_version = metadata.version("pyinstaller")
    except metadata.PackageNotFoundError:
        pyinstaller_version = "?"
    chromium = chromium_version(playwright_dir) if playwright_dir is not None else "?"
    return [
        Component("CPython", platform.python_version(), "PSF-2.0", "https://docs.python.org/3/license.html"),
        Component(
            "PyInstaller (chargeur des exécutables)",
            pyinstaller_version,
            "GPL-2.0-or-later avec exception pour le chargeur (bootloader)",
            "https://pyinstaller.org/en/stable/license.html",
        ),
        Component(
            "Chromium Headless Shell",
            chromium,
            "BSD-3-Clause et licences de ses composants (texte complet : LICENSE.headless_shell, livré avec le navigateur)",
            "https://www.chromium.org/",
        ),
        Component(
            "Node.js (pilote Playwright)",
            "fourni par Playwright",
            "MIT et licences de ses composants (voir aussi driver/package/ThirdPartyNotices.txt)",
            "https://github.com/nodejs/node/blob/main/LICENSE",
        ),
    ]


def project_dependencies(pyproject: Path) -> list[str]:
    """Dépendances directes déclarées dans pyproject.toml.

    Python 3.11+ (tomllib) : utilisé seulement au build (Python 3.13), pas par l'application (3.10+).
    """
    import tomllib

    data = tomllib.loads(pyproject.read_text(encoding="utf-8"))
    return list(data["project"]["dependencies"])


def _fence(text: str) -> str:
    longest = max((len(match.group(0)) for match in re.finditer(r"`+", text)), default=0)
    return "`" * max(3, longest + 1)


def _cell(value: str) -> str:
    return value.replace("|", "\\|").replace("\n", " ")


def render(version: str, embedded: list[Component], python: list[Component], npm: list[Component]) -> str:
    """Contenu Markdown de THIRD_PARTY_NOTICES.md."""
    lines = [
        f"# Avis de tiers — DomainRecon {version}",
        "",
        "DomainRecon est un logiciel à code source disponible (fichier `LICENSE`). Il embarque les",
        "composants tiers ci-dessous, chacun sous sa propre licence. Ce fichier est",
        "généré à la construction du paquet (`packaging/notices.py`).",
        "",
    ]
    sections = (
        ("Composants embarqués", embedded),
        ("Bibliothèques Python", python),
        ("Bibliothèques JavaScript (interface)", npm),
    )
    for title, components in sections:
        lines += [f"## {title}", ""]
        if not components:
            lines += ["Aucune.", ""]
            continue
        lines += ["| Composant | Version | Licence | Source |", "|---|---|---|---|"]
        lines += [
            f"| {_cell(c.name)} | {_cell(c.version)} | {_cell(c.license)} | {_cell(c.source)} |"
            for c in components
        ]
        lines.append("")
    lines += ["## Textes des licences", ""]
    for component in [*python, *npm]:
        for filename, text in component.texts:
            fence = _fence(text)
            lines += [
                f"### {component.name} {component.version} — {filename}",
                "",
                fence + "text",
                text.rstrip("\n"),
                fence,
                "",
            ]
    return "\n".join(lines) + "\n"


def write_notices(
    output: Path,
    version: str,
    *,
    pyproject: Path,
    frontend_lock: Path,
    playwright_dir: Path | None,
    extra_requirements: Iterable[str] = (),
) -> Path:
    """Écrit THIRD_PARTY_NOTICES.md pour l'environnement de build courant."""
    python = python_components([*project_dependencies(pyproject), *extra_requirements])
    npm = npm_components(frontend_lock) if frontend_lock.is_file() else []
    output.write_text(render(version, embedded_components(playwright_dir), python, npm), encoding="utf-8")
    return output


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="notices.py", description="Génère THIRD_PARTY_NOTICES.md.")
    parser.add_argument("--output", type=Path, required=True, help="fichier à écrire")
    parser.add_argument("--version", required=True, help="version de DomainRecon")
    parser.add_argument(
        "--extra",
        action="append",
        default=[],
        help="paquet Python embarqué en plus des dépendances (répétable)",
    )
    args = parser.parse_args(argv)
    try:
        import playwright
    except ImportError:
        playwright_dir = None
    else:
        playwright_dir = Path(playwright.__file__).resolve().parent
    try:
        write_notices(
            args.output,
            args.version,
            pyproject=ROOT / "pyproject.toml",
            frontend_lock=ROOT / "frontend" / "package-lock.json",
            playwright_dir=playwright_dir,
            extra_requirements=args.extra,
        )
    except NoticesError as exc:
        print(f"[!] {exc}", file=sys.stderr)
        return 1
    print(f"Avis de tiers écrits dans {args.output}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
