"""Dépendances de construction : extras de pyproject.toml et verrou packaging/requirements.lock."""

import re
from pathlib import Path

import pytest

tomllib = pytest.importorskip("tomllib")

ROOT = Path(__file__).resolve().parents[2]
LOCK = ROOT / "packaging" / "requirements.lock"
_NAME_RE = re.compile(r"^([A-Za-z0-9][A-Za-z0-9._-]*)")
_PIN_RE = re.compile(r"^([A-Za-z0-9][A-Za-z0-9._-]*)(?:\[[^\]]*\])?==([^\s;\\]+)(.*)$")


def _normalize(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def _pyproject() -> dict:
    return tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))


def _names(requirements: list[str]) -> set[str]:
    return {_normalize(_NAME_RE.match(req).group(1)) for req in requirements}


def _lock_entries() -> dict[str, tuple[str, str, list[str]]]:
    """Paquets du verrou : nom normalisé -> (version, marqueur, hachages)."""
    entries: dict[str, tuple[str, str, list[str]]] = {}
    current = None
    for line in LOCK.read_text(encoding="utf-8").splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        match = _PIN_RE.match(line)
        if match:
            current = _normalize(match.group(1))
            entries[current] = (match.group(2), match.group(3).strip(" \\;"), [])
        elif current is not None and stripped.startswith("--hash=sha256:"):
            entries[current][2].append(stripped.split(":", 1)[1].rstrip(" \\"))
    return entries


def test_extra_dev_contient_pyyaml():
    assert "pyyaml" in _names(_pyproject()["project"]["optional-dependencies"]["dev"])


def test_extra_gtk_reserve_a_linux():
    extras = _pyproject()["project"]["optional-dependencies"]
    assert extras["gtk"] == ["pywebview[gtk]>=6.2,<7; sys_platform == 'linux'"]


def test_icone_de_fenetre_dans_les_donnees_du_package():
    package_data = _pyproject()["tool"]["setuptools"]["package-data"]["domainrecon"]
    assert package_data == ["i18n/*.json", "i18n/modules/*.json", "web/**/*", "desktop/icon.png"]


def test_verrou_epingle_chaque_dependance_avec_hachages():
    entries = _lock_entries()
    wanted = _names(_pyproject()["project"]["dependencies"]) | {"pyinstaller"}
    for name in sorted(wanted):
        assert name in entries, f"{name} absent de packaging/requirements.lock"
        assert entries[name][2], f"{name} sans hachage dans le verrou"


def test_verrou_pythonnet_reserve_a_windows():
    _, marker, _ = _lock_entries()["pythonnet"]
    assert "sys_platform == 'win32'" in marker


def test_verrou_calcule_pour_python_313():
    assert "--python-version 3.13" in LOCK.read_text(encoding="utf-8")
