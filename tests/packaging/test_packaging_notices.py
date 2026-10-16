"""Avis de tiers (packaging/notices.py) et fichier racine THIRD_PARTY_NOTICES.md."""

import json
from importlib import metadata
from pathlib import Path

import pytest

from pkgload import load, touch

ROOT = Path(__file__).resolve().parents[2]


notices = load("notices", "notices.py")


def _by_name(components):
    return {notices.normalize(component.name): component for component in components}


def test_python_components_suit_les_dependances():
    components = _by_name(notices.python_components(["fastapi>=0.1"]))
    assert {"fastapi", "starlette", "pydantic"} <= set(components)
    assert components["fastapi"].version == metadata.version("fastapi")
    assert all(component.license for component in components.values())
    assert any(text for _, text in components["fastapi"].texts)


def test_python_components_extras():
    plain = set(_by_name(notices.python_components(["uvicorn"])))
    standard = set(_by_name(notices.python_components(["uvicorn[standard]"])))
    assert "websockets" not in plain
    assert "websockets" in standard


def test_python_components_ignore_les_paquets_absents():
    assert notices.python_components(["paquet-inexistant-domainrecon>=1"]) == []


def test_npm_components(tmp_path):
    lock = tmp_path / "package-lock.json"
    packages = {
        "": {"name": "domainrecon-frontend", "version": "1.0.0"},
        "node_modules/react": {"version": "19.3.0", "license": "MIT"},
        "node_modules/@fontsource/inter": {"version": "5.2.8", "license": "OFL-1.1"},
        "node_modules/vitest": {"version": "4.0.0", "license": "MIT", "dev": True},
        "node_modules/fsevents": {"version": "2.3.3", "license": "MIT", "devOptional": True},
    }
    lock.write_text(json.dumps({"lockfileVersion": 3, "packages": packages}), encoding="utf-8")
    touch(tmp_path / "node_modules" / "react" / "LICENSE", "MIT License\nCopyright (c) Meta")
    components = notices.npm_components(lock)
    assert [(c.name, c.version, c.license) for c in components] == [
        ("@fontsource/inter", "5.2.8", "OFL-1.1"),
        ("react", "19.3.0", "MIT"),
    ]
    assert components[1].texts == [("LICENSE", "MIT License\nCopyright (c) Meta")]


def test_npm_components_sans_node_modules(tmp_path):
    """Textes de licence perdus sans signal : la génération exige npm ci."""
    lock = tmp_path / "package-lock.json"
    packages = {
        "": {"name": "domainrecon-frontend"},
        "node_modules/react": {"version": "19.3.0", "license": "MIT"},
    }
    lock.write_text(json.dumps({"lockfileVersion": 3, "packages": packages}), encoding="utf-8")
    with pytest.raises(notices.NoticesError, match="npm ci"):
        notices.npm_components(lock)


def test_npm_components_lockfile_sans_paquet_livre(tmp_path):
    """Rien à livrer côté npm : pas besoin de node_modules."""
    lock = tmp_path / "package-lock.json"
    packages = {"": {"name": "x"}, "node_modules/vitest": {"version": "4.0.0", "dev": True}}
    lock.write_text(json.dumps({"lockfileVersion": 3, "packages": packages}), encoding="utf-8")
    assert notices.npm_components(lock) == []


def test_chromium_version(tmp_path):
    browsers = {
        "browsers": [
            {"name": "chromium", "browserVersion": "1"},
            {"name": "chromium-headless-shell", "browserVersion": "153.0.8010.12"},
        ]
    }
    touch(tmp_path / "driver" / "package" / "browsers.json", json.dumps(browsers))
    assert notices.chromium_version(tmp_path) == "153.0.8010.12"


def test_render_structure_et_clotures():
    python = [
        notices.Component("demo", "1.0", "MIT", "https://exemple.org", [("LICENSE", "texte avec ``` dedans")])
    ]
    text = notices.render("1.0.0", [notices.Component("CPython", "3.13.0", "PSF-2.0")], python, [])
    assert text.startswith("# Avis de tiers — DomainRecon 1.0.0\n")
    assert "| demo | 1.0 | MIT | https://exemple.org |" in text
    assert "## Bibliothèques JavaScript (interface)\n\nAucune." in text
    assert "````text\ntexte avec ``` dedans\n````" in text


def test_finalize_app_dir_ecrit_licence_et_avis(tmp_path, monkeypatch):
    pytest.importorskip("tomllib")
    build = load("build", "build.py")
    root = tmp_path / "depot"
    touch(root / "LICENSE", "MIT License")
    touch(
        root / "pyproject.toml", '[project]\nname = "x"\nversion = "1.0.0"\ndependencies = ["fastapi>=0.1"]\n'
    )
    app = root / "dist" / "DomainRecon"
    app.mkdir(parents=True)
    monkeypatch.setattr(build, "_playwright_dir", lambda: None)
    build.finalize_app_dir(root, app, "1.0.0", "windows")
    assert (app / "LICENSE").read_text(encoding="utf-8") == "MIT License"
    text = (app / "THIRD_PARTY_NOTICES.md").read_text(encoding="utf-8")
    assert "| fastapi |" in text
    assert "| Chromium Headless Shell | ? |" in text


def test_finalize_app_dir_sans_node_modules(tmp_path, monkeypatch):
    """Sans npm ci, build.py s'arrête avec une BuildError au lieu de livrer des avis sans licences npm."""
    pytest.importorskip("tomllib")
    build = load("build", "build.py")
    root = tmp_path / "depot"
    touch(root / "LICENSE", "MIT License")
    touch(root / "pyproject.toml", '[project]\nname = "x"\nversion = "1.0.0"\ndependencies = []\n')
    packages = {"": {"name": "f"}, "node_modules/react": {"version": "19.3.0", "license": "MIT"}}
    touch(root / "frontend" / "package-lock.json", json.dumps({"lockfileVersion": 3, "packages": packages}))
    app = root / "dist" / "DomainRecon"
    app.mkdir(parents=True)
    monkeypatch.setattr(build, "_playwright_dir", lambda: None)
    with pytest.raises(build.BuildError, match="npm ci"):
        build.finalize_app_dir(root, app, "1.0.0", "windows")


def test_fichier_racine_resume_les_composants():
    text = (ROOT / "THIRD_PARTY_NOTICES.md").read_text(encoding="utf-8")
    for component in ("CPython", "PyInstaller", "Chromium", "Playwright", "Node.js", "pywebview", "React"):
        assert component in text, component
    # Polices, carte embarquée et notifications de bureau ; jsPDF (et ses dépendances) a été retiré.
    for component in (
        "plyer",
        "Inter",
        "JetBrains Mono",
        "SIL Open Font License",
        "Natural Earth",
        "world-atlas",
    ):
        assert component in text, component
    for retire in ("jsPDF", "DOMPurify", "pako", "rgbcolor", "CARTO"):
        assert retire not in text, retire
    assert "packaging/notices.py" in text
