"""Documentation et fichiers de configuration du dépôt : README, docs/, .env.example, .gitignore, .gitattributes."""

import re
import shutil
import subprocess
from pathlib import Path

import pytest

from domainrecon import __version__

ROOT = Path(__file__).resolve().parents[2]
README = ROOT / "README.md"
_READ_RE = re.compile(
    r'(?:env_str|env_bool|env_int|env_list|_env)\(\s*"([A-Z][A-Z0-9_]*)"'
    r'|os\.(?:getenv|environ\.get)\(\s*"([A-Z][A-Z0-9_]*)"'
    r'|os\.environ\[\s*"([A-Z][A-Z0-9_]*)"\s*\]'
)
_DOCUMENTED_RE = re.compile(r"^#?\s*([A-Z][A-Z0-9_]*)=", re.MULTILINE)
# Variables du système lues par le code, sans rôle de réglage.
SYSTEM_VARIABLES = {
    "LOCALAPPDATA",
    "APPDATA",
    "XDG_DATA_HOME",
    "XDG_CONFIG_HOME",
    "HOME",
    "USERPROFILE",
    "PLAYWRIGHT_BROWSERS_PATH",
}
# Documentées mais lues par httpx / urllib, pas par le code du projet.
PROXY_VARIABLES = {"HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY"}


def _read_variables() -> set[str]:
    names = set()
    for path in (ROOT / "domainrecon").rglob("*.py"):
        for match in _READ_RE.finditer(path.read_text(encoding="utf-8")):
            names.add(next(group for group in match.groups() if group))
    return names


def _documented_variables() -> set[str]:
    return set(_DOCUMENTED_RE.findall((ROOT / ".env.example").read_text(encoding="utf-8")))


def test_env_example_documente_chaque_variable_lue():
    missing = _read_variables() - SYSTEM_VARIABLES - _documented_variables()
    assert not missing, f"Variables lues par domainrecon/ mais absentes de .env.example : {sorted(missing)}"


def test_env_example_ne_documente_que_des_variables_lues():
    extra = _documented_variables() - PROXY_VARIABLES - _read_variables()
    assert not extra, f"Variables de .env.example lues nulle part dans domainrecon/ : {sorted(extra)}"


DOCS = ROOT / "docs"
# Documentation publiée : README, docs/ et fichiers du projet lus sur GitHub.
DOC_FILES = sorted(
    [README, ROOT / "CHANGELOG.md", ROOT / "CONTRIBUTING.md", ROOT / "SECURITY.md", *DOCS.rglob("*.md")]
)
_LINK_RE = re.compile(r"\]\(([^)\s]+)\)|\bsrc=\"([^\"]+)\"|\bhref=\"([^\"]+)\"")
_EXTERNAL_RE = re.compile(r"^(?:https?://|mailto:)")
_FENCE_RE = re.compile(r"^```.*?^```", re.MULTILINE | re.DOTALL)


def _doc(name: str) -> str:
    return (ROOT / name).read_text(encoding="utf-8")


def _slug(heading: str) -> str:
    """Ancre que GitHub donne à un titre : minuscules, ponctuation retirée, espaces en tirets."""
    return re.sub(r"[^\w\- ]", "", heading.strip().lower()).replace(" ", "-")


def _anchors(path: Path) -> set[str]:
    text = _FENCE_RE.sub("", path.read_text(encoding="utf-8"))
    return {_slug(title) for title in re.findall(r"^#{1,6}\s+(.+?)\s*$", text, flags=re.MULTILINE)}


def _link_targets(text: str) -> list[str]:
    return [next(group for group in groups if group) for groups in _LINK_RE.findall(_FENCE_RE.sub("", text))]


def test_sommaire_de_la_documentation():
    """docs/README.md mène à chaque page de docs/ : aucune page orpheline."""
    index = _doc("docs/README.md")
    for path in DOCS.rglob("*.md"):
        if path == DOCS / "README.md":
            continue
        relative = path.relative_to(DOCS).as_posix()
        assert f"]({relative})" in index, relative


def test_readme_livrables_et_telechargement():
    text = README.read_text(encoding="utf-8")
    for fragment in (
        f"DomainRecon-{__version__}-setup.exe",
        f"DomainRecon-{__version__}-portable-win64.zip",
        f"DomainRecon-{__version__}-portable.exe",
        f"domainrecon_{__version__}_amd64.deb",
        "https://github.com/w4ll-i/DomainRecon/releases",
        "SmartScreen",
        "SHA256SUMS",
        "](docs/README.md)",
        "](LICENSE)",
        "](CONTRIBUTING.md)",
        "](SECURITY.md)",
        "## English",
    ):
        assert fragment in text, fragment


def test_installation_livrables_et_dossiers_de_donnees():
    text = _doc("docs/installation.md")
    for fragment in (
        f"DomainRecon-{__version__}-setup.exe",
        f"DomainRecon-{__version__}-portable-win64.zip",
        f"DomainRecon-{__version__}-portable.exe",
        f"domainrecon_{__version__}_amd64.deb",
        "DomainRecon-data",
        "SmartScreen",
        "Lancer DomainRecon.bat",
        "portable.flag",
        "sha256sum -c --ignore-missing SHA256SUMS",
        "Get-FileHash",
        "gh attestation verify",
        "%LOCALAPPDATA%\\DomainRecon",
        "~/.local/share/domainrecon",
        "private/data/",
    ):
        assert fragment in text, fragment


def test_developpement_et_publication():
    """Commandes de développement, de construction et de publication, avec les dossiers de sortie."""
    developpement = _doc("docs/developpement.md")
    for fragment in (
        'pip install -e ".[dev]"',
        "npm ci",
        "python packaging/build.py --target windows",
        "packaging/build.py --target linux",
        "--require-hashes -r packaging/requirements.lock",
        "private/build/ms-playwright",
        "private/build/dist/DomainRecon",
        "private/data/",
        f"release/{__version__}/domainrecon_{__version__}_amd64.deb",
        "SHA256SUMS",
        "NOTES.md",
        "--print-paths",
        "--checksums",
        "E2E_PYTHON",
    ):
        assert fragment in developpement, fragment
    publication = _doc("docs/publication.md")
    for fragment in (f"git tag v{__version__}", "release.yml", "release/<version>/", "NOTES.md", "brouillon"):
        assert fragment in publication, fragment


def test_developpement_cite_les_dossiers_du_build():
    """Les dossiers et variables cités par docs/developpement.md sont les défauts réels de packaging/."""
    from pkgload import load

    helpers = load("pyi_helpers", "pyi_helpers.py")
    text = _doc("docs/developpement.md")
    assert f"`{helpers.DEFAULT_BUILD_DIR.as_posix()}/`" in text
    assert f"`{helpers.DEFAULT_RELEASE_DIR.as_posix()}/<version>/`" in text
    assert helpers.BUILD_DIR_ENV in text
    assert helpers.RELEASE_DIR_ENV in text


def test_ligne_de_commande_documente_le_lanceur_et_les_sous_commandes():
    """Modes, ports, repli navigateur et sous-commandes : écarts d'avec le code = documentation fausse."""
    from domainrecon.desktop import launcher

    text = _doc("docs/ligne-de-commande.md")
    for fragment in (
        "--browser",
        "--server",
        "--host",
        "--port",
        "--no-open",
        "--version",
        str(launcher.PREFERRED_APP_PORT),
        str(launcher.DEFAULT_SERVER_PORT),
        "WebView2",
        "DomainRecon-console.exe",
        "--fail-under",
        "--authorized",
    ):
        assert fragment in text, fragment
    for command in ("scan", "batch", "history", "export", "modules", "import", "monitor"):
        assert f"| `{command}` |" in text, command
    for action in ("run-due", "list", "task install"):
        assert f"monitor {action}" in text, action
    assert "Cert Spotter" in _doc("docs/confidentialite.md")


def test_readme_nombre_de_ports_testes():
    """Le README annonce le nombre réel de ports sondés par le scanner."""
    from domainrecon.scanner.network import COMMON_PORTS

    text = README.read_text(encoding="utf-8")
    assert f"{len(COMMON_PORTS)} ports" in text


def test_readme_badge_de_version():
    """Le badge du README suit __version__ (à mettre à jour à chaque release)."""
    text = README.read_text(encoding="utf-8")
    match = re.search(r"img\.shields\.io/badge/version-((?:[^-]|--)+)-[0-9A-Fa-f]{3,8}\b", text)
    assert match, "badge de version absent du README"
    # shields.io double les tirets du texte (1.1.0-rc1 -> 1.1.0--rc1).
    assert match.group(1).replace("--", "-") == __version__
    assert f'alt="Version {__version__}"' in text


FAMILY_LABELS = {
    "web": "Web",
    "tls": "TLS",
    "email": "E-mail",
    "dns": "DNS et sous-domaines",
    "network": "Réseau",
    "identity": "Identité",
    "reputation": "Réputation",
    "leaks": "Fuites de données",
}
CATEGORY_LABELS = {"passif": "Passif", "actif": "Actif", "cle_api": "Clé d'API", "sensible": "Sensible"}


def test_modules_documentes_selon_le_registre():
    """docs/modules.md liste exactement les modules du registre, avec leur famille et leur catégorie."""
    from domainrecon.scanner import registry

    assert set(FAMILY_LABELS) == set(registry.FAMILIES)
    assert set(CATEGORY_LABELS) == set(registry.CATEGORIES)
    text = _doc("docs/modules.md")
    sections = dict(re.findall(r"^### (.+?)\n(.*?)(?=^#{2,3} |\Z)", text, flags=re.MULTILINE | re.DOTALL))
    documented: dict[str, tuple[str, str]] = {}
    for family, label in FAMILY_LABELS.items():
        assert label in sections, label
        for name, category in re.findall(
            r"^\| [^|]+ \| `([a-z0-9_]+)` \| ([^|]+?) \|", sections[label], re.MULTILINE
        ):
            assert name not in documented, f"{name} documenté deux fois"
            documented[name] = (family, category)
    expected = {
        name: (spec.family, CATEGORY_LABELS[spec.category]) for name, spec in registry.MODULES.items()
    }
    assert documented == expected
    assert f"**{len(expected)} modules**" in text
    assert f"**{len(expected)} modules**" in README.read_text(encoding="utf-8")
    for category, label in CATEGORY_LABELS.items():
        count = sum(1 for spec in registry.MODULES.values() if spec.category == category)
        assert f"| {label} | {count} |" in text, label


def test_notes_de_version_et_changelog():
    """Notes de la version courante (texte de la release) et entrée datée du CHANGELOG."""
    notes = DOCS / "releases" / f"{__version__}.md"
    assert notes.is_file(), notes
    text = notes.read_text(encoding="utf-8")
    for fragment in (
        f"DomainRecon-{__version__}-setup.exe",
        f"DomainRecon-{__version__}-portable-win64.zip",
        f"DomainRecon-{__version__}-portable.exe",
        f"domainrecon_{__version__}_amd64.deb",
        "SHA256SUMS",
        "SmartScreen",
    ):
        assert fragment in text, fragment
    # Texte de la page Release : un lien relatif n'y mènerait nulle part.
    for target in _link_targets(text):
        assert _EXTERNAL_RE.match(target), f"lien relatif dans les notes de version : {target}"
    changelog = _doc("CHANGELOG.md")
    assert re.search(rf"^## \[{re.escape(__version__)}\] - \d{{4}}-\d{{2}}-\d{{2}}$", changelog, re.MULTILINE)
    assert f"[{__version__}]: https://github.com/w4ll-i/DomainRecon/releases/tag/v{__version__}" in changelog


def test_modeles_github():
    """Modèles de tickets (YAML valide, au moins un champ requis) et de demande de fusion."""
    yaml = pytest.importorskip("yaml")
    templates = ROOT / ".github" / "ISSUE_TEMPLATE"
    for name in ("bogue.yml", "idee.yml"):
        form = yaml.safe_load((templates / name).read_text(encoding="utf-8"))
        assert form["name"] and form["description"], name
        assert any(item.get("validations", {}).get("required") for item in form["body"]), name
    config = yaml.safe_load((templates / "config.yml").read_text(encoding="utf-8"))
    assert config["blank_issues_enabled"] is False
    template = (ROOT / ".github" / "pull_request_template.md").read_text(encoding="utf-8")
    assert "python -m pytest -q" in template


def test_documentation_sans_reference_obsolete():
    """Rien de l'ancienne organisation (Docker, run.py, requirements*.txt…) ; « API Docker » reste permis."""
    for path in DOC_FILES:
        text = path.read_text(encoding="utf-8").lower()
        for obsolete in (
            "docker run",
            "docker-compose",
            "docker compose",
            "dockerfile",
            "run.py",
            "backend/app",
            "index.html (html/css/js",
        ):
            assert obsolete not in text, f"{path.name} : {obsolete}"
        assert not re.search(r"requirements[\w.-]*\.txt", text), f"{path.name} : requirements*.txt"


def test_documentation_sans_tiret_cadratin():
    for path in DOC_FILES:
        if path.name == "contrat-modules.md":
            continue
        assert "—" not in path.read_text(encoding="utf-8"), path.relative_to(ROOT).as_posix()


def test_documentation_liens_locaux_valides():
    """Chaque lien relatif (Markdown, src, href) mène à un fichier du dépôt, et à un titre existant s'il a une ancre."""
    for path in DOC_FILES:
        for target in _link_targets(path.read_text(encoding="utf-8")):
            if _EXTERNAL_RE.match(target):
                continue
            location, _, anchor = target.partition("#")
            destination = (path.parent / location).resolve() if location else path
            name = f"{path.relative_to(ROOT).as_posix()} -> {target}"
            assert destination.exists(), name
            assert destination == ROOT or ROOT in destination.parents, name
            if anchor and destination.suffix == ".md":
                assert anchor in _anchors(destination), name


def test_captures_de_la_documentation():
    """Captures en PNG, de poids raisonnable, toutes utilisées par la documentation."""
    shots = sorted((DOCS / "assets" / "screenshots").iterdir())
    assert shots, "aucune capture"
    corpus = "\n".join(path.read_text(encoding="utf-8") for path in DOC_FILES)
    for shot in shots:
        assert shot.suffix == ".png", shot.name
        assert shot.read_bytes()[:8] == b"\x89PNG\r\n\x1a\n", shot.name
        assert shot.stat().st_size <= 300_000, shot.name
        assert f"screenshots/{shot.name}" in corpus, f"capture inutilisée : {shot.name}"


def test_docs_sans_adresse_e_mail():
    """Aucune information personnelle dans la documentation publiée."""
    for path in [*DOC_FILES, ROOT / ".env.example"]:
        text = path.read_text(encoding="utf-8")
        assert not re.search(r"[\w.+-]+@[\w-]+\.[A-Za-z]{2,}", text), path.name


def test_gitignore():
    lines = (ROOT / ".gitignore").read_text(encoding="utf-8").splitlines()
    for entry in (
        "/private/",
        "/release/",
        "/build/",
        "/dist/",
        "/data/",
        "domainrecon/web/",
        "node_modules/",
        "*.egg-info/",
        ".env",
        "__pycache__/",
        "/frontend/playwright-report/",
        "/frontend/test-results/",
    ):
        assert entry in lines, entry
    assert any(line.startswith(".venv") for line in lines), "environnement virtuel non ignoré"
    assert not any(line.strip().endswith(".spec") for line in lines), "la spec PyInstaller doit être suivie"


def test_gitignore_minimal():
    """Une règle par ligne : ni commentaire, ni ligne vide, ni doublon, ni espace parasite."""
    raw = (ROOT / ".gitignore").read_bytes()
    assert b"\r" not in raw and raw.endswith(b"\n") and not raw.startswith(b"\xef\xbb\xbf")
    lines = raw.decode("utf-8").splitlines()
    assert lines, ".gitignore vide"
    for line in lines:
        assert line and line == line.strip(), repr(line)
        assert not line.startswith("#"), line
    assert len(lines) == len(set(lines)), "règle en double"


# Chemins suivis (ou à suivre) et chemins générés ; un dossier finit par « / ».
MUST_BE_TRACKED = (
    "pyproject.toml",
    "domainrecon/__init__.py",
    "packaging/build.py",
    "packaging/domainrecon.spec",
    "packaging/requirements.lock",
    "packaging/icons/domainrecon.ico",
    "packaging/icons/domainrecon-256.png",
    "packaging/icons/logo.svg",
    "domainrecon/desktop/icon.png",
    "frontend/package.json",
    "frontend/package-lock.json",
    "frontend/src/main.tsx",
    "tests/conftest.py",
    ".github/workflows/release.yml",
    ".env.example",
)
MUST_BE_IGNORED = (
    "private/",
    "private/build/ms-playwright/",
    "private/data/domainrecon.db",
    "release/",
    "release/1.0.0/SHA256SUMS",
    "build/",
    "dist/",
    "data/",
    "domainrecon/web/",
    "frontend/node_modules/",
    "frontend/playwright-report/",
    "frontend/test-results/",
    "frontend/coverage/",
    ".pytest_cache/",
    ".ruff_cache/",
    ".coverage",
    "domainrecon/__pycache__/",
    ".env",
    ".env.local",
)


def test_gitignore_selon_git():
    """Verdict de git lui-même (check-ignore, lecture seule), règles négatives et motifs compris."""
    git = shutil.which("git")
    if not git:
        pytest.skip("git absent")
    # --no-index : juge sur les seules règles, que le chemin soit suivi ou non ;
    # core.excludesFile vide : le fichier d'exclusion global du poste ne compte pas.
    result = subprocess.run(
        [git, "-c", "safe.directory=*", "-c", "core.excludesFile=", "check-ignore", "--no-index", "--"]
        + list(MUST_BE_TRACKED + MUST_BE_IGNORED),
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode not in (0, 1):
        if "not a git repository" in result.stderr.lower():
            pytest.skip("hors d'un dépôt git")
        pytest.fail(f"git check-ignore : {result.stderr.strip()}")
    ignored = set(result.stdout.splitlines())
    wrongly_ignored = sorted(ignored.intersection(MUST_BE_TRACKED))
    assert not wrongly_ignored, f"Ignorés à tort : {wrongly_ignored}"
    not_ignored = sorted(set(MUST_BE_IGNORED) - ignored)
    assert not not_ignored, f"Non ignorés : {not_ignored}"


def test_gitattributes_fichiers_du_paquet_en_lf():
    lines = (ROOT / ".gitattributes").read_text(encoding="utf-8").splitlines()
    for entry in (
        "*.sh text eol=lf",
        "packaging/linux/postinst text eol=lf",
        "packaging/linux/control.in text eol=lf",
        "packaging/linux/*.desktop text eol=lf",
        "*.bat text eol=crlf",
        "*.ico binary",
        "*.png binary",
        "*.woff2 binary",
    ):
        assert entry in lines, entry
