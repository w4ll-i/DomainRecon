"""Workflows GitHub Actions et Dependabot."""

import re
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[2]
WORKFLOWS = ROOT / ".github" / "workflows"
EXPRESSION_START = re.compile(r"\$\{\{\s*")
# Seule suite admise dans un script : une référence simple à matrix.* ou needs.*
# (valeurs fixées par le dépôt), sans opérateur ni autre contexte.
ALLOWED_IN_RUN = re.compile(r"(?:matrix|needs)\.[\w.-]+\s*\}\}")
VERSION = "${{ needs.version.outputs.version }}"
ACTION_MAJORS = {
    "actions/checkout": "v7",
    "actions/setup-python": "v7",
    "actions/setup-node": "v7",
    "actions/upload-artifact": "v7",
    "actions/download-artifact": "v8",
    "actions/attest-build-provenance": "v4",
    "softprops/action-gh-release": "v3",
}


def _load_yaml(path: Path) -> dict:
    return yaml.safe_load(path.read_text(encoding="utf-8"))


def _triggers(workflow: dict) -> dict:
    # YAML 1.1 : la clé « on » est lue comme le booléen True.
    return workflow.get("on", workflow.get(True))


def _steps(workflow: dict):
    for job in workflow["jobs"].values():
        yield from job.get("steps", [])


def _runs(job: dict) -> str:
    return "\n".join(step.get("run", "") for step in job["steps"])


def _uses(steps, action: str) -> list[dict]:
    return [step for step in steps if step.get("uses", "").startswith(action + "@")]


def _unsafe_expressions(run: str) -> list[str]:
    """Expressions ${{ }} d'un script hors liste blanche (début de l'expression, pour le message)."""
    return [
        run[match.start() : match.start() + 60]
        for match in EXPRESSION_START.finditer(run)
        if not ALLOWED_IN_RUN.match(run, match.end())
    ]


@pytest.mark.parametrize("name", ["ci.yml", "release.yml"])
def test_actions_epinglees_sur_la_version_majeure(name):
    for step in _steps(_load_yaml(WORKFLOWS / name)):
        if "uses" in step:
            action, _, ref = step["uses"].partition("@")
            assert ACTION_MAJORS.get(action) == ref, step["uses"]


def test_ci_declencheurs_et_permissions():
    ci = _load_yaml(WORKFLOWS / "ci.yml")
    triggers = _triggers(ci)
    assert triggers["push"]["branches"] == ["main"]
    assert "pull_request" in triggers
    assert ci["permissions"] == {"contents": "read"}


def test_ci_jobs():
    assert set(_load_yaml(WORKFLOWS / "ci.yml")["jobs"]) == {
        "lint",
        "test",
        "test-minimal",
        "frontend",
        "e2e",
        "linux-package",
    }


def test_ci_interface():
    jobs = _load_yaml(WORKFLOWS / "ci.yml")["jobs"]
    frontend_runs = [step.get("run") for step in jobs["frontend"]["steps"]]
    for command in ("npm ci", "npm run typecheck", "npm run lint", "npm run test", "npm run build"):
        assert command in frontend_runs, command
    assert jobs["frontend"]["defaults"]["run"]["working-directory"] == "frontend"


def test_ci_e2e_sur_le_backend_reel():
    e2e = _runs(_load_yaml(WORKFLOWS / "ci.yml")["jobs"]["e2e"])
    assert 'pip install -e ".[dev]"' in e2e
    assert "npm run build" in e2e
    assert "npx playwright install --with-deps chromium" in e2e
    assert "npm run e2e" in e2e
    e2e_step = next(
        s for s in _load_yaml(WORKFLOWS / "ci.yml")["jobs"]["e2e"]["steps"] if s.get("run") == "npm run e2e"
    )
    assert e2e_step["env"]["E2E_PYTHON"] == "python"


def test_ci_fichiers_du_paquet_linux():
    runs = _runs(_load_yaml(WORKFLOWS / "ci.yml")["jobs"]["linux-package"])
    assert "desktop-file-validate packaging/linux/domainrecon.desktop" in runs
    assert "sh -n packaging/linux/build-deb.sh" in runs
    assert "sh -n packaging/linux/postinst" in runs


def test_ci_mots_interdits_par_la_phase_1():
    text = (WORKFLOWS / "ci.yml").read_text(encoding="utf-8").lower()
    for word in ("docker", "hadolint", "shellcheck", "requirements"):
        assert word not in text, word


def test_dependabot():
    config = _load_yaml(ROOT / ".github" / "dependabot.yml")
    assert config["version"] == 2
    assert {(u["package-ecosystem"], u["directory"]) for u in config["updates"]} == {
        ("pip", "/"),
        ("npm", "/frontend"),
        ("github-actions", "/"),
    }


def test_pas_d_expression_github_dans_les_scripts():
    """Injection de modèle : les valeurs contrôlables passent par l'environnement, jamais par ${{ }} dans run."""
    for path in WORKFLOWS.glob("*.yml"):
        for step in _steps(_load_yaml(path)):
            assert _unsafe_expressions(step.get("run", "")) == [], path.name


@pytest.mark.parametrize(
    ("run", "unsafe"),
    [
        ("apt-get install ${{ matrix.apt-options }} ./x.deb", False),
        ("echo ${{matrix.image}}", False),
        (f"echo {VERSION}", False),
        ("echo ${{ github.event.head_commit.message }}", True),
        ("echo ${{github.head_ref}}", True),
        ("echo ${{ env.TITLE }}", True),
        ("echo ${{ inputs.tag }}", True),
        ("echo ${{ matrix.image || github.ref_name }}", True),
    ],
)
def test_garde_fou_d_injection(run, unsafe):
    assert bool(_unsafe_expressions(run)) is unsafe


@pytest.mark.parametrize("name", ["ci.yml", "release.yml"])
def test_checkout_sans_identifiants_persistants(name):
    checkouts = _uses(_steps(_load_yaml(WORKFLOWS / name)), "actions/checkout")
    assert checkouts
    for step in checkouts:
        assert step["with"]["persist-credentials"] is False, step


def test_release_declencheurs_et_permissions_minimales():
    release = _load_yaml(WORKFLOWS / "release.yml")
    triggers = _triggers(release)
    assert triggers["push"]["tags"] == ["v*"]
    assert "workflow_dispatch" in triggers
    assert release["permissions"] == {}
    for name, job in release["jobs"].items():
        if name == "release":
            assert job["permissions"] == {"contents": "write", "id-token": "write", "attestations": "write"}
        else:
            assert job["permissions"] == {"contents": "read"}, name


def test_release_jobs_et_plateformes():
    jobs = _load_yaml(WORKFLOWS / "release.yml")["jobs"]
    assert set(jobs) == {"version", "frontend", "windows", "linux", "smoke-deb", "release"}
    assert jobs["windows"]["runs-on"] == "windows-latest"
    assert jobs["linux"]["runs-on"] == "ubuntu-22.04"
    assert set(jobs["windows"]["needs"]) == {"version", "frontend"}
    assert set(jobs["linux"]["needs"]) == {"version", "frontend"}
    assert set(jobs["release"]["needs"]) == {"version", "windows", "linux", "smoke-deb"}
    assert jobs["release"]["if"] == "startsWith(github.ref, 'refs/tags/v')"


def test_release_verifie_le_tag_et_les_dependances_figees():
    jobs = _load_yaml(WORKFLOWS / "release.yml")["jobs"]
    assert 'packaging/build.py --check-tag "$GITHUB_REF_NAME"' in _runs(jobs["version"])
    for name in ("windows", "linux"):
        runs = _runs(jobs[name])
        assert "pip install --require-hashes -r packaging/requirements.lock" in runs, name
        assert "--skip-frontend" in runs, name


def test_release_tests_de_fumee():
    jobs = _load_yaml(WORKFLOWS / "release.yml")["jobs"]
    windows = _runs(jobs["windows"])
    assert windows.count("packaging/smoke_test.py") == 5
    assert "-portable.exe" in windows and "DomainRecon-data/domainrecon.db" in windows
    assert "LOCALAPPDATA" in windows
    assert "--scan example.com" in windows
    assert "DomainRecon.exe" in windows and "--no-capture" in windows and "logs/domainrecon.log" in windows
    assert "portable.flag" in windows
    assert "unins000.exe" in windows
    images = [entry["image"] for entry in jobs["smoke-deb"]["strategy"]["matrix"]["include"]]
    assert images == ["ubuntu:22.04", "ubuntu:24.04", "debian:12"]
    deb = _runs(jobs["smoke-deb"])
    assert "--exe /usr/bin/domainrecon" in deb
    assert "--scan example.com" in deb


RELEASE_DIR = f"release/{VERSION}"


def test_release_publication_brouillon():
    steps = _load_yaml(WORKFLOWS / "release.yml")["jobs"]["release"]["steps"]
    assert any("sha256sum" in step.get("run", "") for step in steps)
    attest = next(s for s in steps if s.get("uses", "").startswith("actions/attest-build-provenance@"))
    assert attest["with"]["subject-checksums"] == f"{RELEASE_DIR}/SHA256SUMS"
    publish = next(s for s in steps if s.get("uses", "").startswith("softprops/action-gh-release@"))
    assert publish["with"]["draft"] is True
    assert publish["with"]["generate_release_notes"] is True
    assert publish["with"]["fail_on_unmatched_files"] is True
    assert f"{RELEASE_DIR}/SHA256SUMS" in publish["with"]["files"]
    # Corps de la release : NOTES.md (copie de docs/releases/<version>.md).
    assert publish["with"]["body_path"] == f"{RELEASE_DIR}/NOTES.md"


def test_release_livrables_dans_release_version():
    """Comme en local : artefacts téléchargés dans release/<version>/, sommes calculées là."""
    jobs = _load_yaml(WORKFLOWS / "release.yml")["jobs"]
    steps = jobs["release"]["steps"]
    download = _uses(steps, "actions/download-artifact")[0]
    assert download["with"]["path"] == RELEASE_DIR
    assert download["with"]["merge-multiple"] is True
    checksums = next(s for s in steps if "sha256sum" in s.get("run", ""))
    assert checksums["working-directory"] == RELEASE_DIR
    assert "sha256sum -- * > SHA256SUMS" in checksums["run"]
    notes = next(s for s in steps if "NOTES.md" in s.get("run", ""))
    assert 'notes="docs/releases/${VERSION}.md"' in notes["run"]
    assert 'cp "$notes" "release/${VERSION}/NOTES.md"' in notes["run"]
    # NOTES.md est écrit après les sommes : il n'est pas couvert par SHA256SUMS.
    assert steps.index(checksums) < steps.index(notes)
    assert jobs["release"]["env"]["VERSION"] == VERSION
    assert _uses(steps, "actions/checkout"), "checkout requis pour docs/releases"


def test_release_chemins_de_construction():
    """Builds : application dans private/build/dist, livrables dans release/<version>/, plus de dist/."""
    jobs = _load_yaml(WORKFLOWS / "release.yml")["jobs"]
    windows = _runs(jobs["windows"])
    assert "private/build/dist/DomainRecon/DomainRecon-console.exe" in windows
    assert "private/build/dist/DomainRecon/DomainRecon.exe" in windows
    for name in ("portable-win64.zip", "portable.exe", "setup.exe"):
        assert f"release/$env:VERSION/DomainRecon-$env:VERSION-{name}" in windows, name
    upload = _uses(jobs["windows"]["steps"], "actions/upload-artifact")[0]
    assert all(line.strip().startswith(f"{RELEASE_DIR}/") for line in upload["with"]["path"].splitlines())
    linux = _runs(jobs["linux"])
    assert 'dpkg-deb --info "release/${VERSION}/domainrecon_${VERSION}_amd64.deb"' in linux
    upload = _uses(jobs["linux"]["steps"], "actions/upload-artifact")[0]
    assert upload["with"]["path"] == f"{RELEASE_DIR}/domainrecon_*_amd64.deb"
    smoke = jobs["smoke-deb"]["steps"]
    assert _uses(smoke, "actions/download-artifact")[0]["with"]["path"] == RELEASE_DIR
    assert "./release/${VERSION}/domainrecon_${VERSION}_amd64.deb" in _runs(jobs["smoke-deb"])
    text = (WORKFLOWS / "release.yml").read_text(encoding="utf-8")
    assert not re.search(r"(?<![\w/-])dist/", text), "ancien dossier dist/ de la racine"


def test_release_attestation_avant_publication():
    steps = _load_yaml(WORKFLOWS / "release.yml")["jobs"]["release"]["steps"]
    checksums = next(i for i, s in enumerate(steps) if "sha256sum" in s.get("run", ""))
    attest = steps.index(_uses(steps, "actions/attest-build-provenance")[0])
    publish = steps.index(_uses(steps, "softprops/action-gh-release")[0])
    assert checksums < attest < publish


def test_release_publie_les_quatre_livrables():
    steps = _load_yaml(WORKFLOWS / "release.yml")["jobs"]["release"]["steps"]
    publish = _uses(steps, "softprops/action-gh-release")[0]
    files = [line.strip() for line in publish["with"]["files"].splitlines()]
    assert files == [
        f"{RELEASE_DIR}/DomainRecon-{VERSION}-setup.exe",
        f"{RELEASE_DIR}/DomainRecon-{VERSION}-portable-win64.zip",
        f"{RELEASE_DIR}/DomainRecon-{VERSION}-portable.exe",
        f"{RELEASE_DIR}/domainrecon_{VERSION}_amd64.deb",
        f"{RELEASE_DIR}/SHA256SUMS",
    ]


def test_release_versions_python_et_node_des_builds():
    """Builds sur Python 3.13 et Node 22 (chaînes YAML : 3.10 non guillemeté deviendrait 3.1)."""
    jobs = _load_yaml(WORKFLOWS / "release.yml")["jobs"]
    for name, job in jobs.items():
        steps = job.get("steps", [])
        for step in _uses(steps, "actions/setup-python"):
            assert step["with"]["python-version"] == "3.13", name
        for step in _uses(steps, "actions/setup-node"):
            assert step["with"]["node-version"] == "22", name
    for name in ("windows", "linux"):
        assert _uses(jobs[name]["steps"], "actions/setup-python"), name
        assert _uses(jobs[name]["steps"], "actions/setup-node"), name
    assert _uses(jobs["frontend"]["steps"], "actions/setup-node")


def test_release_version_lue_sans_masquer_un_echec():
    """« echo "version=$(…)" » renverrait le code d'echo : la commande passe par une variable."""
    runs = _runs(_load_yaml(WORKFLOWS / "release.yml")["jobs"]["version"])
    assert 'version="$(python packaging/build.py --print-version)"' in runs
    assert 'echo "version=$version" >> "$GITHUB_OUTPUT"' in runs
    assert not re.search(r"echo [^\n]*\$\(", runs)


def test_release_inno_setup_de_repli_epingle():
    windows = _runs(_load_yaml(WORKFLOWS / "release.yml")["jobs"]["windows"])
    assert re.search(r"choco install innosetup --version 6\.\d+\.\d+ ", windows)


def test_release_sans_cache():
    """Builds de release reproductibles : aucun cache restauré (empoisonnement de cache)."""
    for step in _steps(_load_yaml(WORKFLOWS / "release.yml")):
        uses = step.get("uses", "")
        if uses.startswith(("actions/setup-python@", "actions/setup-node@")):
            assert "cache" not in step.get("with", {}), uses
        if uses.startswith("actions/setup-node@"):
            assert step["with"]["package-manager-cache"] is False
