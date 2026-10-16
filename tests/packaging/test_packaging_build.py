"""Orchestration des builds (packaging/build.py) : étapes simulées, sans PyInstaller."""

import json
import shutil
import sys
from pathlib import Path

import pytest

from pkgload import load, touch

ROOT = Path(__file__).resolve().parents[2]


build = load("build", "build.py")


def _write_browsers_json(app: Path, revision: str = "1243") -> None:
    """browsers.json du pilote Playwright embarqué : source de la révision de Chromium attendue."""
    data = {"browsers": [{"name": "chromium-headless-shell", "revision": revision}]}
    touch(app / "_internal" / "playwright" / "driver" / "package" / "browsers.json", json.dumps(data))


def _fake_web(root: Path) -> None:
    """Interface construite (domainrecon/web) qui envoie le battement du mode navigateur."""
    touch(root / "domainrecon" / "web" / "index.html")
    touch(root / "domainrecon" / "web" / "assets" / "index-abc.js", 'fetch("/api/system/heartbeat")')


def _fake_app(tmp_path: Path, target: str) -> Path:
    app = tmp_path / "DomainRecon"
    names = ["DomainRecon.exe", "DomainRecon-console.exe"] if target == "windows" else ["domainrecon"]
    for name in names:
        touch(app / name)
    internal = app / "_internal"
    touch(internal / "domainrecon" / "web" / "index.html")
    touch(internal / "domainrecon" / "i18n" / "fr.json", "{}")
    touch(internal / "domainrecon" / "i18n" / "en.json", "{}")
    shell = "chrome-headless-shell.exe" if target == "windows" else "chrome-headless-shell"
    browsers = internal / "browsers"
    touch(browsers / "chromium_headless_shell-1243" / "chrome-headless-shell-x" / shell)
    _write_browsers_json(app)
    touch(app / "LICENSE")
    touch(app / "THIRD_PARTY_NOTICES.md")
    if target == "linux":
        for path in app.rglob("*"):
            if path.is_file():
                path.chmod(0o755)
    return app


@pytest.fixture
def calls(monkeypatch):
    recorded = []
    monkeypatch.setattr(
        build, "run", lambda cmd, cwd=None, env=None: recorded.append(([str(c) for c in cmd], cwd, env))
    )
    monkeypatch.setattr(build, "tool", lambda name: name)
    return recorded


def test_check_tag_conforme():
    build.check_tag("v1.0.0", "1.0.0")


@pytest.mark.parametrize("tag", ["1.0.0", "v1.0.1", "v1.0.0-rc1", "v1.0", "refs/tags/v1.0.0"])
def test_check_tag_refuse(tag):
    with pytest.raises(build.BuildError, match="ne correspond pas"):
        build.check_tag(tag, "1.0.0")


def test_main_print_version(capsys):
    assert build.main(["--print-version"]) == 0
    assert capsys.readouterr().out.strip() == build.pyi_helpers.read_version(ROOT) == "1.0.0"


def test_main_check_tag_en_echec(capsys):
    assert build.main(["--check-tag", "v0.0.1"]) == 1
    assert "ne correspond pas" in capsys.readouterr().err


@pytest.mark.parametrize(("platform", "target"), [("win32", "windows"), ("linux", "linux")])
def test_default_target(platform, target):
    assert build.default_target(platform) == target


def test_default_target_refuse_macos():
    with pytest.raises(build.BuildError, match="non prise en charge"):
        build.default_target("darwin")


def test_run_leve_builderror():
    with pytest.raises(build.BuildError, match="code 3"):
        build.run([sys.executable, "-c", "raise SystemExit(3)"])


def test_bundled_browsers_env_dans_build(tmp_path):
    env = build.bundled_browsers_env(tmp_path, {"PATH": "x", "PLAYWRIGHT_BROWSERS_PATH": "0"})
    assert env == {
        "PATH": "x",
        "PLAYWRIGHT_BROWSERS_PATH": str(tmp_path / "private" / "build" / "ms-playwright"),
    }


def test_bundled_browsers_env_suit_le_dossier_de_build(tmp_path):
    env = build.bundled_browsers_env(tmp_path, {"DOMAINRECON_BUILD_DIR": str(tmp_path / "ailleurs")})
    assert env["PLAYWRIGHT_BROWSERS_PATH"] == str(tmp_path / "ailleurs" / "ms-playwright")


def test_lock_command():
    cmd = build.lock_command("python")
    assert cmd[:6] == ["python", "-m", "uv", "pip", "compile", "pyproject.toml"]
    assert "--universal" in cmd and "--generate-hashes" in cmd
    assert cmd[cmd.index("--python-version") + 1] == "3.13"
    assert cmd[cmd.index("--extra") + 1] == "build"
    assert cmd[cmd.index("--output-file") + 1] == "packaging/requirements.lock"


def test_build_frontend(calls, tmp_path):
    build.build_frontend(tmp_path)
    assert [(cmd, cwd) for cmd, cwd, _ in calls] == [
        (["npm", "ci"], tmp_path / "frontend"),
        (["npm", "run", "build"], tmp_path / "frontend"),
    ]


def test_install_chromium_dans_build(calls, tmp_path):
    build.install_chromium(tmp_path)
    cmd, _, env = calls[0]
    assert cmd[1:] == ["-m", "playwright", "install", "--only-shell", "chromium"]
    assert env["PLAYWRIGHT_BROWSERS_PATH"] == str(tmp_path / "private" / "build" / "ms-playwright")


def test_install_chromium_vide_le_dossier_d_abord(calls, tmp_path):
    """Une révision laissée par un build précédent ne doit pas être embarquée avec la nouvelle."""
    old = touch(
        tmp_path / "private" / "build" / "ms-playwright" / "chromium_headless_shell-1200" / "x" / "shell"
    )
    build.install_chromium(tmp_path)
    assert not old.exists()
    assert len(calls) == 1


def test_run_pyinstaller(calls, tmp_path):
    build.run_pyinstaller(tmp_path)
    cmd, _, _ = calls[0]
    assert cmd[1:5] == ["-m", "PyInstaller", "--noconfirm", "--clean"]
    # Sortie intermédiaire et travail dans private/build/ : rien à la racine du dépôt.
    assert cmd[cmd.index("--distpath") + 1] == str(tmp_path / "private" / "build" / "dist")
    assert cmd[cmd.index("--workpath") + 1] == str(tmp_path / "private" / "build" / "pyinstaller")
    assert cmd[-1] == str(tmp_path / "packaging" / "domainrecon.spec")


def test_run_pyinstaller_dossier_de_build_par_variable(calls, monkeypatch, tmp_path):
    monkeypatch.setenv("DOMAINRECON_BUILD_DIR", "cache/build")
    build.run_pyinstaller(tmp_path)
    cmd, _, _ = calls[0]
    assert cmd[cmd.index("--distpath") + 1] == str(tmp_path / "cache" / "build" / "dist")
    assert cmd[cmd.index("--workpath") + 1] == str(tmp_path / "cache" / "build" / "pyinstaller")


@pytest.mark.parametrize("target", ["windows", "linux"])
def test_verify_bundle_complet(tmp_path, target):
    assert build.verify_bundle(_fake_app(tmp_path, target), target) == []


def test_verify_bundle_signale_les_manques(tmp_path):
    """Chromium embarqué : un dossier sans Chromium embarqué est refusé."""
    app = _fake_app(tmp_path, "windows")
    (app / "DomainRecon-console.exe").unlink()
    (app / "_internal" / "domainrecon" / "web" / "index.html").unlink()
    shutil.rmtree(app / "_internal" / "browsers")
    problems = build.verify_bundle(app, "windows")
    assert "exécutable manquant : DomainRecon-console.exe" in problems
    assert "fichier manquant : _internal/domainrecon/web/index.html" in problems
    assert "Chromium (headless shell) absent de _internal/browsers" in problems


def test_verify_bundle_refuse_une_revision_en_trop(tmp_path):
    """Chromium embarqué : une ancienne révision de Chromium laissée dans browsers/ est refusée."""
    app = _fake_app(tmp_path, "windows")
    extra = app / "_internal" / "browsers" / "chromium_headless_shell-1200" / "chrome-headless-shell-x"
    touch(extra / "chrome-headless-shell.exe")
    problems = build.verify_bundle(app, "windows")
    assert any("en trop" in problem and "chromium_headless_shell-1200" in problem for problem in problems)


def test_verify_bundle_refuse_la_mauvaise_revision(tmp_path):
    """La révision embarquée doit être celle du pilote Playwright (browsers.json)."""
    app = _fake_app(tmp_path, "windows")
    _write_browsers_json(app, "1300")
    problems = build.verify_bundle(app, "windows")
    assert any(
        "mauvaise révision" in problem and "chromium_headless_shell-1300" in problem for problem in problems
    )
    assert any("en trop" in problem and "chromium_headless_shell-1243" in problem for problem in problems)


def test_verify_bundle_sans_browsers_json(tmp_path):
    app = _fake_app(tmp_path, "windows")
    (app / "_internal" / "playwright" / "driver" / "package" / "browsers.json").unlink()
    with pytest.raises(build.BuildError, match="browsers.json"):
        build.verify_bundle(app, "windows")


def test_verify_bundle_refuse_portable_flag(tmp_path):
    """Mode portable : le marqueur portable ne doit jamais atteindre l'installeur."""
    app = _fake_app(tmp_path, "windows")
    touch(app / "portable.flag")
    assert any("portable.flag" in problem for problem in build.verify_bundle(app, "windows"))


def test_verify_bundle_refuse_les_navigateurs_en_double(tmp_path):
    app = _fake_app(tmp_path, "windows")
    touch(app / "_internal" / "playwright" / "driver" / "package" / ".local-browsers" / "x" / "chrome.dll")
    assert any("en double" in problem for problem in build.verify_bundle(app, "windows"))


@pytest.mark.skipif(sys.platform == "win32", reason="droits d'exécution POSIX")
def test_verify_bundle_chromium_non_executable(tmp_path):
    app = _fake_app(tmp_path, "linux")
    for shell in app.rglob("chrome-headless-shell"):
        shell.chmod(0o644)
    assert "Chromium embarqué non exécutable (droits)" in build.verify_bundle(app, "linux")


def test_build_enchaine_les_etapes(monkeypatch, tmp_path):
    steps = []
    touch(tmp_path / "domainrecon" / "__init__.py", '__version__ = "1.2.3"\n')
    _fake_web(tmp_path)
    monkeypatch.setattr(build, "default_target", lambda platform=None: "windows")
    monkeypatch.setattr(build, "build_frontend", lambda root: steps.append("frontend"))
    monkeypatch.setattr(build, "install_chromium", lambda root: steps.append("chromium"))
    monkeypatch.setattr(build, "run_pyinstaller", lambda root: steps.append("pyinstaller"))
    monkeypatch.setattr(
        build,
        "finalize_app_dir",
        lambda root, app_dir, version, target: steps.append(f"finalize {version} {target}"),
    )
    monkeypatch.setattr(build, "verify_bundle", lambda app_dir, target: [])
    monkeypatch.setattr(
        build,
        "package",
        lambda target, root, app_dir, version, *, skip_installer, **_: (
            steps.append(f"package {skip_installer}") or [app_dir]
        ),
    )
    monkeypatch.setattr(
        build,
        "finalize_release",
        lambda root, version: (
            steps.append(f"release {version}") or [root / "release" / version / "SHA256SUMS"]
        ),
    )
    result = build.build("windows", skip_installer=True, root=tmp_path)
    assert steps == [
        "frontend",
        "chromium",
        "pyinstaller",
        "finalize 1.2.3 windows",
        "package True",
        "release 1.2.3",
    ]
    assert result == [
        tmp_path / "private" / "build" / "dist" / "DomainRecon",
        tmp_path / "release" / "1.2.3" / "SHA256SUMS",
    ]


def test_build_saute_frontend_et_chromium(monkeypatch, tmp_path):
    steps = []
    touch(tmp_path / "domainrecon" / "__init__.py", '__version__ = "1.2.3"\n')
    _fake_web(tmp_path)
    monkeypatch.setattr(build, "default_target", lambda platform=None: "linux")
    monkeypatch.setattr(build, "build_frontend", lambda root: steps.append("frontend"))
    monkeypatch.setattr(build, "install_chromium", lambda root: steps.append("chromium"))
    monkeypatch.setattr(build, "run_pyinstaller", lambda root: steps.append("pyinstaller"))
    monkeypatch.setattr(build, "finalize_app_dir", lambda root, app_dir, version, target: None)
    monkeypatch.setattr(build, "verify_bundle", lambda app_dir, target: [])
    monkeypatch.setattr(
        build, "package", lambda target, root, app_dir, version, *, skip_installer, **_: [app_dir]
    )
    monkeypatch.setattr(build, "finalize_release", lambda root, version: [])
    build.build("linux", skip_frontend=True, skip_chromium=True, root=tmp_path)
    assert steps == ["pyinstaller"]


def test_build_sans_interface(monkeypatch, tmp_path):
    touch(tmp_path / "domainrecon" / "__init__.py", '__version__ = "1.2.3"\n')
    monkeypatch.setattr(build, "default_target", lambda platform=None: "windows")
    with pytest.raises(build.BuildError, match="Interface absente"):
        build.build("windows", skip_frontend=True, root=tmp_path)


def test_build_refuse_une_interface_sans_battement(monkeypatch, tmp_path):
    """Revue : bundle construit avant le battement, mode navigateur arrêté en pleine utilisation."""
    touch(tmp_path / "domainrecon" / "__init__.py", '__version__ = "1.2.3"\n')
    touch(tmp_path / "domainrecon" / "web" / "index.html")
    touch(tmp_path / "domainrecon" / "web" / "assets" / "index-old.js", 'fetch("/api/health")')
    monkeypatch.setattr(build, "default_target", lambda platform=None: "windows")
    with pytest.raises(build.BuildError, match="system/heartbeat"):
        build.build("windows", skip_frontend=True, root=tmp_path)


def test_interface_du_depot_envoie_le_battement():
    """domainrecon/web servi par le lanceur : à reconstruire (npm run build) s'il est périmé."""
    web = ROOT / "domainrecon" / "web"
    if not (web / "index.html").is_file():
        pytest.skip("interface non construite")
    assert build.web_sends_heartbeat(web)


def test_build_dossier_incomplet(monkeypatch, tmp_path):
    touch(tmp_path / "domainrecon" / "__init__.py", '__version__ = "1.2.3"\n')
    _fake_web(tmp_path)
    monkeypatch.setattr(build, "default_target", lambda platform=None: "windows")
    monkeypatch.setattr(build, "run_pyinstaller", lambda root: None)
    monkeypatch.setattr(build, "finalize_app_dir", lambda root, app_dir, version, target: None)
    monkeypatch.setattr(build, "verify_bundle", lambda app_dir, target: ["fichier manquant : LICENSE"])
    with pytest.raises(build.BuildError, match="fichier manquant : LICENSE"):
        build.build("windows", skip_frontend=True, skip_chromium=True, root=tmp_path)


def test_build_refuse_la_compilation_croisee(monkeypatch, tmp_path):
    monkeypatch.setattr(build, "default_target", lambda platform=None: "windows")
    with pytest.raises(build.BuildError, match="compilation croisée"):
        build.build("linux", root=tmp_path)


def test_main_affiche_les_erreurs(monkeypatch, capsys):
    def fail(target, **kwargs):
        raise build.BuildError("boum")

    monkeypatch.setattr(build, "build", fail)
    assert build.main(["--target", "windows"]) == 1
    assert "[!] boum" in capsys.readouterr().err


def test_onefile_nom_et_verification(tmp_path):
    assert build.onefile_name("1.2.3") == "DomainRecon-1.2.3-portable.exe"
    exe = tmp_path / "DomainRecon-1.2.3-portable.exe"
    assert any("manquant" in p for p in build.verify_onefile(exe))
    exe.write_bytes(b"x" * 1000)
    assert any("trop petit" in p for p in build.verify_onefile(exe))
    assert build.verify_onefile(exe, min_size=500) == []


def test_build_onefile_lance_la_spec_et_verifie(monkeypatch, tmp_path):
    commands = []
    monkeypatch.setattr(build, "run", lambda cmd, **kw: commands.append([str(c) for c in cmd]))
    with pytest.raises(build.BuildError, match="incomplet"):
        build.build_onefile(tmp_path, "1.2.3")
    command = commands[0]
    assert command[-1].endswith("domainrecon-onefile.spec")
    assert "pyinstaller-onefile" in " ".join(command)  # dossier de travail distinct du onedir
    assert command[command.index("--distpath") + 1] == str(tmp_path / "private" / "build" / "dist")
    built = touch(tmp_path / "private" / "build" / "dist" / "DomainRecon-1.2.3-portable.exe", "x" * 10)
    old = touch(tmp_path / "release" / "1.2.3" / "DomainRecon-1.2.3-portable.exe", "ancien")
    monkeypatch.setattr(build, "verify_onefile", lambda exe: [])
    # Rangé dans release/<version>/ (l'exécutable d'un build précédent est remplacé).
    assert build.build_onefile(tmp_path, "1.2.3") == old
    assert old.read_text(encoding="utf-8") == "x" * 10
    assert not built.exists()


def test_package_windows_ajoute_l_onefile_sauf_skip(monkeypatch, tmp_path):
    app = tmp_path / "dist" / "DomainRecon"
    app.mkdir(parents=True)
    monkeypatch.setattr(build, "make_portable_zip", lambda app_dir, zip_path: zip_path)
    monkeypatch.setattr(build, "build_installer", lambda root, app_dir, version: tmp_path / "setup.exe")
    monkeypatch.setattr(build, "build_onefile", lambda root, version: tmp_path / "portable.exe")
    full = build.package("windows", tmp_path, app, "1.2.3", skip_installer=False)
    assert tmp_path / "portable.exe" in full and tmp_path / "setup.exe" in full
    sans = build.package("windows", tmp_path, app, "1.2.3", skip_installer=True, skip_onefile=True)
    assert tmp_path / "portable.exe" not in sans
    assert tmp_path / "portable.exe" in build.package("windows", tmp_path, app, "1.2.3", skip_installer=True)


def test_option_skip_onefile():
    assert build.parse_args(["--skip-onefile"]).skip_onefile is True
    assert build.parse_args([]).skip_onefile is False


# --- Dossiers de sortie : private/build/ et release/<version>/ -------------------------------------


def test_dossiers_par_defaut(tmp_path):
    paths = build.output_paths(tmp_path, "1.2.3")
    assert paths == {
        "build": tmp_path / "private" / "build",
        "chromium": tmp_path / "private" / "build" / "ms-playwright",
        "app": tmp_path / "private" / "build" / "dist" / "DomainRecon",
        "release": tmp_path / "release" / "1.2.3",
    }


def test_dossiers_par_variables(monkeypatch, tmp_path):
    """Absolu : tel quel ; relatif : depuis la racine du dépôt (pas le dossier courant)."""
    monkeypatch.setenv("DOMAINRECON_BUILD_DIR", str(tmp_path / "travail"))
    monkeypatch.setenv("DOMAINRECON_RELEASE_DIR", "sorties")
    paths = build.output_paths(tmp_path / "depot", "1.2.3")
    assert paths["build"] == tmp_path / "travail"
    assert paths["chromium"] == tmp_path / "travail" / "ms-playwright"
    assert paths["app"] == tmp_path / "travail" / "dist" / "DomainRecon"
    assert paths["release"] == tmp_path / "depot" / "sorties" / "1.2.3"


def test_variable_vide_ignoree(monkeypatch, tmp_path):
    monkeypatch.setenv("DOMAINRECON_BUILD_DIR", "  ")
    monkeypatch.setenv("DOMAINRECON_RELEASE_DIR", "")
    paths = build.output_paths(tmp_path, "1.2.3")
    assert paths["build"] == tmp_path / "private" / "build"
    assert paths["release"] == tmp_path / "release" / "1.2.3"


def test_options_build_dir_et_release_dir(monkeypatch, tmp_path):
    """Les options passent par l'environnement : les specs PyInstaller (sous-processus) les voient aussi."""
    monkeypatch.chdir(tmp_path)
    env: dict[str, str] = {}
    args = build.parse_args(["--build-dir", "b", "--release-dir", str(tmp_path / "r")])
    build.apply_dir_options(args, env)
    assert env == {
        "DOMAINRECON_BUILD_DIR": str((tmp_path / "b").resolve()),
        "DOMAINRECON_RELEASE_DIR": str((tmp_path / "r").resolve()),
    }
    sans: dict[str, str] = {}
    build.apply_dir_options(build.parse_args([]), sans)
    assert sans == {}


def test_main_print_paths(monkeypatch, capsys, tmp_path):
    monkeypatch.setenv("DOMAINRECON_BUILD_DIR", str(tmp_path / "b"))
    monkeypatch.setenv("DOMAINRECON_RELEASE_DIR", str(tmp_path / "r"))
    assert build.main(["--print-paths"]) == 0
    out = capsys.readouterr().out.splitlines()
    assert out == [
        f"build    {tmp_path / 'b'}",
        f"chromium {tmp_path / 'b' / 'ms-playwright'}",
        f"app      {tmp_path / 'b' / 'dist' / 'DomainRecon'}",
        f"release  {tmp_path / 'r' / build.pyi_helpers.read_version(ROOT)}",
    ]


def test_noms_des_livrables():
    assert build.release_names("1.2.3") == (
        "DomainRecon-1.2.3-setup.exe",
        "DomainRecon-1.2.3-portable.exe",
        "DomainRecon-1.2.3-portable-win64.zip",
        "domainrecon_1.2.3_amd64.deb",
    )


def test_sha256sums_format_de_sha256sum(tmp_path):
    """« empreinte, deux espaces, nom », LF, ordre stable ; seuls les livrables connus."""
    import hashlib

    release = tmp_path / "release" / "1.2.3"
    contents = {
        "domainrecon_1.2.3_amd64.deb": b"deb",
        "DomainRecon-1.2.3-setup.exe": b"setup",
        "DomainRecon-1.2.3-portable.exe": b"onefile",
        "DomainRecon-1.2.3-portable-win64.zip": b"zip",
    }
    for name, data in contents.items():
        (release / name).parent.mkdir(parents=True, exist_ok=True)
        (release / name).write_bytes(data)
    touch(release / "NOTES.md", "notes")
    touch(release / "DomainRecon-1.2.2-setup.exe", "autre version")
    output = build.write_checksums(release, "1.2.3")
    assert output == release / "SHA256SUMS"
    raw = output.read_bytes()
    assert b"\r" not in raw and raw.endswith(b"\n")
    lines = raw.decode("ascii").splitlines()
    assert lines == [
        f"{hashlib.sha256(contents[name]).hexdigest()}  {name}"
        for name in sorted(contents)  # ordre ordinal, comme « sha256sum -- * » en locale C
    ]
    assert not (release / "SHA256SUMS.part").exists()


def test_sha256sums_livrables_partiels(tmp_path):
    """Build Windows seul : SHA256SUMS ne couvre que ce qui est là (le .deb s'ajoute ensuite)."""
    release = tmp_path / "1.0.0"
    touch(release / "DomainRecon-1.0.0-portable-win64.zip", "zip")
    build.write_checksums(release, "1.0.0")
    names = [line.split("  ", 1)[1] for line in (release / "SHA256SUMS").read_text().splitlines()]
    assert names == ["DomainRecon-1.0.0-portable-win64.zip"]


def test_sha256sums_sans_livrable(tmp_path):
    with pytest.raises(build.BuildError, match="Aucun livrable"):
        build.write_checksums(tmp_path, "1.2.3")


def test_notes_de_version_copiees(tmp_path):
    touch(tmp_path / "docs" / "releases" / "1.2.3.md", "# DomainRecon 1.2.3\n")
    release = tmp_path / "release" / "1.2.3"
    notes = build.copy_release_notes(tmp_path, release, "1.2.3")
    assert notes == release / "NOTES.md"
    assert notes.read_text(encoding="utf-8") == "# DomainRecon 1.2.3\n"


def test_notes_de_version_absentes(tmp_path):
    release = tmp_path / "release" / "1.2.3"
    assert build.copy_release_notes(tmp_path, release, "1.2.3") is None
    assert not (release / "NOTES.md").exists()


def test_finalize_release(tmp_path):
    touch(tmp_path / "docs" / "releases" / "1.2.3.md", "notes")
    touch(tmp_path / "release" / "1.2.3" / "domainrecon_1.2.3_amd64.deb", "deb")
    written = build.finalize_release(tmp_path, "1.2.3")
    assert written == [
        tmp_path / "release" / "1.2.3" / "SHA256SUMS",
        tmp_path / "release" / "1.2.3" / "NOTES.md",
    ]
    # NOTES.md n'est pas un livrable : absent des sommes.
    assert "NOTES.md" not in (tmp_path / "release" / "1.2.3" / "SHA256SUMS").read_text()


def test_main_checksums(monkeypatch, capsys, tmp_path):
    version = build.pyi_helpers.read_version(ROOT)
    monkeypatch.setenv("DOMAINRECON_RELEASE_DIR", str(tmp_path))
    assert build.main(["--checksums"]) == 1
    assert "Aucun livrable" in capsys.readouterr().err
    touch(tmp_path / version / build.deb_name(version), "deb")
    assert build.main(["--checksums"]) == 0
    assert str(tmp_path / version / "SHA256SUMS") in capsys.readouterr().out


def test_build_ecrit_les_sommes_dans_release(monkeypatch, tmp_path):
    """Enchaînement réel de package -> finalize_release : livrables et SHA256SUMS dans release/<version>/."""
    touch(tmp_path / "domainrecon" / "__init__.py", '__version__ = "1.2.3"\n')
    _fake_web(tmp_path)
    monkeypatch.setattr(build, "default_target", lambda platform=None: "linux")
    monkeypatch.setattr(build, "run_pyinstaller", lambda root: None)
    monkeypatch.setattr(build, "finalize_app_dir", lambda root, app_dir, version, target: None)
    monkeypatch.setattr(build, "verify_bundle", lambda app_dir, target: [])
    monkeypatch.setattr(
        build,
        "build_deb",
        lambda root, app_dir, version: touch(root / "release" / version / build.deb_name(version), "deb"),
    )
    result = build.build("linux", skip_frontend=True, skip_chromium=True, root=tmp_path)
    release = tmp_path / "release" / "1.2.3"
    assert result == [
        tmp_path / "private" / "build" / "dist" / "DomainRecon",
        release / "domainrecon_1.2.3_amd64.deb",
        release / "SHA256SUMS",
    ]
    assert (release / "SHA256SUMS").read_text().endswith("  domainrecon_1.2.3_amd64.deb\n")
    assert not (tmp_path / "dist").exists() and not (tmp_path / "build").exists()
