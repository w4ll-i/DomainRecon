"""Paquet Linux : dépendances Debian tirées de Playwright, fichiers du paquet, script build-deb.sh."""

import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from pkgload import load, touch

ROOT = Path(__file__).resolve().parents[2]
LINUX = ROOT / "packaging" / "linux"
FAKE_BUNDLE = """
var deps;
deps = {
  "ubuntu20.04-x64": { tools: ["xvfb"], chromium: ["libancienne"] },
  "ubuntu22.04-x64": {
    tools: [
      "xvfb",
      "fonts-liberation",
      "libfontconfig1",
      "xfonts-scalable"
    ],
    chromium: [
      "libnss3",
      "libasound2"
    ],
    lib2package: { "libnss3.so": "libnss3" }
  },
};
"""


build = load("build", "build.py")


def test_playwright_native_deps_table_simulee(tmp_path):
    touch(tmp_path / "driver" / "package" / "lib" / "coreBundle.js", FAKE_BUNDLE)
    groups = build.playwright_native_deps(tmp_path)
    assert groups["chromium"] == ["libnss3", "libasound2"]
    assert groups["tools"] == ["xvfb", "fonts-liberation", "libfontconfig1", "xfonts-scalable"]


def test_playwright_native_deps_version_installee():
    """Détecte un changement de format de la table dans une nouvelle version de Playwright."""
    groups = build.playwright_native_deps(build._playwright_dir())
    assert "libnss3" in groups["chromium"]
    assert "fonts-liberation" in groups["tools"]


def test_playwright_native_deps_introuvable(tmp_path):
    touch(tmp_path / "driver" / "package" / "lib" / "coreBundle.js", "var rien = {};")
    with pytest.raises(build.BuildError, match="ubuntu22.04-x64"):
        build.playwright_native_deps(tmp_path)


def test_deb_dependencies():
    depends, recommends = build.deb_dependencies(
        {
            "chromium": ["libnss3", "libasound2"],
            "tools": ["xvfb", "fonts-liberation", "libfontconfig1", "xfonts-scalable"],
        }
    )
    assert depends == ["libc6 (>= 2.35)", "libnss3", "libasound2", "libfontconfig1"]
    assert recommends == ["libwebkit2gtk-4.1-0", "gir1.2-webkit2-4.1", "xdg-utils", "fonts-liberation"]


def test_control_in():
    text = (LINUX / "control.in").read_text(encoding="utf-8")
    for fragment in (
        "Package: domainrecon\n",
        "Version: @VERSION@\n",
        "Architecture: amd64\n",
        "Installed-Size: @INSTALLED_SIZE@\n",
        "Depends: @DEPENDS@\n",
        "Recommends: @RECOMMENDS@\n",
    ):
        assert fragment in text, fragment
    assert text.endswith("\n")


def test_desktop_entry():
    text = (LINUX / "domainrecon.desktop").read_text(encoding="utf-8")
    for line in (
        "Type=Application",
        "Name=DomainRecon",
        "Exec=domainrecon",
        "Icon=domainrecon",
        "Terminal=false",
    ):
        assert line in text.splitlines(), line


def test_scripts_en_lf_avec_shebang():
    """Fins de ligne : fichiers du dépôt en LF (les CR éventuels sont aussi retirés au build)."""
    for name in ("postinst", "build-deb.sh", "docker-build.sh", "docker-smoke.sh"):
        data = (LINUX / name).read_bytes()
        assert data.startswith(b"#!/bin/sh\n"), name
        assert b"\r" not in data, name


def test_scripts_docker():
    """Build du .deb dans Docker : conteneurs jetables, Ubuntu 22.04, build Linux puis test du paquet installé."""
    ps1 = (LINUX / "build-in-docker.ps1").read_text(encoding="utf-8-sig")
    assert "$Image = 'ubuntu:22.04'" in ps1
    assert ps1.count("docker run --rm") == 2
    assert "/work/src/packaging/linux/docker-build.sh" in ps1
    assert "/packaging/linux/docker-smoke.sh" in ps1
    # Paquet rangé avec les autres livrables, sommes recalculées ; travail dans private/build.
    assert 'Join-Path $src "release\\$version\\$deb"' in ps1
    assert 'Join-Path $Root "release\\$version"' in ps1
    assert "Write-Checksums $releaseDir $version" in ps1
    assert "'private\\build\\docker'" in ps1
    build_sh = (LINUX / "docker-build.sh").read_text(encoding="utf-8")
    assert "set -eu" in build_sh
    assert '--require-hashes -r "$SRC/packaging/requirements.lock"' in build_sh
    assert "packaging/build.py --target linux --skip-frontend" in build_sh
    assert "release/${VERSION}/domainrecon_${VERSION}_amd64.deb" in build_sh


def test_docker_copie_par_liste_blanche():
    """Copie vers le conteneur : dossiers et fichiers nommés, jamais un miroir de tout le dépôt."""
    ps1 = (LINUX / "build-in-docker.ps1").read_text(encoding="utf-8-sig")
    assert "$CopiedDirs = @('domainrecon', 'packaging')" in ps1
    assert "$CopiedFrontend = @('package.json', 'package-lock.json')" in ps1
    assert "$CopiedFiles = @('pyproject.toml', 'LICENSE')" in ps1
    assert "frontend\\node_modules" in ps1
    # Plus de liste d'exclusions : robocopy n'est appelé que sur des dossiers de la liste blanche.
    assert "robocopy $Root" not in ps1
    assert [line.strip() for line in ps1.splitlines() if line.strip().startswith("robocopy ")] == [
        "robocopy $From $To /MIR /NFL /NDL /NJH /NJS /NP /XD __pycache__ | Out-Null"
    ]
    assert "/XD __pycache__" in ps1
    for name in (
        "domainrecon",
        "packaging",
        "frontend/package.json",
        "frontend/package-lock.json",
        "LICENSE",
    ):
        assert (ROOT / name).exists(), name


def test_script_powershell_ascii_sans_bom():
    """Windows PowerShell 5.1 lit un .ps1 sans BOM en ANSI : ASCII seul, lisible partout."""
    data = (LINUX / "build-in-docker.ps1").read_bytes()
    assert not data.startswith(b"\xef\xbb\xbf")
    assert data.isascii()
    assert b"\r" not in data


def test_docker_chemin_de_montage_sans_expression_reguliere():
    """Chemin Windows -> montage Docker : remplacement littéral ('\\' seul est une regex invalide pour -replace)."""
    ps1 = (LINUX / "build-in-docker.ps1").read_text(encoding="utf-8-sig")
    assert "return (Resolve-Path $Path).Path.Replace('\\', '/')" in ps1
    assert "-replace '\\'," not in ps1


def test_docker_sommes_au_format_de_build_py():
    """SHA256SUMS réécrit par le script PowerShell : mêmes livrables et même format que build.py."""
    ps1 = (LINUX / "build-in-docker.ps1").read_text(encoding="utf-8-sig")
    for pattern in (
        "DomainRecon-$Version-setup.exe",
        "DomainRecon-$Version-portable.exe",
        "DomainRecon-$Version-portable-win64.zip",
        "domainrecon_${Version}_amd64.deb",
    ):
        assert f'"{pattern}"' in ps1, pattern
    assert '"$hash  $name`n"' in ps1
    assert "[StringComparer]::Ordinal" in ps1
    assert "ToLowerInvariant()" in ps1
    assert build.release_names("X") == (
        "DomainRecon-X-setup.exe",
        "DomainRecon-X-portable.exe",
        "DomainRecon-X-portable-win64.zip",
        "domainrecon_X_amd64.deb",
    )
    smoke_sh = (LINUX / "docker-smoke.sh").read_text(encoding="utf-8")
    assert "set -eu" in smoke_sh
    assert "--version-flag --quick-scan example.com --pdf --scan example.com" in smoke_sh


def test_docker_smoke_options_connues_de_smoke_test():
    """Les options passées par docker-smoke.sh existent dans packaging/smoke_test.py."""
    smoke_test = load("smoke_test", "smoke_test.py")
    code = [
        line
        for line in (LINUX / "docker-smoke.sh").read_text(encoding="utf-8").splitlines()
        if "#" not in line
    ]
    words = {word for line in code for word in line.split()}
    options = sorted(word for word in words if word.startswith("--") and word != "--no-install-recommends")
    assert options == [
        "--data-dir",
        "--exe",
        "--expect-version",
        "--pdf",
        "--quick-scan",
        "--scan",
        "--version-flag",
    ]
    source = (ROOT / "packaging" / "smoke_test.py").read_text(encoding="utf-8")
    for option in options:
        assert f'"{option}"' in source, option
    assert callable(smoke_test.main)


def test_package_linux(monkeypatch, tmp_path):
    monkeypatch.setattr(
        build,
        "build_deb",
        lambda root, app_dir, version: root / "release" / version / f"domainrecon_{version}_amd64.deb",
    )
    app = tmp_path / "private" / "build" / "dist" / "DomainRecon"
    assert build.package("linux", tmp_path, app, "1.0.0", skip_installer=False) == [
        app,
        tmp_path / "release" / "1.0.0" / "domainrecon_1.0.0_amd64.deb",
    ]


def test_build_deb_transmet_les_dependances(monkeypatch, tmp_path):
    recorded = []
    monkeypatch.setattr(
        build, "run", lambda cmd, cwd=None, env=None: recorded.append(([str(c) for c in cmd], env))
    )
    monkeypatch.setattr(
        build, "playwright_native_deps", lambda playwright_dir: {"chromium": ["libnss3"], "tools": []}
    )
    app = tmp_path / "private" / "build" / "dist" / "DomainRecon"
    output = build.build_deb(tmp_path, app, "1.0.0", playwright_dir=tmp_path)
    cmd, env = recorded[0]
    assert output == tmp_path / "release" / "1.0.0" / "domainrecon_1.0.0_amd64.deb"
    assert cmd == [
        "sh",
        str(tmp_path / "packaging" / "linux" / "build-deb.sh"),
        str(app),
        "1.0.0",
        str(output),
        str(tmp_path),
    ]
    assert env["DEB_DEPENDS"] == "libc6 (>= 2.35), libnss3"
    assert env["DEB_RECOMMENDS"] == "libwebkit2gtk-4.1-0, gir1.2-webkit2-4.1, xdg-utils"


@pytest.mark.skipif(
    sys.platform == "win32" or shutil.which("dpkg-deb") is None, reason="dpkg-deb (Linux) requis"
)
def test_build_deb_script_de_bout_en_bout(tmp_path):
    """Fins de ligne : sources du paquet en CRLF (checkout Windows) -> paquet propre."""
    root = tmp_path / "depot"
    for name in ("control.in", "postinst", "domainrecon.desktop"):
        touch(
            root / "packaging" / "linux" / name,
            (LINUX / name).read_text(encoding="utf-8").replace("\n", "\r\n"),
        )
    for size in (256, 128, 48):
        touch(root / "packaging" / "icons" / f"domainrecon-{size}.png", "png")
    touch(root / "LICENSE", "MIT License\n")
    app = tmp_path / "DomainRecon"
    touch(app / "domainrecon", "#!/bin/sh\necho 1.0.0\n").chmod(0o755)
    touch(app / "_internal" / "base_library.zip", "zip")
    output = tmp_path / "out" / "domainrecon_1.0.0_amd64.deb"
    env = dict(os.environ, DEB_DEPENDS="libc6 (>= 2.35), libnss3 | libnss3t64", DEB_RECOMMENDS="xdg-utils")
    subprocess.run(
        ["sh", str(LINUX / "build-deb.sh"), str(app), "1.0.0", str(output), str(root)], env=env, check=True
    )

    fields = subprocess.run(
        ["dpkg-deb", "--field", str(output), "Package", "Version", "Depends", "Recommends"],
        capture_output=True,
        text=True,
        check=True,
    ).stdout
    assert "Package: domainrecon" in fields
    assert "Version: 1.0.0" in fields
    assert "Depends: libc6 (>= 2.35), libnss3 | libnss3t64" in fields
    assert "Recommends: xdg-utils" in fields
    assert "\r" not in fields
    contents = subprocess.run(
        ["dpkg-deb", "--contents", str(output)], capture_output=True, text=True, check=True
    ).stdout
    assert "./usr/bin/domainrecon -> /opt/domainrecon/domainrecon" in contents
    assert "./opt/domainrecon/domainrecon" in contents
    assert "./usr/share/applications/domainrecon.desktop" in contents
    assert "./usr/share/icons/hicolor/256x256/apps/domainrecon.png" in contents
    assert "./usr/share/doc/domainrecon/copyright" in contents
    assert "root/root" in contents
    control_dir = tmp_path / "control"
    subprocess.run(["dpkg-deb", "--control", str(output), str(control_dir)], check=True)
    postinst = (control_dir / "postinst").read_bytes()
    assert postinst.startswith(b"#!/bin/sh\n")
    assert b"\r" not in postinst
    assert os.access(control_dir / "postinst", os.X_OK)


# Faux dpkg-deb : conserve le fichier control et les droits de l'arborescence, que le script supprime ensuite.
FAKE_DPKG_DEB = """#!/bin/sh
case "$1" in
    --info) exit 0 ;;
esac
cp "$4/DEBIAN/control" "$5"
(cd "$4" && find opt -printf '%m %p\\n' | sort) > "$5.modes"
"""


@pytest.mark.skipif(not sys.platform.startswith("linux"), reason="find -printf, ln -s : Linux requis")
def test_build_deb_script_valeurs_speciales_et_droits(tmp_path):
    """« | » (alternatives de Depends), « & » et « \\ » ne cassent pas sed ; droits normalisés sous /opt."""
    root = tmp_path / "depot"
    for name in ("control.in", "postinst", "domainrecon.desktop"):
        touch(root / "packaging" / "linux" / name, (LINUX / name).read_text(encoding="utf-8"))
    for size in (256, 128, 48):
        touch(root / "packaging" / "icons" / f"domainrecon-{size}.png", "png")
    touch(root / "LICENSE", "MIT License\n")
    app = tmp_path / "DomainRecon"
    touch(app / "domainrecon", "#!/bin/sh\n").chmod(0o700)
    touch(app / "_internal" / "lib" / "x.so", "so").chmod(0o666)
    (app / "_internal").chmod(0o700)
    bin_dir = tmp_path / "bin"
    touch(bin_dir / "dpkg-deb", FAKE_DPKG_DEB).chmod(0o755)
    output = tmp_path / "out" / "domainrecon_1.0.0_amd64.deb"
    env = dict(
        os.environ,
        PATH=f"{bin_dir}{os.pathsep}{os.environ['PATH']}",
        DEB_DEPENDS="libc6 (>= 2.35), libasound2t64 | libasound2 & x\\y",
        DEB_RECOMMENDS="a|b&c",
    )
    subprocess.run(
        ["sh", str(LINUX / "build-deb.sh"), str(app), "1.0.0", str(output), str(root)], env=env, check=True
    )

    control = output.read_text(encoding="utf-8")
    assert "Version: 1.0.0\n" in control
    assert "Depends: libc6 (>= 2.35), libasound2t64 | libasound2 & x\\y\n" in control
    assert "Recommends: a|b&c\n" in control
    for token in ("@VERSION@", "@DEPENDS@", "@RECOMMENDS@", "@INSTALLED_SIZE@"):
        assert token not in control
    modes = {}
    for line in output.with_name(output.name + ".modes").read_text(encoding="utf-8").splitlines():
        mode, path = line.split(" ", 1)
        modes[path] = mode
    assert modes["opt/domainrecon"] == "755"
    assert modes["opt/domainrecon/_internal"] == "755"
    assert modes["opt/domainrecon/_internal/lib/x.so"] == "644"
    assert modes["opt/domainrecon/domainrecon"] == "755"
