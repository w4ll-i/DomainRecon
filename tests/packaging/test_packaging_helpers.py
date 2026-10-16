"""Aides de la spec PyInstaller (packaging/pyi_helpers.py)."""

import sys
from pathlib import Path

import pytest

from pkgload import load, touch

ROOT = Path(__file__).resolve().parents[2]
SHELL_DEST = "browsers/chromium_headless_shell-1243/chrome-headless-shell-linux64"


helpers = load("pyi_helpers", "pyi_helpers.py")


def _fake_browsers(tmp_path: Path, shell: str = "chrome-headless-shell") -> Path:
    browsers = tmp_path / "build" / "ms-playwright"
    version_dir = browsers / "chromium_headless_shell-1243"
    browser = version_dir / "chrome-headless-shell-linux64"
    touch(browser / shell)
    touch(browser / "libEGL.so")
    touch(browser / "libvulkan.so.1")
    touch(browser / "debug.log")
    touch(version_dir / "INSTALLATION_COMPLETE", "")
    return browsers


def test_read_version_du_depot():
    from domainrecon import __version__

    assert helpers.read_version(ROOT) == __version__ == "1.0.0"


def test_read_version_absente(tmp_path):
    touch(tmp_path / "domainrecon" / "__init__.py", "VERSION = 1\n")
    with pytest.raises(ValueError, match="__version__"):
        helpers.read_version(tmp_path)


@pytest.mark.parametrize(("version", "expected"), [("1.0.0", (1, 0, 0, 0)), ("12.3.45", (12, 3, 45, 0))])
def test_version_tuple(version, expected):
    assert helpers.version_tuple(version) == expected


@pytest.mark.parametrize("version", ["1.0", "1.0.0.0", "1.0.0rc1", "v1.0.0"])
def test_version_tuple_refuse(version):
    with pytest.raises(ValueError):
        helpers.version_tuple(version)


def _fake_package(tmp_path: Path) -> Path:
    package = tmp_path / "domainrecon"
    touch(package / "web" / "index.html")
    touch(package / "web" / "assets" / "index-abc123.js")
    touch(package / "i18n" / "fr.json", "{}")
    touch(package / "i18n" / "en.json", "{}")
    touch(package / "i18n" / "__init__.py", "")
    touch(package / "desktop" / "icon.png")
    touch(package / "desktop" / "launcher.py", "")
    return package


def test_package_datas(tmp_path):
    package = _fake_package(tmp_path)
    datas = helpers.package_datas(tmp_path, platform="linux")
    assert sorted((Path(src).relative_to(package).as_posix(), dest) for src, dest in datas) == [
        ("desktop/icon.png", "domainrecon/desktop"),
        ("i18n/en.json", "domainrecon/i18n"),
        ("i18n/fr.json", "domainrecon/i18n"),
        ("web/assets/index-abc123.js", "domainrecon/web/assets"),
        ("web/index.html", "domainrecon/web"),
    ]


def test_package_datas_sans_icone_png_sous_windows(tmp_path):
    """Régression : pywebview (WinForms) plante (ArgumentException « picture ») si on lui passe un PNG."""
    package = _fake_package(tmp_path)
    datas = helpers.package_datas(tmp_path, platform="win32")
    sources = {Path(src).relative_to(package).as_posix() for src, _ in datas}
    assert "desktop/icon.png" not in sources
    assert {"i18n/en.json", "i18n/fr.json", "web/index.html"} <= sources


def test_package_datas_sans_interface(tmp_path):
    touch(tmp_path / "domainrecon" / "i18n" / "fr.json", "{}")
    with pytest.raises(FileNotFoundError, match="npm run build"):
        helpers.package_datas(tmp_path)


def test_package_datas_sans_catalogues(tmp_path):
    touch(tmp_path / "domainrecon" / "web" / "index.html")
    with pytest.raises(FileNotFoundError, match="i18n"):
        helpers.package_datas(tmp_path)


def test_build_browsers_dir(tmp_path):
    assert helpers.build_browsers_dir(tmp_path, {}) == tmp_path / "private" / "build" / "ms-playwright"


def test_dossiers_de_sortie_par_defaut(tmp_path):
    assert helpers.build_dir(tmp_path, {}) == tmp_path / "private" / "build"
    assert helpers.build_dist_dir(tmp_path, {}) == tmp_path / "private" / "build" / "dist"
    assert helpers.release_root(tmp_path, {}) == tmp_path / "release"
    assert helpers.release_dir(tmp_path, "1.2.3", {}) == tmp_path / "release" / "1.2.3"


def test_dossiers_de_sortie_par_variables(tmp_path):
    env = {"DOMAINRECON_BUILD_DIR": str(tmp_path / "b"), "DOMAINRECON_RELEASE_DIR": "out"}
    assert helpers.build_dir(tmp_path, env) == tmp_path / "b"
    assert helpers.build_browsers_dir(tmp_path, env) == tmp_path / "b" / "ms-playwright"
    assert helpers.build_dist_dir(tmp_path, env) == tmp_path / "b" / "dist"
    # Relatif : depuis la racine du dépôt.
    assert helpers.release_dir(tmp_path, "1.2.3", env) == tmp_path / "out" / "1.2.3"


def test_dossiers_de_sortie_lus_dans_l_environnement(monkeypatch, tmp_path):
    monkeypatch.setenv("DOMAINRECON_BUILD_DIR", str(tmp_path / "env"))
    assert helpers.build_browsers_dir(tmp_path) == tmp_path / "env" / "ms-playwright"


def test_dossiers_de_sortie_ignores_par_git():
    """Sorties par défaut sous private/ et release/, que .gitignore exclut."""
    lines = (ROOT / ".gitignore").read_text(encoding="utf-8").splitlines()
    assert helpers.DEFAULT_BUILD_DIR.parts[0] == "private" and "/private/" in lines
    assert helpers.DEFAULT_RELEASE_DIR.parts[0] == "release" and "/release/" in lines


def test_browser_datas_garde_les_bibliotheques(tmp_path):
    """Chromium embarqué : tout le dossier du navigateur est collecté (.so/.dll comprises), vers _internal/browsers."""
    datas = {Path(src).name: dest for src, dest in helpers.browser_datas(_fake_browsers(tmp_path))}
    assert datas["libEGL.so"] == SHELL_DEST
    assert datas["libvulkan.so.1"] == SHELL_DEST
    assert datas["chrome-headless-shell"] == SHELL_DEST
    assert datas["INSTALLATION_COMPLETE"] == "browsers/chromium_headless_shell-1243"
    assert "debug.log" not in datas


def test_browser_datas_exclut_ffmpeg_et_winldd(tmp_path):
    """Composants installés avec le headless shell mais inutiles aux captures : poids évité."""
    browsers = _fake_browsers(tmp_path)
    touch(browsers / "ffmpeg-1011" / "ffmpeg-linux")
    touch(browsers / "winldd-1007" / "PrintDeps.exe")
    datas = {Path(src).name for src, _ in helpers.browser_datas(browsers)}
    assert "ffmpeg-linux" not in datas
    assert "PrintDeps.exe" not in datas
    assert "chrome-headless-shell" in datas


def test_browser_datas_exclut_les_liens_de_playwright(tmp_path):
    """.links/ contient le chemin absolu de la machine de build : inutile à l'exécution, non embarqué."""
    browsers = _fake_browsers(tmp_path)
    touch(browsers / ".links" / "0123456789abcdef", "C:\\build\\venv\\Lib\\site-packages\\playwright")
    dests = {dest for _, dest in helpers.browser_datas(browsers)}
    assert not any(".links" in dest for dest in dests)
    assert SHELL_DEST in dests


def test_browser_datas_sans_navigateur(tmp_path):
    (tmp_path / "vide").mkdir()
    with pytest.raises(FileNotFoundError, match="--only-shell chromium"):
        helpers.browser_datas(tmp_path / "vide")


def test_headless_shell_executables_windows(tmp_path):
    browsers = _fake_browsers(tmp_path, shell="chrome-headless-shell.exe")
    assert [p.name for p in helpers.headless_shell_executables(browsers)] == ["chrome-headless-shell.exe"]


def test_chemin_du_navigateur_sous_la_limite_de_windows():
    """Chromium embarqué : CreateProcess échoue au-delà de 260 caractères (spawn ENOENT)."""
    suffix = "\\".join(
        [
            "",
            "_internal",
            helpers.BROWSERS_DIR_NAME,
            "chromium_headless_shell-1243",
            "chrome-headless-shell-win64",
            "chrome-headless-shell.exe",
        ]
    )
    assert len(suffix) <= 110
    portable = r"C:\Users\prenom.nom\Cloud - Mon Entreprise\Documents\Outils\DomainRecon-1.0.0-portable-win64\DomainRecon"
    assert len(portable + suffix) < 260


def test_drop_dest_prefix_retire_les_navigateurs_en_double():
    entries = [
        (
            "playwright/driver/package/.local-browsers/chromium_headless_shell-1243/x/chrome.dll",
            "/s/1",
            "BINARY",
        ),
        (r"playwright\driver\package\.local-browsers\ffmpeg-1011\ffmpeg.exe", "/s/2", "DATA"),
        ("playwright/driver/package/cli.js", "/s/3", "DATA"),
        ("browsers/chromium_headless_shell-1243/x/chrome.dll", "/s/4", "BINARY"),
    ]
    kept = [entry[0] for entry in helpers.drop_dest_prefix(entries, helpers.PLAYWRIGHT_LOCAL_BROWSERS)]
    if sys.platform == "win32":
        assert kept == [
            "playwright/driver/package/cli.js",
            "browsers/chromium_headless_shell-1243/x/chrome.dll",
        ]
    else:
        assert "playwright/driver/package/cli.js" in kept
        assert "browsers/chromium_headless_shell-1243/x/chrome.dll" in kept
        assert entries[0][0] not in kept


def test_filter_system_libs():
    binaries = [
        ("libgtk-3.so.0", "/usr/lib/x86_64-linux-gnu/libgtk-3.so.0", "BINARY"),
        ("libglib-2.0.so.0", "/usr/lib/x86_64-linux-gnu/libglib-2.0.so.0", "BINARY"),
        ("libxcb-shm.so.0", "/usr/lib/x86_64-linux-gnu/libxcb-shm.so.0", "BINARY"),
        ("libX11.so.6", "/usr/lib/x86_64-linux-gnu/libX11.so.6", "BINARY"),
        ("libpython3.13.so.1.0", "/opt/python/lib/libpython3.13.so.1.0", "BINARY"),
        ("libffi.so.8", "/usr/lib/x86_64-linux-gnu/libffi.so.8", "BINARY"),
        (f"{SHELL_DEST}/libxcb.so.1", "/tmp/libxcb.so.1", "BINARY"),
    ]
    kept = [entry[0] for entry in helpers.filter_system_libs(binaries)]
    assert kept == ["libpython3.13.so.1.0", "libffi.so.8", f"{SHELL_DEST}/libxcb.so.1"]


def test_hooks_config_gtk3():
    config = helpers.hooks_config()["gi"]
    assert config["module-versions"] == {"Gtk": "3.0"}
    assert config["languages"] == ["fr", "en"]


def test_windows_version_info():
    pytest.importorskip("PyInstaller.utils.win32.versioninfo")
    text = str(helpers.windows_version_info("1.0.0", "DomainRecon.exe"))
    assert "DomainRecon.exe" in text
    assert "(1, 0, 0, 0)" in text
