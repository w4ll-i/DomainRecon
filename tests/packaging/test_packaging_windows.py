"""Livrables Windows : zip portable et installeur Inno Setup."""

import os
import sys
import zipfile
from pathlib import Path

import pytest

from pkgload import load, touch

ROOT = Path(__file__).resolve().parents[2]
ISS = ROOT / "packaging" / "windows" / "installer.iss"


build = load("build", "build.py")


def test_make_portable_zip(tmp_path):
    """Mode portable et fins de ligne : marqueur et lanceur dans le zip seulement ; lanceur ASCII en CRLF."""
    app = tmp_path / "dist" / "DomainRecon"
    touch(app / "DomainRecon.exe")
    touch(app / "DomainRecon-console.exe")
    touch(app / "_internal" / "base_library.zip")
    archive = build.make_portable_zip(app, tmp_path / "dist" / "DomainRecon-1.0.0-portable-win64.zip")
    with zipfile.ZipFile(archive) as zf:
        names = set(zf.namelist())
        bat = zf.read("DomainRecon/Lancer DomainRecon.bat")
        flag = zf.read("DomainRecon/portable.flag").decode("utf-8")
    assert {
        "DomainRecon/DomainRecon.exe",
        "DomainRecon/DomainRecon-console.exe",
        "DomainRecon/_internal/base_library.zip",
        "DomainRecon/portable.flag",
        "DomainRecon/Lancer DomainRecon.bat",
    } <= names
    assert not (app / "portable.flag").exists()
    assert not (app / "Lancer DomainRecon.bat").exists()
    assert b'"%~dp0DomainRecon-console.exe" --browser' in bat
    assert bat.isascii()
    assert b"\n" not in bat.replace(b"\r\n", b"")
    assert "data\\" in flag


def test_make_portable_zip_fichier_anterieur_a_1980(tmp_path):
    """Un fichier de dépendance daté d'avant 1980 ne fait pas échouer l'archive."""
    app = tmp_path / "dist" / "DomainRecon"
    ancien = touch(app / "_internal" / "ancien.dll")
    os.utime(ancien, (0, 0))
    archive = build.make_portable_zip(app, tmp_path / "dist" / "portable.zip")
    with zipfile.ZipFile(archive) as zf:
        assert "DomainRecon/_internal/ancien.dll" in zf.namelist()


def test_make_portable_zip_sans_archive_partielle_apres_echec(monkeypatch, tmp_path):
    app = tmp_path / "dist" / "DomainRecon"
    touch(app / "DomainRecon.exe")

    def echec(self, *args, **kwargs):
        raise OSError("disque plein")

    monkeypatch.setattr(zipfile.ZipFile, "writestr", echec)
    zip_path = tmp_path / "dist" / "portable.zip"
    with pytest.raises(OSError, match="disque plein"):
        build.make_portable_zip(app, zip_path)
    assert not zip_path.exists()
    assert not zip_path.with_name("portable.zip.part").exists()


def test_marqueur_portable_identique_au_code():
    from domainrecon.core import paths

    assert build.PORTABLE_FLAG == paths.PORTABLE_FLAG


def test_find_iscc_variable(tmp_path):
    iscc = touch(tmp_path / "ISCC.exe")
    assert build.find_iscc({"ISCC": str(iscc), "PATH": str(tmp_path / "vide")}) == iscc


def test_find_iscc_installation_par_utilisateur(tmp_path):
    iscc = touch(tmp_path / "Local" / "Programs" / "Inno Setup 6" / "ISCC.exe")
    assert build.find_iscc({"LOCALAPPDATA": str(tmp_path / "Local"), "PATH": str(tmp_path / "vide")}) == iscc


def test_find_iscc_program_files_x86_version_7(tmp_path):
    iscc = touch(tmp_path / "PF86" / "Inno Setup 7" / "ISCC.exe")
    assert (
        build.find_iscc({"ProgramFiles(x86)": str(tmp_path / "PF86"), "PATH": str(tmp_path / "vide")}) == iscc
    )


def test_find_iscc_absent(tmp_path):
    assert build.find_iscc({"PATH": str(tmp_path / "vide")}) is None


def test_find_iscc_variable_invalide(tmp_path):
    """ISCC pointe vers un fichier inexistant : erreur explicite, pas de repli silencieux sur le PATH."""
    iscc = touch(tmp_path / "bin" / "ISCC.exe")
    absent = tmp_path / "absent" / "ISCC.exe"
    with pytest.raises(build.BuildError, match=r"ISCC pointe vers un fichier inexistant : .*absent"):
        build.find_iscc({"ISCC": str(absent), "PATH": str(iscc.parent)})


def test_build_installer_variable_iscc_invalide(monkeypatch, tmp_path):
    monkeypatch.setenv("ISCC", str(tmp_path / "absent.exe"))
    with pytest.raises(build.BuildError, match="ISCC pointe vers un fichier inexistant"):
        build.build_installer(tmp_path, tmp_path / "dist" / "DomainRecon", "1.0.0")


def test_installer_command(tmp_path):
    app = tmp_path / "dist" / "DomainRecon"
    cmd = build.installer_command(Path("C:/Inno/ISCC.exe"), tmp_path, app, "1.0.0", tmp_path / "dist")
    assert cmd[0] == str(Path("C:/Inno/ISCC.exe"))
    assert cmd[1] == "/Qp"
    assert "/DAppVersion=1.0.0" in cmd
    assert f"/DSourceDir={app}" in cmd
    assert f"/DOutputDir={tmp_path / 'dist'}" in cmd
    assert f"/DRepoRoot={tmp_path}" in cmd
    assert cmd[-1] == str(tmp_path / "packaging" / "windows" / "installer.iss")


def test_build_installer_sans_inno_setup(monkeypatch, tmp_path):
    monkeypatch.setattr(build, "find_iscc", lambda environ=None: None)
    with pytest.raises(build.BuildError, match="winget install --id JRSoftware.InnoSetup"):
        build.build_installer(tmp_path, tmp_path / "dist" / "DomainRecon", "1.0.0")


def test_build_installer_sortie_dans_release(monkeypatch, tmp_path):
    """L'installeur est compilé directement dans release/<version>/."""
    commands = []
    iscc = touch(tmp_path / "Inno" / "ISCC.exe")
    monkeypatch.setattr(build, "find_iscc", lambda environ=None: iscc)

    def fake_run(cmd, **kwargs):
        commands.append([str(c) for c in cmd])
        touch(tmp_path / "release" / "1.0.0" / "DomainRecon-1.0.0-setup.exe")

    monkeypatch.setattr(build, "run", fake_run)
    app = tmp_path / "private" / "build" / "dist" / "DomainRecon"
    setup = build.build_installer(tmp_path, app, "1.0.0")
    assert setup == tmp_path / "release" / "1.0.0" / "DomainRecon-1.0.0-setup.exe"
    assert f"/DOutputDir={tmp_path / 'release' / '1.0.0'}" in commands[0]
    assert f"/DSourceDir={app}" in commands[0]


def test_iss_sortie_par_defaut_dans_release():
    text = ISS.read_text(encoding="utf-8")
    assert '#define OutputDir "..\\..\\release\\" + AppVersion' in text
    assert "dist" not in text.replace("private\\build\\dist", "")


def test_package_windows(monkeypatch, tmp_path):
    monkeypatch.setattr(build, "make_portable_zip", lambda app_dir, zip_path: zip_path)
    monkeypatch.setattr(
        build,
        "build_installer",
        lambda root, app_dir, version: root / "release" / version / f"DomainRecon-{version}-setup.exe",
    )
    monkeypatch.setattr(
        build,
        "build_onefile",
        lambda root, version: root / "release" / version / f"DomainRecon-{version}-portable.exe",
    )
    app = tmp_path / "private" / "build" / "dist" / "DomainRecon"
    portable = tmp_path / "release" / "1.0.0" / "DomainRecon-1.0.0-portable-win64.zip"
    setup = tmp_path / "release" / "1.0.0" / "DomainRecon-1.0.0-setup.exe"
    onefile = tmp_path / "release" / "1.0.0" / "DomainRecon-1.0.0-portable.exe"
    result = build.package("windows", tmp_path, app, "1.0.0", skip_installer=False)
    assert result == [app, portable, setup, onefile]
    assert build.package("windows", tmp_path, app, "1.0.0", skip_installer=True) == [app, portable, onefile]
    assert build.package("windows", tmp_path, app, "1.0.0", skip_installer=True, skip_onefile=True) == [
        app,
        portable,
    ]


def test_iss_installation_par_utilisateur():
    text = ISS.read_text(encoding="utf-8")
    for fragment in (
        "AppId={{63B0E60D-B27E-416A-BEEE-703BF27CD9DC}",
        "PrivilegesRequired=lowest",
        "DefaultDirName={autopf}\\{#AppName}",
        "ArchitecturesInstallIn64BitMode=x64compatible",
        "OutputBaseFilename={#AppName}-{#AppVersion}-setup",
        "SetupIconFile={#RepoRoot}\\packaging\\icons\\domainrecon.ico",
        'Name: "{autoprograms}\\{#AppName}"',
        "Tasks: desktopicon",
        'Parameters: "--browser"',
        'Name: "fr"; MessagesFile: "compiler:Languages\\French.isl"',
    ):
        assert fragment in text, fragment


def test_iss_exclut_le_mode_portable():
    """L'installeur ne contient ni le marqueur portable ni les données."""
    assert 'Excludes: "portable.flag,\\data\\*"' in ISS.read_text(encoding="utf-8")


def test_iss_desinstallation_nettoie_internal():
    """Régression : tldextract écrit son cache dans _internal (mesuré) ; sans cela, le dossier survit à la désinstallation."""
    text = ISS.read_text(encoding="utf-8")
    assert "[UninstallDelete]" in text
    assert 'Type: filesandordirs; Name: "{app}\\_internal"' in text


def test_iss_donnees_conservees_par_defaut():
    text = ISS.read_text(encoding="utf-8")
    assert '#define DataDirName "DomainRecon"' in text
    assert "{localappdata}\\{#DataDirName}" in text
    assert "MB_YESNO or MB_DEFBUTTON2" in text
    assert "UninstallSilent()" in text


def test_dossier_des_donnees_windows_identique_a_l_installeur(monkeypatch, tmp_path):
    """Le dossier que l'installeur propose de supprimer est bien celui de l'application installée."""
    from domainrecon.core import paths

    app = tmp_path / "Programs" / "DomainRecon"
    app.mkdir(parents=True)
    monkeypatch.setattr(sys, "frozen", True, raising=False)
    monkeypatch.setattr(sys, "executable", str(app / "DomainRecon.exe"))
    monkeypatch.setattr(sys, "platform", "win32")
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path / "Local"))
    monkeypatch.delenv("DATA_DIR", raising=False)
    monkeypatch.delenv("DOMAINRECON_PORTABLE", raising=False)
    assert paths.data_dir() == tmp_path / "Local" / "DomainRecon"


def test_iss_desinstallation_complete():
    """« Désinstaller complètement » (Réglages) : /PURGEDATA supprime les données, la tâche planifiée part toujours."""
    from domainrecon.desktop import uninstall
    from domainrecon.monitor import systask

    text = ISS.read_text(encoding="utf-8")
    assert f'#define MonitorTask "{systask.WINDOWS_TASK}"' in text
    assert "[UninstallRun]" in text
    assert (
        'Filename: "{sys}\\schtasks.exe"; Parameters: "/Delete /TN ""{#MonitorTask}"" /F"; Flags: runhidden'
        in text
    )
    assert "CompareText(ParamStr(I), '/PURGEDATA') = 0" in text
    assert "RemoveUserData := PurgeDataRequested();" in text
    # Le dossier de l'application ne part que vide : jamais un contenu inconnu.
    assert 'Type: dirifempty; Name: "{app}"' in text
    assert 'Type: filesandordirs; Name: "{app}"\n' not in text
    assert "/PURGEDATA" in uninstall.UNINSTALLER_ARGS and "/VERYSILENT" in uninstall.UNINSTALLER_ARGS
