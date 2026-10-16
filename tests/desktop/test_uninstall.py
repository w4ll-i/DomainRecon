"""Désinstallation complète (domainrecon/desktop/uninstall.py) : inventaire, suppression, suite après fermeture.

Tout se passe dans des dossiers temporaires : tâche système et processus détachés sont simulés,
rien n'est jamais lancé sur la machine.
"""

import base64
import os
import sys
from pathlib import Path, PurePosixPath

import pytest

from domainrecon.core import paths
from domainrecon.desktop import uninstall
from domainrecon.monitor import systask


class FauxSysteme:
    """Remplace schtasks / systemctl : note chaque commande, répond selon `installee`."""

    def __init__(self, installee: bool = False, refus: bool = False):
        self.installee = installee
        self.refus = refus
        self.appels: list[list[str]] = []

    def __call__(self, args):
        self.appels.append(list(args))
        if args[:2] == ["schtasks", "/Query"]:
            return (0 if self.installee else 1), ""
        if args[:2] == ["schtasks", "/Delete"]:
            if self.refus:
                return 1, "Accès refusé"
            self.installee = False
            return 0, ""
        if "is-enabled" in args:
            return (0 if self.installee else 1), ""
        if "disable" in args:
            self.installee = False
        return 0, ""


@pytest.fixture(autouse=True)
def jamais_le_vrai_systeme(monkeypatch):
    """Garde-fou : aucun vrai schtasks/systemctl, aucun vrai processus détaché."""
    monkeypatch.setattr(systask, "default_runner", lambda args: pytest.fail(f"commande système : {args}"))
    monkeypatch.setattr(uninstall, "spawn_detached", lambda args: pytest.fail(f"processus détaché : {args}"))


def ecrire(path: Path, contenu: bytes = b"x") -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(contenu)
    return path


def donnees(racine: Path) -> Path:
    """Dossier de données complet : base et annexe, captures, journaux, webview, réglages, secret."""
    data = racine / "DomainRecon"
    ecrire(data / "domainrecon.db", b"SQLite format 3\x00" + b"0" * 100)
    ecrire(data / "domainrecon.db-journal")
    ecrire(data / "screenshots" / "a.png", b"png")
    ecrire(data / "logs" / "domainrecon.log", b"log")
    ecrire(data / "webview" / "EBWebView" / "Local State", b"{}")
    ecrire(data / ".env", b"API_TOKEN=x")
    ecrire(data / ".secret_key", b"k" * 32)
    return data


def contexte(tmp_path: Path, **valeurs) -> uninstall.Context:
    data = valeurs.pop("data_dir", None) or donnees(tmp_path)
    app = tmp_path / "app"
    app.mkdir(exist_ok=True)
    base = {
        "mode": "source",
        "platform": "windows",
        "data_dir": data,
        "owned_data_dir": True,
        "safe_data_dir": True,
        "database_files": [
            data / "domainrecon.db",
            *(data / f"domainrecon.db{s}" for s in uninstall.SQLITE_SIDECARS),
        ],
        "external_database": None,
        "temp_dir": tmp_path / "tmp",
        "cache_targets": [],
        "app_dir": app,
        "executable": app / "DomainRecon.exe",
        "uninstaller": None,
        "pid": 4242,
        "runner": FauxSysteme(),
        "spawn": None,
    }
    base.update(valeurs)
    (tmp_path / "tmp").mkdir(exist_ok=True)
    return uninstall.Context(**base)


@pytest.fixture
def systeme_windows(monkeypatch):
    monkeypatch.setattr(systask, "platform_name", lambda: "windows")


# --- Inventaire à blanc ------------------------------------------------------------------------


def test_plan_liste_sans_rien_supprimer(tmp_path, systeme_windows):
    ctx = contexte(tmp_path, runner=FauxSysteme(installee=True))
    ecrire(tmp_path / "tmp" / "domainrecon-import-abc" / "x.db")
    ecrire(tmp_path / "tmp" / "autre-logiciel.tmp")
    rapport = uninstall.plan(ctx)
    assert rapport["dry_run"] is True
    sortes = {(item["kind"], Path(item["path"]).name) for item in rapport["items"]}
    assert {
        ("database", "domainrecon.db"),
        ("database", "domainrecon.db-journal"),
        ("screenshots", "screenshots"),
        ("logs", "logs"),
        ("webview", "webview"),
        ("settings_file", ".env"),
        ("secret_key", ".secret_key"),
        ("temp", "domainrecon-import-abc"),
        ("system_task", "DomainRecon-Monitor"),
    } == sortes
    assert all(item["status"] == "planned" for item in rapport["items"])
    taille = {Path(i["path"]).name: i["size"] for i in rapport["items"] if i["kind"] != "system_task"}
    assert taille["domainrecon.db"] == 116 and taille["screenshots"] == 3
    assert rapport["total_size"] == sum(taille.values())
    # Rien n'a bougé, la tâche a seulement été lue.
    assert (ctx.data_dir / "domainrecon.db").is_file() and (
        tmp_path / "tmp" / "domainrecon-import-abc"
    ).is_dir()
    assert ctx.runner.appels == [["schtasks", "/Query", "/TN", "DomainRecon-Monitor"]]
    assert {"code": "source_tree", "path": str(ctx.app_dir)} in rapport["remaining"]


def test_plan_sans_tache_installee(tmp_path, systeme_windows):
    rapport = uninstall.plan(contexte(tmp_path))
    assert "system_task" not in {item["kind"] for item in rapport["items"]}


# --- Suppression dans un dossier de données temporaire -----------------------------------------


def test_execute_supprime_tout_le_dossier_propre(tmp_path, systeme_windows):
    ctx = contexte(tmp_path, runner=FauxSysteme(installee=True))
    ecrire(ctx.data_dir / "inconnu.txt")  # dossier propre à DomainRecon : tout part
    ecrire(tmp_path / "tmp" / "domainrecon-cert-1.pem")
    voisin = ecrire(tmp_path / "tmp" / "autre-logiciel.tmp")
    rapport = uninstall.execute(ctx)
    assert not ctx.data_dir.exists()
    assert voisin.is_file()
    etats = {(item["kind"], item["status"]) for item in rapport["items"]}
    assert ("data_dir", "deleted") in etats and ("other_data", "deleted") in etats
    assert ("system_task", "deleted") in etats
    assert ["schtasks", "/Delete", "/TN", "DomainRecon-Monitor", "/F"] in ctx.runner.appels
    assert not any(i["status"] == "failed" for i in rapport["items"])
    assert rapport["after_exit_scheduled"] is False


def test_execute_dossier_personnalise_ne_prend_que_les_fichiers_connus(tmp_path, systeme_windows):
    ctx = contexte(tmp_path, owned_data_dir=False)
    autre = ecrire(ctx.data_dir / "mes-documents" / "rapport.odt")
    rapport = uninstall.execute(ctx)
    assert autre.is_file()
    assert not (ctx.data_dir / "domainrecon.db").exists() and not (ctx.data_dir / ".secret_key").exists()
    assert ctx.data_dir.is_dir()
    assert {"code": "custom_data_dir", "path": str(ctx.data_dir)} in rapport["remaining"]


def test_execute_dossier_dangereux_rien_n_est_touche(tmp_path, systeme_windows):
    ctx = contexte(tmp_path, safe_data_dir=False)
    rapport = uninstall.execute(ctx)
    assert (ctx.data_dir / "domainrecon.db").is_file()
    assert [i for i in rapport["items"] if i["kind"] != "system_task"] == []
    assert rapport["remaining"][0] == {"code": "unsafe_data_dir", "path": str(ctx.data_dir)}


def test_dossiers_dangereux(tmp_path):
    assert uninstall.is_dangerous_dir(Path.home())
    assert uninstall.is_dangerous_dir(Path.home().parent)
    assert uninstall.is_dangerous_dir(Path(Path.home().anchor))
    assert uninstall.is_dangerous_dir(paths.package_dir().parent)  # contiendrait le code
    assert not uninstall.is_dangerous_dir(tmp_path / "DomainRecon")


def test_base_externe_jamais_supprimee(tmp_path, systeme_windows):
    externe = ecrire(tmp_path / "ailleurs" / "ma-base.db")
    ctx = contexte(tmp_path, database_files=[], external_database=str(externe))
    rapport = uninstall.execute(ctx)
    assert externe.is_file()
    assert {"code": "external_database", "path": str(externe)} in rapport["remaining"]


def test_echec_d_une_tache_systeme_n_arrete_pas_la_suite(tmp_path, systeme_windows):
    ctx = contexte(tmp_path, runner=FauxSysteme(installee=True, refus=True))
    rapport = uninstall.execute(ctx)
    assert {
        "kind": "system_task",
        "path": "DomainRecon-Monitor",
        "status": "failed",
        "size": None,
    } in rapport["items"]
    assert not ctx.data_dir.exists()


def test_tache_systemd_linux(tmp_path, monkeypatch):
    monkeypatch.setattr(systask, "platform_name", lambda: "linux")
    unites = tmp_path / "systemd"
    ecrire(unites / "domainrecon-monitor.timer")
    ecrire(unites / "domainrecon-monitor.service")
    ecrire(unites / "autre.timer")
    ctx = contexte(tmp_path, platform="linux", runner=FauxSysteme(installee=True), systask_config_dir=unites)
    rapport = uninstall.execute(ctx)
    assert {
        "kind": "system_task",
        "path": "domainrecon-monitor.timer",
        "status": "deleted",
        "size": None,
    } in rapport["items"]
    assert sorted(p.name for p in unites.iterdir()) == ["autre.timer"]
    assert ["systemctl", "--user", "disable", "--now", "domainrecon-monitor.timer"] in ctx.runner.appels


# --- Garde-fous : périmètre et liens -------------------------------------------------------------


def test_remove_path_refuse_hors_perimetre(tmp_path):
    racine = tmp_path / "racine"
    racine.mkdir()
    dehors = ecrire(tmp_path / "dehors.txt")
    with pytest.raises(uninstall.UnsafePath):
        uninstall.remove_path(dehors, racine)
    with pytest.raises(uninstall.UnsafePath):
        uninstall.remove_path(racine / ".." / "dehors.txt", racine)
    with pytest.raises(uninstall.UnsafePath):
        uninstall.remove_path(racine, racine)  # la racine elle-même
    assert dehors.is_file()


def test_execute_ignore_une_cible_hors_perimetre(tmp_path, systeme_windows):
    dehors = ecrire(tmp_path / "precieux" / "garde.txt")
    ctx = contexte(tmp_path, cache_targets=[uninstall.Target("cache", dehors.parent, tmp_path / "app")])
    rapport = uninstall.execute(ctx)
    assert dehors.is_file()
    assert {"kind": "cache", "path": str(dehors.parent), "status": "skipped", "size": None} in rapport[
        "items"
    ]


def _lien_de_dossier(lien: Path, cible: Path) -> None:
    """Jonction sous Windows (sans droit particulier), lien symbolique ailleurs."""
    if sys.platform == "win32":
        import _winapi

        _winapi.CreateJunction(str(cible), str(lien))
    else:
        os.symlink(cible, lien, target_is_directory=True)


def test_lien_vers_l_exterieur_retire_sans_etre_suivi(tmp_path, systeme_windows):
    exterieur = tmp_path / "exterieur"
    precieux = ecrire(exterieur / "precieux.txt")
    ctx = contexte(tmp_path)
    _lien_de_dossier(ctx.data_dir / "screenshots" / "piege", exterieur)  # au fond d'un dossier supprimé
    _lien_de_dossier(ctx.data_dir / "webview-lien", exterieur)  # au premier niveau
    rapport = uninstall.execute(ctx)
    assert precieux.is_file() and precieux.read_bytes() == b"x"
    assert not ctx.data_dir.exists()
    assert not any(i["status"] == "failed" for i in rapport["items"])


def test_lien_symbolique_de_fichier(tmp_path):
    racine = tmp_path / "racine"
    precieux = ecrire(tmp_path / "precieux.txt")
    racine.mkdir()
    try:
        os.symlink(precieux, racine / "lien.txt")
    except OSError:
        pytest.skip("liens symboliques non autorisés sur ce poste")
    assert uninstall.remove_path(racine / "lien.txt", racine) == "deleted"
    assert precieux.is_file()


def test_parent_lien_vers_l_exterieur_refuse(tmp_path):
    racine = tmp_path / "racine"
    racine.mkdir()
    exterieur = tmp_path / "exterieur"
    precieux = ecrire(exterieur / "precieux.txt")
    _lien_de_dossier(racine / "passage", exterieur)
    with pytest.raises(uninstall.UnsafePath):
        uninstall.remove_path(racine / "passage" / "precieux.txt", racine)
    assert precieux.is_file()


def test_fichier_en_lecture_seule(tmp_path):
    racine = tmp_path / "racine"
    fichier = ecrire(racine / "lecture-seule.txt")
    os.chmod(fichier, 0o444)
    assert uninstall.remove_path(fichier, racine) == "deleted"
    assert uninstall.remove_path(fichier, racine) == "missing"


# --- Mode de lancement -----------------------------------------------------------------------------


def _gele(monkeypatch, app: Path, plateforme: str = "win32"):
    monkeypatch.setattr(sys, "frozen", True, raising=False)
    monkeypatch.setattr(sys, "executable", str(app / "DomainRecon.exe"))
    monkeypatch.setattr(sys, "platform", plateforme)
    monkeypatch.delenv("DOMAINRECON_PORTABLE", raising=False)
    monkeypatch.delattr(sys, "_MEIPASS", raising=False)


def test_mode_sources():
    assert uninstall.detect_mode() == "source"


def test_dossier_des_sources_propre_a_domainrecon():
    """private/data/ (défaut des sources) est un dossier propre ; la racine du dépôt ne l'est pas."""
    dirs = uninstall.default_data_dirs()
    assert paths.source_data_dir() in dirs
    assert paths.app_dir() / "private" / "data" in dirs
    assert paths.app_dir() not in dirs
    assert paths.app_dir() / "private" not in dirs


def test_mode_windows_installe(monkeypatch, tmp_path):
    app = tmp_path / "Programs" / "DomainRecon"
    ecrire(app / "DomainRecon.exe")
    _gele(monkeypatch, app)
    assert uninstall.detect_mode() == "frozen_other"  # sans désinstalleur : simple dossier
    ecrire(app / "unins000.exe")
    assert uninstall.detect_mode() == "frozen_other"  # .dat absent : pas un désinstalleur Inno complet
    ecrire(app / "unins000.dat")
    assert uninstall.detect_mode() == "windows_installed"
    assert uninstall.find_uninstaller(app) == app / "unins000.exe"


def test_mode_portables(monkeypatch, tmp_path):
    app = tmp_path / "DomainRecon"
    ecrire(app / "DomainRecon.exe")
    ecrire(app / "portable.flag")
    _gele(monkeypatch, app)
    assert uninstall.detect_mode() == "portable_folder"
    bundle = tmp_path / "_MEI123"
    ecrire(bundle / "portable.flag")
    (app / "portable.flag").unlink()
    monkeypatch.setattr(sys, "_MEIPASS", str(bundle), raising=False)
    assert uninstall.detect_mode() == "portable_onefile"


def test_mode_deb(monkeypatch):
    _gele(monkeypatch, uninstall.DEB_APP_DIR, plateforme="linux")
    monkeypatch.setattr(paths, "app_dir", lambda: uninstall.DEB_APP_DIR)
    assert uninstall.detect_mode() == "deb"


# --- Suite après fermeture : jamais lancée pour de vrai --------------------------------------------


def _script_powershell(commande: list[str]) -> str:
    assert commande[0] == "powershell.exe" and commande[-2] == "-EncodedCommand"
    return base64.b64decode(commande[-1]).decode("utf-16-le")


def test_windows_installe_lance_le_desinstalleur_apres_la_fermeture(tmp_path, systeme_windows):
    lances: list[list[str]] = []
    desinstalleur = ecrire(tmp_path / "app" / "unins000.exe")
    ctx = contexte(tmp_path, mode="windows_installed", uninstaller=desinstalleur, spawn=lances.append)
    rapport = uninstall.execute(ctx)
    assert len(lances) == 1
    script = _script_powershell(lances[0])
    assert "$p = Get-Process -Id 4242" in script
    assert "WaitForExit(600000)) { exit 1 }" in script
    assert script.index("WaitForExit") < script.index("Start-Process")
    assert (
        f"Start-Process -FilePath '{desinstalleur}' -ArgumentList "
        "'/VERYSILENT','/SUPPRESSMSGBOXES','/NORESTART','/PURGEDATA'"
    ) in script
    assert rapport["after_exit_scheduled"] is True
    assert rapport["uninstaller"] == str(desinstalleur)
    assert {"code": "windows_uninstaller", "path": str(desinstalleur)} in rapport["remaining"]


def test_echec_du_lancement_detache_signale(tmp_path, systeme_windows):
    def refuse(args):
        raise OSError("powershell introuvable")

    desinstalleur = ecrire(tmp_path / "app" / "unins000.exe")
    ctx = contexte(tmp_path, mode="windows_installed", uninstaller=desinstalleur, spawn=refuse)
    assert uninstall.execute(ctx)["after_exit_scheduled"] is False


def test_portable_dossier_programme_supprime_apres_fermeture(tmp_path, systeme_windows):
    app = tmp_path / "DomainRecon-1.0.0"
    for nom in ("DomainRecon.exe", "DomainRecon-console.exe", "portable.flag", "Lancer DomainRecon.bat"):
        ecrire(app / nom)
    ecrire(app / "_internal" / "base_library.zip")
    a_moi = ecrire(app / "mes-notes.txt")
    lances: list[list[str]] = []
    data = donnees(app / "data-parent")
    ctx = contexte(
        tmp_path,
        mode="portable_folder",
        app_dir=app,
        executable=app / "DomainRecon.exe",
        data_dir=data,
        spawn=lances.append,
    )
    sans = uninstall.execute(ctx)
    assert lances == [] and {"code": "delete_program", "path": str(app)} in sans["remaining"]
    assert sans["program_removal"]["available"] is True

    donnees(app / "data-parent")
    rapport = uninstall.execute(ctx, remove_program=True)
    script = _script_powershell(lances[0])
    assert f"& cmd.exe /d /c rmdir /s /q '{app / '_internal'}'" in script
    assert f"Remove-Item -LiteralPath '{app / 'DomainRecon.exe'}' -Force" in script
    assert f"& cmd.exe /d /c rmdir '{app}'" in script  # le dossier, seulement s'il est vide
    assert str(a_moi) not in script
    assert a_moi.is_file() and (app / "DomainRecon.exe").is_file()  # rien avant la fermeture
    assert {"code": "program_scheduled", "path": str(app)} in rapport["remaining"]


def test_portable_dossier_sans_marqueur_jamais_supprime(tmp_path, systeme_windows):
    app = tmp_path / "DomainRecon"
    ecrire(app / "DomainRecon.exe")
    ctx = contexte(tmp_path, mode="portable_folder", app_dir=app, executable=app / "DomainRecon.exe")
    assert uninstall.program_removal(ctx) == {"available": False, "paths": []}


def test_portable_monofichier(tmp_path, systeme_windows):
    exe = ecrire(tmp_path / "telechargements" / "DomainRecon-1.0.0-portable.exe")
    lances: list[list[str]] = []
    ctx = contexte(tmp_path, mode="portable_onefile", executable=exe, spawn=lances.append)
    rapport = uninstall.execute(ctx, remove_program=True)
    script = _script_powershell(lances[0])
    assert f"Remove-Item -LiteralPath '{exe}' -Force" in script
    assert str(exe.parent) + "'" not in script.replace(str(exe), "")  # le dossier des téléchargements reste
    assert rapport["program_removal"] == {"available": True, "paths": [str(exe)]}


def test_fichiers_verrouilles_supprimes_apres_fermeture(tmp_path, systeme_windows, monkeypatch):
    lances: list[list[str]] = []
    ctx = contexte(tmp_path, spawn=lances.append)
    reel = uninstall.remove_path
    monkeypatch.setattr(
        uninstall, "remove_path", lambda path, root: "failed" if path.name == "logs" else reel(path, root)
    )
    rapport = uninstall.execute(ctx)
    script = _script_powershell(lances[0])
    assert f"rmdir /s /q '{ctx.data_dir / 'logs'}'" in script
    assert f"& cmd.exe /d /c rmdir '{ctx.data_dir}'" in script
    assert {"code": "leftovers_scheduled"} in rapport["remaining"]


def test_chemin_dangereux_pour_cmd_ignore(tmp_path):
    ctx = contexte(tmp_path, platform="windows")
    script = _script_powershell(uninstall.after_exit_command(ctx, [("rmtree", Path("C:/a&b/c"))]))
    assert "a&b" not in script


def test_apostrophe_protegee_dans_powershell(tmp_path):
    ctx = contexte(tmp_path, platform="windows")
    script = _script_powershell(uninstall.after_exit_command(ctx, [("unlink", Path("C:/l'été/x.exe"))]))
    assert "-LiteralPath 'C:" in script and "l''été" in script


def test_commande_linux(tmp_path):
    ctx = contexte(tmp_path, platform="linux")
    commande = uninstall.after_exit_command(
        ctx,
        [
            ("rmtree", PurePosixPath("/home/moi/Domain Recon/_internal")),
            ("rmdir", PurePosixPath("/home/moi/Domain Recon")),
        ],
    )
    assert commande[:2] == ["/bin/sh", "-c"]
    assert "kill -0 4242" in commande[2]
    assert "rm -rf -- '/home/moi/Domain Recon/_internal'" in commande[2]
    assert "rmdir -- '/home/moi/Domain Recon'" in commande[2]


def test_deb_affiche_la_commande_apt(tmp_path, monkeypatch):
    monkeypatch.setattr(systask, "platform_name", lambda: "linux")
    ctx = contexte(tmp_path, mode="deb", platform="linux", systask_config_dir=tmp_path / "systemd")
    rapport = uninstall.execute(ctx)
    assert {"code": "apt_remove", "command": "sudo apt remove domainrecon"} in rapport["remaining"]
    assert not ctx.data_dir.exists()


def test_contexte_reel_lecture_seule(monkeypatch):
    """build_context ne lance rien : la tâche système n'est lue qu'au plan, par le runner simulé ici."""
    monkeypatch.setattr(systask, "default_runner", FauxSysteme())
    ctx = uninstall.build_context()
    assert ctx.mode == "source"
    assert ctx.spawn is uninstall.spawn_detached
    assert ctx.owned_data_dir is False  # DATA_DIR des tests : dossier temporaire personnalisé
    assert ctx.safe_data_dir is True


# --- Fermeture de l'application par le lanceur ------------------------------------------------------


def test_lanceur_ferme_fenetre_et_serveur(monkeypatch):
    from types import SimpleNamespace

    from domainrecon.api.app import app
    from domainrecon.desktop import launcher

    detruites: list[str] = []
    fenetre = SimpleNamespace(destroy=lambda: detruites.append("fenêtre"))
    monkeypatch.setitem(sys.modules, "webview", SimpleNamespace(windows=[fenetre]))
    monkeypatch.setattr(launcher, "_box_thread", None)
    serveur = SimpleNamespace(should_exit=False)
    monkeypatch.setattr(app.state, "exit_app", None, raising=False)
    launcher.register_exit(serveur)
    app.state.exit_app()
    assert detruites == ["fenêtre"] and serveur.should_exit is True
