"""Routes de sauvegarde et de désinstallation complète (domainrecon/api/routes/uninstall.py).

Le contexte de la désinstallation est toujours un dossier temporaire ; tâche système, processus
détachés et fermeture de l'application sont simulés : rien n'est jamais lancé sur la machine.
"""

import sqlite3
import time
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from domainrecon.api.app import app
from domainrecon.api.routes import uninstall as uninstall_routes
from domainrecon.core import config
from domainrecon.desktop import uninstall
from domainrecon.monitor import systask

LOCAL = ("127.0.0.1", 50000)


class FauxSysteme:
    def __init__(self, installee: bool = True):
        self.installee = installee
        self.appels: list[list[str]] = []

    def __call__(self, args):
        self.appels.append(list(args))
        if args[:2] == ["schtasks", "/Query"]:
            return (0 if self.installee else 1), ""
        if args[:2] == ["schtasks", "/Delete"]:
            self.installee = False
        return 0, ""


def ecrire(path: Path, contenu: bytes = b"x") -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(contenu)
    return path


@pytest.fixture
def bac_a_sable(tmp_path, monkeypatch):
    """Contexte de désinstallation sur un dossier de données temporaire ; état de l'application rétabli ensuite."""
    monkeypatch.setenv("SCHEDULER", "0")
    monkeypatch.setattr(systask, "default_runner", lambda args: pytest.fail(f"commande système : {args}"))
    monkeypatch.setattr(systask, "platform_name", lambda: "windows")
    monkeypatch.setattr(uninstall, "spawn_detached", lambda args: pytest.fail(f"processus détaché : {args}"))
    data = tmp_path / "DomainRecon"
    ecrire(data / "domainrecon.db", b"SQLite format 3\x00")
    ecrire(data / "screenshots" / "a.png")
    ecrire(data / ".secret_key", b"k" * 32)
    (tmp_path / "tmp").mkdir()
    systeme = FauxSysteme()
    lances: list[list[str]] = []

    def fabrique(**valeurs):
        base = {
            "mode": "windows_installed",
            "platform": "windows",
            "data_dir": data,
            "owned_data_dir": True,
            "safe_data_dir": True,
            "database_files": [data / "domainrecon.db"],
            "external_database": None,
            "temp_dir": tmp_path / "tmp",
            "cache_targets": [],
            "app_dir": tmp_path / "app",
            "executable": tmp_path / "app" / "DomainRecon.exe",
            "uninstaller": tmp_path / "app" / "unins000.exe",
            "pid": 4242,
            "runner": systeme,
            "spawn": lances.append,
        }
        base.update(valeurs)
        return uninstall.Context(**base)

    monkeypatch.setattr(uninstall, "context_factory", fabrique)
    fermetures: list[str] = []
    monkeypatch.setattr(app.state, "exit_app", lambda: fermetures.append("fermée"), raising=False)
    yield {"data": data, "systeme": systeme, "lances": lances, "fermetures": fermetures, "fabrique": fabrique}
    for name in ("uninstalled", "uninstall_done"):
        if hasattr(app.state, name):
            delattr(app.state, name)


def test_a_blanc_liste_sans_supprimer(bac_a_sable):
    with TestClient(app, client=LOCAL) as client:
        r = client.post("/api/system/uninstall", json={"dry_run": True})
    assert r.status_code == 200
    rapport = r.json()
    assert rapport["dry_run"] is True and rapport["mode"] == "windows_installed"
    assert {Path(i["path"]).name for i in rapport["items"]} == {
        "domainrecon.db",
        "screenshots",
        ".secret_key",
        "DomainRecon-Monitor",
    }
    assert rapport["can_exit"] is True
    assert (bac_a_sable["data"] / "domainrecon.db").is_file()
    assert bac_a_sable["lances"] == []
    assert not any(args[:2] == ["schtasks", "/Delete"] for args in bac_a_sable["systeme"].appels)


@pytest.mark.parametrize("corps", [{}, {"confirm": ""}, {"confirm": "supprimer tout"}, {"confirm": "OUI"}])
def test_refus_sans_confirmation(bac_a_sable, corps):
    with TestClient(app, client=LOCAL) as client:
        r = client.post("/api/system/uninstall?lang=fr", json=corps)
    assert r.status_code == 400
    assert r.json()["code"] == "api.uninstall_confirm"
    assert (bac_a_sable["data"] / "domainrecon.db").is_file()


def test_refus_d_une_autre_machine(bac_a_sable):
    with TestClient(app) as distant:  # adresse « testclient »
        reponses = [
            distant.post("/api/system/uninstall", json={"dry_run": True}),
            distant.post("/api/system/uninstall", json={"confirm": "SUPPRIMER"}),
            distant.post("/api/system/uninstall/finish", json={}),
            distant.post("/api/system/backup", json={}),
        ]
    assert [r.status_code for r in reponses] == [403] * 4
    assert {r.json()["code"] for r in reponses} == {"api.local_only"}
    assert (bac_a_sable["data"] / "domainrecon.db").is_file()


def test_refus_sans_corps_json(bac_a_sable):
    with TestClient(app, client=LOCAL) as client:
        r = client.post(
            "/api/system/uninstall", content="confirm=SUPPRIMER", headers={"Content-Type": "text/plain"}
        )
    assert r.status_code == 415
    assert (bac_a_sable["data"] / "domainrecon.db").is_file()


def test_desinstallation_puis_fermeture(bac_a_sable, monkeypatch):
    monkeypatch.setattr(uninstall_routes, "EXIT_DELAY", 0)
    with TestClient(app, client=LOCAL) as client:
        assert client.post("/api/system/uninstall/finish", json={}).status_code == 409
        r = client.post("/api/system/uninstall?lang=en", json={"confirm": "DELETE"})
        assert r.status_code == 200
        rapport = r.json()
        # Après coup, l'API ne rouvre plus la base : 410 partout, sauf battement et fermeture.
        apres = client.get("/api/history?lang=en")
        assert apres.status_code == 410
        assert apres.json()["detail"] == "DomainRecon has been uninstalled: close the application."
        assert client.get("/api/health").status_code == 410
        assert client.post("/api/system/heartbeat", json={}).status_code == 204
        fin = client.post("/api/system/uninstall/finish", json={})
        assert fin.json() == {"exiting": True}
        time.sleep(0.3)  # fermeture demandée après la réponse
    assert not bac_a_sable["data"].exists()
    assert rapport["dry_run"] is False
    assert {(Path(i["path"]).name, i["status"]) for i in rapport["items"]} >= {
        ("domainrecon.db", "deleted"),
        ("screenshots", "deleted"),
        (".secret_key", "deleted"),
        ("DomainRecon-Monitor", "deleted"),
        ("DomainRecon", "deleted"),
    }
    # Désinstalleur Inno Setup : un seul processus détaché, préparé, jamais lancé pour de vrai.
    assert len(bac_a_sable["lances"]) == 1 and bac_a_sable["lances"][0][0] == "powershell.exe"
    assert rapport["after_exit_scheduled"] is True
    assert bac_a_sable["fermetures"] == ["fermée"]


def test_fermeture_impossible_sans_lanceur(bac_a_sable, monkeypatch):
    monkeypatch.delattr(app.state, "exit_app")
    with TestClient(app, client=LOCAL) as client:
        rapport = client.post("/api/system/uninstall", json={"confirm": "SUPPRIMER"}).json()
        assert rapport["can_exit"] is False
        assert client.post("/api/system/uninstall/finish", json={}).json() == {"exiting": False}


def test_contexte_isole_ne_coupe_pas_l_application(bac_a_sable, monkeypatch):
    """Serveur E2E : vraie suppression dans son dossier de test, l'API reste servie."""
    monkeypatch.setattr(
        uninstall, "context_factory", lambda: bac_a_sable["fabrique"](isolated=True, spawn=None)
    )
    with TestClient(app, client=LOCAL) as client:
        assert client.post("/api/system/uninstall", json={"confirm": "SUPPRIMER"}).status_code == 200
        assert client.get("/api/history").status_code == 200
    assert not bac_a_sable["data"].exists()


def test_sauvegarde_reimportable(monkeypatch, tmp_path):
    monkeypatch.setenv("SCHEDULER", "0")
    base = tmp_path / "source.db"
    con = sqlite3.connect(base)
    con.execute("CREATE TABLE scans (id INTEGER PRIMARY KEY, domain TEXT)")
    con.execute("INSERT INTO scans (domain) VALUES ('example.org')")
    con.commit()
    con.close()
    monkeypatch.setattr(config, "DATABASE_URL", f"sqlite:///{base.as_posix()}")
    with TestClient(app, client=LOCAL) as client:
        r = client.post("/api/system/backup", json={})
    assert r.status_code == 200
    assert r.headers["content-type"] == "application/vnd.sqlite3"
    assert 'filename="domainrecon-sauvegarde-' in r.headers["content-disposition"]
    assert r.content.startswith(b"SQLite format 3\x00")
    copie = ecrire(tmp_path / "copie.db", r.content)
    con = sqlite3.connect(copie)
    assert con.execute("SELECT domain FROM scans").fetchall() == [("example.org",)]
    con.close()
    # Le fichier temporaire de la sauvegarde est supprimé après l'envoi.
    import tempfile

    assert not list(Path(tempfile.gettempdir()).glob("domainrecon-backup-*.db"))


@pytest.mark.parametrize("url", ["postgresql+psycopg://u:p@localhost/x", "sqlite:///{absent}"])
def test_sauvegarde_indisponible(monkeypatch, tmp_path, url):
    monkeypatch.setenv("SCHEDULER", "0")
    monkeypatch.setattr(config, "DATABASE_URL", url.format(absent=(tmp_path / "absent.db").as_posix()))
    with TestClient(app, client=LOCAL) as client:
        r = client.post("/api/system/backup?lang=en", json={})
    assert r.status_code == 409
    assert r.json()["code"] == "api.backup_unavailable"


def test_bac_a_sable_du_serveur_e2e(monkeypatch, tmp_path):
    """Serveur E2E : la vraie suppression ne vise que son bac à sable, recréé au besoin ; l'API reste servie."""
    from tests import e2e_server

    monkeypatch.setenv("SCHEDULER", "0")
    monkeypatch.setattr(systask, "default_runner", lambda args: pytest.fail(f"commande système : {args}"))
    monkeypatch.setattr(uninstall, "spawn_detached", lambda args: pytest.fail(f"processus détaché : {args}"))
    voisin = ecrire(tmp_path / "e2e.db")
    sandbox = e2e_server.install_uninstall_sandbox(tmp_path, setter=monkeypatch.setattr)
    with TestClient(app, client=LOCAL) as client:
        plan = client.post("/api/system/uninstall", json={"dry_run": True}).json()
        assert {Path(i["path"]).name for i in plan["items"]} == {
            "domainrecon.db",
            "screenshots",
            "logs",
            ".env",
            ".secret_key",
            "domainrecon-import-essai",
            "DomainRecon-Monitor",
        }
        assert all(
            Path(i["path"]).is_relative_to(sandbox) for i in plan["items"] if i["kind"] != "system_task"
        )
        fait = client.post("/api/system/uninstall", json={"confirm": "SUPPRIMER"}).json()
        assert not any(i["status"] == "failed" for i in fait["items"])
        assert not (sandbox / "DomainRecon").exists()
        assert client.get("/api/history").status_code == 200
        # Nouvel essai : le bac à sable est recréé.
        assert len(client.post("/api/system/uninstall", json={"dry_run": True}).json()["items"]) == 7
    assert voisin.is_file()
