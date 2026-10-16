# =============================================================================
# DomainRecon - Tests de la tâche système (schtasks, systemd --user)
# =============================================================================
# Les processus externes passent par un runner simulé : le système n'est jamais modifié.
# =============================================================================

import subprocess
import sys

import pytest

from domainrecon.monitor import systask
from domainrecon.scanner.errors import message_of


class FauxRunner:
    """Enregistre les commandes ; `codes` donne les codes de sortie par préfixe de commande."""

    def __init__(self, **codes: int) -> None:
        self.calls: list[list[str]] = []
        self.codes = codes
        self.installed = False

    def __call__(self, args: list[str]) -> tuple[int, str]:
        self.calls.append(args)
        text = " ".join(args)
        if "/Create" in text or "enable" in text:
            self.installed = self.codes.get("create", 0) == 0
            return self.codes.get("create", 0), "erreur" if self.codes.get("create") else ""
        if "/Delete" in text or "disable" in text:
            self.installed = False
            return self.codes.get("delete", 0), ""
        if "/Query" in text or "is-enabled" in text:
            return (0 if self.installed else 1), ""
        return 0, ""


@pytest.fixture
def windows(monkeypatch):
    monkeypatch.setattr(systask, "platform_name", lambda: "windows")


@pytest.fixture
def linux(monkeypatch):
    monkeypatch.setattr(systask, "platform_name", lambda: "linux")


def test_commande_depuis_les_sources(monkeypatch):
    monkeypatch.setattr(sys, "frozen", False, raising=False)
    command = systask.command_line()
    assert command[1:] == ["-m", "domainrecon", "monitor", "run-due"]
    assert command[0].lower().endswith(("python.exe", "pythonw.exe", "python", "python3", "python3.13"))


def test_commande_de_l_executable_installe(monkeypatch):
    monkeypatch.setattr(sys, "frozen", True, raising=False)
    monkeypatch.setattr(sys, "executable", "C:/Program Files/DomainRecon/DomainRecon.exe")
    assert systask.command_line() == [
        "C:/Program Files/DomainRecon/DomainRecon.exe",
        "monitor",
        "run-due",
    ]


def test_windows_installation_via_schtasks_sans_droits_admin(windows, monkeypatch):
    monkeypatch.setattr(sys, "frozen", True, raising=False)
    monkeypatch.setattr(sys, "executable", "C:/Program Files/DomainRecon/DomainRecon.exe")
    runner = FauxRunner()
    assert systask.status(runner=runner)["installed"] is False
    state = systask.install(runner=runner)
    create = next(c for c in runner.calls if "/Create" in c)
    assert create[0] == "schtasks"
    assert create[create.index("/TN") + 1] == "DomainRecon-Monitor"
    assert create[create.index("/SC") + 1] == "HOURLY" and create[create.index("/MO") + 1] == "1"
    assert "/F" in create
    # Aucune élévation demandée : ni compte système, ni niveau d'exécution maximal.
    assert "/RU" not in create and "/RL" not in create
    task_command = create[create.index("/TR") + 1]
    assert task_command == subprocess.list2cmdline(
        ["C:/Program Files/DomainRecon/DomainRecon.exe", "monitor", "run-due"]
    )
    assert '"C:/Program Files/DomainRecon/DomainRecon.exe"' in task_command
    assert state["installed"] is True and state["platform"] == "windows" and state["supported"] is True


def test_windows_echec_de_l_installation(windows):
    with pytest.raises(ValueError) as error:
        systask.install(runner=FauxRunner(create=1))
    assert message_of(error.value)["$t"] == "systask.error_install"


def test_windows_desinstallation(windows):
    runner = FauxRunner()
    systask.install(runner=runner)
    state = systask.uninstall(runner=runner)
    assert state["installed"] is False
    assert any("/Delete" in c for c in runner.calls)
    # Déjà absente : sans erreur et sans appel de suppression.
    runner2 = FauxRunner()
    assert systask.uninstall(runner=runner2)["installed"] is False
    assert not any("/Delete" in c for c in runner2.calls)


def test_windows_echec_de_la_desinstallation(windows):
    runner = FauxRunner(delete=1)
    systask.install(runner=runner)
    runner.installed = True
    with pytest.raises(ValueError) as error:
        systask.uninstall(runner=runner)
    assert message_of(error.value)["$t"] == "systask.error_uninstall"


def test_linux_minuteur_systemd_utilisateur(linux, tmp_path, monkeypatch):
    monkeypatch.setattr(sys, "frozen", True, raising=False)
    monkeypatch.setattr(sys, "executable", "/opt/domain recon/domainrecon")
    runner = FauxRunner()
    state = systask.install(runner=runner, config_dir=tmp_path)
    service = (tmp_path / "domainrecon-monitor.service").read_text(encoding="utf-8")
    timer = (tmp_path / "domainrecon-monitor.timer").read_text(encoding="utf-8")
    assert 'ExecStart="/opt/domain recon/domainrecon" monitor run-due' in service
    assert "Type=oneshot" in service
    assert "OnCalendar=hourly" in timer and "Persistent=true" in timer and "WantedBy=timers.target" in timer
    commands = [" ".join(c) for c in runner.calls]
    assert "systemctl --user daemon-reload" in commands
    assert "systemctl --user enable --now domainrecon-monitor.timer" in commands
    assert not any("sudo" in c or "--system" in c for c in commands)
    assert state["installed"] is True and state["platform"] == "linux"

    state = systask.uninstall(runner=runner, config_dir=tmp_path)
    assert state["installed"] is False
    assert not (tmp_path / "domainrecon-monitor.timer").exists()
    assert not (tmp_path / "domainrecon-monitor.service").exists()
    assert any("disable --now domainrecon-monitor.timer" in " ".join(c) for c in runner.calls)


def test_linux_echec_de_systemctl(linux, tmp_path):
    with pytest.raises(ValueError) as error:
        systask.install(runner=FauxRunner(create=1), config_dir=tmp_path)
    assert message_of(error.value)["$t"] == "systask.error_install"


def test_linux_dossier_inecrivable(linux, tmp_path):
    blocker = tmp_path / "fichier"
    blocker.write_text("x", encoding="utf-8")
    with pytest.raises(ValueError) as error:
        systask.install(runner=FauxRunner(), config_dir=blocker / "sous-dossier")
    assert message_of(error.value)["$t"] == "systask.error_install"


def test_systeme_non_pris_en_charge(monkeypatch):
    monkeypatch.setattr(systask, "platform_name", lambda: "other")
    assert systask.status(runner=FauxRunner()) == {
        "supported": False,
        "platform": "other",
        "installed": False,
        "command": None,
    }
    for action in (systask.install, systask.uninstall):
        with pytest.raises(ValueError) as error:
            action(runner=FauxRunner())
        assert message_of(error.value)["$t"] == "systask.unsupported"


def test_citation_systemd():
    assert systask._systemd_quote("simple") == "simple"
    assert systask._systemd_quote("a b") == '"a b"'
    assert systask._systemd_quote('a"b') == '"a\\"b"'
    assert systask._systemd_quote("50%") == '"50%%"'


def test_runner_par_defaut_programme_absent():
    code, output = systask.default_runner(["programme-qui-n-existe-pas-domainrecon"])
    assert code == 127 and output == ""


def test_runner_par_defaut_sortie_non_utf8(monkeypatch):
    """schtasks écrit en page de code OEM (« ERREUR : » avec une espace insécable 0xFF) : lue sans exception."""
    erreurs = []
    monkeypatch.setattr("threading.excepthook", lambda args: erreurs.append(args.exc_value))
    # Octets écrits : « ERREUR », 0xFF, « : t », 0xE2, « che », 0xFF 0xFE, « introuvable ».
    sortie = (
        b"ERREUR" + bytes([0xFF]) + b": t" + bytes([0xE2]) + b"che " + bytes([0xFF, 0xFE]) + b" introuvable"
    )
    script = f"import sys; sys.stdout.buffer.write({sortie!r}); sys.exit(1)"
    code, output = systask.default_runner([sys.executable, "-c", script])
    assert erreurs == []
    assert code == 1
    assert output.startswith("ERREUR") and "introuvable" in output


def test_encodage_de_sortie_selon_le_systeme(monkeypatch):
    monkeypatch.setattr(systask.sys, "platform", "win32")
    assert systask.output_encoding() == "oem"
    monkeypatch.setattr(systask.sys, "platform", "linux")
    assert systask.output_encoding() is None
