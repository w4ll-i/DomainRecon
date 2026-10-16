# =============================================================================
# DomainRecon - Tests de la commande `domainrecon monitor`
# =============================================================================
# Le scanner est remplacé par un runner de test ; le système n'est jamais modifié.
# =============================================================================

from datetime import timedelta

import pytest
from surveillance import BASE_TIME, add_scan, add_watch, read_watch

from domainrecon.cli import command_names
from domainrecon.cli import run as run_cli
from domainrecon.cli.monitor import main as monitor_main
from domainrecon.core import database
from domainrecon.core.models import Scan
from domainrecon.monitor import service, systask
from domainrecon.monitor.service import WatchScanError
from domainrecon.notify.models import Notification

PASSE = BASE_TIME + timedelta(days=30)


class Faux:
    def __init__(self, fail: set[str] = frozenset()) -> None:
        self.calls: list[str] = []
        self.fail = fail

    def __call__(self):
        async def run(spec):
            self.calls.append(spec.domain)
            if spec.domain in self.fail:
                raise WatchScanError({"$t": "api.scan_failed", "p": {}})
            return add_scan(spec.domain)

        return run


@pytest.fixture
def faux(monkeypatch):
    runner = Faux()
    monkeypatch.setattr(service, "direct_runner", runner)
    return runner


def test_la_commande_est_decouverte_par_la_ligne_de_commande():
    assert "monitor" in command_names()


def test_run_due_sans_surveillance(capsys, faux):
    assert run_cli(["monitor", "run-due"]) == 0
    assert "Aucune surveillance échue." in capsys.readouterr().out
    assert faux.calls == []


def test_run_due_lance_les_surveillances_echues(capsys, faux):
    done = add_watch("a.test", next_run_at=BASE_TIME)
    add_watch("b.test", next_run_at=BASE_TIME + timedelta(days=3650))
    assert run_cli(["monitor", "run-due"]) == 0
    out = capsys.readouterr().out
    assert faux.calls == ["a.test"]
    assert "[ok] a.test : scan n°" in out and "1 surveillance(s) traitée(s), 0 en échec." in out
    assert read_watch(done).last_status == "done"
    # Rien de plus à lancer au passage suivant.
    assert run_cli(["monitor", "run-due"]) == 0
    assert faux.calls == ["a.test"]


def test_run_due_code_de_sortie_en_cas_d_echec(capsys, monkeypatch):
    runner = Faux(fail={"casse.test"})
    monkeypatch.setattr(service, "direct_runner", runner)
    add_watch("casse.test", next_run_at=BASE_TIME)
    add_watch("bon.test", next_run_at=BASE_TIME)
    assert run_cli(["monitor", "run-due", "--lang", "en"]) == 1
    out = capsys.readouterr().out
    assert "[failed] casse.test: The scan failed" in out
    assert "[ok] bon.test: scan #" in out
    assert "2 watch(es) processed, 1 failed." in out


def test_run_due_dry_run_ne_lance_rien(capsys, faux):
    watch_id = add_watch("a.test", next_run_at=BASE_TIME)
    assert run_cli(["monitor", "run-due", "--dry-run"]) == 0
    out = capsys.readouterr().out
    assert "a.test" in out and "2026-03-01 12:00 UTC" in out
    assert faux.calls == []
    assert read_watch(watch_id).next_run_at == BASE_TIME


def test_run_due_alerte_le_centre_de_notifications(faux, monkeypatch):
    # Premier passage : référence ; second : le certificat approche de son échéance.
    add_watch("a.test", next_run_at=BASE_TIME)
    add_scan("a.test", cert_days=60)
    runner = Faux()

    def une_alerte():
        async def run(spec):
            runner.calls.append(spec.domain)
            return add_scan(spec.domain, cert_days=3)

        return run

    monkeypatch.setattr(service, "direct_runner", une_alerte)
    assert run_cli(["monitor", "run-due"]) == 0
    with database.SessionLocal() as db:
        rows = db.query(Notification).all()
    assert [r.rule for r in rows] == ["cert_expiry"]


def test_liste_des_surveillances(capsys):
    assert run_cli(["monitor", "list"]) == 0
    assert "Aucune surveillance." in capsys.readouterr().out
    add_watch("a.test", frequency="weekly")
    add_watch("b.test", enabled=False)
    assert run_cli(["monitor", "list"]) == 0
    out = capsys.readouterr().out
    assert "a.test" in out and "weekly" in out and "désactivée" in out and "b.test" in out


def test_tache_systeme(capsys, monkeypatch):
    state = {"supported": True, "platform": "linux", "installed": False, "command": "cmd"}
    monkeypatch.setattr(systask, "status", lambda: dict(state))
    monkeypatch.setattr(systask, "install", lambda: {**state, "installed": True})
    assert run_cli(["monitor", "task", "status"]) == 0
    assert "non installée" in capsys.readouterr().out
    assert run_cli(["monitor", "task", "install", "--lang", "en"]) == 0
    assert "System task installed (linux)" in capsys.readouterr().out
    monkeypatch.setattr(systask, "status", lambda: {**state, "supported": False})
    assert run_cli(["monitor", "task", "status"]) == 2


def test_tache_systeme_refusee(capsys, monkeypatch):
    from domainrecon.i18n import msg
    from domainrecon.scanner.errors import message_exception

    def refuse():
        raise message_exception(ValueError, msg("systask.error_install"))

    monkeypatch.setattr(systask, "install", refuse)
    assert run_cli(["monitor", "task", "install"]) == 2
    assert "Installation de la tâche système impossible" in capsys.readouterr().err


def test_point_d_entree_autonome(capsys, faux):
    add_watch("a.test", next_run_at=BASE_TIME)
    assert monitor_main(["run-due"]) == 0
    assert faux.calls == ["a.test"]
    assert "a.test" in capsys.readouterr().out


def test_scan_enregistre_en_base_par_le_runner_direct(monkeypatch):
    """Le runner direct enregistre le résultat de perform_full_scan avec le profil et les modules lancés."""
    seen = {}

    async def scanner(domain, **plan):
        seen.update(domain=domain, **plan)
        return {"domain": domain, "status": "success", "security_score": {"score": 90, "grade": "A"}}

    monkeypatch.setattr(service, "perform_full_scan", scanner)
    import asyncio

    spec = service.WatchSpec(1, "a.test", "rapide", (), False, "daily", (), "fr")
    scan_id = asyncio.run(service.direct_runner()(spec))
    assert seen["profile"] == "rapide" and seen["authorized_target"] is False
    with database.SessionLocal() as db:
        scan = db.get(Scan, scan_id)
        assert scan.domain == "a.test" and scan.profile == "rapide"
        assert scan.modules_launched and "dns_records" in scan.modules_launched
