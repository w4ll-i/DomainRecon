"""Test de fumée des livrables (packaging/smoke_test.py) : faux serveur, puis vrai serveur."""

import json
import os
import signal
import subprocess
import sys
import time
from pathlib import Path

import pytest

from pkgload import load

ROOT = Path(__file__).resolve().parents[2]
FAKE_SERVER = """
import json
import os
import subprocess
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

if "--version" in sys.argv:
    print("domainrecon 9.9.9")
    raise SystemExit(0)

PORT = int(sys.argv[sys.argv.index("--port") + 1])
MODE = os.environ.get("FAKE_SMOKE_MODE", "ok")
if os.environ.get("DATA_DIR"):
    log = Path(os.environ["DATA_DIR"]) / "logs" / "domainrecon.log"
    log.parent.mkdir(parents=True, exist_ok=True)
    log.write_text("demarrage\\n", encoding="utf-8")
# Pannes simulées : "once" (connexion coupée, puis JSON invalide, puis réponse sans scan_id) ou "always".
FLAKY = os.environ.get("FAKE_SMOKE_FLAKY", "")
CALLS = {"job": 0}
# Profil demandé par chaque POST /api/scans (None : profil par défaut de l'API).
PROFILES = []
# Descendant du serveur (comme Chromium) : doit disparaître avec lui.
if os.environ.get("FAKE_SMOKE_CHILD_PID_FILE"):
    child = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(120)"])
    Path(os.environ["FAKE_SMOKE_CHILD_PID_FILE"]).write_text(str(child.pid), encoding="utf-8")
print("serveur factice demarre", flush=True)


class Handler(BaseHTTPRequestHandler):
    def _send(self, status, payload):
        self._send_raw(status, json.dumps(payload).encode("utf-8"))

    def _send_raw(self, status, body):
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if self.path == "/api/health":
            self._send(200, {"api": "healthy", "database": "connected", "version": "9.9.9"})
        elif self.path == "/api/scans/job1":
            CALLS["job"] += 1
            if FLAKY == "always" or (FLAKY == "once" and CALLS["job"] == 1):
                self.close_connection = True  # connexion coupée sans réponse
                return
            if FLAKY == "once" and CALLS["job"] == 2:
                self._send_raw(200, b"pas du json")
                return
            if FLAKY == "once" and CALLS["job"] == 3:
                self._send(200, {"id": "job1", "status": "done"})  # sans scan_id
                return
            self._send(200, {"id": "job1", "domain": "example.com", "status": "done", "scan_id": 7, "done": 18, "total": 18})
        elif self.path == "/api/scan/7":
            ok = MODE == "ok"
            statuses = {"screenshot": {"status": "ok" if ok else "skipped", "error": None if ok else "Chromium absent"}}
            if PROFILES and PROFILES[-1] == "rapide":
                quick_ok = os.environ.get("FAKE_SMOKE_QUICK", "ok") == "ok"
                statuses = {"dns": {"status": "ok" if quick_ok else "error"}, "tls": {"status": "error"}}
            self._send(200, {"module_status": statuses, "screenshot_path": "example_com.png" if ok else None})
        elif self.path == "/api/scan/7/export?format=pdf&lang=fr":
            if os.environ.get("FAKE_SMOKE_PDF") == "missing":
                self._send(503, {"detail": "Chromium absent"})
            else:
                self._send_raw(200, b"%PDF-1.4 rapport factice")
        else:
            self._send(404, {"detail": "introuvable"})

    def do_POST(self):
        body = json.loads(self.rfile.read(int(self.headers.get("Content-Length", "0"))) or b"{}")
        if self.path == "/api/scans":
            PROFILES.append(body.get("profile"))
            if os.environ.get("FAKE_SMOKE_PROFILES_FILE"):
                Path(os.environ["FAKE_SMOKE_PROFILES_FILE"]).write_text(json.dumps(PROFILES), encoding="utf-8")
            self._send(202, {"id": "job1", "status": "running"})
        else:
            self._send(404, {"detail": "introuvable"})

    def log_message(self, *args):
        pass


ThreadingHTTPServer(("127.0.0.1", PORT), Handler).serve_forever()
"""


smoke_test = load("smoke_test", "smoke_test.py")


@pytest.fixture
def fake(tmp_path):
    server = tmp_path / "fake_server.py"
    server.write_text(FAKE_SERVER, encoding="utf-8")
    return [sys.executable, str(server)]


def test_smoke_scan_avec_capture(fake):
    smoke_test.smoke(fake, "9.9.9", scan="example.com", version_flag=True, health_timeout=30, scan_timeout=30)


def test_smoke_capture_absente_echoue(fake, monkeypatch):
    """Chromium embarqué : Chromium introuvable = capture « sans objet » = échec du test de fumée."""
    monkeypatch.setenv("FAKE_SMOKE_MODE", "skipped")
    with pytest.raises(smoke_test.SmokeError, match="Capture d'écran non réalisée : statut 'skipped'"):
        smoke_test.smoke(fake, "9.9.9", scan="example.com", health_timeout=30, scan_timeout=30)


def test_smoke_mauvaise_version(fake):
    with pytest.raises(smoke_test.SmokeError, match="Version annoncée '9.9.9', attendue '1.0.0'"):
        smoke_test.smoke(fake, "1.0.0", health_timeout=30)


def test_smoke_sans_capture_et_fichier_attendu(fake, tmp_path):
    """Exécutable fenêtré : mode de l'exécutable fenêtré (sortie libre, journal dans les données)."""
    data = tmp_path / "donnees"
    smoke_test.smoke(
        fake,
        "9.9.9",
        data_dir=data,
        expect_files=[data / "logs" / "domainrecon.log"],
        capture=False,
        health_timeout=30,
    )


def test_smoke_fichier_attendu_absent(fake, tmp_path):
    with pytest.raises(smoke_test.SmokeError, match="Fichier attendu absent"):
        smoke_test.smoke(fake, "9.9.9", expect_files=[tmp_path / "absent.db"], health_timeout=30)


def test_smoke_processus_arrete():
    with pytest.raises(smoke_test.SmokeError, match=r"s'est arrêté \(code 4\)"):
        smoke_test.smoke([sys.executable, "-c", "raise SystemExit(4)"], "1.0.0", health_timeout=15)


def test_smoke_scan_tolere_les_erreurs_transitoires(fake, monkeypatch):
    """Connexion coupée, JSON invalide puis réponse sans scan_id : le scan est réinterrogé, pas abandonné."""
    monkeypatch.setenv("FAKE_SMOKE_FLAKY", "once")
    monkeypatch.setattr(smoke_test, "POLL_INTERVAL", 0.05)
    smoke_test.smoke(fake, "9.9.9", scan="example.com", health_timeout=30, scan_timeout=30)


def test_smoke_scan_erreurs_persistantes_jusqu_a_l_echeance(fake, monkeypatch, capsys):
    monkeypatch.setenv("FAKE_SMOKE_FLAKY", "always")
    monkeypatch.setattr(smoke_test, "POLL_INTERVAL", 0.05)
    with pytest.raises(smoke_test.SmokeError, match=r"Scan non terminé après 2 s \(dernière erreur : \w+"):
        smoke_test.smoke(fake, "9.9.9", scan="example.com", health_timeout=30, scan_timeout=2)
    assert "serveur factice demarre" in capsys.readouterr().err


def test_smoke_erreur_inattendue_affiche_le_journal(fake, monkeypatch, capsys):
    """Toute exception, pas seulement SmokeError : le journal du livrable est affiché, l'échec reste un SmokeError."""

    def boom(*args, **kwargs):
        raise RuntimeError("boom")

    monkeypatch.setattr(smoke_test, "run_scan", boom)
    with pytest.raises(smoke_test.SmokeError, match="Erreur inattendue : RuntimeError : boom"):
        smoke_test.smoke(fake, "9.9.9", scan="example.com", health_timeout=30)
    err = capsys.readouterr().err
    assert "---- Sortie du livrable ----" in err
    assert "serveur factice demarre" in err


def test_smoke_lancement_impossible(tmp_path):
    with pytest.raises(smoke_test.SmokeError, match="Lancement du livrable impossible"):
        smoke_test.smoke([str(tmp_path / "absent")], "1.0.0", health_timeout=5)


def test_version_flag_delai_depasse(monkeypatch):
    def boom(*args, **kwargs):
        raise subprocess.TimeoutExpired(cmd="x", timeout=120)

    monkeypatch.setattr(smoke_test.subprocess, "run", boom)
    with pytest.raises(smoke_test.SmokeError, match="pas de réponse après 120 s"):
        smoke_test.check_version_flag(["x"], "1.0.0", {}, None)


def test_version_flag_lancement_impossible(tmp_path):
    with pytest.raises(smoke_test.SmokeError, match="lancement impossible"):
        smoke_test.check_version_flag([str(tmp_path / "absent")], "1.0.0", {}, None)


def _pid_alive(pid: int) -> bool:
    if sys.platform == "win32":
        import ctypes

        handle = ctypes.windll.kernel32.OpenProcess(0x1000, False, pid)  # PROCESS_QUERY_LIMITED_INFORMATION
        if not handle:
            return False
        try:
            code = ctypes.c_ulong()
            ok = ctypes.windll.kernel32.GetExitCodeProcess(handle, ctypes.byref(code))
            return bool(ok) and code.value == 259  # STILL_ACTIVE
        finally:
            ctypes.windll.kernel32.CloseHandle(handle)
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    stat = Path(f"/proc/{pid}/stat")
    if stat.exists():  # un zombie (non récolté par un init minimal) est un processus mort
        try:
            return stat.read_text().rsplit(")", 1)[1].split()[0] != "Z"
        except OSError:
            return False
    return True


def _kill_quietly(pid: int) -> None:
    if sys.platform == "win32":
        subprocess.run(["taskkill", "/T", "/F", "/PID", str(pid)], capture_output=True, check=False)
    else:
        try:
            os.kill(pid, signal.SIGKILL)
        except OSError:
            pass


def test_smoke_arrete_aussi_les_descendants(fake, tmp_path, monkeypatch):
    """Après un échec, le descendant du livrable (Chromium, node…) est mort : il ne verrouille plus le dossier."""
    pid_file = tmp_path / "enfant.pid"
    monkeypatch.setenv("FAKE_SMOKE_CHILD_PID_FILE", str(pid_file))
    try:
        with pytest.raises(smoke_test.SmokeError, match="Version annoncée"):
            smoke_test.smoke(fake, "1.0.0", health_timeout=30)
        child = int(pid_file.read_text(encoding="utf-8"))
        deadline = time.monotonic() + 10
        while _pid_alive(child) and time.monotonic() < deadline:
            time.sleep(0.2)
        assert not _pid_alive(child)
    finally:
        if pid_file.exists():
            _kill_quietly(int(pid_file.read_text(encoding="utf-8")))


def test_child_env_neutralise_les_reglages(tmp_path):
    base = {
        "DATA_DIR": "x",
        "DATABASE_URL": "sqlite:///y",
        "API_TOKEN": "secret",
        "PLAYWRIGHT_BROWSERS_PATH": "z",
        "PATH": "p",
    }
    env = smoke_test.child_env(None, base)
    assert "DATA_DIR" not in env
    assert env["DATABASE_URL"] == env["API_TOKEN"] == env["ALLOWED_HOSTS"] == ""
    assert env["PATH"] == "p"
    assert smoke_test.child_env(tmp_path, base)["DATA_DIR"] == str(tmp_path)


def test_child_env_laisse_le_hook_imposer_chromium():
    """C'est le livrable qui impose PLAYWRIGHT_BROWSERS_PATH, pas la machine de test."""
    assert "PLAYWRIGHT_BROWSERS_PATH" not in smoke_test.child_env(None, {"PLAYWRIGHT_BROWSERS_PATH": "z"})


def test_main_executable_introuvable(tmp_path, capsys):
    assert smoke_test.main(["--exe", str(tmp_path / "absent.exe"), "--expect-version", "1.0.0"]) == 1
    assert "Exécutable introuvable" in capsys.readouterr().err


def _record_smoke(monkeypatch):
    calls = []
    monkeypatch.setattr(
        smoke_test, "smoke", lambda command, version, **kwargs: calls.append((command, version, kwargs))
    )
    return calls


def test_main_transmet_les_options(monkeypatch, tmp_path, capsys):
    """Câblage de la ligne de commande : --no-capture, --expect-file (répétable), --scan, délais…"""
    exe = tmp_path / "DomainRecon.exe"
    exe.write_text("x", encoding="utf-8")
    first, second = tmp_path / "a.db", tmp_path / "b.log"
    calls = _record_smoke(monkeypatch)
    code = smoke_test.main(
        [
            *("--exe", str(exe)),
            *("--expect-version", "1.2.3"),
            *("--data-dir", str(tmp_path / "donnees")),
            *("--expect-file", str(first)),
            *("--expect-file", str(second)),
            *("--scan", "example.com"),
            *("--quick-scan", "example.org"),
            "--pdf",
            "--version-flag",
            "--no-capture",
            *("--health-timeout", "12"),
            *("--scan-timeout", "34"),
        ]
    )
    assert code == 0
    assert "Test de fumée réussi" in capsys.readouterr().out
    assert calls == [
        (
            [str(exe)],
            "1.2.3",
            {
                "data_dir": tmp_path / "donnees",
                "expect_files": [first, second],
                "scan": "example.com",
                "quick_scan": "example.org",
                "pdf": True,
                "version_flag": True,
                "capture": False,
                "graceful_stop": False,
                "health_timeout": 12.0,
                "scan_timeout": 34.0,
            },
        )
    ]


def test_main_options_par_defaut(monkeypatch, tmp_path):
    exe = tmp_path / "domainrecon"
    exe.write_text("x", encoding="utf-8")
    calls = _record_smoke(monkeypatch)
    assert smoke_test.main(["--exe", str(exe), "--expect-version", "1.0.0"]) == 0
    assert calls[0][2] == {
        "data_dir": None,
        "expect_files": [],
        "scan": None,
        "quick_scan": None,
        "pdf": False,
        "version_flag": False,
        "capture": True,
        "graceful_stop": True,
        "health_timeout": smoke_test.HEALTH_TIMEOUT,
        "scan_timeout": smoke_test.SCAN_TIMEOUT,
    }


def test_main_no_graceful_stop(monkeypatch, tmp_path):
    exe = tmp_path / "domainrecon"
    exe.write_text("x", encoding="utf-8")
    calls = _record_smoke(monkeypatch)
    assert smoke_test.main(["--exe", str(exe), "--expect-version", "1.0.0", "--no-graceful-stop"]) == 0
    assert calls[0][2]["graceful_stop"] is False
    assert calls[0][2]["capture"] is True


def test_smoke_scan_rapide_puis_pdf(fake, tmp_path, monkeypatch, capsys):
    """Scan rapide (profil « rapide » envoyé à l'API), export PDF de ce scan, puis scan complet avec capture."""
    profiles = tmp_path / "profils.json"
    monkeypatch.setenv("FAKE_SMOKE_PROFILES_FILE", str(profiles))
    smoke_test.smoke(
        fake,
        "9.9.9",
        quick_scan="example.com",
        pdf=True,
        scan="example.com",
        health_timeout=30,
        scan_timeout=30,
    )
    assert json.loads(profiles.read_text(encoding="utf-8")) == ["rapide", None]
    out = capsys.readouterr().out
    assert "[ok] Scan rapide de example.com (n° 7) : error 1, ok 1" in out
    assert "[ok] Export PDF du scan n° 7 : 24 octets" in out
    assert "[ok] Arrêt propre en " in out


def test_smoke_scan_rapide_sans_module_reussi(fake, monkeypatch):
    monkeypatch.setenv("FAKE_SMOKE_QUICK", "ko")
    with pytest.raises(smoke_test.SmokeError, match=r"Scan rapide sans module réussi \(error 2\)"):
        smoke_test.smoke(fake, "9.9.9", quick_scan="example.com", health_timeout=30, scan_timeout=30)


def test_smoke_pdf_indisponible(fake, monkeypatch):
    monkeypatch.setenv("FAKE_SMOKE_PDF", "missing")
    with pytest.raises(smoke_test.SmokeError, match=r"Export PDF du scan 7 : HTTP 503"):
        smoke_test.smoke(
            fake, "9.9.9", quick_scan="example.com", pdf=True, health_timeout=30, scan_timeout=30
        )


def test_smoke_pdf_exige_un_scan(fake):
    with pytest.raises(smoke_test.SmokeError, match="L'export PDF exige un scan"):
        smoke_test.smoke(fake, "9.9.9", pdf=True, health_timeout=30)


def test_check_quick_scan_sans_module():
    with pytest.raises(smoke_test.SmokeError, match=r"\(aucun module\)"):
        smoke_test.check_quick_scan({"module_status": {}})
    assert (
        smoke_test.check_quick_scan({"module_status": {"a": {"status": "ok"}, "b": None}}) == "None 1, ok 1"
    )


IGNORE_STOP = """
import signal
import time
signal.signal(getattr(signal, "SIGBREAK", signal.SIGINT), signal.SIG_IGN)
signal.signal(signal.SIGINT, signal.SIG_IGN)
print("pret", flush=True)
time.sleep(120)
"""


def test_graceful_shutdown_echoue_si_le_livrable_ignore_la_demande():
    """Arrêt propre exigé : un livrable qui ignore Ctrl+Pause / SIGINT fait échouer le test de fumée."""
    process = subprocess.Popen(
        [sys.executable, "-c", IGNORE_STOP], stdout=subprocess.PIPE, **smoke_test.popen_flags()
    )
    try:
        assert process.stdout.readline().strip() == b"pret"
        with pytest.raises(smoke_test.SmokeError, match="tourne encore 2 s après la demande"):
            smoke_test.graceful_shutdown(process, timeout=2)
    finally:
        smoke_test.stop(process)
        process.stdout.close()
    assert process.poll() is not None


def test_graceful_shutdown_livrable_qui_s_arrete():
    process = subprocess.Popen(
        [sys.executable, "-c", "import time; print('pret', flush=True); time.sleep(120)"],
        stdout=subprocess.PIPE,
        **smoke_test.popen_flags(),
    )
    try:
        assert process.stdout.readline().strip() == b"pret"
        _code, duration = smoke_test.graceful_shutdown(process, timeout=20)
        assert duration < 20
        assert process.poll() is not None
    finally:
        smoke_test.stop(process)
        process.stdout.close()


def test_main_echec_renvoie_1(monkeypatch, tmp_path, capsys):
    exe = tmp_path / "domainrecon"
    exe.write_text("x", encoding="utf-8")

    def echec(*args, **kwargs):
        raise smoke_test.SmokeError("capture manquante")

    monkeypatch.setattr(smoke_test, "smoke", echec)
    assert smoke_test.main(["--exe", str(exe), "--expect-version", "1.0.0"]) == 1
    assert "[ÉCHEC] capture manquante" in capsys.readouterr().err


def test_smoke_contre_le_vrai_serveur(tmp_path):
    """Commande et API réelles de la phase 1 : --version, --server, /api/health, base créée au démarrage."""
    from domainrecon import __version__

    data = tmp_path / "donnees"
    smoke_test.smoke(
        [sys.executable, "-m", "domainrecon"],
        __version__,
        data_dir=data,
        expect_files=[data / "domainrecon.db"],
        version_flag=True,
        cwd=ROOT,
        health_timeout=60,
    )
