# =============================================================================
# DomainRecon - Tests du module « nuclei » (sans réseau, binaire simulé)
# =============================================================================

import asyncio
import json

import pytest

from domainrecon.scanner.errors import ModuleError, ModuleSkipped
from domainrecon.scanner.impl import nuclei_runner
from domainrecon.scanner.modules.nuclei import SPEC
from domainrecon.scanner.rules import FindingInput


def _entree(data):
    return FindingInput({"nuclei": data}, "nuclei", lambda scan, m: scan.get(m), lambda s, m: True)


def test_binaire_absent_module_sans_objet(monkeypatch, contexte, outils):
    monkeypatch.setattr(nuclei_runner, "nuclei_binary", lambda: None)
    try:
        outils.executer(SPEC, contexte())
    except ModuleSkipped:
        return
    raise AssertionError("ModuleSkipped attendu quand le binaire manque")


def test_build_command():
    cmd = nuclei_runner.build_command("/bin/nuclei", "https://example.com", "http://127.0.0.1:8080")
    assert "-jsonl" in cmd and "-json" not in cmd
    assert "-proxy" in cmd and "http://127.0.0.1:8080" in cmd
    assert "-exclude-tags" in cmd


def test_parse_findings():
    lignes = [
        json.dumps({"template-id": "cve-2021-1", "info": {"name": "RCE", "severity": "critical"}}),
        "ligne illisible",
        json.dumps({"template-id": "exp-1", "info": {"name": "Open dir", "severity": "medium"}}),
    ]
    findings = nuclei_runner.parse_findings("\n".join(lignes).encode())
    assert len(findings) == 2 and findings[0]["severity"] == "critical"


class _FakeProc:
    def __init__(self, stdout: bytes, code: int = 0):
        self._stdout = stdout
        self.returncode = code

    async def wait(self):
        return self.returncode

    def kill(self):
        pass


async def _fake_streams(stdout: bytes):
    class R:
        def __init__(self, data):
            self._data = data

        async def read(self, n):
            data, self._data = self._data[:n], self._data[n:]
            return data

    return R(stdout)


def test_run_avec_constats(monkeypatch):
    stdout = (
        json.dumps({"template-id": "cve-x", "info": {"name": "RCE", "severity": "critical"}}) + "\n"
    ).encode()
    monkeypatch.setattr(nuclei_runner, "nuclei_binary", lambda: "/bin/nuclei")

    async def fake_exec(*cmd, **kw):
        proc = _FakeProc(stdout)
        proc.stdout = asyncio.StreamReader()
        proc.stdout.feed_data(stdout)
        proc.stdout.feed_eof()
        proc.stderr = asyncio.StreamReader()
        proc.stderr.feed_eof()
        return proc

    monkeypatch.setattr(asyncio, "create_subprocess_exec", fake_exec)
    result = asyncio.run(nuclei_runner.run_nuclei("https://example.com", None, timeout=5))
    assert result["critical"] == 1 and result["total"] == 1
    outcome = SPEC.score_rules[0].evaluate({"nuclei": result})
    assert outcome.points == 0 and outcome.cap_reason is not None
    assert SPEC.findings[0].check(_entree(result)) is not None


def test_echec_de_lancement_leve_module_error(monkeypatch):
    monkeypatch.setattr(nuclei_runner, "nuclei_binary", lambda: "/bin/nuclei")

    async def fake_exec(*cmd, **kw):
        raise OSError("ENOENT")

    monkeypatch.setattr(asyncio, "create_subprocess_exec", fake_exec)
    with pytest.raises(ModuleError):
        asyncio.run(nuclei_runner.run_nuclei("https://example.com", None, timeout=5))


def test_score_propre(monkeypatch):
    outcome = SPEC.score_rules[0].evaluate({"nuclei": {"findings": [], "critical": 0, "high": 0}})
    assert outcome.points == 6 and outcome.cap_reason is None
