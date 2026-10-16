# =============================================================================
# DomainRecon - Tests du statut VPN Mullvad (scanner/vpn.py)
# =============================================================================
# Aucun accès à Internet ni au vrai CLI Mullvad : le CLI est un faux exécutable
# (script lancé par un vrai sous-processus), l'API am.i.mullvad.net un
# transport httpx.MockTransport ou un serveur local.
# =============================================================================

import http.server
import json
import os
import shutil
import subprocess
import sys
import threading

import httpx
import pytest

from domainrecon.scanner import vpn
from rendu import fr

# Le vrai _find_cli, avant que les tests ne le remplacent (voir sans_cli).
REAL_FIND_CLI = vpn._find_cli

# Sorties de « mullvad status » (CLI récent, ancien, déconnecté).
CONNECTED = """Connected
    Relay:                  se-got-wg-001
    Features:               Quantum Resistance
    Visible location:       Sweden, Gothenburg. IPv4: 185.213.154.68, IPv6: 2a03:1b20:5:f011::a01f
"""
CONNECTED_OLD = """Tunnel status: Connected to WireGuard 185.213.154.68:51820/UDP over UDP
  Relay:        se-got-wg-001
  Visible location: Sweden, Gothenburg. IPv4: 185.213.154.68
"""
DISCONNECTED = "Disconnected\n"
DISCONNECTED_LOCATED = """Disconnected
    Visible location:       Germany, Berlin. IPv4: 203.0.113.9, IPv6: 2001:db8::9
"""

API_CONNECTED = {
    "ip": "193.32.126.81",
    "country": "Sweden",
    "city": "Gothenburg",
    "mullvad_exit_ip": True,
    "mullvad_exit_ip_hostname": "se-got-wg-001",
    "organization": "31173 Services AB",
}
API_DISCONNECTED = {"ip": "203.0.113.9", "country": "Germany", "city": "Berlin", "mullvad_exit_ip": False}


@pytest.fixture(autouse=True)
def sans_cli(monkeypatch):
    """Par défaut, aucun CLI Mullvad : le vrai, s'il est installé ici, ne doit jamais être lancé."""
    monkeypatch.setattr(vpn, "_find_cli", lambda: None)


@pytest.fixture
def fake_cli(tmp_path, monkeypatch):
    """Faux CLI : `make(stdout, stderr, code)` crée l'exécutable, que _find_cli() désigne."""

    def make(stdout: str = "", stderr: str = "", code: int = 0) -> str:
        (tmp_path / "stdout.txt").write_text(stdout, encoding="utf-8", newline="\n")
        (tmp_path / "stderr.txt").write_text(stderr, encoding="utf-8", newline="\n")
        if sys.platform == "win32":
            script = tmp_path / "mullvad.cmd"
            script.write_text(
                f'@echo off\ntype "{tmp_path / "stdout.txt"}"\ntype "{tmp_path / "stderr.txt"}" 1>&2\n'
                f"exit /b {code}\n",
                encoding="utf-8",
                newline="\r\n",
            )
        else:
            script = tmp_path / "mullvad"
            script.write_text(
                f'#!/bin/sh\ncat "{tmp_path / "stdout.txt"}"\ncat "{tmp_path / "stderr.txt"}" >&2\nexit {code}\n',
                encoding="utf-8",
                newline="\n",
            )
            script.chmod(0o755)
        monkeypatch.setattr(vpn, "_find_cli", lambda: str(script))
        return str(script)

    return make


def _api(*, status=200, body=None, content=None, error=None):
    """Transport simulé de am.i.mullvad.net : `requests` mémorise les requêtes reçues."""
    requests: list[httpx.Request] = []

    def handler(request):
        requests.append(request)
        if error is not None:
            raise error
        if content is not None:
            return httpx.Response(status, content=content)
        return httpx.Response(status, json=body)

    transport = httpx.MockTransport(handler)
    transport.requests = requests
    return transport


# =============================================================================
# Lecture de « mullvad status »
# =============================================================================


@pytest.mark.parametrize(
    ("output", "expected"),
    [
        (CONNECTED, (True, "185.213.154.68", "Sweden")),
        (CONNECTED_OLD, (True, "185.213.154.68", "Sweden")),
        ("CONNECTED\n", (True, None, None)),
        (DISCONNECTED, (False, None, None)),
        (DISCONNECTED_LOCATED, (False, "203.0.113.9", "Germany")),
        ("Tunnel status: Disconnected\n", (False, None, None)),
        ("Connecting to WireGuard relay se-got-wg-001 in Gothenburg, Sweden\n", (False, None, None)),
        ("Disconnecting\n", (False, None, None)),
        ("Blocked: Failed to apply firewall rules\n", (False, None, None)),
        # Adresse IPv6 seule ; pays sans ville.
        (
            "Connected\nVisible location: Sweden. IPv6: 2a03:1b20:5:f011::a01f\n",
            (True, "2a03:1b20:5:f011::a01f", "Sweden"),
        ),
        # IPv4 invalide : repli sur l'IPv6 ; adresse sans pays.
        (
            "Connected\nVisible location: Sweden. IPv4: 999.1.1.1, IPv6: 2001:db8::1\n",
            (True, "2001:db8::1", "Sweden"),
        ),
        ("Connected\nVisible location: IPv4: 1.2.3.4\n", (True, "1.2.3.4", None)),
        # Lignes vides en tête.
        ("\n\n  Disconnected\n", (False, None, None)),
    ],
)
def test_lecture_de_la_sortie_du_cli(output, expected):
    status = vpn.parse_cli_status(output)

    assert (status["connected"], status["ip"], status["country"]) == expected
    assert status["mullvad_cli"] is True
    assert status["provider"] == ("Mullvad" if expected[0] else None)
    assert status["error"] is None


@pytest.mark.parametrize(
    "output",
    [
        "",
        "   \n\n",
        "Error: Failed to connect to daemon\n",
        "Usage: mullvad [OPTIONS] <COMMAND>\n",
        "Le service Mullvad est arrêté\n",
        "Disconnect\n",
    ],
)
def test_sortie_non_reconnue(output):
    assert vpn.parse_cli_status(output) is None


# =============================================================================
# Avec le CLI Mullvad installé (faux exécutable, vrai sous-processus)
# =============================================================================


@pytest.mark.parametrize(
    ("stdout", "expected"),
    [
        (CONNECTED, (True, "185.213.154.68", "Sweden", "Mullvad")),
        (DISCONNECTED, (False, None, None, None)),
        (DISCONNECTED_LOCATED, (False, "203.0.113.9", "Germany", None)),
    ],
)
def test_statut_depuis_le_cli(fake_cli, monkeypatch, stdout, expected):
    fake_cli(stdout=stdout)
    # Le CLI fait foi : l'API n'est pas interrogée.
    monkeypatch.setattr(vpn, "_fetch_json", lambda transport: pytest.fail("API interrogée malgré le CLI"))

    status = vpn.get_vpn_status()

    assert (status["connected"], status["ip"], status["country"], status["provider"]) == expected
    assert status["mullvad_cli"] is True and status["error"] is None


def test_cli_en_erreur_statut_inconnu(fake_cli, caplog):
    fake_cli(stderr="Error: Failed to connect to daemon\n", code=1)

    with caplog.at_level("WARNING", logger="domainrecon.scanner"):
        status = vpn.get_vpn_status()

    assert status["connected"] is None and status["provider"] is None
    assert status["mullvad_cli"] is True
    assert status["ip"] is None and status["country"] is None
    assert "service Mullvad arrêté" in fr(status["error"])
    # La cause exacte reste dans les journaux du serveur.
    assert "code 1" in caplog.text and "Failed to connect to daemon" in caplog.text


def test_cli_sortie_inattendue_statut_inconnu(fake_cli):
    fake_cli(stdout="Welcome to a very different tool\n")
    status = vpn.get_vpn_status()
    assert status["connected"] is None and status["mullvad_cli"] is True


def test_cli_code_d_erreur_mais_sortie_reconnue(fake_cli):
    """Seule une sortie reconnue compte, quel que soit le code de retour."""
    fake_cli(stdout=CONNECTED, code=1)
    assert vpn.get_vpn_status()["connected"] is True


@pytest.mark.parametrize(
    "failure",
    [
        subprocess.TimeoutExpired(["mullvad", "status"], 5),
        FileNotFoundError("mullvad"),
        PermissionError("refusé"),
    ],
)
def test_cli_injoignable_ou_trop_lent_statut_inconnu(monkeypatch, failure):
    monkeypatch.setattr(vpn, "_find_cli", lambda: "mullvad")

    def run(cli):
        raise failure

    monkeypatch.setattr(vpn, "_run_cli", run)

    status = vpn.get_vpn_status()

    assert status["connected"] is None and status["mullvad_cli"] is True
    assert status["error"] == {"$t": "api.vpn_cli_failed", "p": {}}


def test_cli_lance_sans_shell_avec_delai_et_sans_fenetre(monkeypatch):
    seen = {}

    def run(command, **kwargs):
        seen.update(command=command, **kwargs)
        return subprocess.CompletedProcess(command, 0, stdout=DISCONNECTED, stderr="")

    monkeypatch.setattr(subprocess, "run", run)

    status = vpn._run_cli("C:/Mullvad/mullvad.exe")

    assert status.stdout == DISCONNECTED
    assert seen["command"] == ["C:/Mullvad/mullvad.exe", "status"]
    assert seen["timeout"] == vpn.CLI_TIMEOUT == 5
    assert seen["stdin"] == subprocess.DEVNULL
    assert "shell" not in seen
    # Pas de console qui clignote depuis l'application de bureau.
    assert seen["creationflags"] == (subprocess.CREATE_NO_WINDOW if sys.platform == "win32" else 0)


# =============================================================================
# Recherche du CLI
# =============================================================================


def test_cli_cherche_dans_le_path_puis_aux_emplacements_habituels(tmp_path, monkeypatch):
    habituel = tmp_path / "mullvad-habituel"
    habituel.write_text("", encoding="utf-8")
    monkeypatch.setattr(vpn, "_cli_candidates", lambda: [str(tmp_path / "absent"), str(habituel)])

    monkeypatch.setattr(shutil, "which", lambda name: "/usr/bin/mullvad" if name == "mullvad" else None)
    assert REAL_FIND_CLI() == "/usr/bin/mullvad"

    monkeypatch.setattr(shutil, "which", lambda name: None)
    assert REAL_FIND_CLI() == str(habituel)

    habituel.unlink()
    assert REAL_FIND_CLI() is None


def test_emplacements_habituels_selon_le_systeme(monkeypatch):
    monkeypatch.setenv("ProgramFiles", "D:\\Programmes")
    monkeypatch.setattr(sys, "platform", "win32")
    assert vpn._cli_candidates() == [
        os.path.join("D:\\Programmes", "Mullvad VPN", "resources", "mullvad.exe")
    ]

    monkeypatch.setattr(sys, "platform", "darwin")
    assert vpn._cli_candidates() == ["/Applications/Mullvad VPN.app/Contents/Resources/mullvad"]

    monkeypatch.setattr(sys, "platform", "linux")
    assert vpn._cli_candidates() == []


# =============================================================================
# Sans CLI : am.i.mullvad.net
# =============================================================================


def test_api_connecte():
    transport = _api(body=API_CONNECTED)

    status = vpn.get_vpn_status(transport=transport)

    assert status == {
        "connected": True,
        "ip": "193.32.126.81",
        "country": "Sweden",
        "provider": "Mullvad",
        "mullvad_cli": False,
        "error": None,
    }
    (request,) = transport.requests
    assert str(request.url) == "https://am.i.mullvad.net/json"
    assert request.headers["accept-encoding"] == "identity"


def test_api_non_connecte():
    status = vpn.get_vpn_status(transport=_api(body=API_DISCONNECTED))

    assert status["connected"] is False and status["provider"] is None
    assert (status["ip"], status["country"], status["mullvad_cli"]) == ("203.0.113.9", "Germany", False)


@pytest.mark.parametrize(
    "transport",
    [
        pytest.param(_api(status=500, body={"error": "boom"}), id="http-500"),
        pytest.param(_api(status=302, body={}), id="redirection"),
        pytest.param(_api(content=b"<html>Captive portal</html>"), id="pas-du-json"),
        pytest.param(_api(body=["mullvad_exit_ip", True]), id="json-pas-un-objet"),
        pytest.param(_api(body={"ip": "203.0.113.9"}), id="sans-mullvad_exit_ip"),
        pytest.param(_api(body={"mullvad_exit_ip": "true"}), id="mullvad_exit_ip-texte"),
        pytest.param(_api(body={"mullvad_exit_ip": 1}), id="mullvad_exit_ip-entier"),
        pytest.param(_api(content=b"x" * (vpn.API_MAX_BYTES + 1)), id="trop-volumineuse"),
        pytest.param(_api(content=b"[" * 50_000), id="imbrication-excessive"),
        pytest.param(_api(error=httpx.ConnectError("injoignable")), id="connexion-impossible"),
        pytest.param(_api(error=httpx.ReadTimeout("trop lent")), id="delai-depasse"),
    ],
)
def test_api_en_echec_statut_inconnu(transport):
    status = vpn.get_vpn_status(transport=transport)

    assert status["connected"] is None
    assert (status["ip"], status["country"], status["provider"]) == (None, None, None)
    assert status["mullvad_cli"] is False
    assert status["error"] == {"$t": "api.vpn_api_failed", "p": {}}
    assert "am.i.mullvad.net" in fr(status["error"])


def test_api_valeurs_du_tiers_assainies():
    body = {"mullvad_exit_ip": True, "ip": "pas une adresse", "country": "Swe\x00den\x1b[31m" + "x" * 500}

    status = vpn.get_vpn_status(transport=_api(body=body))

    assert status["connected"] is True
    assert status["ip"] is None
    assert (
        status["country"].startswith("Swe")
        and "\x00" not in status["country"]
        and "\x1b" not in status["country"]
    )
    assert len(status["country"]) == 100
    # Une adresse valide est rendue sous sa forme canonique ; un pays absent ou non textuel : None.
    status = vpn.get_vpn_status(
        transport=_api(body={"mullvad_exit_ip": False, "ip": "2001:0DB8:0:0:0:0:0:1", "country": 12})
    )
    assert (status["ip"], status["country"]) == ("2001:db8::1", None)


def test_delai_de_l_api(monkeypatch):
    seen = {}
    real_client = httpx.Client

    def client(**kwargs):
        seen.update(kwargs)
        return real_client(**kwargs)

    monkeypatch.setattr(httpx, "Client", client)
    vpn.get_vpn_status(transport=_api(body=API_CONNECTED))

    assert seen["timeout"] == vpn.API_TIMEOUT == 5
    assert seen["follow_redirects"] is False
    assert seen["trust_env"] is False


# --- Serveur local : requête réelle, sans proxy, lecture bornée ----------------


@pytest.fixture
def mullvad_local(monkeypatch):
    """Faux am.i.mullvad.net local (HTTP) : `routes["/json"] = (statut, corps)`, chemins reçus dans `hits`."""
    hits: list[str] = []
    routes: dict[str, tuple[int, bytes]] = {"/json": (200, json.dumps(API_CONNECTED).encode())}

    class Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            hits.append(self.path)
            status, body = routes.get(self.path, (404, b""))
            self.send_response(status)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *args):
            pass

    class Server(http.server.ThreadingHTTPServer):
        def handle_error(self, request, client_address):
            pass  # client parti avant la fin de la réponse (lecture bornée) : sans importance

    server = Server(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True)
    thread.start()
    monkeypatch.setattr(vpn, "MULLVAD_API_URL", f"http://127.0.0.1:{server.server_address[1]}/json")
    try:
        yield routes, hits
    finally:
        server.shutdown()
        server.server_close()


def _proxy_env(monkeypatch, **env):
    for name in ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY"):
        monkeypatch.delenv(name, raising=False)
        monkeypatch.delenv(name.lower(), raising=False)
    for name, value in env.items():
        monkeypatch.setenv(name, value)


def test_api_interrogee_sans_proxy(mullvad_local, monkeypatch):
    """C'est la connexion directe de la machine qui compte : les variables de proxy sont ignorées."""
    routes, hits = mullvad_local
    # Un proxy mort : la requête échouerait si le client l'utilisait.
    _proxy_env(monkeypatch, HTTP_PROXY="http://127.0.0.1:9", HTTPS_PROXY="http://127.0.0.1:9")

    status = vpn.get_vpn_status()

    assert status["connected"] is True and status["ip"] == "193.32.126.81"
    assert hits == ["/json"]


def test_api_reponse_lue_en_flux_et_bornee(mullvad_local):
    routes, hits = mullvad_local
    routes["/json"] = (
        200,
        b'{"mullvad_exit_ip": false, "padding": "' + b"x" * (vpn.API_MAX_BYTES * 2) + b'"}',
    )

    status = vpn.get_vpn_status()

    assert status["connected"] is None
    assert status["error"] == {"$t": "api.vpn_api_failed", "p": {}}


def test_api_redirection_non_suivie(mullvad_local):
    routes, hits = mullvad_local
    routes["/json"] = (302, b"")

    assert vpn.get_vpn_status()["connected"] is None
    assert hits == ["/json"]
