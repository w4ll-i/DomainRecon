#!/usr/bin/env python3
"""Test de fumée d'un livrable de DomainRecon : démarrage en --server, /api/health, arrêt.

Usage :
    python packaging/smoke_test.py --exe private/build/dist/DomainRecon/DomainRecon-console.exe --expect-version 1.0.0
Options :
    --data-dir DIR       dossier des données imposé (DATA_DIR) ; sans elle, celui du mode de
                         l'exécutable (portable : data/ à côté ; installé : dossier de l'utilisateur)
    --expect-file PATH   fichier qui doit exister une fois le serveur prêt (répétable)
    --quick-scan DOMAINE lance un scan au profil « rapide » et exige au moins un module réussi
    --pdf                exporte en PDF le premier scan lancé (preuve que le Chromium
                         embarqué produit les rapports)
    --scan DOMAINE       lance aussi un scan et exige une capture d'écran réussie
                         (preuve que le Chromium embarqué fonctionne)
    --version-flag       vérifie aussi la sortie de « <exe> --version »
    --no-capture         laisse libre la sortie du livrable (exécutable fenêtré : sans console,
                         il écrit son journal dans <données>/logs/domainrecon.log) ; l'arrêt
                         propre n'est alors pas exigé (aucune console pour le recevoir)
    --no-graceful-stop   n'exige pas l'arrêt propre (sinon : Ctrl+Pause sous Windows, SIGINT
                         ailleurs, et le livrable doit s'arrêter seul)
Bibliothèque standard uniquement : le script tourne avec le Python du système
(conteneurs Ubuntu 22.04 : Python 3.10).
"""

from __future__ import annotations

import argparse
import http.client
import json
import os
import signal
import socket
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
from collections.abc import Mapping, Sequence
from pathlib import Path

HEALTH_TIMEOUT = 90.0
SCAN_TIMEOUT = 300.0
# Réglages ramenés à leur valeur par défaut : une valeur vide vaut « non
# définie » pour l'application, et un fichier .env ne la remplace pas.
# Intervalle entre deux interrogations du scan (secondes).
POLL_INTERVAL = 2.0
# Profil du scan rapide (--quick-scan) : modules passifs essentiels.
QUICK_PROFILE = "rapide"
# Délai laissé au livrable pour s'arrêter seul après la demande d'arrêt (secondes).
GRACEFUL_TIMEOUT = 30.0
NEUTRAL_SETTINGS = (
    "DATABASE_URL",
    "API_TOKEN",
    "ALLOWED_HOSTS",
    "CORS_ORIGINS",
    "DOMAINRECON_PORTABLE",
    "LOG_LEVEL",
)
# Erreurs d'une requête qui peuvent disparaître à la suivante (connexion coupée, JSON tronqué…).
TRANSIENT_ERRORS = (OSError, ValueError, http.client.HTTPException)
# Requêtes vers 127.0.0.1 : jamais par un proxy de la machine.
_OPENER = urllib.request.build_opener(urllib.request.ProxyHandler({}))


class SmokeError(Exception):
    """Échec du test de fumée (message destiné à l'utilisateur)."""


def free_port(host: str = "127.0.0.1") -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind((host, 0))
        return sock.getsockname()[1]


def child_env(data_dir: Path | None, base: Mapping[str, str] | None = None) -> dict[str, str]:
    """Environnement du livrable : réglages neutres, DATA_DIR imposé ou retiré.

    PLAYWRIGHT_BROWSERS_PATH est retirée : c'est au hook d'exécution du livrable
    d'imposer son Chromium embarqué, pas à l'environnement de la machine de test.
    """
    env = dict(os.environ if base is None else base)
    for name in NEUTRAL_SETTINGS:
        env[name] = ""
    env.pop("DATA_DIR", None)
    env.pop("PLAYWRIGHT_BROWSERS_PATH", None)
    if data_dir is not None:
        env["DATA_DIR"] = str(data_dir)
    return env


def request_json(
    method: str, url: str, body: object | None = None, timeout: float = 10.0
) -> tuple[int, object]:
    """Requête JSON ; renvoie (statut HTTP, corps décodé), y compris pour une réponse d'erreur."""
    data = None if body is None else json.dumps(body).encode("utf-8")
    request = urllib.request.Request(
        url,
        data=data,
        method=method,
        headers={"Content-Type": "application/json", "Accept": "application/json"},
    )
    try:
        with _OPENER.open(request, timeout=timeout) as response:
            raw = response.read().decode("utf-8")
            return response.status, (json.loads(raw) if raw else None)
    except urllib.error.HTTPError as exc:
        raw = exc.read().decode("utf-8", errors="replace")
        try:
            return exc.code, json.loads(raw)
        except ValueError:
            return exc.code, raw


def _signal_group(process: subprocess.Popen, sig: int) -> None:
    """POSIX : envoie `sig` au groupe de processus du livrable (lancé avec start_new_session)."""
    try:
        os.killpg(process.pid, sig)
    except OSError:  # groupe déjà vide
        pass


def stop(process: subprocess.Popen, timeout: float = 20.0) -> None:
    """Arrête le livrable ET ses descendants (Chromium, node), qui sinon verrouilleraient son dossier.

    Windows : `taskkill /T /F` sur l'arbre de processus. Ailleurs : SIGTERM puis SIGKILL
    sur le groupe de processus (le livrable est lancé dans sa propre session).
    """
    if os.name == "nt":
        if process.poll() is None:
            try:
                subprocess.run(
                    ["taskkill", "/T", "/F", "/PID", str(process.pid)],
                    capture_output=True,
                    check=False,
                    timeout=timeout,
                )
            except (OSError, subprocess.SubprocessError):
                pass  # repli : kill() ci-dessous
    else:
        _signal_group(process, signal.SIGTERM)
        try:
            process.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            pass
        _signal_group(process, signal.SIGKILL)  # descendants qui ignoreraient SIGTERM
    try:
        process.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(timeout=timeout)


def popen_flags() -> dict[str, object]:
    """Options de Popen : groupe de processus à part, pour l'arrêt propre (voir request_stop) et stop()."""
    if os.name == "nt":
        return {"creationflags": subprocess.CREATE_NEW_PROCESS_GROUP}
    return {"start_new_session": True}


def request_stop(process: subprocess.Popen) -> None:
    """Demande d'arrêt propre, comme un Ctrl+C dans la console du serveur.

    Windows : CTRL_BREAK_EVENT au groupe du livrable (uvicorn le traite comme Ctrl+C) ;
    ailleurs : SIGINT au processus (KeyboardInterrupt, sortie normale du mode --server).
    """
    try:
        process.send_signal(signal.CTRL_BREAK_EVENT if os.name == "nt" else signal.SIGINT)
    except OSError:  # déjà arrêté
        pass


def graceful_shutdown(process: subprocess.Popen, timeout: float = GRACEFUL_TIMEOUT) -> tuple[int, float]:
    """Arrêt propre : le livrable doit s'arrêter seul après la demande ; renvoie (code, durée en s)."""
    start = time.monotonic()
    request_stop(process)
    try:
        code = process.wait(timeout=timeout)
    except subprocess.TimeoutExpired as exc:
        raise SmokeError(
            f"Arrêt propre : le livrable tourne encore {timeout:.0f} s après la demande."
        ) from exc
    return code, time.monotonic() - start


def wait_for_health(base_url: str, process: subprocess.Popen, timeout: float) -> dict:
    deadline = time.monotonic() + timeout
    last = "aucune réponse"
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise SmokeError(f"Le livrable s'est arrêté (code {process.returncode}) avant d'être prêt.")
        try:
            status, payload = request_json("GET", f"{base_url}/api/health", timeout=5.0)
        except TRANSIENT_ERRORS as exc:
            last = str(exc)
        else:
            if status == 200 and isinstance(payload, dict):
                return payload
            last = f"HTTP {status} : {payload}"
        time.sleep(1.0)
    raise SmokeError(f"/api/health ne répond pas 200 après {timeout:.0f} s ({last}).")


def check_health(payload: dict, expected_version: str) -> None:
    if payload.get("api") != "healthy":
        raise SmokeError(f"/api/health : état {payload.get('api')!r} ({payload}).")
    if payload.get("version") != expected_version:
        raise SmokeError(f"Version annoncée {payload.get('version')!r}, attendue {expected_version!r}.")


def run_scan(base_url: str, domain: str, timeout: float, profile: str | None = None) -> dict:
    """Scan en tâche de fond (POST /api/scans), attente de la fin, puis lecture du scan enregistré.

    `profile` : profil de scan (« rapide »…) ; None garde celui de l'API (« complet »).
    Le scan renvoyé porte son identifiant sous la clé « id ».
    """
    body: dict[str, str] = {"domain": domain}
    if profile is not None:
        body["profile"] = profile
    try:
        status, job = request_json("POST", f"{base_url}/api/scans", body)
    except TRANSIENT_ERRORS as exc:
        raise SmokeError(f"POST /api/scans : {type(exc).__name__} : {exc}") from exc
    if status != 202 or not isinstance(job, dict) or "id" not in job:
        raise SmokeError(f"POST /api/scans : HTTP {status} {job}")
    deadline = time.monotonic() + timeout
    last = "aucune réponse"
    while time.monotonic() < deadline:
        try:
            status, state = request_json("GET", f"{base_url}/api/scans/{job['id']}")
            if status != 200 or not isinstance(state, dict):
                raise SmokeError(f"GET /api/scans/{job['id']} : HTTP {status} {state}")
            if state.get("status") == "done":
                status, scan = request_json("GET", f"{base_url}/api/scan/{state['scan_id']}", timeout=30.0)
                if status != 200 or not isinstance(scan, dict):
                    raise SmokeError(f"GET /api/scan/{state['scan_id']} : HTTP {status}")
                scan.setdefault("id", state["scan_id"])
                return scan
            if state.get("status") in ("failed", "cancelled"):
                raise SmokeError(f"Scan terminé en état {state.get('status')!r}.")
            last = f"scan à l'état {state.get('status')!r}"
        except (*TRANSIENT_ERRORS, KeyError) as exc:
            # Connexion coupée, JSON invalide ou réponse incomplète : on réessaie jusqu'à l'échéance.
            last = f"{type(exc).__name__} : {exc}"
        time.sleep(POLL_INTERVAL)
    raise SmokeError(f"Scan non terminé après {timeout:.0f} s (dernière erreur : {last}).")


def check_screenshot(scan: dict) -> None:
    module = (scan.get("module_status") or {}).get("screenshot") or {}
    if module.get("status") != "ok" or not scan.get("screenshot_path"):
        raise SmokeError(
            f"Capture d'écran non réalisée : statut {module.get('status')!r}, détail {module.get('error')!r}."
        )


def check_quick_scan(scan: dict) -> str:
    """Scan rapide : au moins un module réussi ; renvoie le décompte des statuts (« ok 9, error 1 »)."""
    statuses = [(module or {}).get("status") for module in (scan.get("module_status") or {}).values()]
    counts: dict[str, int] = {}
    for status in statuses:
        counts[str(status)] = counts.get(str(status), 0) + 1
    summary = ", ".join(f"{name} {count}" for name, count in sorted(counts.items())) or "aucun module"
    if not counts.get("ok"):
        raise SmokeError(f"Scan rapide sans module réussi ({summary}).")
    return summary


def fetch_bytes(url: str, timeout: float = 120.0) -> tuple[int, bytes]:
    """GET brut ; renvoie (statut HTTP, corps), y compris pour une réponse d'erreur."""
    try:
        with _OPENER.open(urllib.request.Request(url, method="GET"), timeout=timeout) as response:
            return response.status, response.read()
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read()


def check_pdf_export(base_url: str, scan_id: object) -> int:
    """Export PDF du scan (Chromium embarqué) : 200 et un vrai PDF ; renvoie sa taille en octets."""
    url = f"{base_url}/api/scan/{scan_id}/export?format=pdf&lang=fr"
    try:
        status, content = fetch_bytes(url)
    except TRANSIENT_ERRORS as exc:
        raise SmokeError(f"Export PDF : {type(exc).__name__} : {exc}") from exc
    if status != 200 or not content.startswith(b"%PDF"):
        detail = content[:200].decode("utf-8", errors="replace")
        raise SmokeError(f"Export PDF du scan {scan_id} : HTTP {status} ({detail!r}).")
    return len(content)


def check_version_flag(
    command: Sequence[str], expected_version: str, env: Mapping[str, str], cwd: Path | None
) -> None:
    try:
        completed = subprocess.run(
            [*command, "--version"],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            env=dict(env),
            cwd=cwd,
            timeout=120,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        raise SmokeError(f"« --version » : pas de réponse après {exc.timeout:.0f} s.") from exc
    except OSError as exc:
        raise SmokeError(f"« --version » : lancement impossible ({exc}).") from exc
    output = (completed.stdout or "") + (completed.stderr or "")
    if completed.returncode != 0 or expected_version not in output:
        raise SmokeError(
            f"« --version » : code {completed.returncode}, sortie {output.strip()!r} (attendu : {expected_version})."
        )
    print(f"[ok] --version : {output.strip()}", flush=True)


def smoke(
    command: Sequence[str],
    expected_version: str,
    *,
    data_dir: Path | None = None,
    expect_files: Sequence[Path] = (),
    scan: str | None = None,
    quick_scan: str | None = None,
    pdf: bool = False,
    version_flag: bool = False,
    capture: bool = True,
    graceful_stop: bool = True,
    cwd: Path | None = None,
    health_timeout: float = HEALTH_TIMEOUT,
    scan_timeout: float = SCAN_TIMEOUT,
) -> None:
    """Lance `command --server` sur un port libre, vérifie l'API, puis arrête le processus.

    Dans l'ordre : scan rapide (`quick_scan`), export PDF du premier scan (`pdf`),
    scan au profil par défaut avec capture d'écran (`scan`), puis arrêt propre
    (`graceful_stop` : le livrable doit s'arrêter seul après un Ctrl+C / Ctrl+Pause).
    """
    if pdf and not (quick_scan or scan):
        raise SmokeError("L'export PDF exige un scan (--quick-scan ou --scan).")
    env = child_env(data_dir)
    if version_flag:
        check_version_flag(command, expected_version, env, cwd)
    port = free_port()
    base_url = f"http://127.0.0.1:{port}"
    server = [*command, "--server", "--host", "127.0.0.1", "--port", str(port)]
    with tempfile.TemporaryFile() as log:
        try:
            process = subprocess.Popen(
                server,
                stdout=log if capture else None,
                stderr=subprocess.STDOUT if capture else None,
                env=env,
                cwd=cwd,
                # Groupe de processus à part : arrêt propre (request_stop) et descendants (stop).
                **popen_flags(),
            )
        except OSError as exc:
            raise SmokeError(f"Lancement du livrable impossible : {exc}") from exc
        try:
            payload = wait_for_health(base_url, process, health_timeout)
            check_health(payload, expected_version)
            print(f"[ok] /api/health : {json.dumps(payload, ensure_ascii=False)}", flush=True)
            for path in expect_files:
                if not Path(path).exists():
                    raise SmokeError(f"Fichier attendu absent : {path}")
                print(f"[ok] Présent : {path}", flush=True)
            pdf_pending = pdf
            if quick_scan:
                quick = run_scan(base_url, quick_scan, scan_timeout, profile=QUICK_PROFILE)
                summary = check_quick_scan(quick)
                print(f"[ok] Scan rapide de {quick_scan} (n° {quick['id']}) : {summary}", flush=True)
                if pdf_pending:
                    size = check_pdf_export(base_url, quick["id"])
                    print(f"[ok] Export PDF du scan n° {quick['id']} : {size} octets", flush=True)
                    pdf_pending = False
            if scan:
                result = run_scan(base_url, scan, scan_timeout)
                check_screenshot(result)
                print(f"[ok] Scan de {scan} : capture {result['screenshot_path']}", flush=True)
                if pdf_pending:
                    size = check_pdf_export(base_url, result["id"])
                    print(f"[ok] Export PDF du scan n° {result['id']} : {size} octets", flush=True)
            if graceful_stop:
                code, duration = graceful_shutdown(process)
                print(f"[ok] Arrêt propre en {duration:.1f} s (code {code})", flush=True)
        except Exception as exc:
            # Toute erreur (pas seulement SmokeError) : on affiche d'abord le journal du livrable.
            stop(process)
            if capture:
                log.seek(0)
                output = log.read().decode("utf-8", errors="replace")
                sys.stderr.write(f"---- Sortie du livrable ----\n{output}\n")
            if isinstance(exc, SmokeError):
                raise
            raise SmokeError(f"Erreur inattendue : {type(exc).__name__} : {exc}") from exc
        finally:
            stop(process)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="smoke_test.py", description="Test de fumée d'un livrable de DomainRecon."
    )
    parser.add_argument("--exe", type=Path, required=True, help="exécutable à tester")
    parser.add_argument("--expect-version", required=True, help="version attendue (/api/health)")
    parser.add_argument("--data-dir", type=Path, help="dossier des données imposé (DATA_DIR)")
    parser.add_argument(
        "--expect-file", type=Path, action="append", default=[], help="fichier attendu (répétable)"
    )
    parser.add_argument("--scan", metavar="DOMAINE", help="scan à lancer (capture d'écran exigée)")
    parser.add_argument(
        "--quick-scan", metavar="DOMAINE", help="scan au profil « rapide » (un module réussi au moins)"
    )
    parser.add_argument("--pdf", action="store_true", help="exporte en PDF le premier scan lancé")
    parser.add_argument(
        "--no-graceful-stop",
        action="store_true",
        help="n'exige pas l'arrêt propre (exécutable fenêtré, sans console pour recevoir Ctrl+Pause)",
    )
    parser.add_argument("--version-flag", action="store_true", help="vérifie aussi « --version »")
    parser.add_argument(
        "--no-capture", action="store_true", help="ne capture pas la sortie (exécutable fenêtré)"
    )
    parser.add_argument("--health-timeout", type=float, default=HEALTH_TIMEOUT)
    parser.add_argument("--scan-timeout", type=float, default=SCAN_TIMEOUT)
    args = parser.parse_args(argv)
    if not args.exe.is_file():
        print(f"[ÉCHEC] Exécutable introuvable : {args.exe}", file=sys.stderr)
        return 1
    try:
        smoke(
            [str(args.exe)],
            args.expect_version,
            data_dir=args.data_dir,
            expect_files=args.expect_file,
            scan=args.scan,
            quick_scan=args.quick_scan,
            pdf=args.pdf,
            version_flag=args.version_flag,
            capture=not args.no_capture,
            # Exécutable fenêtré (--no-capture) : aucune console pour recevoir la demande d'arrêt.
            graceful_stop=not (args.no_graceful_stop or args.no_capture),
            health_timeout=args.health_timeout,
            scan_timeout=args.scan_timeout,
        )
    except SmokeError as exc:
        print(f"[ÉCHEC] {exc}", file=sys.stderr)
        return 1
    print("[ok] Test de fumée réussi", flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
