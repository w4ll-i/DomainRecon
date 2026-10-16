# =============================================================================
# DomainRecon - Exécution de Nuclei (binaire externe de Project Discovery)
# =============================================================================
# Lance le binaire nuclei contre https://cible et lit ses constats au format
# JSON par ligne. Options retenues :
#   - l'option -json (retirée) devient -jsonl ; -omit-raw (pas de requête/réponse
#     brute), -duc (pas de vérification de mise à jour), -ni (pas d'interactsh),
#     -etags intrusive,dos (modèles dangereux écartés) ;
#   - stdout et stderr lus en parallèle avec un plafond de taille (pas d'interblocage) ;
#   - à l'annulation, le processus est tué PUIS attendu (pas de zombie) ;
#   - un échec de LANCEMENT (binaire absent, erreur d'argument) n'est jamais pris
#     pour un scan propre sans constat : il lève ModuleSkipped ou ModuleError.
# Aucune donnée réseau du projet n'est utilisée ici : Nuclei gère ses propres
# connexions (le proxy du scan lui est passé par -proxy si présent).
# =============================================================================

import asyncio
import json
import shutil

from ...core import config
from ...i18n import msg
from ..errors import ModuleError, ModuleSkipped

# Plafond de lecture des flux (8 Mio) : un binaire bavard ne remplit pas la mémoire.
_MAX_OUTPUT = 8 * 1024 * 1024
# Modèles lents ou agressifs écartés.
_EXCLUDE_TAGS = "intrusive,dos,fuzz"
_SEVERITY = "critical,high,medium"
_TAGS = "cve,exposure,misconfig,takeover,default-login"


def nuclei_binary() -> str | None:
    """Chemin du binaire nuclei : Réglages (config) puis PATH ; None s'il est introuvable."""
    configured = config.nuclei_path()
    if configured:
        return configured if shutil.which(configured) or _is_file(configured) else None
    return shutil.which("nuclei")


def _is_file(path: str) -> bool:
    from pathlib import Path

    try:
        return Path(path).is_file()
    except OSError:
        return False


def build_command(binary: str, target: str, proxy: str | None, templates: str | None = None) -> list[str]:
    cmd = [
        binary,
        "-target", target,
        "-jsonl",
        "-silent",
        "-no-color",
        "-omit-raw",
        "-duc",
        "-ni",
        "-tags", _TAGS,
        "-exclude-tags", _EXCLUDE_TAGS,
        "-severity", _SEVERITY,
        "-timeout", "5",
        "-rate-limit", "50",
        "-c", "10",
    ]  # fmt: skip
    if templates:
        # Dossier de modèles embarqué dans les livrables (sinon ceux du dossier de config de Nuclei).
        cmd += ["-templates", templates]
    if proxy:
        cmd += ["-proxy", proxy]
    return cmd


async def _read_capped(stream, limit: int) -> bytes:
    """Lit un flux jusqu'à `limit` octets, puis ignore le reste (pas d'interblocage)."""
    chunks: list[bytes] = []
    total = 0
    while True:
        chunk = await stream.read(65536)
        if not chunk:
            break
        if total < limit:
            chunks.append(chunk[: limit - total])
            total += len(chunk)
    return b"".join(chunks)


def parse_findings(stdout: bytes) -> list[dict]:
    """Constats de la sortie JSON par ligne (une ligne illisible est ignorée)."""
    findings = []
    for raw in stdout.splitlines():
        line = raw.strip()
        if not line:
            continue
        try:
            item = json.loads(line)
        except (ValueError, UnicodeDecodeError):
            continue
        if not isinstance(item, dict):
            continue
        info = item.get("info", {}) if isinstance(item.get("info"), dict) else {}
        findings.append(
            {
                "template_id": str(item.get("template-id") or "")[:120],
                "name": str(info.get("name") or "")[:200],
                "severity": str(info.get("severity") or "info")[:20],
                "matched_at": str(item.get("matched-at") or "")[:300],
            }
        )
    return findings


async def run_nuclei(target: str, proxy: str | None, timeout: float, templates: str | None = None) -> dict:
    """Lance nuclei et renvoie ses constats ; ModuleSkipped si le binaire manque."""
    binary = nuclei_binary()
    if binary is None:
        raise ModuleSkipped(msg("nuclei.not_installed"))
    cmd = build_command(binary, target, proxy, templates or config.nuclei_templates())
    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
        )
    except (OSError, ValueError) as e:
        raise ModuleError(msg("nuclei.launch_failed", error=type(e).__name__)) from e

    async def gather_streams():
        return await asyncio.gather(
            _read_capped(proc.stdout, _MAX_OUTPUT), _read_capped(proc.stderr, _MAX_OUTPUT)
        )

    try:
        stdout, stderr = await asyncio.wait_for(gather_streams(), timeout=timeout)
        await proc.wait()
    except (asyncio.TimeoutError, TimeoutError):
        _terminate(proc)
        await proc.wait()
        raise ModuleError(msg("nuclei.timeout", seconds=f"{timeout:.0f}")) from None
    except asyncio.CancelledError:
        _terminate(proc)
        await proc.wait()
        raise

    if proc.returncode not in (0, None):
        # Nuclei rend un code non nul sur erreur de lancement, pas sur « aucun constat ».
        detail = stderr.decode("utf-8", "replace").strip().splitlines()[-1:] or [""]
        raise ModuleError(msg("nuclei.failed", detail=detail[0][:200]))

    findings = parse_findings(stdout)
    return {
        "measured": True,
        "error": None,
        "target": target,
        "findings": findings,
        "total": len(findings),
        "critical": sum(1 for f in findings if f["severity"] == "critical"),
        "high": sum(1 for f in findings if f["severity"] == "high"),
    }


def _terminate(proc) -> None:
    try:
        proc.kill()
    except ProcessLookupError:
        pass
