# backend/app/vpn_manager.py
"""
VPN Manager - Control Mullvad VPN via its CLI + status via am.i.mullvad.net.

Detection strategy (in order):
  1. Mullvad CLI available → full control (status, connect, disconnect, locations).
  2. No CLI (Docker without mount) → query am.i.mullvad.net to detect if the
     host VPN is routing container traffic through Mullvad.
     This works on ALL Docker platforms (Windows, macOS, Linux).
     Status is read-only (no connect/disconnect without the CLI).

Linux Docker full control:
  Uncomment the volume mounts in docker-compose.yml to mount the CLI binary.
"""
import asyncio
import os
import re
import shutil
from typing import Optional

import httpx

_MULLVAD_PATHS = [
    "mullvad",                                                        # PATH (any OS / Linux Docker mount)
    r"C:\Program Files\Mullvad VPN\resources\mullvad.exe",           # Windows
    r"C:\Program Files (x86)\Mullvad VPN\resources\mullvad.exe",     # Windows x86
    "/usr/bin/mullvad",                                               # Linux native
    "/usr/local/bin/mullvad",                                         # Linux Docker mount target
    "/Applications/Mullvad VPN.app/Contents/Resources/mullvad",      # macOS
]

# Linux Mullvad daemon socket - present on host, mountable into container
_MULLVAD_SOCKET = "/var/run/mullvad-vpn"

_VALID_LOC = re.compile(r"^[a-z]{2}(-[a-z0-9]+)?$")


def _find_mullvad() -> Optional[str]:
    """Return the path to the Mullvad CLI binary, or None if not found."""
    for path in _MULLVAD_PATHS:
        if path == "mullvad":
            found = shutil.which("mullvad")
            if found:
                return found
        elif os.path.isfile(path):
            return path
    return None


def _is_docker() -> bool:
    """Best-effort detection of running inside a Docker container."""
    return os.path.exists("/.dockerenv") or os.environ.get("ENV") == "production"


async def _run(*args) -> tuple:
    binary = _find_mullvad()
    if not binary:
        return -1, ""
    try:
        proc = await asyncio.create_subprocess_exec(
            binary, *args,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=15)
        return proc.returncode, stdout.decode("utf-8", errors="replace").strip()
    except asyncio.TimeoutError:
        return -1, "timeout"
    except Exception as e:
        return -1, str(e)


async def _check_mullvad_net() -> dict:
    """
    Query am.i.mullvad.net to detect if container traffic exits via Mullvad.
    Works on all Docker platforms when the host has Mullvad active.
    Returns partial status dict (no CLI control available).
    """
    try:
        async with httpx.AsyncClient(timeout=8) as client:
            r = await client.get("https://am.i.mullvad.net/json")
            if r.status_code == 200:
                d = r.json()
                connected = bool(d.get("mullvad_exit_ip"))
                city    = d.get("city", "")
                country = d.get("country", "")
                location = f"{city}, {country}".strip(", ") if (city or country) else None
                server   = d.get("mullvad_exit_ip_hostname") or None
                ip       = d.get("ip")
                return {
                    "available": True,
                    "connected": connected,
                    "status_text": (
                        f"Connected via host VPN - {location or server or ip}"
                        if connected else
                        f"Not connected - exit IP: {ip}"
                    ),
                    "server": server,
                    "location": location,
                    "exit_ip": ip,
                    "cli_control": False,
                    "docker_note": (
                        "VPN status detected via am.i.mullvad.net. "
                        "Connect/disconnect controls require the Mullvad CLI "
                        "(Linux: mount it via docker-compose.yml volumes)."
                    ),
                    "socket_mounted": os.path.exists(_MULLVAD_SOCKET),
                }
    except Exception:
        pass
    return None


async def get_status() -> dict:
    binary = _find_mullvad()

    if not binary:
        # No CLI - try am.i.mullvad.net for read-only status (all platforms)
        net_status = await _check_mullvad_net()
        if net_status:
            return net_status

        # Fallback: completely unavailable
        in_docker = _is_docker()
        return {
            "available": False,
            "connected": False,
            "status_text": "Mullvad VPN not detected",
            "server": None,
            "location": None,
            "cli_control": False,
            "docker_note": (
                "Running in Docker - install Mullvad VPN on the host to protect scans. "
                "To enable connect/disconnect controls (Linux only), mount the CLI "
                "by uncommenting the volume lines in docker-compose.yml."
            ) if in_docker else None,
            "socket_mounted": os.path.exists(_MULLVAD_SOCKET),
        }

    # CLI available - full control
    code, output = await _run("status")
    lines = output.splitlines()
    first_line = lines[0].strip() if lines else ""
    connected = first_line.lower().startswith("connected")

    server = None
    location = None
    exit_ip = None

    if connected:
        # New Mullvad CLI format (2024+):
        #   Connected
        #       Relay:            fr-mrs-wg-002
        #       Features:         Quantum Resistance
        #       Visible location: France, Marseille. IPv4: 138.199.15.153
        #
        # Old format (pre-2024):
        #   Connected to se-got-001 in Gothenburg, SE

        # Try old single-line format first
        m_old = re.search(r"Connected to (\S+) in (.+)", first_line, re.IGNORECASE)
        if m_old:
            server = m_old.group(1)
            location = m_old.group(2).strip()
        else:
            # Parse new multi-line format
            for line in lines[1:]:
                line = line.strip()
                m_relay = re.match(r"Relay\s*:\s*(.+)", line, re.IGNORECASE)
                if m_relay:
                    server = m_relay.group(1).strip()
                m_loc = re.match(r"Visible location\s*:\s*(.+)", line, re.IGNORECASE)
                if m_loc:
                    # "France, Marseille. IPv4: 138.199.15.153"
                    loc_raw = m_loc.group(1).strip()
                    # Extract IP if present
                    ip_match = re.search(r"IPv(?:4|6):\s*([\d.:a-fA-F]+)", loc_raw)
                    if ip_match:
                        exit_ip = ip_match.group(1)
                        # Strip everything from " IPv4:" onward
                        loc_raw = re.sub(r"\s*IPv(?:4|6):.*$", "", loc_raw)
                    location = loc_raw.rstrip(". ")

    return {
        "available": True,
        "connected": connected,
        "status_text": first_line,
        "server": server,
        "location": location,
        "exit_ip": exit_ip,
        "cli_control": True,
        "docker_note": None,
        "socket_mounted": os.path.exists(_MULLVAD_SOCKET),
    }


async def connect() -> dict:
    if not _find_mullvad():
        return {"success": False, "message": "Mullvad CLI not available in this environment"}
    code, output = await _run("connect")
    return {"success": code == 0, "message": output or "Connecting…"}


async def disconnect() -> dict:
    if not _find_mullvad():
        return {"success": False, "message": "Mullvad CLI not available in this environment"}
    code, output = await _run("disconnect")
    return {"success": code == 0, "message": output or "Disconnected"}


async def list_locations() -> list:
    code, output = await _run("relay", "list")
    if code != 0 or not output:
        return []

    countries = []
    current = None
    for line in output.splitlines():
        cm = re.match(r"^([\w][\w\s]+?)\s+\(([a-z]{2})\)\s*$", line.strip())
        if cm:
            current = {"name": cm.group(1).strip(), "code": cm.group(2), "cities": []}
            countries.append(current)
        elif current and line.startswith(("\t", "  ")):
            citm = re.match(r"\s+([\w][\w\s]+?)\s+\(([a-z]{2}-[a-z0-9]+)\)", line)
            if citm:
                current["cities"].append({
                    "name": citm.group(1).strip(),
                    "code": citm.group(2),
                })
    return countries[:60]


async def set_location(code: str) -> dict:
    if not _VALID_LOC.match(code):
        return {"success": False, "message": "Invalid location code"}
    if not _find_mullvad():
        return {"success": False, "message": "Mullvad CLI not available in this environment"}
    parts = code.split("-")
    rc, output = await _run("relay", "set", "location", *parts)
    return {"success": rc == 0, "message": output or "Location set"}
