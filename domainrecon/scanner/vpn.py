# =============================================================================
# DomainRecon - Scanner : statut du VPN Mullvad (lecture seule)
# =============================================================================
# get_vpn_status() dit si la machine sort par Mullvad VPN :
#   - CLI Mullvad installé : lecture de « mullvad status » ;
#   - sinon : https://am.i.mullvad.net/json (`mullvad_exit_ip`), interrogé SANS
#     proxy ni variable d'environnement de proxy, puisque c'est la connexion
#     directe de la machine que l'on veut connaître ; délai de 5 s.
# Aucun pilotage (connexion, déconnexion) : lecture seule. Les échecs attendus
# (CLI muet, API injoignable ou incohérente) ne lèvent rien : un statut illisible
# donne `connected: None`.
# =============================================================================

import ipaddress
import json
import os
import re
import shutil
import subprocess
import sys

import httpx

from ..i18n import msg
from .common import USER_AGENT, logger

MULLVAD_API_URL = "https://am.i.mullvad.net/json"
# Délais (secondes) de l'API et de la commande « mullvad status ».
API_TIMEOUT = 5.0
CLI_TIMEOUT = 5.0
# Taille maximale lue de la réponse de l'API (la vraie fait moins de 2 Kio).
API_MAX_BYTES = 64 * 1024
# Nom du fournisseur renvoyé quand le VPN est connecté.
PROVIDER = "Mullvad"

_CLI_NAME = "mullvad"
_MAX_TEXT_LENGTH = 100

# Première ligne de « mullvad status » : « Connected », « Disconnected »,
# « Connecting to … », « Blocked: … » ; les anciennes versions la font précéder
# de « Tunnel status: ». Pas « Error: … » : c'est la commande qui échoue, pas un
# état du tunnel.
_STATE_RE = re.compile(
    r"(?:tunnel status:\s*)?(connected|connecting|disconnected|disconnecting|blocked)\b",
    re.IGNORECASE,
)
# « Visible location: Sweden, Gothenburg. IPv4: 185.213.154.68, IPv6: 2a03:… »
_LOCATION_RE = re.compile(r"visible location:\s*((?!IPv[46]:)[^\s,.][^,.\n]*)", re.IGNORECASE)
_IPV4_RE = re.compile(r"IPv4:\s*([0-9.]+)")
_IPV6_RE = re.compile(r"IPv6:\s*([0-9A-Fa-f:]+)")


def _status(connected: bool | None, *, mullvad_cli: bool, ip=None, country=None, error=None) -> dict:
    """Statut dans sa forme publique ; `error` (message traduisible) n'est renseigné que si `connected` est None."""
    return {
        "connected": connected,
        "ip": ip,
        "country": country,
        "provider": PROVIDER if connected else None,
        "mullvad_cli": mullvad_cli,
        "error": error,
    }


def _clean_ip(value: object) -> str | None:
    """Adresse IP valide (forme canonique), sinon None."""
    try:
        return str(ipaddress.ip_address(value)) if isinstance(value, str) else None
    except ValueError:
        return None


def _clean_text(value: object) -> str | None:
    """Texte court et imprimable (nom de pays), sinon None : la valeur vient d'un tiers."""
    if not isinstance(value, str):
        return None
    text = "".join(ch for ch in value if ch.isprintable()).strip()[:_MAX_TEXT_LENGTH]
    return text or None


# =============================================================================
# CLI Mullvad
# =============================================================================


def _cli_candidates() -> list[str]:
    """Emplacements habituels du CLI quand il n'est pas dans le PATH."""
    if sys.platform == "win32":
        program_files = os.environ.get("ProgramFiles", r"C:\Program Files")
        return [os.path.join(program_files, "Mullvad VPN", "resources", "mullvad.exe")]
    if sys.platform == "darwin":
        return ["/Applications/Mullvad VPN.app/Contents/Resources/mullvad"]
    return []


def _find_cli() -> str | None:
    """Chemin du CLI Mullvad (PATH, puis emplacements habituels), ou None s'il n'est pas installé."""
    found = shutil.which(_CLI_NAME)
    if found:
        return found
    return next((path for path in _cli_candidates() if os.path.isfile(path)), None)


def _run_cli(cli: str) -> subprocess.CompletedProcess:
    """Lance « mullvad status » (délai CLI_TIMEOUT) ; lève TimeoutExpired ou OSError."""
    return subprocess.run(
        [cli, "status"],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=CLI_TIMEOUT,
        # Sans entrée standard valide (application de bureau sans console) ni fenêtre de console.
        stdin=subprocess.DEVNULL,
        creationflags=subprocess.CREATE_NO_WINDOW if sys.platform == "win32" else 0,
        check=False,
    )


def parse_cli_status(output: str) -> dict | None:
    """Statut lu dans la sortie de « mullvad status », ou None si elle n'est pas reconnue.

    La première ligne donne l'état : seul « Connected » vaut `connected: True`
    (connexion ou déconnexion en cours, blocage valent False). L'adresse
    IP (IPv4 de préférence) et le pays viennent de la ligne « Visible location »,
    absente des anciennes versions : None dans ce cas.
    """
    lines = [line.strip() for line in output.splitlines() if line.strip()]
    state = _STATE_RE.match(lines[0]) if lines else None
    if state is None:
        return None
    text = "\n".join(lines)
    location = _LOCATION_RE.search(text)
    ip = None
    for pattern in (_IPV4_RE, _IPV6_RE):
        found = pattern.search(text)
        ip = ip or (_clean_ip(found.group(1)) if found else None)
    return _status(
        state.group(1).lower() == "connected",
        mullvad_cli=True,
        ip=ip,
        country=_clean_text(location.group(1)) if location else None,
    )


def _status_from_cli(cli: str) -> dict:
    failed = _status(None, mullvad_cli=True, error=msg("api.vpn_cli_failed"))
    try:
        result = _run_cli(cli)
    except subprocess.TimeoutExpired:
        logger.warning("« mullvad status » : aucune réponse en %s s", CLI_TIMEOUT)
        return failed
    except OSError as e:
        logger.warning("« mullvad status » : lancement impossible (%s)", e)
        return failed
    # Sortie lue même après un code d'erreur : seule une sortie reconnue compte.
    parsed = parse_cli_status(result.stdout)
    if parsed is None:
        lines = (result.stderr or result.stdout or "").strip().splitlines()
        logger.warning(
            "« mullvad status » : code %s, sortie non reconnue (%s)",
            result.returncode,
            lines[0] if lines else "",
        )
        return failed
    return parsed


# =============================================================================
# API am.i.mullvad.net
# =============================================================================


def _fetch_json(transport: httpx.BaseTransport | None) -> object:
    """Réponse JSON de l'API, lue sur au plus API_MAX_BYTES octets. Lève httpx.HTTPError ou ValueError."""
    headers = {"User-Agent": USER_AGENT, "Accept": "application/json", "Accept-Encoding": "identity"}
    # trust_env=False : ni HTTP(S)_PROXY ni autre variable d'environnement.
    with httpx.Client(
        timeout=API_TIMEOUT, trust_env=False, follow_redirects=False, headers=headers, transport=transport
    ) as client:
        with client.stream("GET", MULLVAD_API_URL) as response:
            response.raise_for_status()
            try:
                body = response.content  # réponse déjà en mémoire (tests)
            except httpx.ResponseNotRead:
                body = bytearray()
                for chunk in response.iter_raw():
                    body += chunk
                    if len(body) > API_MAX_BYTES:
                        break
            if len(body) > API_MAX_BYTES:
                raise ValueError("réponse trop volumineuse")
    return json.loads(body)


def _status_from_api(transport: httpx.BaseTransport | None) -> dict:
    failed = _status(None, mullvad_cli=False, error=msg("api.vpn_api_failed"))
    try:
        data = _fetch_json(transport)
    except (httpx.HTTPError, ValueError, RecursionError) as e:
        logger.warning("am.i.mullvad.net : %s", str(e) or type(e).__name__)
        return failed
    # `mullvad_exit_ip` : vrai si l'adresse de sortie est celle d'un serveur Mullvad.
    if not isinstance(data, dict) or not isinstance(data.get("mullvad_exit_ip"), bool):
        logger.warning("am.i.mullvad.net : réponse inattendue")
        return failed
    return _status(
        data["mullvad_exit_ip"],
        mullvad_cli=False,
        ip=_clean_ip(data.get("ip")),
        country=_clean_text(data.get("country")),
    )


# =============================================================================
# Statut
# =============================================================================


def get_vpn_status(*, transport: httpx.BaseTransport | None = None) -> dict:
    """Statut du VPN Mullvad : {connected, ip, country, provider, mullvad_cli, error}.

    - `connected` : True (sortie par Mullvad), False, ou None si le statut n'a
      pas pu être lu (alors `error` est un message traduisible, None sinon) ;
    - `ip`, `country` : adresse publique et pays vus de l'extérieur (None si
      inconnus) ; `provider` : « Mullvad » quand `connected` est vrai ;
    - `mullvad_cli` : le CLI Mullvad est installé (« mullvad status » fait foi).

    Lecture synchrone (processus, requête de 5 s au plus) : depuis une
    coroutine, passer par `asyncio.to_thread`. `transport` sert aux tests
    (httpx.MockTransport).
    """
    cli = _find_cli()
    if cli is not None:
        return _status_from_cli(cli)
    return _status_from_api(transport)
