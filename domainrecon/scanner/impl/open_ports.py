# =============================================================================
# DomainRecon - Scan de ports : 51 ports, niveau de risque par service
# =============================================================================
# S'appuie sur scanner/network.py (33 ports de base, anti-SSRF, détection des
# sondes « bloquées » par la boucle d'événements et des hôtes injoignables) et
# l'étend à 51 ports, chacun avec un NIVEAU DE RISQUE.
# Le résultat reste une liste de {port, state, service} (format lu par
# l'interface et le score), enrichie de `risk` (critical, high, medium, low, info).
#
# Le score et les constats ne s'appuient pas sur ce tableau seul : les gravités des
# services déjà pénalisés (score.SENSITIVE_PORTS) restent celles du barème ; les
# services ajoutés par cette liste étendue y sont complétés (EXTRA_SENSITIVE_PORTS).
# =============================================================================

import asyncio

from ...i18n import msg
from .. import network
from ..errors import ModuleError
from ..rules import FindingInput, FindingRule, PenaltyRule, hit
from ..score import PORT_PENALTY_POINTS, SENSITIVE_PORTS, as_dict, sensitive_open_ports
from ..targets import ensure_ip_allowed

# port -> (service, risque). Risque d'un service exposé sur Internet.
PORTS: dict[int, tuple[str, str]] = {
    21: ("FTP", "medium"),
    22: ("SSH", "info"),
    23: ("Telnet", "critical"),
    25: ("SMTP", "info"),
    53: ("DNS", "info"),
    80: ("HTTP", "info"),
    110: ("POP3", "low"),
    135: ("MS-RPC", "high"),
    139: ("NetBIOS", "high"),
    143: ("IMAP", "low"),
    443: ("HTTPS", "info"),
    445: ("SMB", "critical"),
    465: ("SMTPS", "info"),
    587: ("SMTP/TLS", "info"),
    993: ("IMAPS", "info"),
    995: ("POP3S", "info"),
    1433: ("SQL Server", "high"),
    1521: ("Oracle", "high"),
    2049: ("NFS", "high"),
    2375: ("Docker API", "critical"),
    2376: ("Docker TLS", "medium"),
    3000: ("Node/Grafana", "medium"),
    3001: ("Node.js", "medium"),
    3306: ("MySQL", "high"),
    3389: ("RDP", "high"),
    4848: ("GlassFish admin", "high"),
    5000: ("Flask/Docker registry", "medium"),
    5001: ("Docker registry", "medium"),
    5432: ("PostgreSQL", "high"),
    5900: ("VNC", "high"),
    5984: ("CouchDB", "high"),
    5985: ("WinRM", "high"),
    5986: ("WinRM-HTTPS", "high"),
    6379: ("Redis", "critical"),
    6380: ("Redis TLS", "medium"),
    7001: ("WebLogic", "high"),
    7002: ("WebLogic TLS", "medium"),
    8000: ("HTTP-Alt", "info"),
    8001: ("HTTP-Alt", "info"),
    8080: ("HTTP-Proxy", "info"),
    8081: ("HTTP-Alt", "info"),
    8443: ("HTTPS-Alt", "info"),
    8500: ("Consul", "high"),
    8888: ("HTTP-Alt", "info"),
    9000: ("PHP-FPM", "medium"),
    9200: ("Elasticsearch", "critical"),
    9300: ("Elasticsearch cluster", "high"),
    11211: ("Memcached", "critical"),
    27017: ("MongoDB", "critical"),
    27018: ("MongoDB", "high"),
    50000: ("SAP/Jenkins", "medium"),
}

# Services de la liste étendue que le barème (score.SENSITIVE_PORTS) ne connaît pas encore.
EXTRA_SENSITIVE_PORTS: dict[int, tuple[str, str]] = {
    port: (service, risk)
    for port, (service, risk) in PORTS.items()
    if port not in SENSITIVE_PORTS and risk in ("critical", "high", "medium")
}
ALL_SENSITIVE_PORTS = {**EXTRA_SENSITIVE_PORTS, **SENSITIVE_PORTS}

# Réglages du scan.
PORT_TIMEOUT = 3.0
CONCURRENCY = 16


def service_name(port: int) -> str:
    """Nom du service attendu sur un port (« unknown » s'il n'est pas dans la liste)."""
    return PORTS.get(port, ("unknown", "info"))[0]


def risk_of(port: int) -> str:
    """Niveau de risque d'un service exposé : critical, high, medium, low ou info."""
    if port in SENSITIVE_PORTS:
        return SENSITIVE_PORTS[port][1]
    return PORTS.get(port, ("unknown", "info"))[1]


async def scan_ports(ip: str, ports: list[int] | None = None) -> list[dict]:
    """Scan TCP connect des ports courants d'une IP validée par la politique de cibles.

    Même contrat que network.scan_ports : liste des ports ouverts, ModuleError si
    aucun port n'a répondu (ni ouvert ni refusé : hôte injoignable ou entièrement
    filtré), ValueError / TargetNotAllowedError si l'IP n'est pas autorisée. Les sondes
    sans réponse sont refaites si la boucle d'événements a été bloquée entre-temps.
    """
    if not ip:
        return []
    ip = ensure_ip_allowed(ip)
    targets = list(PORTS) if ports is None else sorted({int(p) for p in ports})
    semaphore = asyncio.Semaphore(CONCURRENCY)

    async def probe(port: int) -> tuple[str, str | None]:
        async with semaphore:
            return await network._check_port(ip, port, PORT_TIMEOUT)

    async def probe_all(batch: list[int]) -> dict[int, tuple[str, str | None]]:
        return dict(zip(batch, await asyncio.gather(*(probe(p) for p in batch)), strict=True))

    states = await probe_all(targets)
    if any(state == network._STALLED for state, _ in states.values()):
        silent = [p for p, (state, _) in states.items() if state in (network._FILTERED, network._STALLED)]
        states.update(await probe_all(silent))

    if states and not any(state in (network._OPEN, network._REFUSED) for state, _ in states.values()):
        errors = [error for state, error in states.values() if state == network._NETWORK_ERROR]
        if len(errors) == len(states):
            raise ModuleError(msg("network.ports_failed", error=errors[0]))
        raise ModuleError(msg("network.ports_filtered", count=len(states)))

    return [
        {"port": port, "state": "open", "service": service_name(port), "risk": risk_of(port)}
        for port, (state, _) in states.items()
        if state == network._OPEN
    ]


# =============================================================================
# Constats et pénalités : tous les services sensibles de la liste
# =============================================================================


def _open_numbers(open_ports: object) -> set[int]:
    """Ports ouverts d'un résultat enregistré (entiers, textes ou dicts « port » / « state »)."""
    numbers: set[int] = set()
    for entry in open_ports if isinstance(open_ports, list) else []:
        if isinstance(entry, dict):
            if entry.get("state", "open") != "open":
                continue
            entry = entry.get("port")
        try:
            numbers.add(int(entry))
        except (TypeError, ValueError):
            continue
    return numbers


def exposed_sensitive_ports(open_ports: object) -> list[tuple[int, str, str]]:
    """(port, service, gravité) des services sensibles ouverts : barème d'origine, puis services ajoutés."""
    extra = [(p, *EXTRA_SENSITIVE_PORTS[p]) for p in _open_numbers(open_ports) if p in EXTRA_SENSITIVE_PORTS]
    return sorted([*sensitive_open_ports(open_ports), *extra], key=lambda item: item[0])


def _check_ports(f: FindingInput) -> list:
    return [
        hit(port=port, service=service, severity=severity)
        for port, service, severity in exposed_sensitive_ports(f.data)
    ]


def _penalties(data: dict) -> list[dict]:
    open_ports = as_dict(data).get("open_ports")
    return [
        {
            "key": f"port_{port}",
            "label": msg("score.penalty_port", port=port, service=service),
            "points": PORT_PENALTY_POINTS[severity],
            "severity": severity,
        }
        for port, service, severity in exposed_sensitive_ports(open_ports)
    ]


# Règles à brancher dans le ModuleSpec d'open_ports (à la place de findings.PORT_FINDINGS et
# score.PORT_PENALTY_RULE, qui ne connaissent que 20 services).
PORT_FINDINGS = (FindingRule(code="finding.port_exposed", severity="high", check=_check_ports),)
PORT_PENALTY_RULE = PenaltyRule(evaluate=_penalties)
