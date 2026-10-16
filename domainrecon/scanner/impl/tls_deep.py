# =============================================================================
# DomainRecon - Analyse TLS approfondie : protocoles, suites, compression, DH
# =============================================================================
# Logique du module « tls_deep » (modules/tls_deep.py). Elle s'appuie sur les
# sondes bas niveau de impl/tls_hello.py (ClientHello forgé), si bien que le
# résultat ne dépend pas de l'OpenSSL de la machine du scan.
#
# Méthode (celle de nmap ssl-enum-ciphers) :
#   1. pour chaque version (SSLv3 à TLS 1.3), un ClientHello qui propose toutes
#      les suites connues : le serveur répond avec la version retenue, ou refuse ;
#   2. pour chaque version acceptée, on retire la suite choisie et on recommence
#      jusqu'au refus : on obtient la liste complète des suites acceptées ;
#   3. une sonde propose la compression (CRIME) ; une autre n'offre que du DHE
#      (taille du premier (p), Logjam) ; l'ordre des suites inversé dit qui, du
#      client ou du serveur, choisit.
# Seul le début de la poignée de main est échangé : aucun certificat n'est
# validé, aucune donnée applicative n'est envoyée.
# =============================================================================

import time
from concurrent.futures import ThreadPoolExecutor

from . import tls_hello as hello

# Versions testées, de la plus ancienne à la plus récente.
VERSIONS = (hello.SSL3, hello.TLS10, hello.TLS11, hello.TLS12, hello.TLS13)
# Tours d'énumération maximum par version (une suite par tour).
MAX_ROUNDS = 70
# Suites listées dans le résultat (au plus), pour ne pas renvoyer de mégaoctets.
MAX_LISTED_SUITES = 150
# Délai d'une sonde, en secondes.
PROBE_TIMEOUT = 5.0


def _accepts(flight: hello.ServerFlight, version: int) -> bool:
    """Le serveur a-t-il retenu exactement la version proposée (et non une version inférieure) ?"""
    return flight.answered and flight.version == version


def _status(flight: hello.ServerFlight, version: int) -> bool | None:
    """True : acceptée ; False : refusée (alerte, fermeture, version inférieure) ; None : indéterminé."""
    if _accepts(flight, version):
        return True
    if flight.outcome in ("alert", "closed") or (flight.answered and flight.version != version):
        return False
    return None


def _probe(address: str, port: int, sni: str | None, version: int, suites: list[int], **options):
    read_flight = options.pop("read_flight", False)
    packet = hello.build_client_hello(version, suites, sni, **options)
    return hello.probe(address, port, packet, timeout=PROBE_TIMEOUT, read_flight=read_flight)


def _enumerate_version(address: str, port: int, sni: str | None, version: int, deadline: float) -> list[int]:
    """Suites acceptées pour `version` (liste ordonnée par choix du serveur)."""
    remaining = hello.suites_for(version)
    accepted: list[int] = []
    for _ in range(MAX_ROUNDS):
        if not remaining or time.monotonic() > deadline:
            break
        flight = _probe(address, port, sni, version, remaining)
        if not _accepts(flight, version) or flight.suite not in remaining:
            break
        accepted.append(flight.suite)
        remaining.remove(flight.suite)
    return accepted


def _grade(report: dict) -> str:
    """Note A à F : voir la table dans le README du module (protocoles, suites, DH, compression)."""
    protocols = report["protocols"]
    modern = protocols.get("TLSv1.2") or protocols.get("TLSv1.3")
    dh_bits = report.get("dh_bits")
    if protocols.get("SSLv3") or report["broken_ciphers"] or not modern:
        return "F"
    if report["weak_ciphers"] or (dh_bits is not None and dh_bits <= 1024):
        return "D"
    if protocols.get("TLSv1.0") or protocols.get("TLSv1.1") or report.get("compression"):
        return "C"
    if not protocols.get("TLSv1.3") or report["no_pfs_ciphers"] or (dh_bits is not None and dh_bits < 2048):
        return "B"
    return "A"


def scan_sync(address: str, port: int, sni: str | None, budget: float = 90.0) -> dict:
    """Analyse complète d'un serveur TLS. Bloquant : à lancer dans un thread.

    `address` : adresse IP validée. Renvoie le résultat du module (measured/error
    compris). Aucun protocole accepté : measured=False et `failure` (refused, timeout, no_tls).
    """
    deadline = time.monotonic() + budget
    with ThreadPoolExecutor(max_workers=len(VERSIONS)) as pool:
        first = list(
            pool.map(lambda v: _probe(address, port, sni, v, hello.suites_for(v)), VERSIONS),
        )
        statuses = {v: _status(flight, v) for v, flight in zip(VERSIONS, first, strict=True)}
        supported = [v for v in VERSIONS if statuses[v]]
        if not supported:
            outcomes = {flight.outcome for flight in first}
            failure = (
                "refused" if outcomes == {"refused"} else "timeout" if "timeout" in outcomes else "no_tls"
            )
            return {"measured": False, "error": None, "failure": failure}

        # Énumération des suites : les versions en parallèle, un tour de sondes par version.
        def enumerate_one(version: int) -> list[int]:
            return _enumerate_version(address, port, sni, version, deadline)

        enumerated = dict(zip(supported, pool.map(enumerate_one, supported), strict=True))

        legacy = [v for v in supported if v != hello.TLS13]
        best_legacy = max(legacy) if legacy else None
        compression = server_preference = dh_bits = None
        if best_legacy is not None and time.monotonic() < deadline:
            suites = hello.suites_for(best_legacy)
            flight = _probe(address, port, sni, best_legacy, suites, compression=(1, 0))
            if _accepts(flight, best_legacy):
                compression = flight.compression == 1
            forward = enumerated[best_legacy][:1]
            if len(enumerated[best_legacy]) > 1 and forward:
                reverse = _probe(address, port, sni, best_legacy, suites[::-1])
                if _accepts(reverse, best_legacy):
                    server_preference = reverse.suite == forward[0]
            dhe = [
                c for c in enumerated[best_legacy] if hello.classify_suite(hello.suite_name(c))["kx"] == "DHE"
            ]
            if dhe and time.monotonic() < deadline:
                flight = _probe(address, port, sni, best_legacy, dhe, read_flight=True)
                if _accepts(flight, best_legacy):
                    dh_bits = flight.dh_bits

    suites_out: list[dict] = []
    weak: list[str] = []
    broken: list[str] = []
    no_pfs: list[str] = []
    for version in supported:
        for code in enumerated[version]:
            name = hello.suite_name(code)
            info = hello.classify_suite(name)
            if info["strength"] == "weak" and name not in weak:
                weak.append(name)
            elif info["strength"] == "broken" and name not in broken:
                broken.append(name)
            if not info["pfs"] and name not in no_pfs:
                no_pfs.append(name)
            suites_out.append(
                {
                    "protocol": hello.VERSION_NAMES[version],
                    "name": name,
                    "strength": info["strength"],
                    "pfs": info["pfs"],
                }
            )
    report = {
        "measured": True,
        "error": None,
        "port": port,
        "protocols": {
            hello.VERSION_NAMES[v]: statuses[v] if statuses[v] is not None else None for v in VERSIONS
        },
        "suite_count": len(suites_out),
        "suites": suites_out[:MAX_LISTED_SUITES],
        "weak_ciphers": weak,
        "broken_ciphers": broken,
        "no_pfs_ciphers": no_pfs,
        "compression": compression,
        "server_preference": server_preference,
        "dh_bits": dh_bits,
    }
    report["grade"] = _grade(report)
    return report
