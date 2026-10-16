# =============================================================================
# DomainRecon - Scanner : réseau (ports, géolocalisation, réseau étendu)
# =============================================================================
# Ces modules travaillent sur une IP déjà résolue. Le scan de ports n'accepte
# qu'une IP validée par la politique de cibles ; les services tiers (ipinfo.io,
# HackerTarget) ne sont interrogés que pour une adresse publique, en HTTPS
# avec vérification TLS. La géolocalisation et le réseau étendu partagent une
# même requête ipinfo.io par IP.
# =============================================================================

import asyncio

from ..i18n import msg
from .cache import LONG_TTL, MEDIUM_TTL, cached
from .common import _api_client, logger, proxy_scope
from .errors import ModuleError, exception_text
from .targets import ensure_ip_allowed, is_ip_literal, is_public_address, is_valid_target

# Ports sondés. Ils couvrent tous les services sensibles que le score pénalise
# (score.SENSITIVE_PORTS) : un service jamais sondé ne serait jamais pénalisé.
COMMON_PORTS = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    135: "MS-RPC",
    139: "NetBIOS",
    143: "IMAP",
    443: "HTTPS",
    445: "SMB",
    587: "SMTP/TLS",
    993: "IMAPS",
    995: "POP3S",
    1433: "SQL Server",
    1521: "Oracle",
    2049: "NFS",
    2375: "Docker API",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    5900: "VNC",
    5984: "CouchDB",
    5985: "WinRM",
    5986: "WinRM-HTTPS",
    6379: "Redis",
    8080: "HTTP-Proxy",
    8443: "HTTPS-Alt",
    8888: "HTTP-Alt",
    9200: "Elasticsearch",
    11211: "Memcached",
    27017: "MongoDB",
}

# Scan de ports : délai par port et nombre de sondes simultanées.
PORT_TIMEOUT = 3.0
PORT_SCAN_CONCURRENCY = 8
# Retard au-delà duquel l'expiration d'une sonde révèle une boucle d'événements
# bloquée (quelques millisecondes d'ordinaire) : la sonde n'est pas concluante.
PORT_STALL_TOLERANCE = 0.1

# États d'une sonde : ouvert, refusé (le port répond RST), sans réponse dans
# le délai, sans réponse faute de boucle disponible, erreur réseau.
_OPEN, _REFUSED, _FILTERED, _STALLED, _NETWORK_ERROR = "open", "refused", "filtered", "stalled", "error"

# Services tiers (HTTPS uniquement). ipinfo.io fournit à la fois la
# géolocalisation et l'ASN : un seul fournisseur de moins voit passer les IP.
IPINFO_URL = "https://ipinfo.io/{ip}/json"
HACKERTARGET_URL = "https://api.hackertarget.com/reverseiplookup/?q={ip}"
IPINFO_TIMEOUT = 8.0

# Réponses des services tiers, gardées par cache.cached : la géolocalisation et le
# réseau étendu d'un scan interrogent la même IP au même moment, et ces services,
# utilisés sans jeton, limitent le débit. Une seule requête part par IP (et par
# proxy : common.proxy_scope) ; sa réponse sert encore aux scans lancés ensuite.
# Les échecs ne sont pas conservés. ipinfo.io (propriétaire d'une IP, position)
# change rarement : IPINFO_CACHE_TTL = 24 h. Les voisins reverse-IP de HackerTarget,
# déduits du DNS passif, sont gardés REVERSE_IP_CACHE_TTL = 1 h.
IPINFO_CACHE_TTL = LONG_TTL
IPINFO_CACHE_MAX_ENTRIES = 256
REVERSE_IP_CACHE_TTL = MEDIUM_TTL
REVERSE_IP_CACHE_MAX_ENTRIES = 256
# IP -> (instant de la requête, tâche), liée à la boucle d'événements qui l'a créée.
_ipinfo_cache: dict[str, tuple[float, asyncio.Task]] = {}

# Nombre maximal de voisins reverse-IP conservés.
REVERSE_IP_MAX_NEIGHBORS = 50

# Réponses texte connues de HackerTarget (renvoyées avec un code 200).
_HACKERTARGET_QUOTA_MARKERS = ("api count exceeded", "increase quota")
_HACKERTARGET_EMPTY_MARKERS = ("no dns a records", "no records found")


# =============================================================================
# Module 5 : Port Scanner
# =============================================================================


async def _check_port(ip: str, port: int, timeout: float = PORT_TIMEOUT) -> tuple[str, str | None]:
    """Test de connexion à un port : (état, message d'erreur réseau ou None).

    Une expiration traitée en retard signale une boucle d'événements bloquée
    au-delà de l'échéance : une connexion établie entre-temps n'a pas pu être
    traitée à temps. La sonde est alors « stalled » (non concluante) et non
    « filtered ».
    """
    loop = asyncio.get_running_loop()
    started = loop.time()
    writer = None
    try:
        _, writer = await asyncio.wait_for(asyncio.open_connection(ip, port), timeout=timeout)
        return _OPEN, None
    # asyncio.TimeoutError n'est fusionné avec TimeoutError qu'à partir de
    # Python 3.11 : les deux sont nécessaires pour rester compatible 3.10.
    except (asyncio.TimeoutError, TimeoutError):
        late = loop.time() - started - timeout
        return (_STALLED if late > PORT_STALL_TOLERANCE else _FILTERED), None
    except ConnectionRefusedError:
        return _REFUSED, None  # fermé : c'est une réponse de l'hôte
    except OSError as e:
        return _NETWORK_ERROR, str(e) or type(e).__name__
    finally:
        if writer is not None:
            writer.close()
            try:
                await writer.wait_closed()
            except OSError:
                pass


async def scan_ports(ip: str) -> list:
    """Scan les ports communs d'une IP validée par la politique de cibles.

    Les connexions sont limitées par un sémaphore. Si la boucle d'événements a
    été bloquée pendant les sondes (autre travail synchrone du scan), le délai
    de certaines a pu expirer avant que leur connexion ne soit traitée : les
    ports restés sans réponse sont alors sondés une seconde fois, pour ne pas
    signaler filtré un port ouvert.

    Lève `ValueError` si `ip` n'est pas une IP littérale, `TargetNotAllowedError`
    si elle n'est pas publique (sans ALLOW_PRIVATE_TARGETS), et `ModuleError`
    si aucun port n'a répondu (ni ouvert ni refusé) : « aucun port ouvert »
    serait alors une conclusion sans mesure.
    """
    if not ip:
        return []
    # Jamais de nom d'hôte ici : open_connection le résoudrait sans contrôle.
    ip = ensure_ip_allowed(ip)

    semaphore = asyncio.Semaphore(PORT_SCAN_CONCURRENCY)
    # Lu à l'appel (et non en valeur par défaut) : réglable sans redéfinir _check_port.
    timeout = PORT_TIMEOUT

    async def probe(port: int) -> tuple[str, str | None]:
        async with semaphore:
            return await _check_port(ip, port, timeout)

    async def probe_all(ports: list[int]) -> dict[int, tuple[str, str | None]]:
        return dict(zip(ports, await asyncio.gather(*(probe(port) for port in ports)), strict=True))

    states = await probe_all(list(COMMON_PORTS))
    if any(state == _STALLED for state, _ in states.values()):
        silent = [port for port, (state, _) in states.items() if state in (_FILTERED, _STALLED)]
        logger.warning(
            "Scan de ports %s : boucle d'événements bloquée pendant les sondes, %s port(s) sondé(s) de nouveau",
            ip,
            len(silent),
        )
        states.update(await probe_all(silent))

    if states and not any(state in (_OPEN, _REFUSED) for state, _ in states.values()):
        errors = [error for state, error in states.values() if state == _NETWORK_ERROR]
        if len(errors) == len(states):
            raise ModuleError(msg("network.ports_failed", error=errors[0]))
        raise ModuleError(msg("network.ports_filtered", count=len(states)))

    open_ports = [
        {"port": port, "state": "open", "service": COMMON_PORTS.get(port, "unknown")}
        for port, (state, _) in states.items()
        if state == _OPEN
    ]
    logger.debug("Scan de ports %s : %s ouverts", ip, len(open_ports))
    return open_ports


# =============================================================================
# Services tiers : garde commune
# =============================================================================


def _third_party_refusal(ip: str | None, what: object) -> tuple[object, bool] | None:
    """Raison de ne PAS interroger un service tiers pour `ip`, ou None.

    Renvoie (message, skipped) : `skipped` vaut True quand le module est
    simplement sans objet (pas d'IP, adresse non publique), False quand
    l'entrée est invalide. `what` : nom (message) de la mesure concernée.
    """
    if not ip:
        return msg("network.no_ip", what=what), True
    if not is_ip_literal(ip):
        return msg("network.invalid_ip", what=what), False
    if not is_public_address(ip):
        # Réseau local (ALLOW_PRIVATE_TARGETS=1) : rien à apprendre d'un service
        # public, et l'adresse interne n'a pas à sortir vers un tiers.
        return msg("network.not_public", what=what), True
    return None


def _describe(e: Exception, context: object) -> object:
    """Message d'erreur lisible (les exceptions httpx ont souvent un texte vide)."""
    if isinstance(e, ModuleError):
        return e.message
    return msg("network.service_error", context=context, detail=exception_text(e) or type(e).__name__)


def _http_error_message(service: str, status_code: int) -> dict:
    if status_code == 429:
        return msg("network.quota", service=service)
    return msg("network.http_status", status=status_code, service=service)


@cached(IPINFO_CACHE_TTL, max_entries=IPINFO_CACHE_MAX_ENTRIES, scope=proxy_scope)
async def _ipinfo_lookup(ip: str) -> dict:
    """Réponse ipinfo.io pour `ip` ; lève ModuleError si elle est inexploitable.

    Mise en cache (IPINFO_CACHE_TTL) : une requête en cours ou récente pour la
    même IP est réutilisée, et chaque appelant en reçoit sa propre copie.
    """
    async with _api_client(timeout=IPINFO_TIMEOUT) as client:
        resp = await client.get(IPINFO_URL.format(ip=ip))
    if resp.status_code != 200:
        raise ModuleError(_http_error_message("ipinfo.io", resp.status_code))
    try:
        data = resp.json()
    except ValueError as e:
        raise ModuleError(msg("network.ipinfo_unreadable")) from e
    if not isinstance(data, dict) or "error" in data:
        raise ModuleError(msg("network.ipinfo_error"))
    return data


def _split_org(org: str) -> tuple[str | None, str]:
    """« AS15169 Google LLC » -> ("AS15169", "Google LLC")."""
    first, _, rest = org.partition(" ")
    if first.upper().startswith("AS") and first[2:].isdigit():
        return first.upper(), rest.strip()
    return None, org.strip()


def _parse_loc(loc: object) -> tuple[float | None, float | None]:
    """« 37.4056,-122.0775 » -> (37.4056, -122.0775)."""
    try:
        lat, lon = (float(part) for part in str(loc).split(","))
    except ValueError:
        return None, None
    return lat, lon


# =============================================================================
# Module 6 : Geolocation (ipinfo.io)
# =============================================================================


def _geo_result(ip: str | None) -> dict:
    return {
        "ip": ip,
        "country": "",
        "country_code": "",
        "region": "",
        "city": "",
        "zip": "",
        "lat": None,
        "lon": None,
        "timezone": "",
        "isp": "",
        "org": "",
        "as_info": "",
        "anycast": False,
        "measured": False,
        "error": None,
    }


async def get_geo_data(ip: str) -> dict:
    """Géolocalise une IP publique via ipinfo.io (HTTPS, TLS vérifié, sans clé).

    `country` contient le code pays ISO 3166 (ipinfo ne fournit pas le nom).
    `anycast` : IP anycast (CDN) partagée par de nombreux sites, dont la
    position est celle de l'enregistrement de l'IP, pas celle du serveur.
    Pour une adresse non publique, aucun service tiers n'est interrogé :
    `measured=False`, `skipped=True`.
    """
    result = _geo_result(ip)
    refusal = _third_party_refusal(ip, msg("network.what_geo"))
    if refusal is not None:
        result["error"], result["skipped"] = refusal
        return result

    try:
        data = await _ipinfo_lookup(ip)
    except Exception as e:
        logger.warning("Géolocalisation indisponible pour %s: %s", ip, e)
        result["error"] = _describe(e, msg("network.geo_unavailable"))
        return result

    org = str(data.get("org") or "")
    _, org_name = _split_org(org)
    lat, lon = _parse_loc(data.get("loc"))
    country_code = str(data.get("country") or "")
    result.update(
        {
            "country": country_code,
            "country_code": country_code,
            "region": str(data.get("region") or ""),
            "city": str(data.get("city") or ""),
            "zip": str(data.get("postal") or ""),
            "lat": lat,
            "lon": lon,
            "timezone": str(data.get("timezone") or ""),
            "isp": org_name,
            "org": org_name,
            "as_info": org,
            "anycast": bool(data.get("anycast", False)),
            "measured": True,
        }
    )
    return result


# =============================================================================
# Module 17 : Extended Network Scan (Reverse IP / ASN)
# =============================================================================


@cached(REVERSE_IP_CACHE_TTL, max_entries=REVERSE_IP_CACHE_MAX_ENTRIES, scope=proxy_scope)
async def _reverse_ip_hosts(ip: str) -> list[str]:
    """Noms d'hôte valides que HackerTarget rattache à `ip`, sans doublon ; lève ModuleError si inexploitable.

    Mise en cache par IP seulement (REVERSE_IP_CACHE_TTL) : le domaine scanné
    n'intervient qu'ensuite (`_reverse_ip_neighbors`), si bien que deux
    domaines d'une même IP partagent la réponse sans jamais se confondre.
    """
    async with _api_client(timeout=10.0) as client:
        resp = await client.get(HACKERTARGET_URL.format(ip=ip))
    if resp.status_code != 200:
        raise ModuleError(_http_error_message("HackerTarget", resp.status_code))

    text = resp.text.strip()
    lowered = text.lower()
    if any(marker in lowered for marker in _HACKERTARGET_QUOTA_MARKERS):
        raise ModuleError(msg("network.hackertarget_quota"))
    if not text or any(marker in lowered for marker in _HACKERTARGET_EMPTY_MARKERS):
        return []

    lines = [line.strip().lower().rstrip(".") for line in text.splitlines() if line.strip()]
    # Seuls les noms d'hôte valides sont gardés : un message d'erreur ou du
    # texte arbitraire ne doit jamais apparaître comme « voisin ».
    hosts = [line for line in dict.fromkeys(lines) if is_valid_target(line)]
    if lines and not hosts:
        raise ModuleError(msg("network.hackertarget_unexpected"))
    return hosts


async def _reverse_ip_neighbors(ip: str, domain: str) -> list[str]:
    """Voisins reverse-IP via HackerTarget (le domaine scanné excepté), tous ; lève ModuleError si inexploitable."""
    return [host for host in await _reverse_ip_hosts(ip) if host != domain]


async def extended_network_scan(ip: str, domain: str) -> dict:
    """Scan réseau étendu : informations ASN (ipinfo.io) et voisins reverse-IP (HackerTarget).

    `measured` vaut True si au moins une des deux sources a répondu ; l'échec
    de chacune est détaillé dans `asn_error` et `neighbors_error`. Seuls les
    REVERSE_IP_MAX_NEIGHBORS premiers voisins sont gardés : `neighbors_total`
    donne leur nombre réel et `neighbors_truncated` signale la coupe. Sur une
    IP anycast (`asn_info.anycast`, CDN), ces voisins partagent seulement
    l'infrastructure du fournisseur.
    """
    result = {
        "reverse_ip_neighbors": [],
        "neighbors_total": 0,
        "neighbors_truncated": False,
        "neighbors_error": None,
        "asn_info": {},
        "asn_error": None,
        "measured": False,
        "error": None,
    }
    refusal = _third_party_refusal(ip, msg("network.what_extended"))
    if refusal is not None:
        result["error"], result["skipped"] = refusal
        return result

    try:
        data = await _ipinfo_lookup(ip)
        asn, org_name = _split_org(str(data.get("org") or ""))
        hostname = str(data.get("hostname") or "").lower().rstrip(".")
        result["asn_info"] = {
            "asn": asn,
            "org": org_name or None,
            # Le PTR est choisi par le propriétaire de l'IP : gardé seulement s'il est valide.
            "hostname": hostname if is_valid_target(hostname) else None,
            "anycast": bool(data.get("anycast", False)),
        }
    except Exception as e:
        logger.warning("Informations ASN indisponibles pour %s: %s", ip, e)
        result["asn_error"] = _describe(e, msg("network.asn_unavailable"))

    try:
        neighbors = await _reverse_ip_neighbors(ip, domain)
        result.update(
            reverse_ip_neighbors=neighbors[:REVERSE_IP_MAX_NEIGHBORS],
            neighbors_total=len(neighbors),
            neighbors_truncated=len(neighbors) > REVERSE_IP_MAX_NEIGHBORS,
        )
    except Exception as e:
        logger.warning("Reverse IP indisponible pour %s: %s", ip, e)
        result["neighbors_error"] = _describe(e, msg("network.reverse_ip_unavailable"))

    result["measured"] = result["asn_error"] is None or result["neighbors_error"] is None
    if not result["measured"]:
        result["error"] = msg("common.join", items=[result["asn_error"], result["neighbors_error"]])
    return result
