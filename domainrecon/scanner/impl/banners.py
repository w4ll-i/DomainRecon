# =============================================================================
# DomainRecon - Bannières de services : sondes propres à chaque protocole
# =============================================================================
# 15 ports, sondes EHLO / HEAD / INFO / isMaster, avec ces précautions :
#   - plus de requête HTTP en clair sur les ports TLS (443, 8443…) : poignée de
#     main TLS (certificat non vérifié, c'est une sonde) puis requête HTTPS ;
#   - ports de messagerie chiffrés (465, 993, 995) lus après la poignée de main ;
#   - un en-tête Host valide (le domaine de la cible) au lieu de « target » ;
#   - Redis : PING (réponse +PONG sans authentification, -NOAUTH sinon), puis
#     INFO server pour la version, seulement si l'accès est ouvert ;
#   - Memcached : « version » ; Elasticsearch, CouchDB, Consul, Docker : GET d'une
#     page d'information ; MySQL : paquet d'accueil analysé ; PostgreSQL : demande
#     SSL ; MongoDB : isMaster binaire (la réponse est possible sans authentification
#     par conception : elle ne prouve pas un accès ouvert) ;
#   - produit et version extraits quand l'annonce les contient ;
#   - un accès sans authentification est détecté (`exposure`) quand la réponse en est la preuve ;
#   - connexions parallèles bornées, délais courts, lecture bornée à 4 Ko, textes assainis.
# Les adresses visées sont validées par la politique de cibles (ensure_ip_allowed).
# =============================================================================

import asyncio
import json
import re
import ssl
import struct

from ..targets import ensure_ip_allowed, is_ip_literal
from . import network_http as nh

CONNECT_TIMEOUT = 4.0
READ_TIMEOUT = 3.0
# Silence après lequel une réponse est jugée complète.
IDLE_TIMEOUT = 0.6
MAX_READ = 4096
CONCURRENCY = 6
MAX_BANNER = 300

# Ports en TLS implicite, avec le protocole parlé une fois la session établie.
TLS_PORTS = {443: "http", 8443: "http", 4848: "http", 5986: "http", 465: "greeting", 993: "greeting",
             995: "greeting", 6380: "redis"}  # fmt: skip
# Ports à protocole texte lisible dès la connexion.
GREETING_PORTS = {21: "FTP", 22: "SSH", 23: "Telnet", 110: "POP3", 143: "IMAP", 5900: "VNC"}
SMTP_PORTS = {25: "SMTP", 587: "SMTP"}
HTTP_PORTS = {
    80: "HTTP", 3000: "HTTP", 3001: "HTTP", 5000: "HTTP", 5001: "HTTP", 5985: "WinRM", 7001: "HTTP",
    7002: "HTTP", 8000: "HTTP", 8001: "HTTP", 8080: "HTTP", 8081: "HTTP", 8888: "HTTP", 50000: "HTTP",
}  # fmt: skip
# Protocoles dédiés : port -> (nom du service, sonde).
SPECIFIC_PORTS = {
    3306: ("MySQL", "mysql"),
    5432: ("PostgreSQL", "postgres"),
    6379: ("Redis", "redis"),
    11211: ("Memcached", "memcached"),
    9200: ("Elasticsearch", "elasticsearch"),
    5984: ("CouchDB", "couchdb"),
    8500: ("Consul", "consul"),
    2375: ("Docker API", "docker"),
    27017: ("MongoDB", "mongodb"),
    27018: ("MongoDB", "mongodb"),
}
TLS_SERVICE_NAMES = {443: "HTTPS", 8443: "HTTPS", 4848: "HTTPS", 5986: "WinRM", 465: "SMTPS", 993: "IMAPS",
                     995: "POP3S", 6380: "Redis TLS"}  # fmt: skip

# Niveaux de gravité d'un accès sans authentification, par service.
EXPOSURE_RISK = {"Redis": "critical", "Memcached": "critical", "Docker API": "critical",
                 "Elasticsearch": "high", "Consul": "high", "CouchDB": "medium"}  # fmt: skip


def probed_ports() -> list[int]:
    """Ports pour lesquels une sonde existe."""
    return sorted({*TLS_PORTS, *GREETING_PORTS, *SMTP_PORTS, *HTTP_PORTS, *SPECIFIC_PORTS})


# =============================================================================
# Connexion et lecture
# =============================================================================


def _tls_context() -> ssl.SSLContext:
    """Contexte TLS d'une sonde : certificat non vérifié (on lit, on ne se fie à rien), TLS 1.0+ accepté."""
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    # Une sonde doit pouvoir lire aussi les serveurs anciens (c'est justement ce qu'on cherche à voir).
    context.minimum_version = ssl.TLSVersion.MINIMUM_SUPPORTED
    try:
        context.set_ciphers("DEFAULT:@SECLEVEL=0")
    except ssl.SSLError:  # pragma: no cover - dépend d'OpenSSL
        pass
    return context


# Point d'injection des tests (aucune vraie connexion).
_open_connection = asyncio.open_connection


async def _open(ip: str, port: int, tls_name: str | None, use_tls: bool):
    kwargs = {"ssl": _tls_context(), "server_hostname": tls_name or None} if use_tls else {}
    return await asyncio.wait_for(_open_connection(ip, port, **kwargs), timeout=CONNECT_TIMEOUT)


async def _read(reader: asyncio.StreamReader, wait: float = READ_TIMEOUT) -> bytes:
    """Lit la réponse : première donnée sous `wait` s, puis jusqu'à un silence de IDLE_TIMEOUT ou MAX_READ octets."""
    data = b""
    timeout = wait
    while len(data) < MAX_READ:
        try:
            chunk = await asyncio.wait_for(reader.read(MAX_READ - len(data)), timeout=timeout)
        except (asyncio.TimeoutError, TimeoutError):
            break
        except (ConnectionError, ssl.SSLError, OSError):
            break
        if not chunk:
            break
        data += chunk
        timeout = IDLE_TIMEOUT
    return data


async def _send(writer: asyncio.StreamWriter, data: bytes) -> None:
    writer.write(data)
    await asyncio.wait_for(writer.drain(), timeout=CONNECT_TIMEOUT)


async def _close(writer: asyncio.StreamWriter) -> None:
    writer.close()
    try:
        await asyncio.wait_for(writer.wait_closed(), timeout=2)
    except (asyncio.TimeoutError, TimeoutError, ConnectionError, ssl.SSLError, OSError):
        pass


def printable(data: bytes, limit: int = MAX_BANNER) -> str:
    """Texte lisible d'une réponse binaire : octets non imprimables retirés, bornée."""
    text = (
        data.decode("utf-8", errors="replace").replace("\r\n", " | ").replace("\n", " | ").replace("\r", " ")
    )
    # Octets IAC de Telnet (0xFF…) et caractères de remplacement : sans intérêt.
    text = text.replace("�", "")
    return nh.clean_text(text, limit).strip(" |")


# =============================================================================
# Analyse des réponses
# =============================================================================

_SOFTWARE_RE = re.compile(
    r"(?i)\b(OpenSSH|dropbear|vsFTPd|ProFTPD|Pure-FTPd|FileZilla|Postfix|Exim|Sendmail|Dovecot|Courier|"
    r"nginx|Apache|lighttpd|Microsoft-IIS|IIS|Jetty|Tomcat|Caddy|MariaDB|MySQL|PostgreSQL|Redis|memcached)"
    r"(?:[ /_-]+v?(\d+(?:\.\d+)+[0-9A-Za-z.+~_-]*))?"
)
_SSH_RE = re.compile(r"^SSH-\d\.\d+-([A-Za-z0-9._-]+?)[_ -]v?(\d[\w.+~-]*)?(?:\s|$)")


def software_of(text: str) -> tuple[str | None, str | None]:
    """(produit, version) reconnus dans une annonce, sinon (None, None)."""
    ssh = _SSH_RE.match(text)
    if ssh:
        return ssh.group(1), ssh.group(2)
    match = _SOFTWARE_RE.search(text)
    if match:
        return match.group(1), match.group(2)
    return None, None


def parse_http(data: bytes) -> dict:
    """Ligne d'état et en-têtes utiles d'une réponse HTTP ; {} si ce n'en est pas une."""
    head = data.split(b"\r\n\r\n", 1)[0].decode("latin-1", errors="replace")
    lines = head.split("\r\n") if "\r\n" in head else head.split("\n")
    if not lines or not lines[0].startswith("HTTP/"):
        return {}
    headers = {}
    for line in lines[1:]:
        name, sep, value = line.partition(":")
        if sep:
            headers.setdefault(name.strip().lower(), value.strip())
    return {"status_line": lines[0].strip(), "headers": headers}


def parse_mysql(data: bytes) -> tuple[str | None, str | None]:
    """(produit, version) du paquet d'accueil MySQL / MariaDB (octet 4 = 10, puis version terminée par 0)."""
    if len(data) < 7 or data[4] != 10:
        if data[5:6] == b"\xff" or data[4:5] == b"\xff":
            return "MySQL", None
        return None, None
    end = data.find(b"\x00", 5)
    version = data[5:end].decode("ascii", errors="ignore") if end > 5 else ""
    if not version:
        return "MySQL", None
    product = "MariaDB" if "mariadb" in version.lower() else "MySQL"
    return product, version.removeprefix("5.5.5-")


def parse_mongo_wire_version(data: bytes) -> int | None:
    """maxWireVersion d'une réponse isMaster (BSON : octet de type 0x10, nom, 0, entier 32 bits)."""
    marker = b"\x10maxWireVersion\x00"
    index = data.find(marker)
    if index < 0 or len(data) < index + len(marker) + 4:
        return None
    return struct.unpack_from("<i", data, index + len(marker))[0]


_MONGO_ISMASTER = (
    b"\x3a\x00\x00\x00\xd4\x07\x00\x00\x00\x00\x00\x00\xd4\x07\x00\x00"
    b"\x00\x00\x00\x00\x61\x64\x6d\x69\x6e\x2e\x24\x63\x6d\x64\x00\x00"
    b"\x00\x00\x00\xff\xff\xff\xff\x13\x00\x00\x00\x10\x69\x73\x6d\x61"
    b"\x73\x74\x65\x72\x00\x01\x00\x00\x00\x00"
)
_POSTGRES_SSL_REQUEST = struct.pack("!II", 8, 80877103)


def _http_request(host: str, path: str = "/", method: str = "HEAD") -> bytes:
    return (
        f"{method} {path} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: DomainRecon\r\n"
        "Accept: */*\r\nConnection: close\r\n\r\n"
    ).encode("ascii", errors="ignore")


def _json_body(data: bytes) -> dict | None:
    """Corps JSON (objet) d'une réponse HTTP, ou None."""
    body = data.split(b"\r\n\r\n", 1)[1] if b"\r\n\r\n" in data else data
    try:
        value = json.loads(body.decode("utf-8", errors="replace"))
    except ValueError:
        return None
    return value if isinstance(value, dict) else None


# =============================================================================
# Sondes : chacune rend un dict de champs (banner, product, version, exposure…)
# =============================================================================


async def _probe_greeting(reader, writer, host: str) -> dict:
    banner = printable(await _read(reader))
    product, version = software_of(banner)
    return {"banner": banner, "product": product, "version": version}


async def _probe_smtp(reader, writer, host: str) -> dict:
    greeting = printable(await _read(reader))
    banner = greeting
    if greeting.startswith("220"):
        await _send(writer, b"EHLO domainrecon.invalid\r\n")
        extensions = printable(await _read(reader, wait=2.0), 200)
        if extensions:
            banner = f"{greeting} | {extensions}"[:MAX_BANNER]
        try:
            await _send(writer, b"QUIT\r\n")
        except (ConnectionError, OSError, asyncio.TimeoutError):
            pass
    product, version = software_of(greeting)
    return {
        "banner": banner,
        "product": product,
        "version": version,
        "starttls": "STARTTLS" in banner.upper(),
    }


async def _probe_http(reader, writer, host: str) -> dict:
    await _send(writer, _http_request(host))
    data = await _read(reader)
    parsed = parse_http(data)
    if not parsed:
        return {"banner": printable(data), "http": False}
    headers = parsed["headers"]
    server, powered = headers.get("server", ""), headers.get("x-powered-by", "")
    banner = parsed["status_line"]
    if server:
        banner += f" | Server: {server}"
    if powered:
        banner += f" | X-Powered-By: {powered}"
    product, version = software_of(f"{server} {powered}")
    return {"banner": nh.clean_text(banner, MAX_BANNER), "product": product, "version": version, "http": True}


async def _probe_mysql(reader, writer, host: str) -> dict:
    data = await _read(reader)
    product, version = parse_mysql(data)
    return {"banner": "", "product": product, "version": version}


async def _probe_postgres(reader, writer, host: str) -> dict:
    await _send(writer, _POSTGRES_SSL_REQUEST)
    data = await _read(reader, wait=2.0)
    # 'S' : TLS accepté ; 'N' : refusé ; 'E' : erreur (version du protocole non prise en charge).
    if data[:1] in (b"S", b"N", b"E"):
        return {"banner": "", "product": "PostgreSQL", "version": None, "ssl_supported": data[:1] == b"S"}
    return {"banner": printable(data), "product": None, "version": None}


async def _probe_redis(reader, writer, host: str) -> dict:
    await _send(writer, b"PING\r\n")
    reply = printable(await _read(reader, wait=2.0), 120)
    if reply.startswith("+PONG"):
        # Accès ouvert : la version est lisible (INFO server), sans autre donnée.
        await _send(writer, b"INFO server\r\n")
        info = (await _read(reader, wait=2.0)).decode("utf-8", errors="replace")
        match = re.search(r"redis_version:([\w.+-]+)", info)
        return {
            "banner": "+PONG",
            "product": "Redis",
            "version": match.group(1) if match else None,
            "exposure": "unauthenticated",
        }
    if reply.startswith("-NOAUTH") or reply.startswith("-ERR") or reply.startswith("-DENIED"):
        return {"banner": reply, "product": "Redis", "version": None, "exposure": None}
    return {"banner": reply, "product": None, "version": None}


async def _probe_memcached(reader, writer, host: str) -> dict:
    await _send(writer, b"version\r\n")
    reply = printable(await _read(reader, wait=2.0), 120)
    match = re.match(r"VERSION\s+([\w.+-]+)", reply)
    if match:
        return {
            "banner": reply,
            "product": "memcached",
            "version": match.group(1),
            "exposure": "unauthenticated",
        }
    return {"banner": reply, "product": None, "version": None}


async def _probe_elasticsearch(reader, writer, host: str) -> dict:
    await _send(writer, _http_request(host, "/", "GET"))
    data = await _read(reader)
    body = _json_body(data)
    if body and ("cluster_name" in body or body.get("tagline")):
        version = body.get("version") if isinstance(body.get("version"), dict) else {}
        number = version.get("number") if isinstance(version.get("number"), str) else None
        return {
            "banner": nh.clean_text(f"cluster {body.get('cluster_name', '?')}", 120),
            "product": "Elasticsearch",
            "version": number,
            "exposure": "unauthenticated",
        }
    parsed = parse_http(data)
    return {
        "banner": printable(parsed.get("status_line", "").encode() or data),
        "product": None,
        "version": None,
    }


async def _probe_couchdb(reader, writer, host: str) -> dict:
    await _send(writer, _http_request(host, "/", "GET"))
    data = await _read(reader)
    body = _json_body(data)
    if body and "couchdb" in body:
        version = body.get("version") if isinstance(body.get("version"), str) else None
        return {"banner": "CouchDB", "product": "CouchDB", "version": version, "exposure": "unauthenticated"}
    return {"banner": printable(data, 120), "product": None, "version": None}


async def _probe_consul(reader, writer, host: str) -> dict:
    await _send(writer, _http_request(host, "/v1/status/leader", "GET"))
    data = await _read(reader)
    parsed = parse_http(data)
    body = (
        data.split(b"\r\n\r\n", 1)[1].decode("utf-8", errors="replace").strip() if b"\r\n\r\n" in data else ""
    )
    # Réponse authentique de Consul : une chaîne JSON « "10.0.0.1:8300" » (adresse du leader).
    if parsed and parsed["status_line"].split(" ")[1:2] == ["200"] and re.fullmatch(r'"[\w.:\[\]-]*"', body):
        return {"banner": "Consul", "product": "Consul", "version": None, "exposure": "unauthenticated"}
    return {
        "banner": printable(parsed.get("status_line", "").encode() or data, 120),
        "product": None,
        "version": None,
    }


async def _probe_docker(reader, writer, host: str) -> dict:
    await _send(writer, _http_request(host, "/version", "GET"))
    data = await _read(reader)
    body = _json_body(data)
    if body and "ApiVersion" in body:
        version = body.get("Version") if isinstance(body.get("Version"), str) else None
        return {
            "banner": "Docker Engine API",
            "product": "Docker",
            "version": version,
            "exposure": "unauthenticated",
        }
    return {"banner": printable(data, 120), "product": None, "version": None}


async def _probe_mongodb(reader, writer, host: str) -> dict:
    await _send(writer, _MONGO_ISMASTER)
    data = await _read(reader, wait=2.0)
    if b"ismaster" in data.lower() or b"maxWireVersion" in data:
        return {
            "banner": "",
            "product": "MongoDB",
            "version": None,
            "wire_version": parse_mongo_wire_version(data),
        }
    return {"banner": printable(data, 120), "product": None, "version": None}


_PROBES = {
    "greeting": _probe_greeting,
    "smtp": _probe_smtp,
    "http": _probe_http,
    "mysql": _probe_mysql,
    "postgres": _probe_postgres,
    "redis": _probe_redis,
    "memcached": _probe_memcached,
    "elasticsearch": _probe_elasticsearch,
    "couchdb": _probe_couchdb,
    "consul": _probe_consul,
    "docker": _probe_docker,
    "mongodb": _probe_mongodb,
}


def plan_for(port: int) -> tuple[str, str, bool] | None:
    """(service, sonde, TLS d'abord) d'un port, ou None s'il n'a pas de sonde."""
    if port in TLS_PORTS:
        return TLS_SERVICE_NAMES.get(port, "HTTPS"), TLS_PORTS[port], True
    if port in SPECIFIC_PORTS:
        service, probe = SPECIFIC_PORTS[port]
        return service, probe, False
    if port in SMTP_PORTS:
        return SMTP_PORTS[port], "smtp", False
    if port in GREETING_PORTS:
        return GREETING_PORTS[port], "greeting", False
    if port in HTTP_PORTS:
        return HTTP_PORTS[port], "http", False
    return None


async def _attempt(ip: str, port: int, probe: str, tls_name: str | None, host: str, use_tls: bool) -> dict:
    reader, writer = await _open(ip, port, tls_name, use_tls)
    try:
        fields = await _PROBES[probe](reader, writer, host)
        if use_tls:
            ssl_object = writer.get_extra_info("ssl_object")
            if ssl_object is not None:
                cipher = ssl_object.cipher()
                fields["tls"] = {
                    "version": ssl_object.version(),
                    "cipher": cipher[0] if cipher else None,
                }
        return fields
    finally:
        await _close(writer)


async def grab(ip: str, port: int, host: str) -> dict | None:
    """Bannière d'un port, ou None s'il n'a pas de sonde ou ne répond pas.

    Un port HTTP en clair qui ne répond pas en HTTP est réessayé en TLS, et un port TLS qui refuse
    la poignée de main l'est en clair (ports de redirection, services d'administration).
    `host` : nom de la cible, en-tête Host (et SNI s'il s'agit d'un nom).
    """
    plan = plan_for(port)
    if plan is None:
        return None
    service, probe, tls_first = plan
    tls_name = None if is_ip_literal(host) else host
    attempts = [tls_first, not tls_first] if probe == "http" else [tls_first]
    fields: dict | None = None
    for use_tls in attempts:
        try:
            result = await _attempt(ip, port, probe, tls_name, host, use_tls)
        except (OSError, asyncio.TimeoutError, TimeoutError, ssl.SSLError):
            continue
        # La première réponse sert de repli ; une vraie réponse HTTP met fin aux essais.
        fields = fields or result
        if probe != "http" or result.get("http"):
            fields = result
            break
    if fields is None:
        return {"port": port, "service": service, "probe": probe, "reachable": False}
    exposure = fields.get("exposure")
    entry = {
        "port": port,
        "service": service,
        "probe": probe,
        "reachable": True,
        "banner": fields.get("banner", ""),
        "product": fields.get("product"),
        "version": fields.get("version"),
        "exposure": exposure,
        "risk": EXPOSURE_RISK.get(service) if exposure else None,
    }
    for extra in ("tls", "starttls", "ssl_supported", "wire_version"):
        if extra in fields:
            entry[extra] = fields[extra]
    return entry


async def grab_all(ip: str, ports: list[int], host: str) -> list[dict]:
    """Bannières des ports donnés (ceux qui ont une sonde), en parallèle borné ; ordre des ports conservé.

    Lève ValueError / TargetNotAllowedError si l'IP n'est pas autorisée par la politique de cibles.
    """
    ip = ensure_ip_allowed(ip)
    semaphore = asyncio.Semaphore(CONCURRENCY)

    async def one(port: int) -> dict | None:
        async with semaphore:
            return await grab(ip, port, host)

    wanted = sorted({p for p in ports if plan_for(p) is not None})
    results = await asyncio.gather(*(one(p) for p in wanted))
    return [r for r in results if r is not None]
