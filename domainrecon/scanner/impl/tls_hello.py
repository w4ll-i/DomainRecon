# =============================================================================
# DomainRecon - Sonde TLS bas niveau : ClientHello forgé et lecture du vol serveur
# =============================================================================
# Pourquoi ne pas utiliser le module ssl de Python ? Il dépend de l'OpenSSL local :
# SSLv3, TLS 1.0 et 1.1 y sont souvent désactivés (on conclurait à tort « non pris
# en charge »), et il ne donne ni la liste des suites
# acceptées, ni l'agrafe OCSP, ni la taille des paramètres Diffie-Hellman.
# Ici, le ClientHello est écrit à la main et la réponse du serveur est lue sans
# jamais terminer la poignée de main : aucune donnée applicative n'est échangée.
#
# Spécifications : RFC 8446 (TLS 1.3), RFC 5246 (TLS 1.2), RFC 6066 (status_request),
# RFC 6101 (SSLv3). Registre des suites : IANA « TLS Cipher Suites ».
#
# Fonctions bloquantes (sockets) : à lancer dans asyncio.to_thread avec leurs bornes.
# Les adresses doivent avoir été validées par la politique de cibles (targets).
# =============================================================================

import os
import socket
import struct
import time
from dataclasses import dataclass, field

# Versions du protocole (valeurs de la couche enregistrement).
SSL3 = 0x0300
TLS10 = 0x0301
TLS11 = 0x0302
TLS12 = 0x0303
TLS13 = 0x0304

VERSION_NAMES = {SSL3: "SSLv3", TLS10: "TLSv1.0", TLS11: "TLSv1.1", TLS12: "TLSv1.2", TLS13: "TLSv1.3"}

# Types d'enregistrements et de messages de poignée de main.
_REC_ALERT = 21
_REC_HANDSHAKE = 22
_HS_SERVER_HELLO = 2
_HS_CERTIFICATE = 11
_HS_SERVER_KEY_EXCHANGE = 12
_HS_SERVER_HELLO_DONE = 14
_HS_CERTIFICATE_STATUS = 22

# Extensions.
_EXT_SNI = 0
_EXT_STATUS_REQUEST = 5
_EXT_GROUPS = 10
_EXT_EC_POINTS = 11
_EXT_SIG_ALGS = 13
_EXT_EXTENDED_MASTER = 23
_EXT_SUPPORTED_VERSIONS = 43
_EXT_KEY_SHARE = 51
_EXT_RENEGOTIATION = 0xFF01

# Plafond de données lues du serveur pour un vol complet (certificats compris).
MAX_FLIGHT_BYTES = 192 * 1024

# Suites TLS connues : code -> nom IANA. Les noms servent à classer les suites
# (voir `classify_suite`) ; une suite inconnue du serveur est nommée « 0x.... ».
CIPHER_SUITES: dict[int, str] = {
    0x0001: "TLS_RSA_WITH_NULL_MD5",
    0x0002: "TLS_RSA_WITH_NULL_SHA",
    0x0003: "TLS_RSA_EXPORT_WITH_RC4_40_MD5",
    0x0004: "TLS_RSA_WITH_RC4_128_MD5",
    0x0005: "TLS_RSA_WITH_RC4_128_SHA",
    0x0006: "TLS_RSA_EXPORT_WITH_RC2_CBC_40_MD5",
    0x0008: "TLS_RSA_EXPORT_WITH_DES40_CBC_SHA",
    0x0009: "TLS_RSA_WITH_DES_CBC_SHA",
    0x000A: "TLS_RSA_WITH_3DES_EDE_CBC_SHA",
    0x0011: "TLS_DHE_DSS_EXPORT_WITH_DES40_CBC_SHA",
    0x0012: "TLS_DHE_DSS_WITH_DES_CBC_SHA",
    0x0013: "TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA",
    0x0014: "TLS_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA",
    0x0015: "TLS_DHE_RSA_WITH_DES_CBC_SHA",
    0x0016: "TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA",
    0x0017: "TLS_DH_anon_EXPORT_WITH_RC4_40_MD5",
    0x0018: "TLS_DH_anon_WITH_RC4_128_MD5",
    0x0019: "TLS_DH_anon_EXPORT_WITH_DES40_CBC_SHA",
    0x001A: "TLS_DH_anon_WITH_DES_CBC_SHA",
    0x001B: "TLS_DH_anon_WITH_3DES_EDE_CBC_SHA",
    0x002F: "TLS_RSA_WITH_AES_128_CBC_SHA",
    0x0032: "TLS_DHE_DSS_WITH_AES_128_CBC_SHA",
    0x0033: "TLS_DHE_RSA_WITH_AES_128_CBC_SHA",
    0x0034: "TLS_DH_anon_WITH_AES_128_CBC_SHA",
    0x0035: "TLS_RSA_WITH_AES_256_CBC_SHA",
    0x0038: "TLS_DHE_DSS_WITH_AES_256_CBC_SHA",
    0x0039: "TLS_DHE_RSA_WITH_AES_256_CBC_SHA",
    0x003A: "TLS_DH_anon_WITH_AES_256_CBC_SHA",
    0x003B: "TLS_RSA_WITH_NULL_SHA256",
    0x003C: "TLS_RSA_WITH_AES_128_CBC_SHA256",
    0x003D: "TLS_RSA_WITH_AES_256_CBC_SHA256",
    0x0040: "TLS_DHE_DSS_WITH_AES_128_CBC_SHA256",
    0x0041: "TLS_RSA_WITH_CAMELLIA_128_CBC_SHA",
    0x0045: "TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA",
    0x0067: "TLS_DHE_RSA_WITH_AES_128_CBC_SHA256",
    0x006A: "TLS_DHE_DSS_WITH_AES_256_CBC_SHA256",
    0x006B: "TLS_DHE_RSA_WITH_AES_256_CBC_SHA256",
    0x006C: "TLS_DH_anon_WITH_AES_128_CBC_SHA256",
    0x006D: "TLS_DH_anon_WITH_AES_256_CBC_SHA256",
    0x0084: "TLS_RSA_WITH_CAMELLIA_256_CBC_SHA",
    0x0088: "TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA",
    0x0096: "TLS_RSA_WITH_SEED_CBC_SHA",
    0x009A: "TLS_DHE_RSA_WITH_SEED_CBC_SHA",
    0x009C: "TLS_RSA_WITH_AES_128_GCM_SHA256",
    0x009D: "TLS_RSA_WITH_AES_256_GCM_SHA384",
    0x009E: "TLS_DHE_RSA_WITH_AES_128_GCM_SHA256",
    0x009F: "TLS_DHE_RSA_WITH_AES_256_GCM_SHA384",
    0x00A2: "TLS_DHE_DSS_WITH_AES_128_GCM_SHA256",
    0x00A3: "TLS_DHE_DSS_WITH_AES_256_GCM_SHA384",
    0x00A6: "TLS_DH_anon_WITH_AES_128_GCM_SHA256",
    0x00A7: "TLS_DH_anon_WITH_AES_256_GCM_SHA384",
    0x00BA: "TLS_RSA_WITH_CAMELLIA_128_CBC_SHA256",
    0x00BE: "TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA256",
    0x00C0: "TLS_RSA_WITH_CAMELLIA_256_CBC_SHA256",
    0x00C4: "TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA256",
    0xC002: "TLS_ECDH_ECDSA_WITH_RC4_128_SHA",
    0xC003: "TLS_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA",
    0xC004: "TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA",
    0xC005: "TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA",
    0xC006: "TLS_ECDHE_ECDSA_WITH_NULL_SHA",
    0xC007: "TLS_ECDHE_ECDSA_WITH_RC4_128_SHA",
    0xC008: "TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA",
    0xC009: "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA",
    0xC00A: "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA",
    0xC00C: "TLS_ECDH_RSA_WITH_RC4_128_SHA",
    0xC00D: "TLS_ECDH_RSA_WITH_3DES_EDE_CBC_SHA",
    0xC00E: "TLS_ECDH_RSA_WITH_AES_128_CBC_SHA",
    0xC00F: "TLS_ECDH_RSA_WITH_AES_256_CBC_SHA",
    0xC010: "TLS_ECDHE_RSA_WITH_NULL_SHA",
    0xC011: "TLS_ECDHE_RSA_WITH_RC4_128_SHA",
    0xC012: "TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA",
    0xC013: "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA",
    0xC014: "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA",
    0xC015: "TLS_ECDH_anon_WITH_NULL_SHA",
    0xC016: "TLS_ECDH_anon_WITH_RC4_128_SHA",
    0xC017: "TLS_ECDH_anon_WITH_3DES_EDE_CBC_SHA",
    0xC018: "TLS_ECDH_anon_WITH_AES_128_CBC_SHA",
    0xC019: "TLS_ECDH_anon_WITH_AES_256_CBC_SHA",
    0xC023: "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256",
    0xC024: "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384",
    0xC025: "TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256",
    0xC026: "TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA384",
    0xC027: "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256",
    0xC028: "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384",
    0xC029: "TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256",
    0xC02A: "TLS_ECDH_RSA_WITH_AES_256_CBC_SHA384",
    0xC02B: "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
    0xC02C: "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
    0xC02D: "TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256",
    0xC02E: "TLS_ECDH_ECDSA_WITH_AES_256_GCM_SHA384",
    0xC02F: "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
    0xC030: "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
    0xC031: "TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256",
    0xC032: "TLS_ECDH_RSA_WITH_AES_256_GCM_SHA384",
    0xC09C: "TLS_RSA_WITH_AES_128_CCM",
    0xC09D: "TLS_RSA_WITH_AES_256_CCM",
    0xC09E: "TLS_DHE_RSA_WITH_AES_128_CCM",
    0xC09F: "TLS_DHE_RSA_WITH_AES_256_CCM",
    0xC0AC: "TLS_ECDHE_ECDSA_WITH_AES_128_CCM",
    0xC0AD: "TLS_ECDHE_ECDSA_WITH_AES_256_CCM",
    0xCCA8: "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
    0xCCA9: "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256",
    0xCCAA: "TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
}
# Suites propres à TLS 1.3 (RFC 8446 et RFC 8447).
TLS13_SUITES: dict[int, str] = {
    0x1301: "TLS_AES_128_GCM_SHA256",
    0x1302: "TLS_AES_256_GCM_SHA384",
    0x1303: "TLS_CHACHA20_POLY1305_SHA256",
    0x1304: "TLS_AES_128_CCM_SHA256",
    0x1305: "TLS_AES_128_CCM_8_SHA256",
}
CIPHER_SUITES.update(TLS13_SUITES)

# Suites proposées par un client moderne (sonde de l'agrafe OCSP et de la chaîne).
MODERN_TLS12_SUITES = [
    0xC02F, 0xC030, 0xC02B, 0xC02C, 0xCCA8, 0xCCA9, 0x009E, 0x009F, 0xC027, 0xC028,
    0xC013, 0xC014, 0xC023, 0xC024, 0xC009, 0xC00A, 0x009C, 0x009D, 0x002F, 0x0035,
]  # fmt: skip


def suite_name(code: int) -> str:
    return CIPHER_SUITES.get(code, f"0x{code:04X}")


def suites_for(version: int) -> list[int]:
    """Suites à proposer pour tester une version : celles de TLS 1.3, ou toutes les autres."""
    if version == TLS13:
        return list(TLS13_SUITES)
    return [code for code in CIPHER_SUITES if code not in TLS13_SUITES]


def classify_suite(name: str) -> dict:
    """Classe une suite : `strength` (broken | weak | ok), `pfs` (confidentialité persistante), `kx`.

    - broken : aucun chiffrement réel ou chiffrement d'exportation, échange anonyme (NULL, EXPORT, anon) ;
    - weak : algorithme cassé ou en fin de vie (RC4, RC2, DES, 3DES, IDEA, MD5) ;
    - ok : le reste (CBC avec AES n'est pas un défaut en soi : seule la suite est listée).
    """
    upper = name.upper()
    if name.startswith("TLS_AES") or name.startswith("TLS_CHACHA20"):
        return {"strength": "ok", "pfs": True, "kx": "TLS13"}
    parts = upper.split("_WITH_", 1)
    exchange = parts[0].removeprefix("TLS_")
    kx = "RSA"
    if exchange.startswith("ECDHE"):
        kx = "ECDHE"
    elif exchange.startswith("DHE"):
        kx = "DHE"
    elif exchange.startswith("ECDH_"):
        kx = "ECDH"
    elif exchange.startswith("DH_"):
        kx = "DH"
    pfs = kx in ("ECDHE", "DHE")
    cipher = parts[1] if len(parts) > 1 else ""
    if "NULL" in upper or "EXPORT" in upper or "ANON" in upper:
        strength = "broken"
    elif (
        "RC4" in cipher
        or "RC2" in cipher
        or "IDEA" in cipher
        or "3DES" in cipher
        or "DES_EDE" in cipher
        or cipher.startswith("DES_")
        or cipher.endswith("_MD5")
    ):
        strength = "weak"
    else:
        strength = "ok"
    return {"strength": strength, "pfs": pfs, "kx": kx}


# =============================================================================
# Construction du ClientHello
# =============================================================================


def _u16(value: int) -> bytes:
    return struct.pack(">H", value)


def _u24(value: int) -> bytes:
    return struct.pack(">I", value)[1:]


def _extension(ext_type: int, body: bytes) -> bytes:
    return _u16(ext_type) + _u16(len(body)) + body


def _is_ip(host: str) -> bool:
    try:
        socket.inet_pton(socket.AF_INET, host)
        return True
    except (OSError, ValueError):
        pass
    try:
        socket.inet_pton(socket.AF_INET6, host)
        return True
    except (OSError, ValueError):
        return False


def build_client_hello(
    version: int,
    suites: list[int],
    sni: str | None,
    *,
    status_request: bool = False,
    compression: tuple[int, ...] = (0,),
) -> bytes:
    """Enregistrement TLS contenant un ClientHello pour `version` (SSL3 à TLS13) avec ces suites.

    SSLv3 : aucune extension (elles n'existent pas dans ce protocole). TLS 1.3 : version
    annoncée via supported_versions et partage de clé x25519 (32 octets aléatoires : le
    serveur n'en fait rien, la poignée de main n'est jamais terminée).
    """
    tls13 = version == TLS13
    legacy = TLS12 if tls13 else version
    session_id = os.urandom(32) if tls13 else b""
    suite_bytes = b"".join(_u16(code) for code in suites)
    body = _u16(legacy) + os.urandom(32) + bytes([len(session_id)]) + session_id
    body += _u16(len(suite_bytes)) + suite_bytes
    body += bytes([len(compression)]) + bytes(compression)

    extensions = b""
    if version != SSL3:
        if sni and not _is_ip(sni):
            host = sni.encode("idna")
            entry = b"\x00" + _u16(len(host)) + host
            extensions += _extension(_EXT_SNI, _u16(len(entry)) + entry)
        groups = [29, 23, 24, 25, 256, 257]
        extensions += _extension(_EXT_GROUPS, _u16(2 * len(groups)) + b"".join(_u16(g) for g in groups))
        extensions += _extension(_EXT_EC_POINTS, b"\x01\x00")
        algorithms = [0x0403, 0x0503, 0x0603, 0x0804, 0x0805, 0x0806, 0x0807, 0x0401, 0x0501, 0x0601]
        algorithms += [0x0203, 0x0201]
        extensions += _extension(
            _EXT_SIG_ALGS, _u16(2 * len(algorithms)) + b"".join(_u16(a) for a in algorithms)
        )
        extensions += _extension(_EXT_RENEGOTIATION, b"\x00")
        extensions += _extension(_EXT_EXTENDED_MASTER, b"")
        if status_request:
            extensions += _extension(_EXT_STATUS_REQUEST, b"\x01\x00\x00\x00\x00")
        if tls13:
            extensions += _extension(_EXT_SUPPORTED_VERSIONS, b"\x02" + _u16(TLS13))
            share = _u16(29) + _u16(32) + os.urandom(32)
            extensions += _extension(_EXT_KEY_SHARE, _u16(len(share)) + share)
        body += _u16(len(extensions)) + extensions

    handshake = b"\x01" + _u24(len(body)) + body
    record_version = SSL3 if version == SSL3 else TLS10
    return bytes([_REC_HANDSHAKE]) + _u16(record_version) + _u16(len(handshake)) + handshake


# =============================================================================
# Lecture de la réponse du serveur
# =============================================================================


@dataclass
class ServerFlight:
    """Ce que le serveur a répondu à un ClientHello.

    outcome : « hello » (ServerHello reçu), « alert » (refus avec alerte), « closed »
    (connexion fermée sans réponse), « timeout », « refused » (connexion TCP impossible)
    ou « garbage » (réponse qui n'est pas du TLS).
    """

    outcome: str
    version: int | None = None
    suite: int | None = None
    compression: int | None = None
    alert: int | None = None
    retry_request: bool = False
    extensions: set[int] = field(default_factory=set)
    certificates: list[bytes] = field(default_factory=list)
    stapled: bytes | None = None
    dh_bits: int | None = None
    ecdh_group: int | None = None

    @property
    def answered(self) -> bool:
        return self.outcome == "hello"


_HELLO_RETRY_RANDOM = bytes.fromhex("CF21AD74E59A6111BE1D8C021E65B891C2A211167ABB8C5E079E09E2C8A8339C")


def _parse_server_hello(body: bytes, flight: ServerFlight) -> None:
    flight.version = struct.unpack(">H", body[0:2])[0]
    flight.retry_request = body[2:34] == _HELLO_RETRY_RANDOM
    position = 34
    position += 1 + body[position]
    flight.suite = struct.unpack(">H", body[position : position + 2])[0]
    flight.compression = body[position + 2]
    position += 3
    if len(body) >= position + 2:
        end = position + 2 + struct.unpack(">H", body[position : position + 2])[0]
        position += 2
        while position + 4 <= min(end, len(body)):
            ext_type, length = struct.unpack(">HH", body[position : position + 4])
            data = body[position + 4 : position + 4 + length]
            flight.extensions.add(ext_type)
            if ext_type == _EXT_SUPPORTED_VERSIONS and len(data) == 2:
                flight.version = struct.unpack(">H", data)[0]
            position += 4 + length


def _parse_certificates(body: bytes) -> list[bytes]:
    certificates: list[bytes] = []
    total = int.from_bytes(body[0:3], "big")
    position, end = 3, min(3 + total, len(body))
    while position + 3 <= end:
        length = int.from_bytes(body[position : position + 3], "big")
        position += 3
        if length == 0 or position + length > end:
            break
        certificates.append(bytes(body[position : position + length]))
        position += length
    return certificates


def _parse_key_exchange(body: bytes, flight: ServerFlight) -> None:
    name = suite_name(flight.suite or 0)
    if "_DHE_" in name and len(body) >= 2:
        prime_length = struct.unpack(">H", body[0:2])[0]
        prime = body[2 : 2 + prime_length]
        if prime and len(prime) == prime_length:
            flight.dh_bits = int.from_bytes(prime, "big").bit_length()
    elif "_ECDHE_" in name and len(body) >= 3 and body[0] == 3:
        flight.ecdh_group = struct.unpack(">H", body[1:3])[0]


def _parse_handshake_messages(buffer: bytearray, flight: ServerFlight, read_flight: bool) -> bool:
    """Consomme les messages complets de `buffer` ; rend True quand la lecture peut s'arrêter."""
    while len(buffer) >= 4:
        length = int.from_bytes(buffer[1:4], "big")
        if len(buffer) < 4 + length:
            return False
        kind, body = buffer[0], bytes(buffer[4 : 4 + length])
        del buffer[: 4 + length]
        if kind == _HS_SERVER_HELLO:
            try:
                _parse_server_hello(body, flight)
            except (struct.error, IndexError):
                flight.outcome = "garbage"
                return True
            flight.outcome = "hello"
            # TLS 1.3 : la suite du vol est chiffrée ; sinon on ne lit plus que sur demande.
            if not read_flight or flight.version == TLS13 or flight.retry_request:
                return True
        elif kind == _HS_CERTIFICATE and flight.outcome == "hello":
            flight.certificates = _parse_certificates(body)
        elif kind == _HS_CERTIFICATE_STATUS and body[:1] == b"\x01":
            size = int.from_bytes(body[1:4], "big")
            flight.stapled = bytes(body[4 : 4 + size])
        elif kind == _HS_SERVER_KEY_EXCHANGE and flight.outcome == "hello":
            try:
                _parse_key_exchange(body, flight)
            except (struct.error, IndexError):
                pass
        elif kind == _HS_SERVER_HELLO_DONE:
            return True
    return False


def probe(
    address: str,
    port: int,
    hello: bytes,
    *,
    timeout: float = 5.0,
    read_flight: bool = False,
) -> ServerFlight:
    """Envoie `hello` à `address:port` et lit la réponse (ServerHello, ou le vol complet).

    `address` : adresse IP validée par la politique de cibles. Ne lève jamais d'erreur
    réseau : le résultat dit ce qui s'est passé (voir ServerFlight.outcome).
    """
    deadline = time.monotonic() + max(timeout * 2, timeout + 3)
    try:
        sock = socket.create_connection((address, port), timeout=timeout)
    except TimeoutError:
        return ServerFlight("timeout")
    except OSError:
        return ServerFlight("refused")
    flight = ServerFlight("closed")
    records = bytearray()
    handshake = bytearray()
    try:
        with sock:
            sock.settimeout(timeout)
            sock.sendall(hello)
            received = 0
            while time.monotonic() < deadline and received < MAX_FLIGHT_BYTES:
                try:
                    chunk = sock.recv(16384)
                except TimeoutError:
                    if flight.outcome == "closed":
                        flight.outcome = "timeout"
                    break
                except OSError:
                    break
                if not chunk:
                    break
                received += len(chunk)
                records += chunk
                while len(records) >= 5:
                    kind, _, length = struct.unpack(">BHH", bytes(records[:5]))
                    if kind not in (20, 21, 22, 23) or length > 18432:
                        flight.outcome = "garbage"
                        return flight
                    if len(records) < 5 + length:
                        break
                    payload = bytes(records[5 : 5 + length])
                    del records[: 5 + length]
                    if kind == _REC_ALERT:
                        if flight.outcome != "hello":
                            flight.outcome = "alert"
                            flight.alert = payload[1] if len(payload) >= 2 else None
                        return flight
                    if kind == _REC_HANDSHAKE:
                        handshake += payload
                        if _parse_handshake_messages(handshake, flight, read_flight):
                            return flight
                    elif kind == 23:
                        return flight
    except OSError:
        return flight
    return flight
