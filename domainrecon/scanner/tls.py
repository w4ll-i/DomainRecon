# =============================================================================
# DomainRecon - Scanner : certificat TLS
# =============================================================================
# Deux questions distinctes :
#   - https : le port 443 accepte-t-il une poignée de main TLS ?
#   - valid : le certificat présenté est-il valide (chaîne, nom d'hôte, dates) ?
# Un certificat invalide est un résultat de mesure (measured=True, valid=False),
# pas un échec : une seconde poignée de main sans vérification permet d'en lire
# le contenu (émetteur, dates, SAN). Seul un hôte injoignable, qui ne répond ni
# en HTTPS ni en HTTP, donne measured=False.
# =============================================================================

import asyncio
import os
import socket
import ssl
import tempfile
import time

from ..i18n import msg
from .common import USER_AGENT, logger
from .errors import exception_text, message_exception
from .targets import ensure_target_allowed

try:  # Magasin de certificats de Mozilla, comme httpx (dont c'est une dépendance).
    import certifi
except ImportError:  # pragma: no cover - certifi est installé avec httpx
    certifi = None

TLS_PORT = 443
HTTP_PORT = 80
# Délai par opération réseau (connexion, poignée de main, lecture).
TLS_TIMEOUT = 5.0
# Nombre maximal d'adresses essayées pour une connexion (borne la durée totale).
MAX_ADDRESSES = 3


def _verify_reason(code: int | None) -> dict | None:
    """Raison traduisible des codes X509_V_ERR_* d'OpenSSL les plus courants, ou None."""
    reasons = {
        2: msg("tls.verify_2"),
        7: msg("tls.verify_7"),
        9: msg("tls.verify_9"),
        10: msg("tls.verify_10"),
        18: msg("tls.verify_18"),
        19: msg("tls.verify_19"),
        20: msg("tls.verify_20"),
        21: msg("tls.verify_21"),
        23: msg("tls.verify_23"),
        24: msg("tls.verify_24"),
        26: msg("tls.verify_26"),
        62: msg("tls.verify_62"),
        64: msg("tls.verify_64"),
        66: msg("tls.verify_66"),
        67: msg("tls.verify_67"),
        68: msg("tls.verify_68"),
    }
    return reasons.get(code)


def _error_text(error: BaseException) -> object:
    return exception_text(error) or type(error).__name__


def _describe_network_error(error: OSError) -> object:
    """Raison lisible (traduisible) d'un échec de connexion (au lieu de « timed out »)."""
    if isinstance(error, TimeoutError):
        return msg("net.timeout")
    if isinstance(error, ConnectionRefusedError):
        return msg("net.connection_refused")
    if isinstance(error, ConnectionResetError):
        return msg("net.connection_reset_by_host")
    if isinstance(error, socket.gaierror):
        return msg("net.name_not_found")
    return _error_text(error)


def _describe_verify_error(error: ssl.SSLCertVerificationError) -> object:
    """Raison lisible (traduisible) d'un échec de vérification du certificat."""
    reason = _verify_reason(error.verify_code)
    if reason is not None:
        return reason
    return msg("tls.verify_other", detail=error.verify_message or _error_text(error))


def _verified_context() -> ssl.SSLContext:
    """Contexte qui vérifie la chaîne, le nom d'hôte et les dates.

    Le magasin de certifi donne le même verdict sur toutes les plateformes :
    sous Windows, le magasin système ne contient une racine qu'après son
    premier usage par le système, d'où de faux « autorité inconnue ».
    """
    if certifi is not None:
        return ssl.create_default_context(cafile=certifi.where())
    return ssl.create_default_context()


def _unverified_context() -> ssl.SSLContext:
    """Contexte sans vérification, pour lire un certificat invalide.

    Utilisé seulement après l'échec du contexte vérifiant, pour relire le
    certificat rejeté : aucune donnée applicative n'est échangée.
    """
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    return context


def _connect(host: str, port: int, timeout: float, addresses: list[str] | None) -> socket.socket:
    """Connexion TCP à `host`, limitée aux adresses déjà validées si elles sont fournies.

    Se connecter aux adresses validées par la politique de cibles, plutôt que de
    résoudre le nom une seconde fois, empêche une nouvelle réponse DNS
    (rebinding) de mener vers un hôte interne.
    """
    if not addresses:
        return socket.create_connection((host, port), timeout=timeout)
    last_error: OSError = message_exception(OSError, msg("net.no_reachable_address", host=host))
    for address in addresses[:MAX_ADDRESSES]:
        try:
            return socket.create_connection((address, port), timeout=timeout)
        except OSError as e:
            last_error = e
    raise last_error


def _handshake(
    host: str, port: int, context: ssl.SSLContext, timeout: float, addresses: list[str] | None = None
):
    """Poignée de main TLS : (certificat décodé, certificat DER, protocole, suite)."""
    with _connect(host, port, timeout, addresses) as sock:
        with context.wrap_socket(sock, server_hostname=host) as tls_sock:
            return (
                tls_sock.getpeercert(),
                tls_sock.getpeercert(binary_form=True),
                tls_sock.version(),
                tls_sock.cipher(),
            )


def _decode_der_certificate(der: bytes) -> dict:
    """Décode un certificat DER au format de `SSLSocket.getpeercert()`.

    Sans vérification, `getpeercert()` ne renvoie que la forme binaire. Faute de
    dépendance dédiée (cryptography), on passe par le décodeur interne de
    CPython, présent de Python 3.2 à 3.14. En cas d'échec, les détails du
    certificat manquent, mais le verdict (valid=False) reste juste.
    """
    decoder = getattr(getattr(ssl, "_ssl", None), "_test_decode_cert", None)
    if decoder is None:
        return {}
    fd, path = tempfile.mkstemp(prefix="domainrecon-cert-", suffix=".pem")
    try:
        with os.fdopen(fd, "w", encoding="ascii") as handle:
            handle.write(ssl.DER_cert_to_PEM_cert(der))
        return decoder(path)
    except Exception as e:
        logger.debug("Décodage du certificat impossible : %s", e)
        return {}
    finally:
        try:
            os.unlink(path)
        except OSError:
            pass


def _days_remaining(not_after: str) -> int | None:
    try:
        expiry = ssl.cert_time_to_seconds(not_after)
    except (ValueError, TypeError) as e:
        logger.debug("Date d'expiration TLS illisible (%s): %s", not_after, e)
        return None
    return int((expiry - time.time()) // 86400)


def _name_fields(rdns) -> dict[str, str]:
    return {key: value for rdn in rdns or () for key, value in rdn}


def _certificate_fields(cert: dict) -> dict:
    subject = _name_fields(cert.get("subject"))
    issuer = _name_fields(cert.get("issuer"))
    not_after = cert.get("notAfter", "")
    return {
        "subject": subject.get("commonName", ""),
        "issuer_org": issuer.get("organizationName", ""),
        "issuer_cn": issuer.get("commonName", ""),
        "serial_number": cert.get("serialNumber", ""),
        "version": cert.get("version", ""),
        "not_before": cert.get("notBefore", ""),
        "not_after": not_after,
        "days_remaining": _days_remaining(not_after) if not_after else None,
        "san": [entry[1] for entry in cert.get("subjectAltName", ())],
    }


def _http_port_responds(host: str, port: int, timeout: float, addresses: list[str] | None = None) -> bool:
    """Le site répond-il en HTTP clair ? (distingue « pas de HTTPS » d'« injoignable »)"""
    host_header = f"[{host}]" if ":" in host else host
    request = (
        f"HEAD / HTTP/1.1\r\nHost: {host_header}\r\nUser-Agent: {USER_AGENT}\r\nConnection: close\r\n\r\n"
    )
    try:
        with _connect(host, port, timeout, addresses) as sock:
            sock.sendall(request.encode("ascii"))
            received = b""
            while len(received) < 5:
                chunk = sock.recv(5 - len(received))
                if not chunk:
                    break
                received += chunk
            return received.startswith(b"HTTP/")
    except (OSError, UnicodeError):
        return False


# =============================================================================
# Module 4 : TLS Certificate
# =============================================================================


def _base_result(measured: bool = True, error: object = None) -> dict:
    return {
        "measured": measured,
        "https": False,
        "valid": False,
        "verify_error": None,
        "verify_code": None,
        "error": error,
    }


def _verified_handshake(domain: str, port: int, timeout: float, addresses: list[str] | None):
    """Poignée de main vérifiée, refaite une fois après une connexion réinitialisée.

    Une réinitialisation passagère (RST d'un équilibreur, d'un pare-feu) ne doit pas
    faire conclure « HTTPS fermé » quand le port HTTP répond : seule une seconde
    réinitialisation est retenue.
    """
    try:
        return _handshake(domain, port, _verified_context(), timeout, addresses)
    except (ConnectionResetError, ConnectionAbortedError) as e:
        logger.debug("Connexion TLS réinitialisée pour %s (%s) : nouvelle tentative", domain, e)
        return _handshake(domain, port, _verified_context(), timeout, addresses)


def _check_tls_sync(
    domain: str,
    port: int = TLS_PORT,
    http_port: int = HTTP_PORT,
    timeout: float = TLS_TIMEOUT,
    addresses: list[str] | None = None,
) -> dict:
    """Analyse TLS synchrone - exécuté dans un thread.

    `addresses` : adresses de `domain` déjà validées par la politique de cibles ;
    les connexions s'y limitent (le nom sert à SNI et à la vérification).
    """
    result = _base_result()

    try:
        cert, _, protocol, cipher = _verified_handshake(domain, port, timeout, addresses)
        result.update(https=True, valid=True)
    except ssl.SSLCertVerificationError as e:
        # Le serveur parle TLS, mais son certificat est invalide : on le relit
        # sans vérification pour en garder les détails.
        logger.debug("Certificat TLS invalide pour %s: %s", domain, e)
        result.update(https=True, verify_code=e.verify_code, verify_error=_describe_verify_error(e))
        try:
            _, der, protocol, cipher = _handshake(domain, port, _unverified_context(), timeout, addresses)
        except Exception as e2:
            logger.debug("Relecture du certificat invalide de %s impossible: %s", domain, e2)
            return result
        cert = _decode_der_certificate(der) if der else {}
    except ssl.SSLError as e:
        # Port ouvert, mais aucune poignée de main possible (service non TLS,
        # protocole obsolète refusé…) : pas de HTTPS utilisable.
        logger.debug("Poignée de main TLS refusée pour %s: %s", domain, e)
        result["verify_error"] = msg("tls.handshake_failed", detail=e.reason or _error_text(e))
        return result
    except OSError as e:
        # Port fermé, filtré ou hôte injoignable : si le site répond en HTTP,
        # l'absence de HTTPS est un constat, pas un échec de mesure.
        logger.debug("Connexion TLS impossible pour %s: %s", domain, e)
        if _http_port_responds(domain, http_port, timeout, addresses):
            result["verify_error"] = msg("tls.https_closed", port=port)
            return result
        result.update(
            measured=False,
            error=msg("tls.host_unreachable", port=port, error=_describe_network_error(e)),
        )
        return result
    except Exception as e:  # nom d'hôte refusé par le module ssl, etc.
        logger.debug("Analyse TLS impossible pour %s: %s", domain, e)
        result.update(measured=False, error=msg("tls.analysis_failed", detail=_error_text(e)))
        return result

    result.update(_certificate_fields(cert or {}))
    result.update(
        protocol=protocol,
        cipher=cipher[0] if cipher else None,
        cipher_bits=cipher[2] if cipher else None,
    )
    return result


async def check_tls_certificate(domain: str, port: int = TLS_PORT) -> dict:
    """Analyse le certificat TLS/SSL d'un domaine.

    Lève TargetNotAllowedError si le nom résout vers une adresse refusée par
    la politique de cibles.
    """
    addresses = await ensure_target_allowed(domain)
    if not addresses:
        return _base_result(measured=False, error=msg("net.resolve_failed", host=domain))
    return await asyncio.to_thread(_check_tls_sync, domain, port, HTTP_PORT, TLS_TIMEOUT, addresses)
