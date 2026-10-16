# =============================================================================
# DomainRecon - Certificats X.509 : récupération de la chaîne et analyse
# =============================================================================
# Brique commune de « crypto_audit » (audit du certificat) et de « cert_revocation »
# (OCSP et CRL). Piège évité : get_verified_chain() renvoie des
# octets DER (et ssl.ENCODING_DER n'existe pas) ; mal lue, la chaîne se réduirait
# au certificat feuille et tout certificat valide serait signalé « chaîne incomplète ».
#
# Récupération, par ordre de préférence :
#   1. ssl : chaîne envoyée par le serveur (`get_unverified_chain`) et chaîne
#      vérifiée jusqu'à la racine du magasin certifi (`get_verified_chain`) ;
#   2. sondes TLS 1.2 forgées (impl/tls_hello) pour un Python sans ces méthodes ;
#   3. le seul certificat feuille (la complétude de la chaîne est alors inconnue).
# Fonctions bloquantes (sockets) : à lancer dans asyncio.to_thread.
# =============================================================================

import socket
import ssl
from datetime import datetime, timezone

from cryptography import x509
from cryptography.exceptions import InvalidSignature, UnsupportedAlgorithm
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import dsa, ec, ed448, ed25519, rsa
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.x509.oid import AuthorityInformationAccessOID, NameOID

from . import tls_hello

try:  # Magasin de certificats de Mozilla, comme httpx : même verdict sur toutes les plateformes.
    import certifi
except ImportError:  # pragma: no cover - certifi est installé avec httpx
    certifi = None

CONNECT_TIMEOUT = 6.0
MAX_CHAIN_LENGTH = 10

_SCT_LIST_OID = "1.3.6.1.4.1.11129.2.4.2"
# Politiques de certificat du CA/Browser Forum (types de validation) et OID d'EV des AC.
_POLICY_TYPES = {
    "2.23.140.1.1": "EV",
    "2.23.140.1.2.1": "DV",
    "2.23.140.1.2.2": "OV",
    "2.23.140.1.2.3": "IV",
}
_EV_OIDS = frozenset(
    {
        "2.16.840.1.114412.2.1",
        "2.16.840.1.114412.1.3.0.2",
        "2.16.840.1.114413.1.7.23.3",
        "2.16.840.1.114414.1.7.23.3",
        "1.3.6.1.4.1.6449.1.2.1.5.1",
        "2.16.840.1.114028.10.1.2",
        "1.3.6.1.4.1.34697.2.1",
        "1.2.392.200091.100.721.1",
        "2.16.756.1.89.1.2.1.1",
    }
)
_WEAK_HASHES = frozenset({"md2", "md4", "md5", "sha1"})
_EXTRA_SIGNATURES = {"1.3.101.112": "ed25519", "1.3.101.113": "ed448"}


# =============================================================================
# Récupération de la chaîne
# =============================================================================


class ChainFetchError(Exception):
    """La chaîne n'a pu être lue : `kind` vaut « refused », « timeout » ou « no_tls »."""

    def __init__(self, kind: str) -> None:
        super().__init__(kind)
        self.kind = kind


def _verified_context() -> ssl.SSLContext:
    return ssl.create_default_context(cafile=certifi.where()) if certifi else ssl.create_default_context()


def _unverified_context() -> ssl.SSLContext:
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    return context


def _der_list(items: object) -> list[bytes]:
    """Liste de DER à partir de ce que rend ssl : octets (3.13+) ou objets Certificate (3.10 à 3.12)."""
    result: list[bytes] = []
    for item in items or ():
        if isinstance(item, (bytes, bytearray)):
            result.append(bytes(item))
        elif hasattr(item, "public_bytes"):
            result.append(item.public_bytes(getattr(ssl, "ENCODING_DER", 1)))
    return result


def _chain_of(tls_sock: ssl.SSLSocket, verified: bool) -> list[bytes]:
    name = "get_verified_chain" if verified else "get_unverified_chain"
    getter = getattr(tls_sock, name, None) or getattr(getattr(tls_sock, "_sslobj", None), name, None)
    if getter is None:
        return []
    try:
        return _der_list(getter())
    except (ValueError, OSError, TypeError, ssl.SSLError):
        return []


def _handshake(address: str, port: int, sni: str | None, context: ssl.SSLContext) -> dict:
    with socket.create_connection((address, port), timeout=CONNECT_TIMEOUT) as sock:
        # Cible IP : ssl vérifie l'adresse contre les SAN de type IP et n'envoie pas de SNI.
        with context.wrap_socket(sock, server_hostname=sni or address) as tls_sock:
            leaf = tls_sock.getpeercert(binary_form=True)
            return {
                "served": _chain_of(tls_sock, False) or ([leaf] if leaf else []),
                "verified_chain": _chain_of(tls_sock, True),
                "leaf_only": not _chain_of(tls_sock, False),
                "protocol": tls_sock.version(),
                "cipher": (tls_sock.cipher() or (None,))[0],
            }


def fetch_chain(address: str, port: int, sni: str | None) -> dict:
    """Chaîne de certificats servie par `address:port` (adresse validée par la politique de cibles).

    Résultat : served (DER, dans l'ordre d'envoi), verified (vrai si la chaîne est approuvée par
    le magasin certifi et le nom correspond), verify_code/verify_message (échec de vérification),
    verified_chain (jusqu'à la racine), source (ssl | wire | leaf), protocol, cipher.
    Lève ChainFetchError (refused, timeout, no_tls).
    """
    verify_code = verify_message = None
    try:
        info = _handshake(address, port, sni, _verified_context())
        verified = True
    except ssl.SSLCertVerificationError as e:
        verified = False
        verify_code, verify_message = e.verify_code, e.verify_message
        try:
            info = _handshake(address, port, sni, _unverified_context())
        except TimeoutError:
            raise ChainFetchError("timeout") from None
        except (OSError, ssl.SSLError):
            raise ChainFetchError("no_tls") from None
    except ssl.SSLError:
        # Poignée de main refusée (service non TLS, protocole incompatible) : sonde TLS 1.2 forgée.
        info = _wire_fallback(address, port, sni)
        verified = False
    except TimeoutError:
        raise ChainFetchError("timeout") from None
    except (ConnectionRefusedError, ConnectionResetError):
        raise ChainFetchError("refused") from None
    except ValueError:  # nom d'hôte refusé par le module ssl
        raise ChainFetchError("no_tls") from None
    except OSError:
        # Hôte ou réseau injoignable, nom introuvable… : pas de HTTPS joignable.
        raise ChainFetchError("refused") from None
    if not info["served"]:
        raise ChainFetchError("no_tls")
    source = "leaf" if info.pop("leaf_only", False) else ("wire" if info.get("wire") else "ssl")
    info.pop("wire", None)
    return {
        **info,
        "verified": verified,
        "verify_code": verify_code,
        "verify_message": verify_message,
        "source": source,
    }


def _wire_fallback(address: str, port: int, sni: str | None) -> dict:
    hello = tls_hello.build_client_hello(tls_hello.TLS12, tls_hello.MODERN_TLS12_SUITES, sni)
    flight = tls_hello.probe(address, port, hello, timeout=CONNECT_TIMEOUT, read_flight=True)
    if flight.outcome == "refused":
        raise ChainFetchError("refused")
    if flight.outcome == "timeout":
        raise ChainFetchError("timeout")
    if not flight.certificates:
        raise ChainFetchError("no_tls")
    return {
        "served": flight.certificates,
        "verified_chain": [],
        "protocol": "TLSv1.2",
        "cipher": tls_hello.suite_name(flight.suite or 0),
        "wire": True,
    }


# =============================================================================
# Analyse d'un certificat
# =============================================================================


def _attribute(name: x509.Name, oid) -> str | None:
    try:
        values = name.get_attributes_for_oid(oid)
    except ValueError:
        return None
    return str(values[0].value) if values else None


def _key_info(public_key: object) -> dict:
    if isinstance(public_key, rsa.RSAPublicKey):
        return {"type": "RSA", "bits": public_key.key_size}
    if isinstance(public_key, ec.EllipticCurvePublicKey):
        return {"type": "EC", "bits": public_key.key_size, "curve": public_key.curve.name}
    if isinstance(public_key, dsa.DSAPublicKey):
        return {"type": "DSA", "bits": public_key.key_size}
    if isinstance(public_key, ed25519.Ed25519PublicKey):
        return {"type": "Ed25519", "bits": 256}
    if isinstance(public_key, ed448.Ed448PublicKey):
        return {"type": "Ed448", "bits": 448}
    return {"type": type(public_key).__name__, "bits": None}


def key_is_weak(key: dict) -> bool:
    """Clé en dessous des minimums actuels : RSA/DSA < 2048 bits, courbe elliptique < 256 bits."""
    bits = key.get("bits")
    if not isinstance(bits, int):
        return False
    if key.get("type") in ("RSA", "DSA"):
        return bits < 2048
    if key.get("type") == "EC":
        return bits < 256
    return False


def _signature_name(cert: x509.Certificate) -> str:
    try:
        algorithm = cert.signature_hash_algorithm
    except Exception:  # algorithme de signature que la bibliothèque ne sait pas nommer
        algorithm = None
    if algorithm is not None:
        return algorithm.name.lower()
    return _EXTRA_SIGNATURES.get(
        cert.signature_algorithm_oid.dotted_string, cert.signature_algorithm_oid.dotted_string
    )


def _extension(cert: x509.Certificate, cls):
    try:
        return cert.extensions.get_extension_for_class(cls).value
    except (x509.ExtensionNotFound, ValueError):
        return None


def _extension_oid(cert: x509.Certificate, dotted: str):
    try:
        return cert.extensions.get_extension_for_oid(x509.ObjectIdentifier(dotted)).value
    except (x509.ExtensionNotFound, ValueError):
        return None


def _access_urls(cert: x509.Certificate, method) -> list[str]:
    aia = _extension(cert, x509.AuthorityInformationAccess)
    if aia is None:
        return []
    return [
        d.access_location.value
        for d in aia
        if d.access_method == method and isinstance(d.access_location, x509.UniformResourceIdentifier)
    ]


def crl_urls(cert: x509.Certificate) -> list[str]:
    points = _extension(cert, x509.CRLDistributionPoints)
    urls: list[str] = []
    for point in points or ():
        for name in point.full_name or ():
            if isinstance(name, x509.UniformResourceIdentifier):
                urls.append(name.value)
    return urls


def ocsp_urls(cert: x509.Certificate) -> list[str]:
    return _access_urls(cert, AuthorityInformationAccessOID.OCSP)


def issuer_urls(cert: x509.Certificate) -> list[str]:
    return _access_urls(cert, AuthorityInformationAccessOID.CA_ISSUERS)


def must_staple(cert: x509.Certificate) -> bool:
    feature = _extension(cert, x509.TLSFeature)
    return bool(feature) and x509.TLSFeatureType.status_request in feature


def _sct_count(cert: x509.Certificate) -> int:
    scts = _extension(cert, x509.PrecertificateSignedCertificateTimestamps)
    if scts is not None:
        return len(scts)
    return 1 if _extension_oid(cert, _SCT_LIST_OID) is not None else 0


def _validation_type(cert: x509.Certificate) -> str:
    policies = _extension(cert, x509.CertificatePolicies)
    oids = {p.policy_identifier.dotted_string for p in policies or ()}
    for oid, kind in _POLICY_TYPES.items():
        if oid in oids:
            return kind
    if oids & _EV_OIDS:
        return "EV"
    return "OV" if _attribute(cert.subject, NameOID.ORGANIZATION_NAME) else "DV"


def is_self_issued(cert: x509.Certificate) -> bool:
    return cert.subject == cert.issuer


def issued_by(cert: x509.Certificate, issuer: x509.Certificate) -> bool:
    """`issuer` a-t-il signé `cert` ? (nom et signature vérifiés)"""
    if cert.issuer != issuer.subject:
        return False
    try:
        cert.verify_directly_issued_by(issuer)
    except (ValueError, TypeError, InvalidSignature):
        return False
    except UnsupportedAlgorithm:  # signature d'un type non pris en charge : on s'en tient au nom
        return True
    return True


def load(der: bytes) -> x509.Certificate | None:
    try:
        return x509.load_der_x509_certificate(der)
    except ValueError:
        return None


def _utc(moment: datetime) -> datetime:
    return moment if moment.tzinfo else moment.replace(tzinfo=timezone.utc)


def parse_certificate(cert: x509.Certificate, position: str, now: datetime | None = None) -> dict:
    """Description JSON d'un certificat de la chaîne (feuille, intermédiaire ou racine)."""
    now = now or datetime.now(timezone.utc)
    not_before, not_after = _utc(cert.not_valid_before_utc), _utc(cert.not_valid_after_utc)
    key = _key_info(cert.public_key())
    signature = _signature_name(cert)
    basic = _extension(cert, x509.BasicConstraints)
    san = _extension(cert, x509.SubjectAlternativeName)
    dns_names = list(san.get_values_for_type(x509.DNSName)) if san else []
    ip_names = [str(ip) for ip in san.get_values_for_type(x509.IPAddress)] if san else []
    usage = _extension(cert, x509.ExtendedKeyUsage)
    info = {
        "position": position,
        "subject_cn": _attribute(cert.subject, NameOID.COMMON_NAME),
        "subject_org": _attribute(cert.subject, NameOID.ORGANIZATION_NAME),
        "issuer_cn": _attribute(cert.issuer, NameOID.COMMON_NAME),
        "issuer_org": _attribute(cert.issuer, NameOID.ORGANIZATION_NAME),
        "self_signed": is_self_issued(cert),
        "serial": format(cert.serial_number, "X"),
        "not_before": not_before.isoformat(),
        "not_after": not_after.isoformat(),
        "validity_days": (not_after - not_before).days,
        "days_remaining": (not_after - now).days,
        "key": key,
        "key_weak": key_is_weak(key),
        "signature": signature,
        "signature_weak": signature in _WEAK_HASHES,
        "is_ca": bool(basic.ca) if basic else False,
        "sha256": cert.fingerprint(hashes.SHA256()).hex().upper(),
        "ocsp_urls": ocsp_urls(cert)[:3],
        "crl_urls": crl_urls(cert)[:3],
        "issuer_urls": issuer_urls(cert)[:3],
    }
    if position == "leaf":
        info.update(
            san=dns_names[:50],
            san_count=len(dns_names) + len(ip_names),
            san_ips=ip_names[:10],
            has_san=san is not None,
            wildcard=any(name.startswith("*.") for name in dns_names),
            validation=_validation_type(cert),
            sct_count=_sct_count(cert),
            must_staple=must_staple(cert),
            server_auth=(usage is None) or (x509.ExtendedKeyUsageOID.SERVER_AUTH in usage),
        )
    return info


# =============================================================================
# Chaîne : liens, complétude
# =============================================================================


def chain_is_complete(served: list[x509.Certificate], fetched: dict) -> bool | None:
    """La chaîne servie suffit-elle à un client sans récupération AIA ? None : indéterminé.

    - chaîne approuvée (certifi) : complète si chaque intermédiaire de la chaîne vérifiée a été
      envoyé par le serveur (une racine du magasin n'a pas à l'être) ;
    - non approuvée avec OpenSSL « émetteur local introuvable » (codes 20 et 21) : l'émetteur du
      certificat feuille n'est pas dans la chaîne envoyée, donc incomplète ;
    - tout autre cas (certificat auto-signé, racine privée…) : on ne conclut pas.
    """
    if fetched.get("source") == "leaf" or not served:
        return None
    served_der = {c.public_bytes(Encoding.DER) for c in served}
    if fetched.get("verified"):
        verified = [load(d) for d in fetched.get("verified_chain") or []]
        if len(verified) < 2 or any(v is None for v in verified):
            return None
        middle = verified[1:-1]
        return all(c.public_bytes(Encoding.DER) in served_der for c in middle)
    if fetched.get("verify_code") in (20, 21) and len(served) > 0:
        leaf = served[0]
        return any(issued_by(leaf, other) for other in served[1:])
    return None
