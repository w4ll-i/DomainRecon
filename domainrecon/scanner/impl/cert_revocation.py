# =============================================================================
# DomainRecon - Révocation du certificat : OCSP (requête et agrafe) et CRL
# =============================================================================
# Logique du module « cert_revocation » (modules/cert_revocation.py).
#
# La seule présence d'une URL OCSP dans le certificat ne prouve pas l'agrafe
# (« stapling ») : tout est donc réellement vérifié :
#   - agrafe OCSP : le serveur joint-il une réponse OCSP à sa poignée de main
#     (sonde TLS 1.2 avec l'extension status_request, impl/tls_hello) ? Cette
#     réponse est lue (état, fraîcheur). Sous TLS 1.3, l'agrafe est chiffrée :
#     impossible à voir sans terminer la poignée de main, l'état est « inconnu » ;
#   - requête OCSP au répondeur de l'autorité (RFC 6960) : état good / revoked /
#     unknown, fraîcheur et signature de la réponse (AC émettrice ou répondeur
#     délégué) vérifiées ;
#   - CRL (RFC 5280) : en secours quand OCSP manque ou ne conclut pas. Let's
#     Encrypt a arrêté OCSP en 2025 au profit des seules CRL : un certificat sans
#     URL OCSP mais avec un point de distribution de CRL est donc normal.
# Les requêtes vers l'autorité de certification passent par le client HTTP du
# scan (anti-SSRF, proxy, TLS vérifié, aucune redirection). L'URL vient du
# certificat, donc d'un tiers : taille des réponses bornée, schéma http(s) exigé.
# =============================================================================

import asyncio
from datetime import datetime, timezone
from urllib.parse import urlsplit

import httpx
from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, ed448, ed25519, padding, rsa
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.x509 import ocsp
from cryptography.x509.oid import ExtendedKeyUsageOID

from ...i18n import msg
from ..http_utils import read_body_limited
from . import tls_hello, tls_x509

OCSP_TIMEOUT = 10.0
CRL_TIMEOUT = 15.0
MAX_OCSP_BYTES = 256 * 1024
MAX_CRL_BYTES = 8 * 1024 * 1024
MAX_ISSUER_BYTES = 64 * 1024
# Au plus ce nombre de répondeurs / points de distribution essayés par type.
MAX_URLS = 2
# Marge sur next_update : les horloges et les caches des répondeurs ne sont pas exacts.
CLOCK_MARGIN_SECONDS = 3600
# Certificats de durée de vie très courte : la révocation n'y est plus exigée (Baseline Requirements).
SHORT_LIVED_MAX_DAYS = 10


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _iso(moment: datetime | None) -> str | None:
    return moment.isoformat() if moment is not None else None


def _http_url(url: str) -> bool:
    parts = urlsplit(url)
    return parts.scheme in ("http", "https") and bool(parts.hostname)


# =============================================================================
# Signatures
# =============================================================================


def _verify_signature(public_key: object, signature: bytes, data: bytes, algorithm) -> bool:
    try:
        if isinstance(public_key, rsa.RSAPublicKey):
            public_key.verify(signature, data, padding.PKCS1v15(), algorithm)
        elif isinstance(public_key, ec.EllipticCurvePublicKey):
            public_key.verify(signature, data, ec.ECDSA(algorithm))
        elif isinstance(public_key, (ed25519.Ed25519PublicKey, ed448.Ed448PublicKey)):
            public_key.verify(signature, data)
        else:
            return False
    except (InvalidSignature, ValueError, TypeError):
        return False
    return True


def _responder_matches(response: ocsp.OCSPResponse, cert: x509.Certificate) -> bool:
    if response.responder_name is not None:
        return response.responder_name == cert.subject
    key_hash = response.responder_key_hash
    if key_hash is None:
        return False
    try:
        ski = cert.extensions.get_extension_for_class(x509.SubjectKeyIdentifier).value.digest
    except x509.ExtensionNotFound:
        ski = x509.SubjectKeyIdentifier.from_public_key(cert.public_key()).digest
    return ski == key_hash


def ocsp_signature_ok(response: ocsp.OCSPResponse, issuer: x509.Certificate) -> bool:
    """Signature de la réponse OCSP : par l'AC émettrice ou par un répondeur qu'elle a délégué."""
    algorithm = response.signature_hash_algorithm
    if algorithm is None:
        return False
    signer = issuer if _responder_matches(response, issuer) else None
    if signer is None:
        for candidate in response.certificates:
            if not _responder_matches(response, candidate) or not tls_x509.issued_by(candidate, issuer):
                continue
            try:
                usage = candidate.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
            except x509.ExtensionNotFound:
                continue
            if ExtendedKeyUsageOID.OCSP_SIGNING in usage:
                signer = candidate
                break
    if signer is None:
        return False
    return _verify_signature(signer.public_key(), response.signature, response.tbs_response_bytes, algorithm)


def _ocsp_summary(response: ocsp.OCSPResponse, leaf: x509.Certificate, now: datetime) -> dict:
    """État lu dans une réponse OCSP (hors signature) : good | revoked | unknown | error."""
    if response.response_status != ocsp.OCSPResponseStatus.SUCCESSFUL:
        return {
            "status": "error",
            "error": msg("cert_revocation.ocsp_refused", reason=response.response_status.name),
        }
    if response.serial_number != leaf.serial_number:
        return {"status": "error", "error": msg("cert_revocation.ocsp_other_certificate")}
    status = response.certificate_status
    info: dict = {
        "status": {
            ocsp.OCSPCertStatus.GOOD: "good",
            ocsp.OCSPCertStatus.REVOKED: "revoked",
        }.get(status, "unknown"),
        "this_update": _iso(response.this_update_utc),
        "next_update": _iso(response.next_update_utc),
    }
    next_update = response.next_update_utc
    info["stale"] = bool(
        next_update is not None and (now - next_update).total_seconds() > CLOCK_MARGIN_SECONDS
    )
    if info["stale"] and info["status"] == "good":
        info["status"] = "unknown"  # une réponse périmée ne prouve rien
    if status == ocsp.OCSPCertStatus.REVOKED:
        info["revoked_at"] = _iso(response.revocation_time_utc)
        reason = response.revocation_reason
        info["reason"] = reason.name if reason is not None else None
    return info


# =============================================================================
# Téléchargements
# =============================================================================


async def _download(client: httpx.AsyncClient, method: str, url: str, limit: int, timeout: float, **kwargs):
    """Corps d'une réponse HTTP 200 borné à `limit` octets ; (corps, None) ou (None, erreur)."""
    try:
        async with client.stream(method, url, timeout=timeout, **kwargs) as response:
            if response.status_code != 200:
                return None, msg("network.http_status", status=response.status_code, service="CA")
            body, truncated = await read_body_limited(response, limit)
    except httpx.TimeoutException:
        return None, msg("net.timeout")
    except (httpx.HTTPError, ValueError) as e:
        # Jamais str(e) : le texte d'une erreur httpx cite l'URL.
        return None, msg("network.service_error", context="CA", detail=type(e).__name__)
    if truncated:
        return None, msg("cert_revocation.too_large")
    return body, None


async def find_issuer(
    leaf: x509.Certificate, others: list[x509.Certificate], client: httpx.AsyncClient | None
) -> x509.Certificate | None:
    """Certificat de l'AC qui a émis `leaf` : dans la chaîne servie, sinon récupéré par AIA (CA Issuers)."""
    for candidate in others:
        if tls_x509.issued_by(leaf, candidate):
            return candidate
    if client is None:
        return None
    for url in tls_x509.issuer_urls(leaf)[:MAX_URLS]:
        if not _http_url(url):
            continue
        body, error = await _download(client, "GET", url, MAX_ISSUER_BYTES, OCSP_TIMEOUT)
        if error is not None or not body:
            continue
        candidates = []
        try:
            candidates = [x509.load_der_x509_certificate(body)]
        except ValueError:
            try:
                candidates = [x509.load_pem_x509_certificate(body)]
            except ValueError:
                try:
                    from cryptography.hazmat.primitives.serialization import pkcs7

                    candidates = pkcs7.load_der_pkcs7_certificates(body)
                except ValueError:
                    candidates = []
        for candidate in candidates:
            if tls_x509.issued_by(leaf, candidate):
                return candidate
    return None


# =============================================================================
# OCSP et CRL
# =============================================================================


async def query_ocsp(
    client: httpx.AsyncClient, leaf: x509.Certificate, issuer: x509.Certificate, urls: list[str]
) -> dict:
    """Interroge les répondeurs OCSP du certificat. `checked` est vrai dès qu'une requête a été tentée."""
    result: dict = {"checked": False, "url": None, "status": None}
    request = (
        ocsp.OCSPRequestBuilder()
        .add_certificate(leaf, issuer, hashes.SHA1())
        .build()
        .public_bytes(Encoding.DER)
    )
    headers = {"Content-Type": "application/ocsp-request", "Accept": "application/ocsp-response"}
    for url in [u for u in urls if _http_url(u)][:MAX_URLS]:
        result.update(checked=True, url=url, status="error")
        body, error = await _download(
            client, "POST", url, MAX_OCSP_BYTES, OCSP_TIMEOUT, content=request, headers=headers
        )
        if error is not None:
            result["error"] = error
            continue
        try:
            response = ocsp.load_der_ocsp_response(body or b"")
        except ValueError:
            result["error"] = msg("cert_revocation.unreadable", source="OCSP")
            continue
        summary = _ocsp_summary(response, leaf, _now())
        result.update(summary)
        if summary["status"] == "error":
            continue
        result.pop("error", None)
        result["signature_ok"] = ocsp_signature_ok(response, issuer)
        return result
    return result


def _parse_crl(body: bytes, leaf: x509.Certificate, issuer: x509.Certificate, now: datetime) -> dict:
    """Analyse (CPU) d'une CRL : signature, fraîcheur, présence du certificat. Exécuté dans un thread."""
    try:
        crl = x509.load_der_x509_crl(body)
    except ValueError:
        try:
            crl = x509.load_pem_x509_crl(body)
        except ValueError:
            return {"status": "error", "error": msg("cert_revocation.unreadable", source="CRL")}
    signature_ok = crl.issuer == issuer.subject and crl.is_signature_valid(issuer.public_key())
    next_update = crl.next_update_utc
    entry = crl.get_revoked_certificate_by_serial_number(leaf.serial_number)
    info: dict = {
        "status": "revoked" if entry is not None else "good",
        "signature_ok": bool(signature_ok),
        "this_update": _iso(crl.last_update_utc),
        "next_update": _iso(next_update),
        "stale": bool(next_update is not None and (now - next_update).total_seconds() > CLOCK_MARGIN_SECONDS),
    }
    if info["stale"] and entry is None:
        info["status"] = "unknown"  # une CRL périmée ne prouve rien
    if entry is not None:
        info["revoked_at"] = _iso(entry.revocation_date_utc)
        try:
            reason = entry.extensions.get_extension_for_class(x509.CRLReason).value.reason
            info["reason"] = reason.name
        except x509.ExtensionNotFound:
            info["reason"] = None
    return info


async def query_crl(
    client: httpx.AsyncClient, leaf: x509.Certificate, issuer: x509.Certificate, urls: list[str]
) -> dict:
    result: dict = {"checked": False, "url": None, "status": None}
    for url in [u for u in urls if _http_url(u)][:MAX_URLS]:
        result.update(checked=True, url=url, status="error")
        body, error = await _download(client, "GET", url, MAX_CRL_BYTES, CRL_TIMEOUT)
        if error is not None:
            result["error"] = error
            continue
        parsed = await asyncio.to_thread(_parse_crl, body or b"", leaf, issuer, _now())
        result.update(parsed)
        if parsed["status"] == "error":
            result["error"] = parsed["error"]
            continue
        result.pop("error", None)
        result["size"] = len(body or b"")
        return result
    return result


# =============================================================================
# Agrafe OCSP
# =============================================================================


def probe_stapling(address: str, port: int, sni: str | None, leaf: x509.Certificate) -> dict:
    """Le serveur agrafe-t-il une réponse OCSP ? Sonde TLS 1.2 (bloquant : à lancer dans un thread).

    supported : True (agrafe reçue), False (aucune) ou None (indéterminé : TLS 1.2 refusé, soit
    un serveur TLS 1.3 seul dont l'agrafe est chiffrée, soit une erreur réseau).
    """
    hello = tls_hello.build_client_hello(
        tls_hello.TLS12, tls_hello.MODERN_TLS12_SUITES, sni, status_request=True
    )
    flight = tls_hello.probe(address, port, hello, timeout=6.0, read_flight=True)
    if not flight.answered or flight.version != tls_hello.TLS12:
        return {"supported": None}
    if not flight.stapled:
        return {"supported": False}
    try:
        response = ocsp.load_der_ocsp_response(flight.stapled)
    except ValueError:
        return {
            "supported": True,
            "status": "error",
            "error": msg("cert_revocation.unreadable", source="OCSP"),
        }
    return {"supported": True, **_ocsp_summary(response, leaf, _now())}


# =============================================================================
# Conclusion
# =============================================================================


def conclude(ocsp_result: dict, crl_result: dict, stapling: dict) -> str:
    """good | revoked | unknown, d'après les sources qui ont répondu (révoqué l'emporte)."""
    states = [ocsp_result.get("status"), crl_result.get("status"), stapling.get("status")]
    if "revoked" in states:
        return "revoked"
    if "good" in states:
        return "good"
    return "unknown"


def short_lived(leaf: x509.Certificate) -> bool:
    not_before, not_after = leaf.not_valid_before_utc, leaf.not_valid_after_utc
    return (not_after - not_before).days <= SHORT_LIVED_MAX_DAYS


def expired(leaf: x509.Certificate) -> bool:
    return leaf.not_valid_after_utc < _now()
