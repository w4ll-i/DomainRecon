# backend/app/scanners/crypto_scanner.py
"""
Crypto Audit — Deep cryptographic certificate analysis.

Uses: ssl + socket (stdlib) + cryptography library (free/open-source).
No external API required.

Checks:
  - Full certificate chain (leaf → intermediate → root)
  - Key type and strength (RSA/EC)
  - Signature algorithm (SHA-1 / MD5 deprecated)
  - SHA-1 and SHA-256 fingerprints
  - Validity period + CA/B Forum 398-day compliance (since 2020)
  - Self-signed detection
  - Wildcard certificate
  - OCSP URL presence
  - Embedded SCTs (Certificate Transparency via TLS extension)
  - Certificate type: EV / OV / DV
  - Incomplete chain detection
"""
import asyncio
import hashlib
import ssl
import socket
from datetime import datetime, timezone
from typing import Optional

try:
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import rsa, ec
    from cryptography.x509.oid import ExtensionOID, NameOID, AuthorityInformationAccessOID
    HAS_CRYPTOGRAPHY = True
except ImportError:
    HAS_CRYPTOGRAPHY = False

_SCT_OID = "1.3.6.1.4.1.11129.2.4.2"

# Known EV policy OIDs (covers major CAs)
_EV_OIDS = {
    "2.23.140.1.1",              # CA/B Forum EV
    "2.16.840.1.114412.2.1",     # DigiCert EV
    "2.16.840.1.114413.1.7.23.3",  # GoDaddy EV
    "2.16.840.1.114414.1.7.23.3",  # Starfield EV
    "1.3.6.1.4.1.6449.1.2.1.5.1",  # Comodo/Sectigo EV
    "2.16.840.1.114028.10.1.2",  # Entrust EV
    "1.3.6.1.4.1.34697.2.1",     # AC Camerfirma EV
    "2.16.840.1.114412.1.3.0.2",  # DigiCert EV (alt)
    "1.2.392.200091.100.721.1",  # SECOM EV
    "2.16.756.1.89.1.2.1.1",     # SwissSign EV
}


# ─── Certificate retrieval ──────────────────────────────────────────────────

def _get_chain_ders(domain: str) -> list:
    """
    Retrieve DER-encoded certificate bytes for the full chain.
    Returns a list: [leaf, intermediate?, root?].
    Falls back to leaf-only if chain retrieval fails.
    """
    ctx = ssl.create_default_context()
    chain_ders = []

    try:
        with socket.create_connection((domain, 443), timeout=10) as sock:
            with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
                # Python 3.10+: get_verified_chain() returns ssl.Certificate objects
                if hasattr(ssock, "get_verified_chain"):
                    enc = getattr(ssl, "ENCODING_DER", None)
                    if enc is not None:
                        for cert_obj in ssock.get_verified_chain():
                            try:
                                chain_ders.append(cert_obj.public_bytes(enc))
                            except Exception:
                                pass

                # Fallback: leaf cert only
                if not chain_ders:
                    leaf = ssock.getpeercert(binary_form=True)
                    if leaf:
                        chain_ders.append(leaf)

    except ssl.SSLCertVerificationError:
        # Self-signed or invalid cert — retrieve anyway (no verification)
        ctx2 = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx2.check_hostname = False
        ctx2.verify_mode = ssl.CERT_NONE
        try:
            with socket.create_connection((domain, 443), timeout=10) as sock:
                with ctx2.wrap_socket(sock, server_hostname=domain) as ssock:
                    leaf = ssock.getpeercert(binary_form=True)
                    if leaf:
                        chain_ders.append(leaf)
        except Exception:
            pass
    except Exception:
        pass

    return chain_ders


# ─── Certificate parsing ────────────────────────────────────────────────────

def _name_attr(name, oid):
    try:
        return name.get_attributes_for_oid(oid)[0].value
    except Exception:
        return None


def _parse_cert(der: bytes, is_leaf: bool = False) -> dict:
    """Parse one DER certificate. Returns a structured dict."""
    if not HAS_CRYPTOGRAPHY:
        # Minimal fallback: fingerprints only
        sha1 = hashlib.sha1(der).hexdigest()
        sha256 = hashlib.sha256(der).hexdigest()
        return {
            "fingerprints": {
                "sha1": ":".join(sha1[i:i+2].upper() for i in range(0, len(sha1), 2)),
                "sha256": ":".join(sha256[i:i+2].upper() for i in range(0, len(sha256), 2)),
            },
            "note": "Install 'cryptography' package for full analysis",
        }

    try:
        cert = x509.load_der_x509_certificate(der)
    except Exception as e:
        return {"parse_error": str(e)[:100]}

    subject = cert.subject
    issuer = cert.issuer

    r: dict = {
        "subject": {
            "cn": _name_attr(subject, NameOID.COMMON_NAME),
            "o":  _name_attr(subject, NameOID.ORGANIZATION_NAME),
            "ou": _name_attr(subject, NameOID.ORGANIZATIONAL_UNIT_NAME),
            "c":  _name_attr(subject, NameOID.COUNTRY_NAME),
        },
        "issuer": {
            "cn": _name_attr(issuer, NameOID.COMMON_NAME),
            "o":  _name_attr(issuer, NameOID.ORGANIZATION_NAME),
            "c":  _name_attr(issuer, NameOID.COUNTRY_NAME),
        },
        "self_signed": (subject == issuer),
        "serial": format(cert.serial_number, "x").upper(),
    }

    # ── Validity ──────────────────────────────────────────────────────────
    try:
        nb = cert.not_valid_before_utc
        na = cert.not_valid_after_utc
    except AttributeError:
        nb = cert.not_valid_before.replace(tzinfo=timezone.utc)
        na = cert.not_valid_after.replace(tzinfo=timezone.utc)

    now = datetime.now(timezone.utc)
    validity_days = (na - nb).days
    days_remaining = (na - now).days

    r["validity"] = {
        "not_before": nb.isoformat(),
        "not_after": na.isoformat(),
        "validity_days": validity_days,
        "days_remaining": days_remaining,
        "expired": days_remaining < 0,
        "expiring_soon": 0 <= days_remaining <= 30,
        "cab_compliant": validity_days <= 398,  # CA/B Forum limit since 2020
    }

    # ── Fingerprints ──────────────────────────────────────────────────────
    sha1_hex = cert.fingerprint(hashes.SHA1()).hex()
    sha256_hex = cert.fingerprint(hashes.SHA256()).hex()
    r["fingerprints"] = {
        "sha1":   ":".join(sha1_hex[i:i+2].upper()   for i in range(0, len(sha1_hex), 2)),
        "sha256": ":".join(sha256_hex[i:i+2].upper() for i in range(0, len(sha256_hex), 2)),
    }

    # ── Signature algorithm ───────────────────────────────────────────────
    sig_alg = cert.signature_hash_algorithm
    alg_name = sig_alg.name.upper() if sig_alg else "UNKNOWN"
    r["signature_algorithm"] = {
        "name": alg_name,
        "weak": alg_name in ("SHA1", "MD5", "MD2"),
    }

    # ── Public key ────────────────────────────────────────────────────────
    pub = cert.public_key()
    if isinstance(pub, rsa.RSAPublicKey):
        bits = pub.key_size
        r["public_key"] = {
            "type": "RSA",
            "bits": bits,
            "secure": bits >= 2048,
            "recommended": bits >= 4096,
        }
    elif isinstance(pub, ec.EllipticCurvePublicKey):
        bits = pub.key_size
        r["public_key"] = {
            "type": "EC",
            "curve": pub.curve.name,
            "bits": bits,
            "secure": bits >= 256,
        }
    else:
        r["public_key"] = {"type": type(pub).__name__, "bits": None, "secure": False}

    # ── Basic Constraints (CA vs end-entity) ──────────────────────────────
    try:
        bc = cert.extensions.get_extension_for_oid(ExtensionOID.BASIC_CONSTRAINTS)
        r["is_ca"] = bc.value.ca
    except Exception:
        r["is_ca"] = False

    # ── Leaf-only extensions ──────────────────────────────────────────────
    if is_leaf:
        # SAN
        try:
            san_ext = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
            sans = list(san_ext.value.get_values_for_type(x509.DNSName))
            r["san"] = sans
            r["wildcard"] = any("*" in s for s in sans)
        except x509.ExtensionNotFound:
            r["san"] = []
            r["wildcard"] = False

        # OCSP + CA Issuers URLs
        try:
            aia = cert.extensions.get_extension_for_oid(ExtensionOID.AUTHORITY_INFORMATION_ACCESS)
            ocsp_urls = [
                desc.access_location.value for desc in aia.value
                if desc.access_method == AuthorityInformationAccessOID.OCSP
            ]
            ca_urls = [
                desc.access_location.value for desc in aia.value
                if desc.access_method == AuthorityInformationAccessOID.CA_ISSUERS
            ]
            r["ocsp_url"] = ocsp_urls[0] if ocsp_urls else None
            r["ca_issuers_url"] = ca_urls[0] if ca_urls else None
        except x509.ExtensionNotFound:
            r["ocsp_url"] = None
            r["ca_issuers_url"] = None

        # SCT / Certificate Transparency (embedded via TLS extension 1.3.6.1.4.1.11129.2.4.2)
        try:
            sct_oid = x509.ObjectIdentifier(_SCT_OID)
            sct_ext = cert.extensions.get_extension_for_oid(sct_oid)
            r["ct_embedded_scts"] = True
            try:
                r["ct_sct_count"] = len(list(sct_ext.value))
            except Exception:
                r["ct_sct_count"] = "present"
        except (x509.ExtensionNotFound, Exception):
            r["ct_embedded_scts"] = False
            r["ct_sct_count"] = 0

        # Certificate type: EV / OV / DV
        try:
            pol_ext = cert.extensions.get_extension_for_oid(ExtensionOID.CERTIFICATE_POLICIES)
            pol_oids = {str(pi.policy_identifier) for pi in pol_ext.value}
            is_ev = bool(pol_oids & _EV_OIDS)
            is_ov = bool(_name_attr(subject, NameOID.ORGANIZATION_NAME)) and not is_ev
            r["certificate_type"] = "EV" if is_ev else ("OV" if is_ov else "DV")
            r["policy_oids"] = list(pol_oids)[:5]
        except x509.ExtensionNotFound:
            is_ov = bool(_name_attr(subject, NameOID.ORGANIZATION_NAME))
            r["certificate_type"] = "OV" if is_ov else "DV"
            r["policy_oids"] = []

    return r


# ─── Main audit logic ───────────────────────────────────────────────────────

def _audit_sync(domain: str) -> dict:
    result: dict = {
        "enriched": False,
        "domain": domain,
        "chain_length": 0,
        "chain": [],
        "leaf": {},
        "issues": [],
        "grade": "F",
        "summary": {},
    }

    chain_ders = _get_chain_ders(domain)
    if not chain_ders:
        result["error"] = "Could not retrieve certificate (connection failed or no TLS)"
        return result

    result["enriched"] = True
    result["chain_length"] = len(chain_ders)

    # Parse each cert in the chain
    chain_info = []
    for i, der in enumerate(chain_ders):
        is_leaf = (i == 0)
        info = _parse_cert(der, is_leaf=is_leaf)
        info["chain_position"] = (
            "leaf" if i == 0
            else ("root" if i == len(chain_ders) - 1 else "intermediate")
        )
        chain_info.append(info)

    result["chain"] = chain_info
    result["leaf"] = chain_info[0] if chain_info else {}

    # ── Issue assessment ──────────────────────────────────────────────────
    issues = []
    leaf = result["leaf"]

    if leaf.get("self_signed"):
        issues.append({"severity": "critical", "message": "Self-signed certificate — not trusted by browsers"})

    val = leaf.get("validity", {})
    if val.get("expired"):
        issues.append({"severity": "critical", "message": "Certificate is EXPIRED"})
    elif val.get("expiring_soon"):
        d = val.get("days_remaining", 0)
        issues.append({"severity": "high", "message": f"Certificate expires in {d} days"})

    if not val.get("cab_compliant", True) and val.get("validity_days", 0) > 0:
        vdays = val.get("validity_days", 0)
        issues.append({"severity": "medium", "message": f"Validity period {vdays} days exceeds 398-day CA/B Forum limit"})

    sig = leaf.get("signature_algorithm", {})
    if sig.get("weak"):
        issues.append({"severity": "critical", "message": f"Weak signature algorithm: {sig.get('name')} (deprecated — use SHA-256 or better)"})

    pk = leaf.get("public_key", {})
    if pk and not pk.get("secure", True):
        issues.append({"severity": "high", "message": f"Weak public key: {pk.get('type')} {pk.get('bits')} bits (min 2048 RSA / 256 EC)"})
    elif pk.get("type") == "RSA" and 2048 <= (pk.get("bits") or 0) < 4096:
        issues.append({"severity": "low", "message": f"RSA {pk.get('bits')} bits — consider upgrading to 4096 for long-term security"})

    if HAS_CRYPTOGRAPHY and not leaf.get("ct_embedded_scts", True):
        issues.append({"severity": "medium", "message": "No embedded SCTs — Certificate Transparency not enforced via TLS extension"})

    if HAS_CRYPTOGRAPHY and not leaf.get("ocsp_url"):
        issues.append({"severity": "low", "message": "No OCSP URL in certificate — online revocation checking unavailable"})

    if leaf.get("wildcard"):
        issues.append({"severity": "info", "message": "Wildcard certificate (*.domain) — valid for all subdomains"})

    if len(chain_ders) == 1 and not leaf.get("self_signed"):
        issues.append({"severity": "medium", "message": "Incomplete chain — intermediate CA certificate not served by server"})

    result["issues"] = issues

    # ── Grade ─────────────────────────────────────────────────────────────
    sevs = {i["severity"] for i in issues}
    if "critical" in sevs:
        grade = "F"
    elif "high" in sevs:
        grade = "D"
    elif "medium" in sevs:
        grade = "C"
    elif "low" in sevs:
        grade = "B"
    else:
        grade = "A"
    result["grade"] = grade

    # ── Summary ───────────────────────────────────────────────────────────
    result["summary"] = {
        "cert_type":      leaf.get("certificate_type", "DV"),
        "key_type":       pk.get("type", "unknown"),
        "key_bits":       pk.get("bits"),
        "sig_alg":        sig.get("name"),
        "days_remaining": val.get("days_remaining"),
        "chain_length":   len(chain_ders),
        "ct_scts":        leaf.get("ct_embedded_scts", False),
        "self_signed":    leaf.get("self_signed", False),
        "wildcard":       leaf.get("wildcard", False),
        "issue_count":    len(issues),
        "grade":          grade,
    }

    return result


async def crypto_audit(domain: str) -> dict:
    """Async wrapper — runs the blocking SSL/crypto audit in a thread pool."""
    loop = asyncio.get_event_loop()
    return await loop.run_in_executor(None, _audit_sync, domain)
