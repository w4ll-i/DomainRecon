# =============================================================================
# DomainRecon - Logique du module « bimi » : logo de marque affiché dans la messagerie
# =============================================================================
# BIMI (Brand Indicators for Message Identification) : TXT default._bimi.<domaine> avec
# v=BIMI1; l=<logo SVG>; a=<certificat VMC/CMC>. Outre la lecture
# du TXT : repli sur le domaine organisationnel, détection du refus explicite
# (l= vide), contrôle du logo (HTTPS, taille, SVG Tiny PS, contenu actif interdit) et du
# certificat (validité, usage BIMI, extension de logotype, nom de domaine couvert).
# Le logo et le certificat sont téléchargés avec le client des API tierces (TLS vérifié,
# aucune redirection, politique anti-SSRF) : ces URL viennent du DNS, donc de la cible.
# =============================================================================

import xml.etree.ElementTree as ET
from datetime import datetime, timezone

import httpx
from cryptography import x509
from cryptography.x509.oid import NameOID

from ...i18n import msg
from ..dns import DnsQuerier, txt_record_text
from ..email_security import parse_tags
from ..errors import TargetNotAllowedError
from ..http_utils import read_body_limited
from .mta_sts import classify_fetch_error

LOGO_MAX_BYTES = 131072
# Taille maximale conseillée du logo SVG (guide BIMI).
LOGO_RECOMMENDED_BYTES = 32768
CERT_MAX_BYTES = 65536
FETCH_TIMEOUT = 10.0
QUERY_TIMEOUT = 3.0
DNS_BUDGET = 15.0
# Alerte avant l'expiration du certificat.
CERT_WARNING_DAYS = 30

# Usage de clé étendu BIMI (id-kp-BrandIndicatorforMessageIdentification) et extension de logotype
# des certificats de marque (RFC 3709, id-pe-logotype).
BIMI_EKU_OID = x509.ObjectIdentifier("1.3.6.1.5.5.7.3.31")
LOGOTYPE_OID = x509.ObjectIdentifier("1.3.6.1.5.5.7.1.12")
# Éléments et attributs qu'un SVG BIMI ne doit pas contenir.
_FORBIDDEN_ELEMENTS = frozenset({"script", "foreignobject", "animate", "set", "style"})

_FETCH_REASONS = {
    "tls": msg("bimi.reason_tls"),
    "timeout": msg("bimi.reason_timeout"),
    "dns": msg("bimi.reason_dns"),
    "blocked": msg("bimi.reason_blocked"),
    "unreachable": msg("bimi.reason_unreachable"),
}


def find_record(querier: DnsQuerier, host: str, apex: str) -> dict:
    """TXT BIMI de `host`, avec repli sur `apex`. {records, source, error}."""
    names = [host] if apex in ("", host) else [host, apex]
    error = None
    for name in names:
        result = querier.lookup(f"default._bimi.{name}", "TXT")
        if result.status == "error":
            error = result.error
            continue
        records = [
            t for t in map(txt_record_text, result.answers) if parse_tags(t).get("v", "").upper() == "BIMI1"
        ]
        if records:
            return {"records": records, "source": name, "error": None}
    return {"records": [], "source": None, "error": error}


async def _download(client: httpx.AsyncClient, url: str, max_bytes: int) -> dict:
    out: dict = {"status": None, "content_type": None, "body": b"", "truncated": False, "reason": None}
    try:
        async with client.stream("GET", url, timeout=FETCH_TIMEOUT) as response:
            out["status"] = response.status_code
            out["content_type"] = response.headers.get("content-type")
            if response.status_code == 200:
                out["body"], out["truncated"] = await read_body_limited(response, max_bytes)
    except (httpx.HTTPError, httpx.InvalidURL, TargetNotAllowedError) as exc:
        out["reason"] = _FETCH_REASONS[classify_fetch_error(exc)]
    return out


# =============================================================================
# Logo
# =============================================================================


def check_logo_svg(body: bytes) -> list[dict]:
    """Défauts du SVG (liste de messages) ; liste vide si le logo est conforme à BIMI."""
    problems: list[dict] = []
    lowered = body[:4096].lower()
    if b"<!doctype" in lowered or b"<!entity" in lowered:
        # Entités et DTD : jamais dans un SVG BIMI, et à ne pas laisser l'analyseur développer.
        return [msg("bimi.logo_forbidden", what="DOCTYPE")]
    try:
        root = ET.fromstring(body)
    except ET.ParseError:
        return [msg("bimi.logo_invalid_xml")]
    tag = root.tag.rsplit("}", 1)[-1].lower()
    if tag != "svg":
        return [msg("bimi.logo_not_svg")]
    if root.get("baseProfile") != "tiny-ps" or root.get("version") != "1.2":
        problems.append(msg("bimi.logo_not_tiny_ps"))
    forbidden = set()
    for element in root.iter():
        name = element.tag.rsplit("}", 1)[-1].lower() if isinstance(element.tag, str) else ""
        if name in _FORBIDDEN_ELEMENTS:
            forbidden.add(name)
        if name == "image":
            forbidden.add("image")
        for attribute in element.attrib:
            local = attribute.rsplit("}", 1)[-1].lower()
            if local.startswith("on"):
                forbidden.add(local)
            elif local == "href" and not str(element.attrib[attribute]).startswith("#"):
                forbidden.add("href")
    if forbidden:
        problems.append(msg("bimi.logo_forbidden", what=sorted(forbidden)))
    box = root.get("viewBox", "").replace(",", " ").split()
    try:
        width, height = float(box[2]), float(box[3])
        if width <= 0 or height <= 0 or abs(width - height) > 0.01 * max(width, height):
            problems.append(msg("bimi.logo_not_square"))
    except (IndexError, ValueError):
        problems.append(msg("bimi.logo_no_viewbox"))
    return problems


async def check_logo(client: httpx.AsyncClient, url: str) -> dict:
    """Télécharge et contrôle le logo. {url, fetched, status, size, content_type, valid, issues}."""
    info: dict = {"url": url, "fetched": False, "status": None, "size": None, "content_type": None,
                  "valid": False, "issues": []}  # fmt: skip
    if not url.lower().startswith("https://"):
        info["issues"].append(msg("bimi.logo_not_https"))
        return info
    download = await _download(client, url, LOGO_MAX_BYTES)
    info.update(status=download["status"], content_type=download["content_type"])
    if download["reason"] is not None:
        info["issues"].append(msg("bimi.logo_fetch_failed", reason=download["reason"]))
        return info
    if download["status"] != 200:
        info["issues"].append(msg("bimi.logo_fetch_status", status=download["status"]))
        return info
    info.update(fetched=True, size=len(download["body"]))
    if download["truncated"] or info["size"] > LOGO_RECOMMENDED_BYTES:
        info["issues"].append(msg("bimi.logo_too_big", size=info["size"], max=LOGO_RECOMMENDED_BYTES))
    content_type = (download["content_type"] or "").split(";")[0].strip().lower()
    if content_type != "image/svg+xml":
        info["issues"].append(msg("bimi.logo_bad_type", content_type=content_type or "?"))
    if not download["truncated"]:
        info["issues"].extend(check_logo_svg(download["body"]))
    info["valid"] = not info["issues"]
    return info


# =============================================================================
# Certificat (VMC / CMC)
# =============================================================================


def _name_attribute(name: x509.Name, oid) -> str | None:
    values = name.get_attributes_for_oid(oid)
    return str(values[0].value) if values else None


def analyze_certificate(pem: bytes, domains: list[str], now: datetime | None = None) -> dict:
    """Caractéristiques du certificat de marque (premier certificat du PEM) et ses défauts."""
    now = now or datetime.now(timezone.utc)
    try:
        certificates = x509.load_pem_x509_certificates(pem)
    except ValueError:
        certificates = []
    if not certificates:
        return {"readable": False, "issues": [msg("bimi.vmc_unreadable")]}
    leaf = certificates[0]
    issues: list[dict] = []
    not_after = leaf.not_valid_after_utc
    days_left = (not_after - now).days
    if now < leaf.not_valid_before_utc:
        issues.append(msg("bimi.vmc_not_yet_valid"))
    if now > not_after:
        issues.append(msg("bimi.vmc_expired", date=not_after.date().isoformat()))
    elif days_left <= CERT_WARNING_DAYS:
        issues.append(msg("bimi.vmc_expiring", days=days_left))
    try:
        eku = leaf.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
        has_bimi_eku = BIMI_EKU_OID in eku
    except x509.ExtensionNotFound:
        has_bimi_eku = False
    if not has_bimi_eku:
        issues.append(msg("bimi.vmc_no_bimi_usage"))
    try:
        leaf.extensions.get_extension_for_oid(LOGOTYPE_OID)
        has_logotype = True
    except x509.ExtensionNotFound:
        has_logotype = False
    try:
        san = leaf.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
        names = [n.lower() for n in san.get_values_for_type(x509.DNSName)]
    except x509.ExtensionNotFound:
        names = []
    if not _covers(names, domains):
        issues.append(msg("bimi.vmc_domain_mismatch"))
    return {
        "readable": True,
        "subject_org": _name_attribute(leaf.subject, NameOID.ORGANIZATION_NAME),
        "issuer_org": _name_attribute(leaf.issuer, NameOID.ORGANIZATION_NAME),
        "not_after": not_after.date().isoformat(),
        "days_left": days_left,
        "bimi_usage": has_bimi_eku,
        "has_logotype": has_logotype,
        "names": names[:10],
        "issues": issues,
    }


def _covers(names: list[str], domains: list[str]) -> bool:
    """L'un des domaines (le domaine de l'expéditeur ou son domaine organisationnel) est couvert par le SAN."""
    for domain in (d.lower() for d in domains):
        for name in names:
            if name == domain or (name.startswith("*.") and domain.endswith(name[1:]) and domain != name[2:]):
                return True
    return False


async def check_certificate(client: httpx.AsyncClient, url: str, domains: list[str]) -> dict:
    """Télécharge et contrôle le certificat de marque. {url, fetched, status, valid, issues, …}."""
    info: dict = {"url": url, "fetched": False, "status": None, "valid": False, "issues": []}
    if not url.lower().startswith("https://"):
        info["issues"].append(msg("bimi.vmc_not_https"))
        return info
    download = await _download(client, url, CERT_MAX_BYTES)
    info["status"] = download["status"]
    if download["reason"] is not None:
        info["issues"].append(msg("bimi.vmc_fetch_failed", reason=download["reason"]))
        return info
    if download["status"] != 200:
        info["issues"].append(msg("bimi.vmc_fetch_status", status=download["status"]))
        return info
    info["fetched"] = True
    details = analyze_certificate(download["body"], domains)
    info["issues"] = details.pop("issues")
    info.update(details)
    info["valid"] = bool(info.get("readable")) and not info["issues"]
    return info


# =============================================================================
# Évaluation
# =============================================================================


def dmarc_enforced(email_security: object) -> bool | None:
    """DMARC appliqué (quarantine ou reject sur 100 % des messages) d'après email_security ; None si inconnu."""
    if not isinstance(email_security, dict) or email_security.get("measured") is False:
        return None
    dmarc = email_security.get("dmarc")
    if not isinstance(dmarc, dict) or dmarc.get("found") is None:
        return None
    pct = dmarc.get("pct")
    return dmarc.get("policy") in ("quarantine", "reject") and (pct is None or pct == 100)


def empty_result(domain: str) -> dict:
    return {
        "measured": True,
        "error": None,
        "domain": domain,
        "found": False,
        "declined": False,
        "source_domain": None,
        "record": None,
        "logo_url": None,
        "vmc_url": None,
        "logo": None,
        "vmc": None,
        "dmarc_enforced": None,
        "issues": [],
    }


async def evaluate(
    client: httpx.AsyncClient, domain: str, apex: str, found: dict, enforced: bool | None
) -> dict:
    """Résultat du module à partir du TXT trouvé (find_record) ; télécharge logo et certificat."""
    result = empty_result(domain)
    if found["error"] is not None and not found["records"]:
        result.update(measured=False, error=msg("bimi.query_failed", error=found["error"]))
        return result
    if not found["records"]:
        return result
    record = found["records"][0]
    tags = parse_tags(record)
    logo_url = tags.get("l", "").strip()
    vmc_url = tags.get("a", "").strip()
    issues = result["issues"]
    result.update(
        found=True,
        record=record,
        source_domain=found["source"],
        logo_url=logo_url or None,
        vmc_url=vmc_url or None,
        dmarc_enforced=enforced,
    )
    if len(found["records"]) > 1:
        issues.append(msg("bimi.record_multiple", count=len(found["records"])))
    if not logo_url:
        # « v=BIMI1; l=; » : refus explicite d'afficher un logo (BIMI désactivé).
        result["declined"] = True
        return result
    if enforced is False:
        issues.append(msg("bimi.dmarc_not_enforced"))
    domains = [d for d in {domain, apex, found["source"]} if d]
    result["logo"] = await check_logo(client, logo_url)
    issues.extend(result["logo"]["issues"])
    if vmc_url:
        result["vmc"] = await check_certificate(client, vmc_url, domains)
        issues.extend(result["vmc"]["issues"])
    else:
        issues.append(msg("bimi.no_vmc"))
    return result
