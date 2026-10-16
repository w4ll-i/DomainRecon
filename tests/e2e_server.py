# =============================================================================
# DomainRecon - Serveur de test de bout en bout (Playwright)
# =============================================================================
# Lancé par frontend/playwright.config.ts :
#     python tests/e2e_server.py --port 8765
# Sert l'interface construite (domainrecon/web) avec une base SQLite seedée et
# un faux scanner (aucun accès réseau). Tout est écrit dans un dossier
# temporaire, supprimé à l'arrêt (sauf --keep-data) ; les dossiers laissés par
# un arrêt brutal (Windows) sont purgés au lancement suivant. Les valeurs sont
# des données de démonstration, cohérentes entre elles mais inventées.
#
# Comme le vrai scanner, les résultats portent des messages traduisibles
# (domainrecon.i18n.msg, codes du catalogue) que l'API rend dans la langue
# demandée ; seul le scan « legacy » (ancien format) garde des textes bruts.
# La note vient du vrai barème (domainrecon.scanner.score) appliqué aux
# données simulées : détail des critères, pénalités et couverture concordent.
# =============================================================================

from __future__ import annotations

import argparse
import asyncio
import functools
import os
import shutil
import signal
import struct
import sys
import tempfile
import time
import zlib
from collections.abc import Awaitable, Callable, Iterable
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from sqlalchemy.orm import Session

ROOT = Path(__file__).resolve().parents[1]

# Ordre de module_status (domainrecon/scanner/orchestrator.py, MODULE_NAMES).
MODULE_NAMES = (
    "dns_records",
    "subdomains",
    "security_headers",
    "tls_certificate",
    "technologies",
    "geo_data",
    "whois_data",
    "open_ports",
    "email_security",
    "waf",
    "redirect_chain",
    "web_files",
    "cookie_security",
    "cors",
    "reverse_dns",
    "network_extended",
    "screenshot",
    "subdomain_takeover",
)

SCREENSHOT_NAME = "example_com_1700000000.png"
FILLER_COUNT = 30

# Préfixe des dossiers de données temporaires et âge à partir duquel un dossier
# d'un lancement précédent est jugé abandonné (secondes).
DATA_DIR_PREFIX = "domainrecon-e2e-"
STALE_AFTER = 3600.0

_IP = "93.184.216.34"
# Délai de l'orchestrateur (MODULE_TIMEOUT), repris dans le message « délai dépassé ».
_MODULE_TIMEOUT = "60"
_DKIM_SELECTORS = ["default", "google", "selector1", "selector2"]


def _msg(code: str, **params: Any) -> dict:
    """Message traduisible du catalogue (import tardif : l'environnement est posé avant domainrecon)."""
    from domainrecon.i18n import msg

    return msg(code, **params)


def configure_environment(data_dir: Path, port: int) -> None:
    """Réglages du serveur E2E, posés AVANT tout import de domainrecon.

    Une valeur vide vaut « réglage absent » (config.env_str) et load_dotenv ne
    remplace pas une variable déjà posée : le .env d'un développeur ne change
    donc rien au serveur E2E.
    """
    data_dir.mkdir(parents=True, exist_ok=True)
    os.environ.update(
        {
            "DATA_DIR": str(data_dir),
            "DATABASE_URL": f"sqlite:///{(data_dir / 'e2e.db').as_posix()}",
            "PORT": str(port),
            "API_TOKEN": "",
            "ALLOW_PRIVATE_TARGETS": "0",
            "MAX_CONCURRENT_SCANS": "4",
            "DOMAINRECON_PORTABLE": "0",
            "LOG_LEVEL": "WARNING",
            "ALLOWED_HOSTS": "",
            "CORS_ORIGINS": "",
            "API_DOCS": "",
        }
    )


def purge_stale_data_dirs(max_age: float = STALE_AFTER, root: Path | None = None) -> int:
    """Supprime les dossiers de données de lancements précédents, âgés de plus de `max_age` secondes.

    Sous Windows, Playwright arrête le serveur de force : son `finally` ne
    s'exécute pas et le dossier temporaire reste. Renvoie le nombre de dossiers supprimés.
    """
    root = root or Path(tempfile.gettempdir())
    limit = time.time() - max_age
    removed = 0
    for path in root.glob(f"{DATA_DIR_PREFIX}*"):
        try:
            if not path.is_dir() or path.stat().st_mtime >= limit:
                continue
            shutil.rmtree(path, ignore_errors=True)
        except OSError:
            continue
        if not path.exists():
            removed += 1
    return removed


# =============================================================================
# Résultats de scan simulés
# =============================================================================


def _module_status(subdomain_count: int, source: str = "crt.sh", **exceptions: dict) -> dict:
    """module_status d'un scan abouti ; les exceptions remplacent l'état d'un module.

    Comme l'orchestrateur : `subdomains` porte total_found, source et partial,
    et la capture est sans objet quand Playwright ou Chromium manque.
    """
    statuses: dict[str, dict] = {name: {"status": "ok", "error": None} for name in MODULE_NAMES}
    statuses["subdomains"].update(total_found=subdomain_count, source=source, partial=source == "certspotter")
    statuses["screenshot"] = {"status": "skipped", "error": _msg("orchestrator.skip_no_playwright")}
    statuses.update(exceptions)
    return statuses


def _unmeasured(error: dict) -> dict:
    """Valeur enregistrée d'un module sans résultat (orchestrator._placeholder)."""
    return {"measured": False, "error": error}


def _security_headers(domain: str, compliant: int) -> dict:
    """En-têtes de sécurité dont `compliant` (0 à 6) sont conformes.

    Ils le deviennent dans l'ordre X-Frame-Options, X-Content-Type-Options,
    Referrer-Policy, HSTS, Permissions-Policy, CSP : 3 = sans HSTS, 4 = avec.
    Valeurs et explications au format de domainrecon.scanner.headers.
    """
    protective = {
        "Strict-Transport-Security": (
            "max-age=63072000; includeSubDomains",
            _msg("headers.hsts_ok_subdomains", max_age=63072000),
        ),
        "X-Frame-Options": ("DENY", "DENY"),
        "X-Content-Type-Options": ("nosniff", "nosniff"),
        "Content-Security-Policy": ("default-src 'self'", _msg("headers.csp_ok")),
        "Referrer-Policy": ("strict-origin-when-cross-origin", "strict-origin-when-cross-origin"),
        "Permissions-Policy": ("geolocation=()", _msg("headers.present")),
    }
    order = (
        "X-Frame-Options",
        "X-Content-Type-Options",
        "Referrer-Policy",
        "Strict-Transport-Security",
        "Permissions-Policy",
        "Content-Security-Policy",
    )
    conforming = set(order[:compliant])
    checks: dict[str, dict] = {}
    found: dict[str, str] = {}
    for header, (value, detail) in protective.items():
        if header in conforming:
            checks[header] = {"value": value, "status": "ok", "detail": detail}
            found[header] = value
        else:
            checks[header] = {"value": None, "status": "missing", "detail": _msg("headers.missing")}
    return {
        "headers_found": found,
        "headers_missing": [header for header in protective if header not in found],
        "score": f"{compliant}/6",
        "counts": {"ok": compliant, "weak": 0, "invalid": 0, "missing": 6 - compliant, "total": 6},
        "checks": checks,
        "url": f"https://{domain}/",
        "https": True,
        "https_downgrade": False,
        "off_site_redirect": None,
        "measured": True,
        "error": None,
    }


def _email_security(domain: str, grade: str) -> dict:
    """Analyse email de note globale B, C ou D (SPF, DMARC et DKIM cohérents avec cette note)."""
    strict = grade == "B"
    enforced = grade in ("B", "C")
    spf_record = "v=spf1 include:_spf.example.net ~all" if strict else "v=spf1 ?all"
    policy = "quarantine" if enforced else "none"
    recommendations = []
    if not strict:
        recommendations.append(_msg("email.rec_end_spf"))
    if not enforced:
        recommendations.append(_msg("email.rec_dmarc_enforce"))
    recommendations.append(_msg("email.rec_check_dkim"))
    return {
        "domain": domain,
        "dmarc_domain": domain,
        "null_mx": False,
        "spf": {
            "domain": domain,
            "apex_domain": None,
            "apex_record": None,
            "found": True,
            "record": spf_record,
            "records": [spf_record],
            "all": "~all" if strict else "?all",
            "dns_lookups": 1 if strict else 0,
            "issues": [_msg("email.spf_softfail" if strict else "email.spf_neutral")],
            "grade": "B" if strict else "D",
            "error": None,
        },
        "dmarc": {
            "found": True,
            "record": f"v=DMARC1; p={policy}; rua=mailto:dmarc@{domain}",
            "policy": policy,
            "subdomain_policy": None,
            "pct": None,
            "source": f"_dmarc.{domain}",
            "inherited": False,
            "issues": [] if enforced else [_msg("email.dmarc_none")],
            "grade": "B" if enforced else "D",
            "error": None,
        },
        "dkim": {
            "found": False,
            "selectors_found": [],
            "revoked_selectors": [],
            "selectors_tested": _DKIM_SELECTORS,
            "wildcard": None,
            "issues": [_msg("email.dkim_missing")],
            "error": None,
        },
        "mta_sts": {"found": False, "record": None, "error": None},
        "tls_rpt": {"found": False, "record": None, "error": None},
        "overall_grade": grade,
        "recommendations": recommendations,
        "notes": [],
        "measured": True,
        "partial": False,
        "error": None,
    }


def _cookie_security(domain: str, defects: int) -> dict:
    """Cookies de session et de préférences, `defects` (0 à 6) attributs de sécurité en moins.

    Analysé par le vrai module (analyze_cookie_headers) : défauts et note
    (0 : A, 1 : B, 2 et 3 : C, 4 et 5 : D, 6 : F) sont ceux du scanner.
    """
    from domainrecon.scanner.cookies import analyze_cookie_headers

    cookies = [
        ["session=x1", "Secure", "HttpOnly", "SameSite=Lax"],
        ["prefs=dark", "Secure", "HttpOnly", "SameSite=Lax"],
    ]
    # (cookie, attribut retiré), dans l'ordre où les défauts apparaissent.
    removals = [
        (1, "HttpOnly"),
        (1, "SameSite=Lax"),
        (1, "Secure"),
        (0, "SameSite=Lax"),
        (0, "HttpOnly"),
        (0, "Secure"),
    ]
    for index, attribute in removals[:defects]:
        cookies[index].remove(attribute)
    result = analyze_cookie_headers(["; ".join([parts[0], "Path=/", *parts[1:]]) for parts in cookies])
    result.update(measured=True, error=None, url=f"https://{domain}/", off_site_redirect=None)
    return result


def _good(
    domain: str,
    ip: str,
    a_records: list[str],
    headers_ok: int = 4,
    email_grade: str = "B",
    cookie_defects: int = 1,
) -> dict:
    """Scan « propre » (note B, 84/100 par défaut) : aucun module en échec, note non calculée."""
    email = _email_security(domain, email_grade)
    subdomains = [
        {"subdomain": f"www.{domain}", "ip": ip, "resolution": "resolved"},
        {"subdomain": f"old.{domain}", "ip": None, "resolution": "unresolved"},
    ]
    return {
        "domain": domain,
        "ip_address": ip,
        "dns_records": {
            "A": a_records,
            "AAAA": [],
            "MX": [{"priority": 10, "value": f"mail.{domain}"}],
            "NS": ["a.iana-servers.net", "b.iana-servers.net"],
            "TXT": [email["spf"]["record"]],
            "CNAME": [],
            "SOA": [{"mname": "ns.icann.org", "rname": "noc.dns.icann.org", "serial": 2024}],
            "DMARC": [email["dmarc"]["record"]],
            "dmarc_source": f"_dmarc.{domain}",
            "errors": {},
            "nxdomain": False,
            "wildcard": False,
            "notes": [],
            "measured": True,
            "error": None,
        },
        "subdomains": subdomains,
        "security_headers": _security_headers(domain, headers_ok),
        "whois_data": {
            "queried_domain": domain,
            "registrar": "Registrar de démonstration",
            "creation_date": "1995-08-14",
            "expiration_date": "2027-08-13",
            "updated_date": "2025-08-14",
            "name_servers": ["a.iana-servers.net"],
            "status": ["clientDeleteProhibited"],
            "dnssec": "signedDelegation",
            "registrant": None,
            "emails": [],
            "registered": True,
            "measured": True,
            "error": None,
        },
        "geo_data": {
            "ip": ip,
            "country": "US",
            "country_code": "US",
            "region": "Massachusetts",
            "city": "Norwell",
            "zip": "",
            "lat": 42.15,
            "lon": -70.82,
            "timezone": "America/New_York",
            "isp": "Edgecast Inc.",
            "org": "Edgecast Inc.",
            "as_info": "AS15133 Edgecast Inc.",
            "anycast": False,
            "measured": True,
            "error": None,
        },
        "tls_certificate": {
            "measured": True,
            "https": True,
            "valid": True,
            "verify_error": None,
            "verify_code": None,
            "error": None,
            "subject": f"www.{domain}",
            "issuer_org": "DigiCert Inc",
            "issuer_cn": "DigiCert Global G2",
            "serial_number": "0A1B2C",
            "version": 3,
            "not_before": "Jan 30 00:00:00 2026 GMT",
            "not_after": "Mar  1 23:59:59 2027 GMT",
            "days_remaining": 154,
            "san": [f"www.{domain}", domain],
            "protocol": "TLSv1.3",
            "cipher": "TLS_AES_256_GCM_SHA384",
            "cipher_bits": 256,
        },
        "technologies": [{"name": "Nginx", "category": _msg("tech.cat_web_server")}],
        "open_ports": [
            {"port": 80, "state": "open", "service": "HTTP"},
            {"port": 443, "state": "open", "service": "HTTPS"},
        ],
        "email_security": email,
        "waf": {
            "measured": True,
            "error": None,
            "detected": False,
            "waf_name": None,
            "confidence": "none",
            "evidence": [],
            "cdn_detected": False,
            "cdn_name": None,
            "cdn_evidence": [],
        },
        "redirect_chain": {
            "chain": [
                {"url": f"http://{domain}/", "status_code": 301, "server": "nginx", "same_site": True},
                {"url": f"https://{domain}/", "status_code": 200, "server": "nginx", "same_site": True},
            ],
            "total_hops": 1,
            "forces_https": True,
            "final_url": f"https://{domain}/",
            "leaves_site": False,
            "https_chain": [
                {"url": f"https://{domain}/", "status_code": 200, "server": "nginx", "same_site": True}
            ],
            "https_downgrade": False,
            "http_available": True,
            "https_available": True,
            "warnings": [],
            "measured": True,
            "error": None,
        },
        "web_files": {
            "measured": True,
            "partial": False,
            "error": None,
            "robots_txt": {
                "found": True,
                "content": "User-agent: *\nDisallow: /admin",
                "disallowed": ["/admin"],
                "sitemaps": [],
                "error": None,
            },
            "sitemap_xml": {"found": True, "url_count": 42, "error": None},
            "security_txt": {"found": False, "content": None, "contact": None, "error": None},
        },
        "cookie_security": _cookie_security(domain, cookie_defects),
        "cors": {
            "cors_enabled": False,
            "misconfigured": False,
            "allows_any_origin": False,
            "allows_credentials_with_wildcard": False,
            "reflects_origin": False,
            "reflects_with_credentials": False,
            "reflected_origin": None,
            "severity": None,
            "details": [],
            "url": f"https://{domain}/",
            "off_site_redirect": None,
            "origin_tests": {"total": 4, "succeeded": 4, "errors": []},
            "partial": False,
            "measured": True,
            "error": None,
        },
        "reverse_dns": {"ptr": f"host.{domain}", "aliases": [], "measured": True, "error": None},
        "subdomain_takeover": [],
        "network_extended": {
            "measured": True,
            "error": None,
            "reverse_ip_neighbors": ["example.net", "example.org"],
            "neighbors_total": 2,
            "neighbors_truncated": False,
            "neighbors_error": None,
            "asn_info": {"asn": "AS15133", "org": "Edgecast Inc.", "hostname": None, "anycast": False},
            "asn_error": None,
        },
        "module_status": _module_status(len(subdomains)),
        "scan_duration": 21.7,
        "screenshot_path": None,
        "status": "success",
        "error_message": None,
    }


def _weak(domain: str) -> dict:
    """Scan faible (note F : 49 points, moins 15 de pénalités de ports) aux constats multiples."""
    result = _good(domain, _IP, [_IP], headers_ok=3, email_grade="D", cookie_defects=4)
    result["tls_certificate"]["days_remaining"] = 20
    result["cors"].update(
        cors_enabled=True,
        misconfigured=True,
        reflects_origin=True,
        reflected_origin="https://evil.com",
        severity="low",
        details=[_msg("cors.reflect_third_party", origin="https://evil.com")],
    )
    http_hop = {"url": f"http://{domain}/", "status_code": 200, "server": "nginx", "same_site": True}
    result["redirect_chain"].update(
        chain=[http_hop],
        total_hops=0,
        forces_https=False,
        final_url=f"http://{domain}/",
        https_chain=[{**http_hop, "url": f"https://{domain}/"}],
    )
    result["subdomains"].append({"subdomain": f"blog.{domain}", "ip": None, "resolution": "unresolved"})
    result["module_status"] = _module_status(len(result["subdomains"]))
    result["subdomain_takeover"] = [
        {
            "subdomain": f"blog.{domain}",
            "cname": "blog-demo.herokuapp.com",
            "service": "heroku",
            "provider": "Heroku",
            "risk": "low",
            "confirmed": False,
            "fingerprint_matched": False,
            "cname_nxdomain": False,
            "status_code": None,
            "evidence": _msg("takeover.no_response", service="Heroku"),
        }
    ]
    result["open_ports"] = [
        {"port": 21, "state": "open", "service": "FTP"},
        {"port": 80, "state": "open", "service": "HTTP"},
        {"port": 443, "state": "open", "service": "HTTPS"},
        {"port": 3306, "state": "open", "service": "MySQL"},
    ]
    result["geo_data"].update(
        country="FR",
        country_code="FR",
        region="Île-de-France",
        city="Paris",
        lat=48.85,
        lon=2.35,
        timezone="Europe/Paris",
    )
    return result


def _legacy(domain: str) -> dict:
    """Scan d'une ancienne version : textes bruts, ni module_status ni verdicts d'en-têtes."""
    return {
        "domain": domain,
        "ip_address": "203.0.113.7",
        "dns_records": {"A": ["203.0.113.7"]},
        "subdomains": [{"subdomain": f"www.{domain}", "ip": "203.0.113.7"}],
        "security_headers": {"headers_found": {"X-Frame-Options": "DENY"}, "score": "1/6"},
        "whois_data": {"registrar": "Ancien registrar"},
        "geo_data": {"country": "FR", "city": "Paris", "lat": 48.85, "lon": 2.35},
        "tls_certificate": {"error": "certificate verify failed: self signed certificate"},
        "open_ports": [{"port": 443, "state": "open", "service": "HTTPS"}],
        "technologies": [],
        "email_security": {
            "overall_grade": "C",
            "spf": {"found": True, "record": "v=spf1 ~all"},
            "dmarc": {"found": False},
        },
        "waf": {"detected": False},
        "redirect_chain": {
            "chain": [{"url": f"http://{domain}/", "status_code": 200}],
            "forces_https": False,
        },
        "security_score": {"score": 40, "grade": "D"},
        "scan_duration": 30.2,
        "status": "success",
        "error_message": None,
    }


def _with_score(result: dict) -> dict:
    """Ajoute la note calculée par le vrai barème sur les données simulées (modifie `result`)."""
    from domainrecon.scanner.score import compute_security_score

    result["security_score"] = compute_security_score(
        {
            "security_headers": result["security_headers"],
            "tls_certificate": result["tls_certificate"],
            "email_security": result["email_security"],
            "waf": result["waf"],
            "cookie_security": result["cookie_security"],
            "cors": result["cors"],
            "redirect_chain": result["redirect_chain"],
            "subdomain_takeover": result["subdomain_takeover"],
            "subdomains_checked": len(result["subdomains"]),
            "open_ports": result["open_ports"],
            "is_ip_target": False,
            "module_status": result["module_status"],
        }
    )
    return result


@functools.cache
def _settings_for(score: int, grade: str) -> tuple[int, str, int]:
    """Réglages de _good (en-têtes conformes, note email, défauts de cookies) qui donnent cette note.

    Le vrai barème décide : on essaie toutes les combinaisons et on garde la
    plus proche du scan « propre » (4, « B », 1).
    """
    best: tuple[int, tuple[int, str, int]] | None = None
    for headers_ok in range(7):
        for email_rank, email_grade in enumerate(("B", "C", "D")):
            for cookie_rank, defects in enumerate((1, 0, 2, 4, 6)):
                trial = _with_score(_good("example.com", _IP, [_IP], headers_ok, email_grade, defects))
                if (trial["security_score"]["score"], trial["security_score"]["grade"]) != (score, grade):
                    continue
                distance = abs(headers_ok - 4) + email_rank + cookie_rank
                if best is None or distance < best[0]:
                    best = (distance, (headers_ok, email_grade, defects))
    if best is None:
        raise ValueError(f"Note {score} {grade} hors de portée des données simulées")
    return best[1]


def build_scan_result(
    domain: str,
    variant: str = "good",
    a_records: list[str] | None = None,
    score: tuple[int, str] | None = None,
) -> dict:
    """Résultat au format de perform_full_scan() (colonnes du modèle Scan).

    Variantes : good (note B), weak (note F), partial (WHOIS en échec, réseau
    étendu hors délai, sous-domaines Cert Spotter partiels), live (réseau
    étendu hors délai : le faux scanner) et legacy (ancien format, textes bruts).
    `score` règle la note par les données (en-têtes, email, cookies) ; la
    variante weak, dont les données fixent la note, le refuse.
    """
    if variant == "legacy":
        return _legacy(domain)
    if variant == "weak":
        if score is not None:
            raise ValueError("La variante weak a sa propre note")
        return _with_score(_weak(domain))
    if variant not in ("good", "partial", "live"):
        raise ValueError(f"Variante inconnue : {variant}")

    settings = _settings_for(*score) if score is not None else (4, "B", 1)
    result = _good(domain, _IP, list(a_records or [_IP]), *settings)
    if variant == "good":
        return _with_score(result)

    # partial et live : le réseau étendu dépasse son délai, comme dans l'orchestrateur.
    timeout = _msg("orchestrator.timeout", seconds=_MODULE_TIMEOUT)
    result["network_extended"] = _unmeasured(timeout)
    failures = {"network_extended": {"status": "timeout", "error": timeout}}
    problems: list[Any] = [_msg("orchestrator.problem_timeout", name="network_extended")]
    source = "crt.sh"
    if variant == "partial":
        unreachable = _msg("whois.server_unreachable")
        result["whois_data"] = _unmeasured(unreachable)
        failures["whois_data"] = {"status": "failed", "error": unreachable}
        problems.insert(0, "whois_data")
        source = "certspotter"
    result["module_status"] = _module_status(len(result["subdomains"]), source, **failures)
    result.update(
        status="partial",
        error_message=_msg("orchestrator.modules_failed", count=len(problems), modules=problems, sep=", "),
    )
    return _with_score(result)


def _png(width: int, height: int) -> bytes:
    """PNG uni (couleur accent), valide, sans dépendance."""

    def chunk(kind: bytes, data: bytes) -> bytes:
        return (
            struct.pack(">I", len(data))
            + kind
            + data
            + struct.pack(">I", zlib.crc32(kind + data) & 0xFFFFFFFF)
        )

    row = b"\x00" + bytes((0x58, 0xA6, 0xFF)) * width
    header = struct.pack(">IIBBBBB", width, height, 8, 2, 0, 0, 0)
    return (
        b"\x89PNG\r\n\x1a\n"
        + chunk(b"IHDR", header)
        + chunk(b"IDAT", zlib.compress(row * height))
        + chunk(b"IEND", b"")
    )


def seed_database(session_factory: Callable[[], Session], screenshots_dir: Path) -> dict[str, list[int]]:
    """Remplit la base ; renvoie les identifiants par domaine (ordre chronologique)."""
    from domainrecon.core.models import Scan
    from domainrecon.i18n import dumps_message

    now = datetime.now(timezone.utc).replace(tzinfo=None)
    screenshots_dir.mkdir(parents=True, exist_ok=True)
    (screenshots_dir / SCREENSHOT_NAME).write_bytes(_png(64, 36))

    latest = build_scan_result("example.com", a_records=["93.184.216.34"])
    latest["screenshot_path"] = SCREENSHOT_NAME
    latest["module_status"]["screenshot"] = {"status": "ok", "error": None}

    plan: list[tuple[dict, datetime, dict]] = [
        (
            build_scan_result(f"filler-{i:02d}.example.net", score=(70, "C")),
            now - timedelta(days=400, hours=i),
            {},
        )
        for i in range(1, FILLER_COUNT + 1)
    ]
    plan += [
        (build_scan_result("legacy.example.org", variant="legacy"), now - timedelta(days=200), {}),
        (
            build_scan_result("example.com", a_records=["93.184.216.30"], score=(62, "C")),
            now - timedelta(days=30),
            {},
        ),
        (build_scan_result("delete-me.example.org"), now - timedelta(days=20), {}),
        (
            build_scan_result("example.com", a_records=["93.184.216.34", "93.184.216.35"], score=(71, "C")),
            now - timedelta(days=10),
            {},
        ),
        (build_scan_result("partial.example.net", variant="partial"), now - timedelta(days=5), {}),
        (build_scan_result("shop.example.com", variant="weak"), now - timedelta(days=3), {}),
        (latest, now - timedelta(days=1), {"tags": ["prod"], "notes": "Scan de démonstration"}),
    ]

    ids: dict[str, list[int]] = {}
    with session_factory() as db:
        for result, when, meta in plan:
            # Colonne TEXT : un message y est rangé en JSON, comme le fait storage.save_scan().
            values = {**result, "error_message": dumps_message(result["error_message"])}
            scan = Scan(**values, scan_timestamp=when, **meta)
            db.add(scan)
            db.flush()
            ids.setdefault(result["domain"], []).append(scan.id)
        db.commit()
    return ids


def make_fake_scanner(step_delay: float = 0.12, slow_delay: float = 1.0) -> Callable[..., Awaitable[dict]]:
    """Faux perform_full_scan : les modules du profil annoncés un à un (16 par défaut), sans réseau.

    Même signature que le vrai scanner : le profil, la sélection, l'autorisation
    et les clés API donnent les modules annoncés (registry.get_modules), de sorte
    que la progression suive le plan de la tâche. « slow.* » avance lentement
    (annulation), « boom.* » tombe en panne au quatrième module (échec interne) ;
    les autres cibles aboutissent.
    """

    async def fake_perform_full_scan(
        url_or_domain: str,
        on_module: Callable[[str, str, float], None] | None = None,
        profile: str = "complet",
        authorized_target: bool = False,
        *,
        selected: Iterable[str] | None = None,
        available_keys: Iterable[str] = (),
    ) -> dict:
        from domainrecon.scanner.registry import get_modules  # import tardif : l'environnement est posé avant

        domain = url_or_domain.strip().lower()
        delay = slow_delay if domain.startswith("slow.") else step_delay
        result = build_scan_result(domain, variant="live")
        names = [spec.name for spec in get_modules(profile, available_keys, authorized_target, selected)]
        for index, name in enumerate(names):
            await asyncio.sleep(delay)
            if domain.startswith("boom.") and index == 3:
                raise RuntimeError("Panne simulée du scanner (E2E)")
            if on_module is not None:
                status = result["module_status"].get(name, {"status": "ok"})["status"]
                on_module(name, status, delay)
        return result

    return fake_perform_full_scan


async def _no_dns(host: str) -> list[str]:
    """Contrôle de cible sans réseau : les cibles des tests E2E sont fictives."""
    return []


def _replace(setter: Callable[[Any, str, Any], None], target: Any, name: str, value: Any) -> None:
    """Remplace un attribut qui doit exister : un crochet disparu fait échouer le serveur, pas un faux silencieux."""
    if not hasattr(target, name):
        raise AttributeError(f"{name} introuvable sur {target!r} : le crochet du faux scanner a changé")
    setter(target, name, value)


def install_fake_scanner(
    step_delay: float = 0.12,
    slow_delay: float = 1.0,
    setter: Callable[[Any, str, Any], None] = setattr,
) -> list[str]:
    """Installe le faux scanner ; renvoie ce qui a été remplacé.

    À appeler après l'import de domainrecon.api.app (routes et tâches chargées).
    `setter` : monkeypatch.setattr dans les tests (remplacements annulés ensuite).
    Lève AttributeError si un crochet attendu n'existe plus.
    """
    from domainrecon.api.routes import jobs as job_routes
    from domainrecon.scanner import orchestrator

    original = orchestrator.perform_full_scan
    fake = make_fake_scanner(step_delay, slow_delay)
    # Crochet prévu par la phase 1 : le gestionnaire de tâches lit `runner` à chaque scan.
    _replace(setter, job_routes.manager, "runner", fake)
    # Cibles fictives : contrôle anti-SSRF de POST /api/scans sans résolution DNS.
    _replace(setter, job_routes, "ensure_target_allowed", _no_dns)
    patched = [
        "domainrecon.api.routes.jobs.manager.runner",
        "domainrecon.api.routes.jobs.ensure_target_allowed",
    ]
    # Route synchrone POST /api/scan et tout module qui a importé la fonction.
    for name, module in list(sys.modules.items()):
        if (name == "domainrecon" or name.startswith("domainrecon.")) and getattr(
            module, "perform_full_scan", None
        ) is original:
            setter(module, "perform_full_scan", fake)
            patched.append(name)
    return sorted(patched)


# Dossier de la désinstallation d'essai, dans le dossier de données temporaire du serveur.
UNINSTALL_SANDBOX = "desinstallation-test"


def seed_uninstall_sandbox(sandbox: Path) -> Path:
    """Dossier de données d'essai (base, captures, journaux, réglages, secret) ; renvoie son chemin."""
    data = sandbox / "DomainRecon"
    files = {
        data / "domainrecon.db": b"SQLite format 3\x00" + bytes(4080),
        data / "screenshots" / SCREENSHOT_NAME: _png(4, 4),
        data / "logs" / "domainrecon.log": b"journal\n",
        data / ".env": b"LOG_LEVEL=INFO\n",
        data / ".secret_key": bytes(32),
        sandbox / "tmp" / "domainrecon-import-essai" / "base.db": b"x",
    }
    for path, content in files.items():
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(content)
    return data


def install_uninstall_sandbox(data_dir: Path, setter: Callable[[Any, str, Any], None] = setattr) -> Path:
    """La désinstallation complète opère sur un bac à sable, jamais sur la machine ni sur la base E2E.

    Vraie suppression, mais dans <dossier de données>/desinstallation-test (recréé à chaque
    appel s'il a disparu) ; tâche système simulée, aucun processus détaché, contexte isolé :
    la base et le planificateur du serveur restent en service pour les tests suivants.
    """
    from domainrecon.desktop import uninstall

    sandbox = data_dir / UNINSTALL_SANDBOX
    task = {"installed": True}

    def fake_system(args: list[str]) -> tuple[int, str]:
        if "/Delete" in args or "disable" in args:
            task["installed"] = False
        if "/Query" in args or "is-enabled" in args:
            return (0 if task["installed"] else 1), ""
        return 0, ""

    def factory() -> uninstall.Context:
        data = sandbox / "DomainRecon"
        if not data.exists():
            seed_uninstall_sandbox(sandbox)
            task["installed"] = True
        return uninstall.Context(
            mode="source",
            platform="windows",
            data_dir=data,
            owned_data_dir=True,
            safe_data_dir=True,
            database_files=[data / "domainrecon.db"],
            external_database=None,
            temp_dir=sandbox / "tmp",
            cache_targets=[],
            app_dir=sandbox / "app",
            executable=sandbox / "app" / "DomainRecon.exe",
            uninstaller=None,
            pid=os.getpid(),
            runner=fake_system,
            spawn=None,
            isolated=True,
        )

    from domainrecon.monitor import systask

    # systask.status/uninstall lisent la plateforme : simulée comme Windows, rien n'est lancé (fake_system).
    _replace(setter, systask, "platform_name", lambda: "windows")
    _replace(setter, uninstall, "context_factory", factory)
    return sandbox


def _stop_on_signal(signum: int, frame: Any) -> None:
    raise SystemExit(0)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Serveur E2E de DomainRecon (base seedée, faux scanner)")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8765)
    parser.add_argument("--step-delay", type=float, default=0.12)
    parser.add_argument("--slow-delay", type=float, default=1.0)
    parser.add_argument("--keep-data", action="store_true", help="garder le dossier de données temporaire")
    args = parser.parse_args(argv)

    purge_stale_data_dirs()
    data_dir = Path(tempfile.mkdtemp(prefix=DATA_DIR_PREFIX))
    configure_environment(data_dir, args.port)
    if str(ROOT) not in sys.path:
        sys.path.insert(0, str(ROOT))

    import uvicorn

    from domainrecon.api.app import app
    from domainrecon.core import config
    from domainrecon.core.database import Base, SessionLocal, engine
    from domainrecon.core.paths import web_dir

    try:
        if not (web_dir() / "index.html").is_file():
            print(
                f"Interface absente de {web_dir()} : lancez d'abord `npm run build` dans frontend/.",
                file=sys.stderr,
            )
            return 2
        Base.metadata.create_all(bind=engine)
        seed_database(SessionLocal, config.SCREENSHOTS_DIR)
        install_fake_scanner(args.step_delay, args.slow_delay)
        install_uninstall_sandbox(data_dir)
        print(f"Serveur E2E sur http://{args.host}:{args.port} (données : {data_dir})", flush=True)
        # Après un arrêt propre, uvicorn rétablit ces gestionnaires puis rejoue le
        # signal : sans eux, le processus mourrait avant le nettoyage ci-dessous.
        for name in ("SIGTERM", "SIGBREAK"):
            if hasattr(signal, name):
                signal.signal(getattr(signal, name), _stop_on_signal)
        uvicorn.run(app, host=args.host, port=args.port, log_level="warning")
        return 0
    finally:
        engine.dispose()
        if not args.keep_data:
            shutil.rmtree(data_dir, ignore_errors=True)


if __name__ == "__main__":
    raise SystemExit(main())
