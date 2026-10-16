# =============================================================================
# DomainRecon - Tests du score de sécurité, des en-têtes et du module TLS
# =============================================================================
# Aucun trafic vers Internet : le score est calculé sur des données
# synthétiques, les en-têtes passent par httpx.MockTransport et le module TLS
# interroge des serveurs locaux sur 127.0.0.1.
# =============================================================================

import asyncio
import http.server
import socket
import ssl
import threading
from contextlib import contextmanager

import httpx
import pytest

from domainrecon.scanner import families as families_module
from domainrecon.scanner import headers as headers_module
from domainrecon.scanner import score as score_module
from domainrecon.scanner import tls as tls_module
from domainrecon.scanner.errors import TargetNotAllowedError
from domainrecon.scanner.headers import (
    SECURITY_HEADERS,
    check_security_headers,
    evaluate_security_headers,
)
from domainrecon.scanner.network import COMMON_PORTS
from domainrecon.scanner.orchestrator import MODULE_NAMES
from domainrecon.scanner.registry import PROFILE_QUICK, get_modules
from domainrecon.scanner.score import (
    REPUTATION_POINTS,
    SCORE_VERSION,
    SENSITIVE_PORTS,
    compute_security_score,
    grade_for_score,
    launched_modules,
)
from rendu import en, fr

# Comportement des 18 modules historiques : registre ramené à eux (tests/conftest.py).
pytestmark = pytest.mark.usefixtures("registre_historique")

# =============================================================================
# Données de test
# =============================================================================

# En-têtes robustes, servis en HTTPS : 6/6 conformes.
STRONG_HEADERS = {
    "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
    "X-Frame-Options": "DENY",
    "X-Content-Type-Options": "nosniff",
    "Content-Security-Policy": "default-src 'self'; script-src 'self'; frame-ancestors 'none'",
    "Referrer-Policy": "strict-origin-when-cross-origin",
    "Permissions-Policy": "geolocation=()",
}


def _scan_complet() -> dict:
    """Un scan au format actuel où tous les critères sont mesurés et conformes."""
    return {
        "security_headers": {
            "measured": True,
            "score": "6/6",
            "counts": {"ok": 6, "weak": 0, "invalid": 0, "missing": 0, "total": 6},
            "headers_found": dict(STRONG_HEADERS),
            "url": "https://example.com/",
            "https": True,
        },
        "tls_certificate": {
            "measured": True,
            "https": True,
            "valid": True,
            "verify_error": None,
            "error": None,
            "days_remaining": 200,
            "protocol": "TLSv1.3",
        },
        "email_security": {"measured": True, "overall_grade": "A"},
        "waf": {"measured": True, "detected": True, "waf_name": "Cloudflare"},
        "cookie_security": {"measured": True, "cookies_present": True, "score": "A"},
        "cors": {
            "measured": True,
            "misconfigured": False,
            "allows_any_origin": False,
            "reflects_origin": False,
            "reflects_with_credentials": False,
        },
        "redirect_chain": {"measured": True, "forces_https": True, "final_url": "https://example.com/"},
        "subdomain_takeover": [],
        "subdomains_checked": 5,
        "open_ports": [{"port": 80, "state": "open"}, {"port": 443, "state": "open"}],
        "is_ip_target": False,
        "module_status": {},
    }


# Certificats de test auto-signés (clés EC sans valeur, générées pour ces tests),
# pour localhost et 127.0.0.1. Le premier expire en 2126, le second a expiré en 2021.
VALID_CERT = """-----BEGIN CERTIFICATE-----
MIIB2DCCAX2gAwIBAgIUP/wUrWP5HznwYY3kDPJUEfORn/YwCgYIKoZIzj0EAwIw
MDESMBAGA1UEAwwJbG9jYWxob3N0MRowGAYDVQQKDBFEb21haW5SZWNvbiBUZXN0
czAgFw0yNjAxMDEwMDAwMDBaGA8yMTI2MDEwMTAwMDAwMFowMDESMBAGA1UEAwwJ
bG9jYWxob3N0MRowGAYDVQQKDBFEb21haW5SZWNvbiBUZXN0czBZMBMGByqGSM49
AgEGCCqGSM49AwEHA0IABDDe0I1HJWGLdKkkTxXyYFOQFuGEUHu904ISPxXGeu/a
r6p4If+ErgnwP9ZC7DHhD4sP2+pYWWOthX7fRNg0HvujczBxMA8GA1UdEwEB/wQF
MAMBAf8wDgYDVR0PAQH/BAQDAgKEMBMGA1UdJQQMMAoGCCsGAQUFBwMBMB0GA1Ud
DgQWBBTdgNY7KW+kgQCY/37Mt3+wRy4vaDAaBgNVHREEEzARgglsb2NhbGhvc3SH
BH8AAAEwCgYIKoZIzj0EAwIDSQAwRgIhAISlmz31MCkCUF8gjCK9TnXXK1PBQnyp
nM1+Kj7rLq7qAiEAumEmcZZWNWHoF1PUZ9vM8lxYvRA/x9WmwRjOjlSyFEA=
-----END CERTIFICATE-----
"""
VALID_KEY = """-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgVYZucTveb6c2mr/Q
gk7IhoJB0DBH+gDtChCyIvnhaGuhRANCAAQw3tCNRyVhi3SpJE8V8mBTkBbhhFB7
vdOCEj8Vxnrv2q+qeCH/hK4J8D/WQuwx4Q+LD9vqWFljrYV+30TYNB77
-----END PRIVATE KEY-----
"""
EXPIRED_CERT = """-----BEGIN CERTIFICATE-----
MIIB1jCCAXugAwIBAgIUNptNg53ME6QaI2cBeLHrbe/nyAswCgYIKoZIzj0EAwIw
MDESMBAGA1UEAwwJbG9jYWxob3N0MRowGAYDVQQKDBFEb21haW5SZWNvbiBUZXN0
czAeFw0yMDAxMDEwMDAwMDBaFw0yMTAxMDEwMDAwMDBaMDAxEjAQBgNVBAMMCWxv
Y2FsaG9zdDEaMBgGA1UECgwRRG9tYWluUmVjb24gVGVzdHMwWTATBgcqhkjOPQIB
BggqhkjOPQMBBwNCAASLe+QV9fKDJ8voZlpaRodaoPxlmTIq7AGSEECWyFuTXdYm
et+G53qcDvsOmveSRt83FEnuXQ4ODJGFU7KueOKyo3MwcTAPBgNVHRMBAf8EBTAD
AQH/MA4GA1UdDwEB/wQEAwIChDATBgNVHSUEDDAKBggrBgEFBQcDATAdBgNVHQ4E
FgQUxJtUYva+r21i2lsmlrguTschthAwGgYDVR0RBBMwEYIJbG9jYWxob3N0hwR/
AAABMAoGCCqGSM49BAMCA0kAMEYCIQD9Ze6VL0tO0+B/P8bRnQKn4UvZV0ScoRAc
JCQrVemPtwIhAOu4VsEBy3uu6P0AvKXiyaBDbOXdELlNmDRJ3jLikMnf
-----END CERTIFICATE-----
"""
EXPIRED_KEY = """-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgzhQKQD73YmVrvFCO
4CeeB2VF6QQUOQxL6OLf6Rp5tFehRANCAASLe+QV9fKDJ8voZlpaRodaoPxlmTIq
7AGSEECWyFuTXdYmet+G53qcDvsOmveSRt83FEnuXQ4ODJGFU7KueOKy
-----END PRIVATE KEY-----
"""


# =============================================================================
# Score : format de sortie
# =============================================================================


def test_score_parfait():
    result = compute_security_score(_scan_complet())
    assert result["score"] == 100
    assert result["grade"] == "A"
    assert result["coverage"] == 100
    assert result["confidence"] == "high"
    assert result["penalties"] == []
    assert result["grade_cap"] is None
    assert result["grade_reason"] is None
    assert result["version"] == SCORE_VERSION


def test_cles_de_sortie_conservees():
    """Contrat §6 : les clés historiques restent, seuls des ajouts sont permis."""
    result = compute_security_score(_scan_complet())
    assert {
        "score",
        "max_score",
        "grade",
        "grade_reason",
        "breakdown",
        "coverage",
        "confidence",
        "measured_points",
        "measured_max",
        "penalties",
        "grade_cap",
    } <= result.keys()
    assert list(result["breakdown"]) == list(score_module.CRITERIA_WEIGHTS)
    for criterion in result["breakdown"].values():
        assert {"score", "max", "detail", "measured", "counted", "applicable"} <= criterion.keys()


@pytest.mark.parametrize(
    "score,grade",
    [
        (100, "A"),
        (90, "A"),
        (89, "B"),
        (75, "B"),
        (74, "C"),
        (55, "C"),
        (54, "D"),
        (35, "D"),
        (34, "F"),
        (0, "F"),
    ],
)
def test_bornes_des_grades(score, grade):
    assert grade_for_score(score) == grade


# =============================================================================
# Score : TLS
# =============================================================================


@pytest.mark.parametrize(
    "tls",
    [
        {
            "measured": True,
            "https": True,
            "valid": False,
            "verify_code": 18,
            "verify_error": "Certificat auto-signé",
            "days_remaining": 300,
            "protocol": "TLSv1.3",
        },
        {
            "measured": True,
            "https": True,
            "valid": False,
            "verify_code": 10,
            "verify_error": "Certificat expiré",
            "days_remaining": -12,
            "protocol": "TLSv1.3",
        },
        {
            "measured": True,
            "https": True,
            "valid": False,
            "verify_code": 62,
            "verify_error": "Nom d'hôte non concordant avec le certificat",
            "protocol": "TLSv1.2",
        },
        # 443 fermé alors que le site répond en HTTP.
        {
            "measured": True,
            "https": False,
            "valid": False,
            "verify_error": "HTTPS indisponible : port 443 fermé ou filtré",
        },
        # Scans enregistrés avant la correction : l'erreur était classée « non mesurée ».
        {
            "measured": False,
            "error": "[SSL: CERTIFICATE_VERIFY_FAILED] certificate verify failed: "
            "certificate has expired (_ssl.c:1000)",
        },
        {"error": "[SSL: CERTIFICATE_VERIFY_FAILED] certificate verify failed: self-signed certificate"},
    ],
)
def test_tls_invalide_vaut_zero_et_jamais_A(tls):
    """Régression SCAN-1 / SCORE-1 : un certificat invalide donnait 100/A."""
    scan = _scan_complet()
    scan["tls_certificate"] = tls

    result = compute_security_score(scan)

    assert result["breakdown"]["tls"]["measured"] is True
    assert result["breakdown"]["tls"]["score"] == 0
    assert result["measured_max"] == 100  # le critère reste dans le dénominateur
    assert result["score"] == 80
    assert result["grade"] == "B"


def test_tls_invalide_ne_depasse_jamais_A_meme_avec_peu_de_criteres():
    for other in ("email_security", "waf", "cookie_security", "cors", "redirect_chain"):
        scan = _scan_complet()
        scan[other] = {"measured": False}
        scan["tls_certificate"] = {"measured": True, "https": True, "valid": False}
        result = compute_security_score(scan)
        assert result["score"] < 90 and result["grade"] != "A"


@pytest.mark.parametrize(
    "tls",
    [
        {"measured": False, "error": "Hôte injoignable sur le port 443 : timed out"},
        {"measured": False, "error": "timeout"},
        {"error": "[Errno 11001] getaddrinfo failed"},
        {},
    ],
)
def test_tls_injoignable_reste_non_mesure(tls):
    scan = _scan_complet()
    scan["tls_certificate"] = tls

    result = compute_security_score(scan)

    assert result["breakdown"]["tls"]["measured"] is False
    assert result["measured_max"] == 80


@pytest.mark.parametrize(
    "days,protocol,points",
    [
        (200, "TLSv1.3", 20),
        (200, "TLSv1.2", 18),
        (20, "TLSv1.3", 17),
        (5, "TLSv1.3", 15),
        (None, "TLSv1.3", 15),
        (200, "TLSv1.1", 15),
    ],
)
def test_points_tls_certificat_valide(days, protocol, points):
    scan = _scan_complet()
    scan["tls_certificate"] = {
        "measured": True,
        "https": True,
        "valid": True,
        "days_remaining": days,
        "protocol": protocol,
    }
    assert compute_security_score(scan)["breakdown"]["tls"]["score"] == points


# =============================================================================
# Score : vulnérabilités critiques et pénalités
# =============================================================================


def test_takeover_confirme_plafonne_le_grade():
    """Régression SCORE-2 : un takeover confirmé laissait le grade à A (95)."""
    scan = _scan_complet()
    scan["subdomain_takeover"] = [
        {
            "subdomain": "dead.example.com",
            "cname": "dead.herokuapp.com",
            "service": "herokuapp.com",
            "risk": "high",
            "confirmed": True,
            "fingerprint_matched": True,
        }
    ]

    result = compute_security_score(scan)

    assert result["breakdown"]["takeover"]["score"] == 0
    assert result["grade_cap"] == "D"
    assert result["grade"] == "D"
    assert result["score"] <= 54
    assert any("dead.example.com" in reason for reason in fr(result["grade_cap_reasons"]))


def test_plafond_sans_effet_sur_un_grade_deja_inferieur():
    scan = _scan_complet()
    scan["subdomain_takeover"] = [{"subdomain": "x.example.com", "risk": "high"}]
    scan["security_headers"] = {"measured": True, "counts": {"ok": 0, "weak": 0, "total": 6}}
    scan["tls_certificate"] = {"measured": True, "https": False, "valid": False}
    scan["email_security"] = {"measured": True, "overall_grade": "F"}
    scan["cors"] = {"measured": True, "misconfigured": True}

    result = compute_security_score(scan)

    assert result["grade_cap"] == "D"
    assert result["grade"] == "F"
    assert result["score"] == 25  # (10 WAF + 10 cookies + 5 redirection) / 100


def test_takeover_confirme_par_cname_pendant():
    """CNAME vers un service dont la cible est en NXDOMAIN : confirmé sans empreinte."""
    scan = _scan_complet()
    scan["subdomain_takeover"] = [
        {
            "subdomain": "old.example.com",
            "cname": "old.azurewebsites.net",
            "risk": "high",
            "confirmed": True,
            "fingerprint_matched": False,
            "cname_nxdomain": True,
        }
    ]

    result = compute_security_score(scan)

    assert result["grade_cap"] == "D"
    assert result["grade"] == "D"


@pytest.mark.parametrize(
    "entry,points",
    [
        # Formats actuels : « à vérifier » (CNAME pendant, service « edge », aucune réponse).
        ({"subdomain": "a.example.com", "risk": "medium", "confirmed": False, "cname_nxdomain": True}, 2),
        (
            {"subdomain": "a.example.com", "risk": "medium", "confirmed": False, "fingerprint_matched": True},
            2,
        ),
        ({"subdomain": "a.example.com", "risk": "low", "confirmed": False, "fingerprint_matched": False}, 4),
        # Anciens scans, sans champ `confirmed`.
        ({"subdomain": "a.example.com", "risk": "medium", "fingerprint_matched": False}, 2),
        ({"subdomain": "a.example.com", "risk": "high", "fingerprint_matched": False}, 2),
    ],
)
def test_takeover_non_confirme_ne_plafonne_pas(entry, points):
    scan = _scan_complet()
    scan["subdomain_takeover"] = [entry]

    result = compute_security_score(scan)

    assert result["breakdown"]["takeover"]["score"] == points
    assert result["grade_cap"] is None
    assert result["grade"] == "A"


def test_takeover_sans_resultat_indique_le_nombre_de_sous_domaines_testes():
    """Le takeover ne teste qu'une partie des sous-domaines : le verdict le dit."""
    scan = _scan_complet()
    scan["subdomains_checked"] = 15

    takeover = compute_security_score(scan)["breakdown"]["takeover"]

    assert takeover["score"] == 5
    assert fr(takeover["detail"]) == "Aucun takeover détecté (15 sous-domaine(s) testé(s))"


def test_cors_reflete_avec_credentials_plafonne_le_grade():
    scan = _scan_complet()
    scan["cors"] = {
        "measured": True,
        "misconfigured": True,
        "reflects_origin": True,
        "reflects_with_credentials": True,
    }

    result = compute_security_score(scan)

    assert result["breakdown"]["cors"]["score"] == 0
    assert result["grade_cap"] == "D"
    assert result["grade"] == "D"
    assert result["score"] <= 54


@pytest.mark.parametrize(
    "cors,points",
    [
        ({"measured": True, "reflects_origin": True, "reflects_with_credentials": False}, 4),
        ({"measured": True, "allows_any_origin": True}, 10),
        (
            {
                "measured": True,
                "allows_any_origin": True,
                "allows_credentials_with_wildcard": True,
                "misconfigured": True,
            },
            4,
        ),
        # Ancien format : réflexion sans information sur les credentials.
        ({"measured": True, "reflects_origin": True, "misconfigured": True}, 0),
        ({"measured": True, "misconfigured": True}, 0),
    ],
)
def test_cors_sans_credentials_ne_plafonne_pas(cors, points):
    scan = _scan_complet()
    scan["cors"] = cors

    result = compute_security_score(scan)

    assert result["breakdown"]["cors"]["score"] == points
    assert result["grade_cap"] is None


def test_cors_wildcard_sans_credentials_non_penalise():
    """Régression : « * » sans credentials (GitHub Pages) était « correct » mais coûtait 6 points sur 10."""
    scan = _scan_complet()
    scan["cors"] = {
        "cors_enabled": True,
        "misconfigured": False,
        "allows_any_origin": True,
        "allows_credentials_with_wildcard": False,
        "reflects_origin": False,
        "reflects_with_credentials": False,
        "severity": "info",
        "measured": True,
        "error": None,
    }

    cors = compute_security_score(scan)["breakdown"]["cors"]

    assert cors["score"] == 10 and cors["counted"] is True
    assert fr(cors["detail"]) == "Wildcard (*) sans credentials (ressource publique)"


@pytest.mark.parametrize(
    "cors,points,measured",
    [
        # Tests de reflet en échec, rien de trouvé : jamais « OK ».
        ({"measured": True, "partial": True}, 0, False),
        ({"measured": True, "partial": True, "allows_any_origin": True}, 0, False),
        # Un défaut trouvé avant l'échec des autres tests reste compté.
        (
            {"measured": True, "partial": True, "reflects_origin": True, "reflects_with_credentials": False},
            4,
            True,
        ),
        ({"measured": True, "partial": True, "misconfigured": True}, 0, True),
    ],
)
def test_cors_tests_incomplets_sans_points(cors, points, measured):
    scan = _scan_complet()
    scan["cors"] = cors

    result = compute_security_score(scan)

    assert result["breakdown"]["cors"]["score"] == points
    assert result["breakdown"]["cors"]["measured"] is measured
    assert result["breakdown"]["cors"]["counted"] is measured
    assert result["measured_max"] == (100 if measured else 90)


def test_ports_sensibles_penalises():
    """Régression SCORE-8 : Redis et Telnet exposés laissaient 100/A."""
    scan = _scan_complet()
    scan["open_ports"] += [
        {"port": 6379, "state": "open", "service": "Redis"},
        {"port": 23, "state": "open", "service": "Telnet"},
    ]

    result = compute_security_score(scan)

    assert [p["key"] for p in result["penalties"]] == ["port_23", "port_6379"]
    assert all(p["severity"] == "critical" and p["points"] == 15 for p in result["penalties"])
    assert {"key", "label", "points", "severity"} == result["penalties"][0].keys()
    assert result["score"] == 70
    assert result["grade"] == "C"


@pytest.mark.parametrize(
    "ports,expected",
    [
        ([22, 25, 80, 443, 587, 993], []),
        ([3306, "5432"], ["port_3306", "port_5432"]),
        ([{"port": 3389, "state": "closed"}], []),
        ([{"port": 21}], ["port_21"]),
    ],
)
def test_ports_attendus_non_penalises(ports, expected):
    scan = _scan_complet()
    scan["open_ports"] = ports
    assert [p["key"] for p in compute_security_score(scan)["penalties"]] == expected


def test_ports_non_mesures_sans_penalite():
    scan = _scan_complet()
    scan["open_ports"] = [{"port": 6379}]
    scan["module_status"] = {"open_ports": {"status": "timeout", "error": "Délai dépassé (60 s)"}}
    assert compute_security_score(scan)["penalties"] == []


def test_ports_sensibles_tous_sondes():
    """Régression : 11 des 20 ports pénalisés (Docker, Elasticsearch, WinRM…) n'étaient jamais sondés."""
    assert set(SENSITIVE_PORTS) <= set(COMMON_PORTS)


# =============================================================================
# Score : en-têtes
# =============================================================================


def test_hsts_servi_en_http_ignore():
    """Régression SCORE-5 : un HSTS reçu en HTTP clair rapportait des points."""
    https = evaluate_security_headers(STRONG_HEADERS, https=True)
    http = evaluate_security_headers(STRONG_HEADERS, https=False)

    assert https["checks"]["Strict-Transport-Security"]["status"] == "ok"
    assert http["checks"]["Strict-Transport-Security"]["status"] == "invalid"
    assert http["counts"]["ok"] == 5

    scan = _scan_complet()
    scan["security_headers"].update(counts=http["counts"], url="http://example.com/", https=False)
    assert compute_security_score(scan)["breakdown"]["headers"]["score"] == round(25 * 5 / 6)


def test_hsts_en_http_ignore_aussi_pour_les_anciens_scans():
    """Un ancien scan (sans `counts`) est réévalué à partir des valeurs stockées."""
    scan = _scan_complet()
    scan["security_headers"] = {
        "measured": True,
        "score": "7/7",
        "url": "http://example.com/",
        "headers_found": {**STRONG_HEADERS, "X-XSS-Protection": "1; mode=block"},
    }
    headers = compute_security_score(scan)["breakdown"]["headers"]
    assert headers["score"] == round(25 * 5 / 6)
    assert fr(headers["detail"]) == "5/6 conformes"


@pytest.mark.parametrize("url", ["https://192.0.2.10/", "https://[2001:db8::1]/"])
def test_hsts_jamais_note_sur_une_ip_pour_les_anciens_scans(url):
    """Un ancien scan d'une cible IP (sans `counts`) est réévalué sans HSTS, comme un scan récent."""
    scan = _scan_complet()
    found = {name: value for name, value in STRONG_HEADERS.items() if name != "Strict-Transport-Security"}
    scan["security_headers"] = {"measured": True, "score": "5/6", "url": url, "headers_found": found}
    headers = compute_security_score(scan)["breakdown"]["headers"]
    assert headers["score"] == 25
    assert fr(headers["detail"]) == "5/5 conformes"


def test_x_xss_protection_n_est_plus_exige():
    evaluation = evaluate_security_headers(STRONG_HEADERS, https=True)
    assert "X-XSS-Protection" not in SECURITY_HEADERS
    assert evaluation["counts"] == {"ok": 6, "weak": 0, "invalid": 0, "missing": 0, "total": 6}

    with_xss = evaluate_security_headers({**STRONG_HEADERS, "X-XSS-Protection": "1; mode=block"}, https=True)
    assert with_xss["checks"]["X-XSS-Protection"]["status"] == "info"
    assert with_xss["counts"] == evaluation["counts"]


@pytest.mark.parametrize(
    "header,value,status",
    [
        ("Strict-Transport-Security", "max-age=0", "invalid"),
        ("Strict-Transport-Security", "max-age=86400", "weak"),
        ("Strict-Transport-Security", "includeSubDomains", "invalid"),
        ("Strict-Transport-Security", 'max-age="31536000"', "ok"),
        ("X-Content-Type-Options", "sniff", "invalid"),
        ("X-Content-Type-Options", "NoSniff", "ok"),
        ("Content-Security-Policy", "default-src * 'unsafe-inline' 'unsafe-eval'", "weak"),
        ("Content-Security-Policy", "script-src 'self' 'unsafe-inline' 'nonce-abc'", "ok"),
        ("Content-Security-Policy", "script-src 'nonce-abc' 'strict-dynamic' https:", "ok"),
        ("Content-Security-Policy", "upgrade-insecure-requests", "weak"),
        ("Referrer-Policy", "unsafe-url", "invalid"),
        ("Referrer-Policy", "no-referrer-when-downgrade", "weak"),
        ("Referrer-Policy", "unsafe-url, strict-origin-when-cross-origin", "ok"),
        ("Referrer-Policy", "n'importe-quoi", "invalid"),
    ],
)
def test_validation_des_valeurs(header, value, status):
    evaluation = evaluate_security_headers({header: value}, https=True)
    assert evaluation["checks"][header]["status"] == status


@pytest.mark.parametrize(
    "xfo,csp,status",
    [
        ("ALLOWALL", None, "invalid"),
        ("ALLOW-FROM https://a.example", None, "invalid"),
        ("SAMEORIGIN", None, "ok"),
        (None, None, "missing"),
        # CSP frame-ancestors prime sur X-Frame-Options.
        (None, "frame-ancestors 'self'", "ok"),
        ("DENY", "frame-ancestors *", "invalid"),
    ],
)
def test_protection_anti_framing(xfo, csp, status):
    headers = {}
    if xfo:
        headers["X-Frame-Options"] = xfo
    if csp:
        headers["Content-Security-Policy"] = csp
    evaluation = evaluate_security_headers(headers, https=True)
    assert evaluation["checks"]["X-Frame-Options"]["status"] == status


def _mock_client(handler):
    def factory(timeout: float = 10.0, follow_redirects: bool = True) -> httpx.AsyncClient:
        return httpx.AsyncClient(transport=httpx.MockTransport(handler), follow_redirects=follow_redirects)

    return factory


def test_module_en_tetes_site_http_aux_valeurs_faibles(monkeypatch):
    """Reproduit SCORE-5 : site HTTP seul, 7 en-têtes aux valeurs faibles, noté 25/25."""

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.scheme == "https":
            raise httpx.ConnectError("connexion refusée", request=request)
        return httpx.Response(
            200,
            headers={
                "Strict-Transport-Security": "max-age=0",
                "X-Frame-Options": "ALLOWALL",
                "X-Content-Type-Options": "sniff",
                "Content-Security-Policy": "default-src *",
                "X-XSS-Protection": "1",
                "Referrer-Policy": "unsafe-url",
                "Permissions-Policy": "camera=*",
            },
        )

    monkeypatch.setattr(headers_module, "_http_client", _mock_client(handler))
    result = asyncio.run(check_security_headers("weak.test"))

    assert result["measured"] is True and result["error"] is None
    assert result["https"] is False
    assert result["url"] == "http://weak.test"
    assert result["counts"] == {"ok": 1, "weak": 1, "invalid": 4, "missing": 0, "total": 6}
    assert result["score"] == "1/6"
    assert result["checks"]["Strict-Transport-Security"]["status"] == "invalid"
    assert "X-XSS-Protection" not in result["headers_found"]

    scan = _scan_complet()
    scan["security_headers"] = result
    assert compute_security_score(scan)["breakdown"]["headers"]["score"] == round(25 * 1.5 / 6)


def test_module_en_tetes_redirection_vers_http(monkeypatch):
    """Le schéma de la réponse finale compte : HTTPS redirigé vers HTTP => HSTS sans effet."""

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.scheme == "https":
            return httpx.Response(301, headers={"Location": "http://downgrade.test/"})
        return httpx.Response(200, headers=STRONG_HEADERS)

    monkeypatch.setattr(headers_module, "_http_client", _mock_client(handler))
    result = asyncio.run(check_security_headers("downgrade.test"))

    assert result["https"] is False
    assert result["checks"]["Strict-Transport-Security"]["status"] == "invalid"
    assert result["counts"]["ok"] == 5


def test_module_en_tetes_redirection_hors_site_non_attribuee(monkeypatch):
    """CRIT-2 : un domaine parqué redirigé vers un site tiers n'hérite pas de ses en-têtes."""
    hosts = []

    def handler(request: httpx.Request) -> httpx.Response:
        hosts.append(request.url.host)
        if request.url.host == "parque.test":
            return httpx.Response(301, headers={"Location": "https://parking-tiers.example/lander"})
        return httpx.Response(200, headers=STRONG_HEADERS)

    monkeypatch.setattr(headers_module, "_http_client", _mock_client(handler))
    result = asyncio.run(check_security_headers("parque.test"))

    assert set(hosts) == {"parque.test"}  # le site tiers n'est jamais contacté
    assert result["measured"] is True
    assert result["off_site_redirect"] == "https://parking-tiers.example/lander"
    assert result["url"] == "https://parque.test"
    assert result["headers_found"] == {}
    assert result["counts"]["ok"] == 0


class _CorpsInterdit(httpx.AsyncByteStream):
    """Corps de réponse qui échoue s'il est lu."""

    async def __aiter__(self):
        raise AssertionError("le corps de la réponse ne doit pas être lu")
        yield b""  # pragma: no cover


def test_module_en_tetes_repli_get_sans_lire_le_corps(monkeypatch):
    """SCAN-11 : HEAD refusé, repli sur GET ; seuls les en-têtes comptent, le corps n'est pas lu."""
    methods = []

    def handler(request: httpx.Request) -> httpx.Response:
        methods.append(request.method)
        if request.method == "HEAD":
            return httpx.Response(405)
        return httpx.Response(200, headers=STRONG_HEADERS, stream=_CorpsInterdit())

    monkeypatch.setattr(headers_module, "_http_client", _mock_client(handler))
    result = asyncio.run(check_security_headers("lourd.test"))

    assert methods == ["HEAD", "GET"]
    assert result["measured"] is True
    assert result["counts"]["ok"] == 6


def test_module_en_tetes_cible_ipv6(monkeypatch):
    """Une IPv6 littérale est mise entre crochets dans l'URL (sinon URL invalide)."""
    urls = []

    def handler(request: httpx.Request) -> httpx.Response:
        urls.append(str(request.url))
        return httpx.Response(200, headers=STRONG_HEADERS)

    monkeypatch.setattr(headers_module, "_http_client", _mock_client(handler))
    result = asyncio.run(check_security_headers("2001:db8::1"))

    assert urls == ["https://[2001:db8::1]"]
    assert result["measured"] is True and result["https"] is True


def test_module_en_tetes_injoignable(monkeypatch):
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectTimeout("", request=request)

    monkeypatch.setattr(headers_module, "_http_client", _mock_client(handler))
    result = asyncio.run(check_security_headers("dead.test"))

    assert result["measured"] is False
    assert fr(result["error"])  # jamais vide, même si l'exception n'a pas de message
    assert result["headers_missing"] == SECURITY_HEADERS


# =============================================================================
# Score : bornes, critères non mesurés, N/A
# =============================================================================


@pytest.mark.parametrize(
    "security_headers",
    [
        {"measured": True, "score": "9/7"},
        {"measured": True, "counts": {"ok": 12, "weak": 3, "total": 6}},
        {"measured": True, "counts": {"ok": -4, "weak": 0, "total": 6}},
    ],
)
def test_score_borne_entre_0_et_100(security_headers):
    """Régression SCORE-14 : '9/7' donnait un score de 107."""
    scan = _scan_complet()
    scan["security_headers"] = security_headers

    result = compute_security_score(scan)

    assert 0 <= result["breakdown"]["headers"]["score"] <= 25
    assert 0 <= result["score"] <= 100


def test_penalites_ne_rendent_jamais_le_score_negatif():
    scan = _scan_complet()
    scan["open_ports"] = [23, 445, 2375, 6379, 9200, 11211, 27017, 3389]
    result = compute_security_score(scan)
    assert result["score"] == 0
    assert result["grade"] == "F"


def test_rien_de_mesure_donne_na():
    result = compute_security_score(
        {
            "security_headers": {"measured": False, "score": "0/6"},
            "tls_certificate": {"measured": False, "error": "Hôte injoignable"},
            "email_security": {"measured": False},
            "waf": {"measured": False},
            "cookie_security": {"measured": False},
            "cors": {"measured": False},
            "redirect_chain": {"measured": False},
            "subdomain_takeover": [],
            "subdomains_checked": 0,
            "open_ports": [{"port": 6379}],
        }
    )
    assert result["grade"] == "N/A"
    assert fr(result["grade_reason"]) == "Couverture insuffisante : 0 % du barème mesuré"
    assert result["score"] == 0
    assert result["coverage"] == 0
    assert result["measured_max"] == 0
    assert [p["key"] for p in result["penalties"]] == ["port_6379"]


def test_donnees_inattendues_ne_plantent_pas():
    assert compute_security_score({})["grade"] == "N/A"
    assert compute_security_score(None)["grade"] == "N/A"
    result = compute_security_score(
        {
            "security_headers": {"measured": True, "score": None},
            "tls_certificate": "erreur",
            "email_security": None,
            "subdomain_takeover": [None, "x"],
            "subdomains_checked": "3",
            "open_ports": "6379",
            "module_status": [],
        }
    )
    # Donnée d'en-têtes illisible : exclue plutôt que comptée 0/25.
    assert result["breakdown"]["headers"]["measured"] is False
    assert result["breakdown"]["takeover"]["measured"] is True


def test_waf_absent_ne_penalise_pas():
    """SCORE-4 : le WAF est un bonus, un site sans WAF n'est pas plafonné à 90."""
    scan = _scan_complet()
    scan["waf"] = {
        "measured": True,
        "detected": False,
        "waf_name": None,
        "cdn_detected": True,
        "cdn_name": "Fastly",
    }

    result = compute_security_score(scan)

    assert result["score"] == 100
    assert result["breakdown"]["waf"]["score"] == 0  # un CDN n'est pas un WAF
    assert "Fastly" in fr(result["breakdown"]["waf"]["detail"])
    assert result["breakdown"]["waf"]["measured"] is True
    assert result["breakdown"]["waf"]["counted"] is False
    assert result["measured_max"] == 90
    assert result["coverage"] == 100


def test_cookies_grade_f_vaut_zero():
    scan = _scan_complet()
    scan["cookie_security"] = {"measured": True, "cookies_present": True, "score": "F"}
    assert compute_security_score(scan)["breakdown"]["cookies"]["score"] == 0


def test_redirection_https_verifiee_sur_l_url_finale():
    """SCORE-9 : une redirection qui finit en HTTP ne force pas HTTPS."""
    scan = _scan_complet()
    scan["redirect_chain"] = {
        "measured": True,
        "forces_https": True,
        "final_url": "http://example.com/login?next=https://example.com/",
    }
    assert compute_security_score(scan)["breakdown"]["https_redirect"]["score"] == 0


def test_cible_ip_exclut_email_et_takeover():
    scan = _scan_complet()
    scan["is_ip_target"] = True
    scan["email_security"] = {"measured": True, "overall_grade": "F"}

    result = compute_security_score(scan)

    assert result["breakdown"]["email"]["measured"] is False
    assert result["breakdown"]["takeover"]["measured"] is False
    assert result["measured_max"] == 80
    assert result["score"] == 100
    # Sans objet, et non « non mesurés » : la couverture reste complète.
    assert result["breakdown"]["email"]["applicable"] is False
    assert result["breakdown"]["takeover"]["applicable"] is False
    assert result["coverage"] == 100


@pytest.mark.parametrize(
    "status,detail,applicable,coverage",
    [
        ("failed", "Non mesuré (échec du module)", True, 80),
        ("timeout", "Non mesuré (délai dépassé)", True, 80),
        # « skipped » : module sans objet, hors couverture.
        ("skipped", "Non applicable : cible IP littérale", False, 100),
    ],
)
def test_module_en_echec_exclut_le_critere(status, detail, applicable, coverage):
    scan = _scan_complet()
    scan["module_status"] = {"tls_certificate": {"status": status, "error": "cible IP littérale"}}

    result = compute_security_score(scan)

    assert result["breakdown"]["tls"]["measured"] is False
    assert fr(result["breakdown"]["tls"]["detail"]) == detail
    assert result["breakdown"]["tls"]["applicable"] is applicable
    assert result["measured_max"] == 80
    assert result["coverage"] == coverage


def test_scans_anciens_sans_drapeau_measured():
    """Les scans enregistrés avant l'ajout des drapeaux restent notés à l'identique."""
    result = compute_security_score(
        {
            "security_headers": {"score": "5/7", "headers_found": {"X-Frame-Options": "DENY"}},
            "tls_certificate": {"days_remaining": 100, "protocol": "TLSv1.2"},
            "email_security": {"overall_grade": "B"},
            "waf": {"detected": False},
            "cookie_security": {"cookies": [{"name": "a"}], "score": "B"},
            "cors": {"misconfigured": False},
            "redirect_chain": {"chain": [{"url": "http://x", "status_code": 301}], "forces_https": True},
            "subdomain_takeover": [],
        }
    )
    # headers 18/25, TLS 18/20, email 12/15, cookies 7/10, CORS 10/10,
    # redirection 5/5 ; WAF absent et takeover non mesuré hors dénominateur.
    assert result["measured_points"] == 70
    assert result["measured_max"] == 85
    assert result["score"] == 82
    assert result["grade"] == "B"
    assert result["coverage"] == 95


@pytest.mark.parametrize("email_grade,score", [("D", 43), ("F", 38)])
def test_arrondi_moitie_vers_le_haut(email_grade, score):
    """Régression : round() arrondit les moitiés au pair (42,5 donnait 42, mais 37,5 donnait 38)."""
    scan = _scan_complet()
    scan["tls_certificate"] = {"measured": True, "https": False, "valid": False}
    scan["email_security"] = {"measured": True, "overall_grade": email_grade}
    scan["waf"] = {"measured": True, "detected": False}
    scan["cookie_security"] = {"measured": True, "cookies_present": False, "score": "N/A"}
    scan["cors"] = {"measured": True, "misconfigured": True}
    scan["redirect_chain"] = {"measured": True, "forces_https": False}

    result = compute_security_score(scan)

    # En-têtes 25 + email (4 ou 0) + takeover 5, sur 80 : 42,5 ou 37,5.
    assert result["measured_max"] == 80
    assert result["score"] == score


def test_arrondi_des_en_tetes_moitie_vers_le_haut():
    scan = _scan_complet()
    scan["security_headers"] = {"measured": True, "counts": {"ok": 3, "weak": 0, "total": 6}}
    # 3/6 de 25 = 12,5 (round() : 12).
    assert compute_security_score(scan)["breakdown"]["headers"]["score"] == 13


def test_couverture_insuffisante_donne_na():
    """Régression : site injoignable, email seul mesuré (DNS) : 53/100 et grade D sur 14 % du barème.

    Barème des 18 modules historiques : 105 points (critère WHOIS de 5 points compris).
    """
    scan = _scan_complet()
    scan["email_security"] = {"measured": True, "overall_grade": "C"}
    scan["module_status"] = {
        score_module.CRITERIA_MODULES[key]: {"status": "failed", "error": "Site injoignable"}
        for key in score_module.CRITERIA_WEIGHTS
        if key != "email"
    }

    result = compute_security_score(scan)

    assert result["coverage"] == 14
    assert result["grade"] == "N/A"
    assert fr(result["grade_reason"]) == "Couverture insuffisante : 14 % du barème mesuré"
    assert result["confidence"] == "low"
    # Score calculé (8/15), indicatif seulement.
    assert result["score"] == 53


def test_couverture_de_50_pourcent_reste_notee():
    scan = _scan_complet()
    scan["module_status"] = {
        score_module.CRITERIA_MODULES[key]: {"status": "timeout", "error": "Délai dépassé (60 s)"}
        for key in ("email", "waf", "cookies", "cors", "https_redirect")
    }

    result = compute_security_score(scan)

    # En-têtes 25 + TLS 20 + takeover 5.
    assert result["coverage"] == 50
    assert result["grade"] == "A" and result["grade_reason"] is None
    assert result["confidence"] == "medium"


def test_couverture_complete_sans_cookie_ni_waf():
    """Régression : tous les modules réussis, mais « 90 % du barème mesuré » faute de cookie posé."""
    scan = _scan_complet()
    scan["waf"] = {"measured": True, "detected": False, "cdn_detected": True, "cdn_name": "Cloudflare"}
    scan["cookie_security"] = {"measured": True, "cookies_present": False, "cookies": [], "score": "N/A"}

    result = compute_security_score(scan)

    cookies = result["breakdown"]["cookies"]
    assert fr(cookies["detail"]) == "Aucun cookie posé (sans objet)"
    assert (cookies["measured"], cookies["counted"], cookies["applicable"]) == (False, False, False)
    assert result["coverage"] == 100
    assert result["confidence"] == "high"


def test_cookies_non_mesures_restent_applicables():
    """« Non mesuré » (module en échec) reste distinct de « sans objet » (aucun cookie)."""
    scan = _scan_complet()
    scan["cookie_security"] = {"measured": False, "error": "Délai dépassé"}

    result = compute_security_score(scan)

    cookies = result["breakdown"]["cookies"]
    assert fr(cookies["detail"]) == "Non mesuré"
    assert (cookies["measured"], cookies["applicable"]) == (False, True)
    assert result["coverage"] == 90


def test_retrogradation_https_vers_http_vaut_zero():
    scan = _scan_complet()
    scan["redirect_chain"] = {
        "measured": True,
        "forces_https": True,
        "final_url": "https://example.com/",
        "https_downgrade": True,
    }

    redirect = compute_security_score(scan)["breakdown"]["https_redirect"]

    assert (redirect["score"], redirect["measured"]) == (0, True)
    assert fr(redirect["detail"]) == "Non (une URL HTTPS redirige vers HTTP)"


def test_redirection_inconnue_quand_http_ne_repond_pas():
    """Un délai dépassé sur http:// n'est lu ni comme « force HTTPS » ni comme « Non »."""
    scan = _scan_complet()
    scan["redirect_chain"] = {
        "measured": True,
        "forces_https": None,
        "http_available": False,
        "final_url": None,
    }

    result = compute_security_score(scan)

    redirect = result["breakdown"]["https_redirect"]
    assert (redirect["score"], redirect["measured"], redirect["applicable"]) == (0, False, True)
    assert result["measured_max"] == 95
    assert result["coverage"] == 95


# =============================================================================
# Score v4 : modules non lancés (profils de scan) et 7e famille
# =============================================================================


def _statuts_ok(noms) -> dict:
    return {nom: {"status": "ok", "error": None} for nom in noms}


def _tous_sauf(*exclus) -> list[str]:
    return [nom for nom in MODULE_NAMES if nom not in exclus]


def test_bareme_v4():
    assert SCORE_VERSION == 4
    assert compute_security_score(_scan_complet())["version"] == 4


@pytest.mark.parametrize(
    "modifier",
    [
        lambda scan: None,
        lambda scan: scan.update(tls_certificate={"measured": True, "https": True, "valid": False}),
        lambda scan: scan.update(
            email_security={"measured": True, "overall_grade": "C"}, waf={"measured": True}
        ),
        lambda scan: scan.update(
            open_ports=[{"port": 6379, "state": "open"}, {"port": 3306, "state": "open"}]
        ),
        lambda scan: scan.update(is_ip_target=True),
        lambda scan: scan.update(module_status={"tls_certificate": {"status": "failed", "error": "x"}}),
        lambda scan: scan.update(
            subdomain_takeover=[{"subdomain": "a.example.com", "risk": "high", "confirmed": True}]
        ),
        lambda scan: scan.update(
            cors={"measured": True, "reflects_origin": True, "reflects_with_credentials": True}
        ),
        lambda scan: scan.update(
            cookie_security={"measured": True, "cookies_present": False, "score": "N/A"}
        ),
    ],
    ids=[
        "parfait",
        "tls",
        "email-sans-waf",
        "ports",
        "ip",
        "module-en-echec",
        "takeover",
        "cors",
        "sans-cookie",
    ],
)
def test_tous_les_modules_lances_meme_resultat_qu_au_bareme_v3(modifier):
    """Compatibilité : les 18 modules tous lancés notent comme avant (même forme de critère, même score)."""
    scan = _scan_complet()
    modifier(scan)

    sans_trace = compute_security_score(scan)  # aucun module déclaré : chemin du barème v3
    avec_trace = compute_security_score({**scan, "modules_launched": list(MODULE_NAMES)})

    assert avec_trace == sans_trace
    for critere in avec_trace["breakdown"].values():
        assert set(critere) == {"score", "max", "detail", "measured", "counted", "applicable"}


def test_profil_rapide_couverture_moindre():
    rapide = [spec.name for spec in get_modules(PROFILE_QUICK)]
    # Le takeover est un module actif : hors du profil rapide, son critère est omis (ni réussi ni échoué).
    assert "subdomain_takeover" not in rapide
    complet = compute_security_score(_scan_complet())

    result = compute_security_score(
        {**_scan_complet(), "modules_launched": rapide, "module_status": _statuts_ok(rapide)}
    )

    assert "takeover" not in result["breakdown"] and "open_ports" not in result["breakdown"]
    # Le WHOIS (passif, hors profil rapide) est un manque du profil : non lancé, jamais « réussi ».
    whois = result["breakdown"]["whois"]
    assert (whois["measured"], whois["counted"], whois["applicable"]) == (False, False, True)
    assert whois["launched"] is False and whois["score"] == 0
    assert fr(whois["detail"]) == "Non lancé (hors du profil de scan)"
    assert en(whois["detail"]) == "Not run (outside the scan profile)"
    # Couverture et points mesurés plus bas : le critère reste dans le barème applicable.
    assert (result["coverage"], result["measured_max"]) == (95, 95)
    assert result["coverage"] < complet["coverage"] and result["measured_max"] < complet["measured_max"]
    assert result["measured_points"] < complet["measured_points"]
    # Le score reste normalisé sur les seuls critères mesurés : aucun point gagné ni perdu.
    assert (result["score"], result["grade"], result["confidence"]) == (100, "A", "high")
    # Les critères lancés gardent la forme du barème v3.
    for key in set(result["breakdown"]) - {"whois"}:
        assert "launched" not in result["breakdown"][key]


def test_module_non_lance_jamais_compte_comme_reussi():
    # Données parfaites pour tous les critères, mais le module TLS n'a pas été lancé.
    scan = {**_scan_complet(), "modules_launched": _tous_sauf("tls_certificate")}

    result = compute_security_score(scan)

    tls = result["breakdown"]["tls"]
    assert (tls["score"], tls["measured"], tls["counted"], tls["applicable"]) == (0, False, False, True)
    assert tls["launched"] is False
    assert (result["measured_max"], result["coverage"]) == (80, 80)
    # Un statut de module prouve qu'il a tourné, même absent de modules_launched.
    scan["module_status"] = _statuts_ok(["tls_certificate"])
    result = compute_security_score(scan)
    assert result["breakdown"]["tls"]["measured"] is True and "launched" not in result["breakdown"]["tls"]
    assert (result["measured_max"], result["coverage"]) == (100, 100)


def test_waf_non_lance_n_est_pas_un_bonus_obtenu():
    # WAF détecté en profil complet : bonus de 10 points compté.
    assert compute_security_score(_scan_complet())["measured_max"] == 100

    result = compute_security_score({**_scan_complet(), "modules_launched": _tous_sauf("waf")})

    waf = result["breakdown"]["waf"]
    assert (waf["score"], waf["measured"], waf["counted"], waf["launched"]) == (0, False, False, False)
    assert (result["measured_max"], result["coverage"], result["score"]) == (90, 90, 100)


def test_critere_sans_objet_reste_sans_objet_meme_non_lance():
    scan = {**_scan_complet(), "is_ip_target": True, "modules_launched": _tous_sauf("email_security")}

    result = compute_security_score(scan)

    email = result["breakdown"]["email"]
    assert (email["applicable"], email["measured"]) == (False, False)
    assert fr(email["detail"]) == "Non applicable (cible IP)"
    assert result["coverage"] == 100


def test_ports_non_lances_sans_penalite():
    scan = {**_scan_complet(), "open_ports": [{"port": 6379, "state": "open"}]}

    lances = compute_security_score({**scan, "modules_launched": list(MODULE_NAMES)})
    assert [penalty["key"] for penalty in lances["penalties"]] == ["port_6379"]

    # La valeur enregistrée d'un module non lancé ne dit rien des ports.
    sans_ports = compute_security_score({**scan, "modules_launched": _tous_sauf("open_ports")})
    assert sans_ports["penalties"] == [] and sans_ports["score"] == 100


def test_profil_tres_reduit_sans_note():
    result = compute_security_score(
        {**_scan_complet(), "modules_launched": ["whois_data", "dns_records", "email_security"]}
    )

    # Seul le critère e-mail (15 points sur 95 applicables) est mesuré ; WHOIS sans date d'expiration est sans objet.
    assert result["coverage"] == 16
    assert result["grade"] == "N/A"
    assert fr(result["grade_reason"]) == "Couverture insuffisante : 16 % du barème mesuré"
    assert result["confidence"] == "low"


def test_modules_lances_lus_du_scan():
    # Aucune liste déclarée : le barème suppose tous les modules lancés (module_status partiel compris,
    # qui ne dit que le sort de certains modules).
    assert launched_modules(None) is None
    assert launched_modules({}) is None
    assert launched_modules({"module_status": {"cors": {"status": "ok"}}}) is None
    assert launched_modules({"modules_launched": None}) is None
    assert launched_modules({"modules_launched": "waf"}) is None
    # Liste déclarée : réunie à module_status (un statut prouve que le module a tourné),
    # noms illisibles ignorés.
    declared = {"modules_launched": ["waf", 3, None], "module_status": {"cors": {"status": "failed"}}}
    assert launched_modules(declared) == {"waf", "cors"}
    assert launched_modules({"modules_launched": []}) == frozenset()


def test_septieme_famille_reputation_sans_point_attribue():
    allocated = sum(
        score_module.CRITERIA_WEIGHTS[key] for key in families_module.FAMILY_CRITERIA["reputation"]
    )
    assert REPUTATION_POINTS == 15
    # Au plus les 15 points de la famille, à répartir entre les modules de la spec 2.
    assert allocated <= REPUTATION_POINTS
    # Chaque critère du barème appartient à une seule famille.
    claimed = [key for criteria in families_module.FAMILY_CRITERIA.values() for key in criteria]
    assert sorted(claimed) == sorted(score_module.CRITERIA_WEIGHTS)
    # Barème des 18 modules d'origine : 100 points, plus le critère WHOIS (5 points, ajouté lors de
    # la récupération des modules). Sans critère de réputation, la famille n'a aucun effet sur le score.
    hors_reputation = sum(
        w
        for key, w in score_module.CRITERIA_WEIGHTS.items()
        if key not in families_module.FAMILY_CRITERIA["reputation"]
    )
    assert hors_reputation == 105
    result = compute_security_score(_scan_complet())
    assert list(result["breakdown"]) == list(score_module.CRITERIA_WEIGHTS)
    assert (result["score"], result["coverage"], result["measured_max"]) == (100, 100, 100)


# =============================================================================
# Module TLS (serveurs locaux sur 127.0.0.1)
# =============================================================================


@contextmanager
def _tls_server(tmp_path, cert_pem: str, key_pem: str):
    """Serveur TLS local qui accepte des poignées de main successives."""
    cert_file, key_file = tmp_path / "cert.pem", tmp_path / "key.pem"
    cert_file.write_text(cert_pem, encoding="ascii")
    key_file.write_text(key_pem, encoding="ascii")
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(cert_file, key_file)

    listener = socket.create_server(("127.0.0.1", 0))
    listener.settimeout(0.1)
    stop = threading.Event()

    def serve():
        while not stop.is_set():
            try:
                conn, _ = listener.accept()
            except TimeoutError:
                continue
            except OSError:
                return
            conn.settimeout(2)
            try:
                with context.wrap_socket(conn, server_side=True) as tls_conn:
                    tls_conn.recv(1)
            except OSError:
                pass
            finally:
                conn.close()

    thread = threading.Thread(target=serve, daemon=True)
    thread.start()
    try:
        yield listener.getsockname()[1]
    finally:
        stop.set()
        thread.join(timeout=2)
        listener.close()


@contextmanager
def _http_server():
    """Serveur HTTP clair local (répond 200 à tout)."""

    class Handler(http.server.BaseHTTPRequestHandler):
        def do_HEAD(self):
            self.send_response(200)
            self.end_headers()

        do_GET = do_HEAD

        def log_message(self, *args):
            pass

    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server.server_address[1]
    finally:
        server.shutdown()
        server.server_close()


@contextmanager
def _raw_server(payload: bytes):
    """Serveur local qui lit la requête du client, répond `payload` puis ferme."""
    listener = socket.create_server(("127.0.0.1", 0))
    listener.settimeout(0.1)
    stop = threading.Event()

    def serve():
        while not stop.is_set():
            try:
                conn, _ = listener.accept()
            except TimeoutError:
                continue
            except OSError:
                return
            with conn:
                try:
                    # Lire avant de répondre : fermer avec des données non lues
                    # provoque un RST au lieu d'une réponse.
                    conn.settimeout(2)
                    conn.recv(4096)
                    conn.sendall(payload)
                    conn.shutdown(socket.SHUT_WR)
                    conn.recv(4096)
                except OSError:
                    pass

    thread = threading.Thread(target=serve, daemon=True)
    thread.start()
    try:
        yield listener.getsockname()[1]
    finally:
        stop.set()
        thread.join(timeout=2)
        listener.close()


def _closed_port() -> int:
    with socket.create_server(("127.0.0.1", 0)) as sock:
        return sock.getsockname()[1]


def _trusting(cert_pem: str):
    """Contexte vérifiant qui fait confiance au certificat de test."""
    return lambda: ssl.create_default_context(cadata=cert_pem)


def test_tls_certificat_auto_signe_reste_mesure(tmp_path):
    """Régression SCAN-1 : certificat lu malgré l'échec de vérification."""
    with _tls_server(tmp_path, VALID_CERT, VALID_KEY) as port:
        result = tls_module._check_tls_sync("127.0.0.1", port=port, timeout=5)

    assert result["measured"] is True
    assert result["https"] is True
    assert result["valid"] is False
    assert result["verify_code"] == 18
    assert fr(result["verify_error"]) == "Certificat auto-signé"
    assert result["error"] is None
    # Détails récupérés par la seconde poignée de main, sans vérification.
    assert result["subject"] == "localhost"
    assert result["issuer_org"] == "DomainRecon Tests"
    assert result["not_after"] == "Jan  1 00:00:00 2126 GMT"
    assert result["days_remaining"] > 30000
    assert result["san"] == ["localhost", "127.0.0.1"]
    assert result["protocol"].startswith("TLSv1.")

    scan = _scan_complet()
    scan["tls_certificate"] = result
    score = compute_security_score(scan)
    assert fr(score["breakdown"]["tls"]) == {
        "score": 0,
        "max": 20,
        "detail": "Invalide : Certificat auto-signé",
        "measured": True,
        "counted": True,
        "applicable": True,
    }
    assert score["grade"] != "A"


def test_tls_certificat_valide(tmp_path, monkeypatch):
    monkeypatch.setattr(tls_module, "_verified_context", _trusting(VALID_CERT))
    with _tls_server(tmp_path, VALID_CERT, VALID_KEY) as port:
        result = tls_module._check_tls_sync("127.0.0.1", port=port, timeout=5)

    assert result["measured"] is True
    assert result["https"] is True
    assert result["valid"] is True
    assert result["verify_error"] is None
    assert result["subject"] == "localhost"
    assert result["days_remaining"] > 30000

    scan = _scan_complet()
    scan["tls_certificate"] = result
    assert compute_security_score(scan)["breakdown"]["tls"]["score"] >= 18


def test_tls_certificat_expire(tmp_path, monkeypatch):
    monkeypatch.setattr(tls_module, "_verified_context", _trusting(EXPIRED_CERT))
    with _tls_server(tmp_path, EXPIRED_CERT, EXPIRED_KEY) as port:
        result = tls_module._check_tls_sync("127.0.0.1", port=port, timeout=5)

    assert result["measured"] is True
    assert result["valid"] is False
    assert result["verify_code"] == 10
    assert fr(result["verify_error"]) == "Certificat expiré"
    assert result["not_after"] == "Jan  1 00:00:00 2021 GMT"
    assert result["days_remaining"] < 0


def test_tls_port_ferme_mais_site_http():
    with _http_server() as http_port:
        # Port libéré après le démarrage du serveur HTTP : il ne peut pas être le sien.
        port = _closed_port()
        result = tls_module._check_tls_sync("127.0.0.1", port=port, http_port=http_port, timeout=3)

    assert result["measured"] is True
    assert result["https"] is False
    assert result["valid"] is False
    assert fr(result["verify_error"]) == f"HTTPS indisponible : port {port} fermé ou filtré"
    assert result["error"] is None

    scan = _scan_complet()
    scan["tls_certificate"] = result
    tls = compute_security_score(scan)["breakdown"]["tls"]
    assert tls["measured"] is True and tls["score"] == 0


def test_tls_service_non_tls_sur_le_port():
    """Port ouvert qui ne parle pas TLS : HTTPS inutilisable, mesure valable."""
    with _raw_server(b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n") as port:
        result = tls_module._check_tls_sync("127.0.0.1", port=port, timeout=3)

    assert result["measured"] is True
    assert result["https"] is False
    assert fr(result["verify_error"]).startswith("Poignée de main TLS impossible")


def test_tls_hote_injoignable_non_mesure():
    result = tls_module._check_tls_sync("127.0.0.1", port=_closed_port(), http_port=_closed_port(), timeout=3)

    assert result["measured"] is False
    assert result["https"] is False
    assert fr(result["error"]).startswith("Hôte injoignable sur le port ")

    scan = _scan_complet()
    scan["tls_certificate"] = result
    assert compute_security_score(scan)["breakdown"]["tls"]["measured"] is False


def test_check_tls_certificate_asynchrone(tmp_path, monkeypatch):
    monkeypatch.setenv("ALLOW_PRIVATE_TARGETS", "1")
    with _tls_server(tmp_path, VALID_CERT, VALID_KEY) as port:
        result = asyncio.run(tls_module.check_tls_certificate("127.0.0.1", port=port))
    assert result["measured"] is True
    assert result["valid"] is False


def test_check_tls_certificate_refuse_une_cible_privee(monkeypatch):
    monkeypatch.setenv("ALLOW_PRIVATE_TARGETS", "0")
    with pytest.raises(TargetNotAllowedError):
        asyncio.run(tls_module.check_tls_certificate("127.0.0.1", port=_closed_port()))


def test_tls_connexion_limitee_aux_adresses_validees(tmp_path, monkeypatch):
    """Le nom sert à SNI et à la vérification ; la connexion va à l'adresse validée."""
    monkeypatch.setattr(tls_module, "_verified_context", _trusting(VALID_CERT))
    with _tls_server(tmp_path, VALID_CERT, VALID_KEY) as port:
        result = tls_module._check_tls_sync("localhost", port=port, timeout=5, addresses=["127.0.0.1"])
    assert result["valid"] is True


def test_tls_nom_non_concordant(tmp_path, monkeypatch):
    # « .invalid » ne résout jamais : la connexion passe forcément par l'adresse fournie.
    monkeypatch.setattr(tls_module, "_verified_context", _trusting(VALID_CERT))
    with _tls_server(tmp_path, VALID_CERT, VALID_KEY) as port:
        result = tls_module._check_tls_sync("tls.invalid", port=port, timeout=5, addresses=["127.0.0.1"])

    assert result["measured"] is True
    assert result["https"] is True
    assert result["valid"] is False
    assert result["verify_code"] == 62
    assert fr(result["verify_error"]) == "Nom d'hôte non concordant avec le certificat"
    assert result["subject"] == "localhost"


@pytest.mark.parametrize(
    "code,message,expected",
    [
        (10, "certificate has expired", "Certificat expiré"),
        (62, "Hostname mismatch", "Nom d'hôte non concordant avec le certificat"),
        (
            20,
            "unable to get local issuer certificate",
            "Autorité de certification inconnue ou chaîne incomplète",
        ),
        (999, "erreur exotique", "Certificat non valide : erreur exotique"),
    ],
)
def test_libelles_des_erreurs_de_verification(code, message, expected):
    error = ssl.SSLCertVerificationError(1, message)
    error.verify_code = code
    error.verify_message = message
    assert fr(tls_module._describe_verify_error(error)) == expected
