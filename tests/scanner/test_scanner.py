# =============================================================================
# DomainRecon - Tests des fonctions pures du scanner
# =============================================================================
# Aucun accès réseau : uniquement normalisation de cibles et calcul de score.
# La politique de cibles (anti-SSRF) est testée en détail dans test_targets.py.
# =============================================================================

import asyncio

import pytest

from domainrecon.scanner import (
    SCREENSHOT_NAME_RE,
    TargetNotAllowedError,
    compute_security_score,
    is_valid_target,
    normalize_target,
    registrable_domain,
    screenshot_filename,
)
from domainrecon.scanner.targets import ensure_target_allowed

# Comportement des 18 modules historiques : registre ramené à eux (tests/conftest.py).
pytestmark = pytest.mark.usefixtures("registre_historique")

# =============================================================================
# Normalisation de la cible
# =============================================================================


@pytest.mark.parametrize(
    "raw, expected",
    [
        ("example.com", "example.com"),
        ("EXAMPLE.COM", "example.com"),
        ("https://example.com", "example.com"),
        ("https://example.com/path?q=1#frag", "example.com"),
        ("http://example.com:8443/", "example.com"),
        ("  example.com.  ", "example.com"),
        ("user@example.com", "example.com"),
        # Le sous-domaine doit être conservé (régression : il était écrasé).
        ("blog.example.com", "blog.example.com"),
        ("https://a.b.example.co.uk/x", "a.b.example.co.uk"),
        # Hôte sans suffixe public : renvoyé tel quel.
        ("localhost", "localhost"),
        # IPv6 sans crochets ni port, IDN en punycode
        ("http://[2001:db8::1]:8443/", "2001:db8::1"),
        ("café.fr", "xn--caf-dma.fr"),
        # Saisie inexploitable (blanc interne) : chaîne vide, jamais la saisie brute
        ("127.0.0.1 <img src=x onerror=alert(1)>", ""),
    ],
)
def test_normalize_target(raw, expected):
    assert normalize_target(raw) == expected


def test_normalize_target_vide():
    assert normalize_target("") == ""
    assert normalize_target(None) == ""


@pytest.mark.parametrize(
    "host, expected",
    [
        ("blog.example.com", "example.com"),
        ("example.com", "example.com"),
        ("a.b.example.co.uk", "example.co.uk"),
        ("localhost", "localhost"),
    ],
)
def test_registrable_domain(host, expected):
    assert registrable_domain(host) == expected


@pytest.mark.parametrize(
    "host, valid",
    [
        ("example.com", True),
        ("blog.example.com", True),
        ("93.184.216.34", True),
        ("2001:db8::1", True),
        ("", False),
        ("exa mple.com", False),
        ("-example.com", False),
        ("../../etc/passwd", False),
        ("a" * 300, False),
        # socket.inet_aton acceptait « IPv4 + blanc + n'importe quoi » et les formes abrégées
        ("127.0.0.1 <img src=x onerror=alert(1)>", False),
        ("127.1", False),
        ("999.1.1.1", False),
    ],
)
def test_is_valid_target(host, valid):
    assert is_valid_target(host) is valid


def test_localhost_valide_mais_refuse_par_la_politique():
    """La syntaxe ne suffit plus : une cible interne est refusée par défaut.

    Il faut ALLOW_PRIVATE_TARGETS=1 pour analyser localhost ou son réseau local.
    """
    assert is_valid_target("localhost") is True
    with pytest.raises(TargetNotAllowedError):
        asyncio.run(ensure_target_allowed("localhost"))


@pytest.mark.parametrize(
    "domain", ["../../etc/passwd", r"..\..\.env", "example.com", "2001:db8::1", "a" * 300]
)
def test_screenshot_filename_est_confine(domain):
    """Le nom de capture ne contient jamais de séparateur de chemin et respecte le
    motif que l'API sert, supprime et nettoie (TEST-10 c)."""
    from domainrecon.api import storage

    name = screenshot_filename(domain)
    assert "/" not in name and "\\" not in name and ".." not in name
    assert SCREENSHOT_NAME_RE.fullmatch(name)
    assert storage._SCREENSHOT_NAME_RE.fullmatch(name)


def test_screenshot_filename_unique():
    """Deux scans du même domaine dans la même seconde ne partagent pas de fichier."""
    assert screenshot_filename("example.com") != screenshot_filename("example.com")


# =============================================================================
# Score de sécurité
# =============================================================================


def _scan_complet():
    """Un scan où tous les critères sont mesurés et conformes."""
    return {
        "security_headers": {"score": "7/7", "measured": True, "headers_found": {"a": "b"}},
        # `https` et `valid` : contrat TLS de la phase 1 (certificat servi et vérifié).
        "tls_certificate": {
            "measured": True,
            "https": True,
            "valid": True,
            "days_remaining": 200,
            "protocol": "TLSv1.3",
        },
        "email_security": {"measured": True, "overall_grade": "A"},
        "waf": {"measured": True, "detected": True, "waf_name": "Cloudflare"},
        "cookie_security": {"measured": True, "cookies_present": True, "score": "A"},
        "cors": {"measured": True, "misconfigured": False},
        "redirect_chain": {"measured": True, "forces_https": True},
        "subdomain_takeover": [],
        "subdomains_checked": 5,
    }


def test_score_parfait():
    result = compute_security_score(_scan_complet())
    assert result["score"] == 100
    assert result["grade"] == "A"
    assert result["coverage"] == 100
    assert result["confidence"] == "high"


def test_domaine_injoignable_ne_marque_aucun_point():
    """Régression : un domaine mort récoltait 20/100 en points « gratuits ».

    Cookies non mesurés, CORS non testable et absence de takeover étaient
    comptés comme conformes.
    """
    result = compute_security_score(
        {
            "security_headers": {"score": "0/7", "measured": False},
            "tls_certificate": {"measured": False, "error": "timeout"},
            "email_security": {"measured": False},
            "waf": {"measured": False},
            "cookie_security": {"measured": False},
            "cors": {"measured": False},
            "redirect_chain": {"measured": False},
            "subdomain_takeover": [],
            "subdomains_checked": 0,
        }
    )
    assert result["score"] == 0
    assert result["grade"] == "N/A"
    assert result["coverage"] == 0
    assert result["measured_max"] == 0


def test_criteres_non_mesures_exclus_du_denominateur():
    """Un site sans cookie ne doit ni être pénalisé ni gagner de points."""
    scan = _scan_complet()
    scan["cookie_security"] = {"measured": True, "cookies_present": False, "score": "N/A"}

    result = compute_security_score(scan)

    assert result["breakdown"]["cookies"]["measured"] is False
    assert result["measured_max"] == 90  # 100 - 10 points de cookies
    assert result["score"] == 100  # tous les critères applicables sont conformes
    # Sans cookie, le critère est sans objet : hors du dénominateur de la couverture.
    assert result["breakdown"]["cookies"]["applicable"] is False
    assert result["coverage"] == 100


def test_couverture_partielle_baisse_la_confiance():
    scan = _scan_complet()
    for key in ("waf", "cookie_security", "cors", "redirect_chain"):
        scan[key] = {"measured": False}
    scan["subdomains_checked"] = 0

    result = compute_security_score(scan)

    assert result["coverage"] == 60  # headers 25 + tls 20 + email 15
    assert result["confidence"] == "medium"


def test_takeover_vulnerable_annule_les_points():
    scan = _scan_complet()
    scan["subdomain_takeover"] = [{"subdomain": "dead.example.com", "risk": "high"}]

    result = compute_security_score(scan)

    assert result["breakdown"]["takeover"]["score"] == 0
    # Contrat §6 : un takeover confirmé plafonne le grade (au plus D) ; il
    # laissait auparavant le grade à A (95/100). Détail du barème : test_score.py.
    assert result["grade_cap"] == "D"
    assert result["grade"] in {"D", "F"}


def test_cors_mal_configure_penalise():
    scan = _scan_complet()
    scan["cors"] = {"measured": True, "misconfigured": True}

    result = compute_security_score(scan)

    assert result["breakdown"]["cors"]["score"] == 0
    assert result["score"] == 90


def test_scans_anciens_sans_drapeau_measured():
    """Les scans enregistrés avant l'ajout des drapeaux restent lisibles."""
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
    # Valeurs exactes (TEST-10 a) : en-têtes 5/7 -> 18/25, TLS valide 1.2 et
    # 100 j -> 18/20, email B -> 12, cookies B -> 7, CORS 10, HTTPS 5 ; WAF
    # absent en bonus non compté, takeover sans sous-domaine non mesuré.
    assert result["measured_points"] == 70 and result["measured_max"] == 85
    assert result["score"] == 82
    assert result["grade"] == "B"
