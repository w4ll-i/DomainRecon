# =============================================================================
# DomainRecon - Tests des points à corriger (scanner/findings.py)
# =============================================================================

import pytest

from domainrecon.i18n import msg
from domainrecon.scanner.families import compute_families
from domainrecon.scanner.findings import SEVERITIES, compute_findings
from domainrecon.scanner.headers import SECURITY_HEADERS
from domainrecon.scanner.orchestrator import MODULE_NAMES
from domainrecon.scanner.score import compute_security_score, sensitive_open_ports, takeover_confirmed
from rendu import en, fr

# Comportement des 18 modules historiques : registre ramené à eux (tests/conftest.py).
pytestmark = pytest.mark.usefixtures("registre_historique")


def scan_sain() -> dict:
    """Scan sans aucun point à corriger (tous les modules mesurés)."""
    return {
        "module_status": {name: {"status": "ok", "error": None} for name in MODULE_NAMES},
        "security_headers": {
            "measured": True,
            "https": True,
            "https_downgrade": False,
            "checks": {name: {"value": "x", "status": "ok", "detail": "x"} for name in SECURITY_HEADERS},
        },
        "tls_certificate": {
            "measured": True,
            "https": True,
            "valid": True,
            "days_remaining": 200,
            "protocol": "TLSv1.3",
        },
        "redirect_chain": {"measured": True, "forces_https": True, "https_downgrade": False, "chain": [{}]},
        "cors": {"measured": True, "reflects_origin": False, "reflects_with_credentials": False},
        "cookie_security": {"measured": True, "cookies": [{"name": "sid", "issues": []}]},
        "web_files": {"measured": True, "security_txt": {"found": True}},
        "email_security": {
            "measured": True,
            "spf": {"found": True, "grade": "A"},
            "dmarc": {"found": True, "policy": "reject"},
        },
        "subdomain_takeover": [],
        "open_ports": [{"port": 443, "state": "open", "service": "HTTPS"}],
    }


def test_constantes():
    assert SEVERITIES == ("critical", "high", "medium", "low")


def test_scan_sain_aucun_point():
    assert compute_findings(scan_sain()) == []


def test_tri_par_gravite_puis_famille():
    scan = scan_sain()
    scan["open_ports"].append({"port": 6379, "state": "open", "service": "Redis"})
    scan["security_headers"]["checks"]["Strict-Transport-Security"]["status"] = "missing"
    scan["cookie_security"]["cookies"][0]["issues"] = [msg("cookies.no_secure")]
    scan["web_files"]["security_txt"]["found"] = False
    scan["email_security"]["dmarc"] = {"found": False}
    findings = compute_findings(scan)
    assert [(f["severity"], f["family"], f["module"]) for f in findings] == [
        ("critical", "network", "open_ports"),
        ("high", "web", "security_headers"),
        ("high", "email", "email_security"),
        ("medium", "web", "cookie_security"),
        ("low", "web", "web_files"),
    ]
    assert en(findings[0]["message"]) == "Port 6379 (Redis) exposed to the Internet"
    assert fr(findings[1]["message"]) == "En-tête HSTS absent : le navigateur peut être ramené en HTTP"
    assert fr(findings[3]["message"]) == "1 cookie(s) sans protections complètes : sid"


def test_certificat_invalide_critique_avec_raison_traduite():
    scan = scan_sain()
    scan["tls_certificate"].update(valid=False, verify_error=msg("tls.verify_10"))
    (finding,) = compute_findings(scan)
    assert (finding["severity"], finding["family"], finding["module"]) == (
        "critical",
        "tls",
        "tls_certificate",
    )
    assert fr(finding["message"]) == "Certificat TLS invalide : Certificat expiré"
    assert en(finding["message"]) == "Invalid TLS certificate: Certificate expired"


def test_certificat_bientot_expire_et_protocole_obsolete():
    scan = scan_sain()
    scan["tls_certificate"].update(days_remaining=5, protocol="TLSv1.1")
    assert [(f["severity"], en(f["message"])) for f in compute_findings(scan)] == [
        ("high", "The TLS certificate expires in 5 days"),
        ("medium", "Obsolete TLS protocol: TLSv1.1"),
    ]


def test_sans_https_pas_de_constat_hsts_ni_redirection():
    scan = scan_sain()
    scan["tls_certificate"].update(https=False, valid=False)
    scan["security_headers"]["https"] = False
    scan["security_headers"]["checks"]["Strict-Transport-Security"]["status"] = "invalid"
    scan["redirect_chain"]["forces_https"] = False
    assert [(f["severity"], f["module"]) for f in compute_findings(scan)] == [("high", "tls_certificate")]


def test_retrogradation_signalee_une_fois():
    scan = scan_sain()
    scan["redirect_chain"]["https_downgrade"] = True
    scan["security_headers"]["https_downgrade"] = True
    findings = compute_findings(scan)
    assert [f["module"] for f in findings] == ["redirect_chain"]
    assert en(findings[0]["message"]) == "An HTTPS URL redirects to HTTP: the encrypted connection is dropped"


def test_cors_takeover_email():
    scan = scan_sain()
    scan["cors"].update(
        reflects_origin=True, reflects_with_credentials=True, reflected_origin="https://evil.com"
    )
    scan["subdomain_takeover"] = [
        {"subdomain": "old.example.com", "provider": "Heroku", "confirmed": True, "risk": "high"},
        {"subdomain": "shop.example.com", "provider": "Shopify", "confirmed": False, "risk": "medium"},
    ]
    scan["email_security"]["dmarc"] = {"found": True, "policy": "none"}
    scan["email_security"]["spf"] = {"found": False}
    findings = compute_findings(scan)
    assert [(f["severity"], f["module"]) for f in findings] == [
        ("critical", "cors"),
        ("critical", "subdomain_takeover"),
        ("high", "email_security"),
        ("high", "subdomain_takeover"),
        ("medium", "email_security"),
    ]
    assert en(findings[1]["message"]) == "Subdomain takeover possible: old.example.com (Heroku)"


def test_module_en_echec_ignore():
    scan = scan_sain()
    scan["tls_certificate"].update(valid=False)
    scan["module_status"]["tls_certificate"] = {"status": "failed", "error": "x"}
    assert compute_findings(scan) == []


def test_ancien_scan_sans_module_status_ni_checks():
    scan = {
        "security_headers": {
            "headers_found": {"X-Frame-Options": "DENY"},
            "headers_missing": ["Strict-Transport-Security", "Content-Security-Policy"],
        },
        "open_ports": [23, 443],
    }
    assert [(f["severity"], f["module"]) for f in compute_findings(scan)] == [
        ("critical", "open_ports"),
        ("high", "security_headers"),
        ("medium", "security_headers"),
    ]


def test_donnees_inattendues_sans_erreur():
    assert compute_findings({}) == []
    assert compute_findings(None) == []
    assert (
        compute_findings(
            {"tls_certificate": "x", "open_ports": "y", "module_status": [], "subdomain_takeover": [None, 3]}
        )
        == []
    )


def test_module_mesure_selon_la_regle_des_familles():
    """Constats et familles lisent le même statut de module (families.module_run_status)."""
    # Ancien scan : résultat enregistré en erreur, module non mesuré, aucun constat.
    scan = {
        "security_headers": {
            "error": "Délai dépassé",
            "headers_found": {"X-Frame-Options": "DENY"},
            "headers_missing": ["Strict-Transport-Security"],
        },
    }
    assert compute_findings(scan) == []
    assert compute_families(scan)["web"]["state"] == "unmeasured"
    # Statut enregistré inconnu : « ok » pour les familles, donc pour les constats.
    scan = scan_sain()
    scan["open_ports"].append({"port": 6379, "state": "open", "service": "Redis"})
    scan["module_status"]["open_ports"] = {"status": "inattendu", "error": None}
    assert [f["module"] for f in compute_findings(scan)] == ["open_ports"]
    assert compute_families(scan)["network"]["state"] == "critical"


def test_module_non_lance_ne_fait_aucun_constat():
    """Un module absent de module_status (profil de scan) n'est pas mesuré, même si sa donnée parle."""
    scan = scan_sain()
    scan["open_ports"].append({"port": 6379, "state": "open", "service": "Redis"})
    scan["tls_certificate"]["valid"] = False
    assert sorted(f["module"] for f in compute_findings(scan)) == ["open_ports", "tls_certificate"]
    for module in ("open_ports", "tls_certificate"):
        del scan["module_status"][module]
    assert compute_findings(scan) == []
    familles = compute_families(scan)
    assert (familles["network"]["state"], familles["tls"]["state"]) == ("unmeasured", "unmeasured")
    # Déclarés lancés (modules_launched), ils sont lus comme un module sans statut : « ok », donc des constats.
    scan["modules_launched"] = ["open_ports", "tls_certificate"]
    assert sorted(f["module"] for f in compute_findings(scan)) == ["open_ports", "tls_certificate"]


def test_ancien_certificat_refuse_est_un_constat_critique():
    """Scan antérieur : « certificate verify failed » vaut certificat invalide (comme au barème)."""
    erreur = "[SSL: CERTIFICATE_VERIFY_FAILED] certificate verify failed: self signed certificate"
    scan = scan_sain()
    scan["tls_certificate"] = {"error": erreur}
    (finding,) = compute_findings(scan)
    assert (finding["severity"], finding["family"], finding["module"]) == (
        "critical",
        "tls",
        "tls_certificate",
    )
    assert en(finding["message"]) == f"Invalid TLS certificate: {erreur}"
    assert compute_security_score(scan)["breakdown"]["tls"]["score"] == 0
    # Sans module_status non plus, et avec measured=False hérité de l'ancien classement.
    scan["module_status"] = None
    scan["tls_certificate"] = {"measured": False, "error": erreur}
    assert [f["severity"] for f in compute_findings(scan)] == ["critical"]
    # Une autre erreur reste « non mesuré » : aucun constat.
    scan["tls_certificate"] = {"error": "timed out"}
    assert compute_findings(scan) == []


def test_redirection_non_signalee_seulement_sans_https_etabli():
    scan = scan_sain()
    scan["redirect_chain"]["forces_https"] = False
    # Module TLS en échec : « https: False » ne prouve rien, le défaut de redirection reste signalé.
    scan["module_status"]["tls_certificate"] = {"status": "failed", "error": "x"}
    scan["tls_certificate"] = {"measured": False, "https": False, "error": "x"}
    assert [(f["severity"], f["module"]) for f in compute_findings(scan)] == [("medium", "redirect_chain")]
    # Même sans module_status, un résultat TLS non mesuré ne supprime pas le constat.
    scan["module_status"] = None
    assert [f["module"] for f in compute_findings(scan)] == ["redirect_chain"]
    # HTTPS absent établi par un module TLS mesuré : seul le constat TLS demeure.
    scan["module_status"] = {name: {"status": "ok", "error": None} for name in MODULE_NAMES}
    scan["tls_certificate"] = {"measured": True, "https": False, "valid": False}
    assert [f["module"] for f in compute_findings(scan)] == ["tls_certificate"]


def test_cors_ancien_format_credentials_non_verifies():
    scan = scan_sain()
    scan["cors"] = {"measured": True, "reflects_origin": True, "reflected_origin": "https://evil.com"}
    (finding,) = compute_findings(scan)
    assert (finding["severity"], finding["module"]) == ("high", "cors")
    assert en(finding["message"]) == (
        "CORS: origin https://evil.com is reflected, credentials not verified (earlier scan)"
    )
    assert "sans credentials" not in fr(finding["message"])
    # Même données au barème : « origine reflétée », sanction pleine, sans plafond de grade.
    cors = compute_security_score(scan)["breakdown"]["cors"]
    assert (cors["score"], en(cors["detail"])) == (0, "Origin reflected")
    # Format actuel : l'absence de credentials est vérifiée, le constat l'affirme.
    scan["cors"]["reflects_with_credentials"] = False
    (finding,) = compute_findings(scan)
    assert finding["severity"] == "medium"
    assert en(finding["message"]) == "CORS: origin https://evil.com is reflected without credentials"
    assert compute_security_score(scan)["breakdown"]["cors"]["score"] == 4


# Ports enregistrés sous toutes les formes lues par le barème : le score et les constats
# doivent en tirer les mêmes conclusions.
PORTS_HETEROGENES = [
    "6379",
    " 3306 ",
    {"port": "23", "state": "open"},
    {"port": 445, "state": "closed"},
    {"port": "21"},
    "٣٣٠٦",
    "abc",
    True,
    None,
    1.5,
]


def test_ports_en_chaines_memes_conclusions_pour_le_score_et_les_constats():
    attendus = [
        (21, "FTP", "medium"),
        (23, "Telnet", "critical"),
        (3306, "MySQL", "high"),
        (6379, "Redis", "critical"),
    ]
    assert sensitive_open_ports(PORTS_HETEROGENES) == attendus
    assert sensitive_open_ports("6379") == [] and sensitive_open_ports(None) == []

    scan = scan_sain()
    scan["open_ports"] = PORTS_HETEROGENES
    constats = [f for f in compute_findings(scan) if f["module"] == "open_ports"]
    assert [(f["severity"], en(f["message"])) for f in constats] == [
        ("critical", "Port 23 (Telnet) exposed to the Internet"),
        ("critical", "Port 6379 (Redis) exposed to the Internet"),
        ("high", "Port 3306 (MySQL) exposed to the Internet"),
        ("medium", "Port 21 (FTP) exposed to the Internet"),
    ]
    penalites = compute_security_score(scan)["penalties"]
    assert [(p["key"], p["points"], p["severity"]) for p in penalites] == [
        ("port_21", 5, "medium"),
        ("port_23", 15, "critical"),
        ("port_3306", 10, "high"),
        ("port_6379", 15, "critical"),
    ]
    assert compute_families(scan)["network"]["state"] == "critical"


def test_takeover_ancien_format_memes_conclusions_pour_le_score_et_les_constats():
    entrees = [
        {"subdomain": "a.example.com", "provider": "Heroku", "risk": "high"},  # confirmé (ancien format)
        {"subdomain": "b.example.com", "provider": "S3", "risk": "high", "fingerprint_matched": False},
        {"subdomain": "c.example.com", "provider": "X", "confirmed": False, "risk": "medium"},
    ]
    assert [takeover_confirmed(e) for e in entrees] == [True, False, False]
    scan = scan_sain()
    scan["subdomain_takeover"] = entrees
    constats = [f["severity"] for f in compute_findings(scan) if f["module"] == "subdomain_takeover"]
    assert constats == ["critical", "high", "medium"]
    assert compute_security_score(scan)["grade_cap"] == "D"
