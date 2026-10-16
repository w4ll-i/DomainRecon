# =============================================================================
# DomainRecon - Aides des tests des rapports et de la ligne de commande
# =============================================================================
# Un scan enregistré réaliste, sans réseau : ports exposés (Redis : constat
# critique), certificat proche de l'expiration (constat moyen), un module en
# échec. La note est fixée à B pour que les seuils de --fail-under aient un sens.
# =============================================================================

import itertools

from domainrecon.scanner.score import compute_security_score

_counter = itertools.count(1)


def build_result(domain: str = "example.com", grade: str = "B", score: int = 82, **overrides) -> dict:
    """Résultat de scan tel que perform_full_scan le rend (puis enregistré par save_scan)."""
    status = {
        "tls_certificate": {"status": "ok", "error": None},
        "open_ports": {"status": "ok", "error": None},
        "dns_records": {"status": "ok", "error": None},
        "waf": {"status": "failed", "error": {"$t": "whois.timeout", "p": {"seconds": 5}}},
    }
    data = {
        "tls_certificate": {
            "https": True,
            "valid": True,
            "days_remaining": 5,
            "protocol": "TLSv1.3",
            "issuer": "Test CA",
            "subject": domain,
        },
        "open_ports": [{"port": 6379, "state": "open"}, {"port": 443, "state": "open"}],
        "dns_records": {"A": ["93.184.216.34"], "measured": True},
    }
    score_input = dict(data, module_status=status, modules_launched=list(status))
    security_score = compute_security_score(score_input)
    security_score.update(grade=grade, score=score, max_score=100, coverage=88)
    result = {
        "domain": domain,
        "ip_address": "93.184.216.34",
        **data,
        "security_score": security_score,
        "module_status": status,
        "modules": {},
        "scan_duration": 3.2,
        "status": "partial",
        "profile": "rapide",
        "modules_launched": list(status),
    }
    result.update(overrides)
    return result


def unique_domain(prefix: str = "rapport") -> str:
    """Domaine propre à chaque appel : les tests partagent la base de la session."""
    return f"{prefix}{next(_counter)}-{id(object()) % 100000}.example.org"
