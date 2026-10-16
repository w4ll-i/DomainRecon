# =============================================================================
# DomainRecon - Module « emailrep » : adresses du domaine et réponses d'EmailRep
# =============================================================================
# Fonctions pures (sans réseau), testables seules.
# Documentation : https://docs.emailrep.io/ — GET https://emailrep.io/<adresse> avec l'en-tête
# « Key » (clé obligatoire depuis la coupure de l'API anonyme : HTTP 429 « the unauthenticated
# API is currently disabled »). Réponse 200 :
#   {email, reputation (high|medium|low|none), suspicious, references, details: {blacklisted,
#    malicious_activity, malicious_activity_recent, credentials_leaked, credentials_leaked_recent,
#    data_breach, first_seen, last_seen, domain_exists, domain_reputation, new_domain,
#    days_since_domain_creation, suspicious_tld, spam, free_provider, disposable, deliverable,
#    accept_all, valid_mx, spoofable, spf_strict, dmarc_enforced, profiles: [réseaux]}}
# Données personnelles : seules les adresses DU domaine analysé sont interrogées (minimisation),
# au plus MAX_EMAILS (l'offre gratuite autorise 10 requêtes par jour), et elles ne sont JAMAIS
# enregistrées en clair (« j***@domaine »).
# =============================================================================

import re

from ..score import as_dict, as_int, as_list
from .leaks_commun import mask_email

# Nombre maximal d'adresses interrogées par scan.
MAX_EMAILS = 5

_EMAIL = re.compile(
    r"(?<![A-Za-z0-9._%+-])([A-Za-z0-9][A-Za-z0-9._%+-]{0,63})@([A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+)"
)
# Pseudo-adresses des pages web : noms de fichiers d'images à deux densités (« logo@2x.png »).
_FALSE_POSITIVE = re.compile(r"(?i)\.(png|jpe?g|gif|svg|webp|css|js)$")


def extract_emails(text: str, apex: str) -> list[str]:
    """Adresses du domaine `apex` (ou d'un sous-domaine) trouvées dans un texte, minuscules, sans doublon."""
    apex = apex.lower()
    found: list[str] = []
    for local, host in _EMAIL.findall((text or "").replace("&#64;", "@").replace("%40", "@")):
        host = host.lower().rstrip(".")
        if _FALSE_POSITIVE.search(host):
            continue
        if host != apex and not host.endswith("." + apex):
            continue
        address = f"{local.lower()}@{host}"
        if address not in found:
            found.append(address)
    return found


def _bool(value: object) -> bool:
    return value is True


def parse_report(payload: object) -> dict:
    """Réputation d'une adresse, réduite aux indicateurs (sans l'adresse elle-même)."""
    data = as_dict(payload)
    details = as_dict(data.get("details"))
    reputation = str(data.get("reputation") or "none").lower()
    return {
        "reputation": reputation if reputation in ("high", "medium", "low", "none") else "none",
        "suspicious": _bool(data.get("suspicious")),
        "references": as_int(data.get("references")) or 0,
        "blacklisted": _bool(details.get("blacklisted")),
        "malicious_activity": _bool(details.get("malicious_activity")),
        "credentials_leaked": _bool(details.get("credentials_leaked")),
        "data_breach": _bool(details.get("data_breach")),
        "spam": _bool(details.get("spam")),
        "disposable": _bool(details.get("disposable")),
        "free_provider": _bool(details.get("free_provider")),
        "deliverable": details.get("deliverable") if isinstance(details.get("deliverable"), bool) else None,
        "profiles": [str(p)[:30] for p in as_list(details.get("profiles"))[:10]],
        "first_seen": str(details.get("first_seen") or "")[:10],
        "last_seen": str(details.get("last_seen") or "")[:10],
    }


def entry(address: str, report: dict) -> dict:
    """Entrée d'un résultat de module : adresse masquée + indicateurs."""
    return {"email": mask_email(address), **report}


def summarize(entries: list[dict]) -> dict:
    return {
        "leaked_count": sum(1 for e in entries if e.get("credentials_leaked")),
        "breached_count": sum(1 for e in entries if e.get("data_breach") and not e.get("credentials_leaked")),
        "malicious_count": sum(1 for e in entries if e.get("malicious_activity") or e.get("blacklisted")),
        "suspicious_count": sum(1 for e in entries if e.get("suspicious")),
    }
