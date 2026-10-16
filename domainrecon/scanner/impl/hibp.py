# =============================================================================
# DomainRecon - Module « hibp » : analyse des réponses de Have I Been Pwned
# =============================================================================
# Fonctions pures (sans réseau), testables seules.
# Documentation : https://haveibeenpwned.com/API/v3
#   - /breaches?Domain=<domaine> : catalogue public des brèches dont le site a ce
#     domaine, SANS clé (champs Name, Title, Domain, BreachDate, PwnCount,
#     DataClasses, IsVerified, IsSensitive, IsRetired, IsSpamList, IsMalware…) ;
#   - /breacheddomain/<domaine> : comptes du domaine retrouvés dans des brèches,
#     avec une clé (en-tête hibp-api-key) ET un domaine vérifié dans le tableau
#     de bord du compte (403 sinon) : {alias: [noms de brèches]}.
# =============================================================================

from ..score import as_dict, as_list
from .leaks_commun import mask_email, strip_html

# Nombre maximal de brèches et d'adresses gardées dans un résultat.
MAX_BREACHES = 50
MAX_ACCOUNT_SAMPLE = 5
# Classes de données qui rendent une brèche grave pour les comptes du domaine.
PASSWORD_CLASSES = frozenset(
    {"passwords", "password hints", "password strengths", "auth tokens", "historical passwords"}
)


def parse_catalog(payload: object, domains: set[str]) -> list[dict]:
    """Brèches du catalogue dont le domaine est l'un des `domains` (comparaison exacte, minuscules).

    Le filtre ?Domain= du service est exact ; on le revérifie ici : un service qui ignorerait
    le paramètre rendrait tout le catalogue (faux positifs). `payload` : la liste JSON.
    """
    wanted = {d.lower().removeprefix("www.") for d in domains}
    breaches: list[dict] = []
    for item in as_list(payload):
        entry = as_dict(item)
        domain = str(entry.get("Domain") or "").lower().removeprefix("www.")
        if not domain or domain not in wanted:
            continue
        classes = [str(c) for c in as_list(entry.get("DataClasses")) if isinstance(c, str)]
        try:
            pwn_count = max(0, int(entry.get("PwnCount") or 0))
        except (TypeError, ValueError):
            pwn_count = 0
        breaches.append(
            {
                "name": str(entry.get("Name") or "")[:80],
                "title": str(entry.get("Title") or "")[:120],
                "domain": domain,
                "date": str(entry.get("BreachDate") or "")[:10],
                "pwn_count": pwn_count,
                "data_classes": classes[:40],
                "passwords": any(c.lower() in PASSWORD_CLASSES for c in classes),
                "is_verified": entry.get("IsVerified") is True,
                "is_sensitive": entry.get("IsSensitive") is True,
                "is_retired": entry.get("IsRetired") is True,
                "is_spam_list": entry.get("IsSpamList") is True,
                "description": strip_html(str(entry.get("Description") or "")),
            }
        )
    breaches.sort(key=lambda b: (b["date"], b["name"]), reverse=True)
    return breaches[:MAX_BREACHES]


def parse_domain_accounts(payload: object, domain: str) -> dict:
    """Comptes du domaine (réponse de /breacheddomain) : nombre, brèches, échantillon d'adresses MASQUÉES."""
    accounts = as_dict(payload)
    breach_names: set[str] = set()
    for names in accounts.values():
        breach_names.update(str(n) for n in as_list(names) if isinstance(n, str))
    sample = [mask_email(f"{alias}@{domain}") for alias in sorted(accounts)[:MAX_ACCOUNT_SAMPLE]]
    return {
        "accounts": len(accounts),
        "accounts_breaches": sorted(breach_names)[:MAX_BREACHES],
        "accounts_sample": sample,
    }


def summarize(breaches: list[dict]) -> dict:
    """Totaux d'une liste de brèches."""
    classes: set[str] = set()
    for breach in breaches:
        classes.update(breach["data_classes"])
    return {
        "breach_count": len(breaches),
        "total_pwned": sum(b["pwn_count"] for b in breaches),
        "sensitive_count": sum(1 for b in breaches if b["is_sensitive"]),
        "passwords_exposed": any(b["passwords"] for b in breaches),
        "data_classes_seen": sorted(classes),
    }
