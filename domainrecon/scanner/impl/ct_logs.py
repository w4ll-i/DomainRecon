# =============================================================================
# DomainRecon - Historique des certificats : journaux Certificate Transparency
# =============================================================================
# Logique du module « ct_logs » (modules/ct_logs.py). Liste des
# certificats, émetteurs et SAN, avec ces précautions :
#   - le JSON actuel de crt.sh n'a plus ni `logged_at` ni `min_cert_id` : la
#     dédoublonnage se fait sur le numéro de série (le certificat et son
#     pré-certificat ont des `id` différents), le tri sur `not_before` ;
#   - l'émetteur était coupé à la première virgule (« "CLOUDFLARE ») : le nom
#     d'organisation est lu en respectant les guillemets du DN ;
#   - délai de 15 s trop court (crt.sh met jusqu'à 20 s) : 30 s, une nouvelle
#     tentative sur les erreurs passagères, puis Cert Spotter en secours (liste
#     partielle : sans clé d'API il ne couvre que des certificats récents).
# Sources : https://crt.sh/ (JSON `?q=%.domaine&output=json`) et
# https://sslmate.com/help/reference/ct_search_api_v1 (Cert Spotter). La requête
# est celle de impl/ct_common.py, partagée et mise en cache avec « subdomains » et
# « certsh_data » : crt.sh, qui limite le débit, n'est interrogé qu'une fois par
# domaine et par heure.
# =============================================================================

import re
from collections import Counter
from datetime import datetime, timedelta, timezone

from . import ct_common

# Bornes des résultats renvoyés (le total reste donné).
MAX_RECORDS = 20000
MAX_LISTED_CERTS = 100
MAX_LISTED_NAMES = 100
MAX_ISSUERS = 10
MAX_INTERNAL_NAMES = 20
INTERNAL_WINDOW_DAYS = 365
MANY_ISSUERS_THRESHOLD = 5

# Mots désignant un usage interne ou de préproduction dans un nom d'hôte.
INTERNAL_WORDS = frozenset(
    {
        "internal",
        "intranet",
        "corp",
        "vpn",
        "staging",
        "stage",
        "preprod",
        "uat",
        "dev",
        "test",
        "admin",
        "jenkins",
        "gitlab",
        "vault",
        "jira",
        "confluence",
        "grafana",
        "kibana",
        "sso",
    }  # fmt: skip
)

# Nom d'hôte plausible (un joker n'est admis qu'en tête) : écarte les « ?.domaine » et les adresses e-mail.
_NAME_RE = re.compile(r"(\*\.)?[a-z0-9_]([a-z0-9_.-]*[a-z0-9_])?")
_ORG_RE = re.compile(r'(?:^|,\s*)O=("(?:[^"]|"")*"|[^,]*)')
_CN_RE = re.compile(r'(?:^|,\s*)CN=("(?:[^"]|"")*"|[^,]*)')


def _unquote(value: str) -> str:
    value = value.strip()
    if len(value) >= 2 and value[0] == value[-1] == '"':
        value = value[1:-1].replace('""', '"')
    return value.strip()


def issuer_organization(issuer_name: str) -> str:
    """Organisation d'un DN d'émetteur (« C=US, O=Let's Encrypt, CN=R3 »), sinon son CN."""
    for pattern in (_ORG_RE, _CN_RE):
        found = pattern.search(issuer_name or "")
        if found and _unquote(found.group(1)):
            return _unquote(found.group(1))[:80]
    return (issuer_name or "")[:80]


def _day(value: object) -> str:
    return str(value or "")[:10]


# =============================================================================
# Source : requête partagée (impl/ct_common.py)
# =============================================================================


def normalize(entry: dict) -> dict | None:
    """Certificat normalisé à partir d'une entrée de ct_common (crt.sh ou Cert Spotter)."""
    if not isinstance(entry, dict):
        return None
    names = [
        name.strip().lower().rstrip(".")
        for name in str(entry.get("name_value") or "").splitlines()
        if name.strip()
    ]
    issuer_name = str(entry.get("issuer_name") or "")
    return {
        "id": entry.get("id"),
        "issuer": issuer_organization(issuer_name),
        "issuer_name": issuer_name,
        "common_name": str(entry.get("common_name") or "")[:120],
        "names": names,
        "not_before": _day(entry.get("not_before")),
        "not_after": _day(entry.get("not_after")),
    }


async def fetch_records(domain: str) -> tuple[list[dict], str, bool]:
    """(certificats, source, partiel) : crt.sh, ou Cert Spotter si crt.sh échoue (alors partiel)."""
    entries, source, _ = await ct_common.fetch_ct_entries(domain)
    records = [r for r in map(normalize, entries[: MAX_RECORDS * 2]) if r]
    return records, source, source != ct_common.SOURCE_CRTSH


# =============================================================================
# Analyse
# =============================================================================


def _parse_day(value: str) -> datetime | None:
    try:
        return datetime.strptime(value, "%Y-%m-%d").replace(tzinfo=timezone.utc)
    except ValueError:
        return None


def _in_site(name: str, site: str) -> bool:
    return name == site or name.endswith("." + site)


def _is_internal(name: str, site: str) -> bool:
    if not _in_site(name, site) or name == site:
        return False
    labels = re.split(r"[.\-_]", name[: -len(site) - 1])
    return any(label in INTERNAL_WORDS for label in labels)


def analyze(records: list[dict], site: str, now: datetime | None = None) -> dict:
    """Synthèse de l'historique des certificats d'un domaine (JSON, volume borné)."""
    now = now or datetime.now(timezone.utc)
    unique: dict[str, dict] = {}
    for record in records:
        # crt.sh liste le pré-certificat et le certificat final (ids différents) : mêmes dates, émetteur
        # et noms. Le numéro de série n'est pas conservé par ct_common : on dédoublonne sur ces champs.
        key = f"{record['not_before']}|{record['not_after']}|{record['issuer_name']}|{'|'.join(record['names'])}"
        unique.setdefault(key, record)
    ordered = sorted(unique.values(), key=lambda r: (r["not_before"], str(r["id"])), reverse=True)
    certs = ordered[:MAX_RECORDS]

    issuers: Counter[str] = Counter()
    issuer_last: dict[str, str] = {}
    by_year: Counter[str] = Counter()
    names: dict[str, dict] = {}
    expired = active = recent_30 = 0
    recent_issuers: set[str] = set()
    internal: dict[str, str] = {}
    window = now - timedelta(days=INTERNAL_WINDOW_DAYS)
    for cert in certs:
        not_before, not_after = _parse_day(cert["not_before"]), _parse_day(cert["not_after"])
        issuers[cert["issuer"]] += 1
        issuer_last.setdefault(cert["issuer"], cert["not_before"])
        if cert["not_before"]:
            by_year[cert["not_before"][:4]] += 1
        if not_after is not None:
            if not_after < now:
                expired += 1
            else:
                active += 1
        if not_before is not None and (now - not_before).days <= 30:
            recent_30 += 1
        if not_before is not None and not_before >= window:
            recent_issuers.add(cert["issuer"])
        for name in cert["names"]:
            base = name.removeprefix("*.")
            if not _NAME_RE.fullmatch(name) or not _in_site(base, site):
                continue
            entry = names.setdefault(name, {"name": name, "certs": 0, "last_seen": cert["not_before"]})
            entry["certs"] += 1
            if not_before is not None and not_before >= window and _is_internal(base, site):
                internal.setdefault(base, cert["not_before"])

    dates = [c["not_before"] for c in certs if c["not_before"]]
    listed_names = sorted(names.values(), key=lambda n: (n["last_seen"], n["name"]), reverse=True)
    return {
        "measured": True,
        "error": None,
        "total_certs": len(certs),
        "truncated": len(ordered) > MAX_RECORDS,
        "active_certs": active,
        "expired_certs": expired,
        "issued_last_30_days": recent_30,
        "first_seen": min(dates) if dates else None,
        "last_seen": max(dates) if dates else None,
        "by_year": dict(sorted(by_year.items())),
        "issuers": [
            {"name": name, "count": count, "last_seen": issuer_last.get(name)}
            for name, count in issuers.most_common(MAX_ISSUERS)
        ],
        "recent_issuer_count": len(recent_issuers),
        "name_count": len(names),
        "wildcard_names": sum(1 for name in names if name.startswith("*.")),
        "names": listed_names[:MAX_LISTED_NAMES],
        "internal_names": sorted(internal)[:MAX_INTERNAL_NAMES],
        "internal_name_count": len(internal),
        "certs": [
            {
                "id": cert["id"],
                "not_before": cert["not_before"],
                "not_after": cert["not_after"],
                "issuer": cert["issuer"],
                "common_name": cert["common_name"],
                "names": cert["names"][:8],
                "name_count": len(cert["names"]),
            }
            for cert in certs[:MAX_LISTED_CERTS]
        ],
    }
