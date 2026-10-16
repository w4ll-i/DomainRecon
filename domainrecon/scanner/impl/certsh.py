# =============================================================================
# DomainRecon - Journaux Certificate Transparency : liste des certificats
# =============================================================================
# À partir des entrées des journaux CT (impl/ct_common.py, requête partagée avec le
# module « subdomains » : crt.sh n'est interrogé qu'une fois par heure et par
# domaine), établit :
#   - la liste des certificats les plus récents (identifiant, validité, émetteur,
#     noms) et des statistiques (certificats valides/échus, jokers, émetteurs) ;
#   - les NOMS VUS SEULEMENT EN CT : sous-domaines qui figurent dans un certificat
#     public mais ne résolvent pas en DNS (environnements retirés, noms internes
#     divulgués par un certificat émis par une autorité publique).
# Les dates viennent des champs `not_before` / `not_after` : crt.sh n'expose pas
# de date d'inscription au journal dans son JSON (aucun champ `logged_at` : ne pas
# trier dessus). Les identifiants servent à dédoublonner et à ordonner.
# =============================================================================

import asyncio
import re
from datetime import datetime, timezone

from .. import dns as scanner_dns
from ..common import logger
from ..targets import resolve_ip
from . import ct_common

MAX_CERTS = 200
MAX_SAN = 25
MAX_ISSUERS = 10
RESOLVE_LIMIT = 60
RESOLVE_CONCURRENCY = 10
MAX_CT_ONLY = 100

_ORG = re.compile(r"(?:^|,\s*)O=([^,]+)")
_CN = re.compile(r"(?:^|,\s*)CN=([^,]+)")


def issuer_label(issuer_name: str) -> str:
    """Nom lisible de l'émetteur : organisation (O=), sinon nom commun (CN=)."""
    for pattern in (_ORG, _CN):
        match = pattern.search(issuer_name)
        if match:
            return match.group(1).strip().strip('"')[:60]
    return issuer_name[:60]


def _date(value: str) -> str:
    return value[:10] if isinstance(value, str) else ""


def _sort_key(entry: dict) -> tuple:
    ident = entry.get("id")
    return (_date(entry.get("not_before", "")), ident if isinstance(ident, int) else 0)


def dedupe(entries: list[dict]) -> list[dict]:
    """Un certificat par identifiant (crt.sh renvoie parfois la même ligne pour plusieurs noms)."""
    seen: set = set()
    unique = []
    for entry in entries:
        key = (
            entry.get("id")
            if entry.get("id") is not None
            else (entry.get("not_before"), entry.get("name_value"))
        )
        if key in seen:
            continue
        seen.add(key)
        unique.append(entry)
    return unique


def certificate(entry: dict, today: str) -> dict:
    names = [n.strip().lower() for n in entry.get("name_value", "").splitlines() if n.strip()]
    not_after = _date(entry.get("not_after", ""))
    return {
        "id": entry.get("id"),
        "not_before": _date(entry.get("not_before", "")),
        "not_after": not_after,
        "expired": bool(not_after) and not_after < today,
        "issuer": issuer_label(entry.get("issuer_name", "")),
        "common_name": entry.get("common_name", ""),
        "san": names[:MAX_SAN],
        "san_count": len(names),
        "wildcard": any(n.startswith("*.") for n in names),
    }


async def _unresolved(names: list[str]) -> list[str]:
    """Noms qui ne résolvent pas en DNS (parmi `names`)."""
    semaphore = asyncio.Semaphore(RESOLVE_CONCURRENCY)

    async def check(name: str) -> str | None:
        async with semaphore:
            try:
                return None if await resolve_ip(name) else name
            except Exception as e:  # un nom anormal ne doit pas faire échouer le module
                logger.debug("Résolution de %s échouée : %r", name, e)
                return None

    return [name for name in await asyncio.gather(*(check(n) for n in names)) if name]


async def analyze(domain: str) -> dict:
    """Certificats CT de `domain` et noms vus seulement en CT. Lève ModuleError si aucune source ne répond."""
    entries, source, fallback_cause = await ct_common.fetch_ct_entries(domain)
    unique = sorted(dedupe(entries), key=_sort_key, reverse=True)
    today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    certs = [certificate(entry, today) for entry in unique[:MAX_CERTS]]

    counts: dict[str, int] = {}
    for entry in unique:
        label = issuer_label(entry.get("issuer_name", ""))
        if label:
            counts[label] = counts.get(label, 0) + 1
    issuers = [
        {"name": name, "count": count}
        for name, count in sorted(counts.items(), key=lambda item: (-item[1], item[0]))[:MAX_ISSUERS]
    ]
    dates = [_date(e.get("not_before", "")) for e in unique if e.get("not_before")]

    # Noms vus en CT, du plus récent au plus ancien, et leur dernière apparition.
    last_seen: dict[str, str] = {}
    expired: dict[str, bool] = {}
    for entry in unique:
        for name in scanner_dns._extract_ct_names([entry], domain):
            if name not in last_seen:
                last_seen[name] = _date(entry.get("not_before", ""))
                expired[name] = _date(entry.get("not_after", "")) < today
    names = sorted(last_seen, key=lambda n: (last_seen[n], n), reverse=True)

    wildcard_dns = bool(await scanner_dns._wildcard_addresses(domain)) if names else False
    ct_only: list[dict] = []
    checked = 0
    if names and not wildcard_dns:
        sample = names[:RESOLVE_LIMIT]
        checked = len(sample)
        for name in sorted(await _unresolved(sample)):
            ct_only.append({"name": name, "last_seen": last_seen[name], "expired": expired[name]})

    return {
        "measured": True,
        "error": None,
        "domain": domain,
        "source": source,
        "partial": source != ct_common.SOURCE_CRTSH,
        "fallback_cause": fallback_cause,
        "total_certs": len(entries),
        "unique_certs": len(unique),
        "active_certs": sum(1 for e in unique if _date(e.get("not_after", "")) >= today),
        "wildcard_certs": sum(
            1 for e in unique if any(n.startswith("*.") for n in e.get("name_value", "").splitlines())
        ),
        "issuers": issuers,
        "date_range": {"oldest": min(dates), "newest": max(dates)} if dates else {},
        "certs": certs,
        "name_count": len(names),
        "ct_only": ct_only[:MAX_CT_ONLY],
        "ct_only_count": len(ct_only),
        "ct_only_checked": checked,
        "wildcard_dns": wildcard_dns,
    }
