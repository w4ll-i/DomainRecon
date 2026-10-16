# =============================================================================
# DomainRecon - Implémentation : RDAP (successeur du WHOIS) pour le module « whois_data »
# =============================================================================
# RDAP (RFC 9082/9083) est le protocole que les registres doivent servir depuis
# janvier 2025 pour les gTLD ; le WHOIS (TCP/43) est en voie d'extinction (coupé
# par Nominet en février 2025) et reste le repli.
#
#   1. la table d'amorçage de l'IANA (https://data.iana.org/rdap/dns.json, gardée
#      24 h) donne le serveur RDAP de l'extension ;
#   2. GET <serveur>domain/<domaine> (Accept: application/rdap+json) ;
#   3. pour un registre « léger » (.com, .net…), le lien « related » mène au
#      serveur RDAP du bureau d'enregistrement, qui porte titulaire et contacts :
#      un saut supplémentaire, facultatif (son échec ne fait rien perdre).
#
# Le résultat reprend les clés de scanner/whois_lookup.py (le front les lit) :
# registrar, whois_server, dates, name_servers, status (codes EPP en camelCase),
# dnssec (« signedDelegation » / « unsigned »), registrant, emails, registered.
# Les requêtes passent par le client HTTP du scan (TLS vérifié, proxy, anti-SSRF).
# =============================================================================

import asyncio
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from urllib.parse import quote, urlsplit

import httpx

from .. import common
from ..cache import LONG_TTL, cached
from ..common import logger
from ..targets import is_ip_literal

BOOTSTRAP_URL = "https://data.iana.org/rdap/dns.json"
_ACCEPT = {"Accept": "application/rdap+json, application/json;q=0.8"}
# Délais (s) : amorçage, serveur du registre, bureau d'enregistrement.
BOOTSTRAP_TIMEOUT = 8
REGISTRY_TIMEOUT = 10
REGISTRAR_TIMEOUT = 8
# Délai global de l'étape RDAP (le repli WHOIS dispose ensuite de son propre délai).
RDAP_BUDGET = 15
# Réponse RDAP : taille maximale lue (les serveurs sérieux répondent en quelques Ko).
MAX_BODY = 512 * 1024
MAX_REDIRECTS = 2
MAX_EMAILS = 20
MAX_NAME_SERVERS = 30

_NO_DATA = (
    "registrar",
    "creation_date",
    "expiration_date",
    "updated_date",
    "name_servers",
    "status",
    "registrant",
    "emails",
)
_EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[A-Za-z]{2,}$")
_EPP_STATUSES = frozenset(
    s.lower()
    for s in (
        "ok",
        "inactive",
        "pendingCreate",
        "pendingDelete",
        "pendingRenew",
        "pendingTransfer",
        "pendingUpdate",
        "addPeriod",
        "autoRenewPeriod",
        "renewPeriod",
        "transferPeriod",
        "redemptionPeriod",
        "pendingRestore",
        "clientDeleteProhibited",
        "clientHold",
        "clientRenewProhibited",
        "clientTransferProhibited",
        "clientUpdateProhibited",
        "serverDeleteProhibited",
        "serverHold",
        "serverRenewProhibited",
        "serverTransferProhibited",
        "serverUpdateProhibited",
    )
)
TRANSFER_LOCKS = frozenset(("clienttransferprohibited", "servertransferprohibited"))


@dataclass(frozen=True)
class RdapOutcome:
    """Issue de l'étape RDAP : « ok » (données), « not_found » (404 du registre) ou « unavailable »."""

    kind: str
    data: dict | None = None


class _RdapError(Exception):
    """Échec de lecture d'une réponse RDAP (réseau, statut, format) ; ne porte jamais d'URL."""


class _RdapNotFound(Exception):
    """Le registre répond 404 : domaine non enregistré."""


# =============================================================================
# Dates et statuts
# =============================================================================


def parse_date(value: object) -> datetime | None:
    """Date WHOIS (« 2027-08-13 04:00:00+00:00 ») ou RDAP (« 2027-08-13T04:00:00Z ») en datetime UTC."""
    if not isinstance(value, str) or not value.strip():
        return None
    text = value.strip().replace("Z", "+00:00").replace("z", "+00:00")
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        try:
            parsed = datetime.strptime(text[:10], "%Y-%m-%d")
        except ValueError:
            return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


def days_until(value: object, now: datetime | None = None) -> int | None:
    """Jours entiers avant la date (négatif : passée) ; None si la date est illisible."""
    date = parse_date(value)
    if date is None:
        return None
    reference = now or datetime.now(timezone.utc)
    return (date - reference).days


def _format_date(value: object) -> str | None:
    """Même présentation que le chemin WHOIS : str(datetime) en UTC ; texte brut si illisible."""
    if not isinstance(value, str) or not value.strip():
        return None
    parsed = parse_date(value)
    return str(parsed.replace(microsecond=0)) if parsed else value.strip()[:40]


def epp_code(status: str) -> str:
    """« client delete prohibited » (RDAP) -> « clientDeleteProhibited » (EPP, comme le WHOIS)."""
    words = re.split(r"[\s_-]+", status.strip())
    words = [w for w in words if w]
    if not words:
        return ""
    if len(words) == 1:
        return words[0]
    return words[0].lower() + "".join(w[:1].upper() + w[1:] for w in words[1:])


def has_epp_status(statuses: list) -> bool:
    """Au moins un statut EPP standard (les ccTLD sans EPP n'ont pas de verrous à contrôler)."""
    return any(isinstance(s, str) and s.lower() in _EPP_STATUSES for s in statuses)


def has_transfer_lock(statuses: list) -> bool:
    return any(isinstance(s, str) and s.lower() in TRANSFER_LOCKS for s in statuses)


# =============================================================================
# Analyse d'une réponse RDAP
# =============================================================================


def _vcard(entity: dict) -> dict[str, list[str]]:
    """Champs texte d'une vCard jCard (RFC 7095) : {« fn »: [...], « org »: [...], « email »: [...]}."""
    fields: dict[str, list[str]] = {}
    card = entity.get("vcardArray")
    if not (isinstance(card, list) and len(card) == 2 and isinstance(card[1], list)):
        return fields
    for item in card[1]:
        if not (isinstance(item, list) and len(item) >= 4 and isinstance(item[0], str)):
            continue
        value = item[3]
        if isinstance(value, list):  # « org » peut être un tableau de composantes
            value = " ".join(str(v) for v in value if isinstance(v, str))
        if isinstance(value, str) and value.strip():
            fields.setdefault(item[0].lower(), []).append(value.strip())
    return fields


def _walk_entities(entities: object, depth: int = 0):
    """Entités et sous-entités (profondeur bornée)."""
    if not isinstance(entities, list) or depth > 4:
        return
    for entity in entities:
        if isinstance(entity, dict):
            yield entity
            yield from _walk_entities(entity.get("entities"), depth + 1)


def _roles(entity: dict) -> set[str]:
    return (
        {r.lower() for r in entity.get("roles", []) if isinstance(r, str)}
        if isinstance(entity.get("roles"), list)
        else set()
    )


def _unique(values) -> list[str]:
    seen: dict[str, str] = {}
    for value in values:
        if isinstance(value, str) and value.strip():
            seen.setdefault(value.strip().lower(), value.strip())
    return list(seen.values())


def _events(data: dict) -> dict[str, str]:
    """Dates des événements : {« registration »: …, « expiration »: …, « last changed »: …}."""
    found: dict[str, str] = {}
    for event in data.get("events", []) if isinstance(data.get("events"), list) else []:
        if isinstance(event, dict) and isinstance(event.get("eventAction"), str):
            date = event.get("eventDate")
            if isinstance(date, str):
                found.setdefault(event["eventAction"].lower(), date)
    return found


def parse_domain(data: dict) -> dict:
    """Objet RDAP « domain » -> champs au format du module (sans measured/registered/source)."""
    events = _events(data)
    entities = list(_walk_entities(data.get("entities")))

    registrar = None
    registrant = None
    emails: list[str] = []
    for entity in entities:
        roles = _roles(entity)
        card = _vcard(entity)
        if "registrar" in roles and not registrar:
            registrar = (card.get("fn") or card.get("org") or [None])[0]
            if not registrar and isinstance(entity.get("handle"), str):
                registrar = entity["handle"]
        if "registrant" in roles and not registrant:
            registrant = (card.get("org") or card.get("fn") or [None])[0]
        emails.extend(e for e in card.get("email", []) if _EMAIL_RE.match(e))

    name_servers = _unique(
        ns.get("ldhName", "").lower() if isinstance(ns, dict) else ""
        for ns in (data.get("nameservers") if isinstance(data.get("nameservers"), list) else [])
    )[:MAX_NAME_SERVERS]

    statuses = _unique(
        epp_code(s)
        for s in (data.get("status") if isinstance(data.get("status"), list) else [])
        if isinstance(s, str)
    )

    dnssec = None
    secure = data.get("secureDNS")
    if isinstance(secure, dict) and isinstance(secure.get("delegationSigned"), bool):
        dnssec = "signedDelegation" if secure["delegationSigned"] else "unsigned"

    port43 = data.get("port43")
    return {
        "registrar": registrar,
        "whois_server": port43.strip().lower() if isinstance(port43, str) and port43.strip() else None,
        "creation_date": _format_date(events.get("registration")),
        "expiration_date": _format_date(events.get("expiration")),
        "updated_date": _format_date(events.get("last changed")),
        "name_servers": name_servers,
        "status": statuses,
        "dnssec": dnssec,
        "registrant": registrant,
        "emails": _unique(emails)[:MAX_EMAILS],
    }


def related_rdap_url(data: dict, base: str) -> str | None:
    """Lien « related » vers le serveur RDAP du bureau d'enregistrement (https, hôte différent du registre)."""
    for link in data.get("links", []) if isinstance(data.get("links"), list) else []:
        if not isinstance(link, dict) or link.get("rel") != "related":
            continue
        href = link.get("href")
        kind = link.get("type")
        if not isinstance(href, str) or (isinstance(kind, str) and "rdap" not in kind):
            continue
        parts = urlsplit(href)
        if parts.scheme == "https" and parts.hostname and parts.hostname != urlsplit(base).hostname:
            return href
    return None


def merge(primary: dict, secondary: dict) -> dict:
    """Complète les champs vides de `primary` avec ceux de `secondary`."""
    merged = dict(primary)
    for key, value in secondary.items():
        if merged.get(key) in (None, "", []) and value not in (None, "", []):
            merged[key] = value
    return merged


def has_data(parsed: dict) -> bool:
    return any(parsed.get(field) for field in _NO_DATA)


# =============================================================================
# Requêtes
# =============================================================================


@cached(LONG_TTL, scope=common.proxy_scope, ignore=("client",))
async def load_bootstrap(client: httpx.AsyncClient) -> dict:
    """Table d'amorçage de l'IANA : {« tlds »: {extension: [URL de base, ...]}} (gardée 24 h)."""
    try:
        response = await client.get(BOOTSTRAP_URL, timeout=BOOTSTRAP_TIMEOUT)
    except httpx.HTTPError as e:
        raise _RdapError(type(e).__name__) from None
    if response.status_code != 200:
        raise _RdapError(f"http {response.status_code}")
    try:
        services = response.json().get("services", [])
    except (ValueError, AttributeError):
        raise _RdapError("illisible") from None
    tlds: dict[str, list[str]] = {}
    for service in services if isinstance(services, list) else []:
        if not (isinstance(service, list) and len(service) == 2):
            continue
        names, urls = service
        https = (
            [u for u in urls if isinstance(u, str) and u.startswith("https://")]
            if isinstance(urls, list)
            else []
        )
        for name in names if isinstance(names, list) else []:
            if isinstance(name, str) and https:
                tlds[name.lower()] = https
    if not tlds:
        raise _RdapError("table vide")
    return {"tlds": tlds}


def base_url(bootstrap: dict, domain: str) -> str | None:
    """URL de base RDAP de l'extension du domaine (suffixe le plus long présent dans la table)."""
    tlds = bootstrap.get("tlds") if isinstance(bootstrap, dict) else None
    if not isinstance(tlds, dict):
        return None
    labels = domain.lower().rstrip(".").split(".")
    for start in range(1, len(labels)):
        urls = tlds.get(".".join(labels[start:]))
        if urls:
            return urls[0] if urls[0].endswith("/") else urls[0] + "/"
    return None


async def _get_json(client: httpx.AsyncClient, url: str, timeout: float) -> dict:
    """GET RDAP avec au plus MAX_REDIRECTS redirections https suivies à la main (le client n'en suit aucune)."""
    for _ in range(MAX_REDIRECTS + 1):
        try:
            response = await client.get(url, headers=_ACCEPT, timeout=timeout)
        except httpx.HTTPError as e:
            raise _RdapError(type(e).__name__) from None
        status = response.status_code
        if status in (301, 302, 303, 307, 308):
            target = response.headers.get("location", "")
            url = str(httpx.URL(url).join(target)) if target else ""
            if not url.startswith("https://"):
                raise _RdapError("redirection refusée")
            continue
        if status == 404:
            raise _RdapNotFound
        if status != 200:
            raise _RdapError(f"http {status}")
        if len(response.content) > MAX_BODY:
            raise _RdapError("réponse trop volumineuse")
        try:
            data = response.json()
        except ValueError:
            raise _RdapError("illisible") from None
        if not isinstance(data, dict):
            raise _RdapError("illisible")
        return data
    raise _RdapError("trop de redirections")


async def _lookup(client: httpx.AsyncClient, domain: str) -> RdapOutcome:
    try:
        bootstrap = await load_bootstrap(client)
    except _RdapError:
        return RdapOutcome("unavailable")
    base = base_url(bootstrap, domain)
    if base is None:
        return RdapOutcome("unavailable")
    url = f"{base}domain/{quote(domain, safe='')}"
    try:
        data = await _get_json(client, url, REGISTRY_TIMEOUT)
    except _RdapNotFound:
        return RdapOutcome("not_found")
    except _RdapError:
        return RdapOutcome("unavailable")
    if data.get("errorCode") or str(data.get("objectClassName", "domain")).lower() != "domain":
        return RdapOutcome("unavailable")
    parsed = parse_domain(data)
    # Registre léger : titulaire et contacts chez le bureau d'enregistrement (un saut, facultatif).
    related = related_rdap_url(data, base)
    if related and (not parsed["registrant"] or not parsed["emails"]):
        try:
            extra = parse_domain(await _get_json(client, related, REGISTRAR_TIMEOUT))
        except (_RdapError, _RdapNotFound):
            extra = {}
        # Dates, serveurs et statuts du registre font foi : seuls les champs vides sont complétés.
        parsed = merge(parsed, extra)
    if not has_data(parsed):
        return RdapOutcome("unavailable")
    return RdapOutcome("ok", parsed)


async def lookup(client: httpx.AsyncClient, domain: str) -> RdapOutcome:
    """RDAP du domaine, borné à RDAP_BUDGET secondes ; jamais d'exception hors annulation."""
    if is_ip_literal(domain):
        return RdapOutcome("unavailable")
    try:
        return await asyncio.wait_for(_lookup(client, domain), RDAP_BUDGET)
    except Exception as e:  # noqa: BLE001 - toute panne du RDAP laisse la main au repli WHOIS (jamais CancelledError)
        logger.info("RDAP indisponible pour %s (%s) : repli sur le WHOIS", domain, type(e).__name__)
        return RdapOutcome("unavailable")
