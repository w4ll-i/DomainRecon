# =============================================================================
# DomainRecon - Scanner : DNS (enregistrements, sous-domaines, DNS inverse)
# =============================================================================
# Contient aussi les briques DNS partagées avec l'analyse email : requêtes
# bornées dans le temps (DnsQuerier), reconstitution des TXT multi-chaînes,
# recherche de l'enregistrement DMARC et reconnaissance du MX nul (RFC 7505).
# Un joker DNS (*.site) est détecté en résolvant un label aléatoire : sous un
# joker, qu'un nom résolve ne prouve pas qu'il existe.
# =============================================================================

import asyncio
import json
import secrets
import time
from typing import NamedTuple
from urllib.parse import parse_qs, urlsplit

import dns.exception
import dns.name
import dns.resolver
import dns.reversename
import httpx

from ..i18n import msg, render, unique
from .cache import MEDIUM_TTL, SHORT_TTL, cached
from .common import ACCEPT_ENCODING, _api_client, logger, proxy_scope
from .errors import ModuleError, TargetNotAllowedError, exception_text
from .http_utils import read_body_limited
from .targets import (
    is_ip_literal,
    is_valid_target,
    registrable_domain,
    resolve_addresses,
    resolve_ip,
    site_domain,
)

DNS_RECORD_TYPES = ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA"]

# Délai d'une requête DNS et budget total du module, inférieur à MODULE_TIMEOUT
# pour que le thread se termine avant l'expiration côté orchestrateur.
DNS_QUERY_TIMEOUT = 5.0
DNS_SCAN_BUDGET = 40.0

# Sous-domaines : la liste renvoyée contient tous les noms trouvés (au plus
# SUBDOMAIN_MAX_RESULTS) ; seuls les SUBDOMAIN_RESOLVE_LIMIT premiers, par
# ordre de priorité, sont résolus.
SUBDOMAIN_RESOLVE_LIMIT = 30
SUBDOMAIN_MAX_RESULTS = 1000
SUBDOMAIN_RESOLVE_CONCURRENCY = 10

CRTSH_URL = "https://crt.sh/"
CRTSH_TIMEOUT = 30.0
CRTSH_MAX_BYTES = 20 * 1024 * 1024
# crt.sh, souvent surchargé, renvoie par intermittence 404, 429 ou 5xx à une
# requête qui aboutit l'instant d'après : une seule nouvelle tentative, rapide.
# Un délai dépassé n'est pas retenté (le budget du module n'y suffirait pas).
CRTSH_ATTEMPTS = 2
CRTSH_RETRY_DELAY = 2.0
CRTSH_TRANSIENT_STATUSES = frozenset({404, 429, 500, 502, 503, 504})

# Source de secours quand crt.sh ne répond pas : l'API Cert Spotter (SSLMate).
# Sans clé d'API, elle ne voit que les certificats en cours de validité et
# limite le débit (une dizaine de requêtes par heure) : ses résultats sont
# partiels. Pages et budget bornés : crt.sh (délai compris) puis Cert Spotter
# tiennent dans MODULE_TIMEOUT.
CERTSPOTTER_URL = "https://api.certspotter.com/v1/issuances"
CERTSPOTTER_TIMEOUT = 10.0
CERTSPOTTER_BUDGET = 20.0
CERTSPOTTER_MAX_PAGES = 2
CERTSPOTTER_MAX_BYTES = 5 * 1024 * 1024

# Source des noms, reportée dans le résultat du module.
CT_SOURCE_CRTSH = "crt.sh"
CT_SOURCE_CERTSPOTTER = "certspotter"

# Cache des réponses des journaux CT (cache.cached), par domaine interrogé et par
# source : plusieurs cibles d'un même domaine (sous-domaines scannés à la suite)
# partagent la même requête, souvent volumineuse, au lieu de la répéter jusqu'à
# ce que crt.sh limite le débit. Les échecs ne sont pas mis en cache. Les noms de
# crt.sh (historique complet) sont gardés CT_CACHE_TTL ; ceux de la source de
# secours, partiels, CT_FALLBACK_CACHE_TTL seulement, pour laisser crt.sh reprendre
# la main dès qu'il répond de nouveau (il est réinterrogé tant qu'il échoue).
# Le proxy du scan fait partie de la clé (common.proxy_scope).
CT_CACHE_TTL = MEDIUM_TTL
CT_FALLBACK_CACHE_TTL = SHORT_TTL
CT_CACHE_MAX_ENTRIES = 64

# Premiers labels résolus en priorité : surface la plus exposée.
_PRIORITY_LABELS = frozenset(
    {
        "www",
        "mail",
        "webmail",
        "smtp",
        "imap",
        "mx",
        "vpn",
        "remote",
        "gateway",
        "api",
        "app",
        "admin",
        "portal",
        "auth",
        "sso",
        "login",
        "dev",
        "staging",
        "test",
        "beta",
        "preprod",
        "intranet",
        "shop",
        "blog",
        "cdn",
        "static",
    }
)


# =============================================================================
# Briques DNS partagées
# =============================================================================


class DnsLookup(NamedTuple):
    """Résultat normalisé d'une requête DNS."""

    status: str  # "ok", "nxdomain", "noanswer" ou "error"
    answers: list
    error: object | None = None  # message traduisible (ou texte)


def _make_resolver() -> dns.resolver.Resolver:
    """Résolveur système. Point d'injection des tests (résolveur simulé)."""
    return dns.resolver.Resolver()


class DnsQuerier:
    """Requêtes DNS bornées : délai par requête et budget total partagé.

    Distingue une réponse négative définitive (NXDOMAIN, aucune donnée) d'un
    échec de la requête (délai, SERVFAIL…), qui ne prouve rien sur le domaine.
    """

    def __init__(self, query_timeout: float, budget: float):
        self._resolver = _make_resolver()
        self._resolver.timeout = query_timeout
        self._query_timeout = query_timeout
        self._deadline = time.monotonic() + budget

    def lookup(self, name, rtype: str) -> DnsLookup:
        remaining = self._deadline - time.monotonic()
        if remaining <= 0:
            return DnsLookup("error", [], msg("dns.budget_exhausted"))
        try:
            answer = self._resolver.resolve(name, rtype, lifetime=min(self._query_timeout, remaining))
        except dns.resolver.NXDOMAIN:
            return DnsLookup("nxdomain", [])
        except dns.resolver.NoAnswer:
            return DnsLookup("noanswer", [])
        except dns.exception.Timeout:
            return DnsLookup("error", [], msg("net.timeout"))
        except dns.resolver.NoNameservers:
            return DnsLookup("error", [], msg("dns.no_nameservers"))
        except Exception as e:
            logger.debug("Requête DNS %s %s échouée : %r", name, rtype, e)
            return DnsLookup("error", [], msg("dns.query_failed", error=type(e).__name__))
        return DnsLookup("ok", list(answer))


def txt_record_text(rdata) -> str:
    """Texte d'un enregistrement TXT, chaînes de 255 octets recollées sans séparateur."""
    strings = getattr(rdata, "strings", None)
    if strings is None:
        return str(rdata).strip('"')
    return b"".join(strings).decode("utf-8", errors="replace")


def is_dmarc_record(text: str) -> bool:
    """Un enregistrement DMARC commence par le tag v=DMARC1 (RFC 7489 §6.6.3)."""
    name, _, value = text.split(";", 1)[0].partition("=")
    return name.strip().lower() == "v" and value.strip().upper() == "DMARC1"


class DmarcLookup(NamedTuple):
    """Enregistrements DMARC trouvés et nom DNS qui les porte."""

    records: list[str]
    source: str | None  # nom interrogé, par exemple « _dmarc.example.com »
    inherited: bool  # trouvés sur le domaine organisationnel, pas sur la cible
    error: object | None


def find_dmarc(querier: DnsQuerier, domain: str) -> DmarcLookup:
    """DMARC de `domain`, avec repli sur le domaine organisationnel (RFC 7489 §6.6.3)."""
    organizational = registrable_domain(domain)
    candidates = [domain] if organizational in ("", domain) else [domain, organizational]
    for index, name in enumerate(candidates):
        source = f"_dmarc.{name}"
        result = querier.lookup(source, "TXT")
        if result.status == "error":
            return DmarcLookup(
                [], source, index > 0, msg("dns.lookup_error", name=source, error=result.error)
            )
        records = [text for text in map(txt_record_text, result.answers) if is_dmarc_record(text)]
        if records:
            return DmarcLookup(records, source, index > 0, None)
    return DmarcLookup([], None, False, None)


def _is_root_exchange(mx) -> bool:
    """MX dont l'hôte est la racine « . » : forme du MX nul (RFC 7505)."""
    return getattr(mx, "exchange", None) == dns.name.root


def has_null_mx(answers: list) -> bool:
    """MX nul (RFC 7505) : un unique MX, vers la racine « . » ; le domaine n'accepte aucun courrier."""
    return len(answers) == 1 and _is_root_exchange(answers[0])


def _wildcard_probe_name(domain: str) -> str:
    """Label aléatoire sous `domain` : il n'existe pas, sauf joker DNS (*.domain)."""
    return f"dr-{secrets.token_hex(8)}.{domain}"


# =============================================================================
# Module 1 : DNS Records (dnspython)
# =============================================================================


def _format_mx(mx) -> dict:
    if _is_root_exchange(mx):
        # MX nul : la valeur « . » est conservée (rstrip la viderait).
        return {"priority": mx.preference, "value": ".", "null_mx": True}
    return {"priority": mx.preference, "value": str(mx.exchange).rstrip(".")}


def _format_answers(rtype: str, answers: list) -> list:
    if rtype == "MX":
        # Ordre de la réponse DNS aléatoire : MX principal (priorité la plus basse) en tête.
        return sorted(map(_format_mx, answers), key=lambda mx: (mx["priority"], mx["value"]))
    if rtype == "SOA":
        return [
            {
                "mname": str(soa.mname).rstrip("."),
                "rname": str(soa.rname).rstrip("."),
                "serial": soa.serial,
                "refresh": soa.refresh,
                "retry": soa.retry,
                "expire": soa.expire,
                "minimum": soa.minimum,
            }
            for soa in answers[:1]
        ]
    if rtype == "TXT":
        return [txt_record_text(r) for r in answers]
    return [str(r) for r in answers]


def _probe_wildcard(querier: DnsQuerier, site: str) -> list[str] | None:
    """Adresses d'un label aléatoire de `site` : [] sans joker DNS, None si la requête a échoué."""
    name = _wildcard_probe_name(site)
    for rtype in ("A", "AAAA"):
        result = querier.lookup(name, rtype)
        if result.status == "error":
            return None
        if result.status == "ok":
            return [str(r) for r in result.answers]
        if result.status == "nxdomain":
            return []
    return []


def _scan_dns_sync(domain: str) -> dict:
    """Scan DNS synchrone - exécuté dans un thread.

    Clés en majuscules : types d'enregistrements (plus « DMARC »), MX triés par
    priorité. Clés en minuscules : `dmarc_source`, `errors` (type -> raison
    d'un échec de requête), `nxdomain` (le nom n'existe pas : mesure valide),
    `wildcard` (joker DNS sur le site de la cible, None si la sonde a échoué),
    `notes` (constats lisibles), `measured` et `error` (contrat des modules).
    """
    querier = DnsQuerier(DNS_QUERY_TIMEOUT, DNS_SCAN_BUDGET)
    records: dict = {}
    errors: dict[str, object] = {}
    statuses: set[str] = set()

    for rtype in DNS_RECORD_TYPES:
        result = querier.lookup(domain, rtype)
        statuses.add(result.status)
        if result.status == "error":
            # Un échec de requête n'est pas une absence d'enregistrement.
            records[rtype] = []
            errors[rtype] = result.error
        else:
            records[rtype] = _format_answers(rtype, result.answers)

    # DMARC : même recherche que l'analyse email (cible, puis domaine
    # organisationnel), pour que les deux onglets concordent.
    dmarc = find_dmarc(querier, domain)
    records["DMARC"] = dmarc.records
    records["dmarc_source"] = dmarc.source
    if dmarc.error:
        errors["DMARC"] = dmarc.error

    # NXDOMAIN : toutes les réponses obtenues disent que le nom n'existe pas.
    # Une réponse vide (noanswer) ou une donnée prouve au contraire son existence.
    nxdomain = statuses - {"error"} == {"nxdomain"}
    site = site_domain(domain)
    wildcard = _probe_wildcard(querier, site)
    notes: list[object] = []
    if nxdomain:
        notes.append(msg("dns.nxdomain_note", domain=domain))
    if wildcard:
        notes.append(msg("dns.wildcard_note", site=site, addresses=", ".join(wildcard)))

    measured = len(errors) < len(DNS_RECORD_TYPES) + 1
    records["errors"] = errors
    records["nxdomain"] = nxdomain
    records["wildcard"] = None if wildcard is None else bool(wildcard)
    records["notes"] = notes
    records["measured"] = measured
    # Erreurs dédoublonnées, triées sur leur texte français (ordre stable), séparées par « ; ».
    records["error"] = (
        None
        if measured
        else msg(
            "dns.no_answer",
            errors=sorted(unique(list(errors.values())), key=lambda error: str(render(error, "fr"))),
            sep="; ",
        )
    )
    return records


async def scan_dns_records(domain: str) -> dict:
    """Scan tous les enregistrements DNS d'un domaine."""
    return await asyncio.to_thread(_scan_dns_sync, domain)


# =============================================================================
# Module 2 : Subdomain Discovery (Certificate Transparency : crt.sh, Cert Spotter)
# =============================================================================


def _extract_ct_names(entries: list, domain: str) -> set[str]:
    """Sous-domaines stricts de `domain` présents dans les entrées crt.sh."""
    suffix = "." + domain
    names = set()
    for entry in entries:
        value = entry.get("name_value") if isinstance(entry, dict) else None
        if not isinstance(value, str):
            continue
        for line in value.splitlines():
            name = line.strip().lower().rstrip(".")
            # Joker ramené à son nom de base : un certificat *.staging.example.com
            # est souvent la seule trace CT de staging.example.com.
            if name.startswith("*."):
                name = name[2:]
            # Frontière de label obligatoire (« myexample.com » n'est pas un
            # sous-domaine d'« example.com ») ; jokers restants, adresses
            # e-mail et noms invalides écartés.
            if name.startswith("*") or not name.endswith(suffix):
                continue
            if is_valid_target(name):
                names.add(name)
    return names


@cached(CT_CACHE_TTL, max_entries=CT_CACHE_MAX_ENTRIES, scope=proxy_scope)
async def _fetch_crtsh_names(domain: str) -> set[str]:
    """Interroge crt.sh ; lève ModuleError si la source ne répond pas correctement.

    La requête est celle de impl/ct_common.fetch_crtsh_entries, mise en cache :
    une seule interrogation de crt.sh par domaine sert les modules subdomains,
    certsh_data et ct_logs. Client des API tierces : TLS vérifié et aucune
    redirection suivie, pour qu'une réponse falsifiée n'injecte pas de faux
    sous-domaines (qui alimentent ensuite la résolution DNS et le takeover) ;
    corps borné et décompressé par morceaux.
    """
    from .impl import ct_common  # import tardif : ct_common importe ce fichier

    return _extract_ct_names(await ct_common.fetch_crtsh_entries(domain), domain)


def _certspotter_next_after(resp: httpx.Response) -> str | None:
    """Curseur `after` de la page suivante (en-tête Link rel="next"), ou None.

    Seul le curseur est repris : la page suivante est demandée à CERTSPOTTER_URL,
    jamais à une URL fournie par la réponse.
    """
    next_url = resp.links.get("next", {}).get("url")
    if not next_url:
        return None
    values = parse_qs(urlsplit(next_url).query).get("after")
    return values[0] if values and values[0].isdigit() else None


@cached(CT_FALLBACK_CACHE_TTL, max_entries=CT_CACHE_MAX_ENTRIES, scope=proxy_scope)
async def _fetch_certspotter_names(domain: str) -> set[str]:
    """Interroge Cert Spotter (source de secours) ; lève ModuleError en cas d'échec.

    Même client que crt.sh (TLS vérifié, aucune redirection). Au plus
    CERTSPOTTER_MAX_PAGES pages, pour ménager le quota sans clé d'API.
    """
    params = {"domain": domain, "include_subdomains": "true", "expand": "dns_names"}
    headers = {"Accept-Encoding": ACCEPT_ENCODING}
    entries: list[dict] = []
    try:
        async with _api_client(timeout=CERTSPOTTER_TIMEOUT) as client:
            for _ in range(CERTSPOTTER_MAX_PAGES):
                async with client.stream("GET", CERTSPOTTER_URL, params=params, headers=headers) as resp:
                    if resp.status_code == 429:
                        raise ModuleError(msg("dns.certspotter_quota"))
                    if resp.status_code != 200:
                        raise ModuleError(msg("dns.certspotter_http", status=resp.status_code))
                    body, truncated = await read_body_limited(resp, CERTSPOTTER_MAX_BYTES)
                    if truncated:
                        raise ModuleError(msg("dns.certspotter_too_large"))
                    after = _certspotter_next_after(resp)
                try:
                    data = json.loads(body)
                except ValueError as e:
                    raise ModuleError(msg("dns.certspotter_invalid_json")) from e
                if not isinstance(data, list):
                    raise ModuleError(msg("dns.certspotter_unexpected"))
                # Même forme que les entrées crt.sh : un nom par ligne.
                for issuance in data:
                    names = issuance.get("dns_names") if isinstance(issuance, dict) else None
                    if isinstance(names, list):
                        entries.append({"name_value": "\n".join(n for n in names if isinstance(n, str))})
                if not after or not data:
                    break
                params = {**params, "after": after}
    except httpx.TimeoutException as e:
        raise ModuleError(msg("dns.certspotter_timeout", seconds=f"{CERTSPOTTER_TIMEOUT:.0f}")) from e
    except (httpx.HTTPError, TargetNotAllowedError) as e:
        raise ModuleError(msg("dns.certspotter_unreachable", error=exception_text(e))) from e
    return _extract_ct_names(entries, domain)


async def _fetch_ct_names(domain: str) -> tuple[set[str], str]:
    """Noms des journaux CT : crt.sh, puis Cert Spotter si crt.sh échoue.

    Renvoie les noms et leur source ; lève ModuleError (avec les deux causes)
    si aucune source ne répond. Chaque source a son cache (CT_CACHE_TTL,
    CT_FALLBACK_CACHE_TTL) : un deuxième appel pour le même domaine ne refait
    pas la requête.
    """
    try:
        return await _fetch_crtsh_names(domain), CT_SOURCE_CRTSH
    except ModuleError as crtsh_error:
        logger.warning("crt.sh indisponible pour %s (%s) : repli sur Cert Spotter", domain, crtsh_error)
        try:
            names = await asyncio.wait_for(_fetch_certspotter_names(domain), timeout=CERTSPOTTER_BUDGET)
        except (asyncio.TimeoutError, TimeoutError) as e:
            second = msg("dns.certspotter_timeout", seconds=f"{CERTSPOTTER_BUDGET:.0f}")
            raise ModuleError(msg("dns.ct_both_failed", first=crtsh_error.message, second=second)) from e
        except ModuleError as e:
            raise ModuleError(msg("dns.ct_both_failed", first=crtsh_error.message, second=e.message)) from e
        return names, CT_SOURCE_CERTSPOTTER


def _subdomain_priority(name: str) -> tuple:
    return (name.split(".", 1)[0] not in _PRIORITY_LABELS, name.count("."), name)


class SubdomainList(list):
    """Liste renvoyée par find_subdomains, avec le nombre de noms trouvés et leur source.

    `total_found` : noms trouvés avant la coupe à SUBDOMAIN_MAX_RESULTS (égal à
    la longueur de la liste quand elle n'est pas tronquée). `source` :
    CT_SOURCE_CRTSH ou CT_SOURCE_CERTSPOTTER (None sans requête) ; `partial` :
    vrai pour la source de secours, qui ne voit que les certificats en cours
    de validité.
    """

    def __init__(self, entries=(), total_found: int | None = None, source: str | None = None):
        super().__init__(entries)
        self.total_found = len(self) if total_found is None else total_found
        self.source = source
        self.partial = source == CT_SOURCE_CERTSPOTTER


async def _wildcard_addresses(domain: str) -> set[str]:
    """Adresses d'un label aléatoire de `domain` : non vide si un joker DNS (*.domain) répond."""
    try:
        return set(await resolve_addresses(_wildcard_probe_name(domain)))
    except Exception as e:
        logger.debug("Sonde de joker DNS sur %s échouée : %r", domain, e)
        return set()


async def find_subdomains(domain: str) -> SubdomainList:
    """Découverte de sous-domaines via les journaux Certificate Transparency.

    Source : crt.sh, ou Cert Spotter (résultats partiels) si crt.sh ne répond pas.
    Renvoie tous les noms trouvés (au plus SUBDOMAIN_MAX_RESULTS), par ordre de
    priorité ; `total_found` de la liste compte les noms avant cette coupe.
    Champ `resolution` de chaque entrée : "resolved", "unresolved" (aucune
    adresse) ou "not_tested" (au-delà de SUBDOMAIN_RESOLVE_LIMIT). Sous un
    joker DNS (*.domain), une entrée résolue vers une adresse du joker porte
    `wildcard: True` : sa résolution ne prouve pas que le nom existe.
    """
    domain = (domain or "").strip().lower().rstrip(".")
    if not domain or is_ip_literal(domain):
        return SubdomainList()

    found, source = await _fetch_ct_names(domain)
    names = sorted(found, key=_subdomain_priority)
    total_found = len(names)
    if total_found > SUBDOMAIN_MAX_RESULTS:
        logger.warning(
            "%s : %d sous-domaines trouvés pour %s, liste limitée à %d",
            source,
            total_found,
            domain,
            SUBDOMAIN_MAX_RESULTS,
        )
        names = names[:SUBDOMAIN_MAX_RESULTS]

    semaphore = asyncio.Semaphore(SUBDOMAIN_RESOLVE_CONCURRENCY)

    async def resolve_sub(sub: str) -> dict:
        async with semaphore:
            try:
                ip = await resolve_ip(sub)
            except Exception as e:
                # Un nom anormal ne doit pas faire échouer tout le module.
                logger.debug("Résolution de %s échouée : %r", sub, e)
                ip = None
        return {"subdomain": sub, "ip": ip, "resolution": "resolved" if ip else "unresolved"}

    to_resolve = names[:SUBDOMAIN_RESOLVE_LIMIT]
    wildcard: set[str] = set()
    resolved: list[dict] = []
    if to_resolve:
        # Sonde du joker menée avec les résolutions, par le même résolveur système.
        wildcard, *resolved = await asyncio.gather(
            _wildcard_addresses(domain), *[resolve_sub(s) for s in to_resolve]
        )
    if wildcard:
        for entry in resolved:
            if entry["ip"] in wildcard:
                entry["wildcard"] = True
    not_tested = [
        {"subdomain": s, "ip": None, "resolution": "not_tested"} for s in names[SUBDOMAIN_RESOLVE_LIMIT:]
    ]
    return SubdomainList([*resolved, *not_tested], total_found=total_found, source=source)


# =============================================================================
# Module 16 : Reverse DNS
# =============================================================================


def _reverse_dns_sync(ip: str) -> dict:
    """Recherche PTR synchrone - exécutée dans un thread."""
    try:
        name = dns.reversename.from_address(ip)
    except (dns.exception.SyntaxError, ValueError):
        return {"ptr": None, "aliases": [], "measured": False, "error": msg("target.invalid_ip", ip=ip)}

    result = DnsQuerier(DNS_QUERY_TIMEOUT, DNS_QUERY_TIMEOUT).lookup(name, "PTR")
    if result.status == "error":
        return {
            "ptr": None,
            "aliases": [],
            "measured": False,
            "error": msg("dns.ptr_failed", error=result.error),
        }
    # NXDOMAIN ou aucune donnée : mesure valide, l'adresse n'a pas de PTR.
    hostnames = [str(r.target).rstrip(".") for r in result.answers]
    return {
        "ptr": hostnames[0] if hostnames else None,
        "aliases": hostnames[1:],
        "measured": True,
        "error": None,
    }


async def reverse_dns(ip: str) -> dict:
    """Reverse DNS lookup - PTR record."""
    if not ip:
        return {"ptr": None, "aliases": [], "measured": False, "error": msg("dns.reverse_no_ip")}
    return await asyncio.to_thread(_reverse_dns_sync, ip)
