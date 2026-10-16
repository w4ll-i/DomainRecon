# =============================================================================
# DomainRecon - Brute-force DNS de sous-domaines (module actif)
# =============================================================================
# Résout `mot.domaine` pour chaque mot de la liste (impl/subdomain_wordlist.py,
# 887 mots) plus quelques noms dérivés du domaine. Points d'attention :
#   - les dix noms dérivés du domaine (api-<nom>, <nom>-dev…) portent le suffixe
#     du domaine, sans quoi ils ne résoudraient jamais ;
#   - un joker DNS (*.domaine) ferait « trouver » toute la liste : il est sondé
#     avant (impl/dns_tools.probe_wildcard) et les réponses identiques à celles du
#     joker sont écartées au lieu d'abandonner l'énumération ;
#   - aucun résolveur public n'est imposé (8.8.8.8, 1.1.1.1) : on utilise le
#     résolveur du système, comme les autres modules DNS (DnsQuerier).
# Chaque entrée garde ses adresses, son CNAME et signale les adresses non
# publiques (home.zonetransfer.me -> 127.0.0.1 : fuite d'adressage interne).
# =============================================================================

import asyncio
from concurrent.futures import ThreadPoolExecutor

from ...i18n import msg
from .. import dns as scanner_dns
from ..errors import ModuleError
from . import dns_tools
from .subdomain_wordlist import WORDS

# Requêtes DNS simultanées, délai d'une requête et budget total de temps (s).
CONCURRENCY = 40
QUERY_TIMEOUT = 3.0
BUDGET = 150.0
MAX_FOUND = 500

# Noms dérivés du domaine : {nom} est le premier label (« example » pour example.com).
DERIVED_PATTERNS = (
    "api-{nom}",
    "{nom}-api",
    "{nom}-dev",
    "{nom}-staging",
    "{nom}-prod",
    "{nom}-test",
    "{nom}-app",
    "{nom}-web",
    "{nom}-service",
    "{nom}-internal",
    "v2-{nom}",
    "dev-{nom}",
    "staging-{nom}",
)

# Premiers labels qui désignent un outil interne, une base de données ou une chaîne de build :
# leur exposition sur Internet mérite un constat.
# fmt: off
SENSITIVE_LABELS = frozenset(
    {
        "jenkins", "gitlab", "git", "grafana", "kibana", "elasticsearch", "phpmyadmin", "adminer",
        "mysql", "postgres", "mongo", "redis", "db", "sql", "nagios", "zabbix", "prometheus",
        "alertmanager", "sonar", "sonarqube", "nexus", "artifactory", "registry", "docker", "k8s",
        "kubernetes", "argocd", "harbor", "vault", "consul", "rabbitmq", "kafka", "intranet",
        "internal", "jira", "confluence", "netdata", "cpanel", "whm", "plesk", "directadmin",
        "backup", "bak", "logstash", "runner", "cluster",
    }
)
# fmt: on


def candidates(domain: str, words: tuple[str, ...] = WORDS) -> list[str]:
    """Noms complets à résoudre : mots de la liste, puis noms dérivés du domaine, sans doublon."""
    base = domain.split(".")[0]
    labels = list(words) + [pattern.format(nom=base) for pattern in DERIVED_PATTERNS]
    seen: set[str] = set()
    names = []
    for label in labels:
        if label and label not in seen and len(label) <= 63:
            seen.add(label)
            names.append(f"{label}.{domain}")
    return names


def resolve_one(querier: scanner_dns.DnsQuerier, fqdn: str) -> dict | None:
    """Entrée {subdomain, ips, cname} si `fqdn` résout, sinon None ; `{"error": True}` si la requête échoue."""
    result = querier.lookup(fqdn, "A")
    if result.status == "error":
        return {"error": True}
    if result.status == "nxdomain":
        return None
    addresses = [str(r) for r in result.answers] if result.status == "ok" else []
    if result.status == "noanswer":
        # Le nom existe sans adresse IPv4 : peut-être IPv6 seulement.
        v6 = querier.lookup(fqdn, "AAAA")
        if v6.status == "ok":
            addresses = [str(r) for r in v6.answers]
    if not addresses:
        return None
    return {
        "subdomain": fqdn,
        "ips": sorted(set(addresses)),
        "cname": dns_tools.cname_of(querier, fqdn),
    }


def _is_wildcard_answer(entry: dict, wildcard: dns_tools.WildcardProbe) -> bool:
    """La réponse est celle du joker : mêmes adresses (ou sous-ensemble) ou même CNAME."""
    if wildcard.cname and entry["cname"] == wildcard.cname:
        return True
    return bool(wildcard.addresses) and set(entry["ips"]) <= wildcard.addresses


async def bruteforce(domain: str, words: tuple[str, ...] = WORDS) -> dict:
    """Brute-force DNS de `domain`. Lève ModuleError si le résolveur ne répond à rien."""
    domain = domain.strip().lower().rstrip(".")
    querier = scanner_dns.DnsQuerier(QUERY_TIMEOUT, BUDGET)
    executor = ThreadPoolExecutor(max_workers=CONCURRENCY, thread_name_prefix="dr-brute")
    loop = asyncio.get_running_loop()
    try:
        wildcard = await loop.run_in_executor(executor, dns_tools.probe_wildcard, querier, domain)
        if wildcard.probes == 0 and wildcard.failed:
            raise ModuleError(msg("subdomain_bruteforce.resolver_failed"))

        names = candidates(domain, words)
        semaphore = asyncio.Semaphore(CONCURRENCY)
        outcomes: list[dict | None] = []

        async def probe(fqdn: str) -> None:
            async with semaphore:
                outcomes.append(await loop.run_in_executor(executor, resolve_one, querier, fqdn))

        # Le budget de DnsQuerier épuisé fait échouer les requêtes restantes : la boucle se termine seule.
        await asyncio.gather(*(probe(name) for name in names))
    finally:
        executor.shutdown(wait=False, cancel_futures=True)

    errors = sum(1 for outcome in outcomes if outcome and outcome.get("error"))
    hits = [o for o in outcomes if o and not o.get("error")]
    if errors == len(outcomes):
        raise ModuleError(msg("subdomain_bruteforce.resolver_failed"))

    filtered = 0
    found: list[dict] = []
    for entry in sorted(hits, key=lambda e: e["subdomain"]):
        if wildcard.wildcard and _is_wildcard_answer(entry, wildcard):
            filtered += 1
            continue
        private = sorted({kind for ip in entry["ips"] if (kind := dns_tools.classify_address(ip))})
        if private:
            entry["private"] = private
        found.append(entry)
    return {
        "measured": True,
        "error": None,
        "domain": domain,
        "wordlist_size": len(names),
        "tested": len(outcomes) - errors,
        "query_errors": errors,
        "incomplete": errors > 0,
        "wildcard_detected": wildcard.wildcard,
        "wildcard_addresses": sorted(wildcard.addresses),
        "wildcard_filtered": filtered,
        "subdomains_found": found[:MAX_FOUND],
        "count": len(found),
    }
