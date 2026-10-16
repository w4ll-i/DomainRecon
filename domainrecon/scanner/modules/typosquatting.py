# =============================================================================
# DomainRecon - Module « typosquatting » : domaines d'usurpation enregistrés
# =============================================================================
# Génère des variantes du domaine (impl/typosquatting.py), résout celles qui sont
# enregistrées (DNS direct, A), puis les classe. Pièges évités
# (vérifiés le 15/10/2026) :
#   - compter toute variante sur une IP différente : homonymes
#     légitimes, domaines en vente (parking) et adresses de CDN feraient autant
#     de « menaces ». Chaque variante reçoit ici un statut :
#       defensive   même IP ou mêmes serveurs de noms que la cible (probablement
#                   enregistré par son propriétaire) ;
#       parked      serveurs de noms d'un service de parking / de vente de domaines ;
#       threat      dangereux : enregistré depuis moins de 90 jours (WHOIS) ou
#                   homoglyphe Unicode (IDN) actif, sans être en parking ni défensif ;
#       watch       à surveiller : capable de recevoir du courrier (MX), signal
#                   faible (beaucoup d'entreprises légitimes ont un MX : sur
#                   example.com, 23 variantes sur 77 en ont un) ;
#       registered  enregistré par un tiers, sans autre signal (information) ;
#     et l'indicateur « cdn » signale une IP de CDN / hébergeur mutualisé, qui ne
#     dit rien du propriétaire (donc jamais une menace à elle seule) ;
#   - le découpage du suffixe public (example.co.uk) et la troncature à 200
#     variantes au hasard : voir impl/typosquatting.py ;
#   - un résolveur qui réécrit les NXDOMAIN (tout nom « existe ») est détecté par
#     un nom aléatoire : le module échoue plutôt que d'annoncer 300 menaces.
# Limites : le WHOIS (TCP/43) n'est interrogé que pour 10 variantes au plus.
# =============================================================================

import asyncio
import ipaddress
import re
import secrets
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone

from ...i18n import msg
from .. import dns, whois_lookup
from ..errors import ModuleError
from ..impl import typosquatting as gen
from ..registry import ModuleSpec, ScanContext, skip_for_ip_target
from ..rules import FindingInput, FindingRule, Outcome, ScoreRule, hit
from ..score import as_dict, as_int, as_list
from ..targets import is_public_address

QUERY_TIMEOUT = 3.0
BUDGET = 60.0
WORKERS = 32
MAX_VARIANTS = 300
# Variantes enrichies (NS, MX) et variantes interrogées en WHOIS au plus.
MAX_ENRICHED = 60
MAX_WHOIS = 10
WHOIS_TIMEOUT = 25
WHOIS_CONCURRENCY = 5
RECENT_DAYS = 90
MAX_LISTED = 100
MAX_EXAMPLES = 5

# Plages de CDN et d'hébergeurs de pages mutualisés : l'IP n'y identifie pas le propriétaire.
CDN_RANGES = tuple(
    ipaddress.ip_network(n)
    for n in (
        # Cloudflare (https://www.cloudflare.com/ips-v4)
        "173.245.48.0/20", "103.21.244.0/22", "103.22.200.0/22", "103.31.4.0/22", "141.101.64.0/18",
        "108.162.192.0/18", "190.93.240.0/20", "188.114.96.0/20", "197.234.240.0/22", "198.41.128.0/17",
        "162.158.0.0/15", "104.16.0.0/13", "104.24.0.0/14", "172.64.0.0/13", "131.0.72.0/22",
        # Fastly, GitHub Pages, Vercel, Netlify, Shopify, Squarespace, Wix, Edgecast
        "151.101.0.0/16", "199.232.0.0/16", "185.199.108.0/22", "76.76.21.0/24", "76.76.19.0/24",
        "75.2.60.0/24", "99.83.190.0/24", "23.227.38.0/24", "198.185.159.0/24", "198.49.23.0/24",
        "185.230.60.0/22", "93.184.215.0/24", "93.184.216.0/24",
    )
)  # fmt: skip

# Serveurs de noms (fin de nom) de services de parking et de vente de domaines.
PARKING_NAMESERVERS = (
    "sedoparking.com", "parkingcrew.net", "bodis.com", "above.com", "afternic.com", "hugedomains.com",
    "parklogic.com", "cashparking.com", "domainsponsor.com", "fabulous.com", "voodoo.com", "ztomy.com",
    "smartname.com", "trafficz.com", "dan.com", "undeveloped.com", "parked.com", "parkingpage.namecheap.com",
    "registrar-servers.com-parking", "dsredirection.com", "domainnamesales.com",
)  # fmt: skip

_DATE_RE = re.compile(r"(\d{4})-(\d{2})-(\d{2})")


def is_cdn_address(address: str) -> bool:
    try:
        ip = ipaddress.ip_address(address)
    except ValueError:
        return False
    return any(ip in network for network in CDN_RANGES if network.version == ip.version)


def is_parking_nameserver(name: str) -> bool:
    name = name.lower().rstrip(".")
    return any(name == p or name.endswith(f".{p}") for p in PARKING_NAMESERVERS)


def age_in_days(creation_date: object, now: datetime | None = None) -> int | None:
    """Âge en jours d'après la date de création du WHOIS (texte ISO), ou None si illisible."""
    if not isinstance(creation_date, str):
        return None
    match = _DATE_RE.search(creation_date)
    if not match:
        return None
    try:
        created = datetime(int(match[1]), int(match[2]), int(match[3]), tzinfo=timezone.utc)
    except ValueError:
        return None
    days = ((now or datetime.now(timezone.utc)) - created).days
    return days if days >= 0 else None


def classify(variant: dict, *, target_ips: set[str], target_ns: set[str]) -> tuple[str, list[str]]:
    """(statut, raisons) d'une variante enregistrée ; voir l'en-tête du fichier."""
    ips = set(variant["ips"])
    nameservers = {n.lower().rstrip(".") for n in variant["nameservers"]}
    if ips & target_ips:
        return "defensive", ["same_ip"]
    if target_ns and nameservers & target_ns:
        return "defensive", ["same_nameservers"]
    if any(is_parking_nameserver(n) for n in nameservers):
        return "parked", ["parking_nameserver"]
    reasons: list[str] = []
    if variant.get("recently_registered"):
        reasons.append("recently_registered")
    if variant["type"] == "idn_homoglyph":
        reasons.append("idn_homoglyph")
    if reasons:
        return "threat", reasons
    if variant["has_mx"]:
        return "watch", ["mail_capable"]
    return "registered", []


# -----------------------------------------------------------------------------
# Collecte
# -----------------------------------------------------------------------------


def _resolve(querier: dns.DnsQuerier, name: str) -> tuple[str, list[str]]:
    """(état, adresses publiques) d'un nom : ok, absent ou erreur."""
    lookup = querier.lookup(name, "A")
    if lookup.status == "error":
        return "error", []
    addresses = sorted({str(a) for a in lookup.answers if is_public_address(str(a))})
    return ("ok" if addresses else "absent"), addresses


def _enrich(querier: dns.DnsQuerier, name: str) -> tuple[list[str], bool]:
    """(serveurs de noms, capable de recevoir du courrier) d'une variante enregistrée."""
    ns = querier.lookup(name, "NS")
    nameservers = sorted({str(r.target).rstrip(".").lower() for r in ns.answers}) if ns.status == "ok" else []
    mx = querier.lookup(name, "MX")
    has_mx = mx.status == "ok" and bool(mx.answers) and not dns.has_null_mx(mx.answers)
    return nameservers, has_mx


async def _age(domain: str, semaphore: asyncio.Semaphore) -> int | None:
    async with semaphore:
        try:
            whois = await whois_lookup.get_whois_data(domain)
        except Exception:  # noqa: BLE001 - la bibliothèque WHOIS lève des erreurs de tout type
            return None
    return age_in_days(as_dict(whois).get("creation_date"))


async def run(context: ScanContext) -> dict:
    parts = gen.split_domain(context.apex)
    if parts is None:
        raise ModuleError(msg("typosquatting.no_registrable_domain"))
    label, suffix = parts
    domain = f"{label}.{suffix}"
    all_variants = gen.generate(domain, limit=10**6)
    variants = all_variants[:MAX_VARIANTS]
    types = dict(variants)

    querier = dns.DnsQuerier(QUERY_TIMEOUT, BUDGET)
    loop = asyncio.get_running_loop()
    pool = ThreadPoolExecutor(max_workers=WORKERS, thread_name_prefix="domainrecon-typo")

    async def in_pool(function, *args):
        return await loop.run_in_executor(pool, function, *args)

    try:
        # Résolveur qui réécrit les NXDOMAIN : un nom aléatoire ne doit pas exister.
        probe_state, _ = await in_pool(
            _resolve, querier, f"dr-{secrets.token_hex(8)}.{suffix.rsplit('.', 1)[-1]}"
        )
        if probe_state == "ok":
            raise ModuleError(msg("typosquatting.resolver_rewrites"))

        target_state, target_ips = await in_pool(_resolve, querier, domain)
        target_ns, _ = await in_pool(_enrich, querier, domain)
        resolved = await asyncio.gather(*(in_pool(_resolve, querier, name) for name, _ in variants))
        if resolved and all(state == "error" for state, _ in resolved):
            raise ModuleError(msg("typosquatting.dns_unavailable"))

        registered = [
            {"domain": name, "type": types[name], "ips": ips}
            for (name, _), (state, ips) in zip(variants, resolved, strict=True)
            if state == "ok"
        ]
        enriched = registered[:MAX_ENRICHED]
        details = await asyncio.gather(*(in_pool(_enrich, querier, v["domain"]) for v in enriched))
    finally:
        pool.shutdown(wait=False, cancel_futures=True)

    target_set = set(target_ips)
    target_ns_set = {n.lower() for n in target_ns}
    for variant, (nameservers, has_mx) in zip(enriched, details, strict=True):
        variant["nameservers"] = nameservers[:3]
        variant["has_mx"] = has_mx
    for variant in registered[MAX_ENRICHED:]:
        variant["nameservers"], variant["has_mx"] = [], False

    # WHOIS : seulement les variantes ni défensives ni en parking, celles qui reçoivent du courrier
    # et les homoglyphes d'abord (les plus utiles à dater).
    candidates = [
        v
        for v in enriched
        if classify(v, target_ips=target_set, target_ns=target_ns_set)[0] in ("registered", "watch", "threat")
    ]
    candidates.sort(key=lambda v: (v["type"] != "idn_homoglyph", not v["has_mx"]))
    candidates = candidates[:MAX_WHOIS]
    semaphore = asyncio.Semaphore(WHOIS_CONCURRENCY)
    ages: list[int | None] = []
    if candidates:
        try:
            ages = await asyncio.wait_for(
                asyncio.gather(*(_age(v["domain"], semaphore) for v in candidates)), timeout=WHOIS_TIMEOUT
            )
        except asyncio.TimeoutError:
            ages = []
    for variant, age in zip(candidates, ages, strict=False):
        if age is not None:
            variant["age_days"] = age
            variant["recently_registered"] = age < RECENT_DAYS

    counts = {"defensive": 0, "parked": 0, "threat": 0, "watch": 0, "registered": 0}
    listed = []
    for variant in registered:
        status, reasons = classify(variant, target_ips=target_set, target_ns=target_ns_set)
        counts[status] += 1
        listed.append(
            {
                "domain": variant["domain"],
                "type": variant["type"],
                "status": status,
                "reasons": reasons,
                "ip": variant["ips"][0],
                "ips": variant["ips"][:3],
                "same_ip": bool(set(variant["ips"]) & target_set),
                "cdn": all(is_cdn_address(ip) for ip in variant["ips"]),
                "has_mx": variant["has_mx"],
                "nameservers": variant["nameservers"],
                "age_days": variant.get("age_days"),
                "recently_registered": variant.get("recently_registered"),
            }
        )
    rank = {"threat": 0, "watch": 1, "registered": 2, "parked": 3, "defensive": 4}
    listed.sort(key=lambda v: (rank[v["status"]], v["domain"]))
    return {
        "measured": True,
        "error": None,
        "domain": domain,
        "name": label,
        "suffix": suffix,
        "target_resolves": target_state == "ok",
        "variants_generated": len(all_variants),
        "variants_checked": len(variants),
        "truncated": len(all_variants) > len(variants),
        "active_count": len(registered),
        "threat_count": counts["threat"],
        "watch_count": counts["watch"],
        "registered_count": counts["registered"],
        "parked_count": counts["parked"],
        "defensive_count": counts["defensive"],
        "recent_count": sum(1 for v in registered if v.get("recently_registered")),
        "whois_checked": len(candidates),
        "variants": listed[:MAX_LISTED],
    }


# -----------------------------------------------------------------------------
# Constats et score
# -----------------------------------------------------------------------------


def _threats(data: dict) -> list[dict]:
    return [v for v in map(as_dict, as_list(data.get("variants"))) if v.get("status") == "threat"]


def _check_threats(f: FindingInput):
    data = as_dict(f.data)
    threats = _threats(data)
    count = as_int(data.get("threat_count")) or len(threats)
    if not threats:
        return None
    dangerous = any("recently_registered" in as_list(v.get("reasons")) and v.get("has_mx") for v in threats)
    examples = ", ".join(str(v.get("domain", "")) for v in threats[:MAX_EXAMPLES])
    return hit(severity="high" if dangerous else "medium", count=count, examples=examples)


def _check_watch(f: FindingInput):
    data = as_dict(f.data)
    watched = [v for v in map(as_dict, as_list(data.get("variants"))) if v.get("status") == "watch"]
    count = as_int(data.get("watch_count")) or len(watched)
    if not watched:
        return None
    return {"count": count, "examples": ", ".join(str(v.get("domain", "")) for v in watched[:MAX_EXAMPLES])}


def _score(data: dict) -> Outcome:
    result = as_dict(data.get("typosquatting"))
    threats = as_int(result.get("threat_count")) or 0
    if threats >= 5:
        return Outcome(0, msg("typosquatting.score_threats", count=threats), True)
    if threats >= 2:
        return Outcome(1, msg("typosquatting.score_threats", count=threats), True)
    if threats == 1:
        return Outcome(2, msg("typosquatting.score_threats", count=threats), True)
    return Outcome(3, msg("typosquatting.score_clean", count=as_int(result.get("active_count")) or 0), True)


SPEC = ModuleSpec(
    name="typosquatting",
    family="reputation",
    category="passif",
    run=run,
    wave=1,
    timeout=120,
    optional=True,
    skip_reason=lambda context: (
        msg("orchestrator.skip_shared_platform") if context.shared_platform else skip_for_ip_target(context)
    ),
    order=670,
    findings=(
        FindingRule(code="finding.typosquatting.threats", severity="medium", check=_check_threats),
        FindingRule(code="finding.typosquatting.watch", severity="low", check=_check_watch),
    ),
    score_rules=(ScoreRule(criterion="typosquatting", weight=3, evaluate=_score),),
)
