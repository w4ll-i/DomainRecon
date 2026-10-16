# =============================================================================
# DomainRecon - Module « dnsbl » : listes noires DNS (adresses IP et domaine)
# =============================================================================
# Listes noires d'adresses IP et de domaines, interrogées zone par zone.
#
# Principe (RFC 5782) : pour l'adresse a.b.c.d, on résout d.c.b.a.<zone> ; une
# réponse 127.0.0.x signifie « listée », NXDOMAIN « absente ». Ce module corrige
# les défauts relevés le 14-15/10/2026 :
#
#   - Réponses de REFUS : Spamhaus, SURBL et d'autres refusent les résolveurs
#     publics ouverts. Selon le résolveur, la réponse est 127.255.255.254
#     (Cloudflare : « requête via un résolveur public ») ou un simple NXDOMAIN
#     (résolveur de l'entreprise ou 8.8.8.8). Prendre toute réponse A
#     pour un « listage » serait un faux positif, et un NXDOMAIN pour « propre »
#     un faux négatif. Ici : tout 127.255.255.x est un refus, jamais un listage, et
#     chaque zone est validée par un POINT DE TEST (127.0.0.2 pour les zones IP,
#     un domaine de test pour les zones de domaines) : une zone qui ne répond pas
#     à son point de test est « inexploitable depuis ce résolveur » et sort du
#     décompte au lieu de compter pour « propre ». La validation positive est
#     gardée 1 h.
#   - Zones mortes ou hors sujet retirées : SORBS (arrêté en 2024), CBL (fusionné
#     dans XBL), dbl.spamhaus.org interrogé avec une IP (zone de DOMAINES, il
#     répondait « listé » à toute adresse), MSRBL, Tornevall, Unsubscore, wpbl,
#     inps, manitu (ne répondent plus), korea.services.net (liste géographique),
#     all.s5h.net (réputé pour ses faux positifs), dnsbl.spfbl.net (signale des
#     adresses de CDN).
#   - Listages « collatéraux » (UCEPROTECT niveaux 2 et 3 : sous-réseau ou système
#     autonome entier ; Spamhaus PBL : plage d'adresses dynamiques ; backscatterer)
#     rapportés mais NON comptés dans la note.
#   - Les serveurs de messagerie (MX) sont aussi testés : c'est eux qui comptent
#     pour la délivrabilité, pas seulement l'IP du site web.
#   - Zones de DOMAINES (Spamhaus DBL, SURBL) pour le domaine enregistrable.
# Requêtes DNS directes (sans proxy), parallèles, bornées par un budget de temps.
# =============================================================================

import asyncio
import ipaddress
import time
from concurrent.futures import ThreadPoolExecutor
from typing import NamedTuple

from ...i18n import msg
from .. import dns
from ..errors import ModuleError, ModuleSkipped
from ..registry import ModuleSpec, ScanContext
from ..rules import FindingInput, FindingRule, Outcome, ScoreRule, hit
from ..score import as_dict, as_int, as_list
from ..targets import is_public_address

QUERY_TIMEOUT = 3.0
BUDGET = 40.0
WORKERS = 16
# Durée pendant laquelle un point de test réussi est gardé en mémoire (secondes).
CANARY_TTL = 3600
MAX_WEB_ADDRESSES = 3
MAX_MAIL_ADDRESSES = 2
# Point de test standard des listes d'adresses (RFC 5782) : toujours listé.
IP_TEST_POINT = "2.0.0.127"

KIND_IP = "ip"
KIND_DOMAIN = "domain"
KIND_WHITELIST = "whitelist"


class Zone(NamedTuple):
    """Une zone DNSBL."""

    name: str
    category: str
    kind: str = KIND_IP
    # Zone majeure : un listage pèse plus lourd (grandes listes de référence).
    major: bool = False
    # Listage compté dans la note ; faux : rapporté à titre d'information (collatéral).
    counted: bool = True
    # Nom de test (zones de domaines) ; zones d'adresses : le point de test standard.
    canary: str | None = None


ZONES: tuple[Zone, ...] = (
    Zone("zen.spamhaus.org", "spam+botnet", major=True),
    Zone("bl.spamcop.net", "spam", major=True),
    Zone("b.barracudacentral.org", "spam", major=True),
    Zone("psbl.surriel.com", "spam", major=True),
    Zone("dnsbl-1.uceprotect.net", "spam", major=True),
    Zone("dnsbl-2.uceprotect.net", "spam_subnet", counted=False),
    Zone("dnsbl-3.uceprotect.net", "spam_network", counted=False),
    Zone("dnsbl.dronebl.org", "botnet", major=True),
    Zone("ips.backscatterer.org", "backscatter", counted=False),
    Zone("spam.dnsbl.anonmails.de", "spam"),
    Zone("singular.ttk.pte.hu", "spam"),
    Zone("bl.0spam.org", "spam"),
    Zone("bl.mailspike.net", "spam"),
    Zone("rbl.interserver.net", "spam"),
    Zone("dnsbl.kempt.net", "spam"),
    Zone("truncate.gbudb.net", "spam"),
    Zone("bl.blocklist.de", "abuse"),
    Zone("dnsrbl.swinog.ch", "spam"),
    Zone("wl.mailspike.net", "whitelist", KIND_WHITELIST),
)

DOMAIN_ZONES: tuple[Zone, ...] = (
    Zone("dbl.spamhaus.org", "domain", KIND_DOMAIN, major=True, canary="dbltest.com"),
    Zone("multi.surbl.org", "domain", KIND_DOMAIN, major=True, canary="test.surbl.org"),
)

# Zones validées par leur point de test : {zone: horodatage}.
_ALIVE: dict[str, float] = {}


def clear_state() -> None:
    """Oublie les points de test validés (tests)."""
    _ALIVE.clear()


# -----------------------------------------------------------------------------
# Interprétation des réponses
# -----------------------------------------------------------------------------

STATE_LISTED = "listed"
STATE_INFO = "info"
STATE_WHITELIST = "whitelist"
STATE_NONE = "none"
STATE_REFUSED = "refused"
STATE_INVALID = "invalid"


def _parse(codes: list[str]) -> list[tuple[int, int, int, int]] | None:
    """Réponses sous forme de quadruplets, ou None si l'une n'est pas une adresse IPv4."""
    parsed = []
    for code in codes:
        try:
            parsed.append(tuple(int(p) for p in str(code).split(".")))
        except ValueError:
            return None
        if len(parsed[-1]) != 4:
            return None
    return parsed


def classify(zone: Zone, codes: list[str]) -> tuple[str, str]:
    """(état, catégorie) d'une réponse positive d'une zone.

    états : listed (listage), info (listage non compté), whitelist, none
    (réponse sans signification), refused (requête refusée au résolveur),
    invalid (réponse hors 127.0.0.0/8 : résolveur qui réécrit les NXDOMAIN).
    """
    parsed = _parse(codes)
    if not parsed or any(a != 127 for a, _, _, _ in parsed):
        return STATE_INVALID, zone.category
    if any((b, c) == (255, 255) for _, b, c, _ in parsed):
        return STATE_REFUSED, zone.category
    last = {d for _, _, _, d in parsed}
    if zone.kind == KIND_WHITELIST:
        return (STATE_WHITELIST, zone.category) if last & {17, 18, 19, 20} else (STATE_NONE, zone.category)
    if zone.name == "zen.spamhaus.org":
        # 10 et 11 : PBL (plages d'adresses dynamiques, non destinées à envoyer du courrier).
        if last <= {10, 11}:
            return STATE_INFO, "policy"
        return STATE_LISTED, "exploits" if last & {4, 5, 6, 7} else "spam"
    if zone.name == "bl.mailspike.net":
        # 2, 10, 11 : pire, très mauvaise et mauvaise réputation ; les autres sont neutres.
        return (STATE_LISTED, zone.category) if last & {2, 10, 11} else (STATE_NONE, zone.category)
    if zone.name == "dbl.spamhaus.org":
        if 255 in last:
            return STATE_REFUSED, zone.category
        names = {2: "spam", 4: "phishing", 5: "malware", 6: "botnet_cc"}
        for code in sorted(last):
            if code in names:
                return STATE_LISTED, names[code]
        return STATE_LISTED, "abused" if last & {102, 103, 104, 105, 106} else "domain"
    if zone.name == "multi.surbl.org":
        if 254 in last:
            return STATE_NONE, zone.category
        if 1 in last:
            return STATE_REFUSED, zone.category
        bits = max(last)
        if bits & 8:
            return STATE_LISTED, "phishing"
        if bits & 16:
            return STATE_LISTED, "malware"
        return STATE_LISTED, "abuse" if bits & 64 else "domain"
    return (STATE_LISTED if zone.counted else STATE_INFO), zone.category


class Probe(NamedTuple):
    """Requête DNS d'une zone pour un objet (adresse ou domaine)."""

    role: str  # web | mail | domain
    host: str  # nom du serveur ou du domaine
    obj: str  # adresse IP ou domaine interrogé
    zone: Zone


def _query_name(zone: Zone, obj: str) -> str:
    if zone.kind == KIND_DOMAIN:
        return f"{obj}.{zone.name}"
    return f"{'.'.join(reversed(obj.split('.')))}.{zone.name}"


def _codes(lookup: dns.DnsLookup) -> list[str]:
    return sorted(str(answer) for answer in lookup.answers)


def _alive(zone: Zone) -> bool:
    stamp = _ALIVE.get(zone.name)
    return stamp is not None and time.monotonic() - stamp < CANARY_TTL


# -----------------------------------------------------------------------------
# Collecte
# -----------------------------------------------------------------------------


def _ipv4(addresses: list[str]) -> list[str]:
    found = []
    for address in addresses:
        try:
            if (
                ipaddress.ip_address(address).version == 4
                and is_public_address(address)
                and address not in found
            ):
                found.append(address)
        except ValueError:
            continue
    return found


def _mail_hosts(querier: dns.DnsQuerier, apex: str) -> list[tuple[str, str]]:
    """(hôte MX, première adresse IPv4 publique) des serveurs de messagerie, par priorité."""
    mx = querier.lookup(apex, "MX")
    if mx.status != "ok" or dns.has_null_mx(mx.answers):
        return []
    hosts = sorted(
        (a.preference, str(a.exchange).rstrip(".").lower())
        for a in mx.answers
        if getattr(a, "exchange", None)
    )
    found: list[tuple[str, str]] = []
    for _, host in hosts:
        if len(found) >= MAX_MAIL_ADDRESSES + 1:
            break
        lookup = querier.lookup(host, "A")
        addresses = _ipv4([str(a) for a in lookup.answers]) if lookup.status == "ok" else []
        if addresses:
            found.append((host, addresses[0]))
    return found


async def _run_lookups(querier: dns.DnsQuerier, names: list[str]) -> dict[str, dns.DnsLookup]:
    """Résout les noms en parallèle (threads bornés) ; un nom n'est résolu qu'une fois."""
    loop = asyncio.get_running_loop()
    pool = ThreadPoolExecutor(max_workers=WORKERS, thread_name_prefix="domainrecon-dnsbl")
    try:
        unique = sorted(set(names))
        results = await asyncio.gather(*(loop.run_in_executor(pool, querier.lookup, n, "A") for n in unique))
    finally:
        pool.shutdown(wait=False, cancel_futures=True)
    return dict(zip(unique, results, strict=True))


def _summarize_zone(zone: Zone, lookup: dns.DnsLookup | None, usable: bool) -> tuple[str, str, list[str]]:
    """(état, catégorie, codes) d'une zone pour un objet ; états spéciaux : clean, unusable, error."""
    if lookup is None or lookup.status == "error":
        return "error", zone.category, []
    if lookup.status in ("nxdomain", "noanswer"):
        return ("clean" if usable else "unusable"), zone.category, []
    codes = _codes(lookup)
    state, category = classify(zone, codes)
    return state, category, codes


async def run(context: ScanContext) -> dict:
    querier = dns.DnsQuerier(QUERY_TIMEOUT, BUDGET)
    loop = asyncio.get_running_loop()
    web_ips = _ipv4(context.addresses)[:MAX_WEB_ADDRESSES]
    if not web_ips:
        raise ModuleSkipped(msg("dnsbl.skip_no_ipv4"))
    check_domain = not context.is_ip_target
    mail: list[tuple[str, str]] = []
    if check_domain and not context.shared_platform:
        mail = await loop.run_in_executor(None, _mail_hosts, querier, context.apex)
        mail = [(host, ip) for host, ip in mail if ip not in web_ips][:MAX_MAIL_ADDRESSES]

    probes: list[Probe] = [Probe("web", ip, ip, z) for ip in web_ips for z in ZONES]
    probes += [Probe("mail", host, ip, z) for host, ip in mail for z in ZONES]
    domain = context.site if context.shared_platform else context.apex
    if check_domain:
        probes += [Probe("domain", domain, domain, z) for z in DOMAIN_ZONES]

    # Points de test des zones pas encore validées, interrogés avec les requêtes réelles.
    canary_names = {}
    for zone in (*ZONES, *DOMAIN_ZONES):
        if any(p.zone is zone for p in probes) and not _alive(zone):
            canary_names[zone.name] = f"{zone.canary or IP_TEST_POINT}.{zone.name}"
    names = [_query_name(p.zone, p.obj) for p in probes] + list(canary_names.values())
    lookups = await _run_lookups(querier, names)

    usable: dict[str, bool] = {}
    for zone in (*ZONES, *DOMAIN_ZONES):
        if zone.name in canary_names:
            lookup = lookups[canary_names[zone.name]]
            codes = _codes(lookup) if lookup.status == "ok" else []
            state, _ = classify(zone, codes) if codes else (STATE_INVALID, "")
            if state in (STATE_LISTED, STATE_INFO, STATE_WHITELIST, STATE_NONE):
                _ALIVE[zone.name] = time.monotonic()
                usable[zone.name] = True
            else:
                usable[zone.name] = False
        else:
            usable[zone.name] = _alive(zone)

    # Regroupe par objet interrogé.
    groups: dict[tuple[str, str, str], dict] = {}
    refused: set[str] = set()
    failed: set[str] = set()
    for probe in probes:
        key = (probe.role, probe.host, probe.obj)
        group = groups.setdefault(
            key,
            {
                "role": probe.role,
                "host": probe.host,
                "ip": probe.obj if probe.role != "domain" else None,
                "domain": probe.obj if probe.role == "domain" else None,
                "listings": [],
                "info": [],
                "whitelisted": False,
                "checked": 0,
            },
        )
        state, category, codes = _summarize_zone(
            probe.zone, lookups.get(_query_name(probe.zone, probe.obj)), usable[probe.zone.name]
        )
        zone = probe.zone
        if state in (STATE_REFUSED, STATE_INVALID, "unusable"):
            refused.add(zone.name)
        elif state == "error":
            failed.add(zone.name)
        elif state == "clean" or state == STATE_NONE:
            group["checked"] += 1
        elif state == STATE_WHITELIST:
            group["checked"] += 1
            group["whitelisted"] = True
        else:
            group["checked"] += 1
            entry = {
                "dnsbl": zone.name,
                "response": ", ".join(codes),
                "category": category,
                "major": zone.major,
            }
            group["listings"].append(entry) if state == STATE_LISTED else group["info"].append(entry)

    ordered = [
        groups[k]
        for k in sorted(groups, key=lambda k: ({"web": 0, "mail": 1, "domain": 2}[k[0]], k[1], k[2]))
    ]
    if not any(g["checked"] for g in ordered):
        if failed and not refused:
            raise ModuleError(msg("dnsbl.unreachable"))
        raise ModuleError(msg("dnsbl.no_usable_zone"))

    web = [g for g in ordered if g["role"] == "web"]
    mails = [g for g in ordered if g["role"] == "mail"]
    domains = [g for g in ordered if g["role"] == "domain"]
    primary = web[0]
    listed = sum(len(g["listings"]) for g in web)
    return {
        "measured": True,
        "error": None,
        "ip": primary["ip"],
        "listed_count": listed,
        "checked_count": primary["checked"],
        "collateral_count": sum(len(g["info"]) for g in web),
        "whitelisted": any(g["whitelisted"] for g in web),
        "severity": "clean"
        if listed == 0
        else "medium"
        if listed <= 2
        else "high"
        if listed <= 5
        else "critical",
        "listings": primary["listings"],
        "web": web,
        "mail": mails,
        "mail_listed_count": sum(len(g["listings"]) for g in mails),
        "domain": domains[0] if domains else None,
        "domain_listed_count": sum(len(g["listings"]) for g in domains),
        "refused_zones": sorted(refused),
        "failed_zones": sorted(failed),
        "zones_total": len(ZONES) - 1 + (len(DOMAIN_ZONES) if check_domain else 0),
    }


# -----------------------------------------------------------------------------
# Constats et score
# -----------------------------------------------------------------------------


def _names(entries: list) -> str:
    return ", ".join(sorted(str(as_dict(e).get("dnsbl", "")) for e in entries))


def _check_ip(f: FindingInput):
    data = as_dict(f.data)
    results = []
    for group in (as_dict(g) for g in as_list(data.get("web"))):
        entries = as_list(group.get("listings"))
        if not entries:
            continue
        major = any(as_dict(e).get("major") for e in entries)
        severity = "high" if major or len(entries) >= 3 else "medium"
        results.append(
            hit(severity=severity, ip=str(group.get("ip", "")), count=len(entries), zones=_names(entries))
        )
    return results


def _check_mail(f: FindingInput):
    data = as_dict(f.data)
    results = []
    for group in (as_dict(g) for g in as_list(data.get("mail"))):
        entries = as_list(group.get("listings"))
        if entries:
            results.append(
                {
                    "host": str(group.get("host", "")),
                    "ip": str(group.get("ip", "")),
                    "count": len(entries),
                    "zones": _names(entries),
                }
            )
    return results


def _check_domain(f: FindingInput):
    group = as_dict(as_dict(f.data).get("domain"))
    entries = as_list(group.get("listings"))
    if not entries:
        return None
    cats = sorted({str(as_dict(e).get("category", "")) for e in entries})
    severity = "critical" if {"phishing", "malware", "botnet_cc"} & set(cats) else "high"
    return hit(
        severity=severity,
        domain=str(group.get("domain", "")),
        zones=_names(entries),
        categories=", ".join(cats),
    )


def _score(data: dict) -> Outcome:
    result = as_dict(data.get("dnsbl"))
    groups = [
        as_dict(g) for g in [*as_list(result.get("web")), *as_list(result.get("mail")), result.get("domain")]
    ]
    entries = [as_dict(e) for g in groups for e in as_list(g.get("listings"))]
    if as_dict(result.get("domain")).get("listings"):
        return Outcome(0, msg("dnsbl.score_domain"), True)
    major = sum(1 for e in entries if e.get("major"))
    count = len(entries)
    if major >= 2 or count >= 4:
        return Outcome(0, msg("dnsbl.score_listed", count=count), True)
    if major == 1 or count >= 2:
        return Outcome(1, msg("dnsbl.score_listed", count=count), True)
    if count == 1:
        return Outcome(3, msg("dnsbl.score_listed", count=count), True)
    if as_int(result.get("collateral_count")):
        return Outcome(4, msg("dnsbl.score_collateral", count=result["collateral_count"]), True)
    return Outcome(5, msg("dnsbl.score_clean", count=as_int(result.get("checked_count")) or 0), True)


def skip_reason(context: ScanContext) -> object | None:
    """Sans objet sans adresse IPv4 publique (les listes noires d'adresses sont en IPv4)."""
    if not _ipv4(context.addresses):
        return msg("dnsbl.skip_no_ipv4")
    return None


SPEC = ModuleSpec(
    name="dnsbl",
    family="reputation",
    category="passif",
    run=run,
    wave=1,
    timeout=60,
    optional=True,
    skip_reason=skip_reason,
    verdict=True,
    order=600,
    findings=(
        FindingRule(code="finding.dnsbl.ip_listed", severity="medium", check=_check_ip),
        FindingRule(code="finding.dnsbl.mail_listed", severity="high", check=_check_mail),
        FindingRule(code="finding.dnsbl.domain_listed", severity="high", check=_check_domain),
    ),
    score_rules=(ScoreRule(criterion="dnsbl", weight=5, evaluate=_score),),
)
