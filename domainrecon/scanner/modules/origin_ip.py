# =============================================================================
# DomainRecon - Module « origin_ip » : adresse IP d'origine derrière un CDN
# =============================================================================
# Cherche l'adresse du serveur qui héberge réellement un site protégé par un CDN
# (Cloudflare, Akamai, Fastly, CloudFront, Imperva, Sucuri…) : noms voisins du
# domaine qui ne passent pas par le CDN, serveurs de messagerie, plages du SPF et
# historique DNS (Robtex), puis comparaison de la page servie en direct par chaque
# candidat avec celle vue à travers le CDN. Détail et verdicts : impl/origin_ip.py.
# Sans CDN détecté, le module est « sans objet » : rien n'est sondé.
# Catégorie SENSIBLE : des serveurs autres que la cible publique sont contactés ;
# personnalisé et autorisation de tester la cible exigés.
# Limites : un serveur qui n'accepte que les adresses du CDN ne répondra pas
# (verdict « unreachable ») ; une absence de résultat ne prouve pas que l'origine
# est protégée ; l'historique DNS peut citer d'anciens hébergeurs sans lien.
# =============================================================================

import asyncio

from ...i18n import msg
from ..errors import ModuleError, ModuleSkipped
from ..impl import origin_ip as origin
from ..impl import robtex as robtex_api
from ..registry import ModuleSpec, ScanContext, skip_for_ip_target
from ..rules import FindingInput, FindingRule, Outcome, ScoreRule, hit
from ..score import as_dict, as_list

# Ordre d'affichage des verdicts.
_ORDER = {"confirmed": 0, "probable": 1, "unverified": 2, "unreachable": 3, "rejected": 4}


async def run(context: ScanContext) -> dict:
    home = await context.homepage()
    semaphore = asyncio.Semaphore(8)
    target_origins = await asyncio.gather(*(origin.origin_of(ip, semaphore) for ip in context.addresses))
    cdn = origin.detect_cdn([o["asn"] if o else None for o in target_origins], home.headers)
    if cdn is None:
        raise ModuleSkipped(msg("origin_ip.no_cdn"))
    cdn_name, evidence = cdn

    # Candidats : DNS (en thread, avec son propre budget) et historique DNS déjà en cache de Robtex.
    dns_found = await asyncio.to_thread(origin.gather_dns_candidates_sync, context.apex)
    history: list[str] = []
    history_error = None
    try:
        passive = await robtex_api.forward(context.http, context.apex)
        history = [r["data"] for r in passive["records"] if r["type"] in ("A", "AAAA")]
    except ModuleError as error:
        history_error = error.message
    candidates = origin.merge_candidates(dns_found, history, exclude=set(context.addresses))

    # Écarte les adresses qui sont elles-mêmes celles d'un CDN (autre nom proxifié du même site).
    origins = await asyncio.gather(*(origin.origin_of(ip, semaphore) for ip in candidates))
    filtered = 0
    for ip, info in zip(list(candidates), origins, strict=True):
        asn = info["asn"] if info else None
        number = origin.asn_number(asn)
        if number in origin.CDN_ASNS:
            del candidates[ip]
            filtered += 1
            continue
        candidates[ip]["asn"] = asn
        candidates[ip]["as_name"] = info["name"] if info else None

    # Vérification directe (Host = cible) des meilleurs candidats, si la page d'accueil permet la comparaison.
    verdicts: dict[str, dict] = {}
    if home.reachable:
        probe_slots = asyncio.Semaphore(origin.PROBE_CONCURRENCY)

        async def check(ip: str) -> None:
            async with probe_slots:
                verdicts[ip] = await origin.verify(ip, context.domain, home)

        await asyncio.gather(*(check(ip) for ip in list(candidates)[: origin.MAX_VERIFIED]))

    rows = []
    for ip, info in candidates.items():
        row = {"ip": ip, **info, **verdicts.get(ip, {"verdict": "unverified"})}
        rows.append(row)
    rows.sort(key=lambda r: (_ORDER.get(r["verdict"], 9), r["ip"]))
    return {
        "measured": True,
        "error": None,
        "behind_cdn": True,
        "cdn": cdn_name,
        "cdn_evidence": evidence,
        "target_addresses": list(context.addresses),
        "candidates_total": len(rows),
        "cdn_filtered": filtered,
        "history_error": history_error,
        "candidates": rows,
        "confirmed": [r["ip"] for r in rows if r["verdict"] == "confirmed"],
        "probable": [r["ip"] for r in rows if r["verdict"] == "probable"],
    }


# -----------------------------------------------------------------------------
# Constats et score
# -----------------------------------------------------------------------------


def _rows(f: FindingInput, verdict: str) -> list[dict]:
    rows = as_list(as_dict(f.data).get("candidates"))
    return [r for r in rows if isinstance(r, dict) and r.get("verdict") == verdict]


def _hits(f: FindingInput, verdict: str) -> list:
    return [
        hit(ip=str(r.get("ip")), cdn=str(as_dict(f.data).get("cdn") or "CDN"), source=_source(r))
        for r in _rows(f, verdict)
    ][:5]


def _source(row: dict) -> str:
    sources = [s for s in as_list(row.get("sources")) if isinstance(s, str)]
    return ", ".join(sources) or "?"


def _check_exposed(f: FindingInput) -> list:
    return _hits(f, "confirmed")


def _check_probable(f: FindingInput) -> list:
    return _hits(f, "probable")


def _score(data: dict) -> Outcome:
    result = as_dict(data.get("origin_ip"))
    if as_list(result.get("confirmed")):
        return Outcome(0, msg("origin_ip.score_exposed"), True)
    if as_list(result.get("probable")):
        return Outcome(2, msg("origin_ip.score_probable"), True)
    return Outcome(5, msg("origin_ip.score_hidden"), True)


SPEC = ModuleSpec(
    name="origin_ip",
    family="network",
    category="sensible",
    run=run,
    skip_reason=skip_for_ip_target,
    wave=3,
    timeout=150,
    optional=True,
    order=270,
    findings=(
        FindingRule(code="finding.origin_ip.exposed", severity="high", check=_check_exposed),
        FindingRule(code="finding.origin_ip.probable", severity="medium", check=_check_probable),
    ),
    score_rules=(ScoreRule(criterion="origin_ip", weight=5, evaluate=_score),),
)
