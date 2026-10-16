# =============================================================================
# DomainRecon - Module « paste » : pastes et vidages de code public mentionnant le domaine
# =============================================================================
# Pastes et recherche de code public. Sources actuelles, interrogées en parallèle (détail dans impl/paste.py) :
#   - Sourcegraph, sans clé : fichiers de vidage ou de journaux du code public indexé ;
#   - GitHub, avec le jeton facultatif github_token : même idée, sur des extensions de vidage ;
#   - Intelligence X, avec la clé facultative intelx_key : bucket de pastes.
# Sources mortes remplacées : psbdmp.ws n'existe plus, Google CSE est fermé aux nouveaux
# clients. Une source indisponible est un état (champ « sources »), pas un échec ; le
# module échoue seulement si AUCUNE source n'a répondu.
# Valeurs sensibles : extraits masqués (adresses, mots de passe, jetons) ; aucun contenu brut.
# Catégorie « sensible » : exige l'autorisation de tester la cible (cadre légal).
# =============================================================================

import asyncio

from ...i18n import msg
from ..errors import ModuleError
from ..impl import github_dork
from ..impl import intelx as intelx_impl
from ..impl import paste as impl
from ..impl.leaks_commun import REQUEST_ERRORS, github_key, intelx_key, request
from ..registry import ModuleSpec, ScanContext, skip_for_ip_target
from ..rules import FindingInput, FindingRule, Outcome, ScoreRule
from ..score import as_dict, as_int

# Taille maximale du flux lu chez Sourcegraph (512 Kio).
_SOURCEGRAPH_MAX = 512 * 1024


async def _from_sourcegraph(context: ScanContext, domain: str) -> tuple[str, list[dict]]:
    try:
        reply = await request(
            context.http,
            "GET",
            impl.SOURCEGRAPH_URL,
            headers={"Accept": "text/event-stream"},
            params={"q": impl.sourcegraph_query(domain), "v": "V3", "display": 30},
            timeout=25,
            max_bytes=_SOURCEGRAPH_MAX,
        )
    except REQUEST_ERRORS:
        return "unavailable", []
    if reply.status != 200:
        return "unavailable", []
    try:
        return "ok", impl.parse_sourcegraph_stream(reply.text, domain)
    except ValueError:
        return "unavailable", []


async def _from_github(context: ScanContext, domain: str, token: str) -> tuple[str, list[dict]]:
    items: dict[str, dict] = {}
    answered = 0
    try:
        for extension in impl.GITHUB_EXTENSIONS:
            state, payload = await github_dork.search_code(
                context.http, token, f'"{domain}" extension:{extension}'
            )
            if state == "rate_limited":
                break
            if state != "ok" or payload is None:
                continue
            answered += 1
            for item in payload.get("items") or []:
                normalized = github_dork.normalize_item(item, domain) if isinstance(item, dict) else None
                if normalized and normalized["url"]:
                    items.setdefault(normalized["url"], normalized)
    except ModuleError:
        return "error", []
    if answered == 0:
        return "rate_limited", []
    return "ok", impl.github_pastes(list(items.values()), domain)


async def _from_intelx(context: ScanContext, key: str, domain: str) -> tuple[str, list[dict]]:
    try:
        found = await intelx_impl.search(context.http, key, domain, media=1)
    except ModuleError:
        return "error", []
    return "ok", impl.intelx_pastes(found["records"])


async def run(context: ScanContext) -> dict:
    domain = context.domain if context.shared_platform else context.apex
    token = context.secrets.get("github_token")
    intelx = context.secrets.get("intelx_key")
    tasks = {"sourcegraph": _from_sourcegraph(context, domain)}
    if token:
        tasks["github"] = _from_github(context, domain, token)
    if intelx:
        tasks["intelx"] = _from_intelx(context, intelx, domain)
    outcomes = await asyncio.gather(*tasks.values())
    sources = {"sourcegraph": "skipped", "github": "skipped", "intelx": "skipped"}
    pastes: list[dict] = []
    for name, (state, found) in zip(tasks, outcomes, strict=True):
        sources[name] = state
        pastes.extend(found)
    if "ok" not in sources.values():
        raise ModuleError(msg("paste.no_source"))
    merged = impl.merge(pastes)
    return {
        "measured": True,
        "error": None,
        "domain": domain,
        "sources": sources,
        "total_found": len(merged),
        "high_count": sum(1 for p in merged if p["severity"] == "high"),
        "pastes": merged,
    }


# -----------------------------------------------------------------------------
# Constats et score
# -----------------------------------------------------------------------------


def _check_credentials(f: FindingInput) -> object:
    count = as_int(as_dict(f.data).get("high_count")) or 0
    return {"count": count} if count > 0 else None


def _check_mentions(f: FindingInput) -> object:
    data = as_dict(f.data)
    total = as_int(data.get("total_found")) or 0
    high = as_int(data.get("high_count")) or 0
    return {"count": total} if total > high else None


def _score(data: dict) -> Outcome:
    paste = as_dict(data.get("paste"))
    total = as_int(paste.get("total_found")) or 0
    high = as_int(paste.get("high_count")) or 0
    if high:
        return Outcome(0, msg("paste.score_credentials", count=high), True)
    if total:
        return Outcome(1, msg("paste.score_mentions", count=total), True)
    return Outcome(3, msg("paste.score_clean"), True)


SPEC = ModuleSpec(
    name="paste",
    family="leaks",
    category="sensible",
    run=run,
    keys=(github_key(required=False), intelx_key(required=False)),
    wave=3,
    timeout=120,
    skip_reason=skip_for_ip_target,
    optional=True,
    order=340,
    findings=(
        FindingRule(code="finding.paste.credentials", severity="high", check=_check_credentials),
        FindingRule(code="finding.paste.mentions", severity="low", check=_check_mentions),
    ),
    score_rules=(ScoreRule(criterion="paste", weight=3, evaluate=_score),),
)
