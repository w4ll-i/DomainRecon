# =============================================================================
# DomainRecon - Module « github_dork » : secrets et configurations dans le code public GitHub
# =============================================================================
# Cherche dans le code public de GitHub (API /search/code, jeton OBLIGATOIRE) des fichiers
# qui citent le domaine avec des mots-clés révélateurs (mot de passe, jeton, .env, clé
# privée…), puis repère les secrets dans les extraits et le début des fichiers sensibles.
# Détails de l'API, des limites et du masquage : impl/github_dork.py.
# Points notables :
#   - sans jeton, GitHub répond 401 : le module exige le jeton (sinon ce 401
#     donnerait « aucun résultat », un faux négatif) ;
#   - les limites de débit sont respectées (cadence, Retry-After, en-têtes X-RateLimit) et
#     les résultats déjà obtenus sont CONSERVÉS quand la limite est atteinte (avant, tout
#     était jeté au premier 403) ;
#   - un résultat qui ne cite pas réellement le domaine (recherche approximative) est écarté ;
#   - les valeurs d'exemple (« changeme », « ${MOT_DE_PASSE} ») ne comptent pas comme secrets.
# Valeurs sensibles : un secret n'est jamais enregistré en clair (type + valeur masquée).
# Catégorie « sensible » : exige l'autorisation de tester la cible (cadre légal).
# =============================================================================

from ...i18n import msg
from ..errors import ModuleError
from ..impl import github_dork as impl
from ..impl.leaks_commun import github_key
from ..registry import ModuleSpec, ScanContext
from ..rules import FindingInput, FindingRule, Outcome, ScoreRule
from ..score import as_dict, as_int


def _search_domain(context: ScanContext) -> str:
    """Domaine cherché : le domaine enregistrable, ou l'hôte lui-même sur une plateforme mutualisée."""
    return context.domain if context.shared_platform else context.apex


async def run(context: ScanContext) -> dict:
    token = context.secrets.get("github_token")
    if not token:
        raise ModuleError(msg("github_dork.key_missing"))
    domain = _search_domain(context)
    results: dict[str, dict] = {}
    queries_run = 0
    rate_limited = False
    skipped = 0
    for template in impl.DORKS:
        state, payload = await impl.search_code(context.http, token, template.format(d=domain))
        if state == "rate_limited":
            rate_limited = True
            break
        queries_run += 1
        if state != "ok" or payload is None:
            skipped += 1
            continue
        for item in payload.get("items") or []:
            if not isinstance(item, dict):
                continue
            normalized = impl.normalize_item(item, domain)
            if normalized and normalized["url"] and normalized["url"] not in results:
                results[normalized["url"]] = normalized
    if queries_run == skipped:
        # Aucune recherche n'a abouti : limite atteinte d'emblée, ou service en erreur.
        if rate_limited:
            raise ModuleError(msg("network.quota", service=impl.LABEL))
        raise ModuleError(
            msg("network.service_error", context=impl.LABEL, detail=msg("github_dork.no_answer"))
        )

    # Contenu brut des fichiers sensibles dont les extraits n'ont montré aucun secret.
    fetched = 0
    for entry in results.values():
        if fetched >= impl.MAX_RAW_FILES:
            break
        if entry["severity"] == "high" and not entry["private"]:
            fetched += 1
            secrets = await impl.raw_secrets(context.http, entry["url"])
            if secrets:
                entry["secrets"] = secrets
                entry["severity"] = "critical"

    ordered = impl.sort_results(list(results.values()))
    count = len(ordered)
    return {
        "measured": True,
        "error": None,
        "domain": domain,
        "queries_total": len(impl.DORKS),
        "queries_run": queries_run,
        "complete": not rate_limited and skipped == 0,
        "rate_limited": rate_limited,
        "total_count": count,
        "critical_count": sum(1 for r in ordered if r["severity"] == "critical"),
        "high_count": sum(1 for r in ordered if r["severity"] == "high"),
        "secrets_count": sum(len(r["secrets"]) for r in ordered),
        "results": ordered[: impl.MAX_RESULTS],
    }


# -----------------------------------------------------------------------------
# Constats et score
# -----------------------------------------------------------------------------


def _check_secrets(f: FindingInput) -> object:
    data = as_dict(f.data)
    files = as_int(data.get("critical_count")) or 0
    return {"files": files, "secrets": as_int(data.get("secrets_count")) or 0} if files > 0 else None


def _check_sensitive_files(f: FindingInput) -> object:
    count = as_int(as_dict(f.data).get("high_count")) or 0
    return {"count": count} if count > 0 else None


def _check_mentions(f: FindingInput) -> object:
    count = as_int(as_dict(f.data).get("total_count")) or 0
    return {"count": count} if count > 0 else None


def _score(data: dict) -> Outcome:
    dork = as_dict(data.get("github_dork"))
    critical = as_int(dork.get("critical_count")) or 0
    high = as_int(dork.get("high_count")) or 0
    total = as_int(dork.get("total_count")) or 0
    if critical:
        return Outcome(0, msg("github_dork.score_secrets", count=critical), True)
    if high:
        return Outcome(1, msg("github_dork.score_sensitive", count=high), True)
    if total:
        return Outcome(3, msg("github_dork.score_mentions", count=total), True)
    return Outcome(5, msg("github_dork.score_clean"), True)


SPEC = ModuleSpec(
    name="github_dork",
    family="leaks",
    category="sensible",
    run=run,
    keys=(github_key(required=True),),
    wave=3,
    timeout=150,
    optional=True,
    order=330,
    findings=(
        FindingRule(code="finding.github_dork.secrets", severity="critical", check=_check_secrets),
        FindingRule(
            code="finding.github_dork.sensitive_files", severity="high", check=_check_sensitive_files
        ),
        FindingRule(code="finding.github_dork.mentions", severity="low", check=_check_mentions),
    ),
    score_rules=(ScoreRule(criterion="github_dork", weight=5, evaluate=_score),),
)
