# =============================================================================
# DomainRecon - Module « nuclei » : scan de vulnérabilités (binaire externe)
# =============================================================================
# Lance le binaire Nuclei de Project Discovery contre la cible et restitue ses
# constats (CVE, expositions, mauvaises configurations, détournements). Option
# -jsonl (-json est retiré de Nuclei) et échec de lancement distingué d'un scan vide :
# voir impl/nuclei_runner.py.
# Sans objet (ModuleSkipped) si le binaire n'est pas installé ; le chemin se
# règle par la variable DOMAINRECON_NUCLEI_PATH. Catégorie « actif » (envoie de
# nombreuses requêtes à la cible) : autorisation requise, module facultatif
# (son indisponibilité ne dégrade pas le scan).
# =============================================================================

from ...i18n import msg
from .. import common
from ..impl import nuclei_runner
from ..registry import ModuleSpec, ScanContext
from ..rules import FindingInput, FindingRule, Outcome, ScoreRule, hit
from ..score import as_dict, as_list

TIMEOUT = 600


async def run(context: ScanContext) -> dict:
    scheme = "https" if not context.is_ip_target else "http"
    target = f"{scheme}://{common.url_host(context.domain)}"
    proxy = context.proxy
    return await nuclei_runner.run_nuclei(target, proxy, timeout=TIMEOUT - 30)


def _check(f: FindingInput, severities: tuple[str, ...]) -> object:
    data = as_dict(f.data)
    names = [
        str(x.get("name") or x.get("template_id"))
        for x in as_list(data.get("findings"))
        if isinstance(x, dict) and x.get("severity") in severities
    ]
    return hit(count=len(names), names=", ".join(names[:8])) if names else None


def _score(data: dict) -> Outcome:
    result = as_dict(data.get("nuclei"))
    findings = as_list(result.get("findings"))
    if result.get("critical"):
        return Outcome(0, msg("nuclei.score_critical"), True, cap_reason=msg("nuclei.cap"))
    if result.get("high"):
        return Outcome(2, msg("nuclei.score_high"), True)
    if findings:
        return Outcome(4, msg("nuclei.score_findings", count=len(findings)), True)
    return Outcome(6, msg("nuclei.score_clean"), True)


SPEC = ModuleSpec(
    name="nuclei",
    family="web",
    category="actif",
    run=run,
    order=200,
    timeout=TIMEOUT,
    optional=True,
    findings=(
        FindingRule(
            code="finding.nuclei.critical",
            severity="critical",
            check=lambda f: _check(f, ("critical",)),
        ),
        FindingRule(code="finding.nuclei.high", severity="high", check=lambda f: _check(f, ("high",))),
        FindingRule(code="finding.nuclei.medium", severity="medium", check=lambda f: _check(f, ("medium",))),
    ),
    score_rules=(ScoreRule(criterion="nuclei", weight=6, evaluate=_score),),
)
