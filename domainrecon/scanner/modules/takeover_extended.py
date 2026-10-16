# =============================================================================
# DomainRecon - Module « takeover_extended » : détournement de sous-domaines, noms étendus
# =============================================================================
# Le module historique « subdomain_takeover » ne teste que 15 noms des journaux CT.
# Celui-ci teste, avec le même moteur (scanner/takeover.py), les noms que les autres
# sources ont apportés et que le premier n'a pas testés :
#   - « subdomains_passive » : HackerTarget, RapidDNS, Anubis, OTX, urlscan, Wayback… ;
#   - « subdomain_bruteforce » (s'il a tourné, avec l'autorisation de tester la cible) :
#     un nom dont le CNAME vise un service connu passe en tête de file.
# Le moteur contient aussi des empreintes complémentaires encore valables d'après can-i-take-over-xyz (impl/takeover_extra.py : une trentaine de
# services de plus, fusionnés par scanner/takeover.py), ce qui profite aux deux modules. Un nom n'est signalé que sur
# preuve : empreinte propre à la page « site inexistant » du fournisseur, ou CNAME pendant
# (la cible n'existe plus). Passif : DNS public et une requête HTTP(S) par nom testé vers
# le fournisseur tiers. Sans objet pour une adresse IP ou sans nom à tester.
# =============================================================================

from ...i18n import msg
from .. import takeover
from ..registry import ModuleSpec, ScanContext, skip_for_ip_target
from ..rules import FindingInput, FindingRule, Hit, Outcome, ScoreRule, hit
from ..score import as_dict, as_list, takeover_confirmed

# Délai propre, comme le module historique : le travail part d'énumérations déjà faites.
TIMEOUT = 30


def _name(entry: dict) -> str:
    value = entry.get("subdomain")
    return value.strip().lower() if isinstance(value, str) else ""


def candidates(results: dict) -> list[dict]:
    """Noms à tester : {subdomain, resolution}, hors ceux que le module historique teste déjà."""
    already = set(takeover.takeover_candidates(results.get("subdomains")))
    found: dict[str, str] = {}
    for entry in as_list(as_dict(results.get("subdomains_passive")).get("subdomains")):
        entry = as_dict(entry)
        name = _name(entry)
        if name and name not in already:
            found.setdefault(name, "unresolved" if entry.get("resolution") == "unresolved" else "resolved")
    for entry in as_list(as_dict(results.get("subdomain_bruteforce")).get("subdomains_found")):
        entry = as_dict(entry)
        name = _name(entry)
        if not name or name in already:
            continue
        cname = entry.get("cname")
        # Un CNAME vers un service connu est le signe classique d'un détournement : testé en premier.
        pointed = isinstance(cname, str) and takeover.match_service(cname) is not None
        if pointed:
            found[name] = "unresolved"
        else:
            found.setdefault(name, "resolved")
    return [{"subdomain": name, "resolution": resolution} for name, resolution in found.items()]


async def run(context: ScanContext) -> list:
    return await takeover.check_subdomain_takeover(candidates(context.results))


def skip_reason(context: ScanContext) -> object | None:
    reason = skip_for_ip_target(context)
    if reason is not None:
        return reason
    if not candidates(context.results):
        return msg("orchestrator.skip_no_subdomains")
    return None


def _entries(f: FindingInput) -> list[tuple[dict, str, str]]:
    found = []
    for entry in as_list(f.data):
        if isinstance(entry, dict):
            found.append(
                (
                    entry,
                    str(entry.get("subdomain") or "?"),
                    str(entry.get("provider") or entry.get("cname") or "?"),
                )
            )
    return found


def _check_confirmed(f: FindingInput) -> list[dict]:
    return [
        {"subdomain": name, "provider": provider}
        for entry, name, provider in _entries(f)
        if takeover_confirmed(entry)
    ]


def _check_to_check(f: FindingInput) -> list[Hit]:
    return [
        hit(subdomain=name, provider=provider, severity="high" if entry.get("risk") == "medium" else "medium")
        for entry, name, provider in _entries(f)
        if not takeover_confirmed(entry)
    ]


def _score(data: dict) -> Outcome:
    entries = [e for e in as_list(data.get("takeover_extended")) if isinstance(e, dict)]
    confirmed = [e for e in entries if takeover_confirmed(e)]
    if confirmed:
        names = ", ".join(str(e.get("subdomain") or "?") for e in confirmed[:3])
        return Outcome(
            0,
            msg("takeover_extended.score_confirmed", count=len(confirmed)),
            True,
            cap_reason=msg("takeover_extended.cap", names=names),
        )
    if entries:
        return Outcome(2, msg("takeover_extended.score_to_check", count=len(entries)), True)
    return Outcome(5, msg("takeover_extended.score_none"), True)


SPEC = ModuleSpec(
    name="takeover_extended",
    family="dns",
    category="passif",
    run=run,
    wave=3,
    depends_on=("subdomains_passive",),
    timeout=TIMEOUT,
    skip_reason=skip_reason,
    order=181,
    optional=True,
    findings=(
        FindingRule(code="finding.takeover_extended.confirmed", severity="critical", check=_check_confirmed),
        FindingRule(code="finding.takeover_extended.to_check", severity="medium", check=_check_to_check),
    ),
    score_rules=(
        ScoreRule(criterion="takeover_extended", weight=5, evaluate=_score, not_applicable_for_ip=True),
    ),
)
