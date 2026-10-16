# =============================================================================
# DomainRecon - Module « mta_sts » : MTA-STS détaillé et TLS-RPT
# =============================================================================
# Va plus loin que email_security (simple présence du TXT) : télécharge la politique
# https://mta-sts.<domaine>/.well-known/mta-sts.txt (certificat vérifié, aucune
# redirection), la valide (version, mode, max_age, type de contenu) et COMPARE ses
# motifs mx: aux MX réels du domaine. Détaille aussi TLS-RPT (destinations rua=).
# Sources : RFC 8461 (MTA-STS), RFC 8460 (TLS-RPT). Passif : DNS public et une
# requête HTTPS vers le site de politique du domaine.
# Critère de score en « bonus » : MTA-STS absent ne pénalise pas, mais une politique
# cassée ou un MX non couvert coûtent des points. Logique : scanner/impl/mta_sts.py.
# =============================================================================

import asyncio

from ...i18n import msg
from .. import common
from ..dns import DnsQuerier
from ..errors import ModuleError
from ..impl import mta_sts as impl
from ..registry import ModuleSpec, ScanContext, skip_for_ip_target
from ..rules import FindingInput, FindingRule, Outcome, ScoreRule, hit
from ..score import as_dict, as_int, as_list

SCORE_WEIGHT = 4


async def run(context: ScanContext) -> dict:
    domain = context.apex
    querier = DnsQuerier(impl.QUERY_TIMEOUT, impl.DNS_BUDGET)
    dns = await asyncio.to_thread(impl.collect_dns, querier, domain)
    fetched = None
    if len(dns.sts_records) == 1 and dns.host_state not in ("nxdomain", "no_address"):
        if context.http is not None:
            fetched = await impl.fetch_policy(context.http, domain)
        else:
            async with common._api_client(timeout=impl.FETCH_TIMEOUT) as client:
                fetched = await impl.fetch_policy(client, domain)
    result = impl.evaluate(domain, dns, fetched)
    if not result["measured"]:
        raise ModuleError(result["error"])
    return result


def skip_reason(context: ScanContext) -> object | None:
    if context.shared_platform:
        return msg("orchestrator.skip_shared_platform")
    return skip_for_ip_target(context)


def _data(f: FindingInput) -> dict:
    return as_dict(f.data)


def _check_broken(f: FindingInput) -> dict | None:
    data = _data(f)
    if data.get("state") != "broken":
        return None
    return {"detail": [i for i in as_list(data.get("issues"))]}


def _check_mx_uncovered(f: FindingInput):
    data = _data(f)
    uncovered = [h for h in as_list(as_dict(data.get("mx_check")).get("uncovered")) if isinstance(h, str)]
    mode = data.get("state")
    if not uncovered or mode not in ("enforce", "testing"):
        return None
    return hit(severity="high" if mode == "enforce" else "medium", hosts=uncovered, mode=mode)


def _check_not_enforced(f: FindingInput) -> dict | None:
    state = _data(f).get("state")
    return {"mode": state} if state in ("testing", "none") else None


def _check_short_max_age(f: FindingInput) -> dict | None:
    data = _data(f)
    max_age = as_int(as_dict(data.get("policy")).get("max_age"))
    if data.get("state") in ("enforce", "testing") and max_age is not None:
        if max_age < impl.MIN_RECOMMENDED_MAX_AGE:
            return {"days": max_age // 86400}
    return None


def _check_missing(f: FindingInput) -> bool:
    data = _data(f)
    return data.get("state") == "absent" and data.get("has_mail") is True


def _check_rpt_missing(f: FindingInput) -> bool:
    data = _data(f)
    return data.get("state") in ("enforce", "testing") and as_dict(data.get("tls_rpt")).get("found") is False


def _score(data: dict) -> Outcome:
    mta = as_dict(data.get("mta_sts"))
    state = mta.get("state")
    uncovered = bool(as_list(as_dict(mta.get("mx_check")).get("uncovered")))
    if state == "absent":
        if mta.get("has_mail") is True:
            # Bonus non obtenu : ne pénalise pas le domaine, n'entre pas dans le calcul.
            return Outcome(0, msg("mta_sts.score_absent"), True, counted=False)
        return Outcome(0, msg("mta_sts.score_no_mail"), False, applicable=False)
    if state == "enforce":
        if uncovered:
            return Outcome(2, msg("mta_sts.score_enforce_uncovered"), True)
        return Outcome(SCORE_WEIGHT, msg("mta_sts.score_enforce"), True)
    if state == "testing":
        return Outcome(2, msg("mta_sts.score_testing"), True)
    if state == "none":
        return Outcome(1, msg("mta_sts.score_none"), True)
    return Outcome(0, msg("mta_sts.score_broken"), True)


SPEC = ModuleSpec(
    name="mta_sts",
    family="email",
    category="passif",
    run=run,
    skip_reason=skip_reason,
    wave=1,
    timeout=40,
    optional=True,
    order=92,
    findings=(
        FindingRule(code="finding.mta_sts.broken", severity="medium", check=_check_broken),
        FindingRule(code="finding.mta_sts.mx_uncovered", severity="high", check=_check_mx_uncovered),
        FindingRule(code="finding.mta_sts.not_enforced", severity="low", check=_check_not_enforced),
        FindingRule(code="finding.mta_sts.short_max_age", severity="low", check=_check_short_max_age),
        FindingRule(code="finding.mta_sts.missing", severity="low", check=_check_missing),
        FindingRule(code="finding.mta_sts.tls_rpt_missing", severity="low", check=_check_rpt_missing),
    ),
    score_rules=(ScoreRule(criterion="mta_sts", weight=SCORE_WEIGHT, evaluate=_score),),
)
