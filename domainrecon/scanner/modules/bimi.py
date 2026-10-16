# =============================================================================
# DomainRecon - Module « bimi » : logo de marque (BIMI) dans la messagerie
# =============================================================================
# Lit le TXT default._bimi.<domaine> (repli sur le domaine organisationnel), puis
# contrôle le logo SVG (HTTPS, taille, profil SVG Tiny PS, aucun contenu actif) et le
# certificat de marque VMC/CMC (validité, usage BIMI, domaine couvert). Vérifie que
# DMARC est appliqué, condition pour que les messageries affichent le logo.
# Sources : brouillon IETF BIMI, guide BIMI Group. Passif : DNS public et téléchargement
# des deux fichiers publiés par le domaine lui-même.
# Critère de score en « bonus » (BIMI absent ne pénalise pas). Logique : scanner/impl/bimi.py.
# =============================================================================

import asyncio

from ...i18n import msg
from .. import common
from ..dns import DnsQuerier
from ..errors import ModuleError
from ..impl import bimi as impl
from ..registry import ModuleSpec, ScanContext, skip_for_ip_target
from ..rules import FindingInput, FindingRule, Outcome, ScoreRule
from ..score import as_dict, as_int, as_list

SCORE_WEIGHT = 2


async def run(context: ScanContext) -> dict:
    querier = DnsQuerier(impl.QUERY_TIMEOUT, impl.DNS_BUDGET)
    found = await asyncio.to_thread(impl.find_record, querier, context.domain, context.apex)
    enforced = impl.dmarc_enforced(context.results.get("email_security"))
    if context.http is not None:
        result = await impl.evaluate(context.http, context.domain, context.apex, found, enforced)
    else:
        async with common._api_client(timeout=impl.FETCH_TIMEOUT) as client:
            result = await impl.evaluate(client, context.domain, context.apex, found, enforced)
    if not result["measured"]:
        raise ModuleError(result["error"])
    return result


def skip_reason(context: ScanContext) -> object | None:
    if context.shared_platform:
        return msg("orchestrator.skip_shared_platform")
    return skip_for_ip_target(context)


def _published(f: FindingInput) -> dict | None:
    data = as_dict(f.data)
    return data if data.get("found") is True and data.get("declined") is not True else None


def _check_dmarc(f: FindingInput) -> bool:
    data = _published(f)
    return data is not None and data.get("dmarc_enforced") is False


def _check_logo(f: FindingInput) -> dict | None:
    data = _published(f)
    logo = as_dict(data.get("logo")) if data else {}
    issues = as_list(logo.get("issues"))
    return {"detail": issues} if issues else None


def _certificate_expired(vmc: dict) -> bool:
    days_left = as_int(vmc.get("days_left"))
    return days_left is not None and days_left < 0


def _check_vmc_expired(f: FindingInput) -> dict | None:
    data = _published(f)
    vmc = as_dict(data.get("vmc")) if data else {}
    return {"date": vmc.get("not_after")} if _certificate_expired(vmc) else None


def _check_vmc_invalid(f: FindingInput) -> dict | None:
    data = _published(f)
    vmc = as_dict(data.get("vmc")) if data else {}
    issues = as_list(vmc.get("issues"))
    if not issues or (_certificate_expired(vmc) and len(issues) == 1):
        return None
    return {"detail": issues}


def _score(data: dict) -> Outcome:
    bimi = as_dict(data.get("bimi"))
    if bimi.get("found") is not True or bimi.get("declined") is True:
        return Outcome(0, msg("bimi.score_absent"), True, counted=False)
    if as_list(bimi.get("issues")):
        return Outcome(1, msg("bimi.score_issues", count=len(as_list(bimi.get("issues")))), True)
    return Outcome(SCORE_WEIGHT, msg("bimi.score_ok"), True)


SPEC = ModuleSpec(
    name="bimi",
    family="email",
    category="passif",
    run=run,
    skip_reason=skip_reason,
    # Vague 2 : lit la politique DMARC déjà évaluée par email_security.
    wave=2,
    depends_on=("email_security",),
    timeout=45,
    optional=True,
    order=93,
    findings=(
        FindingRule(code="finding.bimi.dmarc_not_enforced", severity="medium", check=_check_dmarc),
        FindingRule(code="finding.bimi.logo_invalid", severity="low", check=_check_logo),
        FindingRule(code="finding.bimi.vmc_expired", severity="medium", check=_check_vmc_expired),
        FindingRule(code="finding.bimi.vmc_invalid", severity="low", check=_check_vmc_invalid),
    ),
    score_rules=(ScoreRule(criterion="bimi", weight=SCORE_WEIGHT, evaluate=_score),),
)
