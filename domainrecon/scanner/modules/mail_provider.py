# =============================================================================
# DomainRecon - Module « mail_provider » : fournisseur de messagerie réel derrière les MX
# =============================================================================
# Reconnaît le fournisseur désigné par les MX (Google, Microsoft 365, Proton…),
# repère une passerelle de sécurité (Mimecast, Proofpoint, Barracuda…) et, dans ce
# cas, cherche le fournisseur réel des boîtes derrière elle grâce aux include du
# SPF, aux CNAME autodiscover/DKIM et aux jetons de vérification TXT. Signale
# aussi les MX qui ne résolvent plus (risque de détournement du courrier).
# Source : DNS public uniquement, aucune connexion au serveur de messagerie.
# Limites : heuristique, d'où le niveau de confiance rendu avec le résultat.
# Logique : scanner/impl/mail_provider.py.
# =============================================================================

import asyncio

from ...i18n import msg
from ..dns import DnsQuerier
from ..errors import ModuleError
from ..impl import mail_provider as impl
from ..registry import ModuleSpec, ScanContext, skip_for_ip_target
from ..rules import FindingInput, FindingRule
from ..score import as_dict, as_list

# Délai d'une requête DNS et budget total (inférieur au délai du module).
QUERY_TIMEOUT = 3.0
DNS_BUDGET = 30.0


async def run(context: ScanContext) -> dict:
    spf = impl.spf_from_email_security(context.results.get("email_security"))
    querier = DnsQuerier(QUERY_TIMEOUT, DNS_BUDGET)
    result = await asyncio.to_thread(impl.analyze, querier, context.domain, context.apex, spf)
    if not result["measured"]:
        raise ModuleError(msg("mail_provider.query_failed", error=result["error"]))
    return result


def skip_reason(context: ScanContext) -> object | None:
    if context.shared_platform:
        return msg("orchestrator.skip_shared_platform")
    return skip_for_ip_target(context)


def _check_unresolved_mx(f: FindingInput) -> dict | None:
    hosts = [h for h in as_list(as_dict(f.data).get("unresolved_mx")) if isinstance(h, str)]
    return {"hosts": hosts, "count": len(hosts)} if hosts else None


SPEC = ModuleSpec(
    name="mail_provider",
    family="email",
    category="passif",
    run=run,
    skip_reason=skip_reason,
    # Vague 2 : réutilise le SPF déjà lu par email_security (relu sinon).
    wave=2,
    depends_on=("email_security",),
    timeout=45,
    optional=True,
    order=95,
    findings=(
        FindingRule(
            code="finding.mail_provider.mx_unresolvable", severity="medium", check=_check_unresolved_mx
        ),
    ),
)
