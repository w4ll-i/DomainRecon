# =============================================================================
# DomainRecon - Module « dns_records_extra » : CAA, SRV et TLSA (DANE)
# =============================================================================
# Complète « dns_records » (A, AAAA, MX, NS, TXT, SOA, CNAME, DMARC) avec trois types :
#   - CAA (RFC 8659) : autorités de certification autorisées, cherchées en remontant
#     vers le domaine organisationnel ;
#   - SRV (RFC 2782) : services courants (_sip._tcp, _submission._tcp, _imaps._tcp…) ;
#     interroger le domaine nu ne renverrait jamais rien ;
#   - TLSA (RFC 6698) : DANE sur le port 443 et sur les MX principaux.
# Passif : requêtes DNS publiques. Sans objet pour une adresse IP.
# Logique : impl/dns_extra.py.
# =============================================================================

from ...i18n import msg
from ..errors import ModuleError
from ..impl import dns_extra
from ..registry import ModuleSpec, ScanContext, skip_for_ip_target
from ..rules import FindingInput, FindingRule
from ..score import as_dict, as_list


async def run(context: ScanContext) -> dict:
    result = await dns_extra.scan_extra(context.domain)
    errors = result.pop("extra_errors")
    if len(errors) == 3:
        raise ModuleError(msg("dns_records_extra.query_failed", domain=context.domain))
    return {"measured": True, "error": None, "domain": context.domain, **result, "errors": errors}


def _check_caa_missing(f: FindingInput) -> bool:
    """Aucun CAA sur la cible ni au-dessus : n'importe quelle autorité peut émettre un certificat."""
    data = as_dict(f.data)
    if data.get("domain_exists") is not True or "CAA" in as_dict(data.get("errors")):
        return False
    return not as_list(data.get("CAA"))


SPEC = ModuleSpec(
    name="dns_records_extra",
    family="dns",
    category="passif",
    run=run,
    skip_reason=skip_for_ip_target,
    order=11,
    findings=(
        FindingRule(code="finding.dns_records_extra.caa_missing", severity="low", check=_check_caa_missing),
    ),
)
