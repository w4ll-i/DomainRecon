# =============================================================================
# DomainRecon - Module « ct_logs » : historique des certificats (Certificate Transparency)
# =============================================================================
# Liste tous les certificats publics émis pour le domaine et ses sous-domaines,
# d'après les journaux Certificate Transparency (crt.sh, repli Cert Spotter) :
# autorités d'émission, rythme d'émission, noms exposés, noms à usage interne ou
# de préproduction visibles de tous. Complète « subdomains », qui n'en tire que
# des noms d'hôtes.
#
# Adapté au JSON actuel de crt.sh (voir scanner/impl/ct_logs.py). Passif : service
# public sans clé, la cible n'est pas contactée. Sans objet pour une adresse IP.
# =============================================================================

from ..impl import ct_logs as history
from ..registry import ModuleSpec, ScanContext, skip_for_ip_target
from ..rules import FindingInput, FindingRule
from ..score import as_dict, as_int, as_list


async def run(context: ScanContext) -> dict:
    records, source, partial = await history.fetch_records(context.site)
    result = history.analyze(records, context.site)
    result.update(source=source, partial=partial)
    return result


# -----------------------------------------------------------------------------
# Constats
# -----------------------------------------------------------------------------


def _data(f: FindingInput) -> dict:
    data = as_dict(f.data)
    return {} if data.get("measured") is False else data


def _check_internal(f: FindingInput) -> dict | None:
    data = _data(f)
    names = [str(n) for n in as_list(data.get("internal_names"))]
    if not names:
        return None
    count = as_int(data.get("internal_name_count")) or len(names)
    return {"count": count, "examples": ", ".join(names[:3]) + (" …" if count > 3 else "")}


def _check_many_issuers(f: FindingInput) -> dict | None:
    count = as_int(_data(f).get("recent_issuer_count")) or 0
    return {"count": count} if count >= history.MANY_ISSUERS_THRESHOLD else None


FINDINGS = (
    FindingRule(code="finding.ct_logs.internal_names", severity="low", check=_check_internal),
    FindingRule(code="finding.ct_logs.many_issuers", severity="low", check=_check_many_issuers),
)


SPEC = ModuleSpec(
    name="ct_logs",
    family="tls",
    category="passif",
    run=run,
    skip_reason=skip_for_ip_target,
    wave=1,
    # crt.sh (30 s, une nouvelle tentative) puis Cert Spotter en secours.
    timeout=90,
    # Service tiers souvent surchargé : son échec ne dégrade pas le statut du scan.
    optional=True,
    order=44,
    findings=FINDINGS,
)
