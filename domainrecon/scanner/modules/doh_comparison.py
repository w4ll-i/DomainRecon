# =============================================================================
# DomainRecon - Module « doh_comparison » : comparaison de résolveurs chiffrés
# =============================================================================
# Résout la cible auprès de Cloudflare et Google (DNS-sur-HTTPS, format binaire de
# la RFC 8484), de Quad9 (DNS-sur-TLS) et du résolveur local, puis compare : un
# résolveur qui refuse un nom que les autres résolvent (filtrage ou censure), une
# adresse non publique renvoyée par certains seulement (puits de sondage,
# empoisonnement), les résolveurs qui valident DNSSEC. Des adresses différentes
# d'un résolveur à l'autre sont normales derrière un CDN (information seulement).
# Passif : requêtes de résolution ordinaires. Sans objet pour une adresse IP.
# Logique : impl/doh.py.
# =============================================================================

from ..impl import doh as engine
from ..registry import ModuleSpec, ScanContext, skip_for_ip_target
from ..rules import FindingInput, FindingRule
from ..score import as_dict, as_list


async def run(context: ScanContext) -> dict:
    return await engine.compare(context.http, context.domain)


def _providers(f: FindingInput, kind: str) -> dict | None:
    for anomaly in as_list(as_dict(f.data).get("anomalies")):
        anomaly = as_dict(anomaly)
        if anomaly.get("type") == kind:
            names = [str(n) for n in as_list(anomaly.get("providers"))]
            return {"providers": names} if names else None
    return None


def _check_blocked(f: FindingInput) -> dict | None:
    return _providers(f, "blocked")


def _check_sinkhole(f: FindingInput) -> dict | None:
    return _providers(f, "sinkhole")


SPEC = ModuleSpec(
    name="doh_comparison",
    family="dns",
    category="passif",
    run=run,
    skip_reason=skip_for_ip_target,
    order=26,
    optional=True,
    findings=(
        FindingRule(code="finding.doh_comparison.blocked", severity="medium", check=_check_blocked),
        FindingRule(code="finding.doh_comparison.sinkhole", severity="medium", check=_check_sinkhole),
    ),
)
