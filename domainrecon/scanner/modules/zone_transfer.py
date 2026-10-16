# =============================================================================
# DomainRecon - Module « zone_transfer » : transfert de zone DNS (AXFR)
# =============================================================================
# Demande une copie complète de la zone à chacun des serveurs de noms du domaine
# enregistrable. Un serveur qui la livre expose tous les noms d'hôtes et adresses.
# Module ACTIF : connexions TCP vers les serveurs de noms du domaine (profil
# personnalisé, avec l'autorisation de tester la cible). Logique et correction du
# défaut historique (nom d'hôte au lieu d'une IP) : impl/zone_transfer.py.
# Cible d'essai autorisée : zonetransfer.me. Sans objet pour une adresse IP.
# =============================================================================

from ...i18n import msg
from ..impl import zone_transfer as engine
from ..registry import ModuleSpec, ScanContext, skip_for_ip_target
from ..rules import FindingInput, FindingRule, Outcome, ScoreRule, hit
from ..score import as_dict, as_list


async def run(context: ScanContext) -> dict:
    return await engine.attempt(context.apex)


def _check_open(f: FindingInput) -> list | None:
    data = as_dict(f.data)
    servers = [s for s in as_list(data.get("vulnerable_servers")) if isinstance(s, str)]
    if not data.get("vulnerable") or not servers:
        return None
    return [hit(servers=servers, count=int(data.get("record_count") or 0))]


def _score(data: dict) -> Outcome:
    result = as_dict(data.get("zone_transfer"))
    if result.get("vulnerable"):
        servers = [s for s in as_list(result.get("vulnerable_servers")) if isinstance(s, str)]
        return Outcome(0, msg("zone_transfer.score_open", servers=servers), True)
    return Outcome(10, msg("zone_transfer.score_closed", count=len(as_list(result.get("attempted")))), True)


SPEC = ModuleSpec(
    name="zone_transfer",
    family="dns",
    category="actif",
    run=run,
    skip_reason=skip_for_ip_target,
    wave=3,
    timeout=60,
    order=22,
    findings=(FindingRule(code="finding.zone_transfer.open", severity="high", check=_check_open),),
    score_rules=(
        ScoreRule(criterion="zone_transfer", weight=10, evaluate=_score, not_applicable_for_ip=True),
    ),
)
