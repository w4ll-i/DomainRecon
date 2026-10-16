# =============================================================================
# DomainRecon - Module « subdomain_bruteforce » : brute-force DNS de sous-domaines
# =============================================================================
# Résout les mots d'une liste de 887 noms courants (www, dev, vpn, jenkins…) sous
# le domaine du site : des centaines de requêtes DNS vers les serveurs du domaine,
# donc module ACTIF (profil personnalisé, avec l'autorisation de tester la cible).
# Un joker DNS est sondé avant et ses réponses sont écartées (jamais de faux
# positifs en masse). Complète « subdomains » (sources passives) avec les noms qui
# n'ont jamais eu de certificat public. Logique : impl/subdomain_bruteforce.py.
# Sans objet pour une adresse IP.
# =============================================================================

from ..impl import subdomain_bruteforce as engine
from ..registry import ModuleSpec, ScanContext, skip_for_ip_target
from ..rules import FindingInput, FindingRule, hit
from ..score import as_dict, as_list


async def run(context: ScanContext) -> dict:
    return await engine.bruteforce(context.site)


def _entries(f: FindingInput) -> list[dict]:
    return [e for e in as_list(as_dict(f.data).get("subdomains_found")) if isinstance(e, dict)]


def _check_sensitive(f: FindingInput) -> list | None:
    names = [
        str(e.get("subdomain"))
        for e in _entries(f)
        if str(e.get("subdomain", "")).split(".", 1)[0] in engine.SENSITIVE_LABELS
    ]
    return [hit(names=names[:10], count=len(names))] if names else None


def _check_private(f: FindingInput) -> list | None:
    names = [str(e.get("subdomain")) for e in _entries(f) if e.get("private")]
    return [hit(names=names[:10], count=len(names))] if names else None


SPEC = ModuleSpec(
    name="subdomain_bruteforce",
    family="dns",
    category="actif",
    run=run,
    skip_reason=skip_for_ip_target,
    # Vague 2 (et non 3) : son résultat alimente « takeover_extended » (vague 3), qui teste les
    # CNAME vers des services tiers qu'il a trouvés.
    wave=2,
    timeout=180,
    order=21,
    findings=(
        FindingRule(code="finding.subdomain_bruteforce.sensitive", severity="medium", check=_check_sensitive),
        FindingRule(code="finding.subdomain_bruteforce.private_ip", severity="medium", check=_check_private),
    ),
)
