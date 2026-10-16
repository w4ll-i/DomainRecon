# =============================================================================
# DomainRecon - Module « certsh_data » : certificats publiés dans les journaux CT
# =============================================================================
# Liste les certificats émis pour le domaine et ses sous-domaines d'après les
# journaux Certificate Transparency (crt.sh, Cert Spotter en secours partiel) :
# émetteurs, validité, jokers, et NOMS VUS SEULEMENT EN CT (présents dans un
# certificat public mais absents du DNS : environnements retirés ou noms internes
# divulgués). La requête crt.sh est partagée (et mise en cache) avec le module
# « subdomains ». Passif : archives publiques. Sans objet pour une adresse IP.
# Logique : impl/certsh.py.
# =============================================================================

from ..impl import certsh as engine
from ..registry import ModuleSpec, ScanContext, skip_for_ip_target
from ..rules import FindingInput, FindingRule, hit
from ..score import as_dict, as_int, as_list


async def run(context: ScanContext) -> dict:
    return await engine.analyze(context.site)


def _check_ct_only(f: FindingInput) -> list | None:
    data = as_dict(f.data)
    entries = [as_dict(e) for e in as_list(data.get("ct_only"))]
    count = as_int(data.get("ct_only_count")) or 0
    if not entries or not count:
        return None
    names = [str(e.get("name")) for e in entries[:10]]
    return [hit(count=count, names=names)]


SPEC = ModuleSpec(
    name="certsh_data",
    family="dns",
    category="passif",
    run=run,
    skip_reason=skip_for_ip_target,
    order=27,
    optional=True,
    findings=(FindingRule(code="finding.certsh_data.ct_only", severity="low", check=_check_ct_only),),
)
