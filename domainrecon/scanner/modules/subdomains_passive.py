# =============================================================================
# DomainRecon - Module « subdomains_passive » : sous-domaines, sources passives complémentaires
# =============================================================================
# Complète « subdomains » (journaux Certificate Transparency : crt.sh, Cert Spotter)
# avec les autres sources publiques gratuites encore vivantes en 2026 : HackerTarget,
# RapidDNS, Anubis, AlienVault OTX (url_list), urlscan.io, Wayback Machine et, si la
# clé facultative est renseignée, SecurityTrails. Une source en échec ne bloque pas
# les autres. Passif : archives publiques, la cible n'est pas contactée. Sans objet pour
# une adresse IP. Logique : impl/subdomain_passive.py, impl/subdomain_sources.py.
# =============================================================================

from ..impl import subdomain_passive
from ..keys import ApiKey
from ..registry import ModuleSpec, ScanContext, skip_for_ip_target


async def run(context: ScanContext) -> dict:
    return await subdomain_passive.enumerate_subdomains(context)


SPEC = ModuleSpec(
    name="subdomains_passive",
    family="dns",
    category="passif",
    run=run,
    skip_reason=skip_for_ip_target,
    order=19,
    optional=True,
    # Clé facultative : source supplémentaire quand elle est renseignée (même déclaration que
    # le module « securitytrails », qui l'exige).
    keys=(
        ApiKey(name="securitytrails_key", service="securitytrails", label="SecurityTrails", required=False),
    ),
)
