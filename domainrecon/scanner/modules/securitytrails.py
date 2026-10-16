# =============================================================================
# DomainRecon - Module « securitytrails » : sous-domaines et historique DNS (clé d'API)
# =============================================================================
# SecurityTrails (https://docs.securitytrails.com/) : sous-domaines connus du domaine
# et historique de ses adresses IPv4 (enregistrements A). Clé API obligatoire
# (en-tête APIKEY) ; l'offre gratuite est petite et son quota n'est pas confirmé :
# deux requêtes par scan, résultats gardés 24 h. Les mêmes sous-domaines alimentent
# aussi le module « subdomains » quand la clé est renseignée (même cache, une
# seule requête). L'historique est facultatif : s'il est refusé (offre gratuite), le
# module garde les sous-domaines. Passif. Sans objet pour une adresse IP.
# Logique : impl/securitytrails.py.
# =============================================================================

from ...i18n import msg
from ..errors import ModuleError
from ..impl import securitytrails as api
from ..keys import ApiKey
from ..registry import ModuleSpec, ScanContext, skip_for_ip_target

MAX_LISTED = 500


async def run(context: ScanContext) -> dict:
    key = context.secrets.get("securitytrails_key")
    if not key:
        raise ModuleError(msg("securitytrails.no_key"))
    domain = context.site
    subdomains = await api.fetch_subdomains(context.http, key, domain)
    history: list[dict] = []
    history_error: object | None = None
    try:
        history = await api.fetch_history(context.http, key, domain)
    except ModuleError as e:
        # Souvent un refus propre à l'offre gratuite : les sous-domaines restent valables.
        history_error = e.message
    ips = sorted({ip for item in history for ip in item["ips"]})
    return {
        "measured": True,
        "error": None,
        "domain": domain,
        "subdomains": subdomains[:MAX_LISTED],
        "subdomain_count": len(subdomains),
        "history": history,
        "history_error": history_error,
        "history_ips": ips[:50],
    }


SPEC = ModuleSpec(
    name="securitytrails",
    family="dns",
    category="cle_api",
    run=run,
    skip_reason=skip_for_ip_target,
    order=28,
    optional=True,
    keys=(ApiKey(name="securitytrails_key", service="securitytrails", label="SecurityTrails"),),
)
