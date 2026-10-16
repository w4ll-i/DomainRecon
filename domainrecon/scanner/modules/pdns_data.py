# =============================================================================
# DomainRecon - Module « pdns_data » : DNS passif (historique des enregistrements)
# =============================================================================
# Historique des adresses et noms vus pour le domaine : CIRCL Passive DNS (identifiants
# facultatifs : accès sur demande), AlienVault OTX passive_dns (clé facultative, l'accès
# anonyme est refusé depuis 2026) et Robtex (gratuit, sans clé, 10 requêtes par heure).
# Les trois sources sont fusionnées en une liste d'enregistrements datés. Le module
# tourne sans aucune clé (Robtex seul) et s'enrichit avec elles. Passif : archives
# tierces, aucune requête vers la cible. Sans objet pour une adresse IP.
# Logique : impl/pdns.py.
# =============================================================================

from ..impl import pdns
from ..keys import ApiKey
from ..registry import ModuleSpec, ScanContext, skip_for_ip_target


async def run(context: ScanContext) -> dict:
    secrets = context.secrets
    return await pdns.collect(
        context.http,
        context.site,
        circl_user=secrets.get("circl_user"),
        circl_password=secrets.get("circl_password"),
        otx_key=secrets.get("otx_key"),
    )


SPEC = ModuleSpec(
    name="pdns_data",
    family="dns",
    category="passif",
    run=run,
    skip_reason=skip_for_ip_target,
    order=29,
    optional=True,
    keys=(
        ApiKey(name="circl_user", service="circl", label="CIRCL", required=False, free_text=True),
        ApiKey(name="circl_password", service="circl", label="CIRCL", required=False, hidden=True),
        ApiKey(name="otx_key", service="otx", label="AlienVault OTX", required=False),
    ),
)
