# =============================================================================
# DomainRecon - Module « wayback_data » : historique d'archivage (Wayback Machine)
# =============================================================================
# Consulte l'index public d'archive.org (API CDX et API de disponibilité, sans
# clé, documentation : https://archive.org/developers/wayback-cdx-server.html)
# pour établir si le site est archivé, depuis quand (première capture), jusqu'à
# quand (dernière capture), quelles années ont été capturées, la capture la plus
# proche d'aujourd'hui et quelques URL archivées du site.
#
# Passif : seule la consultation de l'archive est faite, la cible n'est pas
# contactée. Le détail des requêtes et les pièges évités (dates fausses faute de
# tri par date, appel http sans redirection) sont dans
# impl/wayback_cdx.py. Facultatif : archive.org est parfois lent ou limite le
# débit, ce qui ne doit pas dégrader le statut global du scan. Aucun constat
# ni critère de score : l'archive est une information, pas un défaut.
#
# Limites : première et dernière captures sont celles de la page d'accueil du
# nom analysé (pas du site entier) ; le nombre total de captures n'est pas
# donné (le CDX ne le fournit pas sans parcourir tout l'index).
# =============================================================================

from ...i18n import msg
from ..errors import ModuleError
from ..impl import wayback_cdx
from ..registry import ModuleSpec, ScanContext, skip_for_ip_target


async def run(context: ScanContext) -> dict:
    if context.http is None:
        raise ModuleError(
            msg("network.service_error", context=wayback_cdx.SERVICE, detail="client HTTP absent")
        )
    return await wayback_cdx.analyze(context.http, context.domain)


SPEC = ModuleSpec(
    name="wayback_data",
    family="identity",
    category="passif",
    run=run,
    skip_reason=skip_for_ip_target,
    wave=1,
    # Le CDX peut mettre plus de 40 s à répondre pour un domaine très archivé.
    timeout=60,
    optional=True,
    order=190,
)
