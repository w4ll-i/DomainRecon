# =============================================================================
# DomainRecon - Scanner : page d'accueil de la cible, partagée par les modules
# =============================================================================
# Beaucoup de modules lisent la même page (technologies, mentions légales,
# traceurs, formulaires, JavaScript…). ScanContext.homepage() la récupère UNE
# fois par scan (https://cible, sinon http://cible, redirections suivies sans
# quitter le site, corps borné à 1 Mio) et la partage : les modules suivants
# reçoivent le même résultat sans nouvelle requête.
#
# La récupération passe par le client des requêtes vers la cible
# (common._http_client : proxy du scan, politique anti-SSRF, TLS non vérifié
# pour pouvoir lire un site au certificat invalide). Elle continue si le module
# qui l'a demandée est interrompu (délai) : les autres l'attendent encore.
# Une cible injoignable ne lève pas d'exception : HomePage.error le dit.
# =============================================================================

import asyncio
from dataclasses import dataclass, field

from .http_utils import MAX_BODY_BYTES

# Délai de la récupération (connexion et lecture, par requête), en secondes.
HOMEPAGE_TIMEOUT = 15.0


@dataclass(frozen=True)
class HomePage:
    """Page d'accueil de la cible, telle que récupérée une fois pour le scan.

    - url : URL finale (après redirections du site) ; None si injoignable ;
    - status_code : code HTTP final ; None si injoignable ;
    - headers : en-têtes de la réponse finale, noms en minuscules (dict) ;
    - text : corps décodé (borné à MAX_BODY_BYTES), « » sans corps ;
    - truncated : corps coupé à la limite ;
    - redirects : chaîne des URL suivies avant la réponse finale ;
    - off_site_url : redirection vers un autre site, non suivie ;
    - error : message traduisible si aucun schéma n'a répondu.
    Les valeurs sont des types JSON : un module peut les recopier dans son résultat.
    """

    url: str | None = None
    status_code: int | None = None
    headers: dict[str, str] = field(default_factory=dict)
    text: str = ""
    truncated: bool = False
    redirects: tuple[str, ...] = ()
    off_site_url: str | None = None
    error: object | None = None

    @property
    def reachable(self) -> bool:
        return self.status_code is not None

    @property
    def https(self) -> bool:
        return bool(self.url and self.url.startswith("https://"))


async def fetch_homepage(domain: str) -> HomePage:
    """Récupère la page d'accueil de `domain` (https puis http)."""
    # Imports locaux : common lit l'état du scan (proxy) au moment de l'appel.
    from .common import _http_client
    from .http_utils import fetch_first

    async with _http_client(timeout=HOMEPAGE_TIMEOUT, follow_redirects=False) as client:
        fetched, error = await fetch_first(client, domain, max_bytes=MAX_BODY_BYTES)
    if fetched is None:
        return HomePage(error=error)
    headers: dict[str, str] = {}
    for name, value in fetched.headers.multi_items():
        key = name.lower()
        # En-têtes répétés (Set-Cookie…) : joints comme le ferait un navigateur.
        headers[key] = f"{headers[key]}, {value}" if key in headers else value
    return HomePage(
        url=fetched.url,
        status_code=fetched.status_code,
        headers=headers,
        text=fetched.text,
        truncated=fetched.truncated,
        redirects=tuple(str(response.url) for response in fetched.history),
        off_site_url=fetched.off_site_url,
        error=fetched.redirect_error,
    )


class SharedScanState:
    """État partagé par tous les modules d'un même scan (copié par référence entre contextes)."""

    def __init__(self) -> None:
        self._homepage: asyncio.Task | None = None

    async def homepage(self, domain: str) -> HomePage:
        if self._homepage is None:
            self._homepage = asyncio.ensure_future(fetch_homepage(domain))
        # shield : interrompre le module qui attend n'annule pas la récupération des autres.
        return await asyncio.shield(self._homepage)

    def close(self) -> None:
        """Fin du scan : abandonne une récupération encore en cours."""
        task = self._homepage
        if task is not None and not task.done():
            task.cancel()
        elif task is not None and not task.cancelled():
            # Exception déjà consommée par les modules : on la lit pour éviter l'avertissement.
            task.exception()
