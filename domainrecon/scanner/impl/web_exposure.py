# =============================================================================
# DomainRecon - Sondage de chemins exposés (fichiers sensibles, panneaux, API)
# =============================================================================
# Aides partagées par les modules actifs d'exposition web (sensitive_files,
# admin_panels, api_endpoints) :
#   - une LIGNE DE BASE « soft-404 » : un chemin aléatoire inexistant donne la
#     réponse que le serveur sert à toute URL inconnue (code, taille, début de
#     corps). Un chemin n'est retenu que s'il s'en distingue : un simple code
#     200 ne prouve rien sur un serveur « fourre-tout » ou monopage ;
#   - le suivi concurrent borné des chemins, sans suivre les redirections ;
#   - la comparaison « même page que l'introuvable » par similarité de contenu.
# Les validateurs de contenu propres à chaque module décident si une réponse a
# bien la forme attendue (dépôt Git, fichier .env, documentation OpenAPI…) :
# ici, seule la mécanique de requête et de comparaison, sans réseau direct.
# =============================================================================

import asyncio
import difflib
import secrets as _secrets

from ...i18n import msg
from .. import common
from ..errors import ModuleError
from ..http_utils import FETCH_ERRORS, describe_error, fetch

# Taille maximale lue par chemin (64 Kio : assez pour une signature, jamais le
# contenu complet d'un secret).
MAX_BODY = 64 * 1024
REQUEST_TIMEOUT = 8.0
CONCURRENCY = 6


class Baseline:
    """Réponse du serveur à une URL inexistante (page « introuvable » de référence)."""

    def __init__(self, status_code: int | None = None, text: str = "", length: int = 0) -> None:
        self.status_code = status_code
        self.text = text
        self.length = length

    @property
    def catch_all(self) -> bool:
        """Le serveur répond 200 même à une URL inventée (monopage, fourre-tout)."""
        return self.status_code == 200

    def same_page(self, text: str, length: int) -> bool:
        """La réponse est-elle la page « introuvable » servie à toute URL ?"""
        if self.status_code != 200:
            return False
        a, b = text.strip()[:2000], self.text.strip()[:2000]
        if a == b:
            return True
        if a and b and difflib.SequenceMatcher(None, a, b).quick_ratio() >= 0.95:
            return True
        # Corps non texte (binaire) : comparaison par taille, à 5 % près.
        return not a and not b and bool(self.length) and abs(length - self.length) / self.length < 0.05


async def fetch_path(client, origin: str, path: str, host: str, max_redirects: int = 0):
    return await fetch(client, origin + path, site=host, max_bytes=MAX_BODY, max_redirects=max_redirects)


def origin_of(home, host: str) -> str:
    """Origine (schéma + hôte) de la cible d'après la page d'accueil déjà récupérée."""
    return f"{'https' if home.https else 'http'}://{common.url_host(host)}"


async def measure_baseline(client, origin: str, host: str) -> Baseline:
    """Interroge deux URL aléatoires pour établir la page « introuvable » du serveur."""
    for _ in range(2):
        try:
            fetched = await fetch_path(client, origin, f"/dr-{_secrets.token_hex(8)}", host)
        except FETCH_ERRORS:
            continue
        return Baseline(fetched.status_code, fetched.text, len(fetched.body))
    return Baseline()


async def probe_paths(client, origin, host, paths, handle, concurrency: int = CONCURRENCY) -> list:
    """Interroge chaque chemin (au plus `concurrency` à la fois) ; `handle(path, fetched)` -> entrée ou None.

    `handle` reçoit None en cas d'erreur réseau sur ce chemin. Les entrées non nulles sont rendues.
    """
    semaphore = asyncio.Semaphore(concurrency)

    async def one(path: str):
        async with semaphore:
            try:
                fetched = await fetch_path(client, origin, path, host)
            except FETCH_ERRORS as e:
                return handle(path, None, describe_error(e))
            return handle(path, fetched, None)

    results = await asyncio.gather(*(one(path) for path in paths))
    return [entry for entry in results if entry is not None]


async def open_client():
    """Client des requêtes vers la cible (anti-SSRF, TLS non vérifié), sans suivre les redirections."""
    return common._http_client(timeout=REQUEST_TIMEOUT, follow_redirects=False)


async def homepage_or_fail(context):
    """Page d'accueil de la cible ; lève ModuleError si elle est injoignable."""
    home = await context.homepage()
    if not home.reachable:
        raise ModuleError(home.error or msg("orchestrator.module_failed"))
    return home
