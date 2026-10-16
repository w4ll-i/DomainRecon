# =============================================================================
# DomainRecon - Intelligence X : recherche asynchrone (partagée par intelx et paste)
# =============================================================================
# Documentation : https://github.com/IntelligenceX/SDK et https://help.intelx.io/api/
#   1. POST <hôte>/intelligent/search  {term, buckets, lookuplevel, maxresults, timeout,
#      datefrom, dateto, sort, media, terminate}  -> {id, status} (status 0 = lancée) ;
#   2. GET  <hôte>/intelligent/search/result?id=<id>&limit=<n>  -> {records, status} :
#      0 = résultats (d'autres peuvent suivre), 1 = plus de résultat, 2 = identifiant
#      inconnu, 3 = rien encore (attendre) ;
#   3. GET  <hôte>/intelligent/search/terminate?id=<id> : libère la recherche (les
#      recherches simultanées sont limitées : 5 en offre gratuite).
# Hôtes : free.intelx.io (compte gratuit) et 2.intelx.io (offre payante) ; une clé
# n'est reconnue que par son hôte (401 sinon) : on essaie le gratuit puis le payant.
# La clé n'est envoyée QUE dans l'en-tête x-key (jamais dans l'URL, ancien défaut).
# Seules des MÉTADONNÉES sont lues (nom, bucket, date, type) : aucun contenu de
# document n'est téléchargé, aucun identifiant n'est donc enregistré.
# =============================================================================

import asyncio
import time

import httpx

from ...i18n import msg
from ..errors import ModuleError
from ..score import as_dict, as_int, as_list
from .leaks_commun import REQUEST_ERRORS, Reply, mask_text, network_error, request, status_error

LABEL = "Intelligence X"
# Hôtes essayés dans l'ordre : l'offre gratuite d'abord (cas le plus courant pour un outil perso).
HOSTS = (("free", "https://free.intelx.io"), ("paid", "https://2.intelx.io"))
# Attente entre deux lectures de résultats, en secondes (réduite par les tests).
POLL_INTERVAL = 2.0
# Durée maximale d'une recherche (hors envoi), en secondes.
SEARCH_WAIT = 30.0
# Nombre maximal de résultats demandés.
MAX_RESULTS = 50

# Types de média (SDK) utiles à l'affichage.
MEDIA = {1: "paste", 2: "paste_user", 3: "forum", 13: "tweet", 14: "url", 15: "pdf", 23: "html", 24: "text"}


def sanitize_record(record: object) -> dict:
    """Enregistrement réduit à des métadonnées sûres (le nom du fichier peut citer une adresse : masqué)."""
    item = as_dict(record)
    media = as_int(item.get("media"))
    return {
        "name": mask_text(str(item.get("name") or ""), 100),
        "bucket": str(item.get("bucket") or item.get("bucketh") or "")[:60],
        "date": str(item.get("date") or "")[:10],
        "media": media,
        "media_label": MEDIA.get(media or -1, str(item.get("mediah") or "")[:30]),
        "type": as_int(item.get("type")),
        "size": as_int(item.get("size")),
        "storageid": str(item.get("storageid") or "")[:80],
    }


async def _post_search(client: httpx.AsyncClient, base: str, key: str, term: str, media: int) -> Reply:
    body = {
        "term": term,
        "buckets": [],
        "lookuplevel": 0,
        "maxresults": MAX_RESULTS,
        "timeout": 0,
        "datefrom": "",
        "dateto": "",
        "sort": 2,
        "media": media,
        "terminate": [],
    }
    return await request(
        client, "POST", f"{base}/intelligent/search", headers={"x-key": key}, json_body=body, timeout=20
    )


async def _terminate(client: httpx.AsyncClient, base: str, key: str, search_id: str) -> None:
    """Libère la recherche côté service ; un échec est sans conséquence."""
    try:
        await request(
            client,
            "GET",
            f"{base}/intelligent/search/terminate",
            headers={"x-key": key},
            params={"id": search_id},
            timeout=10,
        )
    except REQUEST_ERRORS:
        return


async def search(client: httpx.AsyncClient, key: str, term: str, *, media: int = 0) -> dict:
    """Lance une recherche et rassemble ses résultats (métadonnées).

    Rend {host: « free » | « paid », records: [...], truncated: bool}. Lève ModuleError : clé refusée
    sur les deux hôtes, quota (402, 429), réseau, réponse illisible.
    """
    reply: Reply | None = None
    host_name, base = HOSTS[0]
    rejected = False
    last_error: BaseException | None = None
    for name, url in HOSTS:
        try:
            current = await _post_search(client, url, key, term, media)
        except REQUEST_ERRORS as e:
            # Constaté en réel : l'hôte gratuit coupe la connexion devant une clé qui n'est pas la sienne.
            last_error = e
            continue
        if current.status in (401, 403):  # 403 : clé inconnue de l'hôte payant
            rejected = True
            continue
        reply, host_name, base = current, name, url
        break
    if reply is None:
        if rejected or last_error is None:
            raise ModuleError(msg("intelx.key_rejected"))
        raise network_error(LABEL, last_error) from None
    if reply.status == 402:
        raise ModuleError(msg("intelx.no_credit"))
    if reply.status != 200:
        raise status_error(LABEL, reply.status)
    try:
        started = as_dict(reply.json())
    except ValueError:
        raise ModuleError(msg("intelx.unreadable")) from None
    search_id = started.get("id")
    if started.get("status") not in (0, None) or not isinstance(search_id, str) or not search_id:
        # status 1 : terme invalide ; 2 : trop de recherches simultanées.
        raise ModuleError(msg("intelx.search_refused"))

    records: list[dict] = []
    deadline = time.monotonic() + SEARCH_WAIT
    try:
        while True:
            try:
                page = await request(
                    client,
                    "GET",
                    f"{base}/intelligent/search/result",
                    headers={"x-key": key},
                    params={"id": search_id, "limit": MAX_RESULTS, "statistics": 0, "previewlines": 0},
                    timeout=20,
                )
            except REQUEST_ERRORS as e:
                raise network_error(LABEL, e) from None
            if page.status != 200:
                raise status_error(LABEL, page.status)
            try:
                data = as_dict(page.json())
            except ValueError:
                raise ModuleError(msg("intelx.unreadable")) from None
            records.extend(sanitize_record(r) for r in as_list(data.get("records")))
            state = data.get("status")
            # 1 : terminé ; 2 : recherche inconnue ; sinon (0, 3) : attendre la suite.
            if state in (1, 2) or len(records) >= MAX_RESULTS or time.monotonic() >= deadline:
                break
            await asyncio.sleep(POLL_INTERVAL)
    finally:
        await _terminate(client, base, key, search_id)
    return {"host": host_name, "records": records[:MAX_RESULTS], "truncated": len(records) >= MAX_RESULTS}
