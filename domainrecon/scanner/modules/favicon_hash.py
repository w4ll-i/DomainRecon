# =============================================================================
# DomainRecon - Module « favicon_hash » : empreinte du favicon pour pivoter (Shodan…)
# =============================================================================
# Calcule l'empreinte MurmurHash3 signée du favicon (base64 avec retours à la ligne
# tous les 76 caractères), celle qu'attendent Shodan (`http.favicon.hash:<n>`) et FOFA
# (`icon_hash="<n>"`), ainsi que le MD5 pour Censys : de quoi retrouver les autres
# serveurs qui servent la même icône (origine d'un site derrière un CDN, panneaux de
# gestion, instances d'un même logiciel). L'implémentation pure du MurmurHash3 est vérifiée contre
# la bibliothèque `mmh3`. Voir impl/wc_favicon.py.
#
# Passif : une page d'accueil déjà récupérée et au plus 4 requêtes vers l'icône, comme
# un navigateur. Aucun constat de sécurité : c'est une information de pivot.
# =============================================================================

from ...i18n import msg
from .. import common
from ..errors import ModuleError
from ..http_utils import FETCH_ERRORS, fetch, host_of_url
from ..impl import wc_favicon
from ..impl.wc_runtime import require_homepage
from ..registry import ModuleSpec, ScanContext


async def run(context: ScanContext) -> dict:
    home = await require_homepage(context)
    base = home.url or f"https://{context.domain}/"
    default_url = f"{base.split('://', 1)[0]}://{host_of_url(base)}/favicon.ico"
    candidates = wc_favicon.candidates(home.text, base, default_url)
    tried: list[dict] = []

    async with common._http_client(timeout=8.0) as client:
        for item in candidates:
            content: bytes | None = item.get("data")
            url = item.get("url")
            status = None
            if content is None and url:
                try:
                    fetched = await fetch(
                        client, url, site=host_of_url(url), max_bytes=wc_favicon.MAX_FAVICON_BYTES + 1
                    )
                except FETCH_ERRORS:
                    tried.append({"url": url[:200], "status": None})
                    continue
                status = fetched.status_code
                content = fetched.body if status == 200 and not fetched.truncated else None
            tried.append({"url": (url or "data:")[:200], "status": status})
            if not content or len(content) > wc_favicon.MAX_FAVICON_BYTES:
                continue
            kind = wc_favicon.sniff_image(content)
            if kind is None:
                continue  # page HTML d'erreur servie avec le code 200 : ce n'est pas une icône
            return {
                "measured": True,
                "error": None,
                "found": True,
                "favicon_url": url[:200] if url else None,
                "source": item["source"],
                "content_type": kind,
                "size_bytes": len(content),
                "tried": tried,
                **wc_favicon.fingerprints(content),
            }

    if all(t["status"] is None for t in tried):
        # Aucune adresse n'a répondu : l'icône n'est pas « absente », elle est injoignable.
        raise ModuleError(msg("favicon_hash.unreachable"))
    return {"measured": True, "error": None, "found": False, "tried": tried}


SPEC = ModuleSpec(
    name="favicon_hash",
    family="web",
    category="passif",
    run=run,
    timeout=45,
    order=214,
)
