# =============================================================================
# DomainRecon - Scanner : chaîne de redirections HTTP
# =============================================================================
# Deux chaînes sont tracées en parallèle :
#   - depuis http:// : le site force-t-il HTTPS (`forces_https`) ?
#   - depuis https:// : HTTPS renvoie-t-il vers HTTP (`https_downgrade`) ?
# Une absence de réponse (délai, connexion refusée ou coupée) n'est jamais un
# verdict : `forces_https` reste None (inconnu) et, sauf downgrade avéré, le
# module n'est pas mesuré.
# =============================================================================

import asyncio
from urllib.parse import urlsplit

import httpx

from ..i18n import msg
from .common import _http_client, logger, url_host
from .http_utils import (
    INVALID_LOCATION_HEADER,
    MAX_REDIRECTS,
    describe_error,
    guard_redirects,
    is_same_site_url,
    redirect_target,
)

# =============================================================================
# Module 11 : HTTP Redirect Chain
# =============================================================================


def _scheme(url: str) -> str:
    return urlsplit(url).scheme.lower()


def _url_key(url: str) -> str:
    """Forme comparable d'une URL : « https://hote » et « https://hote/ » sont la même page."""
    parts = urlsplit(url)
    return parts._replace(path=parts.path or "/").geturl()


async def _trace_chain(
    client: httpx.AsyncClient, url: str, domain: str
) -> tuple[list[dict], list[object], bool]:
    """Suit les redirections depuis `url` ; retourne (sauts, avertissements, interrompue).

    Les avertissements sont des messages traduisibles (voir domainrecon.i18n).
    La chaîne n'est pas suivie au-delà du premier saut hors du site ciblé.
    Un saut sans réponse porte status_code=0 et `error`.
    """
    chain: list[dict] = []
    warnings: list[object] = []
    interrupted = False

    for hop in range(MAX_REDIRECTS + 1):
        same_site = is_same_site_url(url, domain)
        try:
            # Seuls le statut et les en-têtes comptent : le corps n'est pas lu.
            async with client.stream("GET", url, follow_redirects=False) as response:
                pass
        except Exception as e:
            logger.debug("Redirection non suivie pour %s: %s", url, e)
            chain.append(
                {
                    "url": url,
                    "status_code": 0,
                    "error": describe_error(e),
                    "same_site": same_site,
                }
            )
            interrupted = True
            break

        chain.append(
            {
                "url": url,
                "status_code": response.status_code,
                "server": response.headers.get("server", ""),
                "same_site": same_site,
            }
        )

        if INVALID_LOCATION_HEADER in response.headers:
            warnings.append(msg("redirect.invalid_location"))
            interrupted = True
            break
        if not response.has_redirect_location:
            break
        if not same_site:
            # On ne suit pas les redirections internes d'un site tiers.
            break
        next_url = redirect_target(url, response.headers.get("location"))
        if next_url is None:
            warnings.append(msg("redirect.invalid_location"))
            interrupted = True
            break
        if hop == MAX_REDIRECTS:
            warnings.append(msg("redirect.too_many", max=MAX_REDIRECTS))
            interrupted = True
            break
        url = next_url

    return chain, warnings, interrupted


def _downgrades(chain: list[dict]) -> list[tuple[str, str]]:
    """Redirections d'une URL https vers une URL http du même site."""
    return [
        (prev["url"], nxt["url"])
        for prev, nxt in zip(chain, chain[1:], strict=False)
        if _scheme(prev["url"]) == "https" and _scheme(nxt["url"]) == "http" and nxt["same_site"]
    ]


def _responded(chain: list[dict]) -> bool:
    return bool(chain) and chain[0]["status_code"] != 0


async def trace_redirects(domain: str) -> dict:
    """Trace les chaînes de redirections à partir de http://domaine et https://domaine.

    Les Location relatives et protocol-relative sont résolues par urljoin.
    `forces_https` n'est vrai que si la chaîne HTTP aboutit, sur le même site,
    à une URL dont le schéma est https ; il vaut None si elle n'a pas pu être
    suivie jusqu'au bout sur le site (HTTP sans réponse, saut sans réponse).
    `https_downgrade` est vrai si une URL https du site redirige vers une URL
    http du site, dans l'une ou l'autre chaîne.
    `warnings` et `error` sont des messages traduisibles (voir domainrecon.i18n).
    """
    host = url_host(domain)
    async with _http_client(timeout=10.0, follow_redirects=False) as client:
        guard_redirects(client)
        (chain, warnings, interrupted), (https_chain, _, _) = await asyncio.gather(
            _trace_chain(client, f"http://{host}", domain),
            _trace_chain(client, f"https://{host}", domain),
        )

    # Un même saut peut figurer dans les deux chaînes : rapporté une fois.
    unique: dict[tuple[str, str], tuple[str, str]] = {}
    for source, target in _downgrades(chain) + _downgrades(https_chain):
        unique.setdefault((_url_key(source), _url_key(target)), (source, target))
    downgrades = list(unique.values())
    result = {
        "chain": chain,
        "total_hops": len(chain) - 1 if chain else 0,
        "forces_https": None,
        "final_url": chain[-1]["url"] if chain else None,
        "leaves_site": any(not hop["same_site"] for hop in chain),
        "https_chain": https_chain,
        "https_downgrade": bool(downgrades),
        "http_available": _responded(chain),
        "https_available": _responded(https_chain),
        "warnings": warnings,
        "measured": False,
        "error": None,
    }
    for source, target in downgrades:
        warnings.append(msg("redirect.downgrade", source=source, target=target))

    final = chain[-1] if chain else {}
    if not result["http_available"]:
        # Délai dépassé, connexion refusée ou coupée : rien ne prouve que le
        # site ne sert pas HTTP, ni qu'il redirige vers HTTPS.
        http_error = final.get("error") or msg("redirect.no_response")
        if downgrades:
            result["measured"] = True
        elif result["https_available"]:
            result["error"] = msg("redirect.http_silent", host=host, error=http_error)
        else:
            https_error = (https_chain[0].get("error") if https_chain else None) or msg(
                "redirect.no_response"
            )
            result["error"] = msg("redirect.unreachable", http_error=http_error, https_error=https_error)
        return result

    result["measured"] = True
    if result["leaves_site"]:
        warnings.append(msg("redirect.leaves_site", url=final["url"]))
    if final.get("error") and final["same_site"]:
        # Saut du site sans réponse : la destination finale reste inconnue.
        if downgrades:
            warnings.append(msg("redirect.hop_silent", url=final["url"], error=final["error"]))
        else:
            result.update(
                measured=False,
                error=msg("redirect.hop_silent_unverifiable", url=final["url"], error=final["error"]),
            )
        return result
    if final.get("error"):
        warnings.append(msg("redirect.off_site_silent", url=final["url"], error=final["error"]))
    result["forces_https"] = (
        len(chain) > 1 and not interrupted and _scheme(final["url"]) == "https" and final["same_site"]
    )
    return result
