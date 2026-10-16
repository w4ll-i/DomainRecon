# =============================================================================
# DomainRecon - Scanner : utilitaires HTTP des modules de collecte
# =============================================================================
# - Lecture de corps bornée en streaming : la taille et la durée d'un
#   téléchargement ne dépendent plus de la cible. La taille DÉCODÉE aussi :
#   gzip/deflate sont décompressés ici par morceaux bornés (une seule couche),
#   et non par httpx, dont les décodeurs n'ont aucune limite de sortie
#   (bombe de décompression).
# - Suivi manuel des redirections : Location résolue par urljoin (relative,
#   protocol-relative…), schémas limités à http/https, et arrêt avant de
#   quitter le site ciblé quand on le demande.
# - Comparaison « même site » : même domaine enregistrable (eTLD+1).
# =============================================================================

import ipaddress
import zlib
from dataclasses import dataclass, field
from urllib.parse import urljoin, urlsplit

import httpx
import tldextract

from ..i18n import msg
from .common import url_host
from .errors import TargetNotAllowedError, exception_text, message_exception

# Taille maximale lue pour un corps de réponse (1 Mio).
MAX_BODY_BYTES = 1024 * 1024

# Nombre maximal de redirections suivies par requête.
MAX_REDIRECTS = 10

_ALLOWED_SCHEMES = ("http", "https")

# Liste PSL complète, section privée comprise, comme les navigateurs pour la
# notion de « site » : alice.github.io et bob.github.io sont deux sites
# distincts. Extraction hors ligne (liste embarquée).
_SITE_EXTRACT = tldextract.TLDExtract(suffix_list_urls=(), include_psl_private_domains=True)

# Erreurs d'une requête vers la cible : réseau, URL invalide, cible refusée.
FETCH_ERRORS = (httpx.HTTPError, httpx.InvalidURL, TargetNotAllowedError)


@dataclass
class FetchResult:
    """Résultat d'une requête avec redirections suivies manuellement."""

    # Dernière réponse obtenue (déjà fermée : statut et en-têtes restent lisibles).
    response: httpx.Response
    # Réponses de redirection suivies, dans l'ordre (sans la réponse finale).
    history: list[httpx.Response] = field(default_factory=list)
    body: bytes = b""
    # True si le corps a été coupé à la limite de taille.
    truncated: bool = False
    # Redirection vers un autre site, volontairement non suivie.
    off_site_url: str | None = None
    # Suivi interrompu : schéma non pris en charge, trop de redirections, cible refusée
    # (message traduisible, voir domainrecon.i18n).
    redirect_error: object | None = None

    @property
    def url(self) -> str:
        return str(self.response.url)

    @property
    def status_code(self) -> int:
        return self.response.status_code

    @property
    def headers(self) -> httpx.Headers:
        return self.response.headers

    @property
    def responses(self) -> list[httpx.Response]:
        """Toutes les réponses de la chaîne, redirections comprises."""
        return [*self.history, self.response]

    @property
    def text(self) -> str:
        return decode_body(self.response, self.body)


_GZIP_CODINGS = ("gzip", "x-gzip")


class _BoundedDecoder:
    """Décodeur gzip ou deflate dont chaque appel produit au plus `room` octets.

    Ce que zlib n'a pas pu sortir faute de place reste compressé dans
    `unconsumed_tail` : quelques Ko très compressés ne sont jamais développés
    au-delà de la limite demandée.
    """

    def __init__(self, coding: str) -> None:
        # deflate : décompresseur choisi sur les 2 premiers octets (voir decode).
        self._zlib = zlib.decompressobj(zlib.MAX_WBITS | 16) if coding in _GZIP_CODINGS else None
        self._head = b""

    def decode(self, data: bytes, room: int) -> tuple[bytes, bytes]:
        """Décode au plus `room` octets (> 0) ; retourne (sortie, entrée restante)."""
        if self._zlib is None:
            # deflate : flux zlib (RFC 9110) si l'en-tête zlib est valide, sinon
            # deflate brut, qu'envoient certains serveurs (httpx s'y replie aussi).
            self._head += data
            if len(self._head) < 2:
                return b"", b""
            data, self._head = self._head, b""
            cmf, flg = data[0], data[1]
            is_zlib = cmf & 0x0F == 8 and cmf >> 4 <= 7 and (cmf << 8 | flg) % 31 == 0
            self._zlib = zlib.decompressobj(zlib.MAX_WBITS if is_zlib else -zlib.MAX_WBITS)
        out = self._zlib.decompress(data, room)
        return out, self._zlib.unconsumed_tail

    def flush(self) -> bytes:
        # Appelé une fois toute l'entrée consommée : il ne reste que quelques
        # octets en attente dans zlib.
        return self._zlib.flush() if self._zlib is not None else b""


async def read_body_limited(response: httpx.Response, max_bytes: int = MAX_BODY_BYTES) -> tuple[bytes, bool]:
    """Lit au plus `max_bytes` octets décodés d'une réponse ouverte en streaming.

    Retourne `(corps, tronqué)`. Avec `max_bytes <= 0`, le corps n'est pas lu.
    Le corps brut est décodé ici, avec une sortie bornée : une seule couche
    gzip ou deflate. Des encodages empilés (« gzip, gzip ») ne sont pas lus
    (corps vide, tronqué) ; un encodage inconnu est rendu brut, comme httpx.
    Un flux compressé invalide lève `httpx.DecodingError`.
    """
    if max_bytes <= 0:
        return b"", False

    codings = [
        value.strip().lower() for value in response.headers.get_list("content-encoding", split_commas=True)
    ]
    codings = [coding for coding in codings if coding and coding != "identity"]
    if len(codings) > 1:
        # Encodages empilés : les taux de compression se multiplient (quelques
        # Ko pour des Go). Corps non décodé.
        return b"", True
    try:
        content = response.content
    except httpx.ResponseNotRead:
        pass  # cas normal : corps pas encore lu
    else:
        # Réponse construite en mémoire (httpx.Response(content=…), tests) :
        # corps déjà lu et décodé par httpx, il ne reste qu'à le borner.
        return content[:max_bytes], len(content) > max_bytes
    decoder = _BoundedDecoder(codings[0]) if codings and codings[0] in (*_GZIP_CODINGS, "deflate") else None

    body = bytearray()
    # Un octet de plus que la limite suffit à savoir si le corps est tronqué.
    limit = max_bytes + 1
    try:
        async for chunk in response.aiter_raw():
            if decoder is None:
                body += chunk[: limit - len(body)]
            else:
                while chunk and len(body) < limit:
                    out, rest = decoder.decode(chunk, limit - len(body))
                    if not out and len(rest) >= len(chunk):
                        # Garde-fou : zlib n'avance plus, ne jamais boucler sans fin.
                        raise message_exception(zlib.error, msg("http.decompression_stuck"))
                    body += out
                    chunk = rest
            if len(body) > max_bytes:
                return bytes(body[:max_bytes]), True
        if decoder is not None:
            body += decoder.flush()
    except zlib.error as exc:
        raise message_exception(
            httpx.DecodingError,
            msg("http.bad_compressed_body", detail=exception_text(exc)),
            request=response.request,
        ) from exc
    if len(body) > max_bytes:
        return bytes(body[:max_bytes]), True
    return bytes(body), False


def decode_body(response: httpx.Response, body: bytes) -> str:
    """Décode un corps lu en streaming (charset annoncé, sinon UTF-8)."""
    encoding = response.charset_encoding or "utf-8"
    try:
        return body.decode(encoding, errors="replace")
    except LookupError:
        return body.decode("utf-8", errors="replace")


def host_of_url(url: str | httpx.URL) -> str:
    """Hôte d'une URL, en minuscules et en ASCII (punycode), sans crochets IPv6."""
    try:
        raw = httpx.URL(str(url)).raw_host
    except Exception:
        return ""
    return raw.decode("ascii", errors="replace").lower().rstrip(".")


def _is_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
    except ValueError:
        return False
    return True


def site_of(host: str) -> str:
    """Domaine enregistrable d'un hôte au sens des navigateurs (PSL complète)."""
    extracted = _SITE_EXTRACT(host)
    if extracted.domain and extracted.suffix:
        return f"{extracted.domain}.{extracted.suffix}"
    return host


def same_site(host: str, target: str) -> bool:
    """Vrai si `host` appartient au même site que `target` (même domaine enregistrable).

    Une adresse IP littérale, ou un hôte sans suffixe public, n'est du même site
    que s'il est identique.
    """
    host = (host or "").lower().strip("[]").rstrip(".")
    target = (target or "").lower().strip("[]").rstrip(".")
    if not host or not target:
        return False
    if host == target:
        return True
    if _is_ip(host) or _is_ip(target):
        return False
    # Sans suffixe public (localhost, nom interne), site_of rend l'hôte tel
    # quel : seule l'égalité compte alors.
    return site_of(host) == site_of(target)


def is_same_site_url(url: str | httpx.URL, target: str) -> bool:
    return same_site(host_of_url(url), target)


def redirect_target(current_url: str, location: str | None) -> str | None:
    """Résout une en-tête Location par rapport à l'URL courante.

    Gère les formes relatives (`login`, `../x`, `?a=b`) et protocol-relative
    (`//hote/chemin`). Retourne None si la cible n'est pas en http(s).
    """
    location = (location or "").strip()
    if not location:
        return None
    try:
        joined = urljoin(current_url, location)
        parts = urlsplit(joined)
    except ValueError:
        return None
    if parts.scheme.lower() not in _ALLOWED_SCHEMES or not parts.hostname:
        return None
    return joined


# En-tête où est déplacée une Location inexploitable (voir guard_redirects).
INVALID_LOCATION_HEADER = "x-domainrecon-invalid-location"
_INVALID_LOCATION_MESSAGE = msg("http.invalid_location")


async def _neutralize_invalid_location(response: httpx.Response) -> None:
    """Hook httpx : écarte une Location inexploitable (javascript:, mailto:, URL invalide).

    httpx calcule la redirection suivante même sans la suivre, et lève alors
    InvalidURL : la réponse serait perdue et le site paraîtrait injoignable.
    La Location est déplacée dans INVALID_LOCATION_HEADER.
    """
    if not response.has_redirect_location:
        return
    location = response.headers["location"]
    valid = redirect_target(str(response.request.url), location) is not None
    if valid:
        try:
            response.request.url.join(location)
        except Exception:
            valid = False
    if not valid:
        del response.headers["location"]
        response.headers[INVALID_LOCATION_HEADER] = location


def guard_redirects(client: httpx.AsyncClient) -> httpx.AsyncClient:
    """Installe (une seule fois) le hook qui neutralise les Location inexploitables."""
    hooks = client.event_hooks["response"]
    if _neutralize_invalid_location not in hooks:
        hooks.append(_neutralize_invalid_location)
    return client


async def fetch(
    client: httpx.AsyncClient,
    url: str,
    *,
    method: str = "GET",
    headers: dict | None = None,
    site: str | None = None,
    max_bytes: int = MAX_BODY_BYTES,
    max_redirects: int = MAX_REDIRECTS,
    timeout: httpx.Timeout | float | None = None,
) -> FetchResult:
    """Envoie une requête, suit les redirections et lit un corps borné.

    - Les redirections sont suivies une à une (Location résolue par urljoin,
      http/https uniquement). Le corps des réponses de redirection n'est pas lu.
    - Si `site` est fourni, une redirection vers un autre site n'est pas suivie :
      la réponse de redirection est rendue avec `off_site_url` renseigné. Rien
      de ce site tiers n'est donc attribué à la cible.
    - Les erreurs de la première requête (réseau, délai, cible refusée) sont
      levées ; celles d'une redirection interrompent le suivi et sont rendues
      dans `redirect_error` avec la dernière réponse obtenue.
    """
    guard_redirects(client)
    history: list[httpx.Response] = []
    current = url
    kwargs: dict = {"headers": headers, "follow_redirects": False}
    if timeout is not None:
        kwargs["timeout"] = timeout

    max_redirects = max(max_redirects, 0)
    for hop in range(max_redirects + 1):
        try:
            async with client.stream(method, current, **kwargs) as response:
                if INVALID_LOCATION_HEADER in response.headers:
                    return FetchResult(response, history, redirect_error=_INVALID_LOCATION_MESSAGE)
                if not response.has_redirect_location:
                    body, truncated = await read_body_limited(response, max_bytes)
                    return FetchResult(response, history, body, truncated)
        except FETCH_ERRORS as exc:
            if not history:
                raise
            # Redirection vers un hôte injoignable ou refusé : on garde la
            # dernière réponse obtenue.
            last = history.pop()
            return FetchResult(
                last,
                history,
                redirect_error=msg("http.redirect_not_followed", url=current, error=exception_text(exc)),
            )

        next_url = redirect_target(str(response.url), response.headers.get("location"))
        if next_url is None:
            return FetchResult(response, history, redirect_error=_INVALID_LOCATION_MESSAGE)
        if site and not is_same_site_url(next_url, site):
            return FetchResult(response, history, off_site_url=next_url)
        if hop == max_redirects:
            return FetchResult(
                response,
                history,
                redirect_error=msg("http.too_many_redirects", max=max_redirects),
            )
        history.append(response)
        current = next_url

    raise AssertionError("inaccessible")  # pragma: no cover


async def fetch_first(
    client: httpx.AsyncClient,
    domain: str,
    path: str = "",
    **kwargs,
) -> tuple[FetchResult | None, object | None]:
    """Essaie `https://domain` puis `http://domain` ; retourne (résultat, erreur).

    L'erreur (message traduisible) n'est renseignée que si aucun des deux
    schémas n'a répondu. Le suivi est limité au site ciblé, sauf si `site`
    est passé explicitement.
    """
    kwargs.setdefault("site", domain)
    errors: list[object] = []
    for scheme in ("https", "http"):
        try:
            return await fetch(client, f"{scheme}://{url_host(domain)}{path}", **kwargs), None
        except FETCH_ERRORS as exc:
            errors.append(msg("http.scheme_error", scheme=scheme.upper(), error=describe_error(exc)))
    return None, msg("http.unreachable", errors=errors)


def describe_error(exc: BaseException) -> object:
    """Message court et lisible (traduisible) pour une erreur HTTP.

    Renvoie un message ; à défaut de texte exploitable, le nom brut du type de l'erreur.
    """
    if isinstance(exc, httpx.TimeoutException):
        return msg("net.timeout")
    if isinstance(exc, TargetNotAllowedError):
        return exc.message or msg("http.target_refused")
    if isinstance(exc, httpx.ConnectError):
        detail = exception_text(exc)
        return msg("http.connect_failed_detail", detail=detail) if detail else msg("http.connect_failed")
    text = str(exc)
    # Erreurs courantes de httpx : message traduit plutôt que le texte brut.
    if isinstance(exc, httpx.RemoteProtocolError):
        if "disconnected" in text.lower():
            return msg("http.server_disconnected")
        return msg("http.protocol_error_detail", detail=text) if text else msg("http.protocol_error")
    if isinstance(exc, (httpx.ReadError, httpx.WriteError)):
        return msg("http.connection_interrupted")
    if text:
        return msg("common.exception", error=type(exc).__name__, detail=exception_text(exc))
    return type(exc).__name__
