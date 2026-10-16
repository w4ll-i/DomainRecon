# =============================================================================
# DomainRecon - Scanner : normalisation, validation et politique des cibles
# =============================================================================
# Politique anti-SSRF : par défaut, seules les adresses publiques (globalement
# routables) sont analysées. Loopback, réseaux privés (RFC 1918, ULA),
# link-local (dont les métadonnées cloud 169.254.169.254), plages partagées,
# réservées ou multicast sont refusés, sauf si ALLOW_PRIVATE_TARGETS=1 (usage
# volontaire sur son propre réseau).
#
# Le contrôle porte sur les ADRESSES RÉSOLUES, jamais sur la chaîne saisie :
# une liste de blocage textuelle se contourne par une autre écriture de la
# même adresse (« 127.1 », « 0x7f000001 », « ::ffff:127.0.0.1 »…).
# =============================================================================

import asyncio
import ipaddress
import logging
import re
import socket
import unicodedata
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import urlsplit

import idna
import tldextract

from ..core import config
from ..i18n import msg
from .errors import TargetNotAllowedError, message_exception

# Même logger que common.logger (nom du package) ; importer common ici créerait
# un import circulaire, common dépendant de ce module.
logger = logging.getLogger(__package__)

# Extracteur hors-ligne : utilise la liste PSL embarquée dans tldextract.
# Sans cela, le premier appel télécharge la PSL (dépendance réseau au runtime).
_TLD_EXTRACT = tldextract.TLDExtract(suffix_list_urls=())

# Même liste, section privée comprise (github.io, herokuapp.com, pages.dev…) :
# alice.github.io est un site distinct de la plateforme qui l'héberge.
_SITE_EXTRACT = tldextract.TLDExtract(suffix_list_urls=(), include_psl_private_domains=True)

# Nom d'hôte ASCII (IDN déjà converti en punycode) : labels de 1 à 63 caractères.
# `\Z` et non `$` : `$` accepte un saut de ligne final.
_HOSTNAME_RE = re.compile(
    r"^[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?)*\Z"
)

# Dernier label numérique (« 1.2.3 », « 999.1.1.1 », « 2130706433 »,
# « 0x7f000001 ») : les résolveurs système l'interprètent comme une IPv4 au
# format inet_aton, et aucun TLD réel n'a cette forme.
_NUMERIC_LABEL_RE = re.compile(r"(?:[0-9]+|0x[0-9a-f]*)\Z")

# Délai maximal d'une résolution DNS, en secondes.
RESOLVE_TIMEOUT = 6.0

# Préfixe NAT64 « bien connu » (RFC 6052) : l'IPv4 réelle est dans les 32 bits de poids faible.
_NAT64_PREFIX = ipaddress.IPv6Network("64:ff9b::/96")

# Pool dédié aux résolutions en masse de resolve_ip() (sous-domaines) : elles
# ne doivent pas occuper l'exécuteur par défaut, partagé avec TLS, WHOIS,
# e-mail et les résolutions internes de httpx.
_RESOLVER_POOL = ThreadPoolExecutor(max_workers=16, thread_name_prefix="domainrecon-dns")

_IPAddress = ipaddress.IPv4Address | ipaddress.IPv6Address


# =============================================================================
# Normalisation et validation syntaxique
# =============================================================================


def _has_forbidden_chars(value: str) -> bool:
    """Blanc ou caractère de contrôle/format n'importe où dans la chaîne."""
    return any(ch.isspace() or unicodedata.category(ch).startswith("C") for ch in value)


def _parse_ip(value: object) -> _IPAddress | None:
    """Adresse IP littérale stricte (formes décimales canoniques, sans zone IPv6)."""
    if not isinstance(value, str) or not value or "%" in value:
        return None
    try:
        return ipaddress.ip_address(value)
    except ValueError:
        return None


def normalize_target(value: str) -> str:
    """Normalise une URL ou un hôte en nom d'hôte scannable.

    Hôte en minuscules, IDN converti en punycode, IP en forme canonique, IPv6
    sans crochets. Renvoie `''` si la saisie est inexploitable (blancs ou
    caractères de contrôle, port invalide, crochets mal formés, IDN invalide…).
    Le sous-domaine est conservé : `blog.example.com` reste `blog.example.com`.
    """
    if not isinstance(value, str):
        return ""
    raw = value.strip()
    # Un blanc interne (« 127.0.0.1 <img …> ») ou une barre oblique inverse
    # (interprétée comme « / » par les navigateurs, pas par urlsplit) rendent
    # la saisie ambiguë : refus plutôt que deviner.
    if not raw or _has_forbidden_chars(raw) or "\\" in raw:
        return ""

    # IP littérale nue, IPv6 sans crochets comprise (urlsplit la couperait au premier « : »).
    literal = _parse_ip(raw)
    if literal is None and raw.startswith("[") and raw.endswith("]"):
        literal = _parse_ip(raw[1:-1])
        if literal is not None and literal.version != 6:
            return ""
    if literal is not None:
        return str(literal)

    try:
        parts = urlsplit(raw if "://" in raw else f"//{raw}")
        host = parts.hostname or ""
        _ = parts.port  # lève ValueError si le port est invalide ou hors plage
    except ValueError:
        return ""

    host = host.rstrip(".")
    if not host:
        return ""

    literal = _parse_ip(host)
    if "[" in parts.netloc:
        # Entre crochets : seule une IPv6 est acceptable.
        return str(literal) if literal is not None and literal.version == 6 else ""
    if literal is not None:
        return str(literal)

    if not host.isascii():
        try:
            host = idna.encode(host, uts46=True).decode("ascii")
        except (UnicodeError, ValueError):
            return ""
    return host


def registrable_domain(host: str) -> str:
    """Retourne le domaine enregistrable (eTLD+1) d'un hôte.

    Utilisé pour le WHOIS et l'analyse email, qui doivent interroger le domaine
    racine et non le sous-domaine ciblé. Section ICANN de la PSL seulement :
    c'est le nom connu du registre (`github.io` pour `alice.github.io`, voir
    `site_domain()`).
    """
    extracted = _TLD_EXTRACT(host)
    if extracted.domain and extracted.suffix:
        return f"{extracted.domain}.{extracted.suffix}"
    return host


def site_domain(host: str) -> str:
    """Retourne le site d'un hôte : domaine enregistrable au sens de la PSL complète.

    Contrairement à `registrable_domain()`, la section privée de la PSL compte :
    `alice.github.io` rend `alice.github.io` et non `github.io`. Un hôte qui est
    lui-même un suffixe privé (`s3.amazonaws.com`) appartient à la plateforme :
    son site est alors son domaine enregistrable. Même convention que
    `registrable_domain()` sinon (IP ou nom sans suffixe public rendus tels quels).
    """
    extracted = _SITE_EXTRACT(host)
    if extracted.domain and extracted.suffix:
        return f"{extracted.domain}.{extracted.suffix}"
    return registrable_domain(host)


def is_ip_literal(host: str) -> bool:
    """Vrai si `host` est une adresse IPv4 ou IPv6 littérale (sans crochets)."""
    return _parse_ip(host) is not None


def is_valid_target(host: str) -> bool:
    """Vérifie qu'un hôte normalisé est syntaxiquement scannable.

    Validation stricte : IP littérale en forme canonique, ou nom d'hôte ASCII
    complet (`fullmatch`). Tout blanc ou caractère de contrôle est refusé, de
    même qu'un dernier label numérique (IPv4 déguisée). Ne dit rien de
    l'adresse visée : voir `ensure_target_allowed()`.
    """
    if not isinstance(host, str) or not host or len(host) > 253:
        return False
    if _has_forbidden_chars(host):
        return False
    literal = _parse_ip(host)
    if literal is not None:
        return str(literal) == host
    if not _HOSTNAME_RE.fullmatch(host):
        return False
    return not _NUMERIC_LABEL_RE.fullmatch(host.rsplit(".", 1)[-1])


# Conservé pour compatibilité ascendante.
extract_domain = registrable_domain


# =============================================================================
# Politique d'adresses
# =============================================================================


def _embedded_ipv4(addr: ipaddress.IPv6Address) -> ipaddress.IPv4Address | None:
    """IPv4 réellement visée par une IPv6 de transition (mappée, 6to4, NAT64)."""
    if addr.ipv4_mapped is not None:
        return addr.ipv4_mapped
    if addr.sixtofour is not None:
        return addr.sixtofour
    if addr in _NAT64_PREFIX:
        return ipaddress.IPv4Address(int(addr) & 0xFFFFFFFF)
    return None


def is_public_address(ip: str) -> bool:
    """Vrai si `ip` est une adresse globalement routable.

    Les IPv6 qui embarquent une IPv4 (mappée ::ffff:0:0/96, 6to4, NAT64) sont
    jugées sur cette IPv4. Les tests explicites complètent `is_global`, dont
    le périmètre varie selon la version de Python (multicast, site-local…).
    """
    addr = _parse_ip(ip)
    if addr is None:
        return False
    if addr.version == 6:
        embedded = _embedded_ipv4(addr)
        if embedded is not None:
            addr = embedded
        elif addr.is_site_local:
            return False
    return addr.is_global and not (
        addr.is_private
        or addr.is_loopback
        or addr.is_link_local
        or addr.is_multicast
        or addr.is_reserved
        or addr.is_unspecified
    )


def primary_address(addresses: list[str]) -> str | None:
    """Adresse principale d'une liste résolue : première IPv4, sinon première IPv6."""
    for address in addresses:
        if ":" not in address:
            return address
    return addresses[0] if addresses else None


def _system_getaddrinfo(host: str) -> list:
    """Résolution système A + AAAA (point d'injection pour les tests)."""
    return socket.getaddrinfo(host, None, 0, socket.SOCK_STREAM)


async def _lookup(host: str, timeout: float, executor: ThreadPoolExecutor | None) -> list[str]:
    """Résout `host` en adresses uniques, dans l'ordre du résolveur ; `[]` en cas d'échec."""
    literal = _parse_ip(host)
    if literal is not None:
        return [str(literal)]
    if not isinstance(host, str) or not host or _has_forbidden_chars(host):
        return []

    loop = asyncio.get_running_loop()
    try:
        infos = await asyncio.wait_for(
            loop.run_in_executor(executor, _system_getaddrinfo, host), timeout=timeout
        )
    except asyncio.TimeoutError:
        logger.debug("Résolution DNS de %s : délai de %.0f s dépassé", host, timeout)
        return []
    # UnicodeError : label vide ou trop long, refusé par l'encodeur IDNA avant
    # toute requête (ce n'est pas un gaierror).
    except (OSError, UnicodeError, ValueError) as e:
        logger.debug("Résolution DNS de %s impossible : %s", host, e)
        return []

    addresses: list[str] = []
    for family, _, _, _, sockaddr in infos:
        if family not in (socket.AF_INET, socket.AF_INET6):
            continue
        address = str(sockaddr[0]).split("%", 1)[0]
        if address not in addresses:
            addresses.append(address)
    return addresses


async def resolve_addresses(host: str, timeout: float = RESOLVE_TIMEOUT) -> list[str]:
    """Toutes les adresses A et AAAA de `host` (`[host]` pour une IP littérale).

    Renvoie `[]` si le nom ne résout pas ou si le délai est dépassé. Passe par
    l'exécuteur par défaut, comme les connexions httpx qu'elle protège : un
    contrôle de sécurité ne doit pas attendre derrière des résolutions en masse.
    """
    return await _lookup(host, timeout, None)


async def resolve_ip(domain: str, timeout: float = RESOLVE_TIMEOUT) -> str | None:
    """Adresse principale d'un domaine (première IPv4, sinon première IPv6), sous délai."""
    return primary_address(await _lookup(domain, timeout, _RESOLVER_POOL))


def _not_allowed_message(host: str) -> dict:
    # L'adresse résolue n'est pas renvoyée au client : elle ne va que dans les logs.
    if is_valid_target(host):
        return msg("target.not_allowed_host", host=host)
    return msg("target.not_allowed")


async def ensure_target_allowed(host: str) -> list[str]:
    """Résout `host` et applique la politique de cibles.

    Lève `TargetNotAllowedError` si UNE des adresses n'est pas publique et que
    `ALLOW_PRIVATE_TARGETS` n'est pas activé. Renvoie les adresses ; une liste
    vide signifie une cible injoignable, pas un problème de SSRF.
    """
    addresses = await resolve_addresses(host)
    if config.private_targets_allowed():
        return addresses
    blocked = [address for address in addresses if not is_public_address(address)]
    if blocked:
        logger.warning("Cible refusée par la politique anti-SSRF : %s -> %s", host, ", ".join(blocked))
        raise TargetNotAllowedError(_not_allowed_message(host))
    return addresses


def ensure_ip_allowed(ip: str) -> str:
    """Valide une IP littérale avant une connexion directe (scan de ports…).

    Renvoie sa forme canonique. Lève `ValueError` si ce n'est pas une IP, et
    `TargetNotAllowedError` si elle n'est pas publique sans ALLOW_PRIVATE_TARGETS.
    """
    addr = _parse_ip(ip)
    if addr is None:
        raise message_exception(ValueError, msg("target.invalid_ip", ip=repr(ip)))
    canonical = str(addr)
    if not config.private_targets_allowed() and not is_public_address(canonical):
        logger.warning("Adresse refusée par la politique anti-SSRF : %s", canonical)
        raise TargetNotAllowedError(msg("target.ip_not_allowed"))
    return canonical
