# =============================================================================
# DomainRecon - Scanner : WHOIS
# =============================================================================
# Fichier nommé whois_lookup.py (et non whois.py) pour ne pas masquer le
# paquet python-whois importé ci-dessous.
# Les statuts EPP sont ramenés à leur code (URL retirée) et dédoublonnés : le
# registre et le bureau d'enregistrement renvoient les mêmes, en deux formats.
# Organisation du titulaire, DNSSEC et e-mails sont relus dans la réponse brute
# quand le parseur de l'extension ne les extrait pas (.io, par exemple).
# =============================================================================

import asyncio
import inspect
import re

import whois

from ..i18n import msg
from .common import logger
from .errors import exception_text
from .targets import is_ip_literal

try:
    from whois.exceptions import WhoisDomainNotFoundError
except ImportError:  # python-whois < 0.9.5 : pas d'exception dédiée

    class WhoisDomainNotFoundError(Exception):
        """Jamais levée : remplace l'exception absente des anciennes versions."""


# Délai de socket par serveur WHOIS interrogé, en secondes.
WHOIS_TIMEOUT = 10

# Options selon la version de python-whois. Les erreurs réseau ne sont pas
# levées (comportement par défaut) : python-whois les remplace par le texte
# « Socket not responding ». Une erreur sur le second saut (serveur WHOIS du
# bureau d'enregistrement) conserve ainsi la réponse du registre ; une erreur
# sur le premier ne laisse aucun champ et est traitée comme un échec.
_WHOIS_PARAMS = inspect.signature(whois.whois).parameters
_WHOIS_KWARGS = {"timeout": WHOIS_TIMEOUT} if "timeout" in _WHOIS_PARAMS else {}

# Marqueur inséré par python-whois à la place d'une réponse en cas d'erreur réseau.
_SOCKET_ERROR_MARKER = "Socket not responding"

_DATA_FIELDS = (
    "registrar",
    "creation_date",
    "expiration_date",
    "updated_date",
    "name_servers",
    "status",
    "registrant",
    "emails",
)


# Organisation du titulaire : clé selon le parseur de l'extension.
_REGISTRANT_ORG_KEYS = ("org", "registrant_org", "registrant_organization")

# URL d'un statut EPP, éventuellement entre parenthèses (« (https://icann.org/epp#…) »).
_STATUS_URL_RE = re.compile(r"\(?\s*https?://\S*\s*\)?", re.IGNORECASE)
_REGISTRANT_ORG_RE = re.compile(r"^\s*Registrant\s+Organi[sz]ation:[ \t]*(\S.*?)\s*$", re.IGNORECASE | re.M)
_DNSSEC_RE = re.compile(r"^\s*DNSSEC:[ \t]*(\S.*?)\s*$", re.IGNORECASE | re.M)
_NAME_SERVER_RE = re.compile(r"^\s*Name\s*Server:[ \t]*([A-Za-z0-9._-]+)", re.IGNORECASE | re.M)
_REGISTRAR_SERVER_RE = re.compile(
    r"^\s*Registrar\s+WHOIS\s+Server:[ \t]*([A-Za-z0-9._-]+)", re.IGNORECASE | re.M
)
_EMAIL_RE = re.compile(
    r"[\w.!#$%&'*+/=?^`{|}~-]+@(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z]{2,}", re.IGNORECASE
)


def _format_date(value) -> str | None:
    if isinstance(value, list):
        value = value[0] if value else None
    return str(value) if value else None


def _as_list(value) -> list:
    if not value:
        return []
    return list(value) if isinstance(value, (list, tuple)) else [value]


def _first(value):
    if isinstance(value, (list, tuple)):
        return value[0] if value else None
    return value or None


def _unique(values) -> list[str]:
    """Valeurs sans doublon (casse et blancs ignorés), dans l'ordre d'apparition."""
    seen: dict[str, str] = {}
    for value in values:
        seen.setdefault("".join(value.split()).lower(), value)
    return list(seen.values())


def _epp_statuses(value) -> list[str]:
    """Statuts ramenés à leur code, sans URL, et dédoublonnés.

    « clientDeleteProhibited https://icann.org/epp#… » (registre) et
    « clientDeleteProhibited (https://www.icann.org/epp#…) » (bureau
    d'enregistrement) désignent le même statut.
    """
    statuses = (" ".join(_STATUS_URL_RE.sub(" ", str(status)).split()) for status in _as_list(value))
    return _unique(status for status in statuses if status)


# =============================================================================
# Module 7 : WHOIS
# =============================================================================


def _get_whois_sync(domain: str) -> dict:
    """Requête WHOIS synchrone - exécuté dans un thread.

    `queried_domain` : nom réellement interrogé (le domaine racine, github.io
    pour octocat.github.io), None si aucune requête n'a été faite.
    """
    result = {
        "queried_domain": None,
        "registrar": None,
        "whois_server": None,
        "creation_date": None,
        "expiration_date": None,
        "updated_date": None,
        "name_servers": [],
        "status": [],
        "dnssec": None,
        "registrant": None,
        "emails": [],
        "registered": None,
        "measured": False,
        "error": None,
    }
    if is_ip_literal(domain):
        result["error"] = msg("whois.not_for_ip")
        return result

    result["queried_domain"] = domain
    try:
        w = whois.whois(domain, **_WHOIS_KWARGS)
    except WhoisDomainNotFoundError as e:
        if "no whois server" in str(e).lower():
            result["error"] = msg("whois.no_server")
            return result
        # Réponse explicite du registre : le domaine n'est pas enregistré.
        result.update(registered=False, measured=True)
        return result
    except TimeoutError:
        logger.info("WHOIS : délai dépassé pour %s", domain)
        result["error"] = msg("whois.timeout", seconds=WHOIS_TIMEOUT)
        return result
    except Exception as e:
        logger.info("WHOIS indisponible pour %s: %s", domain, e)
        result["error"] = msg("whois.unavailable", error=exception_text(e))
        return result

    result.update(
        {
            "registrar": getattr(w, "registrar", None),
            "whois_server": _first(getattr(w, "whois_server", None)),
            "creation_date": _format_date(getattr(w, "creation_date", None)),
            "expiration_date": _format_date(getattr(w, "expiration_date", None)),
            "updated_date": _format_date(getattr(w, "updated_date", None)),
            "name_servers": _as_list(getattr(w, "name_servers", None)),
            "status": _epp_statuses(getattr(w, "status", None)),
            "dnssec": getattr(w, "dnssec", None),
            "registrant": next(
                filter(None, (_first(getattr(w, key, None)) for key in _REGISTRANT_ORG_KEYS)), None
            ),
            "emails": _as_list(getattr(w, "emails", None)),
        }
    )
    text = str(getattr(w, "text", "") or "")
    if not any(result[field] for field in _DATA_FIELDS):
        # Réponse vide ou non analysable (quota, format inconnu, serveur
        # injoignable) : pas une mesure.
        if _SOCKET_ERROR_MARKER in text:
            logger.info("WHOIS : serveur injoignable pour %s", domain)
            if "timed out" in text.lower():
                result["error"] = msg("whois.timeout", seconds=WHOIS_TIMEOUT)
            else:
                result["error"] = msg("whois.server_unreachable")
        else:
            result["error"] = msg("whois.empty")
        return result
    if _SOCKET_ERROR_MARKER in text:
        # Registre lu, serveur du bureau d'enregistrement injoignable : les
        # données du registre suffisent.
        logger.info("WHOIS : second serveur injoignable pour %s, réponse du registre conservée", domain)

    # Champs que le parseur de l'extension n'extrait pas, relus dans la réponse
    # brute, une fois celle-ci reconnue exploitable.
    if not result["registrant"] and (match := _REGISTRANT_ORG_RE.search(text)):
        result["registrant"] = match.group(1)
    if not result["dnssec"] and (match := _DNSSEC_RE.search(text)):
        result["dnssec"] = match.group(1)
    if not result["emails"]:
        result["emails"] = _unique(_EMAIL_RE.findall(text))
    # Serveurs de noms que le parseur manque (.me, par exemple) : lignes « Name Server: ».
    if not result["name_servers"]:
        result["name_servers"] = _unique(_NAME_SERVER_RE.findall(text))
    # Serveur WHOIS du bureau d'enregistrement : la ligne de la réponse est plus fiable
    # que l'attribut du parseur (qui renvoie whois.iana.org pour example.com).
    if match := _REGISTRAR_SERVER_RE.search(text):
        result["whois_server"] = match.group(1).lower()

    result.update(registered=True, measured=True)
    return result


async def get_whois_data(domain: str) -> dict:
    """Récupère les informations WHOIS d'un domaine."""
    return await asyncio.to_thread(_get_whois_sync, domain)
