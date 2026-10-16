# =============================================================================
# DomainRecon - Journaux Certificate Transparency : requêtes partagées
# =============================================================================
# crt.sh (source principale, gratuite, sans clé) puis Cert Spotter (secours,
# certificats en cours de validité seulement). Une seule requête par domaine et
# par heure est faite, partagée entre les modules « subdomains » (noms) et
# « certsh_data » (liste des certificats) : crt.sh, souvent surchargé, limite le
# débit dès qu'on le sollicite deux fois.
#
# Entrée normalisée (même forme pour les deux sources) :
#   {id, not_before, not_after, issuer_name, common_name, name_value, logged_at}
# `name_value` : un nom par ligne, comme crt.sh. Les noms sont validés ensuite
# par l'appelant (scanner.dns._extract_ct_names). Seuls les champs utiles sont
# gardés en cache (une réponse crt.sh complète peut peser des dizaines de Mo).
#
# Sources : https://crt.sh (JSON, `q=%.domaine&output=json`) et
# https://sslmate.com/help/reference/ct_search_api_v1 (Cert Spotter, `issuances`).
# =============================================================================

import asyncio
import json
from urllib.parse import parse_qs, urlsplit

import httpx

from ...i18n import msg
from .. import dns as scanner_dns
from ..cache import cached
from ..common import ACCEPT_ENCODING, logger, proxy_scope
from ..errors import ModuleError, TargetNotAllowedError, exception_text
from ..http_utils import read_body_limited

SOURCE_CRTSH = scanner_dns.CT_SOURCE_CRTSH
SOURCE_CERTSPOTTER = scanner_dns.CT_SOURCE_CERTSPOTTER

CRTSH_URL = scanner_dns.CRTSH_URL
CRTSH_TIMEOUT = scanner_dns.CRTSH_TIMEOUT
CRTSH_MAX_BYTES = scanner_dns.CRTSH_MAX_BYTES
CRTSH_ATTEMPTS = scanner_dns.CRTSH_ATTEMPTS
CRTSH_RETRY_DELAY = scanner_dns.CRTSH_RETRY_DELAY
CRTSH_TRANSIENT_STATUSES = scanner_dns.CRTSH_TRANSIENT_STATUSES

CERTSPOTTER_URL = scanner_dns.CERTSPOTTER_URL
CERTSPOTTER_TIMEOUT = scanner_dns.CERTSPOTTER_TIMEOUT
CERTSPOTTER_BUDGET = scanner_dns.CERTSPOTTER_BUDGET
CERTSPOTTER_MAX_PAGES = scanner_dns.CERTSPOTTER_MAX_PAGES
CERTSPOTTER_MAX_BYTES = scanner_dns.CERTSPOTTER_MAX_BYTES

# Entrées gardées en cache (crt.sh : une heure ; secours partiel : cinq minutes,
# pour que crt.sh reprenne la main dès qu'il répond de nouveau).
CACHE_ENTRIES = 8


def _crtsh_max_bytes() -> int:
    """Taille maximale d'une réponse crt.sh : la plus stricte des deux bornes (ce fichier et scanner.dns)."""
    return min(CRTSH_MAX_BYTES, scanner_dns.CRTSH_MAX_BYTES)


def _slim(entry: dict) -> dict:
    """Champs utiles d'une entrée crt.sh, en texte."""

    def text(key: str) -> str:
        value = entry.get(key)
        return value if isinstance(value, str) else ""

    ident = entry.get("id", entry.get("min_cert_id"))
    return {
        "id": ident if isinstance(ident, (int, str)) and not isinstance(ident, bool) else None,
        "not_before": text("not_before"),
        "not_after": text("not_after"),
        "issuer_name": text("issuer_name"),
        "common_name": text("common_name"),
        "name_value": text("name_value"),
        "logged_at": text("entry_timestamp"),
    }


@cached(scanner_dns.CT_CACHE_TTL, max_entries=CACHE_ENTRIES, scope=proxy_scope)
async def fetch_crtsh_entries(domain: str) -> list[dict]:
    """Certificats de crt.sh pour `%.domain` ; lève ModuleError si la source ne répond pas correctement.

    Client des API tierces : TLS vérifié, aucune redirection suivie (une réponse
    falsifiée n'injecte pas de faux noms). Corps borné et décompressé par morceaux.
    """
    params = {"q": f"%.{domain}", "output": "json"}
    headers = {"Accept-Encoding": ACCEPT_ENCODING}
    try:
        async with scanner_dns._api_client(timeout=CRTSH_TIMEOUT) as client:
            for attempt in range(1, CRTSH_ATTEMPTS + 1):
                async with client.stream("GET", CRTSH_URL, params=params, headers=headers) as resp:
                    status = resp.status_code
                    if status == 200:
                        body, truncated = await read_body_limited(resp, _crtsh_max_bytes())
                        if truncated:
                            raise ModuleError(msg("dns.crtsh_too_large"))
                        break
                if status not in CRTSH_TRANSIENT_STATUSES or attempt == CRTSH_ATTEMPTS:
                    raise ModuleError(msg("dns.crtsh_http", status=status))
                logger.info("crt.sh a répondu HTTP %s pour %s : nouvelle tentative", status, domain)
                await asyncio.sleep(min(CRTSH_RETRY_DELAY, scanner_dns.CRTSH_RETRY_DELAY))
    except httpx.TimeoutException as e:
        raise ModuleError(msg("dns.crtsh_timeout", seconds=f"{CRTSH_TIMEOUT:.0f}")) from e
    except (httpx.HTTPError, TargetNotAllowedError) as e:
        raise ModuleError(msg("dns.crtsh_unreachable", error=exception_text(e))) from e
    try:
        data = json.loads(body)
    except ValueError as e:
        raise ModuleError(msg("dns.crtsh_invalid_json")) from e
    if not isinstance(data, list):
        raise ModuleError(msg("dns.crtsh_unexpected"))
    return [_slim(entry) for entry in data if isinstance(entry, dict)]


def _next_after(resp: httpx.Response) -> str | None:
    """Curseur `after` de la page suivante de Cert Spotter (en-tête Link rel="next")."""
    next_url = resp.links.get("next", {}).get("url")
    if not next_url:
        return None
    values = parse_qs(urlsplit(next_url).query).get("after")
    return values[0] if values and values[0].isdigit() else None


def _issuer_text(issuance: dict) -> str:
    issuer = issuance.get("issuer")
    if isinstance(issuer, dict):
        for key in ("name", "friendly_name"):
            if isinstance(issuer.get(key), str):
                return issuer[key]
    return ""


@cached(scanner_dns.CT_FALLBACK_CACHE_TTL, max_entries=CACHE_ENTRIES, scope=proxy_scope)
async def fetch_certspotter_entries(domain: str) -> list[dict]:
    """Émissions de Cert Spotter (source de secours, partielle sans clé) ; lève ModuleError en cas d'échec."""
    params: list[tuple[str, str]] = [
        ("domain", domain),
        ("include_subdomains", "true"),
        ("expand", "dns_names"),
        ("expand", "issuer"),
    ]
    headers = {"Accept-Encoding": ACCEPT_ENCODING}
    entries: list[dict] = []
    try:
        async with scanner_dns._api_client(timeout=CERTSPOTTER_TIMEOUT) as client:
            for _ in range(CERTSPOTTER_MAX_PAGES):
                async with client.stream("GET", CERTSPOTTER_URL, params=params, headers=headers) as resp:
                    if resp.status_code == 429:
                        raise ModuleError(msg("dns.certspotter_quota"))
                    if resp.status_code != 200:
                        raise ModuleError(msg("dns.certspotter_http", status=resp.status_code))
                    body, truncated = await read_body_limited(resp, CERTSPOTTER_MAX_BYTES)
                    if truncated:
                        raise ModuleError(msg("dns.certspotter_too_large"))
                    after = _next_after(resp)
                try:
                    data = json.loads(body)
                except ValueError as e:
                    raise ModuleError(msg("dns.certspotter_invalid_json")) from e
                if not isinstance(data, list):
                    raise ModuleError(msg("dns.certspotter_unexpected"))
                for issuance in data:
                    if not isinstance(issuance, dict):
                        continue
                    names = issuance.get("dns_names")
                    names = [n for n in names if isinstance(n, str)] if isinstance(names, list) else []
                    ident = issuance.get("id")
                    entries.append(
                        {
                            "id": int(ident) if isinstance(ident, str) and ident.isdigit() else ident,
                            "not_before": str(issuance.get("not_before") or ""),
                            "not_after": str(issuance.get("not_after") or ""),
                            "issuer_name": _issuer_text(issuance),
                            "common_name": names[0] if names else "",
                            "name_value": "\n".join(names),
                            "logged_at": "",
                        }
                    )
                if not after or not data:
                    break
                params = [(k, v) for k, v in params if k != "after"] + [("after", after)]
    except httpx.TimeoutException as e:
        raise ModuleError(msg("dns.certspotter_timeout", seconds=f"{CERTSPOTTER_TIMEOUT:.0f}")) from e
    except (httpx.HTTPError, TargetNotAllowedError) as e:
        raise ModuleError(msg("dns.certspotter_unreachable", error=exception_text(e))) from e
    return entries


async def fetch_ct_entries(domain: str) -> tuple[list[dict], str, object | None]:
    """Certificats des journaux CT : crt.sh, puis Cert Spotter si crt.sh échoue.

    Renvoie (entrées, source, cause du repli : message de l'échec de crt.sh ou None).
    Lève ModuleError (avec les deux causes) si aucune source ne répond.
    """
    try:
        return await fetch_crtsh_entries(domain), SOURCE_CRTSH, None
    except ModuleError as crtsh_error:
        logger.warning("crt.sh indisponible pour %s (%s) : repli sur Cert Spotter", domain, crtsh_error)
        try:
            entries = await asyncio.wait_for(fetch_certspotter_entries(domain), timeout=CERTSPOTTER_BUDGET)
        except (asyncio.TimeoutError, TimeoutError) as e:
            second = msg("dns.certspotter_timeout", seconds=f"{CERTSPOTTER_BUDGET:.0f}")
            raise ModuleError(msg("dns.ct_both_failed", first=crtsh_error.message, second=second)) from e
        except ModuleError as e:
            raise ModuleError(msg("dns.ct_both_failed", first=crtsh_error.message, second=e.message)) from e
        return entries, SOURCE_CERTSPOTTER, crtsh_error.message
