# =============================================================================
# DomainRecon - Censys Platform API v3 : fiche d'un hôte
# =============================================================================
# L'API « Legacy Search » (search.censys.io/api/v2, identifiant + secret en Basic)
# est éteinte depuis le 30 septembre 2026 (HTTP 403 « decommissioned »). Ce module
# utilise la Censys Platform :
#   GET https://api.platform.censys.io/v3/global/asset/host/{ip}
#   Authorization: Bearer <jeton d'accès personnel (PAT)>
#   X-Organization-ID: <identifiant d'organisation>   (facultatif)
# Documentation : https://docs.censys.com/reference/get-started
# Un compte gratuit a 100 crédits par mois et accède aux consultations d'hôte
# (1 crédit chacune) ; la recherche et l'agrégation exigent une offre payante :
# le module ne fait donc qu'UNE consultation par scan. Le jeton est le « secret »
# (censys_secret) des Réglages, l'organisation l'« identifiant » (censys_id).
# =============================================================================

import re

import httpx

from ...i18n import msg
from ..errors import ModuleError
from . import network_http as nh

clean_text = nh.clean_text
HOST_URL = "https://api.platform.censys.io/v3/global/asset/host/{ip}"
SERVICE = "Censys"
MAX_SERVICES = 60
MAX_CERTS = 10
MAX_LABELS = 20

_ORG_RE = re.compile(r"[A-Za-z0-9._-]{1,64}")


def headers(token: str, organization: str | None) -> dict[str, str]:
    """En-têtes d'authentification (le jeton ne quitte jamais cet en-tête)."""
    result = {"Authorization": f"Bearer {token}", "Accept": "application/json"}
    if organization and _ORG_RE.fullmatch(organization.strip()):
        result["X-Organization-ID"] = organization.strip()
    return result


def _resource(body: object) -> dict | None:
    """Objet hôte de la réponse (`result.resource`, ou `result` seul selon la version de l'API)."""
    if not isinstance(body, dict):
        return None
    result = body.get("result", body)
    if isinstance(result, dict):
        resource = result.get("resource")
        return resource if isinstance(resource, dict) else result
    return None


def _labels(value: object) -> list[str]:
    labels = []
    for item in value if isinstance(value, list) else []:
        name = item.get("value") or item.get("name") if isinstance(item, dict) else item
        if isinstance(name, str) and name and name not in labels:
            labels.append(clean_text(name, 60))
    return labels[:MAX_LABELS]


def normalize(body: object, ip: str) -> dict | None:
    """Fiche d'hôte réduite aux champs utiles ; None si la réponse n'a pas la forme attendue."""
    host = _resource(body)
    if host is None or not (host.get("services") is None or isinstance(host.get("services"), list)):
        return None
    system = host.get("autonomous_system") if isinstance(host.get("autonomous_system"), dict) else {}
    location = host.get("location") if isinstance(host.get("location"), dict) else {}
    entries = [s for s in host.get("services") or [] if isinstance(s, dict)]
    services = []
    certificates: list[str] = []
    labels = _labels(host.get("labels"))
    for entry in entries[:MAX_SERVICES]:
        software = [s for s in entry.get("software") or [] if isinstance(s, dict)]
        first = software[0] if software else {}
        port = entry.get("port")
        services.append(
            {
                "port": port if isinstance(port, int) and not isinstance(port, bool) else None,
                "name": clean_text(entry.get("protocol") or entry.get("service_name"), 40),
                "transport": clean_text(entry.get("transport_protocol"), 8),
                "product": clean_text(first.get("product"), 80),
                "version": clean_text(first.get("version"), 60),
            }
        )
        cert = entry.get("cert")
        fingerprint = cert.get("fingerprint_sha256") if isinstance(cert, dict) else None
        if isinstance(fingerprint, str) and fingerprint not in certificates and len(certificates) < MAX_CERTS:
            certificates.append(clean_text(fingerprint, 80))
        for label in _labels(entry.get("labels")):
            if label not in labels and len(labels) < MAX_LABELS:
                labels.append(label)
    dns_info = host.get("dns") if isinstance(host.get("dns"), dict) else {}
    reverse = dns_info.get("reverse_dns") if isinstance(dns_info.get("reverse_dns"), dict) else {}
    asn = system.get("asn")
    return {
        "ip": str(host.get("ip") or ip),
        "asn": f"AS{asn}" if isinstance(asn, int) and not isinstance(asn, bool) else None,
        "as_name": clean_text(system.get("name") or system.get("description"), 120) or None,
        "bgp_prefix": clean_text(system.get("bgp_prefix"), 50) or None,
        "country": clean_text(location.get("country_code") or location.get("country"), 60) or None,
        "city": clean_text(location.get("city"), 60) or None,
        "services": services,
        "services_total": len(entries),
        "ports": sorted({s["port"] for s in services if s["port"] is not None}),
        "labels": labels,
        "certificates": certificates,
        "reverse_dns": [
            clean_text(n, 200) for n in (reverse.get("names") or [])[:10] if isinstance(n, str) and n
        ],
        "last_updated": clean_text(host.get("last_updated_at") or host.get("last_updated"), 40) or None,
    }


async def host(
    client: httpx.AsyncClient | None, ip: str, token: str, organization: str | None = None
) -> dict | None:
    """Fiche Censys de l'adresse, ou None si Censys ne la connaît pas.

    Lève ModuleError : jeton refusé (401), accès ou crédits refusés (403, 402), quota (429),
    autre code HTTP, réseau, réponse illisible. Le jeton n'apparaît dans aucun message.
    """
    async with nh.use_client(client, timeout=20) as http:
        response = await nh.get(
            http, HOST_URL.format(ip=ip), service=SERVICE, headers=headers(token, organization)
        )
    if response.status_code == 404:
        return None
    if response.status_code == 401:
        raise ModuleError(msg("censys.key_rejected"))
    if response.status_code != 200:
        raise nh.status_error(SERVICE, response.status_code)
    result = normalize(nh.parse_json(response), ip)
    if result is None:
        raise ModuleError(msg("censys.unreadable"))
    return result
