# =============================================================================
# DomainRecon - Scanner : détection de WAF / CDN
# =============================================================================
# Détection passive : seules des preuves propres à un WAF (en-têtes, cookies)
# concluent à un WAF. Les en-têtes d'infrastructure (CDN, cache, équilibreur
# de charge) sont rapportés à part, dans `cdn_*` : ils ne prouvent aucune
# protection applicative. Ainsi `server: cloudflare` et `cf-ray`, présents sur
# toute réponse du proxy Cloudflare, désignent le CDN, pas un WAF.
# =============================================================================

import re

from ..i18n import msg, render
from .common import _http_client, logger
from .http_utils import fetch_first

# =============================================================================
# Module 10 : WAF Detection
# =============================================================================

# Signatures de WAF. `headers` : {en-tête: sous-chaîne attendue ("" = présence)} ;
# `cookies` : expressions régulières sur le nom des cookies posés ;
# `max_confidence` (facultatif) : confiance maximale, quelles que soient les preuves.
WAF_SIGNATURES = {
    # cf-mitigated marque une page de challenge ; __cf_bm (Bot Management) et
    # cf_clearance (challenge réussi) relèvent de la protection, mais pas
    # forcément des règles WAF : confiance moyenne au plus.
    "Cloudflare": {
        "headers": {"cf-mitigated": ""},
        "cookies": [r"^__cf_bm$", r"^cf_clearance$"],
        "max_confidence": "medium",
    },
    "AWS WAF": {
        "headers": {"x-amzn-waf-action": ""},
        "cookies": [r"^aws-waf-token$"],
    },
    "Akamai Bot Manager": {
        "headers": {},
        "cookies": [r"^ak_bmsc$", r"^bm_sz$", r"^_abck$"],
    },
    "Sucuri": {
        "headers": {"server": "sucuri", "x-sucuri-id": "", "x-sucuri-cache": ""},
        "cookies": [r"^sucuri_cloudproxy"],
    },
    "Imperva/Incapsula": {
        "headers": {"x-cdn": "incapsula", "x-iinfo": ""},
        "cookies": [r"^incap_ses_", r"^visid_incap_"],
    },
    "F5 BIG-IP ASM": {
        "headers": {},
        "cookies": [r"^ts[0-9a-f]{6,8}(_[0-9a-z]+)?$", r"^f5_cspm$"],
    },
    "Barracuda": {
        "headers": {"server": "barracuda"},
        "cookies": [r"^barra_counter_session$", r"^bni__barracuda_lb_cookie$"],
    },
    "ModSecurity": {
        "headers": {"server": "mod_security"},
        "cookies": [],
    },
    "DDoS-Guard": {
        "headers": {"server": "ddos-guard"},
        "cookies": [r"^__ddg"],
    },
    # Signatures complémentaires, limitées aux preuves passives (en-têtes, cookies). Leur
    # détection par page de blocage exigerait une requête provoquant le blocage.
    "Fortinet FortiWeb": {
        "headers": {"server": "fortiweb"},
        "cookies": [r"^fortiwafsid$"],
    },
    "Palo Alto Networks": {
        "headers": {"x-pan-rematch": ""},
        "cookies": [],
    },
    "Citrix NetScaler AppFirewall": {
        "headers": {"via": "ns-cache", "cneonction": ""},
        "cookies": [r"^citrix_ns_id", r"^ns_af$", r"^nsc_"],
    },
    "Wallarm": {
        "headers": {"server": "nginx-wallarm"},
        "cookies": [],
    },
    "Reblaze": {
        "headers": {"server": "reblaze"},
        "cookies": [r"^rbzid$", r"^rbzsessionid$"],
    },
    "Alibaba Cloud WAF": {
        "headers": {},
        "cookies": [r"^aliyungf_tc$"],
    },
    "Wordfence": {
        "headers": {},
        "cookies": [r"^wfwaf-authcookie-"],
    },
}

# CDN, caches et équilibreurs : rapportés, mais ce ne sont pas des WAF.
CDN_SIGNATURES = {
    "Cloudflare": {"server": "cloudflare", "cf-ray": "", "cf-cache-status": ""},
    "Amazon CloudFront": {"x-amz-cf-id": "", "x-amz-cf-pop": "", "via": "cloudfront"},
    "Fastly": {"x-fastly-request-id": "", "x-served-by": "cache-"},
    "Akamai": {"server": "akamaighost", "x-akamai-transformed": "", "akamai-grn": ""},
    "Azure Front Door": {"x-azure-ref": ""},
    "Google Cloud (Google Frontend)": {"via": "google", "server": "google frontend"},
    "Varnish": {"x-varnish": "", "via": "varnish"},
    "F5 BIG-IP": {"server": "big-ip", "x-wa-info": ""},
}

_GENERIC_WAF_HEADERS = ("x-waf-event", "x-waf-status", "x-firewall")

# Niveaux de confiance, du plus faible au plus fort.
_CONFIDENCE_LEVELS = ("low", "medium", "high")


def _header_evidence(headers: dict[str, list[str]], sigs: dict[str, str]) -> list[str]:
    evidence = []
    for key, expected in sigs.items():
        values = headers.get(key, [])
        if any(not expected or expected in value for value in values):
            evidence.append(f"Header: {key}")
    return evidence


def analyze_waf_responses(responses) -> dict:
    """Analyse les en-têtes et cookies de réponses déjà obtenues (sans réseau).

    `waf_name` est le nom du produit (texte), ou le message `waf.unknown` pour un WAF générique.
    """
    # Valeurs de chaque en-tête sur toute la chaîne (redirections comprises).
    headers: dict[str, list[str]] = {}
    cookie_names: list[str] = []
    for response in responses:
        for key, value in response.headers.multi_items():
            headers.setdefault(key.lower(), []).append(value.lower())
        for raw in response.headers.get_list("set-cookie"):
            name = raw.split(";", 1)[0].split("=", 1)[0].strip().lower()
            if name and name not in cookie_names:
                cookie_names.append(name)

    result = {
        "detected": False,
        "waf_name": None,
        "confidence": "none",
        "evidence": [],
        "cdn_detected": False,
        "cdn_name": None,
        "cdn_evidence": [],
    }

    for cdn_name, sigs in CDN_SIGNATURES.items():
        evidence = _header_evidence(headers, sigs)
        if evidence:
            result.update(cdn_detected=True, cdn_name=cdn_name, cdn_evidence=evidence)
            break

    for waf_name, sigs in WAF_SIGNATURES.items():
        evidence = _header_evidence(headers, sigs["headers"])
        for pattern in sigs["cookies"]:
            evidence.extend(f"Cookie: {name}" for name in cookie_names if re.search(pattern, name))
        if evidence:
            confidence = "high" if len(evidence) >= 2 else "medium"
            cap = sigs.get("max_confidence", "high")
            result.update(
                detected=True,
                waf_name=waf_name,
                evidence=evidence,
                confidence=min(confidence, cap, key=_CONFIDENCE_LEVELS.index),
            )
            return result

    for header in _GENERIC_WAF_HEADERS:
        if header in headers:
            result.update(
                detected=True,
                waf_name=msg("waf.unknown"),
                evidence=[f"Header: {header}"],
                confidence="low",
            )
            return result

    return result


async def detect_waf(domain: str) -> dict:
    """Détecte la présence d'un WAF, et à part celle d'un CDN.

    Seules les réponses du site ciblé sont analysées : une redirection vers un
    autre site n'est pas suivie (`off_site_redirect`).
    """
    async with _http_client(timeout=10.0) as client:
        fetched, error = await fetch_first(client, domain, max_bytes=0)

    if fetched is None:
        logger.debug("Détection WAF impossible sur %s: %s", domain, render(error, "fr"))
        result = analyze_waf_responses([])
        result.update(measured=False, error=error, url=None, off_site_redirect=None)
        return result

    result = analyze_waf_responses(fetched.responses)
    result.update(measured=True, error=None, url=fetched.url, off_site_redirect=fetched.off_site_url)
    return result
