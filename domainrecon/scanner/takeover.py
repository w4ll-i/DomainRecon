# =============================================================================
# DomainRecon - Scanner : subdomain takeover
# =============================================================================
# Un sous-domaine n'est signalé que sur une preuve :
# - l'empreinte SPÉCIFIQUE de la page d'erreur du fournisseur (un simple 404
#   ou un « Not found » générique ne suffit plus) ;
# - ou un CNAME pendant : la cible du CNAME n'existe pas (NXDOMAIN) et
#   n'appartient pas au même site que le sous-domaine.
# Le risque tient compte du fournisseur (réclamation par le nom, ou preuve de
# propriété exigée) et du type de preuve. Les fournisseurs jugés non
# exploitables par la référence can-i-take-over-xyz ne sont pas listés.
# =============================================================================

import asyncio
import re

import dns.asyncresolver
import dns.exception
import dns.resolver

from ..i18n import msg
from .common import _http_client, logger
from .errors import ModuleError, TargetNotAllowedError, exception_text
from .http_utils import fetch, same_site
from .targets import is_valid_target

# Limite de collecte (évite de saturer les services interrogés). Les
# sous-domaines sans adresse (« unresolved ») sont testés en premier.
TAKEOVER_MAX_SUBDOMAINS = 15
# Sous-domaines vérifiés en parallèle.
TAKEOVER_CONCURRENCY = 5
# Délai des requêtes DNS, en secondes.
TAKEOVER_DNS_TIMEOUT = 3.0
# Les empreintes figurent en tête de page : inutile de lire plus.
TAKEOVER_BODY_BYTES = 256 * 1024


# =============================================================================
# Module 15 : Subdomain Takeover Detection
# =============================================================================

# Clé : suffixe du service (historique). `cname` : expression régulière sur la
# cible du CNAME. `fingerprint` : expression régulière propre à la page
# « site inexistant » du fournisseur, ou None pour un service où la ressource se
# réclame par son nom (un CNAME pendant suffit). `edge` : le fournisseur exige
# une preuve de propriété du domaine (« Edge case » dans can-i-take-over-xyz),
# l'exploitation reste à vérifier.
TAKEOVER_FINGERPRINTS = {
    "github.io": {
        "service": "GitHub Pages",
        "cname": r"\.github\.io$",
        "fingerprint": r"There isn't a GitHub Pages site here",
        "edge": True,
    },
    "herokuapp.com": {
        "service": "Heroku",
        "cname": r"\.(herokuapp|herokudns|herokussl)\.com$",
        "fingerprint": r"no-such-app\.html|<title>\s*No such app\s*</title>",
        "edge": True,
    },
    "pantheonsite.io": {
        "service": "Pantheon",
        "cname": r"\.pantheonsite\.io$",
        "fingerprint": r"The gods are wise, but do not know of the site which you seek",
    },
    "ghost.io": {
        "service": "Ghost",
        "cname": r"\.ghost\.io$",
        "fingerprint": r"Failed to resolve DNS path for this host"
        r"|The thing you were looking for is no longer here, or never was",
    },
    "myshopify.com": {
        "service": "Shopify",
        "cname": r"(^|\.)myshopify\.com$",
        "fingerprint": r"Sorry, this shop is currently unavailable",
        "edge": True,
    },
    "tumblr.com": {
        "service": "Tumblr",
        "cname": r"(^|\.)domains\.tumblr\.com$",
        "fingerprint": r"Whatever you were looking for doesn't currently exist at this address",
        "edge": True,
    },
    "wordpress.com": {
        "service": "WordPress.com",
        "cname": r"\.wordpress\.com$",
        "fingerprint": r"Do you want to register [^<]*\.wordpress\.com",
    },
    "teamwork.com": {
        "service": "Teamwork",
        "cname": r"\.teamwork\.com$",
        "fingerprint": r"Oops - We didn't find your site",
    },
    "helpjuice.com": {
        "service": "Helpjuice",
        "cname": r"\.helpjuice\.com$",
        "fingerprint": r"We could not find what you're looking for",
    },
    "helpscoutdocs.com": {
        "service": "Help Scout",
        "cname": r"\.helpscoutdocs\.com$",
        "fingerprint": r"No settings were found for this company",
    },
    "s3.amazonaws.com": {
        # bucket.s3.amazonaws.com, bucket.s3-website-<région>.amazonaws.com,
        # bucket.s3.<région>.amazonaws.com…
        "service": "AWS S3",
        "cname": r"(^|\.)s3([.-][a-z0-9]+)*\.amazonaws\.com$",
        "fingerprint": r"NoSuchBucket|The specified bucket does not exist",
    },
    "surge.sh": {
        "service": "Surge.sh",
        "cname": r"(^|\.)surge\.sh$",
        "fingerprint": r"project not found",
    },
    "bitbucket.io": {
        "service": "Bitbucket",
        "cname": r"\.bitbucket\.io$",
        "fingerprint": r"Repository not found",
    },
    "smartling.com": {
        "service": "Smartling",
        "cname": r"\.smartling\.com$",
        "fingerprint": r"Domain is not configured",
        "edge": True,
    },
    "ngrok.io": {
        "service": "ngrok",
        "cname": r"(^|\.)ngrok(-free|-cname)?\.(io|app|dev|com)$",
        "fingerprint": r"Tunnel \S+ not found|ERR_NGROK_3200",
    },
    "tilda.ws": {
        "service": "Tilda",
        "cname": r"\.tilda\.ws$",
        "fingerprint": r"Please renew your subscription",
        "edge": True,
    },
    "netlify.app": {
        "service": "Netlify",
        "cname": r"\.netlify\.(app|com)$",
        "fingerprint": r"Not Found - Request ID:",
        "edge": True,
    },
    "vercel.app": {
        "service": "Vercel",
        "cname": r"\.vercel(-dns)?\.(app|com)$",
        "fingerprint": r"DEPLOYMENT_NOT_FOUND",
        "edge": True,
    },
    # Ressources réclamables par leur nom : seul le NXDOMAIN fait foi. Pas
    # d'azurestaticapps.net : Azure tire ces noms au hasard, nul ne peut les choisir.
    "azurewebsites.net": {
        "service": "Microsoft Azure",
        "cname": r"\.(azurewebsites\.net|cloudapp\.net|cloudapp\.azure\.com|trafficmanager\.net"
        r"|blob\.core\.windows\.net|azure-api\.net|azureedge\.net|azurecontainer\.io)$",
        "fingerprint": None,
    },
    "elasticbeanstalk.com": {
        "service": "AWS Elastic Beanstalk",
        "cname": r"\.elasticbeanstalk\.com$",
        "fingerprint": None,
    },
}

_COMPILED = [
    (
        key,
        info,
        re.compile(info["cname"], re.I),
        re.compile(info["fingerprint"], re.I) if info["fingerprint"] else None,
    )
    for key, info in TAKEOVER_FINGERPRINTS.items()
]


# Empreintes complémentaires encore valables d'après can-i-take-over-xyz
# (impl/takeover_extra.py) : fusionnées dans la table dès le chargement du moteur,
# pour les modules subdomain_takeover et takeover_extended.
from .impl import takeover_extra as _takeover_extra  # noqa: E402

_takeover_extra.install()


def match_service(cname: str):
    """Retourne (clé, infos, empreinte compilée) du service visé par un CNAME, ou None."""
    for key, info, cname_re, fingerprint_re in _COMPILED:
        if cname_re.search(cname):
            return key, info, fingerprint_re
    return None


# --- Résolution DNS (fonctions isolées pour pouvoir être simulées en test) ---


def _make_resolver() -> dns.asyncresolver.Resolver:
    resolver = dns.asyncresolver.Resolver()
    resolver.timeout = TAKEOVER_DNS_TIMEOUT
    resolver.lifetime = TAKEOVER_DNS_TIMEOUT
    return resolver


async def _resolve_cname(resolver, name: str) -> str | None:
    """Cible du CNAME de `name`, ou None s'il n'en a pas.

    Les erreurs non concluantes (délai, SERVFAIL) sont levées.
    """
    try:
        answer = await resolver.resolve(name, "CNAME")
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
        return None
    return str(answer[0].target).rstrip(".").lower()


async def _cname_target_state(resolver, name: str) -> str:
    """État de la cible d'un CNAME : "exists", "nxdomain" ou "unknown"."""
    try:
        await resolver.resolve(name, "A")
    except dns.resolver.NXDOMAIN:
        return "nxdomain"
    except dns.resolver.NoAnswer:
        return "exists"
    except dns.exception.DNSException:
        return "unknown"
    return "exists"


async def _fingerprint_check(client, sub: str, fingerprint_re) -> tuple[bool, bool, int | None]:
    """Cherche l'empreinte en HTTPS puis en HTTP.

    Retourne (empreinte trouvée, le service a répondu, statut HTTP).
    Lève TargetNotAllowedError si la politique de cibles refuse l'hôte.
    """
    responded, status = False, None
    for scheme in ("https", "http"):
        try:
            page = await fetch(client, f"{scheme}://{sub}", site=sub, max_bytes=TAKEOVER_BODY_BYTES)
        except TargetNotAllowedError:
            raise
        except Exception as e:
            logger.debug("Takeover : %s://%s injoignable: %s", scheme, sub, e)
            continue
        responded, status = True, page.status_code
        if fingerprint_re.search(page.text):
            return True, True, status
    return False, responded, status


def _entry(sub, cname, key, info, **fields) -> dict:
    entry = {
        "subdomain": sub,
        "cname": cname,
        "service": key,
        "provider": info["service"] if info else None,
        "risk": "low",
        "confirmed": False,
        "fingerprint_matched": False,
        "cname_nxdomain": False,
        "status_code": None,
        "evidence": "",
    }
    entry.update(fields)
    return entry


async def _check_one(sub: str, client, resolver) -> dict | None:
    """Évalue un sous-domaine. Lève dns.exception.DNSException si son CNAME n'a pu être lu."""
    cname = await _resolve_cname(resolver, sub)
    if not cname:
        return None

    matched = match_service(cname)
    key, info, fingerprint_re = matched if matched else (None, None, None)
    target_state = await _cname_target_state(resolver, cname)

    if target_state == "nxdomain":
        if info and fingerprint_re is None:
            return _entry(
                sub,
                cname,
                key,
                info,
                risk="high",
                confirmed=True,
                cname_nxdomain=True,
                evidence=msg("takeover.claimable", service=info["service"]),
            )
        if not info and same_site(cname, sub):
            # Cible dans le même site que le sous-domaine : enregistrement DNS
            # obsolète, qu'aucun tiers ne peut réclamer.
            logger.debug("Takeover : %s -> %s (NXDOMAIN) dans le même site, ignoré", sub, cname)
            return None
        return _entry(
            sub,
            cname,
            key,
            info,
            risk="medium",
            cname_nxdomain=True,
            evidence=msg("takeover.dangling", cname=cname),
        )

    if fingerprint_re is None:
        # Service inconnu, ou service « NXDOMAIN » dont la cible existe : rien à signaler.
        return None

    try:
        found, responded, status = await _fingerprint_check(client, sub, fingerprint_re)
    except TargetNotAllowedError as e:
        logger.debug("Takeover : %s ignoré par la politique de cibles: %s", sub, e)
        return None

    if found:
        edge = bool(info.get("edge"))
        service = info["service"]
        evidence = (
            msg("takeover.fingerprint_edge", service=service)
            if edge
            else msg("takeover.fingerprint", service=service)
        )
        return _entry(
            sub,
            cname,
            key,
            info,
            risk="medium" if edge else "high",
            confirmed=not edge,
            fingerprint_matched=True,
            status_code=status,
            evidence=evidence,
        )
    if not responded:
        return _entry(
            sub,
            cname,
            key,
            info,
            risk="low",
            evidence=msg("takeover.no_response", service=info["service"]),
        )
    return None


def takeover_candidates(subdomains: list) -> list[str]:
    """Sous-domaines que check_subdomain_takeover teste, dans l'ordre.

    Noms valides et sans doublon, au plus TAKEOVER_MAX_SUBDOMAINS. Les
    sous-domaines sans adresse (`resolution` « unresolved », signe classique
    d'un CNAME pendant) passent en tête ; les autres gardent l'ordre de
    priorité de find_subdomains.
    """
    unresolved: dict[str, bool] = {}
    for sub_info in subdomains or []:
        sub_info = sub_info or {}
        sub = str(sub_info.get("subdomain", "")).strip().lower().rstrip(".")
        if sub and sub not in unresolved and is_valid_target(sub):
            unresolved[sub] = sub_info.get("resolution") == "unresolved"
    # Tri stable : l'ordre d'origine est conservé dans chaque groupe.
    names = sorted(unresolved, key=lambda name: not unresolved[name])
    return names[:TAKEOVER_MAX_SUBDOMAINS]


async def check_subdomain_takeover(subdomains: list) -> list:
    """Vérifie si des sous-domaines sont exposés au takeover via leur CNAME.

    Seuls les noms de `takeover_candidates()` sont testés. Lève ModuleError
    si le CNAME n'a pu être lu pour la majorité d'entre eux (résolveur
    injoignable) et qu'aucun takeover n'a été trouvé : un test aussi partiel
    ne doit pas passer pour « aucun takeover ». L'annulation (délai de
    l'orchestrateur) n'est jamais interceptée.
    """
    names = takeover_candidates(subdomains)
    if not names:
        return []

    try:
        resolver = _make_resolver()
    except dns.exception.DNSException as e:
        raise ModuleError(msg("takeover.resolver_unavailable", error=exception_text(e))) from e

    semaphore = asyncio.Semaphore(TAKEOVER_CONCURRENCY)
    dns_errors: list[object] = []

    async with _http_client(timeout=5.0) as client:

        async def guarded(sub: str) -> dict | None:
            async with semaphore:
                try:
                    return await _check_one(sub, client, resolver)
                except dns.exception.DNSException as e:
                    dns_errors.append(msg("takeover.dns_error", subdomain=sub, error=type(e).__name__))
                    logger.debug("Takeover : CNAME illisible pour %s: %s", sub, e)
                except Exception as e:
                    logger.debug("Takeover : vérification de %s échouée: %s", sub, e)
                return None

        results = await asyncio.gather(*(guarded(sub) for sub in names))

    findings = [entry for entry in results if entry]
    if not findings and len(dns_errors) * 2 > len(names):
        raise ModuleError(
            msg("takeover.dns_failed", failed=len(dns_errors), total=len(names), example=dns_errors[0])
        )
    if dns_errors:
        logger.info("Takeover : CNAME illisible pour %d sous-domaine(s) sur %d", len(dns_errors), len(names))
    return findings
