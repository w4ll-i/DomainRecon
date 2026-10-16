# =============================================================================
# DomainRecon - Module « hibp » : brèches de données publiques du domaine
# =============================================================================
# Interroge Have I Been Pwned (https://haveibeenpwned.com/API/v3) :
#   - SANS clé : le catalogue public des brèches (/breaches?Domain=…) dont le site
#     est le domaine analysé (le service lui-même a été piraté) ;
#   - AVEC la clé facultative (hibp_key, offre payante) : en plus, les comptes du
#     domaine retrouvés dans des brèches (/breacheddomain/…), à condition que le
#     domaine soit vérifié dans le tableau de bord du compte (403 sinon, signalé
#     sans faire échouer le module).
# Valeurs sensibles : les adresses ne sont jamais enregistrées en clair (alias
# masqué « j***@domaine ») ; seuls des totaux et des noms de brèches publics sont gardés.
# Le catalogue complet (plusieurs Mo) n'est pas téléchargé à chaque scan : le filtre
# ?Domain= du service le fait côté serveur,
# et le résultat est gardé 24 h.
# Catégorie « sensible » : exige l'autorisation de tester la cible.
# =============================================================================

import httpx

from ...i18n import msg
from .. import common
from ..cache import LONG_TTL, cached
from ..errors import ModuleError
from ..impl import hibp as impl
from ..impl.leaks_commun import REQUEST_ERRORS, network_error, request, status_error
from ..keys import ApiKey, KeyTest, Probe
from ..registry import ModuleSpec, ScanContext, skip_for_ip_target
from ..rules import FindingInput, FindingRule, Outcome, ScoreRule, hit
from ..score import as_dict, as_int, as_list

_LABEL = "HIBP"
_API = "https://haveibeenpwned.com/api/v3"


# -----------------------------------------------------------------------------
# Exécution
# -----------------------------------------------------------------------------


@cached(LONG_TTL, scope=common.proxy_scope, ignore=("client",))
async def _catalog(client: httpx.AsyncClient, domain: str) -> list[dict]:
    """Brèches publiques du domaine (catalogue gratuit, gardé 24 h ; seule une réponse valide est gardée)."""
    try:
        reply = await request(client, "GET", f"{_API}/breaches", params={"Domain": domain}, timeout=15)
    except REQUEST_ERRORS as e:
        raise network_error(_LABEL, e) from None
    if reply.status != 200:
        raise status_error(_LABEL, reply.status)
    try:
        payload = reply.json()
    except ValueError:
        raise ModuleError(msg("hibp.unreadable")) from None
    if not isinstance(payload, list):
        raise ModuleError(msg("hibp.unreadable"))
    return impl.parse_catalog(payload, {domain})


async def _domain_accounts(client: httpx.AsyncClient, domain: str, key: str) -> dict:
    """Comptes du domaine (clé payante). Un refus ou un quota est un état, pas un échec du module."""
    try:
        reply = await request(
            client, "GET", f"{_API}/breacheddomain/{domain}", headers={"hibp-api-key": key}, timeout=20
        )
    except REQUEST_ERRORS:
        return {"domain_search": "error"}
    if reply.status == 404:
        return {"domain_search": "ok", "accounts": 0, "accounts_breaches": [], "accounts_sample": []}
    if reply.status == 200:
        try:
            return {"domain_search": "ok", **impl.parse_domain_accounts(reply.json(), domain)}
        except ValueError:
            return {"domain_search": "error"}
    states = {401: "rejected", 403: "not_verified", 429: "quota"}
    return {"domain_search": states.get(reply.status, "error")}


async def run(context: ScanContext) -> dict:
    client = context.http
    domains = list(dict.fromkeys(d.removeprefix("www.") for d in (context.apex, context.domain)))
    breaches: list[dict] = []
    seen: set[str] = set()
    for domain in domains:
        for breach in await _catalog(client, domain):
            if breach["name"] not in seen:
                seen.add(breach["name"])
                breaches.append(breach)
    result = {
        "measured": True,
        "error": None,
        "source": "catalog",
        "domains_checked": domains,
        "breaches": breaches,
        **impl.summarize(breaches),
        "domain_search": "not_requested",
        "accounts": None,
    }
    key = context.secrets.get("hibp_key")
    if key:
        result.update(await _domain_accounts(client, context.apex, key))
        if result["domain_search"] == "ok":
            result["source"] = "catalog+key"
    return result


# -----------------------------------------------------------------------------
# Constats et score
# -----------------------------------------------------------------------------


def _check_breaches(f: FindingInput) -> object:
    data = as_dict(f.data)
    breaches = [as_dict(b) for b in as_list(data.get("breaches"))]
    if not breaches:
        return None
    names = ", ".join(str(b.get("name")) for b in breaches[:3] if b.get("name"))
    grave = data.get("passwords_exposed") is True or (as_int(data.get("sensitive_count")) or 0) > 0
    return hit(severity="high" if grave else "medium", count=len(breaches), names=names or "-")


def _check_accounts(f: FindingInput) -> object:
    data = as_dict(f.data)
    accounts = as_int(data.get("accounts")) or 0
    if accounts <= 0:
        return None
    return {"count": accounts, "breaches": len(as_list(data.get("accounts_breaches")))}


def _score(data: dict) -> Outcome:
    hibp = as_dict(data.get("hibp"))
    accounts = as_int(hibp.get("accounts")) or 0
    breaches = len(as_list(hibp.get("breaches")))
    if accounts > 0:
        return Outcome(0, msg("hibp.score_accounts", count=accounts), True)
    if breaches == 0:
        return Outcome(5, msg("hibp.score_clean"), True)
    points = 0 if hibp.get("passwords_exposed") is True else 2
    return Outcome(points, msg("hibp.score_breaches", count=breaches), True)


SPEC = ModuleSpec(
    name="hibp",
    family="leaks",
    category="sensible",
    run=run,
    keys=(ApiKey(name="hibp_key", service="haveibeenpwned", label="Have I Been Pwned", required=False),),
    key_tests={
        "haveibeenpwned": KeyTest(
            "Have I Been Pwned",
            ("hibp_key",),
            # Statut de l'abonnement : ne consomme aucune requête de recherche.
            probes=lambda s: [Probe(f"{_API}/subscription/status", headers={"hibp-api-key": s["hibp_key"]})],
        )
    },
    wave=3,
    timeout=45,
    skip_reason=skip_for_ip_target,
    optional=True,
    order=300,
    findings=(
        FindingRule(code="finding.hibp.breaches", severity="medium", check=_check_breaches),
        FindingRule(code="finding.hibp.accounts", severity="high", check=_check_accounts),
    ),
    score_rules=(ScoreRule(criterion="hibp", weight=5, evaluate=_score),),
)
