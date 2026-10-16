# =============================================================================
# DomainRecon - Module « leakix » : services exposés et fuites (LeakIX)
# =============================================================================
# Interroge LeakIX (https://leakix.net, documentation : https://leakix.net/api-documentation) :
#   GET /domain/<domaine> (ou /host/<ip> pour une cible IP) avec l'en-tête api-key.
# Format de réponse ACTUEL : {"Services": [...], "Leaks": [...]} (voir impl/leakix.py).
# L'ancienne route /api/domain/<d> et son API anonyme n'existent plus : une clé est
# désormais obligatoire (401 « Invalid API key » sans elle). L'offre gratuite donne
# 3000 requêtes, 1 par seconde, et des résultats retardés de 15 jours.
# Valeurs sensibles : les identifiants que LeakIX associe à un service ne sont jamais
# recopiés ; les résumés sont masqués (adresses e-mail, jetons, mots de passe).
# Catégorie « sensible » : exige l'autorisation de tester la cible.
# =============================================================================

import httpx

from ...i18n import msg
from .. import common
from ..cache import MEDIUM_TTL, cached
from ..errors import ModuleError
from ..impl import leakix as impl
from ..impl.leaks_commun import REQUEST_ERRORS, network_error, request, status_error
from ..keys import ApiKey, KeyTest, Probe
from ..registry import ModuleSpec, ScanContext
from ..rules import FindingInput, FindingRule, Outcome, ScoreRule, hit
from ..score import as_dict, as_int

_LABEL = "LeakIX"
_BASE = "https://leakix.net"


@cached(MEDIUM_TTL, scope=common.proxy_scope, ignore=("client", "key"))
async def _query(client: httpx.AsyncClient, key: str, kind: str, target: str) -> dict:
    """Interroge LeakIX (kind : « domain » ou « host »). Réponse vide (204, 404) : aucun événement."""
    headers = {"api-key": key, "Accept": "application/json"}
    try:
        reply = await request(client, "GET", f"{_BASE}/{kind}/{target}", headers=headers, timeout=20)
    except REQUEST_ERRORS as e:
        raise network_error(_LABEL, e) from None
    if reply.status in (401, 403):
        raise ModuleError(msg("leakix.key_rejected"))
    if reply.status in (204, 404):
        return impl.parse_response(None, target, by_domain=kind == "domain")
    if reply.status != 200:
        raise status_error(_LABEL, reply.status)
    try:
        payload = reply.json()
    except ValueError:
        raise ModuleError(msg("leakix.unreadable")) from None
    if payload is not None and not isinstance(payload, (dict, list)):
        raise ModuleError(msg("leakix.unreadable"))
    return impl.parse_response(payload, target, by_domain=kind == "domain")


async def run(context: ScanContext) -> dict:
    key = context.secrets.get("leakix_key")
    if not key:
        raise ModuleError(msg("leakix.key_missing"))
    kind = "host" if context.is_ip_target else "domain"
    target = context.domain if kind == "host" else context.apex
    data = await _query(context.http, key, kind, target)
    return {"measured": True, "error": None, "query": kind, "target": target, **data}


# -----------------------------------------------------------------------------
# Constats et score
# -----------------------------------------------------------------------------


def _check_leaks(f: FindingInput) -> object:
    data = as_dict(f.data)
    count = as_int(data.get("leak_count")) or 0
    if count <= 0:
        return None
    critical = as_int(data.get("critical_count")) or 0
    high = as_int(data.get("high_count")) or 0
    severity = "critical" if critical else "high" if high else "medium"
    return hit(severity=severity, count=count, critical=critical)


def _check_exposed(f: FindingInput) -> object:
    count = as_int(as_dict(f.data).get("noauth_count")) or 0
    return {"count": count} if count > 0 else None


def _score(data: dict) -> Outcome:
    leakix = as_dict(data.get("leakix"))
    leaks = as_int(leakix.get("leak_count")) or 0
    critical = as_int(leakix.get("critical_count")) or 0
    exposed = as_int(leakix.get("noauth_count")) or 0
    if critical:
        return Outcome(0, msg("leakix.score_leaks", count=leaks), True)
    if leaks:
        return Outcome(1, msg("leakix.score_leaks", count=leaks), True)
    if exposed:
        return Outcome(2, msg("leakix.score_exposed", count=exposed), True)
    return Outcome(5, msg("leakix.score_clean"), True)


SPEC = ModuleSpec(
    name="leakix",
    family="leaks",
    category="sensible",
    run=run,
    keys=(ApiKey(name="leakix_key", service="leakix", label="LeakIX"),),
    key_tests={
        "leakix": KeyTest(
            "LeakIX",
            ("leakix_key",),
            # Une recherche sur un hôte réservé : 200, 204 ou 404 prouvent que la clé est reconnue.
            probes=lambda s: [
                Probe(
                    f"{_BASE}/domain/example.com",
                    headers={"api-key": s["leakix_key"], "Accept": "application/json"},
                    accepted=frozenset({204, 404}),
                )
            ],
        )
    },
    wave=3,
    timeout=45,
    optional=True,
    order=310,
    findings=(
        FindingRule(code="finding.leakix.leaks", severity="medium", check=_check_leaks),
        FindingRule(code="finding.leakix.exposed", severity="high", check=_check_exposed),
    ),
    score_rules=(ScoreRule(criterion="leakix", weight=5, evaluate=_score),),
)
