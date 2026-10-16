# =============================================================================
# DomainRecon - Module « dkim » : clés DKIM des sélecteurs courants
# =============================================================================
# Complète email_security (qui ne teste que 11 sélecteurs) : une centaine de
# sélecteurs courants sont interrogés
# en parallèle, puis chaque clé trouvée est analysée : type, taille (RSA < 1024
# bits cassable, 1024 bits à renouveler), mode test (t=y), hachage SHA-1 seul,
# délégation à un fournisseur (CNAME). Les clés révoquées (p= vide) et un joker
# *._domainkey sont distingués d'une vraie clé, pour éviter les faux positifs.
# Source : DNS public (RFC 6376, RFC 8463). Limite : un sélecteur personnalisé ou
# daté n'est pas devinable ; l'absence de clé trouvée n'est donc jamais un constat.
# Logique : scanner/impl/dkim.py.
# =============================================================================

import asyncio

from ...i18n import msg
from ..dns import DnsQuerier
from ..errors import ModuleError
from ..impl import dkim as impl
from ..registry import ModuleSpec, ScanContext, skip_for_ip_target
from ..rules import FindingInput, FindingRule, hit
from ..score import as_dict, as_list


async def run(context: ScanContext) -> dict:
    querier = DnsQuerier(impl.QUERY_TIMEOUT, impl.DNS_BUDGET)
    result = await asyncio.to_thread(impl.scan, querier, context.apex)
    if not result["measured"]:
        # Tous les sélecteurs en échec : résolveur indisponible, rien à conclure.
        raise ModuleError(msg("dkim.query_failed", count=result["selectors_failed"]))
    return result


def skip_reason(context: ScanContext) -> object | None:
    if context.shared_platform:
        return msg("orchestrator.skip_shared_platform")
    return skip_for_ip_target(context)


def _keys(f: FindingInput) -> list[dict]:
    return [key for key in as_list(as_dict(f.data).get("keys")) if isinstance(key, dict)]


def _check_weak_key(f: FindingInput) -> list:
    broken = []
    short = []
    for key in _keys(f):
        bits = impl.weak_rsa_bits(key)
        if bits is None:
            continue
        (broken if bits < 1024 else short).append((key.get("selector"), bits))
    hits = []
    if broken:
        hits.append(hit(severity="high", selectors=[s for s, _ in broken], bits=min(b for _, b in broken)))
    if short:
        hits.append(hit(severity="low", selectors=[s for s, _ in short], bits=1024))
    return hits


def _check_testing(f: FindingInput) -> dict | None:
    selectors = [k.get("selector") for k in _keys(f) if k.get("testing") is True]
    return {"selectors": selectors} if selectors else None


def _check_sha1_only(f: FindingInput) -> dict | None:
    selectors = [k.get("selector") for k in _keys(f) if as_list(k.get("hash_algorithms")) == ["sha1"]]
    return {"selectors": selectors} if selectors else None


def _check_unreadable(f: FindingInput) -> dict | None:
    selectors = [k.get("selector") for k in _keys(f) if k.get("valid_key") is False]
    return {"selectors": selectors} if selectors else None


SPEC = ModuleSpec(
    name="dkim",
    family="email",
    category="passif",
    run=run,
    skip_reason=skip_reason,
    wave=1,
    timeout=60,
    optional=True,
    order=91,
    findings=(
        FindingRule(code="finding.dkim.weak_key", severity="high", check=_check_weak_key),
        FindingRule(code="finding.dkim.testing_mode", severity="low", check=_check_testing),
        FindingRule(code="finding.dkim.sha1_only", severity="low", check=_check_sha1_only),
        FindingRule(code="finding.dkim.key_unreadable", severity="low", check=_check_unreadable),
    ),
)
