# =============================================================================
# DomainRecon - Module « emailrep » : réputation des adresses publiées par le site
# =============================================================================
# Cherche les adresses e-mail du domaine publiées sur le site (page d'accueil, /contact,
# /.well-known/security.txt), puis demande à EmailRep (https://emailrep.io) leur réputation :
# fuite d'identifiants, brèche de données, activité malveillante, liste noire.
# Une clé est OBLIGATOIRE : l'API anonyme est coupée (HTTP 429). Offre gratuite : 10
# requêtes par jour ; on n'interroge donc que 5 adresses au plus, et les réponses sont
# gardées 24 h (le quota est journalier).
# Données personnelles (RGPD) : seules les adresses du domaine analysé sont interrogées ;
# elles ne sont jamais enregistrées en clair (« j***@domaine »), seuls des indicateurs le sont.
# Catégorie « sensible » : exige l'autorisation de tester la cible (cadre légal).
# =============================================================================

import asyncio
from urllib.parse import quote

import httpx

from ...i18n import msg
from .. import common, http_utils
from ..cache import LONG_TTL, cached
from ..errors import ModuleError, ModuleSkipped
from ..impl import emailrep as impl
from ..impl.leaks_commun import REQUEST_ERRORS, network_error, request, status_error
from ..keys import ApiKey, KeyTest, Probe
from ..registry import ModuleSpec, ScanContext, skip_for_ip_target
from ..rules import FindingInput, FindingRule, Outcome, ScoreRule
from ..score import as_dict, as_int

_LABEL = "EmailRep"
_API = "https://emailrep.io"
# Pages où un site publie ses adresses (la page d'accueil est partagée par tout le scan).
_PAGES = ("/contact", "/.well-known/security.txt")
# Durée maximale accordée à la lecture de ces pages, en secondes.
_PAGES_TIMEOUT = 20


@cached(LONG_TTL, scope=common.proxy_scope, ignore=("client", "key"))
async def _lookup(client: httpx.AsyncClient, key: str, address: str) -> dict:
    """Réputation d'une adresse. {measured: False, state} (non gardé en cache) en cas de quota ou d'adresse refusée."""
    headers = {"Key": key, "Accept": "application/json"}
    try:
        reply = await request(
            client, "GET", f"{_API}/{quote(address, safe='@')}", headers=headers, timeout=15
        )
    except REQUEST_ERRORS as e:
        raise network_error(_LABEL, e) from None
    if reply.status in (401, 403):
        raise ModuleError(msg("emailrep.key_rejected"))
    if reply.status == 429:
        return {"measured": False, "error": None, "state": "quota"}
    if reply.status == 400:
        return {"measured": False, "error": None, "state": "invalid"}
    if reply.status != 200:
        raise status_error(_LABEL, reply.status)
    try:
        payload = reply.json()
    except ValueError:
        raise ModuleError(msg("emailrep.unreadable")) from None
    if not isinstance(payload, dict):
        raise ModuleError(msg("emailrep.unreadable"))
    return {"measured": True, "error": None, "state": "ok", "report": impl.parse_report(payload)}


async def _extra_pages(context: ScanContext) -> list[str]:
    """Adresses des pages usuelles de contact (une page absente ou illisible est simplement ignorée)."""
    emails: list[str] = []
    async with common._http_client(timeout=8) as client:
        for path in _PAGES:
            fetched, _ = await http_utils.fetch_first(client, context.domain, path)
            if fetched is not None and fetched.response.status_code == 200:
                text = http_utils.decode_body(fetched.response, fetched.body)
                emails.extend(a for a in impl.extract_emails(text, context.apex) if a not in emails)
    return emails


async def _published_emails(context: ScanContext) -> list[str]:
    """Adresses du domaine publiées sur le site (page d'accueil, puis pages usuelles si le site répond)."""
    home = await context.homepage()
    emails = impl.extract_emails(home.text, context.apex)
    if home.reachable and len(emails) < impl.MAX_EMAILS:
        try:
            more = await asyncio.wait_for(_extra_pages(context), timeout=_PAGES_TIMEOUT)
        except asyncio.TimeoutError:
            more = []
        emails.extend(a for a in more if a not in emails)
    return emails


async def run(context: ScanContext) -> dict:
    key = context.secrets.get("emailrep_key")
    if not key:
        raise ModuleError(msg("emailrep.key_missing"))
    found = await _published_emails(context)
    if not found:
        raise ModuleSkipped(msg("emailrep.no_address"))
    entries: list[dict] = []
    quota = False
    for address in found[: impl.MAX_EMAILS]:
        outcome = await _lookup(context.http, key, address)
        if outcome["state"] == "quota":
            quota = True
            break
        if outcome["state"] == "ok":
            entries.append(impl.entry(address, outcome["report"]))
    if quota and not entries:
        raise ModuleError(msg("network.quota", service=_LABEL))
    return {
        "measured": True,
        "error": None,
        "emails_found": len(found),
        "emails_checked": len(entries),
        "quota_reached": quota,
        "results": entries,
        **impl.summarize(entries),
    }


# -----------------------------------------------------------------------------
# Constats et score
# -----------------------------------------------------------------------------


def _count(f: FindingInput, field: str) -> dict | None:
    count = as_int(as_dict(f.data).get(field)) or 0
    return {"count": count} if count > 0 else None


def _check_leaked(f: FindingInput) -> object:
    return _count(f, "leaked_count")


def _check_breached(f: FindingInput) -> object:
    return _count(f, "breached_count")


def _check_malicious(f: FindingInput) -> object:
    return _count(f, "malicious_count")


def _score(data: dict) -> Outcome:
    mail = as_dict(data.get("emailrep"))
    leaked = as_int(mail.get("leaked_count")) or 0
    malicious = as_int(mail.get("malicious_count")) or 0
    breached = as_int(mail.get("breached_count")) or 0
    if leaked:
        return Outcome(0, msg("emailrep.score_leaked", count=leaked), True)
    if malicious:
        return Outcome(1, msg("emailrep.score_malicious", count=malicious), True)
    if breached:
        return Outcome(2, msg("emailrep.score_breached", count=breached), True)
    return Outcome(3, msg("emailrep.score_clean"), True)


SPEC = ModuleSpec(
    name="emailrep",
    family="leaks",
    category="sensible",
    run=run,
    keys=(ApiKey(name="emailrep_key", service="emailrep", label="EmailRep"),),
    key_tests={
        "emailrep": KeyTest(
            "EmailRep",
            ("emailrep_key",),
            # Aucune route gratuite : une consultation (1 requête du quota journalier) d'une adresse réservée.
            probes=lambda s: [
                Probe(
                    f"{_API}/test@example.com",
                    headers={"Key": s["emailrep_key"], "Accept": "application/json"},
                )
            ],
        )
    },
    wave=3,
    timeout=90,
    skip_reason=skip_for_ip_target,
    optional=True,
    order=350,
    findings=(
        FindingRule(code="finding.emailrep.leaked", severity="high", check=_check_leaked),
        FindingRule(code="finding.emailrep.malicious", severity="medium", check=_check_malicious),
        FindingRule(code="finding.emailrep.breached", severity="medium", check=_check_breached),
    ),
    score_rules=(ScoreRule(criterion="emailrep", weight=3, evaluate=_score),),
)
