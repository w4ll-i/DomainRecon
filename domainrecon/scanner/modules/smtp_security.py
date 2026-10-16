# =============================================================================
# DomainRecon - Module « smtp_security » : sonde SMTP des serveurs MX (actif)
# =============================================================================
# Se connecte aux (au plus trois) serveurs MX du domaine, port 25 : bannière et logiciel,
# extensions EHLO, STARTTLS (version TLS, certificat vérifié contre le nom du MX),
# méthodes AUTH annoncées en clair, domaine « catch-all » (deux adresses aléatoires).
# Le test de relais ouvert reste OPTIONNEL et DÉSACTIVÉ par défaut : il s'active avec la
# variable d'environnement DOMAINRECON_SMTP_RELAY_TEST=1 (voir impl/smtp_security.py).
# Source : RFC 5321 (SMTP), RFC 3207 (STARTTLS), RFC 8314. Aucun message n'est jamais envoyé
# (pas de commande DATA). Catégorie « actif » : exige l'autorisation de tester la cible.
# Limite : le port 25 sortant est souvent bloqué par les FAI, clouds et pare-feu locaux.
# Logique : scanner/impl/smtp_security.py.
# =============================================================================

import asyncio

from ...i18n import msg
from .. import targets
from ..dns import DnsQuerier
from ..errors import ModuleError, ModuleSkipped, TargetNotAllowedError
from ..impl import smtp_security as impl
from ..impl.mail_provider import lookup_mail_exchangers
from ..registry import ModuleSpec, ScanContext, skip_for_ip_target
from ..rules import FindingInput, FindingRule, Outcome, ScoreRule, hit
from ..score import as_dict, as_list

SCORE_WEIGHT = 5
QUERY_TIMEOUT = 3.0
DNS_BUDGET = 15.0
SUBMISSION_PORT = 587


async def _probe_one(entry: dict, domain: str, port: int, relay_test: bool) -> dict:
    host = entry["host"]
    try:
        addresses = await targets.resolve_addresses(host)
        address = impl.pick_address(addresses)
        if address is None:
            info = impl.empty_host(host, None, port, entry["priority"])
            return impl.fail(info, "unreachable")
        # Politique de cibles : un MX qui résout vers une adresse privée n'est jamais contacté.
        targets.ensure_ip_allowed(address)
    except TargetNotAllowedError:
        return impl.fail(impl.empty_host(host, None, port, entry["priority"]), "blocked")
    return await asyncio.to_thread(
        impl.probe_host, host, address, port, domain, entry["priority"], probes=True, relay_test=relay_test
    )


async def run(context: ScanContext) -> dict:
    querier = DnsQuerier(QUERY_TIMEOUT, DNS_BUDGET)
    mx = await asyncio.to_thread(lookup_mail_exchangers, querier, context.domain, context.apex)
    if mx.null_mx:
        raise ModuleSkipped(msg("smtp_security.null_mx"))
    if not mx.hosts:
        if mx.error is not None:
            raise ModuleError(msg("smtp_security.mx_query_failed", error=mx.error))
        raise ModuleSkipped(msg("smtp_security.no_mx"))

    domain = mx.domain or context.apex
    relay_test = impl.relay_test_enabled()
    selected = mx.hosts[: impl.MAX_HOSTS]
    hosts = list(await asyncio.gather(*(_probe_one(entry, domain, 25, relay_test) for entry in selected)))
    # Port 25 filtré partout : repli sur la soumission (587) du MX principal, à titre indicatif.
    if all(h["error_code"] in impl.CONNECTION_ERRORS for h in hosts):
        hosts.append(await _probe_one(selected[0], domain, SUBMISSION_PORT, relay_test))
    summary = impl.summarize(hosts)
    if summary["examined"] == 0:
        blocked = all(h["error_code"] in impl.CONNECTION_ERRORS for h in hosts)
        raise ModuleError(
            msg("smtp_security.port_filtered", count=len(hosts))
            if blocked
            else msg("smtp_security.no_server_examined", count=len(hosts))
        )
    return {
        "measured": True,
        "error": None,
        "domain": domain,
        "relay_test": relay_test,
        "hosts": hosts,
        **summary,
    }


def skip_reason(context: ScanContext) -> object | None:
    if context.shared_platform:
        return msg("orchestrator.skip_shared_platform")
    return skip_for_ip_target(context)


# --- Lecture défensive des résultats ---------------------------------------------


def _examined(data: object) -> list[dict]:
    """Serveurs réellement examinés (connexion établie, bannière acceptée)."""
    hosts = [h for h in as_list(as_dict(data).get("hosts")) if isinstance(h, dict)]
    return [h for h in hosts if h.get("reachable") is True and not h.get("error_code")]


def _names(hosts: list[dict]) -> list[str]:
    return [str(h.get("host")) for h in hosts]


def _tls(host: dict) -> dict:
    return as_dict(host.get("tls"))


def _check_no_starttls(f: FindingInput) -> dict | None:
    hosts = [h for h in _examined(f.data) if h.get("starttls") is False]
    return {"hosts": _names(hosts)} if hosts else None


def _check_tls_failed(f: FindingInput) -> dict | None:
    hosts = [h for h in _examined(f.data) if _tls(h).get("error") == "handshake_failed"]
    return {"hosts": _names(hosts)} if hosts else None


def _certificate_state(host: dict) -> str | None:
    """expired, untrusted (auto-signé, chaîne inconnue, nom différent…) ou None si le certificat est valide."""
    tls = _tls(host)
    if tls.get("verified") is not False:
        return None
    return "expired" if tls.get("verify_error") == "expired" else "untrusted"


def _check_cert_expired(f: FindingInput) -> dict | None:
    hosts = [h for h in _examined(f.data) if _certificate_state(h) == "expired"]
    return {"hosts": _names(hosts)} if hosts else None


def _check_cert_untrusted(f: FindingInput) -> dict | None:
    hosts = [h for h in _examined(f.data) if _certificate_state(h) == "untrusted"]
    return {"hosts": _names(hosts)} if hosts else None


def _cleartext_auth(host: dict) -> bool:
    """Le serveur annonce PLAIN ou LOGIN avant tout chiffrement."""
    return bool(impl.CLEARTEXT_AUTH & {str(a).upper() for a in as_list(host.get("auth_before_tls"))})


def _check_auth_cleartext(f: FindingInput) -> dict | None:
    hosts = [h for h in _examined(f.data) if _cleartext_auth(h)]
    return {"hosts": _names(hosts)} if hosts else None


def _check_banner_version(f: FindingInput) -> list | None:
    hits = [
        hit(host=h.get("host"), software=h.get("software"), version=h.get("version"))
        for h in _examined(f.data)
        if h.get("software") and h.get("version")
    ]
    return hits or None


def _check_catch_all(f: FindingInput) -> bool:
    return as_dict(f.data).get("catch_all") is True


def _check_open_relay(f: FindingInput) -> dict | None:
    hosts = [h for h in _examined(f.data) if h.get("relay") == "open"]
    return {"hosts": _names(hosts)} if hosts else None


def _score(data: dict) -> Outcome:
    smtp = as_dict(data.get("smtp_security"))
    hosts = _examined(smtp)
    if not hosts:
        return Outcome(0, msg("smtp_security.score_none"), False)
    if any(h.get("relay") == "open" for h in hosts):
        return Outcome(0, msg("smtp_security.score_relay"), True)
    if any(h.get("starttls") is False for h in hosts):
        return Outcome(0, msg("smtp_security.score_no_starttls"), True)
    points = SCORE_WEIGHT
    reasons = []
    if any(_tls(h).get("error") == "handshake_failed" for h in hosts):
        points = min(points, 1)
        reasons.append(msg("smtp_security.score_tls_failed"))
    if any(_certificate_state(h) == "expired" for h in hosts):
        points -= 2
        reasons.append(msg("smtp_security.score_cert_expired"))
    elif any(_certificate_state(h) == "untrusted" for h in hosts):
        points -= 1
        reasons.append(msg("smtp_security.score_cert_untrusted"))
    if any(_cleartext_auth(h) for h in hosts):
        points -= 1
        reasons.append(msg("smtp_security.score_auth_cleartext"))
    if not reasons:
        return Outcome(SCORE_WEIGHT, msg("smtp_security.score_ok"), True)
    return Outcome(max(points, 0), msg("smtp_security.score_issues", reasons=reasons), True)


SPEC = ModuleSpec(
    name="smtp_security",
    family="email",
    category="actif",
    run=run,
    skip_reason=skip_reason,
    # Vague 3 : actif, ouvre des connexions vers les serveurs de messagerie de la cible.
    wave=3,
    timeout=90,
    optional=True,
    order=96,
    findings=(
        FindingRule(code="finding.smtp_security.open_relay", severity="critical", check=_check_open_relay),
        FindingRule(code="finding.smtp_security.no_starttls", severity="high", check=_check_no_starttls),
        FindingRule(code="finding.smtp_security.tls_failed", severity="medium", check=_check_tls_failed),
        FindingRule(code="finding.smtp_security.cert_expired", severity="medium", check=_check_cert_expired),
        FindingRule(code="finding.smtp_security.cert_untrusted", severity="low", check=_check_cert_untrusted),
        FindingRule(
            code="finding.smtp_security.auth_cleartext", severity="medium", check=_check_auth_cleartext
        ),
        FindingRule(code="finding.smtp_security.banner_version", severity="low", check=_check_banner_version),
        FindingRule(code="finding.smtp_security.catch_all", severity="low", check=_check_catch_all),
    ),
    score_rules=(ScoreRule(criterion="smtp_security", weight=SCORE_WEIGHT, evaluate=_score),),
)
