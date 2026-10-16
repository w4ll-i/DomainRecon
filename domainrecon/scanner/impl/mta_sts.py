# =============================================================================
# DomainRecon - Logique du module « mta_sts » : MTA-STS (RFC 8461) et TLS-RPT (RFC 8460)
# =============================================================================
# 1. DNS : TXT _mta-sts.<domaine> (v=STSv1; id=…), MX réels, TXT _smtp._tls.<domaine>.
# 2. HTTPS : politique https://mta-sts.<domaine>/.well-known/mta-sts.txt, obtenue avec le
#    client des API tierces (TLS vérifié, aucune redirection : la RFC 8461 §3.3 les interdit).
# 3. Évaluation pure (sans réseau) : politique valide ?, mode, max_age, et COMPARAISON des
#    motifs mx: de la politique aux MX réels (un MX non couvert ne reçoit plus de courrier
#    d'un expéditeur qui applique la politique en mode enforce).
# Au-delà de mode/max_age, les lignes mx:, la version, le type de contenu et la
# validité du certificat sont vérifiés.
# =============================================================================

import re
import socket
import ssl
from typing import NamedTuple

import httpx

from ...i18n import msg
from ..dns import DnsQuerier, txt_record_text
from ..email_security import parse_tags
from ..errors import TargetNotAllowedError
from ..http_utils import read_body_limited
from .mail_provider import lookup_mail_exchangers, resolution_state

# RFC 8461 §3.2 : la politique ne dépasse pas 64 Kio ; max_age au plus 31 557 600 s (1 an).
POLICY_MAX_BYTES = 65536
MAX_AGE_LIMIT = 31_557_600
# Durée de mise en cache conseillée : en dessous d'une semaine, la protection est fragile.
MIN_RECOMMENDED_MAX_AGE = 604_800
FETCH_TIMEOUT = 10.0
QUERY_TIMEOUT = 3.0
DNS_BUDGET = 20.0
MAX_PATTERNS = 30

_ID_RE = re.compile(r"[A-Za-z0-9]{1,32}")
_MX_PATTERN_RE = re.compile(r"(\*\.)?[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+")

MODES = ("enforce", "testing", "none")


class DnsData(NamedTuple):
    """Ce que la partie DNS établit avant la requête HTTPS."""

    mx_domain: str | None
    mx_hosts: list[str]
    null_mx: bool
    mx_error: object | None
    sts_records: list[str]
    sts_error: object | None
    host_state: str
    rpt_records: list[str]
    rpt_error: object | None


def collect_dns(querier: DnsQuerier, domain: str) -> DnsData:
    """Requêtes DNS du module (bloquantes : à lancer dans un thread)."""
    mx = lookup_mail_exchangers(querier, domain, domain)
    sts = querier.lookup(f"_mta-sts.{domain}", "TXT")
    sts_records = (
        [t for t in map(txt_record_text, sts.answers) if parse_tags(t).get("v", "").lower() == "stsv1"]
        if sts.status == "ok"
        else []
    )
    host_state = resolution_state(querier, f"mta-sts.{domain}") if sts_records else "unknown"
    rpt = querier.lookup(f"_smtp._tls.{domain}", "TXT")
    rpt_records = (
        [t for t in map(txt_record_text, rpt.answers) if parse_tags(t).get("v", "").lower() == "tlsrptv1"]
        if rpt.status == "ok"
        else []
    )
    return DnsData(
        mx.domain,
        [entry["host"] for entry in mx.hosts],
        mx.null_mx,
        mx.error,
        sts_records,
        sts.error if sts.status == "error" else None,
        host_state,
        rpt_records,
        rpt.error if rpt.status == "error" else None,
    )


# =============================================================================
# Politique
# =============================================================================


def classify_fetch_error(exc: BaseException) -> str:
    """Catégorie d'un échec de récupération : tls, timeout, dns, blocked, unreachable (sans citer l'URL)."""
    if isinstance(exc, TargetNotAllowedError):
        return "blocked"
    if isinstance(exc, httpx.TimeoutException):
        return "timeout"
    seen: set[int] = set()
    current: BaseException | None = exc
    while current is not None and id(current) not in seen:
        seen.add(id(current))
        if isinstance(current, ssl.SSLError):
            return "tls"
        if isinstance(current, socket.gaierror):
            return "dns"
        current = current.__cause__ or current.__context__
    return "unreachable"


async def fetch_policy(client: httpx.AsyncClient, domain: str) -> dict:
    """Télécharge la politique : {status, content_type, text, error, truncated}. Ne lève pas d'erreur réseau."""
    url = f"https://mta-sts.{domain}/.well-known/mta-sts.txt"
    outcome: dict = {"status": None, "content_type": None, "text": None, "error": None, "truncated": False}
    try:
        async with client.stream(
            "GET", url, timeout=FETCH_TIMEOUT, headers={"Accept": "text/plain"}
        ) as response:
            outcome["status"] = response.status_code
            outcome["content_type"] = response.headers.get("content-type")
            if response.status_code == 200:
                body, truncated = await read_body_limited(response, POLICY_MAX_BYTES)
                outcome["truncated"] = truncated
                outcome["text"] = body.decode("utf-8", errors="replace")
    except (httpx.HTTPError, httpx.InvalidURL, TargetNotAllowedError) as exc:
        outcome["error"] = classify_fetch_error(exc)
    return outcome


def parse_policy(text: str) -> dict:
    """Lit la politique (lignes « clé: valeur ») : version, mode, max_age, mx (liste), lignes inconnues ignorées."""
    policy: dict = {"version": None, "mode": None, "max_age": None, "max_age_raw": None, "mx": []}
    for line in text.splitlines():
        key, sep, value = line.partition(":")
        key, value = key.strip().lower(), value.strip()
        if not sep or not key:
            continue
        if key == "version":
            policy["version"] = value
        elif key == "mode":
            policy["mode"] = value.lower()
        elif key == "max_age":
            policy["max_age_raw"] = value
            if value.isdigit():
                policy["max_age"] = int(value)
        elif key == "mx" and value and len(policy["mx"]) < MAX_PATTERNS:
            policy["mx"].append(value.lower().rstrip("."))
    return policy


def mx_pattern_matches(pattern: str, host: str) -> bool:
    """Le MX correspond au motif (RFC 8461 §4.1) : nom exact, ou « *.domaine » = UN seul label à gauche."""
    pattern, host = pattern.lower().rstrip("."), host.lower().rstrip(".")
    if pattern.startswith("*."):
        suffix = pattern[1:]
        label = host[: -len(suffix)] if host.endswith(suffix) else ""
        return bool(label) and "." not in label
    return pattern == host


def parse_rua(record: str) -> tuple[list[str], list[str]]:
    """Destinations rua= de TLS-RPT : (valides, invalides). Valide : mailto: ou https://."""
    rua = parse_tags(record).get("rua", "")
    valid: list[str] = []
    invalid: list[str] = []
    for item in (part.strip() for part in rua.split(",")):
        if not item:
            continue
        low = item.lower()
        if low.startswith("mailto:") and "@" in item:
            valid.append(item)
        elif low.startswith("https://") and len(item) > len("https://"):
            valid.append(item)
        else:
            invalid.append(item)
    return valid, invalid


# =============================================================================
# Évaluation
# =============================================================================


def evaluate(domain: str, dns: DnsData, fetched: dict | None) -> dict:
    """Résultat du module à partir des données DNS et de la politique téléchargée (pur, sans réseau)."""
    issues: list[object] = []
    has_mail = bool(dns.mx_hosts)
    result: dict = {
        "measured": True,
        "error": None,
        "domain": domain,
        "mx_domain": dns.mx_domain,
        "has_mail": has_mail,
        "state": "absent",
        "txt": {"found": False, "record": None, "id": None, "count": len(dns.sts_records), "error": None},
        "policy": {
            "url": f"https://mta-sts.{domain}/.well-known/mta-sts.txt",
            "host_resolves": None,
            "fetched": False,
            "status": None,
            "content_type": None,
            "error": None,
            "version": None,
            "mode": None,
            "max_age": None,
            "mx": [],
            "valid": False,
        },
        "mx_check": {"hosts": dns.mx_hosts, "uncovered": [], "unused_patterns": []},
        "tls_rpt": {"found": False, "record": None, "rua": [], "invalid_rua": [], "error": None},
        "issues": issues,
    }
    _evaluate_tls_rpt(result["tls_rpt"], dns, issues)

    txt = result["txt"]
    if dns.sts_error is not None and not dns.sts_records:
        txt["error"] = msg("mta_sts.query_failed", error=dns.sts_error)
        result.update(measured=False, error=txt["error"], state="unknown")
        return result
    if not dns.sts_records:
        return result

    txt.update(found=True, record=dns.sts_records[0])
    policy = result["policy"]
    state = "broken"
    if len(dns.sts_records) > 1:
        # RFC 8461 §3.1 : plusieurs enregistrements STSv1, l'expéditeur ignore MTA-STS.
        issues.append(msg("mta_sts.txt_multiple", count=len(dns.sts_records)))
        result["state"] = state
        return result
    sts_id = parse_tags(dns.sts_records[0]).get("id", "")
    txt["id"] = sts_id or None
    if not _ID_RE.fullmatch(sts_id):
        issues.append(msg("mta_sts.txt_bad_id"))

    if dns.host_state in ("nxdomain", "no_address"):
        policy["host_resolves"] = False
        policy["error"] = "dns"
        issues.append(msg("mta_sts.policy_host_missing", host=f"mta-sts.{domain}"))
        result["state"] = state
        return result
    policy["host_resolves"] = True if dns.host_state == "ok" else None

    if fetched is None:
        result["state"] = state
        return result
    policy.update(status=fetched["status"], content_type=fetched["content_type"], error=fetched["error"])
    if fetched["error"] is not None:
        issues.append(_FETCH_ERRORS.get(fetched["error"], _FETCH_ERRORS["unreachable"]))
        result["state"] = state
        return result
    if fetched["status"] != 200:
        issues.append(msg("mta_sts.fetch_status", status=fetched["status"]))
        result["state"] = state
        return result
    policy["fetched"] = True
    problems = _evaluate_policy(policy, fetched)
    issues.extend(message for message, _ in problems)
    policy["valid"] = not any(fatal for _, fatal in problems)
    if not policy["valid"]:
        result["state"] = state
        return result

    state = policy["mode"]
    result["state"] = state
    _compare_mx(result, dns, issues)
    if policy["max_age"] is not None and policy["max_age"] < MIN_RECOMMENDED_MAX_AGE and state != "none":
        issues.append(msg("mta_sts.max_age_short", days=policy["max_age"] // 86400))
    return result


# Message selon la catégorie d'échec de récupération de la politique (classify_fetch_error).
_FETCH_ERRORS = {
    "tls": msg("mta_sts.fetch_tls"),
    "timeout": msg("mta_sts.fetch_timeout"),
    "dns": msg("mta_sts.fetch_dns"),
    "blocked": msg("mta_sts.fetch_blocked"),
    "unreachable": msg("mta_sts.fetch_unreachable"),
}


def _evaluate_policy(policy: dict, fetched: dict) -> list[tuple[dict, bool]]:
    """Problèmes de la politique : [(message, fatal)]. Un problème fatal rend la politique inutilisable."""
    problems: list[tuple[dict, bool]] = []
    content_type = (fetched.get("content_type") or "").split(";")[0].strip().lower()
    if content_type != "text/plain":
        problems.append((msg("mta_sts.policy_bad_content_type", content_type=content_type or "?"), False))
    if fetched.get("truncated"):
        problems.append((msg("mta_sts.policy_too_big"), True))
    parsed = parse_policy(fetched.get("text") or "")
    policy.update(version=parsed["version"], mode=parsed["mode"], max_age=parsed["max_age"], mx=parsed["mx"])
    if parsed["version"] != "STSv1":
        problems.append((msg("mta_sts.policy_bad_version"), True))
    if parsed["mode"] not in MODES:
        problems.append((msg("mta_sts.policy_bad_mode", mode=parsed["mode"] or "?"), True))
    if parsed["max_age"] is None or parsed["max_age"] > MAX_AGE_LIMIT:
        problems.append((msg("mta_sts.policy_bad_max_age", value=parsed["max_age_raw"] or "?"), True))
    if not parsed["mx"] and parsed["mode"] != "none":
        problems.append((msg("mta_sts.policy_no_mx"), True))
    for pattern in parsed["mx"]:
        if not _MX_PATTERN_RE.fullmatch(pattern):
            problems.append((msg("mta_sts.policy_bad_mx", pattern=pattern), False))
    return problems


def _compare_mx(result: dict, dns: DnsData, issues: list[object]) -> None:
    patterns = result["policy"]["mx"]
    check = result["mx_check"]
    check["uncovered"] = [h for h in dns.mx_hosts if not any(mx_pattern_matches(p, h) for p in patterns)]
    check["unused_patterns"] = [
        p for p in patterns if not any(mx_pattern_matches(p, h) for h in dns.mx_hosts)
    ]
    if check["uncovered"] and result["policy"]["mode"] != "none":
        issues.append(msg("mta_sts.mx_uncovered", hosts=check["uncovered"], mode=result["policy"]["mode"]))
    if check["unused_patterns"] and dns.mx_hosts and result["policy"]["mode"] != "none":
        issues.append(msg("mta_sts.mx_unused_patterns", patterns=check["unused_patterns"]))


def _evaluate_tls_rpt(rpt: dict, dns: DnsData, issues: list[object]) -> None:
    if dns.rpt_error is not None and not dns.rpt_records:
        rpt["error"] = msg("mta_sts.query_failed", error=dns.rpt_error)
        return
    if not dns.rpt_records:
        return
    rpt.update(found=True, record=dns.rpt_records[0])
    if len(dns.rpt_records) > 1:
        issues.append(msg("mta_sts.rpt_multiple", count=len(dns.rpt_records)))
    valid, invalid = parse_rua(dns.rpt_records[0])
    rpt.update(rua=valid, invalid_rua=invalid)
    if invalid or not valid:
        issues.append(msg("mta_sts.rpt_bad_rua"))
