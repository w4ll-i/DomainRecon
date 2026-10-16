# =============================================================================
# DomainRecon - Module « tls_deep » : protocoles et suites de chiffrement acceptés
# =============================================================================
# Teste, par poignées de main partielles, quelles versions du protocole (SSLv3,
# TLS 1.0 à 1.3) et quelles suites le serveur accepte, puis cherche la
# compression TLS (CRIME), des paramètres Diffie-Hellman faibles (Logjam) et
# l'absence de confidentialité persistante. Le travail est dans
# scanner/impl/tls_deep.py et scanner/impl/tls_hello.py (ClientHello écrit à la
# main : le verdict ne dépend pas de l'OpenSSL de la machine du scan).
#
# Le verdict sur TLS 1.0 et 1.1 ne dépend pas de l'OpenSSL local ; les suites sont
# énumérées et SSLv3 est détecté.
#
# Catégorie « actif » : une dizaine à plusieurs dizaines de connexions vers le
# port 443 de la cible. Réservé aux cibles dont l'utilisateur a l'autorisation.
# =============================================================================

import asyncio

from ...i18n import msg
from ..errors import ModuleError, ModuleSkipped
from ..impl import tls_deep as analysis
from ..registry import ModuleSpec, ScanContext, skip_without_address
from ..rules import FindingInput, FindingRule, Outcome, ScoreRule, hit
from ..score import as_dict, as_int, as_list
from ..targets import ensure_ip_allowed

TLS_PORT = 443
# Budget de l'analyse (secondes) : le thread se termine avant le délai du module.
ANALYSIS_BUDGET = 90.0
# Au plus deux adresses essayées (la première peut refuser la connexion).
MAX_ADDRESSES = 2
LEGACY_PROTOCOLS = ("TLSv1.0", "TLSv1.1")


async def run(context: ScanContext) -> dict:
    sni = None if context.is_ip_target else context.domain
    failure = "refused"
    for address in context.addresses[:MAX_ADDRESSES]:
        ip = ensure_ip_allowed(address)
        report = await asyncio.to_thread(analysis.scan_sync, ip, TLS_PORT, sni, ANALYSIS_BUDGET)
        failure = report.pop("failure", None)
        if failure is None:
            return report
        if failure != "refused":
            break
    if failure == "timeout":
        raise ModuleError(msg("net.timeout"))
    raise ModuleSkipped(msg("tls.https_closed", port=TLS_PORT))


# -----------------------------------------------------------------------------
# Constats « À corriger »
# -----------------------------------------------------------------------------


def _report(f: FindingInput) -> dict:
    data = as_dict(f.data)
    return {} if data.get("measured") is False else data


def _protocols(f: FindingInput) -> dict:
    return as_dict(_report(f).get("protocols"))


def _names(value: object, limit: int = 3) -> str:
    names = [str(name).removeprefix("TLS_") for name in as_list(value)]
    shown = ", ".join(names[:limit])
    return shown + (" …" if len(names) > limit else "")


def _check_sslv3(f: FindingInput) -> bool:
    return _protocols(f).get("SSLv3") is True


def _check_legacy(f: FindingInput) -> dict | None:
    protocols = _protocols(f)
    found = [name for name in LEGACY_PROTOCOLS if protocols.get(name) is True]
    return {"protocols": ", ".join(found)} if found else None


def _check_no_modern(f: FindingInput) -> bool:
    protocols = _protocols(f)
    # Un protocole indéterminé (None) n'est pas une preuve d'absence.
    if not protocols or any(protocols.get(name) is None for name in ("TLSv1.2", "TLSv1.3")):
        return False
    return not protocols.get("TLSv1.2") and not protocols.get("TLSv1.3")


def _check_broken(f: FindingInput) -> dict | None:
    names = as_list(_report(f).get("broken_ciphers"))
    return {"count": len(names), "examples": _names(names)} if names else None


def _check_weak(f: FindingInput) -> dict | None:
    names = as_list(_report(f).get("weak_ciphers"))
    return {"count": len(names), "examples": _names(names)} if names else None


def _check_weak_dh(f: FindingInput) -> object:
    bits = as_int(_report(f).get("dh_bits"))
    if bits is None or bits >= 2048:
        return None
    return hit(severity="high" if bits <= 1024 else "medium", bits=bits)


def _check_compression(f: FindingInput) -> bool:
    return _report(f).get("compression") is True


def _check_no_pfs(f: FindingInput) -> object:
    report = _report(f)
    names = as_list(report.get("no_pfs_ciphers"))
    if not names:
        return None
    suites = as_list(report.get("suites"))
    with_pfs = [s for s in suites if as_dict(s).get("pfs") is True]
    # Aucune suite à confidentialité persistante : un trafic enregistré se déchiffre avec la clé volée.
    return hit(severity="low" if with_pfs else "medium", count=len(names))


def _check_no_tls13(f: FindingInput) -> bool:
    protocols = _protocols(f)
    return protocols.get("TLSv1.3") is False and protocols.get("TLSv1.2") is True


FINDINGS = (
    FindingRule(code="finding.tls_deep.broken_ciphers", severity="critical", check=_check_broken),
    FindingRule(code="finding.tls_deep.sslv3", severity="high", check=_check_sslv3),
    FindingRule(code="finding.tls_deep.no_modern_protocol", severity="high", check=_check_no_modern),
    FindingRule(code="finding.tls_deep.weak_ciphers", severity="high", check=_check_weak),
    FindingRule(code="finding.tls_deep.weak_dh", severity="high", check=_check_weak_dh),
    FindingRule(code="finding.tls_deep.legacy_protocols", severity="medium", check=_check_legacy),
    FindingRule(code="finding.tls_deep.compression", severity="medium", check=_check_compression),
    FindingRule(code="finding.tls_deep.no_pfs", severity="low", check=_check_no_pfs),
    FindingRule(code="finding.tls_deep.no_tls13", severity="low", check=_check_no_tls13),
)


# -----------------------------------------------------------------------------
# Score : 10 points ; SSLv3, suites cassées ou aucun protocole moderne plafonnent la note
# -----------------------------------------------------------------------------


def _score(data: dict) -> Outcome:
    report = as_dict(data.get("tls_deep"))
    protocols = as_dict(report.get("protocols"))
    grade = str(report.get("grade") or "?")
    if protocols.get("SSLv3") is True or as_list(report.get("broken_ciphers")):
        return Outcome(
            0, msg("tls_deep.score_detail", grade=grade), True, cap_reason=msg("tls_deep.score_cap")
        )
    if not protocols.get("TLSv1.2") and not protocols.get("TLSv1.3"):
        return Outcome(0, msg("tls_deep.score_detail", grade=grade), True)
    points = 10
    points -= 2 if protocols.get("TLSv1.0") else 0
    points -= 1 if protocols.get("TLSv1.1") else 0
    points -= 3 if as_list(report.get("weak_ciphers")) else 0
    bits = as_int(report.get("dh_bits"))
    if bits is not None and bits < 2048:
        points -= 3 if bits <= 1024 else 1
    points -= 2 if report.get("compression") is True else 0
    points -= 1 if protocols.get("TLSv1.3") is False else 0
    if as_list(report.get("no_pfs_ciphers")) and not any(
        as_dict(s).get("pfs") is True for s in as_list(report.get("suites"))
    ):
        points -= 2
    return Outcome(max(points, 0), msg("tls_deep.score_detail", grade=grade), True)


SPEC = ModuleSpec(
    name="tls_deep",
    family="tls",
    # actif : dizaines de poignées de main vers la cible (énumération des suites).
    category="actif",
    run=run,
    skip_reason=skip_without_address,
    wave=3,
    timeout=120,
    order=41,
    findings=FINDINGS,
    score_rules=(ScoreRule(criterion="tls_deep", weight=10, evaluate=_score, rank=21),),
)
