# =============================================================================
# DomainRecon - Surveillance : règles d'alerte
# =============================================================================
# Règles (activables une à une, par surveillance) :
#   grade_drop      la note affichée baisse (A -> B…) ;
#   new_findings    un constat critique ou élevé apparaît ;
#   cert_expiry_days  le certificat expire dans N jours ou moins ;
#   new_port        un nouveau port est ouvert ;
#   new_subdomain   un nouveau sous-domaine apparaît.
#
# Alerte seulement sur changement d'état : les règles de comparaison lisent les
# différences avec le scan précédent du domaine (un constat qui persiste ne
# réalerte pas) ; l'expiration du certificat mémorise son état dans la
# surveillance (alert_state) et ne réalerte qu'après être repassée au-dessus du
# seuil (certificat renouvelé). Sans scan précédent (premier scan), seule
# l'expiration du certificat est évaluée : le premier relevé est la référence.
# Une rubrique non mesurée par l'un des deux scans n'alerte jamais.
# =============================================================================

from pydantic import BaseModel, ConfigDict, Field

from ..i18n import msg
from ..notify.channels import Alert, severity_message
from ..scanner.families import module_run_status
from .scorefmt import grade_rank

CERT_EXPIRING = "cert_expiring"
ALERT_SEVERITIES = ("critical", "high")
# Constats couverts par une règle dédiée (expiration du certificat) : pas de double alerte.
COVERED_FINDINGS = frozenset({"finding.tls_expires_soon"})
# Nombre de sous-domaines cités dans un message d'alerte.
SUBDOMAINS_SHOWN = 10


class AlertRules(BaseModel):
    """Règles d'alerte d'une surveillance."""

    model_config = ConfigDict(extra="forbid")

    grade_drop: bool = True
    new_findings: bool = True
    cert_expiry_days: int | None = Field(
        14, ge=1, le=365, description="Seuil en jours ; null : règle désactivée"
    )
    new_port: bool = True
    new_subdomain: bool = True


def rules_of(stored: object) -> AlertRules:
    """Règles enregistrées ; valeurs par défaut pour une donnée absente ou invalide."""
    try:
        return AlertRules.model_validate(stored or {})
    except ValueError:
        return AlertRules()


def _cert_days(view: dict) -> int | None:
    if module_run_status(view, "tls_certificate") != "ok":
        return None
    cert = view.get("tls_certificate")
    if not isinstance(cert, dict) or cert.get("https") is False or cert.get("valid") is False:
        return None
    days = cert.get("days_remaining")
    return days if isinstance(days, int) and not isinstance(days, bool) else None


def _evaluate_cert(rules: AlertRules, view: dict, state: dict, domain: str) -> tuple[list[Alert], dict]:
    new_state = dict(state)
    days = _cert_days(view)
    if rules.cert_expiry_days is None or days is None:
        return [], new_state
    if days > rules.cert_expiry_days:
        new_state[CERT_EXPIRING] = False
        return [], new_state
    if new_state.get(CERT_EXPIRING):
        return [], new_state
    new_state[CERT_EXPIRING] = True
    severity = "high" if days <= 7 else "medium"
    message = msg("alert.cert_expiry", domain=domain, days=days, threshold=rules.cert_expiry_days)
    return [Alert("cert_expiry", severity, message, {"days": days})], new_state


def evaluate(
    rules: AlertRules,
    state: dict,
    domain: str,
    current_view: dict,
    diff: dict | None,
) -> tuple[list[Alert], dict]:
    """(alertes, nouvel état) pour un scan terminé.

    `diff` : différences avec le scan précédent (compare.diff_scans), ou None au
    premier scan. `state` : alert_state de la surveillance.
    """
    alerts, new_state = _evaluate_cert(rules, current_view, state if isinstance(state, dict) else {}, domain)
    if diff is None or not diff["comparable"]:
        return alerts, new_state

    if rules.grade_drop:
        before, after = diff["score"]["a"]["grade"], diff["score"]["b"]["grade"]
        rank_before, rank_after = grade_rank(before), grade_rank(after)
        if rank_before is not None and rank_after is not None and rank_after > rank_before:
            severity = "high" if rank_after - rank_before >= 2 else "medium"
            alerts.append(
                Alert(
                    "grade_drop",
                    severity,
                    msg("alert.grade_drop", domain=domain, before=before, after=after),
                    {"before": before, "after": after},
                )
            )

    if rules.new_findings and diff["findings"]:
        for finding in diff["findings"]["new"]:
            if (
                finding.get("severity") in ALERT_SEVERITIES
                and finding["message"]["$t"] not in COVERED_FINDINGS
            ):
                alerts.append(
                    Alert(
                        "new_finding",
                        finding["severity"],
                        msg(
                            "alert.new_finding",
                            domain=domain,
                            severity=severity_message(finding["severity"]),
                            finding=finding["message"],
                        ),
                        {"module": finding.get("module")},
                    )
                )

    ports = diff["ports"]
    if rules.new_port and ports and ports["opened"]:
        opened = [p["port"] for p in ports["opened"]]
        alerts.append(
            Alert("new_port", "medium", msg("alert.new_port", domain=domain, ports=opened), {"ports": opened})
        )

    subdomains = diff["subdomains"]
    if rules.new_subdomain and subdomains and subdomains["added"]:
        added = subdomains["added"]
        alerts.append(
            Alert(
                "new_subdomain",
                "low",
                msg(
                    "alert.new_subdomain",
                    domain=domain,
                    count=len(added),
                    subdomains=added[:SUBDOMAINS_SHOWN],
                ),
                {"subdomains": added[:SUBDOMAINS_SHOWN], "count": len(added)},
            )
        )
    return alerts, new_state


__all__ = ["AlertRules", "evaluate", "rules_of"]
