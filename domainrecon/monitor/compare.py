# =============================================================================
# DomainRecon - Surveillance : différences entre deux scans d'un même domaine
# =============================================================================
# `diff_scans(a, b)` compare un scan de référence (a, le plus ancien) à un scan
# plus récent (b) : note et score, constats nouveaux et résolus, changements
# DNS, ports, sous-domaines, certificat, technologies. Le résultat est
# structuré ; ses textes sont des messages traduisibles (`changes`, constats),
# rendus par la route dans la langue de la requête. Une rubrique vaut None
# quand l'un des deux scans ne l'a pas mesurée (module non lancé ou en échec) :
# ce n'est pas « rien n'a changé ». Les mêmes différences servent aux règles
# d'alerte (alerts.py).
# =============================================================================

import json

from ..api.routes.history import _dns_changes, _dns_snapshot
from ..api.schemas import ScanResponse
from ..core.models import Scan
from ..i18n import msg
from ..scanner.families import module_run_status
from ..scanner.findings import compute_findings
from .scorefmt import display_score

# Champs du certificat comparés.
CERT_FIELDS = ("subject", "issuer_org", "issuer_cn", "serial_number", "not_before", "not_after")


def scan_view(scan: Scan) -> dict:
    """Scan sous la forme que lisent les règles de constats : dictionnaire JSON, constats compris."""
    payload = ScanResponse.model_validate(scan).model_dump(mode="json")
    payload["findings"] = compute_findings(payload)
    return payload


def _measured(view: dict, module: str) -> bool:
    return module_run_status(view, module) == "ok"


# Paramètres numériques qui varient d'un scan à l'autre sans que le constat change
# (jours restants du certificat, effectifs, durées) : écartés de l'identité d'un constat.
_VOLATILE_PARAMS = frozenset(
    {"days", "count", "total", "seconds", "remaining", "age", "size", "length", "score", "percent", "max"}
)


def _finding_key(finding: dict) -> str:
    """Identité d'un constat : module, code et paramètres stables.

    Les paramètres qui varient seuls (_VOLATILE_PARAMS : jours restants, effectifs)
    sont écartés : un constat qui persiste d'un scan à l'autre garde la même
    identité. Les autres (sous-domaine, port, cookies…) l'identifient.
    """
    message = finding.get("message") if isinstance(finding.get("message"), dict) else {}
    params = message.get("p") if isinstance(message.get("p"), dict) else {}
    stable = {k: v for k, v in params.items() if k not in _VOLATILE_PARAMS}
    return json.dumps([finding.get("module"), message.get("$t"), stable], sort_keys=True, default=str)


def _findings_diff(a: dict, b: dict) -> dict:
    """Constats nouveaux, résolus, inchangés.

    Un constat de a n'est « résolu » que si son module a bien tourné dans b : un
    module non lancé (profil rapide) ou en échec ne prouve pas la correction.
    """
    before = {_finding_key(f): f for f in a["findings"]}
    after = {_finding_key(f): f for f in b["findings"]}
    gone = [f for key, f in before.items() if key not in after]
    return {
        "new": [f for key, f in after.items() if key not in before],
        "resolved": [f for f in gone if not f.get("module") or _measured(b, f["module"])],
        "unchanged": sum(1 for key in after if key in before),
    }


def _ports(view: dict) -> dict[int, dict]:
    ports = {}
    for entry in view["open_ports"]:
        if isinstance(entry, dict) and isinstance(entry.get("port"), int):
            ports[entry["port"]] = {"port": entry["port"], "service": entry.get("service")}
    return ports


def _ports_diff(a: dict, b: dict) -> dict | None:
    if not (_measured(a, "open_ports") and _measured(b, "open_ports")):
        return None
    before, after = _ports(a), _ports(b)
    return {
        "opened": [after[p] for p in sorted(after.keys() - before.keys())],
        "closed": [before[p] for p in sorted(before.keys() - after.keys())],
    }


def _subdomain_names(view: dict) -> set[str]:
    names = set()
    for entry in view["subdomains"]:
        name = entry.get("subdomain") if isinstance(entry, dict) else entry
        if isinstance(name, str) and name:
            names.add(name.lower())
    return names


def _subdomains_diff(a: dict, b: dict) -> dict | None:
    if not (_measured(a, "subdomains") and _measured(b, "subdomains")):
        return None
    before, after = _subdomain_names(a), _subdomain_names(b)
    return {"added": sorted(after - before), "removed": sorted(before - after)}


def _technology_names(view: dict) -> set[str]:
    names = set()
    for entry in view["technologies"]:
        name = entry.get("name") if isinstance(entry, dict) else entry
        if isinstance(name, str) and name:
            names.add(name)
    return names


def _technologies_diff(a: dict, b: dict) -> dict | None:
    if not (_measured(a, "technologies") and _measured(b, "technologies")):
        return None
    before, after = _technology_names(a), _technology_names(b)
    return {"added": sorted(after - before), "removed": sorted(before - after)}


def _certificate_diff(a: dict, b: dict) -> dict | None:
    if not (_measured(a, "tls_certificate") and _measured(b, "tls_certificate")):
        return None
    before, after = a["tls_certificate"], b["tls_certificate"]
    fields = {
        name: {"a": before.get(name), "b": after.get(name)}
        for name in CERT_FIELDS
        if before.get(name) != after.get(name)
    }
    return {
        "changed": bool(fields),
        "fields": fields,
        "days_remaining": {"a": before.get("days_remaining"), "b": after.get("days_remaining")},
    }


def _score_diff(a: dict, b: dict) -> dict:
    before, after = display_score(a["security_score"]), display_score(b["security_score"])
    delta = None
    if before["score"] is not None and after["score"] is not None:
        delta = round(after["score"] - before["score"], 2)
    return {"a": before, "b": after, "delta": delta, "grade_changed": before["grade"] != after["grade"]}


def _dns_diff(scan_a: Scan, scan_b: Scan) -> dict | None:
    changes = _dns_changes(_dns_snapshot(scan_a), _dns_snapshot(scan_b))
    return None if changes is None else {rtype: change.model_dump() for rtype, change in changes.items()}


def summary_messages(diff: dict) -> list[dict]:
    """Résumé traduisible des changements : un message par rubrique modifiée."""
    changes: list[dict] = []
    score = diff["score"]
    if score["grade_changed"] or score["delta"]:
        changes.append(
            msg(
                "compare.summary_score",
                before=score["a"]["grade"],
                after=score["b"]["grade"],
                delta=score["delta"] if score["delta"] is not None else "",
            )
        )
    findings = diff["findings"]
    if findings and findings["new"]:
        changes.append(msg("compare.summary_new_findings", count=len(findings["new"])))
    if findings and findings["resolved"]:
        changes.append(msg("compare.summary_resolved_findings", count=len(findings["resolved"])))
    if diff["dns"]:
        changes.append(msg("compare.summary_dns", types=sorted(diff["dns"])))
    ports = diff["ports"]
    if ports and ports["opened"]:
        changes.append(msg("compare.summary_ports_opened", ports=[p["port"] for p in ports["opened"]]))
    if ports and ports["closed"]:
        changes.append(msg("compare.summary_ports_closed", ports=[p["port"] for p in ports["closed"]]))
    subs = diff["subdomains"]
    if subs and subs["added"]:
        changes.append(msg("compare.summary_subdomains_added", count=len(subs["added"])))
    if subs and subs["removed"]:
        changes.append(msg("compare.summary_subdomains_removed", count=len(subs["removed"])))
    cert = diff["certificate"]
    if cert and cert["changed"]:
        changes.append(msg("compare.summary_certificate"))
    techs = diff["technologies"]
    if techs and (techs["added"] or techs["removed"]):
        changes.append(
            msg("compare.summary_technologies", added=len(techs["added"]), removed=len(techs["removed"]))
        )
    return changes


def diff_scans(scan_a: Scan, scan_b: Scan, view_a: dict | None = None, view_b: dict | None = None) -> dict:
    """Différences entre `scan_a` (référence) et `scan_b`.

    `comparable` est faux si l'un des scans est en erreur : aucune rubrique
    n'est alors comparée (None). `view_a` et `view_b` : vues déjà calculées (scan_view).
    """
    a = view_a or scan_view(scan_a)
    b = view_b or scan_view(scan_b)
    comparable = scan_a.status != "error" and scan_b.status != "error"
    diff: dict = {
        "domain": scan_b.domain,
        "a": {"id": scan_a.id, "timestamp": a["scan_timestamp"], "status": scan_a.status},
        "b": {"id": scan_b.id, "timestamp": b["scan_timestamp"], "status": scan_b.status},
        "comparable": comparable,
        "score": _score_diff(a, b),
    }
    if comparable:
        diff.update(
            findings=_findings_diff(a, b),
            dns=_dns_diff(scan_a, scan_b),
            ports=_ports_diff(a, b),
            subdomains=_subdomains_diff(a, b),
            certificate=_certificate_diff(a, b),
            technologies=_technologies_diff(a, b),
        )
    else:
        diff.update(findings=None, dns=None, ports=None, subdomains=None, certificate=None, technologies=None)
    diff["changes"] = summary_messages(diff) if comparable else []
    return diff
