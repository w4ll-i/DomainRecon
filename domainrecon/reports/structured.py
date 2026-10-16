# =============================================================================
# DomainRecon - Rapports : formats structurés (JSON, CSV, SARIF, JUnit XML)
# =============================================================================
# Formats lus par des machines (tableur, intégration continue, GitHub code
# scanning). Les valeurs de classement (gravité, famille, module, statut) restent
# les codes du projet ; seuls les messages sont rendus dans la langue demandée.
# =============================================================================

from __future__ import annotations

import csv
import hashlib
import io
import json
import re
import xml.etree.ElementTree as ET

from ..i18n import render
from .model import ReportData

# Gravité -> niveau SARIF et score de sécurité (échelle CVSS, lue par GitHub).
_SARIF_LEVEL = {"critical": "error", "high": "error", "medium": "warning", "low": "note"}
_SECURITY_SEVERITY = {"critical": "9.5", "high": "8.0", "medium": "5.5", "low": "3.0"}
SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"

# Caractères interdits en XML 1.0.
_XML_INVALID = re.compile("[\x00-\x08\x0b\x0c\x0e-\x1f￾￿]")
# Début de cellule interprété comme une formule par les tableurs.
_FORMULA_START = ("=", "+", "-", "@", "\t", "\r")


# --- JSON -------------------------------------------------------------------


def to_json(payload: dict, data: ReportData) -> str:
    """Scan complet rendu dans la langue demandée, avec un en-tête décrivant le rapport."""
    document = {
        "report": {
            "generator": "DomainRecon",
            "version": data.version,
            "lang": data.lang,
            "generated_at": data.generated_at,
            "format": "json",
        },
        "scan": render(payload, data.lang),
    }
    return json.dumps(document, ensure_ascii=False, indent=2, default=str) + "\n"


# --- CSV --------------------------------------------------------------------

CSV_COLUMNS = ("type", "domain", "severity", "family", "module", "status", "duration_s", "message")


def _csv_cell(value: object) -> str:
    """Cellule de texte, neutralisée si un tableur la prendrait pour une formule."""
    if value is None:
        return ""
    text = str(value)
    return "'" + text if text.startswith(_FORMULA_START) else text


def to_csv(data: ReportData) -> str:
    """Un tableau unique : une ligne `finding` par constat, une ligne `module` par module lancé."""
    out = io.StringIO()
    writer = csv.writer(out, lineterminator="\n")
    writer.writerow(CSV_COLUMNS)
    for f in data.findings:
        writer.writerow(
            [
                "finding",
                _csv_cell(data.domain),
                f.severity,
                f.family or "",
                f.module,
                "",
                "",
                _csv_cell(f.message),
            ]
        )
    for m in data.modules:
        duration = "" if m.duration is None else f"{m.duration:.3f}"
        writer.writerow(
            [
                "module",
                _csv_cell(data.domain),
                "",
                m.family or "",
                m.name,
                m.status,
                duration,
                _csv_cell(m.error),
            ]
        )
    return out.getvalue()


# --- SARIF 2.1.0 ------------------------------------------------------------


def to_sarif(data: ReportData) -> str:
    """Rapport SARIF 2.1.0 : une règle par code de constat, un résultat par constat."""
    rules: list[dict] = []
    rule_index: dict[str, int] = {}
    results: list[dict] = []
    for f in data.findings:
        rule_id = f.code or "domainrecon.finding"
        if rule_id not in rule_index:
            rule_index[rule_id] = len(rules)
            rules.append(
                {
                    "id": rule_id,
                    "name": rule_id,
                    "shortDescription": {"text": f.message},
                    "defaultConfiguration": {"level": _SARIF_LEVEL[f.severity]},
                    "properties": {
                        "tags": [t for t in (f.family, "security") if t],
                        "security-severity": _SECURITY_SEVERITY[f.severity],
                    },
                }
            )
        fingerprint = hashlib.sha256(f"{rule_id}|{data.domain}|{f.module}|{f.message}".encode()).hexdigest()
        results.append(
            {
                "ruleId": rule_id,
                "ruleIndex": rule_index[rule_id],
                "level": _SARIF_LEVEL[f.severity],
                "message": {"text": f.message},
                "locations": [
                    {
                        "logicalLocations": [
                            {
                                "name": data.domain,
                                "fullyQualifiedName": f"{data.domain}/{f.module}"
                                if f.module
                                else data.domain,
                                "kind": "module",
                            }
                        ]
                    }
                ],
                "partialFingerprints": {"domainrecon/v1": fingerprint[:32]},
                "properties": {"severity": f.severity, "family": f.family, "module": f.module},
            }
        )
    run = {
        "tool": {"driver": {"name": "DomainRecon", "version": data.version, "rules": rules}},
        "invocations": [{"executionSuccessful": data.status != "error"}],
        "results": results,
        "properties": {
            "domain": data.domain,
            "scanId": data.scan_id,
            "grade": data.grade,
            "score": data.score,
            "coverage": data.coverage,
        },
    }
    document = {"$schema": SARIF_SCHEMA, "version": "2.1.0", "runs": [run]}
    return json.dumps(document, ensure_ascii=False, indent=2) + "\n"


# --- JUnit XML --------------------------------------------------------------


def _xml(text: object) -> str:
    return _XML_INVALID.sub("", str(text))


def to_junit(data: ReportData) -> str:
    """JUnit XML : une testsuite par famille, un testcase par module.

    Un constat est un `failure` du module qui l'a produit ; un module en échec ou
    hors délai est un `error` ; un module sans objet est `skipped`.
    """
    by_module: dict[str, list] = {}
    for f in data.findings:
        by_module.setdefault(f.module, []).append(f)
    suites: dict[str, list[tuple[str, object]]] = {}
    seen = set()
    for m in data.modules:
        seen.add(m.name)
        suites.setdefault(m.family or "other", []).append((m.name, m))
    for name in by_module:
        if name not in seen:
            suites.setdefault(by_module[name][0].family or "other", []).append((name, None))
    family_order = [f.key for f in data.families]
    ordered = sorted(suites, key=lambda k: (family_order.index(k) if k in family_order else 99, k))

    root = ET.Element("testsuites", name=_xml(f"DomainRecon {data.domain}"))
    totals = dict(tests=0, failures=0, errors=0, skipped=0)
    total_time = 0.0
    for family in ordered:
        suite = ET.SubElement(root, "testsuite", name=family, timestamp=_xml(data.timestamp or ""))
        counts = dict(tests=0, failures=0, errors=0, skipped=0)
        time_sum = 0.0
        props = ET.SubElement(suite, "properties")
        ET.SubElement(props, "property", name="domain", value=_xml(data.domain))
        ET.SubElement(props, "property", name="grade", value=data.grade)
        for name, entry in suites[family]:
            duration = entry.duration if entry is not None and entry.duration else 0.0
            time_sum += duration
            case = ET.SubElement(
                suite, "testcase", classname=_xml(f"domainrecon.{family}"), name=name, time=f"{duration:.3f}"
            )
            counts["tests"] += 1
            if entry is not None and entry.status in ("failed", "timeout"):
                counts["errors"] += 1
                err = ET.SubElement(
                    case, "error", message=_xml(entry.error or entry.status), type=entry.status
                )
                err.text = _xml(entry.error or entry.status)
            elif entry is not None and entry.status == "skipped":
                counts["skipped"] += 1
                ET.SubElement(case, "skipped", message=_xml(entry.error or ""))
            for f in by_module.get(name, []):
                counts["failures"] += 1
                failure = ET.SubElement(
                    case, "failure", message=_xml(f"[{f.severity}] {f.message}"), type=f.severity
                )
                failure.text = _xml(f.message)
        suite.set("tests", str(counts["tests"]))
        suite.set("failures", str(counts["failures"]))
        suite.set("errors", str(counts["errors"]))
        suite.set("skipped", str(counts["skipped"]))
        suite.set("time", f"{time_sum:.3f}")
        for key, value in counts.items():
            totals[key] += value
        total_time += time_sum
    for key, value in totals.items():
        root.set(key, str(value))
    root.set("time", f"{total_time:.3f}")
    ET.indent(root)
    return '<?xml version="1.0" encoding="UTF-8"?>\n' + ET.tostring(root, encoding="unicode") + "\n"
