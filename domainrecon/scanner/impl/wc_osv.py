# =============================================================================
# DomainRecon - Contenu web : interrogation d'OSV.dev (vulnérabilités connues)
# =============================================================================
# Source : https://google.github.io/osv.dev/api/ - POST https://api.osv.dev/v1/query
# {"package": {"name": "jquery", "ecosystem": "npm"}, "version": "3.0.0"}. Gratuit,
# sans clé ; OSV calcule lui-même si la version est touchée (bornes introduced /
# fixed de chaque avis), nous n'avons qu'à lui donner un nom de paquet exact et
# une version exacte. Écosystèmes utilisés : npm, PyPI, Packagist, RubyGems.
#
# Piège évité : OSV met dans `severity[].score` un VECTEUR CVSS
# (« CVSS:3.1/AV:N/… »), pas un nombre ; lu comme un nombre, la gravité resterait
# toujours « moyenne ». Ici : gravité de l'avis GitHub (database_specific),
# sinon score CVSS v3 recalculé depuis le vecteur.
#
# Aucune clé : le seul secret en jeu est absent. Les erreurs ne citent que le code
# HTTP (jamais le texte d'une exception httpx, qui contient l'URL).
# =============================================================================

import math

import httpx

from .. import common
from ..cache import MEDIUM_TTL, cached
from .wc_versions import compare_versions, parse_version

OSV_URL = "https://api.osv.dev/v1/query"
OSV_TIMEOUT = 10.0
# Pages lues au plus par paquet, et avis conservés par paquet.
MAX_PAGES = 3
MAX_VULNS = 10

# Écosystèmes acceptés (garde contre une valeur inattendue envoyée au service).
ECOSYSTEMS = ("npm", "PyPI", "Packagist", "RubyGems")

_SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}
_GHSA_SEVERITY = {
    "CRITICAL": "critical",
    "HIGH": "high",
    "MODERATE": "medium",
    "MEDIUM": "medium",
    "LOW": "low",
}


class OsvError(Exception):
    """Échec d'une requête OSV : `kind` vaut « http », « quota », « invalid » ou « network »."""

    def __init__(self, kind: str, status: int | None = None):
        super().__init__(kind)
        self.kind = kind
        self.status = status


# --- Gravité --------------------------------------------------------------------------

_AV = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}
_AC = {"L": 0.77, "H": 0.44}
_UI = {"N": 0.85, "R": 0.62}
_CIA = {"H": 0.56, "L": 0.22, "N": 0.0}


def _roundup(value: float) -> float:
    return math.ceil(round(value * 10, 5)) / 10


def cvss3_score(vector: str) -> float | None:
    """Score de base d'un vecteur CVSS v3.x (« CVSS:3.1/AV:N/AC:L/… »), None si illisible ou autre version."""
    if not isinstance(vector, str) or not vector.startswith(("CVSS:3.0/", "CVSS:3.1/")):
        return None
    try:
        metrics = dict(part.split(":", 1) for part in vector.split("/")[1:])
        scope_changed = metrics["S"] == "C"
        privileges = {"N": 0.85, "L": 0.68 if scope_changed else 0.62, "H": 0.5 if scope_changed else 0.27}
        iss = 1 - (1 - _CIA[metrics["C"]]) * (1 - _CIA[metrics["I"]]) * (1 - _CIA[metrics["A"]])
        if scope_changed:
            impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15
        else:
            impact = 6.42 * iss
        exploitability = (
            8.22 * _AV[metrics["AV"]] * _AC[metrics["AC"]] * privileges[metrics["PR"]] * _UI[metrics["UI"]]
        )
    except (KeyError, ValueError):
        return None
    if impact <= 0:
        return 0.0
    total = impact + exploitability
    return _roundup(min(1.08 * total if scope_changed else total, 10))


def severity_from_score(score: float) -> str:
    if score >= 9.0:
        return "critical"
    if score >= 7.0:
        return "high"
    if score >= 4.0:
        return "medium"
    return "low"


def vuln_severity(vuln: dict) -> str:
    """Gravité d'un avis OSV : avis GitHub, sinon vecteur CVSS v3 ; « medium » à défaut de donnée."""
    database = vuln.get("database_specific")
    if isinstance(database, dict):
        label = database.get("severity")
        if isinstance(label, str) and label.upper() in _GHSA_SEVERITY:
            return _GHSA_SEVERITY[label.upper()]
    best: float | None = None
    for entry in vuln.get("severity") or []:
        if not isinstance(entry, dict):
            continue
        score = cvss3_score(entry.get("score"))
        if score is not None and (best is None or score > best):
            best = score
    return severity_from_score(best) if best is not None else "medium"


# --- Lecture d'un avis ------------------------------------------------------------------


def _fixed_version(vuln: dict, ecosystem: str, package: str, version: str) -> str | None:
    """Plus petite version corrigée supérieure à `version` pour ce paquet, si l'avis la donne."""
    candidates: list[str] = []
    for affected in vuln.get("affected") or []:
        if not isinstance(affected, dict):
            continue
        pkg = affected.get("package") or {}
        if (
            str(pkg.get("name", "")).lower() != package.lower()
            or str(pkg.get("ecosystem", "")).split(":")[0] != ecosystem
        ):
            continue
        for rng in affected.get("ranges") or []:
            for event in (rng or {}).get("events") or []:
                fixed = event.get("fixed") if isinstance(event, dict) else None
                if isinstance(fixed, str) and compare_versions(fixed, version) == 1:
                    candidates.append(fixed)
    if not candidates:
        return None
    candidates.sort(key=lambda text: _version_key(text))
    return candidates[0]


def _version_key(text: str) -> tuple:
    parsed = parse_version(text)
    return (parsed[0], not parsed[1]) if parsed else ((10**9,), True)


def normalize(vulns: list, ecosystem: str, package: str, version: str) -> list[dict]:
    """Avis OSV -> [{id, cve, severity, summary, fixed, url}], sans doublon, du plus grave au moins grave."""
    seen: set[str] = set()
    result: list[dict] = []
    for vuln in vulns:
        if not isinstance(vuln, dict) or vuln.get("withdrawn") or not isinstance(vuln.get("id"), str):
            continue
        aliases = [a for a in (vuln.get("aliases") or []) if isinstance(a, str)]
        cve = next(
            (a for a in aliases if a.startswith("CVE-")),
            vuln["id"] if vuln["id"].startswith("CVE-") else None,
        )
        key = cve or vuln["id"]
        if key in seen:
            continue
        seen.add(key)
        summary = vuln.get("summary") or str(vuln.get("details") or "").strip().split("\n", 1)[0]
        result.append(
            {
                "id": vuln["id"][:60],
                "cve": cve,
                "severity": vuln_severity(vuln),
                "summary": str(summary)[:200],
                "fixed": _fixed_version(vuln, ecosystem, package, version),
                "url": f"https://osv.dev/vulnerability/{vuln['id']}"[:200],
            }
        )
    result.sort(key=lambda v: (_SEVERITY_ORDER.get(v["severity"], 9), v["id"]))
    return result[:MAX_VULNS]


# --- Requête ------------------------------------------------------------------------------


@cached(MEDIUM_TTL, scope=common.proxy_scope, ignore=("client",))
async def lookup(client: httpx.AsyncClient, ecosystem: str, package: str, version: str) -> list[dict]:
    """Vulnérabilités connues d'un paquet à une version exacte. Lève OsvError."""
    if ecosystem not in ECOSYSTEMS:
        raise OsvError("invalid")
    body = {"package": {"name": package, "ecosystem": ecosystem}, "version": version}
    raw: list = []
    for _ in range(MAX_PAGES):
        try:
            response = await client.post(OSV_URL, json=body, timeout=OSV_TIMEOUT)
        except httpx.HTTPError:
            raise OsvError("network") from None
        if response.status_code == 429:
            raise OsvError("quota", 429)
        if response.status_code != 200:
            raise OsvError("http", response.status_code)
        try:
            data = response.json()
        except ValueError:
            raise OsvError("invalid") from None
        if not isinstance(data, dict):
            raise OsvError("invalid")
        page = data.get("vulns") or []
        if not isinstance(page, list):
            raise OsvError("invalid")
        raw.extend(page)
        token = data.get("next_page_token")
        if not token or not isinstance(token, str):
            break
        body = {**body, "page_token": token}
    return normalize(raw, ecosystem, package, version)
