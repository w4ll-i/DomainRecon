# =============================================================================
# DomainRecon - Rapports : modèle commun à tous les formats
# =============================================================================
# À partir de la charge utile d'un scan (api.routes.scans.scan_payload : messages
# non rendus, familles et constats compris), construit une vue unique que les
# formats se contentent de mettre en page : note, résumé, familles, constats
# (avec leur code de message, utile à SARIF), conseils de correction des modules
# qui ont relevé un constat (i18n/fix.py) et modules (état, durée, données).
# Les messages sont rendus dans la langue demandée. Les données brutes des
# modules sont élaguées (listes et textes longs coupés) pour garder un rapport
# lisible.
# =============================================================================

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone

from ..core.config import APP_VERSION
from ..i18n import is_msg, message, render
from ..i18n.fix import fix_steps, fix_texts, is_https_url, snippet_variants
from ..scanner import registry
from ..scanner.families import FAMILY_KEYS, NOT_LAUNCHED, module_run_status, module_value
from ..scanner.rules import SEVERITIES
from .labels import norm_lang, tr

GRADES = ("A", "B", "C", "D", "F")

# Élagage des données brutes affichées en annexe.
MAX_ITEMS = 40
MAX_DEPTH = 6
MAX_TEXT = 400


@dataclass
class FamilyEntry:
    key: str
    label: str
    state: str
    grade: str | None
    summary: str


@dataclass
class FindingEntry:
    code: str | None
    severity: str
    family: str | None
    module: str
    module_title: str
    message: str


@dataclass
class FixEntry:
    """« Comment corriger » d'un module (textes littéraux du catalogue, jamais des gabarits)."""

    module: str
    module_title: str
    steps: list[str]
    # Variantes de l'extrait : (libellé ou None, code).
    snippets: list[tuple[str | None, str]]
    ref: str | None


@dataclass
class ModuleEntry:
    name: str
    title: str
    family: str | None
    status: str
    duration: float | None
    error: str | None
    data: object = None


@dataclass
class ReportData:
    lang: str
    scan_id: int | None
    domain: str
    ip_address: str | None
    timestamp: str | None
    duration: float | None
    status: str
    profile: str | None
    tags: list[str]
    notes: str | None
    error_message: str | None
    grade: str
    score: float | int | None
    max_score: float | int | None
    coverage: float | int | None
    families: list[FamilyEntry]
    findings: list[FindingEntry]
    modules: list[ModuleEntry]
    generated_at: str
    version: str = APP_VERSION
    screenshot: str | None = None
    extra: dict = field(default_factory=dict)
    fixes: list[FixEntry] = field(default_factory=list)

    def t(self, key: str, **params) -> str:
        return tr(self.lang, key, **params)

    @property
    def failed_modules(self) -> int:
        return sum(1 for m in self.modules if m.status in ("failed", "timeout"))


def _num(value: object) -> float | int | None:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    return value


def _as_dict(value: object) -> dict:
    return value if isinstance(value, dict) else {}


def _text(value: object, lang: str) -> str | None:
    """Texte d'un message (ou texte brut d'un ancien scan) rendu dans `lang`."""
    if value is None or value == "":
        return None
    rendered = render(value, lang)
    return rendered if isinstance(rendered, str) else str(rendered)


def module_title(name: str, lang: str) -> str:
    """Titre d'aide d'un module dans `lang`, sinon son nom."""
    spec = registry.MODULES.get(name) or registry.COLUMN_MODULES.get(name)
    code = (spec.help_codes if spec is not None else {}).get("title")
    if not code:
        return name
    title = render(message(code), lang)
    return title if isinstance(title, str) and title != code else name


def module_family_of(name: str) -> str | None:
    spec = registry.MODULES.get(name) or registry.COLUMN_MODULES.get(name)
    return spec.family if spec is not None else None


def prune(value: object, depth: int = 0) -> object:
    """Copie élaguée d'une donnée JSON : profondeur, longueur des listes et des textes bornées."""
    if isinstance(value, str):
        return value if len(value) <= MAX_TEXT else value[:MAX_TEXT] + "…"
    if value is None or isinstance(value, (bool, int, float)):
        return value
    if depth >= MAX_DEPTH:
        return "…"
    if isinstance(value, dict):
        items = list(value.items())
        out = {str(k): prune(v, depth + 1) for k, v in items[:MAX_ITEMS]}
        if len(items) > MAX_ITEMS:
            out["…"] = f"+{len(items) - MAX_ITEMS}"
        return out
    if isinstance(value, (list, tuple)):
        out_list = [prune(v, depth + 1) for v in value[:MAX_ITEMS]]
        if len(value) > MAX_ITEMS:
            out_list.append(f"… +{len(value) - MAX_ITEMS}")
        return out_list
    return str(value)


def _families(payload: dict, lang: str) -> list[FamilyEntry]:
    raw = _as_dict(payload.get("families"))
    entries = []
    for key in FAMILY_KEYS:
        info = _as_dict(raw.get(key))
        if not info:
            continue
        grade = info.get("grade")
        entries.append(
            FamilyEntry(
                key=key,
                label=tr(lang, f"family.{key}"),
                state=str(info.get("state") or "unmeasured"),
                grade=grade if grade in GRADES else None,
                summary=_text(info.get("summary"), lang) or "",
            )
        )
    return entries


def _findings(payload: dict, lang: str) -> list[FindingEntry]:
    entries = []
    for item in payload.get("findings") or []:
        if not isinstance(item, dict) or item.get("severity") not in SEVERITIES:
            continue
        raw = item.get("message")
        module = str(item.get("module") or "")
        entries.append(
            FindingEntry(
                code=raw["$t"] if is_msg(raw) else None,
                severity=item["severity"],
                family=item.get("family"),
                module=module,
                module_title=module_title(module, lang) if module else "",
                message=_text(raw, lang) or "",
            )
        )
    return entries


def _fixes(findings: list[FindingEntry], lang: str) -> list[FixEntry]:
    """Conseils de correction des modules qui ont un constat, dans l'ordre des constats (un par module)."""
    entries: list[FixEntry] = []
    seen: set[str] = set()
    for finding in findings:
        name = finding.module
        if not name or name in seen:
            continue
        seen.add(name)
        texts = fix_texts(name, lang)
        steps = fix_steps(texts.get("fix", ""))
        if not steps:
            continue
        snippet = texts.get("fix_snippet")
        ref = texts.get("fix_ref")
        entries.append(
            FixEntry(
                module=name,
                module_title=finding.module_title or name,
                steps=steps,
                snippets=[v for v in snippet_variants(snippet) if v[1]] if snippet else [],
                ref=ref if is_https_url(ref) else None,
            )
        )
    return entries


def code_segments(step: str) -> list[tuple[bool, str]]:
    """Découpe une étape en segments (est_du_code, texte) : le code en ligne est entre accents graves."""
    parts = step.split("`")
    if len(parts) % 2 == 0:  # accent grave orphelin : tout en texte
        return [(False, step)]
    return [(i % 2 == 1, part) for i, part in enumerate(parts) if part]


def _modules(payload: dict, lang: str) -> list[ModuleEntry]:
    status_map = _as_dict(payload.get("module_status"))
    stored = _as_dict(payload.get("modules"))
    names = [*registry.MODULES, *(n for n in status_map if n not in registry.MODULES)]
    entries = []
    for name in names:
        status = module_run_status(payload, name)
        if status == NOT_LAUNCHED:
            continue
        duration = _num(_as_dict(stored.get(name)).get("duration"))
        error = _text(_as_dict(status_map.get(name)).get("error"), lang)
        data = prune(render(module_value(payload, name), lang)) if status == "ok" else None
        entries.append(
            ModuleEntry(
                name=name,
                title=module_title(name, lang),
                family=module_family_of(name),
                status=status,
                duration=duration,
                error=error,
                data=data,
            )
        )
    return entries


def build_report_data(payload: dict, lang: str = "fr", screenshot: str | None = None) -> ReportData:
    """Vue du rapport d'un scan (`payload` : api.routes.scans.scan_payload), textes dans `lang`."""
    lang = norm_lang(lang)
    score = _as_dict(payload.get("security_score"))
    grade = score.get("grade")
    value = _num(score.get("score"))
    # Note affichée comme dans l'interface : une lettre sans score reste « N/A ».
    shown = grade if grade in GRADES and value is not None else "N/A"
    tags = payload.get("tags")
    findings = _findings(payload, lang)
    return ReportData(
        lang=lang,
        scan_id=payload.get("id"),
        domain=str(payload.get("domain") or ""),
        ip_address=payload.get("ip_address"),
        timestamp=payload.get("scan_timestamp"),
        duration=_num(payload.get("scan_duration")),
        status=str(payload.get("status") or ""),
        profile=payload.get("profile"),
        tags=[str(t) for t in tags] if isinstance(tags, list) else [],
        notes=payload.get("notes"),
        error_message=_text(payload.get("error_message"), lang),
        grade=shown,
        score=value,
        max_score=_num(score.get("max_score")),
        coverage=_num(score.get("coverage")),
        families=_families(payload, lang),
        findings=findings,
        modules=_modules(payload, lang),
        generated_at=datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
        screenshot=screenshot,
        fixes=_fixes(findings, lang),
    )


def summary_lines(data: ReportData) -> list[str]:
    """Résumé en langage courant : portée, sens de la note, constats, couverture, état du scan."""
    lines = [data.t("sum.scope", domain=data.domain, id=data.scan_id if data.scan_id is not None else "?")]
    grade_key = f"grade.{data.grade}" if data.grade in GRADES else "grade.NA"
    lines.append(data.t(grade_key))
    if data.findings:
        counts = {s: sum(1 for f in data.findings if f.severity == s) for s in SEVERITIES}
        detail = ", ".join(f"{counts[s]} {data.t('severity.' + s).lower()}" for s in SEVERITIES if counts[s])
        lines.append(data.t("sum.findings", n=len(data.findings), detail=detail))
    else:
        lines.append(data.t("no_findings"))
    if data.coverage is not None:
        lines.append(data.t("sum.coverage", n=round(data.coverage)))
    if data.status == "error":
        lines.append(data.t("sum.error"))
    elif data.failed_modules:
        lines.append(data.t("sum.partial", n=data.failed_modules))
    return lines


def priorities(data: ReportData, limit: int = 5) -> list[FindingEntry]:
    """Constats à traiter d'abord (les plus graves ; l'ordre est celui de compute_findings)."""
    return data.findings[:limit]


def score_text(data: ReportData) -> str:
    """« 78/100 », ou « — » sans score."""
    if data.score is None:
        return "—"
    if data.max_score is None:
        return f"{data.score:g}"
    return f"{data.score:g}/{data.max_score:g}"
