# =============================================================================
# DomainRecon - Rapports : Markdown et texte brut
# =============================================================================

from __future__ import annotations

import json

from .model import ReportData, priorities, score_text, summary_lines


def _cell(text: object) -> str:
    """Texte sûr dans une cellule de tableau Markdown."""
    return str(text if text is not None else "").replace("|", "\\|").replace("\r", " ").replace("\n", " ")


def _fence(body: str) -> str:
    """Délimiteur de bloc de code plus long que toute suite de ` du contenu."""
    longest = 0
    run = 0
    for char in body:
        run = run + 1 if char == "`" else 0
        longest = max(longest, run)
    return "`" * max(3, longest + 1)


def _seconds(data: ReportData, value: float | None) -> str:
    return "" if value is None else f"{value:.1f} {data.t('seconds')}"


def to_markdown(data: ReportData) -> str:
    t = data.t
    out: list[str] = [f"# {t('title')} : {data.domain}", ""]
    meta = [
        f"- **{t('scanned_on')}** : {data.timestamp or t('unknown')}",
        f"- **{t('ip')}** : {data.ip_address or t('unknown')}",
        f"- **{t('profile')}** : {data.profile or t('unknown')}",
        f"- **{t('scan_status')}** : {t('scan.' + data.status) if data.status else t('unknown')}",
    ]
    if data.duration is not None:
        meta.append(f"- **{t('scan_duration')}** : {_seconds(data, data.duration)}")
    if data.tags:
        meta.append(f"- **{t('tags')}** : {', '.join(data.tags)}")
    meta.append(f"- **{t('generated')}** : {data.generated_at} (DomainRecon {data.version})")
    out += [*meta, ""]

    out += [f"## {t('summary')}", ""]
    out += [f"**{t('grade')} : {data.grade}** ({t('score')} {score_text(data)})", ""]
    out += [f"- {line}" for line in summary_lines(data)]
    top = priorities(data)
    if top:
        out += ["", f"### {t('priorities')}", ""]
        out += [f"{i}. **{t('severity.' + f.severity)}** : {f.message}" for i, f in enumerate(top, 1)]
    out.append("")

    if data.families:
        out += [
            f"## {t('families')}",
            "",
            f"| {t('family')} | {t('state')} | {t('grade')} | {t('summary')} |",
        ]
        out.append("|---|---|---|---|")
        for fam in data.families:
            out.append(
                f"| {_cell(fam.label)} | {t('state.' + fam.state)} | {fam.grade or '—'} | {_cell(fam.summary)} |"
            )
        out.append("")

    out += [f"## {t('findings')}", ""]
    if data.findings:
        out += [f"| {t('severity')} | {t('family')} | {t('module')} | {t('message')} |", "|---|---|---|---|"]
        for f in data.findings:
            family = t("family." + f.family) if f.family else ""
            out.append(
                f"| {t('severity.' + f.severity)} | {_cell(family)} | {_cell(f.module_title or f.module)} "
                f"| {_cell(f.message)} |"
            )
    else:
        out.append(t("no_findings"))
    out.append("")

    if data.fixes:
        out += [f"## {t('fix.title')}", "", t("fix.intro"), ""]
        for entry in data.fixes:
            out += [f"### {entry.module_title} (`{entry.module}`)", ""]
            # Étapes du catalogue : le code en ligne y est déjà entre accents graves.
            out += [f"{i}. {step}" for i, step in enumerate(entry.steps, 1)]
            out.append("")
            for label, code in entry.snippets:
                if label:
                    out += [f"**{label}**", ""]
                fence = _fence(code)
                out += [fence, code, fence, ""]
            if entry.ref:
                out += [f"{t('fix.ref')} : <{entry.ref}>", ""]

    out += [f"## {t('modules')}", "", f"| {t('module')} | {t('family')} | {t('status')} | {t('duration')} |"]
    out.append("|---|---|---|---|")
    for m in data.modules:
        family = t("family." + m.family) if m.family else ""
        out.append(
            f"| {_cell(m.title)} (`{m.name}`) | {_cell(family)} | {t('status.' + m.status)} "
            f"| {_seconds(data, m.duration)} |"
        )
    out.append("")

    out += [f"## {t('annex')}", "", t("annex_intro"), ""]
    for m in data.modules:
        out += [f"### {m.title} (`{m.name}`)", ""]
        if m.status != "ok":
            out += [f"{t('status.' + m.status)}" + (f" : {m.error}" if m.error else ""), ""]
            continue
        if m.data in (None, {}, []):
            out += [t("no_data"), ""]
            continue
        body = json.dumps(m.data, ensure_ascii=False, indent=2, default=str)
        fence = _fence(body)
        out += [f"{fence}json", body, fence, ""]
    return "\n".join(out).rstrip("\n") + "\n"


def to_text(data: ReportData) -> str:
    """Rendu texte sobre pour le terminal (sans annexe technique)."""
    t = data.t
    lines = [
        f"{t('title')} - {data.domain}",
        "=" * 60,
        f"{t('scanned_on'):<26}{data.timestamp or t('unknown')}",
        f"{t('ip'):<26}{data.ip_address or t('unknown')}",
        f"{t('profile'):<26}{data.profile or t('unknown')}",
        f"{t('grade'):<26}{data.grade} ({score_text(data)})",
        "",
    ]
    lines += [f"  {line}" for line in summary_lines(data)]
    if data.families:
        lines += ["", t("families"), "-" * 60]
        for fam in data.families:
            grade = fam.grade or "-"
            lines.append(f"  {fam.label:<24}{t('state.' + fam.state):<16}{grade}")
    lines += ["", t("findings"), "-" * 60]
    if data.findings:
        for f in data.findings:
            lines.append(f"  [{t('severity.' + f.severity)}] {f.message}")
    else:
        lines.append(f"  {t('no_findings')}")
    lines += ["", t("modules"), "-" * 60]
    for m in data.modules:
        extra = f"  {m.error}" if m.error and m.status != "ok" else ""
        lines.append(f"  {m.name:<28}{t('status.' + m.status):<16}{_seconds(data, m.duration)}{extra}")
    return "\n".join(lines) + "\n"
