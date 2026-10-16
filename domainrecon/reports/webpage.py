# =============================================================================
# DomainRecon - Rapports : page HTML autonome
# =============================================================================
# Une seule page : CSS embarqué, aucun script, aucune requête réseau (la capture
# d'écran éventuelle est incluse en data:). Style monochrome sobre. Un résumé
# en langage courant d'abord, les points à corriger et la façon de les corriger,
# puis l'annexe technique module par module. L'adresse de la documentation est
# écrite en texte, sans lien : la page ne référence aucune ressource externe.
# Tout texte venu du scan est échappé.
# =============================================================================

from __future__ import annotations

from html import escape

from .model import FixEntry, ReportData, code_segments, priorities, score_text, summary_lines

CSS = """
:root{color-scheme:light}
*{box-sizing:border-box}
body{margin:0;background:#fff;color:#111;font:15px/1.5 system-ui,-apple-system,"Segoe UI",Roboto,Arial,sans-serif}
main{max-width:56rem;margin:0 auto;padding:2rem 1.25rem 3rem}
h1{font-size:1.6rem;margin:0 0 .25rem}
h2{font-size:1.2rem;margin:2.2rem 0 .75rem;padding-bottom:.35rem;border-bottom:2px solid #111}
h3{font-size:1rem;margin:1.5rem 0 .5rem}
p{margin:.4rem 0}
.meta{color:#555;margin:0}
.hero{display:flex;gap:1.25rem;align-items:center;margin:1rem 0;padding:1rem;border:2px solid #111}
.grade{font-size:3.2rem;font-weight:700;line-height:1;min-width:4.5rem;text-align:center;border-right:1px solid #999;padding-right:1.25rem}
.hero ul{margin:0;padding-left:1.1rem}
table{width:100%;border-collapse:collapse;margin:.5rem 0;font-size:.93rem}
th,td{text-align:left;vertical-align:top;padding:.4rem .6rem;border:1px solid #bbb}
th{background:#eee;font-weight:600}
.sev{font-weight:700;white-space:nowrap}
.sev-critical{text-transform:uppercase;text-decoration:underline}
.sev-high{text-transform:uppercase}
.sev-low{font-weight:400}
.muted{color:#666}
code{font:.88em ui-monospace,SFMono-Regular,Consolas,monospace;background:#f2f2f2;padding:0 .25em}
.module{margin:1.2rem 0;padding-top:.6rem;border-top:1px solid #ccc;break-inside:avoid-page}
.kv th{width:28%;font-weight:600;background:#f7f7f7}
.kv table{margin:0}
ul.data,ol.data{margin:0;padding-left:1.2rem}
img.shot{max-width:100%;border:1px solid #999;margin:.5rem 0}
.fix{margin:1.2rem 0;break-inside:avoid-page}
.fix ol{margin:.3rem 0;padding-left:1.4rem}
pre{margin:.3rem 0 .6rem;padding:.6rem .75rem;background:#f2f2f2;border:1px solid #ccc;white-space:pre-wrap;overflow-wrap:anywhere;font:.85em/1.45 ui-monospace,SFMono-Regular,Consolas,monospace}
pre code{background:none;padding:0;font:inherit}
.variant{margin:.5rem 0 0;font-weight:600}
.ref{overflow-wrap:anywhere}
footer{margin-top:3rem;padding-top:.75rem;border-top:1px solid #ccc;color:#666;font-size:.85rem}
@media print{main{max-width:none;padding:0}h2{break-after:avoid}tr{break-inside:avoid}}
"""


def _e(value: object) -> str:
    return escape("" if value is None else str(value), quote=True)


def _data(value: object) -> str:
    """Donnée JSON élaguée en HTML : tableaux clé/valeur, listes, texte."""
    if isinstance(value, dict):
        if not value:
            return '<span class="muted">—</span>'
        rows = "".join(f"<tr><th>{_e(k)}</th><td>{_data(v)}</td></tr>" for k, v in value.items())
        return f'<table class="kv">{rows}</table>'
    if isinstance(value, list):
        if not value:
            return '<span class="muted">—</span>'
        if all(not isinstance(v, (dict, list)) for v in value):
            return _e(", ".join("" if v is None else str(v) for v in value))
        return '<ol class="data">' + "".join(f"<li>{_data(v)}</li>" for v in value) + "</ol>"
    if value is None:
        return '<span class="muted">—</span>'
    if isinstance(value, bool):
        return "true" if value else "false"
    return _e(value)


def _step(step: str) -> str:
    return "".join(f"<code>{_e(text)}</code>" if code else _e(text) for code, text in code_segments(step))


def _fix(entry: FixEntry, t) -> str:
    out = [f'<div class="fix"><h3>{_e(entry.module_title)} <code>{_e(entry.module)}</code></h3>']
    out.append("<ol>" + "".join(f"<li>{_step(s)}</li>" for s in entry.steps) + "</ol>")
    if entry.snippets:
        out.append(f'<p class="variant">{_e(t("fix.snippet"))}</p>')
        for label, code in entry.snippets:
            if label:
                out.append(f'<p class="variant">{_e(label)}</p>')
            out.append(f"<pre><code>{_e(code)}</code></pre>")
    if entry.ref:
        out.append(f'<p class="ref">{_e(t("fix.ref"))} : {_e(entry.ref)}</p>')
    out.append("</div>")
    return "".join(out)


def to_html(data: ReportData) -> str:
    t = data.t
    meta_rows = [
        (t("scanned_on"), data.timestamp or t("unknown")),
        (t("ip"), data.ip_address or t("unknown")),
        (t("profile"), data.profile or t("unknown")),
        (t("scan_status"), t("scan." + data.status) if data.status else t("unknown")),
    ]
    if data.duration is not None:
        meta_rows.append((t("scan_duration"), f"{data.duration:.1f} {t('seconds')}"))
    if data.tags:
        meta_rows.append((t("tags"), ", ".join(data.tags)))
    meta_table = "".join(f"<tr><th>{_e(k)}</th><td>{_e(v)}</td></tr>" for k, v in meta_rows)

    parts: list[str] = []
    parts.append(f'<header><h1>{_e(t("title"))}</h1><p class="meta">{_e(data.domain)}</p></header>')

    summary = "".join(f"<li>{_e(line)}</li>" for line in summary_lines(data))
    parts.append(
        f'<section id="summary"><h2>{_e(t("summary"))}</h2>'
        f'<div class="hero"><div class="grade" aria-label="{_e(t("grade"))}">{_e(data.grade)}</div>'
        f"<div><p><strong>{_e(t('score'))} : {_e(score_text(data))}</strong></p><ul>{summary}</ul></div></div>"
    )
    top = priorities(data)
    if top:
        items = "".join(
            f'<li><span class="sev sev-{_e(f.severity)}">{_e(t("severity." + f.severity))}</span> : {_e(f.message)}</li>'
            for f in top
        )
        parts.append(f"<h3>{_e(t('priorities'))}</h3><ol>{items}</ol>")
    parts.append(f'<table class="kv">{meta_table}</table>')
    if data.error_message:
        parts.append(f"<p><strong>{_e(t('error'))}</strong> : {_e(data.error_message)}</p>")
    if data.screenshot:
        parts.append(f'<h3>{_e(t("screenshot"))}</h3><img class="shot" alt="" src="{_e(data.screenshot)}">')
    parts.append("</section>")

    if data.families:
        rows = "".join(
            f"<tr><td>{_e(f.label)}</td><td>{_e(t('state.' + f.state))}</td><td>{_e(f.grade or '—')}</td>"
            f"<td>{_e(f.summary)}</td></tr>"
            for f in data.families
        )
        parts.append(
            f'<section id="families"><h2>{_e(t("families"))}</h2><table><tr><th>{_e(t("family"))}</th>'
            f"<th>{_e(t('state'))}</th><th>{_e(t('grade'))}</th><th>{_e(t('summary'))}</th></tr>{rows}</table></section>"
        )

    parts.append(f'<section id="findings"><h2>{_e(t("findings"))}</h2>')
    if data.findings:
        rows = "".join(
            f'<tr><td class="sev sev-{_e(f.severity)}">{_e(t("severity." + f.severity))}</td>'
            f"<td>{_e(t('family.' + f.family) if f.family else '')}</td>"
            f"<td>{_e(f.module_title or f.module)}</td><td>{_e(f.message)}</td></tr>"
            for f in data.findings
        )
        parts.append(
            f"<table><tr><th>{_e(t('severity'))}</th><th>{_e(t('family'))}</th><th>{_e(t('module'))}</th>"
            f"<th>{_e(t('message'))}</th></tr>{rows}</table>"
        )
    else:
        parts.append(f"<p>{_e(t('no_findings'))}</p>")
    parts.append("</section>")

    if data.fixes:
        parts.append(
            f'<section id="fixes"><h2>{_e(t("fix.title"))}</h2><p class="muted">{_e(t("fix.intro"))}</p>'
        )
        parts.extend(_fix(entry, t) for entry in data.fixes)
        parts.append("</section>")

    rows = "".join(
        f"<tr><td>{_e(m.title)} <code>{_e(m.name)}</code></td>"
        f"<td>{_e(t('family.' + m.family) if m.family else '')}</td><td>{_e(t('status.' + m.status))}</td>"
        f"<td>{'' if m.duration is None else _e(f'{m.duration:.1f} ' + t('seconds'))}</td></tr>"
        for m in data.modules
    )
    parts.append(
        f'<section id="modules"><h2>{_e(t("modules"))}</h2><table><tr><th>{_e(t("module"))}</th>'
        f"<th>{_e(t('family'))}</th><th>{_e(t('status'))}</th><th>{_e(t('duration'))}</th></tr>{rows}</table></section>"
    )

    parts.append(f'<section id="annex"><h2>{_e(t("annex"))}</h2><p class="muted">{_e(t("annex_intro"))}</p>')
    for m in data.modules:
        parts.append(f'<div class="module"><h3>{_e(m.title)} <code>{_e(m.name)}</code></h3>')
        if m.status != "ok":
            detail = f" : {_e(m.error)}" if m.error else ""
            parts.append(f"<p>{_e(t('status.' + m.status))}{detail}</p>")
        elif m.data in (None, {}, []):
            parts.append(f'<p class="muted">{_e(t("no_data"))}</p>')
        else:
            parts.append(_data(m.data))
        parts.append("</div>")
    parts.append("</section>")

    parts.append(
        f"<footer>{_e(t('generated'))} {_e(data.generated_at)} - DomainRecon {_e(data.version)}</footer>"
    )

    return (
        f'<!doctype html>\n<html lang="{_e(data.lang)}"><head><meta charset="utf-8">'
        '<meta name="viewport" content="width=device-width, initial-scale=1">'
        f"<title>{_e(t('title'))} - {_e(data.domain)}</title><style>{CSS}</style></head>"
        f"<body><main>{''.join(parts)}</main></body></html>\n"
    )
