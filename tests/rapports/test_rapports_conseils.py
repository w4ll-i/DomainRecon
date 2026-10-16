# =============================================================================
# DomainRecon - Tests du « Comment corriger » dans les rapports (HTML, Markdown, PDF)
# =============================================================================
# Chaque module qui a relevé un constat a sa section de correction : étapes
# numérotées, extrait à copier (une variante par plateforme), adresse de la
# documentation officielle en texte. Textes du catalogue (i18n/fix.py), échappés.
# =============================================================================

import re

import pytest

from domainrecon import reports
from domainrecon.i18n.fix import fix_steps, fix_texts
from domainrecon.reports import model
from domainrecon.reports.markdown import to_markdown
from domainrecon.reports.model import build_report_data, code_segments
from domainrecon.reports.webpage import to_html


def _text(payload, fmt, lang="fr"):
    return reports.generate(payload, fmt, lang).content.decode("utf-8-sig")


def _section(page: str) -> str:
    match = re.search(r'<section id="fixes">(.*?)</section>', page, re.S)
    assert match, "section « Comment corriger » absente"
    return match.group(1)


def test_un_conseil_par_module_avec_constat(payload):
    data = build_report_data(payload)
    modules = list(dict.fromkeys(f.module for f in data.findings if f.module))
    assert modules, "la charge de test doit avoir des constats"
    # Les 84 modules ont leur conseil : un par module en constat, dans l'ordre des constats.
    assert [f.module for f in data.fixes] == modules
    for entry in data.fixes:
        assert entry.steps == fix_steps(fix_texts(entry.module, "fr")["fix"])
        assert entry.module_title and entry.module_title != entry.module
        assert entry.ref is None or entry.ref.startswith("https://")
        assert all(code for _, code in entry.snippets)


def test_aucun_conseil_sans_constat(payload):
    data = build_report_data(dict(payload, findings=[]))
    assert data.fixes == []
    page = to_html(data)
    assert 'id="fixes"' not in page
    assert "## Comment corriger" not in to_markdown(data)


def test_html_montre_les_etapes_l_extrait_et_la_documentation(payload):
    page = _text(payload, "html")
    section = _section(page)
    assert "<h2>Comment corriger</h2>" in section
    data = build_report_data(payload)
    first = data.fixes[0]
    # Étapes numérotées par la liste, code en ligne sans accent grave.
    assert section.count("<ol>") == len(data.fixes)
    assert section.count("<li>") == sum(len(f.steps) for f in data.fixes)
    assert "`" not in re.sub(r"<pre>.*?</pre>", "", section, flags=re.S)
    if any("`" in step for step in first.steps):
        assert "<li>" in section and "<code>" in section
    # Extrait : un bloc <pre> par variante, libellé au-dessus, ligne « # libellé » retirée du code.
    variants = sum(len(f.snippets) for f in data.fixes)
    assert section.count("<pre><code>") == variants
    for entry in data.fixes:
        for label, _ in entry.snippets:
            if label:
                assert f'<p class="variant">{label}</p>' in section
    # Documentation : l'adresse en texte, jamais un lien (rapport sans référence externe).
    refs = [f.ref for f in data.fixes if f.ref]
    assert refs
    for ref in refs:
        assert f"Documentation officielle : {ref}" in section
    assert "<a " not in section
    # Ordre du rapport : constats, puis correction, puis annexe.
    assert page.index('id="findings"') < page.index('id="fixes"') < page.index('id="annex"')


def test_html_conseil_en_anglais(payload):
    section = _section(_text(payload, "html", "en"))
    assert "<h2>How to fix</h2>" in section
    data = build_report_data(payload, "en")
    assert data.fixes[0].steps == fix_steps(fix_texts(data.fixes[0].module, "en")["fix"])
    assert data.fixes[0].steps != fix_steps(fix_texts(data.fixes[0].module, "fr")["fix"])
    assert "Official documentation : https://" in section


def test_html_echappe_le_catalogue(payload, monkeypatch):
    hostile = {
        "fix": "Ouvrez `<script>alert(1)</script>` puis relancez.\n<img src=x onerror=alert(1)>",
        "fix_snippet": '# nginx\nserver { add_header X "<b>"; }\n\n# Apache\nHeader set X "1"',
        "fix_ref": "javascript:alert(1)",
    }
    monkeypatch.setattr(model, "fix_texts", lambda name, lang: hostile)
    page = to_html(build_report_data(payload))
    section = _section(page)
    assert "<script" not in page.lower() and "<img src=x" not in page and "<b>" not in section
    assert "<code>&lt;script&gt;alert(1)&lt;/script&gt;</code>" in section
    assert "&lt;img src=x onerror=alert(1)&gt;" in section
    # Accolades gardées telles quelles, deux variantes.
    assert "server { add_header X &quot;&lt;b&gt;&quot;; }" in section
    assert '<p class="variant">nginx</p>' in section and '<p class="variant">Apache</p>' in section
    # Une adresse qui n'est pas en https n'est pas reprise.
    assert "javascript:" not in page


def test_markdown_section_de_correction(payload):
    md = _text(payload, "md")
    assert "## Comment corriger" in md
    assert (
        md.index("## Points à corriger") < md.index("## Comment corriger") < md.index("## Annexe technique")
    )
    data = build_report_data(payload)
    first = data.fixes[0]
    assert f"### {first.module_title} (`{first.module}`)" in md
    assert f"1. {first.steps[0]}" in md
    if first.ref:
        assert f"Documentation officielle : <{first.ref}>" in md
    md_en = _text(payload, "md", "en")
    assert "## How to fix" in md_en


def test_markdown_extrait_avec_accents_graves(payload, monkeypatch):
    monkeypatch.setattr(
        model, "fix_texts", lambda name, lang: {"fix": "Une étape.", "fix_snippet": "echo ```fin```"}
    )
    md = to_markdown(build_report_data(payload))
    assert "````\necho ```fin```\n````" in md


@pytest.mark.parametrize(
    ("step", "segments"),
    [
        ("Sans code.", [(False, "Sans code.")]),
        (
            "Ajoutez `X: 1` puis `Y`.",
            [(False, "Ajoutez "), (True, "X: 1"), (False, " puis "), (True, "Y"), (False, ".")],
        ),
        ("`dig` d'abord", [(True, "dig"), (False, " d'abord")]),
        ("Accent ` orphelin", [(False, "Accent ` orphelin")]),
    ],
)
def test_code_segments(step, segments):
    assert code_segments(step) == segments
