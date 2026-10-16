# =============================================================================
# DomainRecon - Tests du générateur de rapports (domainrecon/reports)
# =============================================================================
# Un test par format (JSON, CSV, Markdown, HTML, PDF, SARIF, JUnit, texte),
# langues FR et EN, neutralisation des contenus hostiles, nom de fichier.
# Aucun accès réseau.
# =============================================================================

import copy
import csv
import io
import json
import re
import xml.etree.ElementTree as ET

import pytest

from domainrecon import reports
from domainrecon.reports.labels import tr
from domainrecon.reports.model import build_report_data, prune, summary_lines
from domainrecon.reports.structured import to_csv


def _text(payload, fmt, lang="fr"):
    report = reports.generate(payload, fmt, lang)
    return report.content.decode("utf-8-sig")


def test_formats_declares():
    assert reports.FORMATS == ("json", "csv", "md", "html", "pdf", "sarif", "junit")
    assert reports.CLI_FORMATS[0] == "text"


def test_format_inconnu_et_pdf_synchrone(payload):
    with pytest.raises(ValueError, match="Format inconnu"):
        reports.generate(payload, "docx")
    with pytest.raises(ValueError, match="asynchrone"):
        reports.generate(payload, "pdf")


def test_mime_et_extension(payload):
    attendus = {
        "json": ("application/json", "json"),
        "csv": ("text/csv", "csv"),
        "md": ("text/markdown", "md"),
        "html": ("text/html", "html"),
        "sarif": ("application/sarif+json", "sarif"),
        "junit": ("application/xml", "xml"),
        "text": ("text/plain", "txt"),
    }
    for fmt, (mime, ext) in attendus.items():
        report = reports.generate(payload, fmt)
        assert report.mime.startswith(mime)
        assert report.extension == ext
        assert reports.export_filename(payload, fmt).endswith(f".{ext}")


def test_nom_de_fichier_sur(payload):
    hostile = dict(payload, domain='a/b\\c"d e.com', id=7)
    assert reports.export_filename(hostile, "json") == "domainrecon-a_b_c_d_e.com-7.json"


# --- JSON -------------------------------------------------------------------


def test_json_scan_complet_et_entete(payload):
    doc = json.loads(_text(payload, "json"))
    assert doc["report"]["generator"] == "DomainRecon"
    assert doc["report"]["lang"] == "fr"
    assert doc["scan"]["id"] == payload["id"]
    assert doc["scan"]["domain"] == payload["domain"]
    assert doc["scan"]["findings"], "les constats sont inclus"
    # Messages rendus : plus aucun {"$t": …}.
    assert '"$t"' not in json.dumps(doc)


def test_json_langue(payload):
    fr = json.loads(_text(payload, "json", "fr"))["scan"]["findings"][0]["message"]
    en = json.loads(_text(payload, "json", "en"))["scan"]["findings"][0]["message"]
    assert fr != en and "6379" in fr and "6379" in en


# --- CSV --------------------------------------------------------------------


def test_csv_constats_et_modules(payload):
    raw = reports.generate(payload, "csv").content
    assert raw.startswith(b"\xef\xbb\xbf"), "BOM pour Excel"
    rows = list(csv.DictReader(io.StringIO(raw.decode("utf-8-sig"))))
    findings = [r for r in rows if r["type"] == "finding"]
    modules = [r for r in rows if r["type"] == "module"]
    assert len(findings) == len(payload["findings"])
    assert findings[0]["severity"] == "critical" and findings[0]["module"] == "open_ports"
    assert {m["module"]: m["status"] for m in modules}["waf"] == "failed"
    assert all(r["domain"] == payload["domain"] for r in rows)


def test_csv_neutralise_les_formules(payload):
    data = build_report_data(payload)
    data.findings[0].message = '=HYPERLINK("http://x")'
    rows = list(csv.DictReader(io.StringIO(to_csv(data))))
    assert rows[0]["message"].startswith("'=")


# --- Markdown ---------------------------------------------------------------


def test_markdown_structure(payload):
    md = _text(payload, "md")
    assert md.startswith("# Rapport DomainRecon : ")
    for titre in ("## Résumé", "## Familles de contrôles", "## Points à corriger", "## Annexe technique"):
        assert titre in md
    assert "**Note globale : B**" in md
    # Résumé avant annexe.
    assert md.index("## Résumé") < md.index("## Annexe technique")
    assert "```json" in md


def test_markdown_anglais(payload):
    md = _text(payload, "md", "en")
    assert md.startswith("# DomainRecon report : ") and "## Technical appendix" in md


def test_markdown_echappe_tableaux_et_blocs(payload):
    data = build_report_data(payload)
    from domainrecon.reports.markdown import to_markdown

    data.findings[0].message = "a | b\nligne"
    data.modules[0].data = {"x": "``` fin de bloc"}
    data.modules[0].status = "ok"
    md = to_markdown(data)
    assert "a \\| b ligne" in md
    assert "````json" in md  # délimiteur plus long que le contenu


# --- HTML -------------------------------------------------------------------


def test_html_autonome(payload):
    page = _text(payload, "html")
    assert page.startswith("<!doctype html>")
    assert "<style>" in page and "<script" not in page.lower()
    # Aucune ressource externe : ni src/href, ni @import, ni url() hors data:.
    assert not re.search(r"""(?:src|href)\s*=\s*["'](?!data:)""", page)
    assert "@import" not in page and "url(" not in page
    assert "<h1>Rapport DomainRecon</h1>" in page
    assert page.index('id="summary"') < page.index('id="annex"')
    assert 'class="grade"' in page and ">B<" in page


def test_html_resume_lisible(payload):
    page = _text(payload, "html", "en")
    assert "Good level of protection" in page and 'lang="en"' in page


def test_html_echappe_le_contenu_hostile(payload):
    hostile = copy.deepcopy(payload)
    hostile["findings"][0]["message"] = "<script>alert(1)</script>"
    hostile["domain"] = "<img src=x onerror=alert(1)>"
    page = _text(hostile, "html")
    assert "<script" not in page.lower() and "<img src=x" not in page
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in page


def test_html_inclut_la_capture_en_data_uri(payload, tmp_path, monkeypatch):
    from domainrecon.api import storage as stockage_api
    from domainrecon.core import config

    png = b"\x89PNG\r\n\x1a\n" + b"0" * 20
    monkeypatch.setattr(stockage_api, "SCREENSHOTS_DIR", config.SCREENSHOTS_DIR)
    config.SCREENSHOTS_DIR.mkdir(parents=True, exist_ok=True)
    name = "rapport_test_1700000000.png"
    (config.SCREENSHOTS_DIR / name).write_bytes(png)
    try:
        page = _text(dict(payload, screenshot_path=name), "html")
    finally:
        (config.SCREENSHOTS_DIR / name).unlink()
    assert 'src="data:image/png;base64,' in page


# --- SARIF ------------------------------------------------------------------


def test_sarif_2_1_0(payload):
    doc = json.loads(_text(payload, "sarif"))
    assert doc["version"] == "2.1.0" and doc["$schema"].endswith("sarif-2.1.0.json")
    run = doc["runs"][0]
    assert run["tool"]["driver"]["name"] == "DomainRecon"
    results = run["results"]
    assert len(results) == len(payload["findings"])
    rules = {r["id"]: r for r in run["tool"]["driver"]["rules"]}
    first = results[0]
    assert first["ruleId"] == payload["findings"][0]["message"]["$t"]
    assert rules[first["ruleId"]] is run["tool"]["driver"]["rules"][first["ruleIndex"]]
    assert first["level"] == "error"  # critique
    assert rules[first["ruleId"]]["properties"]["security-severity"] == "9.5"
    assert first["locations"][0]["logicalLocations"][0]["name"] == payload["domain"]
    assert first["partialFingerprints"]["domainrecon/v1"]
    assert {r["level"] for r in results} <= {"error", "warning", "note"}


# --- JUnit ------------------------------------------------------------------


def test_junit_une_suite_par_famille(payload):
    root = ET.fromstring(reports.generate(payload, "junit").content)
    assert root.tag == "testsuites"
    suites = {s.get("name"): s for s in root.findall("testsuite")}
    assert {"network", "tls"} <= set(suites)
    assert len(suites) == len(root.findall("testsuite"))
    failures = root.findall(".//failure")
    assert len(failures) == len(payload["findings"])
    assert int(root.get("failures")) == len(failures)
    network = suites["network"]
    case = next(c for c in network.findall("testcase") if c.get("name") == "open_ports")
    assert case.find("failure").get("type") == "critical"
    # Le module en échec (waf) est une erreur, pas un échec de constat.
    waf_case = next(c for s in suites.values() for c in s.findall("testcase") if c.get("name") == "waf")
    assert waf_case.find("error") is not None
    assert int(root.get("errors")) == 1
    for suite in suites.values():
        assert int(suite.get("tests")) == len(suite.findall("testcase"))


def test_junit_caracteres_interdits(payload):
    hostile = copy.deepcopy(payload)
    hostile["findings"][0]["message"] = "a\x00b\x0bc & <d>"
    ET.fromstring(reports.generate(hostile, "junit").content)  # XML valide


# --- Texte et modèle ----------------------------------------------------------


def test_texte_terminal(payload):
    text = _text(payload, "text")
    assert "Note globale" in text and "Points à corriger" in text
    assert "[Critique]" in text and "waf" in text


def test_resume_pour_non_expert(payload):
    lignes = summary_lines(build_report_data(payload, "fr"))
    assert any("Bon niveau" in ligne for ligne in lignes)
    assert any("point(s) à corriger" in ligne for ligne in lignes)
    assert any("en échec" in ligne for ligne in lignes)


def test_note_non_calculee(payload):
    sans_note = dict(payload, security_score={"grade": "A", "score": None})
    assert build_report_data(sans_note).grade == "N/A"
    assert any("non calculée" in ligne for ligne in summary_lines(build_report_data(sans_note)))


def test_prune_borne_la_taille():
    data = {
        "liste": list(range(500)),
        "texte": "x" * 5000,
        "prof": {"a": {"b": {"c": {"d": {"e": {"f": 1}}}}}},
    }
    out = prune(data)
    assert len(out["liste"]) == 41 and out["liste"][-1].startswith("…")
    assert len(out["texte"]) < 500
    assert out["prof"]["a"]["b"]["c"]["d"]["e"] == "…"


def test_libelles_fr_en_coherents():
    from domainrecon.reports.labels import LABELS

    assert LABELS["fr"].keys() == LABELS["en"].keys()
    assert tr("xx", "title") == "Rapport DomainRecon"
