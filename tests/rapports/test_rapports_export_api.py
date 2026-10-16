# =============================================================================
# DomainRecon - Tests de l'export d'un scan (GET /api/scan/{id}/export) et du PDF
# =============================================================================
# Le PDF réel n'est testé que si le Chromium de Playwright est installé (sinon
# le test est sauté) ; les autres tests simulent la génération.
# =============================================================================

import asyncio
import json
import xml.etree.ElementTree as ET

import pytest
from fastapi.testclient import TestClient

from domainrecon import reports
from domainrecon.api.app import app


@pytest.fixture
def client():
    with TestClient(app) as c:
        yield c


ATTENDUS = {
    "json": ("application/json", ".json"),
    "csv": ("text/csv", ".csv"),
    "md": ("text/markdown", ".md"),
    "html": ("text/html", ".html"),
    "sarif": ("application/sarif+json", ".sarif"),
    "junit": ("application/xml", ".xml"),
}


@pytest.mark.parametrize("fmt", sorted(ATTENDUS))
def test_export_type_mime_et_nom(client, scan_id, fmt):
    r = client.get(f"/api/scan/{scan_id}/export", params={"format": fmt})
    assert r.status_code == 200
    mime, ext = ATTENDUS[fmt]
    assert r.headers["content-type"].startswith(mime)
    disposition = r.headers["content-disposition"]
    assert disposition.startswith('attachment; filename="domainrecon-')
    assert disposition.endswith(f'-{scan_id}{ext}"')
    assert r.headers["cache-control"] == "no-store"
    assert r.content


def test_export_contenus_valides(client, scan_id):
    assert json.loads(client.get(f"/api/scan/{scan_id}/export?format=json").content)["scan"]["id"] == scan_id
    assert json.loads(client.get(f"/api/scan/{scan_id}/export?format=sarif").content)["version"] == "2.1.0"
    assert ET.fromstring(client.get(f"/api/scan/{scan_id}/export?format=junit").content).tag == "testsuites"
    assert client.get(f"/api/scan/{scan_id}/export?format=html").text.startswith("<!doctype html>")


def test_export_langue(client, scan_id):
    fr = client.get(f"/api/scan/{scan_id}/export", params={"format": "md", "lang": "fr"}).text
    en = client.get(f"/api/scan/{scan_id}/export", params={"format": "md", "lang": "en"}).text
    assert "## Résumé" in fr and "## Summary" in en
    # Accept-Language est aussi suivi, comme pour le reste de l'API.
    auto = client.get(f"/api/scan/{scan_id}/export?format=md", headers={"Accept-Language": "en"}).text
    assert "## Summary" in auto


def test_export_scan_inconnu(client, stockage):
    r = client.get("/api/scan/99999999/export", params={"format": "json"})
    assert r.status_code == 404 and r.json()["code"] == "api.scan_not_found"


def test_export_format_invalide_ou_absent(client, scan_id):
    assert client.get(f"/api/scan/{scan_id}/export", params={"format": "docx"}).status_code == 422
    assert client.get(f"/api/scan/{scan_id}/export").status_code == 422


def test_export_pdf_simule(client, scan_id, monkeypatch):
    recu = {}

    async def faux_pdf(html):
        recu["html"] = html
        return b"%PDF-1.7 faux"

    monkeypatch.setattr(reports, "html_to_pdf", faux_pdf)
    r = client.get(f"/api/scan/{scan_id}/export", params={"format": "pdf"})
    assert r.status_code == 200
    assert r.headers["content-type"] == "application/pdf"
    assert r.headers["content-disposition"].endswith(f'-{scan_id}.pdf"')
    assert r.content.startswith(b"%PDF-")
    # Le PDF est imprimé depuis la page HTML du rapport.
    assert recu["html"].startswith("<!doctype html>")


def test_export_pdf_sans_chromium(client, scan_id, monkeypatch):
    async def absent(html):
        raise reports.PdfUnavailableError("Chromium n'est pas installé")

    monkeypatch.setattr(reports, "html_to_pdf", absent)
    r = client.get(f"/api/scan/{scan_id}/export", params={"format": "pdf", "lang": "en"})
    assert r.status_code == 503
    assert r.json()["code"] == "api.export_pdf_unavailable"
    assert "playwright install" in r.json()["detail"]
    # Les autres formats restent disponibles.
    assert client.get(f"/api/scan/{scan_id}/export", params={"format": "html"}).status_code == 200


def test_html_to_pdf_playwright_absent(monkeypatch):
    import builtins

    real_import = builtins.__import__

    def refuse(name, *args, **kwargs):
        if name.startswith("playwright"):
            raise ImportError(name)
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", refuse)
    with pytest.raises(reports.PdfUnavailableError, match="Playwright"):
        asyncio.run(reports.html_to_pdf("<p>x</p>"))


def test_pdf_reel_avec_chromium(payload):
    try:
        report = reports.generate_sync(payload, "pdf", "fr")
    except reports.PdfUnavailableError as exc:
        pytest.skip(f"Chromium indisponible : {exc}")
    assert report.content.startswith(b"%PDF-")
    assert report.mime == "application/pdf" and report.extension == "pdf"
