# =============================================================================
# DomainRecon - Tests du service de l'interface (api/spa.py) et de sa CSP
# =============================================================================

import mimetypes
import subprocess
import sys

import pytest
from fastapi.testclient import TestClient

from domainrecon.api import security
from domainrecon.api.app import app
from domainrecon.core import config, paths

CSP_FRONTEND = (
    "default-src 'self'; script-src 'self'; style-src 'self'; "
    "img-src 'self' data: blob:; font-src 'self'; connect-src 'self'; "
    "object-src 'none'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'"
)


@pytest.fixture
def client():
    with TestClient(app) as c:
        yield c


def test_csp_frontend_exacte():
    assert security.FRONTEND_CSP == CSP_FRONTEND


def test_racine_sert_index_html(client, web_build):
    response = client.get("/")
    assert response.status_code == 200
    assert response.headers["content-type"].startswith("text/html")
    assert response.headers["cache-control"] == "no-cache"
    assert response.headers["content-security-policy"] == CSP_FRONTEND
    assert '<div id="root">' in response.text


@pytest.mark.parametrize(
    "chemin", ["/scans/12", "/scans/12/web", "/scans/live/abc", "/history/example.com", "/settings"]
)
def test_routes_de_l_interface_rendent_index(client, web_build, chemin):
    response = client.get(chemin)
    assert response.status_code == 200
    assert '<div id="root">' in response.text
    assert response.headers["content-security-policy"] == CSP_FRONTEND
    assert client.head(chemin).status_code == 200


def test_assets_a_empreinte_en_cache_immuable(client, web_build):
    js = client.get("/assets/index-1a2b3c4d.js")
    assert js.status_code == 200
    assert js.headers["content-type"] == "text/javascript; charset=utf-8"
    assert js.headers["cache-control"] == "public, max-age=31536000, immutable"
    assert client.get("/assets/index-1a2b3c4d.css").headers["content-type"] == "text/css; charset=utf-8"
    police = client.get("/assets/inter-latin-400-normal-C38fXH4l.woff2")
    assert police.headers["content-type"] == "font/woff2"
    assert police.headers["cache-control"] == "public, max-age=31536000, immutable"


def test_asset_sans_empreinte_revalide(client, web_build):
    """Cache d'un an seulement pour un nom haché : un fichier au nom stable reste revalidé."""
    response = client.get("/assets/inter-latin-400.woff2")
    assert response.status_code == 200
    assert response.headers["content-type"] == "font/woff2"
    assert response.headers["cache-control"] == "no-cache"


def test_mime_js_force_meme_si_le_systeme_dit_text_plain(client, web_build, monkeypatch):
    """Review Focus n° 3 : registre Windows qui associe .js à text/plain."""
    monkeypatch.setattr(mimetypes, "guess_type", lambda *args, **kwargs: ("text/plain", None))
    response = client.get("/assets/index-1a2b3c4d.js")
    assert response.headers["content-type"] == "text/javascript; charset=utf-8"


def test_asset_absent_404_json_jamais_index(client, web_build):
    response = client.get("/assets/absent-0000.js")
    assert response.status_code == 404
    assert response.json()["code"] == "api.not_found"


def test_fichier_public_a_la_racine(client, web_build):
    response = client.get("/favicon.svg")
    assert response.status_code == 200
    assert response.headers["content-type"] == "image/svg+xml"


@pytest.mark.parametrize(
    "chemin",
    [
        "/.env",
        "/assets/.hidden",
        "/assets/..%2F.env",
        "/assets/..%2Fsecret.txt",
        "/assets/..%2F..%2Fsecret.txt",
        "/assets/%2e%2e/%2e%2e/secret.txt",
        "/..%2Fsecret.txt",
        "/%2e%2e/secret.txt",
    ],
)
def test_fichiers_caches_et_traversee_refuses(client, web_build, chemin):
    """Le secret existe pour de vrai (hors de web/, ou fichier caché) : seule la garde l'en protège."""
    response = client.get(chemin)
    assert "SECRET" not in response.text
    if chemin.startswith("/assets/"):
        assert response.status_code == 404
        assert response.json()["code"] == "api.not_found"


def _lier_dossier(lien, cible) -> None:
    """Lien de dossier : symbolique, sinon jonction (Windows sans droit de créer des liens symboliques)."""
    try:
        lien.symlink_to(cible, target_is_directory=True)
    except (OSError, NotImplementedError):
        if sys.platform != "win32":
            pytest.skip("liens symboliques indisponibles")
        resultat = subprocess.run(["cmd", "/c", "mklink", "/J", str(lien), str(cible)], capture_output=True)
        if resultat.returncode != 0:
            pytest.skip("liens de dossier indisponibles")


def test_lien_vers_l_exterieur_refuse(client, web_build):
    """Un lien dans assets/ qui mène hors du dossier : seul is_relative_to l'arrête (aucun « .. » dans le chemin)."""
    _lier_dossier(web_build / "assets" / "ext", web_build.parent)
    response = client.get("/assets/ext/secret.txt")
    assert response.status_code == 404
    assert "SECRET" not in response.text


def test_routes_api_inconnues_restent_json(client, web_build):
    for methode in ("get", "post"):
        response = getattr(client, methode)("/api/route-inconnue")
        assert response.status_code == 404
        assert response.headers["content-type"].startswith("application/json")
        assert response.headers["content-security-policy"] == security.API_CSP


def test_sans_build_indication_json(client, tmp_path, monkeypatch):
    monkeypatch.setattr(paths, "web_dir", lambda: tmp_path / "absent")
    response = client.get("/")
    assert response.status_code == 200
    assert response.json() == {"message": "Interface non construite", "hint": "cd frontend && npm run build"}
    assert client.get("/?lang=en").json()["message"] == "User interface not built"
    assert client.get("/history").json()["hint"] == "cd frontend && npm run build"


def test_interface_publique_meme_avec_jeton(client, web_build, monkeypatch):
    monkeypatch.setattr(config, "API_TOKEN", "s3cret-jeton")
    assert client.get("/").status_code == 200
    assert client.get("/scans/1").status_code == 200
    assert client.get("/assets/index-1a2b3c4d.js").status_code == 200
    assert client.get("/api/history").status_code == 401
    assert client.get("/api").status_code == 401
    assert client.post("/scans/1").status_code == 401
