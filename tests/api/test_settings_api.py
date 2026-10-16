# =============================================================================
# DomainRecon - Tests de l'API des réglages : GET/PUT /api/settings et
# POST /api/settings/test/{service}
# =============================================================================
# Base réelle (celle des tests), aucun trafic réseau : les services tiers sont
# simulés par un transport httpx.MockTransport derrière le client du scanner
# (politique de cibles comprise) et la résolution DNS est remplacée.
# =============================================================================

import asyncio
import base64
import json
import logging
import os
import sqlite3
import subprocess
import sys
from pathlib import Path

import httpx
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, inspect, text

from domainrecon.api import service_checks
from domainrecon.api.app import app
from domainrecon.core import config, crypto
from domainrecon.core.database import Base, SessionLocal, engine
from domainrecon.core.models import SECRET_FIELDS, Scan, Settings
from domainrecon.core.settings_store import read_secret, secret_fields
from domainrecon.scanner import common, targets

CLE = "sk-abcdefghijklmnopqrstuvwxyz1234"
CLE_MASQUEE = "sk-…1234"


@pytest.fixture
def client():
    with TestClient(app) as c:
        yield c


@pytest.fixture(autouse=True)
def reglages_vierges():
    """Table des réglages vide avant et après chaque test."""
    Base.metadata.create_all(bind=engine)
    with SessionLocal() as db:
        db.query(Settings).delete()
        db.commit()
    yield
    with SessionLocal() as db:
        db.query(Settings).delete()
        db.commit()


@pytest.fixture
def dns_public(monkeypatch):
    """Les services tiers résolvent vers une adresse publique : aucun paquet DNS ne sort."""

    async def resoudre(host, timeout=targets.RESOLVE_TIMEOUT):
        return ["93.184.216.34"]

    monkeypatch.setattr(targets, "resolve_addresses", resoudre)


class FauxServices:
    """Serveur simulé des services tiers : mémorise les requêtes reçues, répond par `reponse`."""

    def __init__(self):
        self.requetes: list[httpx.Request] = []
        # Corps qui convient à tous les services : urlscan (portée) et BuiltWith (compte) le lisent.
        self.reponse = lambda request: httpx.Response(
            200, json={"ok": True, "scope": "user", "account": {}, "credits": {}}
        )

    def __call__(self, request: httpx.Request) -> httpx.Response:
        self.requetes.append(request)
        return self.reponse(request)


@pytest.fixture
def services(monkeypatch, dns_public):
    faux = FauxServices()

    def client_simule():
        return common._api_client(service_checks.PROBE_TIMEOUT, transport=httpx.MockTransport(faux))

    monkeypatch.setattr(service_checks, "_client", client_simule)
    return faux


def _valeur_en_base(champ: str):
    with engine.connect() as conn:
        return conn.execute(text(f"SELECT {champ} FROM settings WHERE id = 1")).scalar_one_or_none()


def _enregistrer(client, **champs):
    response = client.put("/api/settings", json=champs)
    assert response.status_code == 200, response.text
    return response.json()


# =============================================================================
# GET /api/settings
# =============================================================================


def test_lecture_par_defaut(client):
    response = client.get("/api/settings")

    assert response.status_code == 200
    assert response.json() == {
        **dict.fromkeys(SECRET_FIELDS, ""),
        "api_keys": dict.fromkeys(secret_fields(), ""),
        "scan_timeout": 60,
        "quick_timeout": 30,
        "screenshot_enabled": True,
        "proxy_url": "",
    }
    # La ligne unique a été créée au démarrage.
    with SessionLocal() as db:
        assert db.query(Settings).count() == 1


def test_les_quatorze_cles_sont_exposees(client):
    corps = client.get("/api/settings").json()
    assert len(SECRET_FIELDS) == 14
    assert {champ for champ in corps if champ in SECRET_FIELDS} == set(SECRET_FIELDS)


def test_lecture_masque_les_cles(client):
    _enregistrer(client, shodan_key=CLE, circl_password="un-mot-de-passe-long-1234", censys_id="court")

    response = client.get("/api/settings")

    corps = response.json()
    assert corps["shodan_key"] == CLE_MASQUEE
    assert corps["circl_password"] == "****"
    assert corps["censys_id"] == "****"
    assert corps["virustotal_key"] == ""
    # Jamais la clé en clair, ni son milieu.
    assert CLE not in response.text and "abcdefghijklmnop" not in response.text
    assert "un-mot-de-passe" not in response.text


def test_lecture_apres_redemarrage_du_chiffreur(client):
    """Les clés restent lisibles tant que .secret_key est le même."""
    _enregistrer(client, shodan_key=CLE)
    crypto._fernet_for.cache_clear()

    assert client.get("/api/settings").json()["shodan_key"] == CLE_MASQUEE


# =============================================================================
# PUT /api/settings
# =============================================================================


def test_ecriture_chiffre_les_cles(client):
    corps = _enregistrer(client, shodan_key=CLE, github_token="ghp_" + "x" * 36)

    assert corps["shodan_key"] == CLE_MASQUEE
    assert corps["github_token"] == "ghp…xxxx"
    brut = _valeur_en_base("shodan_key")
    assert brut.startswith("enc:v1:") and CLE not in brut
    assert _valeur_en_base("github_token").startswith("enc:v1:")
    assert _valeur_en_base("virustotal_key") is None


def test_ecriture_des_autres_reglages(client):
    corps = _enregistrer(
        client,
        scan_timeout=120,
        quick_timeout=15,
        screenshot_enabled=False,
        proxy_url="socks5h://alice:mdp@127.0.0.1:1080",
    )

    assert corps["scan_timeout"] == 120
    assert corps["quick_timeout"] == 15
    assert corps["screenshot_enabled"] is False
    assert corps["proxy_url"] == "socks5h://alice:****@127.0.0.1:1080"
    # En base, le proxy est chiffré comme une clé (il porte un mot de passe) ; le scan, lui,
    # le lit en clair (scanner.proxy.get_proxy_url) pour les modules et Chromium.
    brut = _valeur_en_base("proxy_url")
    assert brut.startswith("enc:v1:") and "mdp" not in brut and "alice" not in brut
    with SessionLocal() as db:
        assert read_secret(db.get(Settings, 1), "proxy_url") == "socks5h://alice:mdp@127.0.0.1:1080"
    assert client.get("/api/settings").json() == corps


def test_proxy_chiffre_au_repos_et_masque_a_la_lecture(client):
    """Mot de passe du proxy : jamais en clair en base ni dans GET, y compris après une relecture complète."""
    url = "http://alice:mdp-secret@proxy.local:3128"

    corps = _enregistrer(client, proxy_url=url)

    assert corps["proxy_url"] == "http://alice:****@proxy.local:3128"
    brut = _valeur_en_base("proxy_url")
    assert brut.startswith("enc:v1:") and "mdp-secret" not in brut
    lecture = client.get("/api/settings")
    assert "mdp-secret" not in lecture.text and lecture.json()["proxy_url"] == corps["proxy_url"]
    # Un proxy sans mot de passe n'a rien à masquer, mais il est chiffré lui aussi.
    corps = _enregistrer(client, proxy_url="socks5://127.0.0.1:9050")
    assert corps["proxy_url"] == "socks5://127.0.0.1:9050"
    assert _valeur_en_base("proxy_url").startswith("enc:v1:")


def test_proxy_masque_renvoye_tel_quel_est_ignore(client):
    """GET montre « alice:**** » ; l'écran le renvoie à l'identique : le vrai mot de passe est conservé."""
    _enregistrer(client, proxy_url="http://alice:mdp-secret@proxy.local:3128")
    avant = _valeur_en_base("proxy_url")

    corps = _enregistrer(client, proxy_url="http://alice:****@proxy.local:3128")

    assert _valeur_en_base("proxy_url") == avant  # ni réécrit, ni re-chiffré
    assert corps["proxy_url"] == "http://alice:****@proxy.local:3128"
    with SessionLocal() as db:
        assert read_secret(db.get(Settings, 1), "proxy_url") == "http://alice:mdp-secret@proxy.local:3128"


def test_champ_absent_ou_null_ne_change_rien(client):
    _enregistrer(client, shodan_key=CLE, scan_timeout=90, proxy_url="http://proxy.local:3128")

    corps = _enregistrer(client, virustotal_key=CLE)  # les autres champs sont absents
    assert (corps["shodan_key"], corps["scan_timeout"]) == (CLE_MASQUEE, 90)

    corps = _enregistrer(client, shodan_key=None, scan_timeout=None, screenshot_enabled=None, proxy_url=None)
    assert corps["shodan_key"] == CLE_MASQUEE
    assert corps["scan_timeout"] == 90
    assert corps["screenshot_enabled"] is True
    assert corps["proxy_url"] == "http://proxy.local:3128"

    assert _enregistrer(client) == corps  # corps vide : rien ne change


def test_champ_vide_supprime(client):
    _enregistrer(client, shodan_key=CLE, circl_user="alice", proxy_url="http://proxy.local:3128")

    corps = _enregistrer(client, shodan_key="", circl_user="", proxy_url="")

    assert corps["shodan_key"] == "" and corps["circl_user"] == "" and corps["proxy_url"] == ""
    assert _valeur_en_base("shodan_key") is None
    assert _valeur_en_base("circl_user") is None
    assert _valeur_en_base("proxy_url") is None


def test_renvoyer_les_valeurs_affichees_ne_change_rien(client):
    """L'écran peut renvoyer tous les champs tels qu'il les a reçus : aucune clé n'est remplacée par son masque."""
    _enregistrer(client, shodan_key=CLE, circl_password="mot-de-passe", proxy_url="http://a:b@proxy.local")
    affiche = client.get("/api/settings").json()
    avant = (_valeur_en_base("shodan_key"), _valeur_en_base("circl_password"), _valeur_en_base("proxy_url"))

    assert _enregistrer(client, **affiche) == affiche

    assert (
        _valeur_en_base("shodan_key"),
        _valeur_en_base("circl_password"),
        _valeur_en_base("proxy_url"),
    ) == avant


def test_blancs_de_bord_retires_des_cles(client):
    """Un copier-coller apporte souvent un espace ou un retour à la ligne final."""
    _enregistrer(client, shodan_key=f"  {CLE}\n")
    with SessionLocal() as db:
        assert read_secret(db.get(Settings, 1), "shodan_key") == CLE


def test_mot_de_passe_conserve_tel_quel(client):
    _enregistrer(client, circl_password=" mot de passe avec espaces ")
    with SessionLocal() as db:
        assert read_secret(db.get(Settings, 1), "circl_password") == " mot de passe avec espaces "


@pytest.mark.parametrize(
    ("champ", "valeur"),
    [
        ("shodan_key", "cle avec espace"),
        ("shodan_key", "cle\navec\nretour"),
        ("shodan_key", "clé-non-ascii"),
        ("shodan_key", "cle\u200binvisible"),  # espace de largeur nulle collé avec la clé
        ("censys_secret", "a\tb"),
        ("circl_user", "alice bob"),
        ("circl_user", "alice\x00"),
        ("circl_password", "mdp\nretour"),
        ("circl_password", "mdp\x07"),
    ],
)
def test_caracteres_interdits_refuses(client, champ, valeur):
    response = client.put("/api/settings", json={champ: valeur})

    assert response.status_code == 422
    assert response.json()["code"] == "api.settings_secret_forbidden_chars"
    assert _valeur_en_base(champ) is None


@pytest.mark.parametrize(
    "corps",
    [
        {"shodan_key": "x" * 513},
        {"scan_timeout": 4},
        {"scan_timeout": 601},
        {"quick_timeout": 0},
        {"quick_timeout": "lent"},
        {"scan_timeout": 1.5},
        {"screenshot_enabled": "peut-être"},
        {"id": 2},
        {"champ_inconnu": "x"},
        {"shodan_key": ["liste"]},
    ],
)
def test_valeurs_invalides_refusees(client, corps):
    response = client.put("/api/settings", json=corps)

    assert response.status_code == 422, response.text
    with SessionLocal() as db:
        assert db.query(Settings).filter(Settings.id != 1).count() == 0
    assert client.get("/api/settings").json()["scan_timeout"] == 60


@pytest.mark.parametrize(
    "proxy",
    [
        "proxy.local:3128",
        "ftp://proxy.local",
        "http://",
        "http://proxy.local:99999",
        "http://h/chemin",
        "http://a b",
    ],
)
def test_proxy_invalide_refuse(client, proxy):
    response = client.put("/api/settings", json={"proxy_url": proxy})

    assert response.status_code == 422
    assert response.json()["code"] == "api.settings_invalid_proxy"
    assert _valeur_en_base("proxy_url") is None


def test_erreurs_dans_la_langue_demandee(client):
    fr = client.put("/api/settings", json={"proxy_url": "ftp://x"})
    en = client.put("/api/settings?lang=en", json={"proxy_url": "ftp://x"})
    assert "URL de proxy invalide" in fr.json()["detail"]
    assert "Invalid proxy URL" in en.json()["detail"]


def test_ecriture_exige_du_json(client):
    response = client.put(
        "/api/settings", content=b'{"scan_timeout": 90}', headers={"Content-Type": "text/plain"}
    )

    assert response.status_code == 415
    assert client.get("/api/settings").json()["scan_timeout"] == 60


def test_ecriture_atomique_en_cas_de_valeur_invalide(client):
    """Une valeur refusée n'écrit rien, même si les autres champs de la requête sont valides."""
    response = client.put("/api/settings", json={"shodan_key": CLE, "scan_timeout": 0})

    assert response.status_code == 422
    assert client.get("/api/settings").json()["shodan_key"] == ""


def test_les_cles_ne_sont_jamais_journalisees(client, caplog):
    with caplog.at_level(logging.DEBUG):
        _enregistrer(client, shodan_key=CLE)
        client.get("/api/settings")
    assert CLE not in caplog.text


# =============================================================================
# Jeton d'API
# =============================================================================


@pytest.mark.parametrize(
    ("methode", "url", "corps"),
    [
        ("get", "/api/settings", None),
        ("put", "/api/settings", {"scan_timeout": 90}),
        ("post", "/api/settings/test/shodan", {}),
    ],
)
def test_routes_protegees_par_le_jeton(client, monkeypatch, methode, url, corps):
    monkeypatch.setattr(config, "API_TOKEN", "s3cret-jeton")
    requete = getattr(client, methode)

    sans = requete(url, json=corps) if corps is not None else requete(url)
    assert sans.status_code == 401
    mauvais = requete(url, headers={"X-API-Token": "autre"}, **({"json": corps} if corps is not None else {}))
    assert mauvais.status_code == 401

    for en_tetes in ({"X-API-Token": "s3cret-jeton"}, {"Authorization": "Bearer s3cret-jeton"}):
        avec = requete(url, headers=en_tetes, **({"json": corps} if corps is not None else {}))
        assert avec.status_code == 200, avec.text


def test_refus_du_jeton_n_ecrit_rien(client, monkeypatch):
    monkeypatch.setattr(config, "API_TOKEN", "s3cret-jeton")
    assert client.put("/api/settings", json={"shodan_key": CLE}).status_code == 401
    monkeypatch.setattr(config, "API_TOKEN", "")
    assert client.get("/api/settings").json()["shodan_key"] == ""


def test_cors_autorise_put_pour_une_origine_configuree(monkeypatch):
    """Frontend servi ailleurs (CORS_ORIGINS) : le préflight de PUT /api/settings passe."""
    monkeypatch.setattr(config, "CORS_ORIGINS", ["https://front.example"])
    monkeypatch.setattr(app, "middleware_stack", None)

    response = TestClient(app).options(
        "/api/settings",
        headers={
            "Origin": "https://front.example",
            "Access-Control-Request-Method": "PUT",
            "Access-Control-Request-Headers": "content-type,x-api-token",
        },
    )

    assert response.status_code == 200
    assert "PUT" in response.headers["access-control-allow-methods"]


def test_documentation_openapi_des_routes(client):
    chemins = app.openapi()["paths"]
    assert {"get", "put"} <= set(chemins["/api/settings"])
    assert "post" in chemins["/api/settings/test/{service}"]
    schema = app.openapi()["components"]["schemas"]["SettingsResponse"]
    assert schema["properties"]["shodan_key"]["type"] == "string"


# =============================================================================
# POST /api/settings/test/{service} : issues d'un test, avec un faux serveur httpx
# =============================================================================


def _tester(client, service="shodan", lang=None):
    url = f"/api/settings/test/{service}" + (f"?lang={lang}" if lang else "")
    return client.post(url, json={})


def test_service_inconnu(client):
    response = _tester(client, "inconnu")

    assert response.status_code == 404
    assert response.json() == {
        "detail": "Service inconnu : inconnu",
        "code": "api.settings_unknown_service",
        "params": {"service": "inconnu"},
    }
    assert _tester(client, "inconnu", lang="en").json()["detail"] == "Unknown service: inconnu"


def test_test_exige_du_json(client, services):
    response = client.post("/api/settings/test/shodan", content=b"", headers={"Content-Type": "text/plain"})

    assert response.status_code == 415
    assert services.requetes == []


def test_sans_cle_aucun_appel(client, services):
    response = _tester(client)

    assert response.status_code == 200
    corps = response.json()
    assert corps["service"] == "shodan"
    assert corps["success"] is False
    assert "Shodan" in corps["message"] and "absents" in corps["message"]
    assert services.requetes == []


def test_cle_valide(client, services):
    _enregistrer(client, shodan_key=CLE)

    response = _tester(client)

    assert response.status_code == 200
    assert response.json() == {
        "service": "shodan",
        "success": True,
        "message": "Clé valide : Shodan l'a acceptée.",
    }
    assert len(services.requetes) == 1


def test_message_dans_la_langue_de_la_requete(client, services):
    _enregistrer(client, shodan_key=CLE)

    assert _tester(client, lang="en").json()["message"] == "Valid key: Shodan accepted it."
    assert _tester(client, lang="fr").json()["message"] == "Clé valide : Shodan l'a acceptée."
    anglais = client.post("/api/settings/test/shodan", json={}, headers={"Accept-Language": "en-GB,en;q=0.9"})
    assert anglais.json()["message"] == "Valid key: Shodan accepted it."


@pytest.mark.parametrize("statut", [401, 403])
def test_cle_refusee(client, services, statut):
    _enregistrer(client, shodan_key=CLE)
    services.reponse = lambda request: httpx.Response(statut, json={"error": "Invalid API key"})

    corps = _tester(client).json()

    assert corps["success"] is False
    assert corps["message"] == f"Shodan a refusé la clé (HTTP {statut})."


def test_quota_depasse(client, services):
    _enregistrer(client, shodan_key=CLE)
    services.reponse = lambda request: httpx.Response(429)

    corps = _tester(client).json()

    assert corps["success"] is False
    assert corps["message"].startswith("Quota de Shodan dépassé")


@pytest.mark.parametrize("statut", [400, 404, 500, 502, 503])
def test_erreur_du_service(client, services, statut):
    _enregistrer(client, shodan_key=CLE)
    services.reponse = lambda request: httpx.Response(statut, text="oups")

    corps = _tester(client).json()

    assert corps["success"] is False
    assert f"Shodan a répondu par une erreur (HTTP {statut})" in corps["message"]


def test_redirection_non_suivie(client, services):
    """La clé n'est jamais renvoyée ailleurs que chez le service : une redirection est une erreur."""
    _enregistrer(client, shodan_key=CLE)
    services.reponse = lambda request: httpx.Response(
        302, headers={"Location": "https://pirate.example/api-info"}
    )

    corps = _tester(client).json()

    assert corps["success"] is False
    assert "HTTP 302" in corps["message"]
    assert [r.url.host for r in services.requetes] == ["api.shodan.io"]


def test_delai_depasse(client, services):
    _enregistrer(client, shodan_key=CLE)

    def trop_lent(request):
        raise httpx.ReadTimeout("lent", request=request)

    services.reponse = trop_lent

    corps = _tester(client).json()

    assert corps["success"] is False
    assert corps["message"] == "Shodan n'a pas répondu dans le délai imparti (10 s)."


def test_delai_global_depasse(client, services, monkeypatch):
    """Une réponse qui n'arrive jamais ne bloque pas la route au-delà du délai total."""
    _enregistrer(client, shodan_key=CLE)
    monkeypatch.setattr(service_checks, "TOTAL_TIMEOUT", 0.2)

    async def sans_fin(self, request):
        await asyncio.sleep(30)

    monkeypatch.setattr(httpx.MockTransport, "handle_async_request", sans_fin)

    corps = _tester(client).json()

    assert corps["success"] is False
    assert "n'a pas répondu dans le délai imparti (0.2 s)" in corps["message"]


def test_service_injoignable_sans_divulguer_la_cle(client, services, caplog):
    _enregistrer(client, shodan_key=CLE)

    def coupe(request):
        # Un message d'erreur qui cite la clé (URL, en-tête) : elle ne doit pas ressortir.
        raise httpx.ConnectError(f"échec de connexion pour {request.url} avec {CLE}", request=request)

    services.reponse = coupe

    with caplog.at_level(logging.DEBUG):
        response = _tester(client)

    corps = response.json()
    assert corps["success"] is False
    assert corps["message"].startswith("Shodan est injoignable : ")
    assert CLE not in response.text
    assert CLE not in caplog.text


def test_politique_de_cibles_appliquee(client, services, monkeypatch):
    """Un service qui résoudrait vers une adresse interne n'est pas contacté : la clé ne part pas."""
    _enregistrer(client, shodan_key=CLE)

    async def interne(host, timeout=targets.RESOLVE_TIMEOUT):
        return ["10.0.0.5"]

    monkeypatch.setattr(targets, "resolve_addresses", interne)

    corps = _tester(client).json()

    assert corps["success"] is False
    assert "injoignable" in corps["message"]
    assert services.requetes == []


def test_cle_illisible_comptee_comme_absente(client, services):
    """Fichier .secret_key remplacé : le test le dit au lieu d'envoyer un jeton chiffré au service."""
    _enregistrer(client, shodan_key=CLE)
    with engine.begin() as conn:
        conn.execute(text("UPDATE settings SET shodan_key = 'enc:v1:illisible' WHERE id = 1"))

    corps = _tester(client).json()

    assert corps["success"] is False and "absents" in corps["message"]
    assert services.requetes == []


def test_test_utilise_la_cle_enregistree_et_pas_celle_affichee(client, services):
    _enregistrer(client, shodan_key=CLE)
    _tester(client)

    (requete,) = services.requetes
    assert requete.url.params["key"] == CLE
    assert CLE_MASQUEE not in str(requete.url)


def test_journaux_httpx_sans_url_de_requete(client, services, caplog, monkeypatch):
    """httpx écrit l'URL complète de chaque requête (INFO) : elle porte la clé de Shodan (?key=…)."""
    niveau = logging.getLogger("httpx").level
    try:
        config.configure_logging()
        _enregistrer(client, shodan_key=CLE)
        with caplog.at_level(logging.DEBUG):
            assert _tester(client).json()["success"] is True
        assert CLE not in caplog.text
        assert logging.getLogger("httpx").getEffectiveLevel() >= logging.WARNING
    finally:
        logging.getLogger("httpx").setLevel(niveau)


@pytest.mark.parametrize("niveau", ["DEBUG", "INFO", "WARNING", "ERROR"])
def test_httpx_jamais_sous_warning(monkeypatch, niveau):
    ancien = logging.getLogger("httpx").level
    monkeypatch.setattr(config, "LOG_LEVEL", niveau)
    try:
        config.configure_logging()
        assert logging.getLogger("httpx").level >= logging.WARNING
    finally:
        logging.getLogger("httpx").setLevel(ancien)


# =============================================================================
# Un appel minimal par service : hôte, emplacement de la clé, issues particulières
# =============================================================================

# Hôte de la première requête de chaque service (un service ajouté sans test échoue ici).
HOTES = {
    "shodan": "api.shodan.io",
    "virustotal": "www.virustotal.com",
    "censys": "api.platform.censys.io",
    "abuseipdb": "api.abuseipdb.com",
    "urlscan": "urlscan.io",
    "otx": "otx.alienvault.com",
    "safebrowsing": "safebrowsing.googleapis.com",
    "securitytrails": "api.securitytrails.com",
    "builtwith": "api.builtwith.com",
    "circl": "www.circl.lu",
    "intelx": "2.intelx.io",
    "github": "api.github.com",
}
# Valeurs distinctes pour chaque clé : on retrouve laquelle est envoyée, et où.
VALEURS = {champ: f"val_{champ}_0123456789abcdef" for champ in SECRET_FIELDS}


def _enregistrer_toutes_les_cles(client):
    _enregistrer(client, **VALEURS)


def _emplacements(requete: httpx.Request) -> dict[str, str]:
    """Où chaque clé voyage dans une requête : en-tête, paramètre d'URL, HTTP Basic, chemin."""
    trouvees = {}
    en_tetes = dict(requete.headers)
    basic = en_tetes.get("authorization", "")
    if basic.startswith("Basic "):
        identifiant, _, mot_de_passe = base64.b64decode(basic[6:]).decode().partition(":")
        en_tetes["basic"] = f"{identifiant}:{mot_de_passe}"
    for champ, valeur in VALEURS.items():
        if valeur in requete.url.path:
            trouvees[champ] = "chemin"
        elif any(valeur in v for v in requete.url.params.values()):
            trouvees[champ] = "paramètre"
        elif any(valeur in v for v in en_tetes.values()):
            trouvees[champ] = "en-tête"
    return trouvees


def test_services_connus():
    assert set(service_checks.SERVICES) == set(HOTES)
    assert len(HOTES) == 12


def test_chaque_cle_est_utilisee_par_un_service():
    utilisees = {champ for check in service_checks.SERVICES.values() for champ in check.fields}
    # Le jeton Censys (colonne « secret ») suffit au test : l'identifiant n'y intervient pas.
    assert utilisees | {"censys_id"} == set(SECRET_FIELDS)


@pytest.mark.parametrize("service", sorted(HOTES))
def test_premier_appel_de_chaque_service(client, services, service):
    _enregistrer_toutes_les_cles(client)

    corps = _tester(client, service).json()

    assert corps["success"] is True, corps
    requete = services.requetes[0]
    assert requete.url.scheme == "https"
    assert requete.url.host == HOTES[service]
    assert requete.method == "GET"
    assert requete.content == b""
    emplacements = _emplacements(requete)
    # Jamais dans le chemin : seulement en-tête, paramètre ou HTTP Basic.
    assert "chemin" not in emplacements.values(), emplacements
    # Exactement les clés exigées par le service : aucune de plus, aucune de moins.
    assert set(emplacements) == set(service_checks.SERVICES[service].fields), emplacements


@pytest.mark.parametrize("service", sorted(HOTES))
def test_chaque_service_exige_toutes_ses_cles(client, services, service):
    check = service_checks.SERVICES[service]
    for manquante in check.fields:
        _enregistrer_toutes_les_cles(client)
        _enregistrer(client, **{manquante: ""})

        corps = _tester(client, service).json()

        assert corps["success"] is False
        assert "absents" in corps["message"], (manquante, corps)
        assert services.requetes == []


@pytest.mark.parametrize("service", sorted(HOTES))
def test_une_cle_refusee_est_signalee_pour_chaque_service(client, services, service):
    _enregistrer_toutes_les_cles(client)
    services.reponse = lambda request: httpx.Response(401, json={"error": "invalid"})

    corps = _tester(client, service).json()

    assert corps["success"] is False
    assert f"{service_checks.SERVICES[service].label} a refusé la clé (HTTP 401)" in corps["message"]


@pytest.mark.parametrize("service", sorted(HOTES))
def test_la_cle_ne_sort_jamais_dans_la_reponse(client, services, service):
    """Succès, refus ou panne : ni le message ni les journaux ne contiennent une clé."""
    _enregistrer_toutes_les_cles(client)
    for reponse in (
        lambda request: httpx.Response(200, json={"echo": request.headers.get("authorization", "")}),
        lambda request: httpx.Response(403, text=str(request.url)),
    ):
        services.reponse = reponse
        texte = _tester(client, service).text
        assert not any(valeur in texte for valeur in VALEURS.values()), texte


def test_shodan_cle_en_parametre(client, services):
    _enregistrer_toutes_les_cles(client)
    _tester(client, "shodan")

    (requete,) = services.requetes
    assert requete.url.path == "/api-info"
    assert requete.url.params["key"] == VALEURS["shodan_key"]


def test_urlscan_quotas_de_l_utilisateur(client, services):
    _enregistrer_toutes_les_cles(client)
    _tester(client, "urlscan")

    (requete,) = services.requetes
    assert requete.url.path == "/api/v1/quotas"
    assert requete.headers["api-key"] == VALEURS["urlscan_key"]
    assert not requete.url.query


@pytest.mark.parametrize("portee", ["user", "team"])
def test_urlscan_portee_de_l_utilisateur_ou_de_l_equipe_prouve_la_cle(client, services, portee):
    _enregistrer(client, urlscan_key=VALEURS["urlscan_key"])
    services.reponse = lambda request: httpx.Response(200, json={"scope": portee, "limits": {}})

    assert _tester(client, "urlscan").json()["success"] is True


@pytest.mark.parametrize(
    "reponse",
    [
        pytest.param(
            lambda r: httpx.Response(200, json={"scope": "ip-address", "limits": {}}), id="portee-ip"
        ),
        pytest.param(lambda r: httpx.Response(200, json={"limits": {}}), id="sans-portee"),
        pytest.param(lambda r: httpx.Response(200, json=["liste"]), id="liste"),
        pytest.param(lambda r: httpx.Response(200, text="<html>"), id="pas-du-json"),
    ],
)
def test_urlscan_reponse_anonyme_n_est_pas_une_cle_valide(client, services, reponse):
    """urlscan répond 200 sans clé valide, avec les quotas de l'adresse IP : ce n'est pas la preuve de la clé."""
    _enregistrer(client, urlscan_key=VALEURS["urlscan_key"])
    services.reponse = reponse

    corps = _tester(client, "urlscan").json()

    assert corps["success"] is False
    assert "urlscan.io a refusé la clé (HTTP 200)" in corps["message"]


def test_virustotal_cle_en_en_tete(client, services):
    _enregistrer_toutes_les_cles(client)
    _tester(client, "virustotal")

    (requete,) = services.requetes
    assert requete.url.path == "/api/v3/domains/example.com"
    assert requete.headers["x-apikey"] == VALEURS["virustotal_key"]
    assert not requete.url.query


def test_github_jeton_en_bearer_avec_agent_utilisateur(client, services):
    _enregistrer_toutes_les_cles(client)
    _tester(client, "github")

    (requete,) = services.requetes
    assert requete.url.path == "/user"
    assert requete.headers["authorization"] == f"Bearer {VALEURS['github_token']}"
    # GitHub refuse les requêtes sans agent utilisateur.
    assert requete.headers["user-agent"].startswith("DomainRecon/")


def test_circl_identifiants_en_http_basic(client, services):
    _enregistrer_toutes_les_cles(client)
    _tester(client, "circl")

    (requete,) = services.requetes
    attendu = base64.b64encode(f"{VALEURS['circl_user']}:{VALEURS['circl_password']}".encode()).decode()
    assert requete.headers["authorization"] == f"Basic {attendu}"


def test_circl_aucun_resultat_prouve_que_les_identifiants_sont_reconnus(client, services):
    _enregistrer_toutes_les_cles(client)
    services.reponse = lambda request: httpx.Response(404)

    assert _tester(client, "circl").json()["success"] is True


def test_safebrowsing_cle_dans_l_url_de_l_api_v5(client, services):
    _enregistrer_toutes_les_cles(client)
    _tester(client, "safebrowsing")

    (requete,) = services.requetes
    assert requete.url.path == "/v5/hashLists"
    assert dict(requete.url.params) == {"key": VALEURS["safebrowsing_key"], "pageSize": "1"}


def test_safebrowsing_cle_invalide_est_un_400(client, services):
    """Google répond 400 (API_KEY_INVALID) à une clé inconnue, pas 401."""
    _enregistrer_toutes_les_cles(client)
    services.reponse = lambda request: httpx.Response(400, json={"error": {"status": "INVALID_ARGUMENT"}})

    corps = _tester(client, "safebrowsing").json()

    assert corps["success"] is False
    assert "a refusé la clé (HTTP 400)" in corps["message"]


def test_censys_jeton_en_bearer(client, services):
    """API Platform : le jeton d'accès personnel (colonne « secret ») suffit, l'identifiant n'est pas envoyé."""
    _enregistrer(client, censys_secret=VALEURS["censys_secret"])

    assert _tester(client, "censys").json()["success"] is True

    (requete,) = services.requetes
    assert requete.url.path == "/v3/accounts/users/credits"
    assert requete.headers["authorization"] == f"Bearer {VALEURS['censys_secret']}"
    assert not requete.url.query


def test_censys_identifiant_non_envoye(client, services):
    _enregistrer_toutes_les_cles(client)
    _tester(client, "censys")

    (requete,) = services.requetes
    assert VALEURS["censys_id"] not in str(requete.url) + str(requete.headers)


def test_censys_compte_d_organisation_404_prouve_le_jeton(client, services):
    """« User not found » : l'endpoint des comptes gratuits ne connaît pas ce compte, mais le jeton est reconnu."""
    _enregistrer(client, censys_secret=VALEURS["censys_secret"])
    services.reponse = lambda request: httpx.Response(404, json={"error": {"message": "User not found"}})

    assert _tester(client, "censys").json()["success"] is True


def test_intelx_essaie_l_offre_gratuite_si_la_cle_est_refusee_ailleurs(client, services):
    _enregistrer_toutes_les_cles(client)
    services.reponse = lambda request: httpx.Response(200 if request.url.host == "free.intelx.io" else 401)

    assert _tester(client, "intelx").json()["success"] is True
    assert [r.url.host for r in services.requetes] == ["2.intelx.io", "free.intelx.io"]


def test_intelx_refusee_partout(client, services):
    _enregistrer_toutes_les_cles(client)
    services.reponse = lambda request: httpx.Response(401)

    corps = _tester(client, "intelx").json()

    assert corps["success"] is False
    assert "a refusé la clé (HTTP 401)" in corps["message"]
    assert [r.url.host for r in services.requetes] == ["2.intelx.io", "free.intelx.io"]


def test_service_en_panne_puis_succes_sur_le_second_essai(client, services):
    """Le premier échec réseau n'empêche pas d'essayer la requête suivante."""
    _enregistrer_toutes_les_cles(client)

    def reponse(request):
        if request.url.host == "2.intelx.io":
            raise httpx.ConnectError("injoignable", request=request)
        return httpx.Response(200)

    services.reponse = reponse

    assert _tester(client, "intelx").json()["success"] is True


def test_toutes_les_urls_des_services_sont_fixes_et_en_https():
    secrets = {champ: "x" * 20 for champ in SECRET_FIELDS}
    for nom, check in service_checks.SERVICES.items():
        for probe in check.probes(secrets):
            url = httpx.URL(probe.url)
            assert url.scheme == "https", nom
            assert url.host and not url.query and not url.userinfo, nom


# =============================================================================
# BuiltWith : erreurs signalées dans le corps d'une réponse 200
# =============================================================================


@pytest.mark.parametrize(
    ("corps", "succes", "extrait"),
    [
        (
            {"account": {"email": "moi@example.org", "plan": "Free"}, "credits": {"remaining": 5}},
            True,
            "Clé valide",
        ),
        ({"credits": {"remaining": 0}, "Errors": []}, True, "Clé valide"),
        ({"domain": "example.com", "groups": []}, False, "erreur (HTTP 200)"),  # ne décrit pas un compte
        ({}, False, "erreur (HTTP 200)"),
        (
            {
                "Errors": [
                    {"Lookup": None, "Message": "API Key is wrong - it needs to be a Guid.", "Code": -2}
                ]
            },
            False,
            "BuiltWith a refusé la clé (HTTP 200)",
        ),
        (
            {"Errors": [{"Message": "You've run out of API Credits.", "Code": -3}]},
            False,
            "Quota de BuiltWith",
        ),
        ({"Errors": [{"Message": "Erreur interne", "Code": -99}]}, False, "erreur (HTTP 200)"),
        ({"Errors": ["texte"]}, False, "erreur (HTTP 200)"),
        (["liste", "inattendue"], False, "erreur (HTTP 200)"),
    ],
)
def test_builtwith_erreurs_dans_le_corps(client, services, corps, succes, extrait):
    _enregistrer(client, builtwith_key=VALEURS["builtwith_key"])
    services.reponse = lambda request: httpx.Response(200, json=corps)

    reponse = _tester(client, "builtwith").json()

    assert reponse["success"] is succes, reponse
    assert extrait in reponse["message"]


def test_builtwith_whoami_sans_credit_avec_la_cle_en_parametre(client, services):
    _enregistrer_toutes_les_cles(client)
    _tester(client, "builtwith")

    (requete,) = services.requetes
    assert requete.url.path == "/whoamiv1/api.json"
    assert dict(requete.url.params) == {"KEY": VALEURS["builtwith_key"]}


def test_builtwith_corps_qui_n_est_pas_du_json(client, services):
    _enregistrer(client, builtwith_key=VALEURS["builtwith_key"])
    services.reponse = lambda request: httpx.Response(200, text="<html>maintenance</html>")

    reponse = _tester(client, "builtwith").json()

    assert reponse["success"] is False
    assert "erreur (HTTP 200)" in reponse["message"]


def test_builtwith_code_http_d_erreur_sans_lire_le_corps(client, services):
    _enregistrer(client, builtwith_key=VALEURS["builtwith_key"])
    services.reponse = lambda request: httpx.Response(401, json={"Errors": []})

    assert "a refusé la clé (HTTP 401)" in _tester(client, "builtwith").json()["message"]


class _FluxSansFin(httpx.AsyncByteStream):
    """Corps qui ne finit jamais : seule une lecture bornée en vient à bout."""

    async def __aiter__(self):
        while True:
            yield b"x" * 65536


def test_lecture_du_corps_bornee(client, services):
    _enregistrer(client, builtwith_key=VALEURS["builtwith_key"])
    services.reponse = lambda request: httpx.Response(200, stream=_FluxSansFin())

    reponse = _tester(client, "builtwith").json()

    assert reponse["success"] is False
    assert "erreur (HTTP 200)" in reponse["message"]


def test_les_autres_services_ne_lisent_pas_le_corps(client, services):
    """Seul le code HTTP compte : un corps interminable ne ralentit pas le test."""
    _enregistrer_toutes_les_cles(client)
    services.reponse = lambda request: httpx.Response(200, stream=_FluxSansFin())

    assert _tester(client, "shodan").json()["success"] is True


# =============================================================================
# Démarrage sur une base d'une version antérieure (sans table des réglages)
# =============================================================================

RACINE = Path(__file__).resolve().parents[2]

SCRIPT_DEMARRAGE = """
import json
from fastapi.testclient import TestClient
from domainrecon.api.app import app

with TestClient(app) as c:
    avant = c.get("/api/settings").json()
    apres = c.put("/api/settings", json={"shodan_key": "abcdefghijklmnopqrstuvwxyz0123"}).json()
print(json.dumps({"avant": avant, "apres": apres}))
"""


def test_base_d_une_version_anterieure_recoit_la_table_des_reglages(tmp_path):
    """Mise à jour de l'application : la base existante (scans seulement) est migrée au démarrage, sans perte."""
    donnees = tmp_path / "donnees"
    donnees.mkdir()
    base = donnees / "domainrecon.db"
    url = f"sqlite:///{base.as_posix()}"
    ancien = create_engine(url)
    Base.metadata.create_all(ancien, tables=[Scan.__table__])
    with ancien.begin() as conn:
        conn.execute(
            text(
                "INSERT INTO scans (domain, scan_timestamp, status) VALUES ('example.com', '2025-01-01', 'success')"
            )
        )
    assert "settings" not in inspect(ancien).get_table_names()
    ancien.dispose()

    # Processus neuf : l'application lit DATABASE_URL et DATA_DIR une seule fois, à l'import.
    env = {**os.environ, "DATA_DIR": str(donnees), "DATABASE_URL": url, "PYTHONIOENCODING": "utf-8"}
    resultat = subprocess.run(
        [sys.executable, "-c", SCRIPT_DEMARRAGE],
        cwd=RACINE,
        env=env,
        capture_output=True,
        encoding="utf-8",
        timeout=120,
    )
    assert resultat.returncode == 0, resultat.stderr
    reponses = json.loads(resultat.stdout.strip().splitlines()[-1])

    assert reponses["avant"]["scan_timeout"] == 60 and reponses["avant"]["shodan_key"] == ""
    assert reponses["apres"]["shodan_key"] == "abc…0123"
    with sqlite3.connect(base) as conn:
        assert conn.execute(
            "SELECT id, scan_timeout, quick_timeout, screenshot_enabled FROM settings"
        ).fetchall() == [(1, 60, 30, 1)]
        assert conn.execute("SELECT shodan_key FROM settings").fetchone()[0].startswith("enc:v1:")
        assert conn.execute("SELECT domain FROM scans").fetchall() == [("example.com",)]
    # Le secret de chiffrement est créé à côté de la base, au premier enregistrement d'une clé.
    assert len((donnees / ".secret_key").read_bytes()) == 32
    conn.close()
