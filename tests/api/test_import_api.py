# =============================================================================
# DomainRecon - Tests de POST /api/import : import d'une ancienne base depuis l'interface
# =============================================================================
# Base valide, bases invalides, fichier trop gros, doublons ; requêtes locales et
# de même origine seulement ; fichier temporaire toujours supprimé ; un import à
# la fois. Le fichier est envoyé en multipart/form-data, champ « file ».
# =============================================================================

import itertools
import json
import os
import sqlite3
import tempfile
import threading
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from domainrecon.api.app import app
from domainrecon.api.routes import importer as import_routes
from domainrecon.cli import importer as cli_importer
from domainrecon.core import config
from domainrecon.core.database import SessionLocal
from domainrecon.core.models import Scan

LOCAL = ("127.0.0.1", 50000)
_compteur = itertools.count(1)


@pytest.fixture
def local(monkeypatch):
    """Client venu de cette machine, seul à pouvoir importer."""
    monkeypatch.setenv("SCHEDULER", "0")
    with TestClient(app, client=LOCAL) as client:
        yield client


@pytest.fixture
def distant(monkeypatch):
    """Client d'une autre machine (adresse « testclient »)."""
    monkeypatch.setenv("SCHEDULER", "0")
    with TestClient(app) as client:
        yield client


@pytest.fixture
def dossier_temporaire(tmp_path, monkeypatch):
    """Dossier temporaire du système redirigé : on y vérifie que l'import ne laisse rien."""
    racine = tmp_path / "temp-systeme"
    racine.mkdir()
    monkeypatch.setattr(tempfile, "tempdir", str(racine))
    return racine


def domaine(prefixe: str = "imp") -> str:
    """Domaine propre à chaque appel : les tests partagent la base de la session."""
    return f"{prefixe}{next(_compteur)}-{os.getpid()}.example.org"


SCHEMA = (
    "CREATE TABLE scans (id INTEGER PRIMARY KEY, domain VARCHAR(255) NOT NULL, ip_address VARCHAR(45), "
    "dns_records JSON, subdomains JSON, tls_certificate JSON, reverse_dns_data JSON, security_score JSON, "
    "tags JSON, notes TEXT, scan_timestamp DATETIME, status VARCHAR(50), error_message TEXT, "
    "screenshot_path VARCHAR(500), colonne_disparue TEXT)"
)


def ancienne_base(chemin: Path, lignes: list[dict], schema: str = SCHEMA) -> bytes:
    """Écrit une ancienne base SQLite DomainRecon et renvoie son contenu."""
    conn = sqlite3.connect(chemin)
    conn.execute(schema)
    for ligne in lignes:
        conn.execute(
            f"INSERT INTO scans ({', '.join(ligne)}) VALUES ({', '.join('?' * len(ligne))})",
            list(ligne.values()),
        )
    conn.commit()
    conn.close()
    return chemin.read_bytes()


def scans_de(nom: str) -> list[Scan]:
    with SessionLocal() as db:
        scans = db.query(Scan).filter(Scan.domain == nom).order_by(Scan.scan_timestamp).all()
        db.expunge_all()
        return scans


def envoyer(client, contenu: bytes, nom: str = "domainrecon.db", **options):
    return client.post("/api/import", files={"file": (nom, contenu, "application/octet-stream")}, **options)


def multipart(
    *parties: tuple[str, bytes], boundary: str = "limite-de-test", fin: bool = True
) -> tuple[bytes, dict]:
    """Corps multipart écrit à la main (parties = (nom du champ, contenu)) et son en-tête Content-Type."""
    corps = b""
    for nom, contenu in parties:
        corps += (
            f'--{boundary}\r\nContent-Disposition: form-data; name="{nom}"; filename="x.db"\r\n\r\n'.encode()
        )
        corps += contenu + b"\r\n"
    if fin:
        corps += f"--{boundary}--\r\n".encode()
    return corps, {"Content-Type": f"multipart/form-data; boundary={boundary}"}


DETAIL_LOCAL_ONLY = "Action reserved for the user of this machine"


# --- Base valide ----------------------------------------------------------------------------


def test_import_d_une_base_valide(local, tmp_path):
    nom = domaine()
    contenu = ancienne_base(
        tmp_path / "ancienne.db",
        [
            {
                "id": 41,
                "domain": nom.upper(),
                "ip_address": "192.0.2.1",
                "dns_records": json.dumps({"A": ["192.0.2.1"]}),
                "subdomains": json.dumps(["www." + nom]),
                "tls_certificate": "pas du json",
                "reverse_dns_data": json.dumps({"ptr": "x"}),
                "security_score": json.dumps({"score": 70, "grade": "C"}),
                "tags": json.dumps(["prod"]),
                "notes": "ancien",
                "scan_timestamp": "2025-03-04 10:11:12.123456",
                "status": "success",
                "screenshot_path": "ancienne_capture.png",
                "colonne_disparue": "x",
            },
            {
                "id": 42,
                "domain": nom,
                "scan_timestamp": "2025-03-05 08:00:00",
                "security_score": json.dumps(55),
            },
            {"id": 43, "domain": "", "scan_timestamp": "2025-03-05 08:00:00"},
            {"id": 44, "domain": nom, "scan_timestamp": "n'importe quoi"},
        ],
    )
    response = envoyer(local, contenu)
    assert response.status_code == 200
    assert response.headers["content-type"] == "application/json"
    # Le contrat exact de la réponse : six champs, rien de plus.
    assert response.json() == {
        "read": 4,
        "imported": 2,
        "ignored": 2,
        "duplicates": 0,
        "unusable": 2,
        "unknown_columns": ["colonne_disparue"],
    }
    premier, second = scans_de(nom)
    assert premier.dns_records == {"A": ["192.0.2.1"]} and premier.subdomains == ["www." + nom]
    assert premier.tls_certificate is None, "JSON illisible laissé vide"
    assert premier.reverse_dns == {"ptr": "x"} and premier.tags == ["prod"] and premier.notes == "ancien"
    assert premier.screenshot_path is None
    assert premier.scan_timestamp.isoformat() == "2025-03-04T10:11:12.123456"
    assert second.security_score == {"score": 55}
    # Les scans importés apparaissent dans l'historique de l'application.
    historique = local.get("/api/history", params={"domain": nom}).json()
    assert len(historique["scans"]) == 2


def test_import_d_anciens_noms_de_colonnes(local, tmp_path):
    nom = domaine("old")
    contenu = ancienne_base(
        tmp_path / "v1.db",
        [{"id": 1, "target": nom, "ip": "192.0.2.9", "timestamp": "2024-05-06T07:08:09Z", "score": 80}],
        schema="CREATE TABLE scans (id INTEGER PRIMARY KEY, target TEXT, ip TEXT, timestamp TEXT, score INTEGER)",
    )
    response = envoyer(local, contenu)
    assert response.status_code == 200
    assert response.json() == {
        "read": 1,
        "imported": 1,
        "ignored": 0,
        "duplicates": 0,
        "unusable": 0,
        "unknown_columns": [],
    }
    (scan,) = scans_de(nom)
    assert scan.ip_address == "192.0.2.9" and scan.security_score == {"score": 80}


def test_import_d_une_base_sans_scan(local, tmp_path):
    contenu = ancienne_base(tmp_path / "vide.db", [])
    assert envoyer(local, contenu).json() == {
        "read": 0,
        "imported": 0,
        "ignored": 0,
        "duplicates": 0,
        "unusable": 0,
        "unknown_columns": ["colonne_disparue"],
    }


def test_import_de_nombreux_scans_par_lots(local, tmp_path):
    """Plus que la taille d'un lot d'écriture (200) : lecture au fil de l'eau, écritures par lots."""
    nom = domaine("lots")
    lignes = [
        {"id": i, "domain": nom, "scan_timestamp": f"2025-01-01 00:{i // 60:02d}:{i % 60:02d}"}
        for i in range(1, 451)
    ]
    reponse = envoyer(local, ancienne_base(tmp_path / "gros.db", lignes)).json()
    assert reponse["read"] == reponse["imported"] == 450 and reponse["ignored"] == 0
    assert len(scans_de(nom)) == 450


def test_import_d_une_base_de_plus_d_un_mio(local, tmp_path):
    """La limite de 1 Mio des corps JSON ne s'applique pas à l'envoi d'une base."""
    nom = domaine("gros")
    contenu = ancienne_base(
        tmp_path / "volumineux.db",
        [{"id": 1, "domain": nom, "scan_timestamp": "2025-01-01 00:00:00", "notes": "x" * 1_500_000}],
    )
    assert len(contenu) > 1024 * 1024
    assert envoyer(local, contenu).json()["imported"] == 1
    assert len(scans_de(nom)[0].notes) == 1_500_000


def test_import_d_une_base_en_mode_wal(local, tmp_path, dossier_temporaire):
    """Base copiée d'une installation en mode WAL (fichier principal seul) : lue, sans rien laisser à côté."""
    nom = domaine("wal")
    chemin = tmp_path / "wal.db"
    conn = sqlite3.connect(chemin)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("CREATE TABLE scans (id INTEGER PRIMARY KEY, domain TEXT, scan_timestamp TEXT)")
    conn.execute("INSERT INTO scans VALUES (1, ?, '2025-01-01 00:00:00')", (nom,))
    conn.commit()
    conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
    conn.close()
    assert chemin.read_bytes()[18:20] == b""  # en-tête : mode WAL
    assert envoyer(local, chemin.read_bytes()).json()["imported"] == 1
    assert list(dossier_temporaire.iterdir()) == []


# --- Doublons --------------------------------------------------------------------------------


def test_import_ignore_les_doublons(local, tmp_path):
    nom = domaine("dup")
    contenu = ancienne_base(
        tmp_path / "a.db",
        [
            {"id": 1, "domain": nom, "scan_timestamp": "2025-01-01 00:00:00"},
            {"id": 2, "domain": nom, "scan_timestamp": "2025-01-02 00:00:00"},
        ],
    )
    assert envoyer(local, contenu).json()["imported"] == 2
    second = envoyer(local, contenu).json()
    assert second == {
        "read": 2,
        "imported": 0,
        "ignored": 2,
        "duplicates": 2,
        "unusable": 0,
        "unknown_columns": ["colonne_disparue"],
    }
    assert len(scans_de(nom)) == 2


def test_import_melange_nouveaux_scans_doublons_et_lignes_inexploitables(local, tmp_path):
    nom = domaine("mel")
    lignes = [{"id": 1, "domain": nom, "scan_timestamp": "2025-01-01 00:00:00"}]
    assert envoyer(local, ancienne_base(tmp_path / "a.db", lignes)).json()["imported"] == 1
    lignes += [
        {"id": 2, "domain": nom, "scan_timestamp": "2025-01-02 00:00:00"},
        {"id": 3, "domain": "", "scan_timestamp": "2025-01-03 00:00:00"},
    ]
    resultat = envoyer(local, ancienne_base(tmp_path / "b.db", lignes)).json()
    assert (resultat["read"], resultat["imported"], resultat["ignored"]) == (3, 1, 2)
    assert (resultat["duplicates"], resultat["unusable"]) == (1, 1)
    assert resultat["read"] == resultat["imported"] + resultat["ignored"]
    assert resultat["ignored"] == resultat["duplicates"] + resultat["unusable"]
    assert len(scans_de(nom)) == 2


# --- Bases invalides -------------------------------------------------------------------------


def _sans_effet(monkeypatch):
    """Aucune écriture ne doit avoir lieu : import_scans échoue le test s'il est appelé."""
    monkeypatch.setattr(cli_importer, "import_scans", lambda *a, **k: pytest.fail("import_scans appelé"))


@pytest.mark.parametrize(
    "contenu",
    [
        b"",
        b"ceci n'est pas une base SQLite " * 100,
        b"SQLite format 2\x00" + b"\x00" * 200,
        b"%PDF-1.7\n" + bytes(range(256)) * 20,
    ],
    ids=["vide", "texte", "autre-version", "pdf"],
)
def test_fichier_qui_n_est_pas_sqlite(local, contenu):
    for langue, detail in (
        ("fr", "Ce fichier n'est pas une base SQLite lisible."),
        ("en", "This file is not a readable SQLite database."),
    ):
        response = envoyer(local, contenu, params={"lang": langue})
        assert response.status_code == 400
        assert response.json() == {"detail": detail, "code": "api.import_not_sqlite", "params": {}}


def test_base_sqlite_sans_table_scans(local, tmp_path):
    chemin = tmp_path / "autre.db"
    conn = sqlite3.connect(chemin)
    conn.execute("CREATE TABLE autre (x INTEGER)")
    conn.commit()
    conn.close()
    response = envoyer(local, chemin.read_bytes(), params={"lang": "en"})
    assert response.status_code == 400
    assert response.json() == {
        "detail": 'This SQLite database is not a DomainRecon database: no "scans" table, or it has no domain or date column.',
        "code": "api.import_not_domainrecon",
        "params": {},
    }
    assert "scans" in envoyer(local, chemin.read_bytes()).json()["detail"]


@pytest.mark.parametrize(
    "schema",
    [
        "CREATE TABLE scans (id INTEGER PRIMARY KEY, ip TEXT, notes TEXT)",  # ni domaine ni date
        "CREATE TABLE scans (id INTEGER PRIMARY KEY, domain TEXT)",  # pas de date
        "CREATE TABLE scans (id INTEGER PRIMARY KEY, scan_timestamp TEXT)",  # pas de domaine
    ],
    ids=["ni-domaine-ni-date", "sans-date", "sans-domaine"],
)
def test_table_scans_sans_colonnes_reconnues(local, tmp_path, schema):
    contenu = ancienne_base(tmp_path / "x.db", [], schema=schema)
    response = envoyer(local, contenu)
    assert response.status_code == 400 and response.json()["code"] == "api.import_not_domainrecon"


def test_scans_qui_est_une_vue_refuse(local, tmp_path):
    chemin = tmp_path / "vue.db"
    conn = sqlite3.connect(chemin)
    conn.execute("CREATE TABLE reelle (domain TEXT, scan_timestamp TEXT)")
    conn.execute("CREATE VIEW scans AS SELECT * FROM reelle")
    conn.commit()
    conn.close()
    response = envoyer(local, chemin.read_bytes())
    assert response.status_code == 400 and response.json()["code"] == "api.import_not_domainrecon"


def test_base_tronquee_ou_corrompue(local, tmp_path):
    nom = domaine("corrompu")
    lignes = [
        {"id": i, "domain": nom, "scan_timestamp": f"2025-01-01 00:00:{i % 60:02d}", "notes": "n" * 3000}
        for i in range(1, 60)
    ]
    contenu = ancienne_base(tmp_path / "ok.db", lignes)
    assert len(contenu) > 20_000
    response = envoyer(local, contenu[:6000])  # en-tête et schéma intacts, pages de données absentes
    assert response.status_code == 400 and response.json()["code"] == "api.import_not_sqlite"
    # Les lignes que la lecture aurait pu atteindre avant l'erreur ne sont pas une raison de la taire,
    # mais une base corrompue ne doit rien laisser derrière elle.
    assert len(scans_de(nom)) <= 3


def test_aucune_ecriture_quand_la_base_est_refusee(local):
    avant = _compter_scans()
    envoyer(local, b"pas sqlite")
    assert _compter_scans() == avant


def _compter_scans() -> int:
    with SessionLocal() as db:
        return db.query(Scan).count()


# --- Formulaire invalide ---------------------------------------------------------------------


@pytest.mark.parametrize(
    "en_tetes",
    [
        {"Content-Type": "application/json"},
        {"Content-Type": "text/plain"},
        {"Content-Type": "application/octet-stream"},
        {"Content-Type": "application/x-www-form-urlencoded"},
        {"Content-Type": "multipart/form-data"},
        {"Content-Type": "multipart/form-data; boundary="},
        {"Content-Type": "multipart/mixed; boundary=abc"},
        {},
    ],
    ids=["json", "texte", "octets", "urlencoded", "sans-frontiere", "frontiere-vide", "mixed", "sans-type"],
)
def test_corps_qui_n_est_pas_un_formulaire_multipart(local, monkeypatch, en_tetes):
    _sans_effet(monkeypatch)
    response = local.post("/api/import?lang=en", content=b"SQLite format 3\x00 ...", headers=en_tetes)
    assert response.status_code == 415
    assert response.json() == {
        "detail": "The request body must be a multipart/form-data form (Content-Type: multipart/form-data) containing the file.",
        "code": "api.multipart_required",
        "params": {},
    }


def test_formulaire_sans_champ_file(local, monkeypatch):
    _sans_effet(monkeypatch)
    corps, en_tetes = multipart(("autre", b"SQLite format 3\x00"), ("base", b"x"))
    response = local.post("/api/import?lang=en", content=corps, headers=en_tetes)
    assert response.status_code == 400
    assert response.json() == {
        "detail": 'No file received: send the old database in the "file" form field.',
        "code": "api.import_no_file",
        "params": {},
    }
    vide, en_tetes = multipart()
    assert local.post("/api/import", content=vide, headers=en_tetes).json()["code"] == "api.import_no_file"


def test_fichier_envoye_deux_fois_refuse(local, monkeypatch):
    _sans_effet(monkeypatch)
    corps, en_tetes = multipart(("file", b"un"), ("file", b"deux"))
    response = local.post("/api/import", content=corps, headers=en_tetes)
    assert response.status_code == 400 and response.json()["code"] == "api.multipart_invalid"


def test_formulaire_tronque_refuse_et_jamais_importe(local, tmp_path, monkeypatch):
    """Envoi coupé avant la frontière finale : refusé, même si le début du fichier est une base valide."""
    nom = domaine("tronque")
    contenu = ancienne_base(
        tmp_path / "ok.db", [{"id": 1, "domain": nom, "scan_timestamp": "2025-01-01 00:00:00"}]
    )
    _sans_effet(monkeypatch)
    corps, en_tetes = multipart(("file", contenu), fin=False)
    response = local.post("/api/import?lang=en", content=corps, headers=en_tetes)
    assert response.status_code == 400
    assert response.json()["code"] == "api.multipart_invalid"
    assert response.json()["detail"] == "Unreadable or incomplete multipart/form-data form."
    assert scans_de(nom) == []


def test_formulaire_mal_forme_refuse(local, monkeypatch):
    _sans_effet(monkeypatch)
    corps = b"--limite-de-test suffixe inattendu\r\n\r\nx\r\n--limite-de-test--\r\n"
    response = local.post(
        "/api/import", content=corps, headers={"Content-Type": "multipart/form-data; boundary=limite-de-test"}
    )
    assert response.status_code == 400 and response.json()["code"] == "api.multipart_invalid"


def test_corps_vide_ou_trop_de_parties_refuses(local, monkeypatch):
    _sans_effet(monkeypatch)
    en_tetes = {"Content-Type": "multipart/form-data; boundary=limite-de-test"}
    vide = local.post("/api/import", content=b"", headers=en_tetes)
    assert vide.status_code == 400 and vide.json()["code"] == "api.multipart_invalid"
    corps, en_tetes = multipart(*[(f"champ{i}", b"x") for i in range(40)])
    nombreux = local.post("/api/import", content=corps, headers=en_tetes)
    assert nombreux.status_code == 400 and nombreux.json()["code"] == "api.multipart_invalid"


def test_fichier_envoye_par_morceaux(local, tmp_path):
    """Corps sans Content-Length (transfert par morceaux), frontière coupée entre deux morceaux."""
    nom = domaine("morceaux")
    contenu = ancienne_base(
        tmp_path / "ok.db", [{"id": 1, "domain": nom, "scan_timestamp": "2025-01-01 00:00:00"}]
    )
    corps, en_tetes = multipart(("file", contenu))

    def morceaux():
        for debut in range(0, len(corps), 1000):
            yield corps[debut : debut + 1000]

    response = local.post("/api/import", content=morceaux(), headers=en_tetes)
    assert response.status_code == 200 and response.json()["imported"] == 1


# --- Taille ----------------------------------------------------------------------------------


@pytest.fixture
def plafond_de_4_kio(monkeypatch):
    monkeypatch.setattr(import_routes, "MAX_IMPORT_BYTES", 4096)
    monkeypatch.setattr(import_routes, "FORM_OVERHEAD_BYTES", 2048)


def test_fichier_trop_gros(local, plafond_de_4_kio, monkeypatch, dossier_temporaire):
    _sans_effet(monkeypatch)
    for langue, detail in (
        ("fr", "Fichier trop volumineux : 1 Mio au maximum."),
        ("en", "File too large: 1 MiB at most."),
    ):
        # Juste au-dessus du plafond, mais dans la marge de l'enveloppe : refusé par la route…
        response = envoyer(local, b"x" * 5000, params={"lang": langue})
        assert response.status_code == 413
        assert response.json() == {"detail": detail, "code": "api.import_too_large", "params": {"max": 1}}
        # … et bien au-dessus : refusé d'emblée, sur Content-Length, avec le même message.
        response = envoyer(local, b"x" * 100_000, params={"lang": langue})
        assert response.status_code == 413
        assert response.json() == {"detail": detail, "code": "api.import_too_large", "params": {"max": 1}}
    assert list(dossier_temporaire.iterdir()) == []


def test_fichier_trop_gros_envoye_par_morceaux(local, plafond_de_4_kio, monkeypatch, dossier_temporaire):
    """Sans Content-Length, le dépassement est compté au fil de la lecture."""
    _sans_effet(monkeypatch)
    corps, en_tetes = multipart(("file", b"x" * 100_000))

    def morceaux():
        for debut in range(0, len(corps), 4096):
            yield corps[debut : debut + 4096]

    response = local.post("/api/import", content=morceaux(), headers=en_tetes)
    assert response.status_code == 413 and response.json()["code"] == "api.import_too_large"
    assert list(dossier_temporaire.iterdir()) == []


def test_fichier_a_la_limite_est_accepte(local, plafond_de_4_kio):
    """Au plafond exact, la taille ne gêne pas : le refus vient alors du contenu (pas une base SQLite)."""
    response = envoyer(local, b"x" * 4096)
    assert response.status_code == 400 and response.json()["code"] == "api.import_not_sqlite"


def test_la_limite_des_autres_routes_reste_de_1_mio(local):
    gros = b'{"domain": "' + b"a" * (1024 * 1024) + b'"}'
    response = local.post("/api/scan", content=gros, headers={"Content-Type": "application/json"})
    assert response.status_code == 413 and response.json()["code"] == "api.body_too_large"


def test_plafond_par_defaut():
    assert import_routes.MAX_IMPORT_BYTES == 512 * 1024 * 1024
    limite, message = import_routes.upload_limit()
    assert limite == import_routes.MAX_IMPORT_BYTES + import_routes.FORM_OVERHEAD_BYTES
    assert message == {"$t": "api.import_too_large", "p": {"max": 512}}


# --- Requêtes locales et de même origine ------------------------------------------------------


def test_reserve_aux_requetes_locales(distant, tmp_path, monkeypatch, dossier_temporaire):
    nom = domaine("distant")
    contenu = ancienne_base(
        tmp_path / "ok.db", [{"id": 1, "domain": nom, "scan_timestamp": "2025-01-01 00:00:00"}]
    )
    _sans_effet(monkeypatch)
    response = envoyer(distant, contenu, params={"lang": "en"})
    assert response.status_code == 403
    assert response.json() == {"detail": DETAIL_LOCAL_ONLY, "code": "api.local_only", "params": {}}
    assert scans_de(nom) == []
    assert list(dossier_temporaire.iterdir()) == []  # le corps n'a même pas été copié
    # La provenance prime sur la forme du corps : rien n'est révélé à une autre machine.
    assert distant.post("/api/import", json={}).status_code == 403
    assert (
        distant.post("/api/import", content=b"x", headers={"X-Forwarded-For": "127.0.0.1"}).status_code == 403
    )


@pytest.mark.parametrize("adresse", ["127.0.0.1", "::1", "localhost", "::ffff:127.0.0.1"])
def test_adresses_de_bouclage_acceptees(monkeypatch, tmp_path, adresse):
    monkeypatch.setenv("SCHEDULER", "0")
    nom = domaine("boucle")
    contenu = ancienne_base(
        tmp_path / "ok.db", [{"id": 1, "domain": nom, "scan_timestamp": "2025-01-01 00:00:00"}]
    )
    with TestClient(app, client=(adresse, 50000)) as client:
        assert envoyer(client, contenu).json()["imported"] == 1


@pytest.mark.parametrize("adresse", ["192.168.1.20", "10.0.0.5", "8.8.8.8", "fe80::1", "::ffff:192.168.1.20"])
def test_adresses_hors_de_la_machine_refusees(monkeypatch, adresse):
    monkeypatch.setenv("SCHEDULER", "0")
    _sans_effet(monkeypatch)
    with TestClient(app, client=(adresse, 50000)) as client:
        assert envoyer(client, b"x").status_code == 403


@pytest.mark.parametrize(
    "en_tetes",
    [
        {"Origin": "http://evil.example"},
        {"Origin": "http://127.0.0.1:9999"},
        {"Origin": "null"},
        {"Origin": "https://testserver.evil.example"},
        {"Sec-Fetch-Site": "cross-site"},
        {"Sec-Fetch-Site": "same-site"},
        {"Origin": "http://testserver", "Sec-Fetch-Site": "cross-site"},
    ],
    ids=[
        "site-tiers",
        "autre-port",
        "origine-null",
        "hote-voisin",
        "cross-site",
        "same-site",
        "origine-ok-mais-cross-site",
    ],
)
def test_requete_d_une_autre_origine_refusee(local, monkeypatch, en_tetes):
    """Un formulaire HTML d'un site tiers peut envoyer du multipart vers l'API locale : refusé (anti-CSRF)."""
    _sans_effet(monkeypatch)
    response = envoyer(local, b"x", headers=en_tetes, params={"lang": "en"})
    assert response.status_code == 403
    assert response.json() == {
        "detail": "Request refused: it does not come from the application's own interface (different origin).",
        "code": "api.cross_origin",
        "params": {},
    }


@pytest.mark.parametrize(
    "en_tetes",
    [
        {},  # client sans navigateur (curl, script)
        {"Origin": "http://testserver"},
        {"Origin": "HTTP://TestServer"},
        {"Origin": "http://testserver", "Sec-Fetch-Site": "same-origin"},
        {"Sec-Fetch-Site": "none"},
    ],
    ids=["sans-en-tete", "meme-origine", "casse-ignoree", "same-origin", "none"],
)
def test_requete_de_la_meme_origine_acceptee(local, tmp_path, en_tetes):
    nom = domaine("origine")
    contenu = ancienne_base(
        tmp_path / "ok.db", [{"id": 1, "domain": nom, "scan_timestamp": "2025-01-01 00:00:00"}]
    )
    assert envoyer(local, contenu, headers=en_tetes).json()["imported"] == 1


def test_origine_declaree_dans_cors_origins_acceptee(local, tmp_path, monkeypatch):
    """Interface servie ailleurs : son origine, déclarée par l'opérateur, peut importer ; une autre reste refusée."""
    monkeypatch.setattr(config, "CORS_ORIGINS", ["http://front.example"])
    nom = domaine("cors")
    contenu = ancienne_base(
        tmp_path / "ok.db", [{"id": 1, "domain": nom, "scan_timestamp": "2025-01-01 00:00:00"}]
    )
    entetes = {"Origin": "http://front.example", "Sec-Fetch-Site": "cross-site"}
    assert envoyer(local, contenu, headers=entetes).json()["imported"] == 1
    refus = envoyer(local, contenu, headers={**entetes, "Origin": "http://evil.example"})
    assert refus.status_code == 403 and refus.json()["code"] == "api.cross_origin"


def test_la_provenance_est_verifiee_avant_l_origine(distant, monkeypatch):
    _sans_effet(monkeypatch)
    response = envoyer(distant, b"x", headers={"Origin": "http://evil.example"})
    assert response.json()["code"] == "api.local_only"


def test_jeton_d_api_exige(local, tmp_path, monkeypatch):
    monkeypatch.setattr(config, "API_TOKEN", "s3cret-jeton")
    nom = domaine("jeton")
    contenu = ancienne_base(
        tmp_path / "ok.db", [{"id": 1, "domain": nom, "scan_timestamp": "2025-01-01 00:00:00"}]
    )
    assert envoyer(local, contenu).status_code == 401
    assert scans_de(nom) == []
    response = envoyer(local, contenu, headers={"X-API-Token": "s3cret-jeton"})
    assert response.status_code == 200 and response.json()["imported"] == 1


# --- Fichier temporaire et verrou -------------------------------------------------------------


def test_fichier_temporaire_supprime_apres_un_import_reussi(local, tmp_path, dossier_temporaire, monkeypatch):
    nom = domaine("nettoye")
    contenu = ancienne_base(
        tmp_path / "ok.db", [{"id": 1, "domain": nom, "scan_timestamp": "2025-01-01 00:00:00"}]
    )
    vus: list[Path] = []
    importer_reel = cli_importer.import_scans

    def espion(chemin, *args, **kwargs):
        vus.append(Path(chemin))
        assert Path(chemin).is_file() and Path(chemin).parent.parent == dossier_temporaire
        assert Path(chemin).parent.name.startswith(import_routes.TEMP_PREFIX)
        return importer_reel(chemin, *args, **kwargs)

    monkeypatch.setattr(cli_importer, "import_scans", espion)
    assert envoyer(local, contenu).status_code == 200
    assert len(vus) == 1
    assert not vus[0].exists() and not vus[0].parent.exists()
    assert list(dossier_temporaire.iterdir()) == []


@pytest.mark.parametrize(
    "contenu",
    [b"pas une base", b""],
    ids=["texte", "vide"],
)
def test_fichier_temporaire_supprime_apres_un_refus(local, dossier_temporaire, contenu):
    assert envoyer(local, contenu).status_code == 400
    assert list(dossier_temporaire.iterdir()) == []


def test_fichier_temporaire_supprime_apres_un_formulaire_invalide(local, dossier_temporaire):
    corps, en_tetes = multipart(("file", b"SQLite format 3\x00" + b"\x00" * 500), fin=False)
    assert local.post("/api/import", content=corps, headers=en_tetes).status_code == 400
    corps, en_tetes = multipart(("autre", b"x"))
    assert local.post("/api/import", content=corps, headers=en_tetes).status_code == 400
    assert list(dossier_temporaire.iterdir()) == []


def test_echec_inattendu_de_l_import(local, tmp_path, monkeypatch, dossier_temporaire, caplog):
    """Erreur imprévue : 500 explicite sans détail interne, fichier supprimé, verrou rendu."""
    monkeypatch.setattr(
        cli_importer, "import_scans", lambda *a, **k: (_ for _ in ()).throw(RuntimeError("secret-interne"))
    )
    response = envoyer(local, b"x", params={"lang": "en"})
    assert response.status_code == 500
    assert response.json()["code"] == "api.import_failed"
    assert "secret-interne" not in response.text
    assert "secret-interne" in caplog.text  # le détail reste dans les journaux
    assert list(dossier_temporaire.iterdir()) == []
    assert not import_routes._import_lock.locked()


def test_ecriture_impossible_du_fichier_temporaire(local, monkeypatch, dossier_temporaire):
    def disque_plein(**kwargs):
        raise OSError(28, "No space left on device")

    monkeypatch.setattr(import_routes.tempfile, "mkdtemp", disque_plein)
    response = envoyer(local, b"x")
    assert response.status_code == 500 and response.json()["code"] == "api.import_failed"
    assert not import_routes._import_lock.locked()


def test_un_seul_import_a_la_fois(local, tmp_path):
    nom = domaine("verrou")
    contenu = ancienne_base(
        tmp_path / "ok.db", [{"id": 1, "domain": nom, "scan_timestamp": "2025-01-01 00:00:00"}]
    )
    assert import_routes._import_lock.acquire(blocking=False)
    try:
        response = envoyer(local, contenu, params={"lang": "en"})
        assert response.status_code == 409
        assert response.json() == {
            "detail": "An import is already running: wait for it to finish before starting another.",
            "code": "api.import_running",
            "params": {},
        }
        assert scans_de(nom) == []
    finally:
        import_routes._import_lock.release()
    assert envoyer(local, contenu).json()["imported"] == 1


def test_le_verrou_est_rendu_apres_chaque_issue(local, tmp_path):
    for contenu in (b"pas une base", b""):
        envoyer(local, contenu)
        assert not import_routes._import_lock.locked()
    corps, en_tetes = multipart(("file", b"x"), fin=False)
    local.post("/api/import", content=corps, headers=en_tetes)
    assert not import_routes._import_lock.locked()


def test_deux_imports_simultanes_un_seul_s_execute(local, tmp_path, monkeypatch):
    """Deux envois en même temps : l'un est importé, l'autre reçoit 409 (jamais deux écritures croisées)."""
    nom = domaine("simultane")
    contenu = ancienne_base(
        tmp_path / "ok.db", [{"id": 1, "domain": nom, "scan_timestamp": "2025-01-01 00:00:00"}]
    )
    entre = threading.Event()
    liberer = threading.Event()
    importer_reel = cli_importer.import_scans

    def lent(chemin, *args, **kwargs):
        entre.set()
        assert liberer.wait(30)
        return importer_reel(chemin, *args, **kwargs)

    monkeypatch.setattr(cli_importer, "import_scans", lent)
    reponses: dict[str, int] = {}
    fil = threading.Thread(target=lambda: reponses.update(premier=envoyer(local, contenu).status_code))
    fil.start()
    try:
        assert entre.wait(30)
        assert envoyer(local, contenu).status_code == 409
    finally:
        liberer.set()
        fil.join(30)
    assert reponses == {"premier": 200}
    assert len(scans_de(nom)) == 1


# --- Réponse ----------------------------------------------------------------------------------


def test_colonnes_inconnues_bornees_dans_la_reponse(local, tmp_path):
    nom = domaine("colonnes")
    inconnues = [f"colonne_inconnue_{i:03d}_" + "x" * 80 for i in range(80)]
    schema = (
        "CREATE TABLE scans (id INTEGER PRIMARY KEY, domain TEXT, scan_timestamp TEXT, "
        + ", ".join(f'"{nom_colonne}" TEXT' for nom_colonne in inconnues)
        + ")"
    )
    contenu = ancienne_base(
        tmp_path / "colonnes.db",
        [{"id": 1, "domain": nom, "scan_timestamp": "2025-01-01 00:00:00"}],
        schema=schema,
    )
    resultat = envoyer(local, contenu).json()
    assert resultat["imported"] == 1
    assert len(resultat["unknown_columns"]) == import_routes.MAX_UNKNOWN_COLUMNS
    assert all(
        len(nom_colonne) <= import_routes.MAX_COLUMN_NAME_LENGTH
        for nom_colonne in resultat["unknown_columns"]
    )
    assert resultat["unknown_columns"][0] == inconnues[0][: import_routes.MAX_COLUMN_NAME_LENGTH]


def test_methode_get_non_prise_en_charge(local):
    assert local.get("/api/import").status_code == 405


def test_csp_de_l_api_sur_la_reponse(local):
    response = envoyer(local, b"pas une base")
    assert response.headers["content-security-policy"].startswith("default-src 'none'")


def test_route_documentee_dans_openapi():
    schema = app.openapi()["paths"][import_routes.IMPORT_PATH]["post"]
    assert schema["requestBody"]["content"]["multipart/form-data"]["schema"]["required"] == ["file"]
    assert {"400", "403", "409", "413", "415", "500"} <= set(schema["responses"])
    resultat = app.openapi()["components"]["schemas"]["ImportResult"]
    assert set(resultat["properties"]) == {
        "read",
        "imported",
        "ignored",
        "duplicates",
        "unusable",
        "unknown_columns",
    }


def test_chemin_de_la_route_et_limite_alignes():
    chemins = {route.path for route in import_routes.router.routes}
    assert chemins == {import_routes.IMPORT_PATH}
