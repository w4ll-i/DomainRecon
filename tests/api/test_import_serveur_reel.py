# =============================================================================
# DomainRecon - Test de POST /api/import contre un vrai serveur uvicorn
# =============================================================================
# Le TestClient appelle l'application sans réseau. Ici, le serveur du lanceur
# écoute sur 127.0.0.1 et une vraie connexion HTTP envoie une base de plusieurs
# Mio, avec Content-Length puis par morceaux (Transfer-Encoding: chunked) : la
# provenance (adresse de bouclage de la connexion), l'origine et la limite de
# taille sont jugées sur de vrais sockets.
# =============================================================================

import http.client
import itertools
import json
import os
import sqlite3
from pathlib import Path

import pytest

from domainrecon.api.routes import importer as import_routes
from domainrecon.core.database import SessionLocal
from domainrecon.core.models import Scan
from domainrecon.desktop import launcher

BOUNDARY = "----frontiere-du-test-reel"
_compteur = itertools.count(1)


@pytest.fixture(scope="module")
def serveur():
    with pytest.MonkeyPatch.context() as monkeypatch:
        monkeypatch.setenv("SCHEDULER", "0")  # pas de planificateur : aucun scan ne part pendant le test
        port = launcher.find_free_port()
        handle = launcher.start_server("127.0.0.1", port)
        try:
            assert launcher.wait_until_healthy(handle.url, timeout=30) is True
            yield port
        finally:
            handle.stop()


def base_volumineuse(chemin: Path, domaine: str, lignes: int = 3, octets: int = 3_000_000) -> bytes:
    conn = sqlite3.connect(chemin)
    conn.execute("CREATE TABLE scans (id INTEGER PRIMARY KEY, domain TEXT, scan_timestamp TEXT, notes TEXT)")
    for i in range(1, lignes + 1):
        conn.execute(
            "INSERT INTO scans (id, domain, scan_timestamp, notes) VALUES (?, ?, ?, ?)",
            (i, domaine, f"2025-02-0{i} 00:00:00", chr(97 + i) * octets),
        )
    conn.commit()
    conn.close()
    return chemin.read_bytes()


def formulaire(contenu: bytes) -> bytes:
    return (
        (
            f'--{BOUNDARY}\r\nContent-Disposition: form-data; name="file"; filename="domainrecon.db"\r\n'
            "Content-Type: application/octet-stream\r\n\r\n"
        ).encode()
        + contenu
        + f"\r\n--{BOUNDARY}--\r\n".encode()
    )


def envoyer(port: int, corps, en_tetes: dict | None = None, **options):
    """POST /api/import sur une vraie connexion ; renvoie (statut, JSON)."""
    entetes = {"Content-Type": f"multipart/form-data; boundary={BOUNDARY}", **(en_tetes or {})}
    connexion = http.client.HTTPConnection("127.0.0.1", port, timeout=120)
    try:
        connexion.request("POST", "/api/import", body=corps, headers=entetes, **options)
        reponse = connexion.getresponse()
        return reponse.status, json.loads(reponse.read())
    finally:
        connexion.close()


def morceaux(corps: bytes, taille: int = 50_000):
    for debut in range(0, len(corps), taille):
        yield corps[debut : debut + taille]


def scans_de(domaine: str) -> int:
    with SessionLocal() as db:
        return db.query(Scan).filter(Scan.domain == domaine).count()


def test_base_de_plusieurs_mio_envoyee_avec_content_length(serveur, tmp_path):
    domaine = f"reel{next(_compteur)}-{os.getpid()}.example.org"
    corps = formulaire(base_volumineuse(tmp_path / "gros.db", domaine))
    assert len(corps) > 9_000_000  # bien au-delà de la limite de 1 Mio des corps JSON
    statut, reponse = envoyer(serveur, corps)
    assert statut == 200, reponse
    assert reponse == {
        "read": 3,
        "imported": 3,
        "ignored": 0,
        "duplicates": 0,
        "unusable": 0,
        "unknown_columns": [],
    }
    assert scans_de(domaine) == 3
    # Même envoi une seconde fois : tout est reconnu comme déjà présent.
    statut, reponse = envoyer(serveur, corps)
    assert statut == 200 and (reponse["imported"], reponse["duplicates"], reponse["ignored"]) == (0, 3, 3)
    assert scans_de(domaine) == 3


def test_base_envoyee_par_morceaux_sans_content_length(serveur, tmp_path):
    domaine = f"reel{next(_compteur)}-{os.getpid()}.example.org"
    corps = formulaire(base_volumineuse(tmp_path / "gros.db", domaine, lignes=2, octets=2_000_000))
    statut, reponse = envoyer(serveur, morceaux(corps), {"Transfer-Encoding": "chunked"}, encode_chunked=True)
    assert statut == 200, reponse
    assert reponse["imported"] == 2 and scans_de(domaine) == 2


def test_taille_plafonnee_sur_une_vraie_connexion(serveur, tmp_path, monkeypatch):
    domaine = f"reel{next(_compteur)}-{os.getpid()}.example.org"
    corps = formulaire(base_volumineuse(tmp_path / "gros.db", domaine, lignes=1, octets=2_000_000))
    monkeypatch.setattr(import_routes, "MAX_IMPORT_BYTES", 1_000_000)
    # Content-Length annoncé : refusé sans lire le corps ; le serveur absorbe la fin de l'envoi.
    statut, reponse = envoyer(serveur, corps)
    assert statut == 413 and reponse["code"] == "api.import_too_large"
    # Par morceaux : le dépassement est constaté au fil de la lecture.
    statut, reponse = envoyer(serveur, morceaux(corps), {"Transfer-Encoding": "chunked"}, encode_chunked=True)
    assert statut == 413 and reponse["code"] == "api.import_too_large"
    assert scans_de(domaine) == 0


def test_origine_jugee_sur_une_vraie_connexion(serveur, tmp_path):
    domaine = f"reel{next(_compteur)}-{os.getpid()}.example.org"
    corps = formulaire(base_volumineuse(tmp_path / "petit.db", domaine, lignes=1, octets=1000))
    statut, reponse = envoyer(serveur, corps, {"Origin": "http://evil.example"})
    assert statut == 403 and reponse["code"] == "api.cross_origin"
    assert scans_de(domaine) == 0
    statut, reponse = envoyer(serveur, corps, {"Origin": f"http://127.0.0.1:{serveur}"})
    assert statut == 200 and reponse["imported"] == 1


def test_en_tete_x_forwarded_for_ne_change_pas_la_provenance(serveur, tmp_path):
    """Le serveur du lanceur ne croit pas X-Forwarded-For : la machine locale reste locale (et le reste, jugé sur la connexion)."""
    domaine = f"reel{next(_compteur)}-{os.getpid()}.example.org"
    corps = formulaire(base_volumineuse(tmp_path / "petit.db", domaine, lignes=1, octets=1000))
    statut, reponse = envoyer(serveur, corps, {"X-Forwarded-For": "203.0.113.9"})
    assert statut == 200 and reponse["imported"] == 1


def test_base_invalide_sur_une_vraie_connexion(serveur):
    statut, reponse = envoyer(serveur, formulaire(b"ceci n'est pas une base SQLite" * 1000))
    assert statut == 400 and reponse["code"] == "api.import_not_sqlite"
    statut, reponse = envoyer(serveur, b"x", {"Content-Type": "application/json"})
    assert statut == 415 and reponse["code"] == "api.multipart_required"
