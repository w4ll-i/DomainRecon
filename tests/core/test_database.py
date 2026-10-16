# =============================================================================
# DomainRecon - Tests de la base : migration de schéma, moteur, modèle
# =============================================================================

import logging
import sqlite3
from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import JSON, Column, Integer, String, Text, create_engine, inspect, text
from sqlalchemy.orm import declarative_base, sessionmaker

from domainrecon.api import schemas, storage
from domainrecon.core import database, settings_store
from domainrecon.core.database import SchemaMigrationError, sync_schema
from domainrecon.core.models import Scan, utcnow

# Schéma tel qu'il existait avant l'ajout de module_status / scan_duration (v3.1)
# et de modules, profile / modules_launched (v2).
ANCIEN_SCHEMA = """
CREATE TABLE scans (
    id INTEGER NOT NULL PRIMARY KEY,
    domain VARCHAR(255) NOT NULL,
    ip_address VARCHAR(45),
    dns_records JSON,
    subdomains JSON,
    security_headers JSON,
    whois_data JSON,
    geo_data JSON,
    tls_certificate JSON,
    open_ports JSON,
    technologies JSON,
    email_security JSON,
    waf JSON,
    redirect_chain JSON,
    web_files JSON,
    cookie_security JSON,
    cors JSON,
    reverse_dns_data JSON,
    subdomain_takeover JSON,
    network_extended JSON,
    security_score JSON,
    screenshot_path VARCHAR(500),
    tags JSON,
    notes TEXT,
    scan_timestamp DATETIME NOT NULL,
    status VARCHAR(50) NOT NULL,
    error_message TEXT
);
"""


def _ancienne_base(tmp_path):
    db = tmp_path / "ancienne.db"
    with sqlite3.connect(db) as conn:
        conn.executescript(ANCIEN_SCHEMA)
        conn.execute(
            "INSERT INTO scans (domain, scan_timestamp, status) VALUES (?, ?, ?)",
            ("example.com", "2025-01-01 00:00:00", "success"),
        )
    conn.close()
    return create_engine(f"sqlite:///{db.as_posix()}")


def test_migration_ajoute_les_colonnes_manquantes(tmp_path):
    """Une base créée par une version antérieure doit rester exploitable.

    `create_all()` ne touche pas une table existante : sans migration, chaque
    requête échouait dès qu'une colonne était ajoutée au modèle.
    """
    engine = _ancienne_base(tmp_path)
    ajoutees = sync_schema(Scan, target_engine=engine)

    assert set(ajoutees) == {"module_status", "scan_duration", "modules", "profile", "modules_launched"}

    colonnes = {c["name"] for c in inspect(engine).get_columns("scans")}
    assert {"module_status", "scan_duration", "modules", "profile", "modules_launched"} <= colonnes

    # La ligne existante est préservée et lisible.
    with engine.connect() as conn:
        row = conn.execute(text("SELECT domain, module_status FROM scans")).one()
    assert row[0] == "example.com"
    assert row[1] is None

    # Deuxième passage : rien à faire, aucune erreur.
    assert sync_schema(Scan, target_engine=engine) == []
    engine.dispose()


def test_migration_cree_les_index_du_modele(tmp_path):
    engine = _ancienne_base(tmp_path)
    sync_schema(Scan, target_engine=engine)

    index = {i["name"]: i["column_names"] for i in inspect(engine).get_indexes("scans")}
    # create_all ne crée pas les index d'une table existante : sync_schema s'en charge.
    assert index["ix_scans_domain"] == ["domain"]
    assert index["ix_scans_scan_timestamp"] == ["scan_timestamp"]
    engine.dispose()


def test_migration_ignore_une_table_absente(tmp_path):
    engine = create_engine(f"sqlite:///{(tmp_path / 'vide.db').as_posix()}")
    assert sync_schema(Scan, target_engine=engine) == []
    engine.dispose()


def _base_v1(tmp_path):
    """Base d'une v1 à jour : toutes les colonnes d'aujourd'hui, sauf celles de la v2 (`modules`, `profile`, `modules_launched`)."""
    engine = _ancienne_base(tmp_path)
    with engine.begin() as conn:
        conn.exec_driver_sql("ALTER TABLE scans ADD COLUMN module_status JSON")
        conn.exec_driver_sql("ALTER TABLE scans ADD COLUMN scan_duration FLOAT")
    return engine


def test_migration_ajoute_la_colonne_modules(tmp_path):
    """Base d'avant la v2 : `modules`, `profile` et `modules_launched` sont ajoutées, vides, sans toucher aux anciens scans."""
    engine = _base_v1(tmp_path)
    assert {"modules", "profile", "modules_launched"}.isdisjoint(
        {c["name"] for c in inspect(engine).get_columns("scans")}
    )

    assert sync_schema(Scan, target_engine=engine) == ["modules", "profile", "modules_launched"]

    colonnes = {c["name"]: c for c in inspect(engine).get_columns("scans")}
    for nom in ("modules", "profile", "modules_launched"):
        assert colonnes[nom]["nullable"], nom
    assert isinstance(colonnes["modules"]["type"], JSON)
    assert isinstance(colonnes["modules_launched"]["type"], JSON)
    assert isinstance(colonnes["profile"]["type"], Text)

    # L'ancien scan est préservé : NULL SQL (et non le JSON « null »), None à la lecture.
    with engine.connect() as conn:
        row = conn.execute(
            text("SELECT domain, modules IS NULL, profile IS NULL, modules_launched IS NULL FROM scans")
        ).one()
    assert tuple(row) == ("example.com", 1, 1, 1)
    with sessionmaker(bind=engine)() as db:
        assert tuple(db.query(Scan.domain, Scan.modules, Scan.profile, Scan.modules_launched).one()) == (
            "example.com",
            None,
            None,
            None,
        )

    # Deuxième démarrage : rien à faire, aucune erreur.
    assert sync_schema(Scan, target_engine=engine) == []
    engine.dispose()


def test_base_migree_ecrit_et_relit_les_modules(tmp_path):
    engine = _base_v1(tmp_path)
    sync_schema(Scan, target_engine=engine)
    modules = {"shodan": {"status": "ok", "data": {"ports": [80, 443]}, "duration": 1.5, "error": None}}

    with sessionmaker(bind=engine)() as db:
        db.add(Scan(domain="avec.example", status="success", modules=modules))
        # None explicite : NULL SQL, comme un ancien scan (pas le JSON « null »).
        db.add(Scan(domain="sans.example", status="success", modules=None))
        db.commit()

    with sessionmaker(bind=engine)() as db:
        lus = dict(db.query(Scan.domain, Scan.modules).all())
    assert lus == {"example.com": None, "avec.example": modules, "sans.example": None}
    with engine.connect() as conn:
        nuls = conn.execute(text("SELECT domain FROM scans WHERE modules IS NULL ORDER BY domain")).scalars()
        assert list(nuls) == ["example.com", "sans.example"]
    engine.dispose()


def test_le_demarrage_ajoute_la_colonne_modules(tmp_path, monkeypatch, caplog):
    """prepare_storage() migre la base existante, une seule fois ; son ancien scan reste lisible."""
    engine = _base_v1(tmp_path)
    sessions = sessionmaker(bind=engine)
    # La base d'avant la v2 remplace celle de l'application ; captures dans un dossier à part.
    monkeypatch.setattr(database, "engine", engine)
    monkeypatch.setattr(storage, "engine", engine)
    monkeypatch.setattr(storage, "SessionLocal", sessions)
    monkeypatch.setattr(settings_store, "SessionLocal", sessions)
    monkeypatch.setattr(storage, "SCREENSHOTS_DIR", tmp_path / "captures")
    try:
        with caplog.at_level(logging.INFO, logger="domainrecon.api.storage"):
            storage.prepare_storage()
        assert "Colonnes ajoutées à la base existante : modules, profile, modules_launched" in caplog.messages
        assert {"modules", "profile", "modules_launched"} <= {
            c["name"] for c in inspect(engine).get_columns("scans")
        }

        with sessions() as db:
            ancien = schemas.ScanResponse.model_validate(db.query(Scan).one())
        assert (ancien.domain, ancien.modules, ancien.profile, ancien.modules_launched) == (
            "example.com",
            None,
            None,
            None,
        )

        # Redémarrage : plus rien à ajouter.
        caplog.clear()
        with caplog.at_level(logging.INFO, logger="domainrecon.api.storage"):
            storage.prepare_storage()
        assert not [message for message in caplog.messages if message.startswith("Colonnes ajoutées")]
    finally:
        engine.dispose()


def _modele(**colonnes):
    """Modèle `scans` réduit, avec des colonnes supplémentaires."""
    base = declarative_base()
    attributs = {
        "__tablename__": "scans",
        "id": Column(Integer, primary_key=True),
        "domain": Column(String(255), nullable=False),
        **colonnes,
    }
    return type("ScanFutur", (base,), attributs)


def test_colonne_obligatoire_sans_defaut_bloque_le_demarrage(tmp_path):
    engine = _ancienne_base(tmp_path)
    modele = _modele(
        categorie=Column(String(20), nullable=True),
        proprietaire=Column(String(50), nullable=False),
    )

    with pytest.raises(SchemaMigrationError, match="proprietaire"):
        sync_schema(modele, target_engine=engine)

    # Rien n'a été modifié : pas de migration à moitié faite.
    colonnes = {c["name"] for c in inspect(engine).get_columns("scans")}
    assert "categorie" not in colonnes
    assert "proprietaire" not in colonnes
    engine.dispose()


def test_colonne_obligatoire_avec_defaut_serveur_ajoutee(tmp_path):
    engine = _ancienne_base(tmp_path)
    modele = _modele(origine=Column(String(20), nullable=False, server_default="manuel"))

    assert sync_schema(modele, target_engine=engine) == ["origine"]
    with engine.connect() as conn:
        assert conn.execute(text("SELECT origine FROM scans")).scalar_one() == "manuel"
    engine.dispose()


def test_colonne_ajoutee_par_un_autre_processus(tmp_path, monkeypatch):
    """Deux workers démarrent ensemble : l'ALTER du second échoue, sans gravité."""
    engine = _ancienne_base(tmp_path)
    sync_schema(Scan, target_engine=engine)  # le « premier worker » a migré

    vraie_lecture = database._column_names
    appels = []

    def lecture_perimee(target_engine, table_name):
        appels.append(table_name)
        colonnes = vraie_lecture(target_engine, table_name)
        # Première lecture : état d'avant la migration du premier worker.
        return colonnes - {"module_status"} if len(appels) == 1 else colonnes

    monkeypatch.setattr(database, "_column_names", lecture_perimee)
    assert sync_schema(Scan, target_engine=engine) == []
    assert len(appels) == 2  # relu après l'échec de l'ALTER
    engine.dispose()


def test_options_du_moteur():
    fichier = database._engine_options("sqlite:///C:/donnees/recon.db")
    assert fichier["connect_args"] == {"check_same_thread": False}
    assert fichier["pool_timeout"] == database.POOL_TIMEOUT

    # Base en mémoire : pool à connexion unique, qui refuse pool_timeout.
    memoire = database._engine_options("sqlite://")
    assert "pool_timeout" not in memoire
    create_engine("sqlite://", **memoire).dispose()

    postgres = database._engine_options("postgresql+psycopg://user:mdp@localhost/recon")
    assert "connect_args" not in postgres
    assert postgres["pool_timeout"] == database.POOL_TIMEOUT


def test_horodatage_stocke_en_utc_naif():
    maintenant = utcnow()
    assert maintenant.tzinfo is None
    reference = datetime.now(timezone.utc).replace(tzinfo=None)
    assert abs(reference - maintenant) < timedelta(seconds=5)


def test_attribut_reverse_dns_sur_la_colonne_historique():
    # L'attribut suit le nom de l'API ; la colonne garde son nom en base.
    assert Scan.__table__.c.reverse_dns_data is Scan.reverse_dns.property.columns[0]
    assert "reverse_dns" not in Scan.__table__.c
