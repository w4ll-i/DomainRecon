# =============================================================================
# DomainRecon - Tests de la lecture de l'ancienne base (cli/importer.py)
# =============================================================================
# Ce que l'import en ligne de commande et POST /api/import partagent : causes
# des refus (ImportSourceError.reason), base source ouverte en lecture seule et
# sans schéma de confiance, lecture au fil de l'eau, fichier libéré après usage.
# =============================================================================

import inspect
import sqlite3

import pytest

from domainrecon.cli import importer
from domainrecon.cli._common import CliError
from domainrecon.core.database import SessionLocal, engine
from domainrecon.core.models import Scan

from .rapports_aides import unique_domain

SCHEMA = (
    "CREATE TABLE scans (id INTEGER PRIMARY KEY, domain VARCHAR(255) NOT NULL, dns_records JSON, "
    "scan_timestamp DATETIME, notes TEXT)"
)


def _base(chemin, lignes=(), schema=SCHEMA, commandes=()):
    conn = sqlite3.connect(chemin)
    conn.execute(schema)
    for commande in commandes:
        conn.execute(commande)
    for ligne in lignes:
        conn.execute(
            f"INSERT INTO scans ({', '.join(ligne)}) VALUES ({', '.join('?' * len(ligne))})",
            list(ligne.values()),
        )
    conn.commit()
    conn.close()
    return chemin


def _colonnes_actuelles() -> set[str]:
    return importer._current_columns()[0]


def _scans_de(domaine):
    with SessionLocal() as db:
        return db.query(Scan).filter(Scan.domain == domaine).all()


# --- Causes des refus --------------------------------------------------------------------------


def test_une_base_inutilisable_leve_une_erreur_de_la_ligne_de_commande(stockage, tmp_path):
    with pytest.raises(importer.ImportSourceError) as erreur:
        importer.import_scans(tmp_path / "absent.db")
    assert isinstance(erreur.value, CliError) and erreur.value.code == 2
    assert erreur.value.reason == importer.REASON_NOT_FOUND and "Fichier introuvable" in str(erreur.value)


def test_la_base_courante_est_refusee(stockage):
    with pytest.raises(importer.ImportSourceError) as erreur:
        importer.import_scans(engine.url.database)
    assert erreur.value.reason == importer.REASON_CURRENT and "base courante" in str(erreur.value)


@pytest.mark.parametrize(
    "contenu",
    [b"", b"ceci n'est pas SQLite" * 50, b"SQLite format 3" + b"\x01" * 100, b"\x89PNG\r\n" + bytes(300)],
    ids=["vide", "texte", "en-tete-altere", "png"],
)
def test_un_fichier_qui_n_est_pas_sqlite(stockage, tmp_path, contenu):
    fichier = tmp_path / "x.db"
    fichier.write_bytes(contenu)
    with pytest.raises(importer.ImportSourceError) as erreur:
        importer.import_scans(fichier)
    assert erreur.value.reason == importer.REASON_NOT_SQLITE and "SQLite" in str(erreur.value)


def test_en_tete_sqlite_sur_un_contenu_illisible(stockage, tmp_path):
    fichier = tmp_path / "x.db"
    fichier.write_bytes(importer.SQLITE_HEADER + b"\xff" * 4096)
    with pytest.raises(importer.ImportSourceError) as erreur:
        importer.import_scans(fichier)
    assert erreur.value.reason == importer.REASON_NOT_SQLITE


@pytest.mark.parametrize(
    ("schema", "commandes"),
    [
        ("CREATE TABLE autre (x INTEGER)", ()),
        (
            "CREATE TABLE reelle (domain TEXT, scan_timestamp TEXT)",
            ("CREATE VIEW scans AS SELECT * FROM reelle",),
        ),
        ("CREATE TABLE scans (id INTEGER PRIMARY KEY, notes TEXT)", ()),
        ("CREATE TABLE scans (id INTEGER PRIMARY KEY, domain TEXT)", ()),
        ("CREATE TABLE scans (id INTEGER PRIMARY KEY, scan_timestamp TEXT)", ()),
    ],
    ids=["sans-table-scans", "scans-est-une-vue", "ni-domaine-ni-date", "sans-date", "sans-domaine"],
)
def test_une_base_sqlite_qui_n_est_pas_dans_le_format_de_domainrecon(stockage, tmp_path, schema, commandes):
    fichier = tmp_path / "x.db"
    conn = sqlite3.connect(fichier)
    conn.execute(schema)
    for commande in commandes:
        conn.execute(commande)
    conn.commit()
    conn.close()
    with pytest.raises(importer.ImportSourceError) as erreur:
        importer.import_scans(fichier)
    assert erreur.value.reason == importer.REASON_NOT_DOMAINRECON


def test_une_base_dont_la_table_s_ecrit_en_majuscules_est_acceptee(stockage, tmp_path):
    domaine = unique_domain("casse")
    fichier = _base(
        tmp_path / "x.db",
        [{"id": 1, "domain": domaine, "scan_timestamp": "2025-01-01 00:00:00"}],
        schema=SCHEMA.replace("TABLE scans", "TABLE SCANS"),
    )
    assert importer.import_scans(fichier).imported == 1


# --- Base source : lecture seule, schéma non fiable, flux ------------------------------------------


def test_la_base_source_est_ouverte_en_lecture_seule_sans_schema_de_confiance(tmp_path):
    fichier = _base(
        tmp_path / "x.db", [{"id": 1, "domain": "a.example.org", "scan_timestamp": "2025-01-01 00:00:00"}]
    )
    avant = fichier.read_bytes()
    with importer._Source(fichier, _colonnes_actuelles()) as source:
        assert source._conn.execute("PRAGMA trusted_schema").fetchone()[0] == 0
        with pytest.raises(sqlite3.OperationalError, match="readonly"):
            source._conn.execute("INSERT INTO scans (domain) VALUES ('x')")
    assert fichier.read_bytes() == avant


def test_les_lignes_sont_lues_au_fil_de_l_eau(tmp_path):
    lignes = [
        {"id": i, "domain": f"d{i}.example.org", "scan_timestamp": "2025-01-01 00:00:00"} for i in range(1, 6)
    ]
    fichier = _base(tmp_path / "x.db", lignes)
    with importer._Source(fichier, _colonnes_actuelles()) as source:
        flux = source.rows()
        assert inspect.isgenerator(flux)
        premier = next(flux)
        assert premier["domain"] == "d1.example.org"
        assert set(premier) == {
            "domain",
            "dns_records",
            "scan_timestamp",
            "notes",
        }  # « id » n'est jamais repris
        assert [ligne["domain"] for ligne in flux] == [f"d{i}.example.org" for i in range(2, 6)]


def test_les_colonnes_sont_rapprochees_une_seule_fois(tmp_path):
    """Deux colonnes qui visent la même colonne actuelle : la première gagne, l'autre est « sans équivalent »."""
    fichier = _base(
        tmp_path / "x.db",
        schema="CREATE TABLE scans (id INTEGER, target TEXT, hostname TEXT, timestamp TEXT, bizarre TEXT)",
    )
    with importer._Source(fichier, _colonnes_actuelles()) as source:
        assert source.rename == {"target": "domain", "timestamp": "scan_timestamp"}
        assert source.unknown == ["hostname", "bizarre"]


def test_fichier_libere_apres_l_import(stockage, tmp_path):
    """Le fichier peut être supprimé tout de suite (Windows refuse de supprimer un fichier resté ouvert)."""
    fichier = _base(
        tmp_path / "x.db",
        [{"id": 1, "domain": unique_domain("libre"), "scan_timestamp": "2025-01-01 00:00:00"}],
    )
    importer.import_scans(fichier)
    fichier.unlink()
    assert not fichier.exists()
    refusee = _base(tmp_path / "y.db", schema="CREATE TABLE autre (x INTEGER)")
    with pytest.raises(importer.ImportSourceError):
        importer.import_scans(refusee)
    refusee.unlink()


def test_fichier_libere_quand_la_lecture_echoue_en_cours_de_route(stockage, tmp_path, monkeypatch):
    fichier = _base(
        tmp_path / "x.db",
        [{"id": 1, "domain": unique_domain("echec"), "scan_timestamp": "2025-01-01 00:00:00"}],
    )

    def casse(row, json_columns):
        raise RuntimeError("boum")

    monkeypatch.setattr(importer, "map_row", casse)
    with pytest.raises(RuntimeError, match="boum"):
        importer.import_scans(fichier)
    fichier.unlink()


def test_texte_qui_n_est_pas_de_l_utf8_ne_fait_pas_echouer_l_import(stockage, tmp_path):
    domaine = unique_domain("latin")
    fichier = _base(tmp_path / "x.db")
    conn = sqlite3.connect(fichier)
    conn.execute(
        "INSERT INTO scans (id, domain, scan_timestamp, notes) VALUES (1, ?, '2025-01-01 00:00:00', CAST(X'636166E9' AS TEXT))",
        (domaine,),
    )
    conn.execute(
        "INSERT INTO scans (id, domain, scan_timestamp, notes) VALUES (2, ?, '2025-01-02 00:00:00', 'propre')",
        (domaine,),
    )
    conn.commit()
    conn.close()
    assert importer.import_scans(fichier).imported == 2
    premier, second = sorted(_scans_de(domaine), key=lambda scan: scan.scan_timestamp)
    assert premier.notes == "caf�" and second.notes == "propre"


def test_json_imbrique_a_l_exces_laisse_vide_sans_faire_echouer_l_import(stockage, tmp_path):
    domaine = unique_domain("profond")
    profond = "[" * 200_000 + "]" * 200_000
    fichier = _base(
        tmp_path / "x.db",
        [
            {"id": 1, "domain": domaine, "scan_timestamp": "2025-01-01 00:00:00", "dns_records": profond},
            {
                "id": 2,
                "domain": domaine,
                "scan_timestamp": "2025-01-02 00:00:00",
                "dns_records": '{"A": ["192.0.2.1"]}',
            },
        ],
    )
    statistiques = importer.import_scans(fichier)
    assert (statistiques.read, statistiques.imported) == (2, 2)
    premier, second = sorted(_scans_de(domaine), key=lambda scan: scan.scan_timestamp)
    assert premier.dns_records is None and second.dns_records == {"A": ["192.0.2.1"]}


def test_statistiques_inchangees(stockage, tmp_path):
    domaine = unique_domain("stats")
    fichier = _base(
        tmp_path / "x.db",
        [
            {"id": 1, "domain": domaine, "scan_timestamp": "2025-01-01 00:00:00"},
            {"id": 2, "domain": domaine, "scan_timestamp": "2025-01-01 00:00:00"},
            {"id": 3, "domain": "", "scan_timestamp": "2025-01-01 00:00:00"},
        ],
    )
    statistiques = importer.import_scans(fichier, dry_run=True)
    assert (statistiques.read, statistiques.imported, statistiques.duplicates, statistiques.ignored) == (
        3,
        1,
        1,
        1,
    )
    assert statistiques.mapped == ["domain", "dns_records", "scan_timestamp", "notes"]
    assert statistiques.unknown == []
    assert _scans_de(domaine) == []  # à sec : rien n'est écrit
