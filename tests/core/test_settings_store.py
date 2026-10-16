# =============================================================================
# DomainRecon - Tests des réglages enregistrés : modèle, chiffrement des clés,
# affichage masqué, migration de la table
# =============================================================================

import logging
import sqlite3

import pytest
from sqlalchemy import Text, create_engine, inspect, text
from sqlalchemy.exc import IntegrityError, OperationalError

from domainrecon.core import settings_store
from domainrecon.core.crypto import encrypt, mask_key
from domainrecon.core.database import Base, SessionLocal, engine, sync_schema
from domainrecon.core.models import SECRET_FIELDS, Settings
from domainrecon.core.settings_store import (
    ScanSettings,
    get_settings,
    is_masked_proxy_url,
    is_masked_secret,
    is_valid_proxy_url,
    load_scan_settings,
    load_secrets,
    mask_proxy_url,
    mask_secret,
    prepare_settings,
    read_secret,
    secret_fields,
    settings_view,
    update_settings,
)

CLE_LONGUE = "sk-abcdefghijklmnopqrstuvwxyz1234"


@pytest.fixture(autouse=True)
def reglages_vierges():
    """Table des réglages vide avant et après chaque test (la ligne est recréée par défaut)."""
    Base.metadata.create_all(bind=engine)
    with SessionLocal() as db:
        db.query(Settings).delete()
        db.commit()
    yield
    with SessionLocal() as db:
        db.query(Settings).delete()
        db.commit()


@pytest.fixture
def db():
    with SessionLocal() as session:
        yield session


def _valeur_en_base(champ: str):
    """Valeur brute d'une colonne, lue sans passer par le modèle."""
    with engine.connect() as conn:
        return conn.execute(text(f"SELECT {champ} FROM settings WHERE id = 1")).scalar_one()


# =============================================================================
# Modèle
# =============================================================================


def test_colonnes_du_modele():
    colonnes = Settings.__table__.columns
    assert set(colonnes.keys()) == {
        "id",
        *SECRET_FIELDS,
        "scan_timeout",
        "quick_timeout",
        "screenshot_enabled",
        "proxy_url",
        # Clés déclarées par les modules hors des 14 colonnes (JSON chiffré par valeur).
        "extra_secrets",
    }
    assert Settings.__tablename__ == "settings"
    assert len(SECRET_FIELDS) == 14
    for champ in SECRET_FIELDS:
        assert isinstance(colonnes[champ].type, Text), champ
        assert colonnes[champ].nullable, champ
    assert isinstance(colonnes["proxy_url"].type, Text) and colonnes["proxy_url"].nullable


def test_ligne_unique_creee_avec_les_valeurs_par_defaut(db):
    row = get_settings(db)

    assert row.id == 1
    assert (row.scan_timeout, row.quick_timeout, row.screenshot_enabled) == (60, 30, True)
    assert row.proxy_url is None
    assert all(getattr(row, champ) is None for champ in SECRET_FIELDS)
    # Relue : toujours la même ligne, jamais une seconde.
    assert get_settings(db) is row
    assert db.query(Settings).count() == 1


def test_une_seule_ligne_possible(db):
    get_settings(db)
    db.add(Settings(id=2))
    with pytest.raises(IntegrityError):
        db.commit()
    db.rollback()


def test_creation_concurrente_de_la_ligne(db, monkeypatch):
    """Un autre processus a créé la ligne entre notre lecture et notre insertion : on relit la sienne."""
    with SessionLocal() as autre:
        autre.add(Settings(id=1, scan_timeout=90))
        autre.commit()
    vrai_get = db.get
    appels = []

    def get_une_fois_vide(modele, ident):
        appels.append(ident)
        return None if len(appels) == 1 else vrai_get(modele, ident)

    monkeypatch.setattr(db, "get", get_une_fois_vide)

    assert get_settings(db).scan_timeout == 90
    assert db.query(Settings).count() == 1


def test_repr_sans_cle(db):
    update_settings(db, {"shodan_key": CLE_LONGUE})
    assert CLE_LONGUE not in repr(get_settings(db))


# =============================================================================
# Chiffrement des clés
# =============================================================================


def test_cles_chiffrees_en_base(db):
    update_settings(db, {"shodan_key": CLE_LONGUE, "circl_password": "mot de passe"})

    brut = _valeur_en_base("shodan_key")
    assert brut.startswith("enc:v1:")
    assert CLE_LONGUE not in brut
    assert _valeur_en_base("circl_password").startswith("enc:v1:")
    assert "mot de passe" not in _valeur_en_base("circl_password")
    assert read_secret(get_settings(db), "shodan_key") == CLE_LONGUE
    assert read_secret(get_settings(db), "circl_password") == "mot de passe"
    # Les clés non renseignées restent NULL.
    assert _valeur_en_base("virustotal_key") is None


def test_valeur_vide_supprime_la_cle(db):
    update_settings(db, {"shodan_key": CLE_LONGUE})
    update_settings(db, {"shodan_key": ""})
    assert _valeur_en_base("shodan_key") is None
    # Supprimer une clé absente ne fait rien.
    update_settings(db, {"virustotal_key": ""})
    assert _valeur_en_base("virustotal_key") is None


def test_champ_absent_inchange(db):
    update_settings(db, {"shodan_key": CLE_LONGUE, "scan_timeout": 120})
    update_settings(db, {"virustotal_key": CLE_LONGUE})

    row = get_settings(db)
    assert read_secret(row, "shodan_key") == CLE_LONGUE
    assert row.scan_timeout == 120


def test_reglage_inconnu_refuse(db):
    with pytest.raises(KeyError, match="id"):
        update_settings(db, {"id": 2})
    with pytest.raises(KeyError):
        update_settings(db, {"champ_invente": 1})


def test_ancienne_valeur_en_clair_lue_et_masquee(db):
    """Valeur sans préfixe (base éditée à la main, ancienne version) : lue telle quelle."""
    get_settings(db)
    with engine.begin() as conn:
        conn.execute(text("UPDATE settings SET shodan_key = :v WHERE id = 1"), {"v": CLE_LONGUE})
    db.expire_all()

    assert read_secret(get_settings(db), "shodan_key") == CLE_LONGUE
    assert settings_view(get_settings(db))["shodan_key"] == "sk-…1234"
    # Réécrite, elle est chiffrée.
    update_settings(db, {"shodan_key": CLE_LONGUE})
    assert _valeur_en_base("shodan_key").startswith("enc:v1:")


def test_cle_illisible_traitee_comme_absente(db, caplog):
    """Fichier .secret_key remplacé : la valeur chiffrée par l'ancien secret ne bloque ni l'affichage ni le scan."""
    get_settings(db)
    with engine.begin() as conn:
        conn.execute(text("UPDATE settings SET shodan_key = 'enc:v1:jeton-illisible' WHERE id = 1"))
        conn.execute(text("UPDATE settings SET virustotal_key = :v WHERE id = 1"), {"v": encrypt(CLE_LONGUE)})
    db.expire_all()

    with caplog.at_level(logging.WARNING, logger=settings_store.logger.name):
        assert read_secret(get_settings(db), "shodan_key") == ""
        assert settings_view(get_settings(db))["shodan_key"] == ""
        assert "shodan_key" not in load_secrets(db)
    assert load_secrets(db) == {"virustotal_key": CLE_LONGUE}
    assert any("shodan_key" in r.getMessage() for r in caplog.records)
    assert not any("jeton-illisible" in r.getMessage() for r in caplog.records)


# =============================================================================
# Vue masquée et lecture pour le scan
# =============================================================================


def test_vue_par_defaut(db):
    vue = settings_view(get_settings(db))

    assert vue == {
        **dict.fromkeys(SECRET_FIELDS, ""),
        "api_keys": dict.fromkeys(secret_fields(), ""),
        "scan_timeout": 60,
        "quick_timeout": 30,
        "screenshot_enabled": True,
        "proxy_url": "",
    }


def test_vue_masque_les_cles(db):
    update_settings(
        db,
        {
            "shodan_key": CLE_LONGUE,
            "censys_id": "id-court",
            "circl_user": "utilisateur@exemple.org",
            "circl_password": "un-mot-de-passe-long-1234",
            "scan_timeout": 90,
            "screenshot_enabled": False,
            "proxy_url": "http://alice:mdp@proxy.local:3128",
        },
    )

    vue = settings_view(get_settings(db))

    assert vue["shodan_key"] == "sk-…1234"
    assert vue["censys_id"] == "****"  # trop court pour montrer un fragment
    assert vue["circl_user"] == "uti….org"
    assert vue["circl_password"] == "****"  # un mot de passe n'affiche jamais de fragment
    assert vue["virustotal_key"] == ""
    assert (vue["scan_timeout"], vue["quick_timeout"], vue["screenshot_enabled"]) == (90, 30, False)
    assert vue["proxy_url"] == "http://alice:****@proxy.local:3128"
    texte = str(vue)
    for secret in (CLE_LONGUE, "un-mot-de-passe-long-1234", "mdp"):
        assert secret not in texte


def test_load_secrets_en_clair_et_seulement_les_cles_renseignees(db):
    update_settings(db, {"shodan_key": CLE_LONGUE, "github_token": "ghp_x", "otx_key": ""})

    assert load_secrets(db) == {"shodan_key": CLE_LONGUE, "github_token": "ghp_x"}
    # Sans session : ouverte et fermée par la fonction elle-même (usage du scan).
    assert load_secrets() == {"shodan_key": CLE_LONGUE, "github_token": "ghp_x"}


def test_load_secrets_sur_base_neuve():
    assert load_secrets() == {}


# =============================================================================
# Valeurs masquées : ce que l'interface peut renvoyer telle quelle
# =============================================================================


@pytest.mark.parametrize(
    ("valeur", "masquee"),
    [
        ("****", True),
        ("sk-…1234", True),
        ("abc…defg", True),
        ("uti….org", True),
        ("", False),
        ("…", False),
        ("sk-abcdefghijklmnop1234", False),
        ("sk…1234", False),  # 2 caractères avant
        ("sk-…123", False),  # 3 caractères après
        ("sk-…12345", False),  # 5 caractères après
        ("***", False),
        ("*****", False),
    ],
)
def test_is_masked_secret(valeur, masquee):
    assert is_masked_secret(valeur) is masquee


@pytest.mark.parametrize(
    "valeur", [CLE_LONGUE, "0123456789abcdef", "court", "x", "é" * 20, "ghp_" + "y" * 36]
)
def test_tout_ce_que_l_api_affiche_est_reconnu_comme_masque(valeur):
    """Sinon, une clé renvoyée telle quelle par l'interface serait enregistrée comme nouvelle clé."""
    for champ in ("shodan_key", "circl_password", "circl_user"):
        assert is_masked_secret(mask_secret(champ, valeur)), (champ, valeur)


def test_une_vraie_cle_n_est_pas_prise_pour_un_masque():
    assert not any(is_masked_secret(mask_key(CLE_LONGUE) + suffixe) for suffixe in ("x", "xx"))
    assert not is_masked_secret(CLE_LONGUE)


@pytest.mark.parametrize(
    ("url", "masquee"),
    [
        ("http://alice:****@proxy.local:3128", True),
        ("socks5://:****@proxy.local", True),
        ("http://alice:mdp@proxy.local:3128", False),
        ("http://alice@proxy.local:3128", False),
        ("http://proxy.local:3128", False),
    ],
)
def test_is_masked_proxy_url(url, masquee):
    assert is_masked_proxy_url(url) is masquee


def test_tout_proxy_affiche_est_reconnu_comme_masque():
    for url in ("http://alice:mdp@proxy.local:3128", "socks5h://a:b@[::1]:1080"):
        assert is_masked_proxy_url(mask_proxy_url(url))


# =============================================================================
# Proxy
# =============================================================================


@pytest.mark.parametrize(
    "valeur",
    [
        "http://proxy.local:3128",
        "https://proxy.local",
        "socks5://127.0.0.1:1080",
        "socks5h://alice:mdp@proxy.local:1080",
        "http://[::1]:3128",
        "http://proxy.local:3128/",
    ],
)
def test_proxy_valide(valeur):
    assert is_valid_proxy_url(valeur)


@pytest.mark.parametrize(
    "valeur",
    [
        "",
        "proxy.local:3128",
        "ftp://proxy.local",
        "socks4://proxy.local:1080",
        "http://",
        "http://:3128",
        "http://proxy.local:port",
        "http://proxy.local:99999",
        "http://proxy.local:3128/chemin",
        "http://proxy.local:3128?x=1",
        "http://proxy.local#frag",
        "http://proxy .local",
        "http://proxy.local\n",
        "javascript:alert(1)",
    ],
)
def test_proxy_invalide(valeur):
    assert not is_valid_proxy_url(valeur)


@pytest.mark.parametrize(
    ("url", "attendu"),
    [
        ("http://alice:mdp@proxy.local:3128", "http://alice:****@proxy.local:3128"),
        ("socks5://alice:p%40ss@[::1]:1080", "socks5://alice:****@[::1]:1080"),
        ("http://:mdp@proxy.local", "http://:****@proxy.local"),
        ("http://alice@proxy.local:3128", "http://alice@proxy.local:3128"),  # sans mot de passe
        ("http://proxy.local:3128", "http://proxy.local:3128"),
        ("", ""),
        (None, ""),
    ],
)
def test_mask_proxy_url(url, attendu):
    assert mask_proxy_url(url) == attendu


def test_proxy_vide_supprime_le_proxy(db):
    update_settings(db, {"proxy_url": "http://proxy.local:3128"})
    update_settings(db, {"proxy_url": ""})
    assert get_settings(db).proxy_url is None


# =============================================================================
# Proxy sortant : chiffré au repos comme une clé, masqué à l'affichage
# =============================================================================

PROXY = "http://alice:mdp-secret@proxy.local:3128"


def test_proxy_chiffre_en_base_et_dechiffre_par_read_secret(db):
    update_settings(db, {"proxy_url": PROXY})

    brut = _valeur_en_base("proxy_url")
    assert brut.startswith("enc:v1:")
    assert "mdp-secret" not in brut and "alice" not in brut and "proxy.local" not in brut
    assert read_secret(get_settings(db), "proxy_url") == PROXY


def test_proxy_masque_a_l_affichage_apres_chiffrement(db):
    update_settings(db, {"proxy_url": PROXY})

    vue = settings_view(get_settings(db))

    assert vue["proxy_url"] == "http://alice:****@proxy.local:3128"
    assert "mdp-secret" not in str(vue) and "enc:v1:" not in str(vue)
    # Ce que l'interface renvoie tel quel est reconnu comme masqué (ignoré par l'API au PUT).
    assert is_masked_proxy_url(vue["proxy_url"])


def test_proxy_sans_mot_de_passe_chiffre_lui_aussi(db):
    update_settings(db, {"proxy_url": "socks5://127.0.0.1:9050"})

    assert _valeur_en_base("proxy_url").startswith("enc:v1:")
    assert settings_view(get_settings(db))["proxy_url"] == "socks5://127.0.0.1:9050"


def test_proxy_illisible_compte_comme_absent_a_l_affichage(db, caplog):
    get_settings(db).proxy_url = "enc:v1:pas-un-jeton"
    db.commit()

    with caplog.at_level(logging.WARNING):
        assert settings_view(get_settings(db))["proxy_url"] == ""
    assert any("proxy_url" in r.getMessage() for r in caplog.records)


def test_ancien_proxy_en_clair_reste_lisible(db):
    get_settings(db).proxy_url = PROXY  # enregistré avant le chiffrement du proxy
    db.commit()

    assert read_secret(get_settings(db), "proxy_url") == PROXY
    assert settings_view(get_settings(db))["proxy_url"] == "http://alice:****@proxy.local:3128"


def test_prepare_settings_chiffre_un_ancien_proxy_en_clair(db):
    get_settings(db).proxy_url = PROXY
    db.commit()

    prepare_settings()

    brut = _valeur_en_base("proxy_url")
    assert brut.startswith("enc:v1:") and "mdp-secret" not in brut
    db.expire_all()
    assert read_secret(get_settings(db), "proxy_url") == PROXY
    prepare_settings()  # deuxième démarrage : pas de double chiffrement
    assert _valeur_en_base("proxy_url") == brut


def test_prepare_settings_ne_bloque_pas_le_demarrage_si_le_secret_est_illisible(db, monkeypatch, caplog):
    get_settings(db).proxy_url = PROXY
    db.commit()

    def secret_illisible(texte):
        raise PermissionError("secret illisible")

    monkeypatch.setattr(settings_store, "encrypt", secret_illisible)
    with caplog.at_level(logging.WARNING):
        prepare_settings()

    assert _valeur_en_base("proxy_url") == PROXY  # inchangé, encore utilisable
    assert "mdp-secret" not in caplog.text


# =============================================================================
# load_scan_settings : délais par profil et capture, lus par l'orchestrateur
# =============================================================================


def test_load_scan_settings_sans_ligne_valeurs_par_defaut_sans_ecriture():
    assert load_scan_settings() == ScanSettings(scan_timeout=60, quick_timeout=30, screenshot_enabled=True)
    with SessionLocal() as session:
        assert session.query(Settings).count() == 0  # lecture seule : la ligne n'est pas créée


def test_load_scan_settings_valeurs_enregistrees(db):
    update_settings(db, {"scan_timeout": 120, "quick_timeout": 15, "screenshot_enabled": False})

    assert load_scan_settings() == ScanSettings(scan_timeout=120, quick_timeout=15, screenshot_enabled=False)
    assert load_scan_settings(db) == load_scan_settings()


def test_load_scan_settings_valeur_inexploitable_remplacee_par_le_defaut(db):
    row = get_settings(db)
    row.scan_timeout, row.quick_timeout = 0, -5
    db.commit()

    assert load_scan_settings(db) == ScanSettings(scan_timeout=60, quick_timeout=30, screenshot_enabled=True)


def test_load_scan_settings_base_illisible_valeurs_par_defaut(monkeypatch, caplog):
    class Illisible:
        def get(self, *args, **kwargs):
            raise OperationalError("SELECT 1", {}, Exception("no such table: settings"))

    with caplog.at_level(logging.WARNING):
        assert load_scan_settings(Illisible()) == ScanSettings()
    assert "valeurs par défaut" in caplog.text


# =============================================================================
# Migration au démarrage
# =============================================================================

# Table créée par une version qui ne connaissait que deux colonnes.
ANCIENNE_TABLE = """
CREATE TABLE settings (
    id INTEGER NOT NULL PRIMARY KEY,
    shodan_key TEXT
);
"""


def test_migration_ajoute_les_colonnes_manquantes_avec_leurs_valeurs_par_defaut(tmp_path):
    base = tmp_path / "ancienne.db"
    with sqlite3.connect(base) as conn:
        conn.executescript(ANCIENNE_TABLE)
        conn.execute("INSERT INTO settings (id, shodan_key) VALUES (1, 'enc:v1:conservee')")
    conn.close()
    cible = create_engine(f"sqlite:///{base.as_posix()}")

    ajoutees = sync_schema(Settings, target_engine=cible)

    assert set(ajoutees) == set(Settings.__table__.columns.keys()) - {"id", "shodan_key"}
    assert {c["name"] for c in inspect(cible).get_columns("settings")} == set(
        Settings.__table__.columns.keys()
    )
    with cible.connect() as conn:
        ligne = conn.execute(
            text(
                "SELECT shodan_key, scan_timeout, quick_timeout, screenshot_enabled, proxy_url FROM settings"
            )
        ).one()
    # La ligne existante est conservée ; les nouvelles colonnes ont leur valeur par défaut.
    assert tuple(ligne) == ("enc:v1:conservee", 60, 30, 1, None)
    assert sync_schema(Settings, target_engine=cible) == []
    cible.dispose()


def test_prepare_settings_cree_la_ligne_par_defaut():
    with SessionLocal() as db:
        assert db.query(Settings).count() == 0

    prepare_settings()
    prepare_settings()  # deuxième démarrage : rien de plus

    with SessionLocal() as db:
        assert db.query(Settings).count() == 1
        assert get_settings(db).scan_timeout == 60


def test_prepare_settings_n_empeche_pas_de_demarrer_sur_une_base_en_lecture_seule(monkeypatch, caplog):
    from sqlalchemy.exc import OperationalError

    def base_en_lecture_seule(db):
        raise OperationalError("INSERT INTO settings", {}, Exception("attempt to write a readonly database"))

    monkeypatch.setattr(settings_store, "get_settings", base_en_lecture_seule)

    with caplog.at_level(logging.WARNING, logger=settings_store.logger.name):
        prepare_settings()

    assert any("réglages" in r.getMessage().lower() for r in caplog.records)
