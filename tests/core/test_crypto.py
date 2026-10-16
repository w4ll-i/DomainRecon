# =============================================================================
# DomainRecon - Tests du chiffrement des secrets (core/crypto.py)
# =============================================================================
# Le fichier de secret est créé dans un dossier temporaire : aucun test ne
# touche au .secret_key des données de l'application.
# =============================================================================

import os
import threading

import pytest

from domainrecon.core import crypto, paths
from domainrecon.core.crypto import DecryptionError, decrypt, encrypt, is_encrypted, mask_key


@pytest.fixture
def donnees(tmp_path, monkeypatch):
    """Dossier de données vide (pas encore créé) : le secret naît au premier usage."""
    dossier = tmp_path / "donnees"
    monkeypatch.setattr(paths, "data_dir", lambda: dossier)
    crypto._fernet_for.cache_clear()
    yield dossier
    crypto._fernet_for.cache_clear()


def _nouveau_processus():
    """Simule un redémarrage : le chiffreur est relu depuis le fichier de secret."""
    crypto._fernet_for.cache_clear()


# =============================================================================
# Chiffrement et déchiffrement
# =============================================================================


def test_aller_retour(donnees):
    chiffre = encrypt("sk-clé-secrète-1234")
    assert chiffre.startswith("enc:v1:")
    assert "secrète" not in chiffre and "sk-" not in chiffre
    assert decrypt(chiffre) == "sk-clé-secrète-1234"


@pytest.mark.parametrize("valeur", ["", "a", "é…€😀", "x" * 600, "enc:v1:déjà-un-préfixe", " espaces \n"])
def test_aller_retour_de_toute_valeur(donnees, valeur):
    assert decrypt(encrypt(valeur)) == valeur


def test_deux_chiffrements_de_la_meme_valeur_different(donnees):
    """Vecteur d'initialisation aléatoire : on ne voit pas que deux clés sont identiques."""
    assert encrypt("meme-valeur") != encrypt("meme-valeur")


def test_valeur_en_clair_tolere(donnees):
    """Ancienne valeur sans préfixe : rendue telle quelle (jamais une erreur)."""
    assert decrypt("ancienne-cle-en-clair") == "ancienne-cle-en-clair"
    assert decrypt("gAAAAAB-sans-prefixe") == "gAAAAAB-sans-prefixe"


@pytest.mark.parametrize("absente", [None, ""])
def test_valeur_absente(donnees, absente):
    assert decrypt(absente) == ""


def test_valeur_chiffree_alteree_leve_une_erreur(donnees):
    chiffre = encrypt("cle")
    for abimee in (
        chiffre[:-4] + "AAAA",  # jeton modifié : signature invalide
        "enc:v1:pas-un-jeton",
        "enc:v1:",
        "enc:v1:jeton-é-non-ascii",
    ):
        with pytest.raises(DecryptionError):
            decrypt(abimee)


def test_erreur_sans_la_valeur_dans_le_message(donnees):
    with pytest.raises(DecryptionError) as erreur:
        decrypt("enc:v1:secret-qui-ne-doit-pas-sortir")
    assert "secret-qui-ne-doit-pas-sortir" not in str(erreur.value)


def test_is_encrypted(donnees):
    assert is_encrypted(encrypt("x"))
    assert not is_encrypted("x")
    assert not is_encrypted("")
    assert not is_encrypted(None)


# =============================================================================
# Fichier de secret
# =============================================================================


def test_fichier_absent_cree_avec_le_dossier(donnees):
    fichier = donnees / ".secret_key"
    assert not donnees.exists()

    encrypt("premier usage")

    assert fichier.is_file()
    assert len(fichier.read_bytes()) == crypto.SECRET_SIZE == 32
    assert crypto.secret_key_path() == fichier


def test_secret_cree_une_seule_fois_et_conserve_au_redemarrage(donnees):
    chiffre = encrypt("a conserver")
    secret = (donnees / ".secret_key").read_bytes()

    _nouveau_processus()

    assert decrypt(chiffre) == "a conserver"
    assert (donnees / ".secret_key").read_bytes() == secret


def test_secrets_aleatoires_d_une_installation_a_l_autre(tmp_path, monkeypatch):
    secrets = []
    for nom in ("a", "b"):
        monkeypatch.setattr(paths, "data_dir", lambda nom=nom: tmp_path / nom)
        crypto._fernet_for.cache_clear()
        encrypt("x")
        secrets.append((tmp_path / nom / ".secret_key").read_bytes())
    crypto._fernet_for.cache_clear()
    assert secrets[0] != secrets[1]


def test_secret_perdu_rend_les_cles_illisibles(donnees):
    """Fichier .secret_key supprimé : un nouveau secret est créé, les anciennes valeurs ne se déchiffrent plus."""
    chiffre = encrypt("cle")
    (donnees / ".secret_key").unlink()
    _nouveau_processus()

    with pytest.raises(DecryptionError):
        decrypt(chiffre)
    # Le chiffrement, lui, repart normalement avec le nouveau secret.
    assert decrypt(encrypt("nouvelle cle")) == "nouvelle cle"


def test_fichier_vide_refait(donnees, monkeypatch):
    """Écriture interrompue : un fichier vide n'a jamais chiffré quoi que ce soit, il est refait."""
    monkeypatch.setattr(crypto, "_WRITE_GRACE", 0.0)
    donnees.mkdir()
    (donnees / ".secret_key").write_bytes(b"")

    assert decrypt(encrypt("cle")) == "cle"
    assert len((donnees / ".secret_key").read_bytes()) == 32


def test_le_secret_n_est_pas_le_sha256_d_un_fichier_vide(donnees, monkeypatch):
    """Jamais de clé de chiffrement connue de tous, même si le fichier reste vide."""
    monkeypatch.setattr(crypto, "_WRITE_GRACE", 0.0)

    def creation_perdue(path):
        # Un autre processus a recréé le fichier, qui reste vide.
        path.write_bytes(b"")
        return None

    monkeypatch.setattr(crypto, "_create_secret", creation_perdue)
    donnees.mkdir()
    (donnees / ".secret_key").write_bytes(b"")

    with pytest.raises(RuntimeError, match="vide"):
        encrypt("cle")


def test_creation_sans_ecraser_un_fichier_existant(donnees):
    donnees.mkdir()
    fichier = donnees / ".secret_key"
    fichier.write_bytes(b"secret-d-un-autre-processus")

    assert crypto._create_secret(fichier) is None
    assert fichier.read_bytes() == b"secret-d-un-autre-processus"


def test_demarrages_simultanes_partagent_le_meme_secret(donnees):
    """Deux workers au démarrage : un seul crée le fichier, tous lisent le même secret."""
    fichier = donnees / ".secret_key"
    barriere = threading.Barrier(8)
    obtenus: list[bytes] = []
    erreurs: list[BaseException] = []

    def demarrer():
        try:
            barriere.wait(timeout=10)
            obtenus.append(crypto._load_secret(fichier))
        except BaseException as e:  # noqa: BLE001 - remonté par l'assertion ci-dessous
            erreurs.append(e)

    threads = [threading.Thread(target=demarrer) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=20)

    assert erreurs == []
    assert len(obtenus) == 8
    assert len(set(obtenus)) == 1
    assert obtenus[0] == fichier.read_bytes()


@pytest.mark.skipif(os.name == "nt", reason="droits POSIX : sous Windows, ceux du dossier de l'utilisateur")
def test_fichier_lisible_par_son_proprietaire_seul(donnees):
    encrypt("x")
    assert (donnees / ".secret_key").stat().st_mode & 0o777 == 0o600


def test_aucun_fichier_temporaire_laisse(donnees):
    encrypt("x")
    assert [p.name for p in donnees.iterdir()] == [".secret_key"]


# =============================================================================
# Masquage
# =============================================================================


@pytest.mark.parametrize(
    ("valeur", "attendu"),
    [
        ("sk-abcdefghijklmnop1234", "sk-…1234"),
        ("0123456789abcdef", "012…cdef"),  # 16 caractères : le minimum affiché
        ("0123456789abcde", "****"),  # 15 caractères : trop court
        ("court", "****"),
        ("a", "****"),
        ("", ""),
        (None, ""),
    ],
)
def test_mask_key(valeur, attendu):
    assert mask_key(valeur) == attendu


def test_mask_key_sans_fragment_pour_un_mot_de_passe():
    assert mask_key("un-mot-de-passe-tres-long-1234", reveal=False) == "****"
    assert mask_key("", reveal=False) == ""


def test_mask_key_ne_revele_pas_le_milieu():
    cle = "AAA" + "secretsecretsecret" + "ZZZZ"
    masquee = mask_key(cle)
    assert masquee == "AAA…ZZZZ"
    assert "secret" not in masquee
