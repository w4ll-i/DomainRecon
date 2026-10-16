# =============================================================================
# DomainRecon - Chiffrement des secrets enregistrés (clés API des Réglages)
# =============================================================================
# Fernet (AES-128-CBC + HMAC-SHA256) de la bibliothèque « cryptography ». La
# clé de chiffrement est le SHA-256 d'un secret de 32 octets aléatoires, rangé
# une fois pour toutes dans <dossier de données>/.secret_key (créé au premier
# usage ; lisible par son seul propriétaire sous Linux et macOS, sous Windows
# par les droits du dossier de l'utilisateur).
#
# Ce que cela protège : une base copiée, sauvegardée ou envoyée sans ce fichier
# ne livre pas les clés. Ce que cela ne protège pas : quelqu'un qui lit tout le
# dossier de données (base ET fichier) les déchiffre. Un fichier perdu rend les
# clés enregistrées illisibles : elles sont à ressaisir (decrypt() lève
# DecryptionError, les Réglages les traitent alors comme absentes).
#
# Valeur enregistrée : « enc:v1:<jeton Fernet> ». Le préfixe porte la version du
# format ; une valeur sans préfixe est un ancien texte en clair, rendu tel quel
# par decrypt().
# =============================================================================

import base64
import functools
import hashlib
import os
import secrets
import time
from pathlib import Path

from cryptography.fernet import Fernet, InvalidToken

from . import paths

# Préfixe (et version du format) des valeurs chiffrées.
PREFIX = "enc:v1:"

SECRET_KEY_FILENAME = ".secret_key"
SECRET_SIZE = 32

# Valeur affichée à la place d'un secret trop court (ou à ne jamais révéler).
MASK = "****"
# Un secret affiché garde ses 3 premiers et ses 4 derniers caractères, s'il en
# compte au moins 16 : aucune clé d'API réelle n'est plus courte.
_REVEAL_PREFIX = 3
_REVEAL_SUFFIX = 4
_MIN_REVEAL_LENGTH = 16

# Attente maximale (secondes) qu'un autre processus finisse d'écrire le fichier
# de secret qu'il vient de créer, avant de le juger vide.
_WRITE_GRACE = 2.0


class DecryptionError(ValueError):
    """Valeur chiffrée illisible : secret .secret_key différent de celui du chiffrement, ou valeur altérée."""


def secret_key_path() -> Path:
    """Fichier du secret : <dossier de données>/.secret_key."""
    return paths.data_dir() / SECRET_KEY_FILENAME


def _read_secret(path: Path) -> bytes:
    """Contenu du fichier ; vide seulement s'il l'est encore après `_WRITE_GRACE` secondes."""
    deadline = time.monotonic() + _WRITE_GRACE
    while True:
        data = path.read_bytes()
        if data or time.monotonic() >= deadline:
            return data
        # Création et écriture ne sont pas atomiques : un autre processus (second
        # worker uvicorn) vient peut-être de créer le fichier et l'écrit encore.
        time.sleep(0.05)


def _create_secret(path: Path) -> bytes | None:
    """Crée le fichier avec un secret neuf ; None s'il existe déjà (créé entre-temps par un autre processus)."""
    secret = secrets.token_bytes(SECRET_SIZE)
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        # O_EXCL : un seul processus crée le fichier, les autres reliront le sien.
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0), 0o600)
    except FileExistsError:
        return None
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(secret)
            handle.flush()
            os.fsync(handle.fileno())
    except BaseException:
        # Jamais de fichier à moitié écrit : le secret serait faux au prochain démarrage.
        path.unlink(missing_ok=True)
        raise
    return secret


def _load_secret(path: Path) -> bytes:
    """Secret du fichier, créé au premier usage."""
    try:
        secret = _read_secret(path)
    except FileNotFoundError:
        secret = _create_secret(path) or _read_secret(path)
    if not secret:
        # Fichier resté vide (écriture interrompue, coupure de courant) : rien n'a
        # jamais pu être chiffré avec lui, on le refait plutôt que de bloquer les Réglages.
        path.unlink(missing_ok=True)
        secret = _create_secret(path) or _read_secret(path)
    if not secret:
        # Jamais le SHA-256 d'un secret vide : une clé de chiffrement connue de tous.
        raise RuntimeError(f"Fichier de secret vide : supprimez {path} (les clés API seront à ressaisir)")
    return secret


@functools.lru_cache(maxsize=4)
def _fernet_for(path: Path) -> Fernet:
    """Chiffreur dérivé du secret de `path`, construit une fois par processus et par fichier."""
    key = base64.urlsafe_b64encode(hashlib.sha256(_load_secret(path)).digest())
    return Fernet(key)


def _fernet() -> Fernet:
    return _fernet_for(secret_key_path())


def is_encrypted(value: object) -> bool:
    """Vrai pour une valeur au format chiffré (préfixe « enc:v1: »)."""
    return isinstance(value, str) and value.startswith(PREFIX)


def encrypt(plaintext: str) -> str:
    """Valeur à enregistrer : « enc:v1: » suivi du jeton Fernet (texte ASCII)."""
    return PREFIX + _fernet().encrypt(plaintext.encode("utf-8")).decode("ascii")


def decrypt(ciphertext: str | None) -> str:
    """Texte en clair d'une valeur enregistrée ; « » pour une valeur absente.

    Une valeur sans préfixe est un ancien texte en clair : rendue telle quelle.
    Lève DecryptionError si une valeur chiffrée est illisible.
    """
    if not ciphertext:
        return ""
    if not ciphertext.startswith(PREFIX):
        return ciphertext
    try:
        return _fernet().decrypt(ciphertext[len(PREFIX) :]).decode("utf-8")
    except (InvalidToken, ValueError) as exc:
        # ValueError : jeton qui n'est pas de l'ASCII, ou texte déchiffré invalide.
        raise DecryptionError("valeur chiffrée illisible (secret différent ou valeur altérée)") from exc


def mask_key(value: str | None, *, reveal: bool = True) -> str:
    """Secret masqué pour l'affichage : « sk-…1234 » (3 premiers et 4 derniers caractères).

    « **** » si la valeur compte moins de 16 caractères, ou si `reveal` est
    faux (mot de passe : jamais de fragment) ; « » si rien n'est renseigné.
    """
    if not value:
        return ""
    if not reveal or len(value) < _MIN_REVEAL_LENGTH:
        return MASK
    return f"{value[:_REVEAL_PREFIX]}…{value[-_REVEAL_SUFFIX:]}"
