# =============================================================================
# DomainRecon - Réglages enregistrés : ligne unique de la table settings
# =============================================================================
# Lecture et écriture des réglages (clés API chiffrées, délais, capture, proxy),
# pour l'API (api/routes/settings.py) comme pour le scan, qui lit les clés par
# load_secrets(), le proxy par scanner.proxy.get_proxy_url() et les délais et la
# capture par load_scan_settings().
#
# Clés API acceptées : les 14 colonnes historiques (SECRET_FIELDS) et toute clé
# déclarée par un module du scanner (ModuleSpec.keys, voir scanner/keys.py),
# rangée chiffrée dans la colonne JSON extra_secrets. Le scanner est lu à la
# demande (import local) : il importe lui-même ce fichier. Les clés et le proxy (qui peut porter des
# identifiants : http://utilisateur:mdp@hôte) sont chiffrés avant l'écriture
# (crypto.py) et ne sortent jamais en clair vers l'interface : settings_view()
# les masque.
# =============================================================================

import logging
import re
from dataclasses import dataclass
from urllib.parse import urlsplit, urlunsplit

from sqlalchemy.exc import IntegrityError, SQLAlchemyError
from sqlalchemy.orm import Session

from .crypto import MASK, DecryptionError, decrypt, encrypt, is_encrypted, mask_key
from .database import SessionLocal, sync_schema
from .models import DEFAULT_QUICK_TIMEOUT, DEFAULT_SCAN_TIMEOUT, SECRET_FIELDS, Settings

logger = logging.getLogger(__name__)

# Identifiant de l'unique ligne de la table.
SETTINGS_ID = 1

# Réglages hors clés API, modifiables par l'API : le proxy est chiffré comme une
# clé (lu par read_secret, affiché par mask_proxy_url) ; les autres sont en clair.
ENCRYPTED_FIELDS = ("proxy_url",)
PLAIN_FIELDS = ("scan_timeout", "quick_timeout", "screenshot_enabled")
EDITABLE_FIELDS = (*SECRET_FIELDS, *ENCRYPTED_FIELDS, *PLAIN_FIELDS)

# Secrets dont aucun fragment n'est jamais affiché (mot de passe), en plus des clés
# déclarées « hidden » par les modules.
HIDDEN_FIELDS = frozenset({"circl_password"})
# Identifiants en texte libre (et non jetons ASCII sans espace), en plus des clés
# déclarées « free_text » par les modules.
FREE_TEXT_FIELDS = frozenset({"circl_user", "circl_password"})

# Schémas d'un proxy sortant : HTTP ou SOCKS (httpx, avec le paquet socksio pour SOCKS).
PROXY_SCHEMES = ("http", "https", "socks5", "socks5h")

# Forme d'une clé affichée par mask_key() : « sk-…1234 ».
_MASKED_KEY_RE = re.compile(r"[^…]{3}…[^…]{4}")


# =============================================================================
# Affichage masqué
# =============================================================================


def declared_keys() -> dict:
    """Clés API déclarées par les modules du scanner, par nom (scanner.keys.ApiKey)."""
    from ..scanner import registry

    return registry.declared_keys()


def secret_fields() -> tuple[str, ...]:
    """Toutes les clés API acceptées : colonnes historiques, puis clés déclarées par les modules (triées)."""
    extra = sorted(set(declared_keys()) - set(SECRET_FIELDS))
    return (*SECRET_FIELDS, *extra)


def is_hidden_field(field: str) -> bool:
    """Clé jamais affichée, même partiellement (mot de passe)."""
    key = declared_keys().get(field)
    return field in HIDDEN_FIELDS or bool(key is not None and key.hidden)


def is_free_text_field(field: str) -> bool:
    """Identifiant en texte libre (espaces permis seulement s'il est caché)."""
    key = declared_keys().get(field)
    return field in FREE_TEXT_FIELDS or bool(key is not None and key.free_text)


def mask_secret(field: str, value: str | None) -> str:
    """Valeur d'une clé API telle qu'affichée : « sk-…1234 », « **** » ou « » (absente)."""
    return mask_key(value, reveal=not is_hidden_field(field))


def mask_proxy_url(url: str | None) -> str:
    """URL de proxy sans son mot de passe (« http://utilisateur:****@hôte:3128 »)."""
    if not url:
        return ""
    try:
        parts = urlsplit(url)
        if parts.password is None:
            return url
        host = parts.netloc.rpartition("@")[2]
        return urlunsplit(parts._replace(netloc=f"{parts.username or ''}:{MASK}@{host}"))
    except ValueError:
        return MASK


def is_masked_secret(value: str) -> bool:
    """Vrai pour une clé telle que l'API l'affiche (« **** » ou « sk-…1234 »).

    L'interface peut renvoyer ce qu'elle a reçu : une telle valeur n'est jamais
    une clé, elle veut dire « inchangée ».
    """
    return value == MASK or _MASKED_KEY_RE.fullmatch(value) is not None


def is_masked_proxy_url(value: str) -> bool:
    """Vrai pour une URL de proxy telle que l'API l'affiche (mot de passe « **** »)."""
    return f":{MASK}@" in value


def is_valid_proxy_url(value: str) -> bool:
    """Vrai pour « schéma://[utilisateur:mot de passe@]hôte[:port] » (schémas de PROXY_SCHEMES)."""
    if not value or any(ch.isspace() or ord(ch) < 32 or ord(ch) == 127 for ch in value):
        return False
    try:
        parts = urlsplit(value)
        _ = parts.port  # lève ValueError si le port est invalide ou hors plage
    except ValueError:
        return False
    return (
        parts.scheme in PROXY_SCHEMES
        and bool(parts.hostname)
        and parts.path in ("", "/")
        and not parts.query
        and not parts.fragment
    )


# =============================================================================
# Lecture
# =============================================================================


def get_settings(db: Session) -> Settings:
    """Ligne unique des réglages, créée avec ses valeurs par défaut si elle manque."""
    row = db.get(Settings, SETTINGS_ID)
    if row is None:
        db.add(Settings(id=SETTINGS_ID))
        try:
            db.commit()
        except IntegrityError:
            # Créée entre-temps par un autre processus (second worker).
            db.rollback()
        row = db.get(Settings, SETTINGS_ID)
    return row


def _extra_secrets(row: Settings) -> dict:
    """Clés des modules enregistrées (chiffrées), par nom ; {} si la colonne est vide ou inattendue."""
    stored = getattr(row, "extra_secrets", None)
    return dict(stored) if isinstance(stored, dict) else {}


def read_secret(row: Settings, field: str) -> str:
    """Clé API en clair (« » si absente) ; une valeur illisible compte comme absente."""
    if field in SECRET_FIELDS or field in ENCRYPTED_FIELDS:
        stored = getattr(row, field)
    else:
        stored = _extra_secrets(row).get(field)
        stored = stored if isinstance(stored, str) else None
    try:
        return decrypt(stored)
    except DecryptionError:
        logger.warning("Réglage %s illisible (fichier .secret_key différent ?) : traité comme absent", field)
        return ""


def load_secrets(db: Session | None = None) -> dict[str, str]:
    """Clés API renseignées, en clair, par nom (colonnes historiques et clés des modules)."""
    if db is None:
        with SessionLocal() as session:
            return load_secrets(session)
    row = get_settings(db)
    fields = (*SECRET_FIELDS, *(name for name in _extra_secrets(row) if name not in SECRET_FIELDS))
    return {field: value for field in fields if (value := read_secret(row, field))}


def settings_view(row: Settings) -> dict:
    """Réglages tels que l'API les montre : clés et mot de passe du proxy masqués, « » pour une valeur absente.

    `api_keys` : toutes les clés acceptées (historiques et déclarées par les
    modules), masquées, par nom.
    """
    view = {field: mask_secret(field, read_secret(row, field)) for field in SECRET_FIELDS}
    view["api_keys"] = {field: mask_secret(field, read_secret(row, field)) for field in secret_fields()}
    view.update(
        scan_timeout=row.scan_timeout,
        quick_timeout=row.quick_timeout,
        screenshot_enabled=row.screenshot_enabled,
        # Déchiffré pour être masqué : l'interface ne voit jamais le jeton ni le mot de passe.
        proxy_url=mask_proxy_url(read_secret(row, "proxy_url")),
    )
    return view


@dataclass(frozen=True)
class ScanSettings:
    """Réglages qui pilotent un scan : délais par profil (secondes) et capture d'écran."""

    scan_timeout: int = DEFAULT_SCAN_TIMEOUT
    quick_timeout: int = DEFAULT_QUICK_TIMEOUT
    screenshot_enabled: bool = True


def load_scan_settings(db: Session | None = None) -> ScanSettings:
    """Délais et capture d'écran enregistrés, pour l'orchestrateur ; lecture synchrone, sans rien écrire.

    Depuis une coroutine : `asyncio.to_thread(load_scan_settings)`. Sans ligne de
    réglages, ou si la base est illisible, ce sont les valeurs par défaut : un
    scan ne dépend jamais de la disponibilité de ses Réglages. Une valeur
    inexploitable (délai nul ou négatif) est remplacée par celle par défaut.
    """
    if db is None:
        with SessionLocal() as session:
            return load_scan_settings(session)
    try:
        row = db.get(Settings, SETTINGS_ID)
    except SQLAlchemyError as e:
        logger.warning("Réglages du scan illisibles (%s) : valeurs par défaut", type(e).__name__)
        return ScanSettings()
    if row is None:
        return ScanSettings()

    def seconds(value: object, default: int) -> int:
        return value if isinstance(value, int) and not isinstance(value, bool) and value > 0 else default

    return ScanSettings(
        scan_timeout=seconds(row.scan_timeout, DEFAULT_SCAN_TIMEOUT),
        quick_timeout=seconds(row.quick_timeout, DEFAULT_QUICK_TIMEOUT),
        # Seul un « faux » enregistré désactive la capture.
        screenshot_enabled=row.screenshot_enabled is not False,
    )


# =============================================================================
# Écriture
# =============================================================================


def update_settings(db: Session, changes: dict[str, object]) -> Settings:
    """Applique des modifications partielles et les enregistre.

    Seuls les champs présents sont touchés. Une chaîne vide supprime une clé API
    ou le proxy ; une clé et le proxy sont chiffrés avant l'écriture. Valeurs
    invalides et valeurs « masquées » renvoyées par l'interface sont écartées
    avant, par les schémas de l'API (is_masked_secret, is_masked_proxy_url,
    is_valid_proxy_url) : ici, ce qui est donné est écrit.
    """
    accepted = {*EDITABLE_FIELDS, *secret_fields()}
    unknown = sorted(set(changes) - accepted)
    if unknown:
        raise KeyError(f"Réglage inconnu : {', '.join(unknown)}")
    row = get_settings(db)
    extra = _extra_secrets(row)
    extra_changed = False
    for field, value in changes.items():
        if field in SECRET_FIELDS or field in ENCRYPTED_FIELDS:
            setattr(row, field, encrypt(value) if value else None)
        elif field in PLAIN_FIELDS:
            setattr(row, field, value)
        else:
            # Clé déclarée par un module : colonne JSON (nouveau dict : SQLAlchemy voit le changement).
            if value:
                extra[field] = encrypt(value)
            else:
                extra.pop(field, None)
            extra_changed = True
    if extra_changed:
        row.extra_secrets = extra or None
    db.commit()
    return row


# =============================================================================
# Démarrage
# =============================================================================


def prepare_settings() -> None:
    """Au démarrage : colonnes manquantes ajoutées à une table plus ancienne, ligne unique créée.

    La table elle-même est créée avec les autres (Base.metadata.create_all). Une
    base en lecture seule n'empêche pas de démarrer : get_settings() recrée la
    ligne au premier besoin.
    """
    added = sync_schema(Settings)
    if added:
        logger.info("Colonnes ajoutées à la table des réglages : %s", ", ".join(added))
    try:
        with SessionLocal() as db:
            _encrypt_legacy_proxy(get_settings(db), db)
    except SQLAlchemyError as e:
        logger.warning("Ligne des réglages non créée au démarrage : %s", e)


def _encrypt_legacy_proxy(row: Settings, db: Session) -> None:
    """Chiffre un proxy enregistré en clair (avant que proxy_url ne soit chiffré) : il peut porter des identifiants."""
    stored = row.proxy_url
    if not stored or is_encrypted(stored):
        return
    try:
        row.proxy_url = encrypt(stored)
    except (OSError, RuntimeError) as e:
        # Fichier .secret_key illisible : le proxy reste lisible tel quel, le démarrage n'en dépend pas.
        logger.warning("Proxy sortant des réglages non chiffré (%s)", type(e).__name__)
        return
    db.commit()
    logger.info("Proxy sortant des réglages chiffré")
