# =============================================================================
# DomainRecon - API : schémas Pydantic, dates UTC et bornes des paramètres
# =============================================================================

import unicodedata
from datetime import datetime, timezone
from typing import Annotated, Literal

from fastapi import Path as PathParam
from fastapi import Query
from pydantic import (
    AfterValidator,
    BaseModel,
    BeforeValidator,
    ConfigDict,
    Field,
    PlainSerializer,
    StrictBool,
    WithJsonSchema,
    field_validator,
)
from pydantic_core import PydanticCustomError

from ..i18n import loads_message, msg

# Bornes des identifiants : un entier hors de la plage de la colonne ferait
# échouer le binding SQL (500). 2^31 - 1 convient à SQLite comme à PostgreSQL.
MAX_SCAN_ID = 2**31 - 1

# Tags et notes (PATCH /api/scan/{id}/meta).
MAX_TAGS = 20
MAX_TAG_LENGTH = 50
MAX_NOTES_LENGTH = 10_000

# Profils de scan (ceux de scanner.registry.PROFILES) et bornes de la sélection
# de modules du profil « personnalise » (POST /api/scans).
ScanProfile = Literal["rapide", "complet", "personnalise"]
MAX_SELECTED_MODULES = 100
MAX_MODULE_NAME_LENGTH = 64

# Langue des messages de la réponse (voir i18n.negotiate_lang). Les routes la
# déclarent pour la validation et le schéma OpenAPI ; la langue elle-même est
# lue sur la requête par errors.request_lang.
LangQuery = Annotated[
    str | None,
    Query(max_length=16, description="Langue des messages : fr ou en (défaut : Accept-Language, sinon fr)"),
]

# Filtres de l'historique : grade du score et statut global du scan.
GradeFilter = Literal["A", "B", "C", "D", "F", "N/A"]
StatusFilter = Literal["success", "partial", "error"]


# =============================================================================
# Dates : un seul format, ISO 8601 UTC avec suffixe Z
# =============================================================================


def as_utc(value: datetime) -> datetime:
    """Datetime en UTC. Une valeur naïve (lue en base) est déjà de l'UTC."""
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def iso_utc(value: datetime) -> str:
    """Sérialisation de toutes les dates de l'API : ISO 8601 UTC suffixé de Z.

    Sans marqueur de fuseau, le navigateur interprète la date comme une heure
    locale et l'affiche décalée.
    """
    return as_utc(value).isoformat().replace("+00:00", "Z")


UtcDatetime = Annotated[
    datetime,
    AfterValidator(as_utc),
    PlainSerializer(iso_utc, return_type=str, when_used="json"),
    WithJsonSchema({"type": "string", "format": "date-time", "examples": ["2026-01-01T12:00:00Z"]}),
]


# =============================================================================
# Schémas Pydantic
# =============================================================================


def _dict_or_empty(value):
    return {} if value is None else value


def _list_or_empty(value):
    return [] if value is None else value


def _stored_tags(value) -> list:
    """Tags lus en base : les valeurs non textuelles d'avant la validation sont écartées."""
    if not isinstance(value, list):
        return []
    return [tag for tag in value if isinstance(tag, str)]


def _stored_modules(value) -> dict | None:
    """Résultats génériques lus en base : un dictionnaire, sinon None (valeur inattendue comprise)."""
    return value if isinstance(value, dict) else None


def _stored_modules_launched(value) -> list[str] | None:
    """Noms des modules lancés, lus en base : une liste de textes, sinon None (valeur inattendue comprise)."""
    if not isinstance(value, list):
        return None
    return [name for name in value if isinstance(name, str)]


# Colonnes JSON : NULL en base devient la valeur vide du type attendu.
JsonDict = Annotated[dict, BeforeValidator(_dict_or_empty)]
JsonList = Annotated[list, BeforeValidator(_list_or_empty)]
StoredTags = Annotated[list[str], BeforeValidator(_stored_tags)]
# Colonne `modules` : NULL reste None (scan d'avant la v2), et non « {} » : c'est
# ce qui distingue un ancien scan d'un scan sans résultat générique.
StoredModules = Annotated[dict | None, BeforeValidator(_stored_modules)]
# Colonne `modules_launched` : NULL reste None (scan d'avant la v2 : modules lancés inconnus).
StoredModulesLaunched = Annotated[list[str] | None, BeforeValidator(_stored_modules_launched)]

# error_message est une colonne TEXT : message JSON (nouveaux scans) ou texte
# brut (anciens scans), relu tel quel.
StoredMessage = Annotated[str | dict | None, BeforeValidator(loads_message)]


class ScanRequest(BaseModel):
    domain: str = Field(..., min_length=3, max_length=255)


class ScanJobRequest(ScanRequest):
    """Corps de POST /api/scans : la cible, le profil de scan et, au besoin, les modules choisis."""

    profile: ScanProfile = Field(
        "complet",
        description=(
            "Profil de scan : « rapide » (modules passifs essentiels), « complet » (tous les modules "
            "passifs, et ceux à clé API dont la clé est renseignée) ou « personnalise » (modules de `selected`)."
        ),
    )
    selected: list[Annotated[str, Field(max_length=MAX_MODULE_NAME_LENGTH)]] | None = Field(
        None,
        max_length=MAX_SELECTED_MODULES,
        description=(
            "Noms des modules du profil « personnalise » (leurs dépendances sont ajoutées) ; ignoré avec "
            "les autres profils. Un nom inconnu est ignoré : sans aucun module valide, la requête est refusée."
        ),
    )
    authorized_target: StrictBool = Field(
        False,
        description=(
            "Déclare avoir l'autorisation de tester la cible. Exigé, et vérifié côté serveur, dès qu'un "
            "module actif ou sensible est choisi ; sans elle, la requête est refusée."
        ),
    )


class ScanResponse(BaseModel):
    """Scan complet. Se construit directement depuis un objet Scan."""

    model_config = ConfigDict(from_attributes=True)

    id: int
    domain: str
    ip_address: str | None = None
    dns_records: JsonDict = Field(default_factory=dict)
    subdomains: JsonList = Field(default_factory=list)
    security_headers: JsonDict = Field(default_factory=dict)
    whois_data: JsonDict = Field(default_factory=dict)
    geo_data: JsonDict = Field(default_factory=dict)
    tls_certificate: JsonDict = Field(default_factory=dict)
    open_ports: JsonList = Field(default_factory=list)
    technologies: JsonList = Field(default_factory=list)
    email_security: JsonDict = Field(default_factory=dict)
    waf: JsonDict = Field(default_factory=dict)
    redirect_chain: JsonDict = Field(default_factory=dict)
    web_files: JsonDict = Field(default_factory=dict)
    cookie_security: JsonDict = Field(default_factory=dict)
    cors: JsonDict = Field(default_factory=dict)
    reverse_dns: JsonDict = Field(default_factory=dict)
    subdomain_takeover: JsonList = Field(default_factory=list)
    network_extended: JsonDict = Field(default_factory=dict)
    security_score: JsonDict = Field(default_factory=dict)
    module_status: JsonDict = Field(default_factory=dict)
    modules: StoredModules = Field(
        default=None,
        description=(
            "Résultats des modules du registre, par nom : {status, data, duration, error}. "
            "null pour un scan d'avant la v2 : ses résultats sont dans les champs ci-dessus, "
            "qui restent lus en priorité."
        ),
    )
    profile: str | None = Field(
        default=None,
        description="Profil du scan (rapide, complet ou personnalise) ; null pour un scan d'avant la v2.",
    )
    modules_launched: StoredModulesLaunched = Field(
        default=None,
        description=(
            "Noms des modules lancés, dans l'ordre d'exécution ; null quand la liste est inconnue "
            "(scan d'avant la v2, ou lancé par POST /api/scan)."
        ),
    )
    scan_duration: float | None = None
    screenshot_path: str | None = None
    tags: StoredTags = Field(default_factory=list)
    notes: str | None = None
    scan_timestamp: UtcDatetime
    status: str
    error_message: StoredMessage = None
    # Calculés à la lecture (scanner/families.py, scanner/findings.py), jamais enregistrés.
    families: dict = Field(default_factory=dict)
    findings: list = Field(default_factory=list)


class ScanSummary(BaseModel):
    """Vue allégée pour les listes — évite de transporter tous les blobs JSON."""

    id: int
    domain: str
    ip_address: str | None = None
    # None si le module n'a rien mesuré (échec, délai dépassé, sans objet) :
    # ce n'est pas « 0 trouvé ».
    subdomains_count: int | None = None
    open_ports_count: int | None = None
    security_score: JsonDict = Field(default_factory=dict)
    tags: StoredTags = Field(default_factory=list)
    scan_timestamp: UtcDatetime
    status: str


class HistoryResponse(BaseModel):
    total: int
    scans: list[ScanSummary]


# Caractères de mise en forme bidirectionnelle (inversion du texte affiché) et
# séparateurs de ligne Unicode : refusés comme les caractères de contrôle.
_FORBIDDEN_FORMAT_CHARS = frozenset("\u202a\u202b\u202c\u202d\u202e\u2066\u2067\u2068\u2069\u2028\u2029")


def _rule_error(message: dict) -> PydanticCustomError:
    """Erreur de validation portant un message traduisible.

    Le type de l'erreur est le code du message, son contexte en est les
    paramètres : le gestionnaire 422 (errors.py) la rend dans la langue de la
    requête (detail et errors[].msg).
    """
    return PydanticCustomError(message["$t"], message["$t"], message["p"])


def _has_control_chars(value: str, allowed: str = "") -> bool:
    return any(
        (unicodedata.category(ch) == "Cc" and ch not in allowed) or ch in _FORBIDDEN_FORMAT_CHARS
        for ch in value
    )


class ScanMetaUpdate(BaseModel):
    """Tags et notes d'un scan. Un champ absent ou null n'est pas modifié."""

    model_config = ConfigDict(extra="forbid")

    tags: list[str] | None = None
    notes: str | None = Field(None, max_length=MAX_NOTES_LENGTH)

    @field_validator("tags")
    @classmethod
    def _clean_tags(cls, value: list[str] | None) -> list[str] | None:
        """Tags nettoyés (strip), validés et dédoublonnés sans tenir compte de la casse."""
        if value is None:
            return None
        cleaned: list[str] = []
        seen: set[str] = set()
        for raw in value:
            tag = raw.strip()
            if not 1 <= len(tag) <= MAX_TAG_LENGTH:
                raise _rule_error(msg("api.meta_tag_length", max=MAX_TAG_LENGTH))
            if _has_control_chars(tag):
                raise _rule_error(msg("api.meta_tag_forbidden_chars"))
            key = tag.casefold()
            if key not in seen:
                seen.add(key)
                cleaned.append(tag)
        if len(cleaned) > MAX_TAGS:
            raise _rule_error(msg("api.meta_too_many_tags", max=MAX_TAGS))
        return cleaned

    @field_validator("notes")
    @classmethod
    def _check_notes(cls, value: str | None) -> str | None:
        # Tabulations et sauts de ligne sont permis ; NUL et consorts, non
        # (PostgreSQL refuse d'ailleurs le caractère NUL dans un texte).
        if value is not None and _has_control_chars(value, allowed="\t\n\r"):
            raise _rule_error(msg("api.meta_notes_forbidden_chars"))
        return value


class DnsChange(BaseModel):
    added: list = Field(default_factory=list)
    removed: list = Field(default_factory=list)


class TimelineEntry(BaseModel):
    scan_id: int
    timestamp: UtcDatetime
    status: str
    ip_address: str | None = None
    # None si le module n'a rien mesuré, comme dans ScanSummary.
    subdomains_count: int | None = None
    open_ports_count: int | None = None
    # Non nul exactement quand l'interface montre un score. None quand rien
    # n'a pu être mesuré (couverture nulle, valeur non numérique, ou couverture
    # sous 50 % sans critère compté, ancien scan noté A à F compris) : ce n'est
    # pas un 0/100. Sous 50 % de couverture avec des critères comptés
    # (measured_max > 0) : score indicatif, transmis.
    security_score: int | float | None = None
    grade: str | None = None
    coverage: int | float | None = None
    # Barème des critères comptés (None : scan antérieur à ce champ) ; le
    # frontend en tire la même règle d'affichage que l'Historique.
    measured_max: int | float | None = None
    # Version du barème de score (None : scan antérieur au versionnage).
    score_version: int | None = None
    # Enregistrements DNS apparus ou disparus depuis le relevé DNS précédent,
    # par type ; None si l'un des deux relevés n'a pas pu être fait.
    dns_changes: dict[str, DnsChange] | None = None


class RelatedDomain(BaseModel):
    domain: str
    total_scans: int


class TimelineResponse(BaseModel):
    domain: str
    # Site de la cible (scanner.site_domain) : son domaine enregistrable, ou,
    # sur une plateforme mutualisée, le site de l'utilisateur (alice.github.io
    # et non github.io). Nom de champ historique, conservé.
    apex: str
    total_scans: int
    timeline: list[TimelineEntry]
    # Autres cibles du même site (le site lui-même, ses sous-domaines) : les
    # scans antérieurs au changement de normalisation sont rangés sous l'apex.
    related_domains: list[RelatedDomain] = Field(default_factory=list)


ScanId = Annotated[int, PathParam(ge=1, le=MAX_SCAN_ID, description="Identifiant du scan")]
