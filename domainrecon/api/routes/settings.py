# =============================================================================
# DomainRecon - API : réglages (clés API chiffrées, délais, capture, proxy)
# =============================================================================
# GET /api/settings montre les réglages, clés masquées (« sk-…1234 ») ; PUT les
# modifie (clés chiffrées avant l'écriture) ; POST /api/settings/test/{service}
# essaie la clé d'un service par un appel réel minimal (api/service_checks.py,
# ou le test fourni par le module qui déclare la clé). Les 14 clés historiques
# ont leur champ ; `api_keys` porte TOUTES les clés acceptées, celles que les
# modules déclarent comprises (ModuleSpec.keys).
# Comme toute route /api, elles exigent le jeton d'API s'il est défini.
# =============================================================================

import re
from typing import Annotated

from fastapi import APIRouter, Depends, Request
from fastapi import Path as PathParam
from fastapi.concurrency import run_in_threadpool
from pydantic import BaseModel, ConfigDict, Field, ValidationInfo, field_validator
from sqlalchemy.orm import Session

from ...core.database import get_db
from ...core.models import SECRET_FIELDS
from ...core.settings_store import (
    get_settings,
    is_free_text_field,
    is_hidden_field,
    is_masked_proxy_url,
    is_masked_secret,
    is_valid_proxy_url,
    load_secrets,
    secret_fields,
    settings_view,
    update_settings,
)
from ...i18n import msg, render
from ..errors import ApiError, request_lang
from ..schemas import LangQuery, _has_control_chars, _rule_error
from ..security import require_json_body
from ..service_checks import SERVICES, all_services, run_check

router = APIRouter(prefix="/api", tags=["Réglages"])

# Bornes des délais (secondes) et des valeurs texte.
MIN_TIMEOUT = 5
MAX_TIMEOUT = 600
MAX_SECRET_LENGTH = 512
MAX_PROXY_LENGTH = 2048
# Nombre maximal de clés dans `api_keys` (PUT).
MAX_API_KEYS = 200

# Une clé API est du texte ASCII visible, sans espace : un blanc ou un caractère
# invisible (espace insécable, retour à la ligne) venu d'un copier-coller la
# ferait refuser par le service. L'identifiant et le mot de passe CIRCL sont
# libres, sans caractère de contrôle ; seul le mot de passe peut contenir des
# espaces et n'est jamais « nettoyé ».
_TOKEN_RE = re.compile(r"[\x21-\x7e]+")


def _clean_secret_value(name: str, value: str | None) -> str | None:
    """Valeur d'une clé nettoyée (blancs de bord retirés, sauf secret caché) ; None : inchangée.

    Refusée (erreur de validation traduisible) si elle contient un caractère
    interdit : jeton ASCII visible sans espace, ou texte libre sans caractère de
    contrôle (espaces permis seulement pour un secret caché : mot de passe).
    """
    if value is None:
        return None
    hidden = is_hidden_field(name)
    if not hidden:
        value = value.strip()
    if is_masked_secret(value):
        # Valeur affichée par GET et renvoyée telle quelle : la clé enregistrée ne change pas.
        return None
    if not is_free_text_field(name):
        valid = not value or _TOKEN_RE.fullmatch(value) is not None
    else:
        valid = not _has_control_chars(value) and (hidden or not any(ch.isspace() for ch in value))
    if not valid:
        raise _rule_error(msg("api.settings_secret_forbidden_chars"))
    return value


# =============================================================================
# Schémas
# =============================================================================


class SettingsResponse(BaseModel):
    """Réglages : clés masquées (« » si absente), délais en secondes."""

    shodan_key: str = ""
    virustotal_key: str = ""
    censys_id: str = ""
    censys_secret: str = ""
    abuseipdb_key: str = ""
    urlscan_key: str = ""
    otx_key: str = ""
    safebrowsing_key: str = ""
    securitytrails_key: str = ""
    builtwith_key: str = ""
    circl_user: str = ""
    circl_password: str = ""
    intelx_key: str = ""
    github_token: str = ""
    # Toutes les clés acceptées (historiques et déclarées par les modules), masquées, par nom.
    api_keys: dict[str, str] = Field(default_factory=dict)
    scan_timeout: int
    quick_timeout: int
    screenshot_enabled: bool
    # Mot de passe du proxy masqué ; « » : aucun proxy.
    proxy_url: str = ""


class SettingsUpdate(BaseModel):
    """Modification des réglages : un champ absent ou null reste inchangé, une chaîne vide supprime la valeur."""

    model_config = ConfigDict(extra="forbid")

    shodan_key: str | None = Field(None, max_length=MAX_SECRET_LENGTH)
    virustotal_key: str | None = Field(None, max_length=MAX_SECRET_LENGTH)
    censys_id: str | None = Field(None, max_length=MAX_SECRET_LENGTH)
    censys_secret: str | None = Field(None, max_length=MAX_SECRET_LENGTH)
    abuseipdb_key: str | None = Field(None, max_length=MAX_SECRET_LENGTH)
    urlscan_key: str | None = Field(None, max_length=MAX_SECRET_LENGTH)
    otx_key: str | None = Field(None, max_length=MAX_SECRET_LENGTH)
    safebrowsing_key: str | None = Field(None, max_length=MAX_SECRET_LENGTH)
    securitytrails_key: str | None = Field(None, max_length=MAX_SECRET_LENGTH)
    builtwith_key: str | None = Field(None, max_length=MAX_SECRET_LENGTH)
    circl_user: str | None = Field(None, max_length=MAX_SECRET_LENGTH)
    circl_password: str | None = Field(None, max_length=MAX_SECRET_LENGTH)
    intelx_key: str | None = Field(None, max_length=MAX_SECRET_LENGTH)
    github_token: str | None = Field(None, max_length=MAX_SECRET_LENGTH)
    scan_timeout: int | None = Field(None, ge=MIN_TIMEOUT, le=MAX_TIMEOUT)
    quick_timeout: int | None = Field(None, ge=MIN_TIMEOUT, le=MAX_TIMEOUT)
    screenshot_enabled: bool | None = None
    proxy_url: str | None = Field(None, max_length=MAX_PROXY_LENGTH)
    # Clés par nom (historiques ou déclarées par les modules) : même règle que les champs
    # ci-dessus (null : inchangée, « » : supprimée, valeur masquée : inchangée).
    api_keys: dict[str, str | None] | None = Field(None, max_length=MAX_API_KEYS)

    @field_validator(*SECRET_FIELDS)
    @classmethod
    def _clean_secret(cls, value: str | None, info: ValidationInfo) -> str | None:
        """Valeur nettoyée (blancs de bord retirés, sauf mot de passe) et refusée si elle contient un caractère interdit."""
        return _clean_secret_value(info.field_name, value)

    @field_validator("api_keys")
    @classmethod
    def _check_api_keys(cls, value: dict[str, str | None] | None) -> dict[str, str] | None:
        """Noms connus seulement (clés historiques ou déclarées par un module), valeurs nettoyées."""
        if value is None:
            return None
        known = set(secret_fields())
        cleaned: dict[str, str] = {}
        for name, raw in value.items():
            if name not in known:
                raise _rule_error(msg("api.settings_unknown_key", key=name[:64]))
            if raw is not None and len(raw) > MAX_SECRET_LENGTH:
                raise _rule_error(msg("api.settings_secret_too_long", max=MAX_SECRET_LENGTH))
            secret = _clean_secret_value(name, raw)
            if secret is not None:
                cleaned[name] = secret
        return cleaned

    @field_validator("proxy_url")
    @classmethod
    def _check_proxy(cls, value: str | None) -> str | None:
        if value is None:
            return None
        value = value.strip()
        if is_masked_proxy_url(value):
            # Valeur affichée par GET (mot de passe masqué) et renvoyée telle quelle : inchangée.
            return None
        if value and not is_valid_proxy_url(value):
            raise _rule_error(msg("api.settings_invalid_proxy"))
        return value


class ServiceTestResult(BaseModel):
    """Résultat du test d'une clé : message dans la langue de la requête."""

    service: str
    success: bool
    message: str


ServiceName = Annotated[
    str,
    PathParam(max_length=32, description=f"Service à tester : {', '.join(SERVICES)}"),
]


# =============================================================================
# Routes
# =============================================================================


@router.get("/settings", response_model=SettingsResponse)
def read_settings(lang: LangQuery = None, db: Session = Depends(get_db)):
    """Réglages enregistrés ; les clés API sont masquées (« sk-…1234 »), jamais renvoyées en clair."""
    return settings_view(get_settings(db))


@router.put(
    "/settings",
    response_model=SettingsResponse,
    dependencies=[Depends(require_json_body)],
    responses={415: {"description": "Corps non JSON"}},
)
def put_settings(body: SettingsUpdate, lang: LangQuery = None, db: Session = Depends(get_db)):
    """Modifie les réglages indiqués (clés chiffrées avant l'écriture) et renvoie les réglages à jour.

    Un champ absent ou null reste inchangé ; une chaîne vide supprime une clé
    ou le proxy. Une valeur renvoyée telle que GET l'affiche (masquée : « **** »,
    « sk-…1234 », mot de passe du proxy « **** ») est elle aussi ignorée.
    """
    changes = body.model_dump(exclude_none=True)
    # Clés par nom : mises à plat avec les autres réglages (elles priment sur un champ homonyme).
    changes.update(changes.pop("api_keys", None) or {})
    row = update_settings(db, changes)
    return settings_view(row)


@router.post(
    "/settings/test/{service}",
    response_model=ServiceTestResult,
    dependencies=[Depends(require_json_body)],
    responses={404: {"description": "Service inconnu"}, 415: {"description": "Corps non JSON"}},
)
async def check_service(service: ServiceName, request: Request, lang: LangQuery = None):
    """Teste la clé enregistrée d'un service par un appel réel minimal (corps : {} en JSON).

    Répond toujours 200 quand le service existe : `success` dit si la clé est
    acceptée, `message` pourquoi sinon (clé absente ou refusée, quota, service
    injoignable).
    """
    check = all_services().get(service)
    if check is None:
        raise ApiError(404, msg("api.settings_unknown_service", service=service))
    # Lecture de la base hors de la boucle d'événements.
    secrets = await run_in_threadpool(load_secrets)
    outcome = await run_check(check, secrets)
    return {
        "service": service,
        "success": outcome.success,
        "message": render(outcome.message, request_lang(request)),
    }
