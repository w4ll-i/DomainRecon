# =============================================================================
# DomainRecon - Scanner : exceptions
# =============================================================================
# Exceptions partagées par les modules de collecte et l'orchestrateur. Leur
# message est un texte ou un message traduisible (voir domainrecon.i18n) :
# `.message` le conserve pour l'utilisateur, str(exc) le rend en français
# pour les journaux et les bibliothèques.
# =============================================================================

from typing import TypeVar

from ..i18n import is_msg, render

E = TypeVar("E", bound=BaseException)

# Profondeur maximale de la chaîne __cause__ parcourue par message_of().
_CAUSE_DEPTH = 5


class _MessageMixin:
    """Exception dont le message est un texte ou un message traduisible."""

    def __init__(self, message: object = "") -> None:
        self.message = message
        super().__init__(render(message, "fr") if is_msg(message) else message)

    def __reduce__(self):
        # copy et pickle : reconstruire avec le message d'origine, pas son rendu.
        return (type(self), (self.message,))


class ModuleError(_MessageMixin, Exception):
    """Échec réel d'un module de collecte (réseau, délai…), distinct d'un résultat vide."""


class ModuleSkipped(_MessageMixin, Exception):
    """Le module découvre en s'exécutant qu'il est sans objet pour cette cible (statut skipped).

    Son message dit pourquoi (outil absent, aucune donnée à analyser…) ; le statut
    global du scan n'en est pas dégradé.
    """


class TargetNotAllowedError(_MessageMixin, ValueError):
    """Cible refusée par la politique de cibles (adresse non publique, etc.)."""


class ProxyError(_MessageMixin, ConnectionError):
    """Le proxy sortant est injoignable ou a refusé de joindre l'hôte demandé (voir proxy.open_tunnel)."""


def message_exception(exc_type: type[E], message: dict, **kwargs) -> E:
    """Exception d'un type tiers (httpx, httpcore, OSError…) qui porte aussi un message.

    Son texte est le rendu français (journaux, bibliothèques) ; `.message`
    garde le message, que message_of() retrouve même à travers `raise … from`.
    """
    exc = exc_type(render(message, "fr"), **kwargs)
    exc.message = message
    return exc


def message_of(exc: BaseException | None) -> object | None:
    """Message porté par l'exception ou par l'une de ses causes (`raise … from`), sinon None."""
    depth = 0
    while exc is not None and depth < _CAUSE_DEPTH:
        value = getattr(exc, "message", None)
        if is_msg(value) or (isinstance(value, str) and value):
            return value
        exc = exc.__cause__
        depth += 1
    return None


def exception_text(exc: BaseException) -> object:
    """Message d'une exception pour l'utilisateur : message porté, sinon str(exc)."""
    return message_of(exc) or str(exc)
