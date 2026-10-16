# =============================================================================
# DomainRecon - Scanner : clés API déclarées par les modules et leur test
# =============================================================================
# Un module à clé déclare ses identifiants (ApiKey) dans son ModuleSpec : les
# Réglages acceptent alors de les enregistrer (chiffrés), l'orchestrateur les
# lui transmet (ScanContext.secrets) et l'interface sait les demander. Un
# service peut avoir plusieurs identifiants (Censys : identifiant et secret ;
# CIRCL : utilisateur et mot de passe) et une clé peut être facultative (le
# module tourne sans, en mode dégradé).
#
# Test d'une clé (POST /api/settings/test/{service}) : KeyTest, déclaré par le
# module (ModuleSpec.key_test). Le plus simple est une liste de requêtes GET
# minimales (Probe) ; un test sur mesure (`run`) reçoit les clés et le client
# HTTP des API tierces (TLS vérifié, sans redirection, politique de cibles).
# Ce fichier ne dépend d'aucun autre du scanner.
# =============================================================================

import re
from collections.abc import Awaitable, Callable, Mapping, Sequence
from dataclasses import dataclass

import httpx

# Nom de stockage d'une clé (colonne ou entrée des Réglages) : « hibp_key ».
KEY_NAME_RE = re.compile(r"[a-z][a-z0-9_]{1,63}")
# Identifiant d'un service testable (URL de POST /api/settings/test/{service}).
SERVICE_RE = re.compile(r"[a-z][a-z0-9_]{0,31}")

# Verdicts d'un service qui signale une erreur dans le corps d'une réponse 2xx.
REJECTED = "rejected"
QUOTA = "quota"
ERROR = "error"


@dataclass(frozen=True, kw_only=True)
class ApiKey:
    """Identifiant d'un service tiers, déclaré par un module.

    - name : nom de stockage (« hibp_key »), le même pour tous les modules qui
      l'emploient ; les 14 noms historiques (core/models.SECRET_FIELDS :
      shodan_key, virustotal_key…) gardent leur colonne ;
    - service : identifiant du service (« hibp ») ; label : son nom affiché
      (« Have I Been Pwned », nom propre, non traduit) ;
    - required : sans elle le module n'est pas lancé (True) ; False : clé
      facultative, le module tourne sans et la lit dans ScanContext.secrets ;
    - free_text : texte libre (identifiant, nom d'utilisateur) au lieu d'un
      jeton ASCII sans espace ;
    - hidden : jamais affiché, même partiellement (mot de passe) ; un champ
      caché accepte les espaces.
    """

    name: str
    service: str
    label: str
    required: bool = True
    free_text: bool = False
    hidden: bool = False

    def __post_init__(self) -> None:
        if not isinstance(self.name, str) or not KEY_NAME_RE.fullmatch(self.name):
            raise ValueError(f"Nom de clé API invalide : {self.name!r} (minuscules, chiffres et « _ »)")
        if not isinstance(self.service, str) or not SERVICE_RE.fullmatch(self.service):
            raise ValueError(f"Clé {self.name} : identifiant de service invalide {self.service!r}")
        if not isinstance(self.label, str) or not self.label.strip():
            raise ValueError(f"Clé {self.name} : nom de service affiché manquant")

    def same_definition(self, other: "ApiKey") -> bool:
        """Deux déclarations d'une même clé doivent concorder (hors caractère facultatif, propre au module)."""
        return (self.name, self.service, self.label, self.free_text, self.hidden) == (
            other.name,
            other.service,
            other.label,
            other.free_text,
            other.hidden,
        )


@dataclass(frozen=True)
class Probe:
    """Requête minimale (GET) d'un test de clé, à URL fixe en https."""

    url: str
    params: Mapping[str, str] | None = None
    headers: Mapping[str, str] | None = None
    # Identifiants HTTP Basic (identifiant, mot de passe).
    auth: tuple[str, str] | None = None
    # Codes HTTP, hors 2xx, qui prouvent que les identifiants sont reconnus (requête authentifiée, sans résultat).
    accepted: frozenset[int] = frozenset()
    # Codes HTTP qui signifient « clé refusée » ; tout autre code hors 2xx et 429 est une erreur du service.
    rejected: frozenset[int] = frozenset({401, 403})
    # Pour un service qui répond 2xx même en cas d'erreur : lit le corps JSON (None s'il n'en est pas un)
    # et rend un verdict (REJECTED, QUOTA, ERROR), ou None si la réponse est bonne.
    body_error: Callable[[object], str | None] | None = None


@dataclass(frozen=True)
class CheckOutcome:
    """Résultat d'un test : succès et message traduisible."""

    success: bool
    message: dict


@dataclass(frozen=True)
class KeyTest:
    """Service testable : nom affiché, clés requises et requêtes à essayer dans l'ordre.

    - label : nom du service affiché ;
    - fields : noms des clés requises par le test (toutes renseignées, sinon
      « clé absente » sans requête) ;
    - probes(clés) -> requêtes GET à essayer dans l'ordre : la première
      réussie l'emporte ;
    - run(clés, client) -> CheckOutcome : test sur mesure, à la place des
      requêtes (POST, réponse à interpréter…). Ne jamais mettre une clé dans
      le message rendu.
    """

    label: str
    fields: tuple[str, ...]
    probes: Callable[[Mapping[str, str]], Sequence[Probe]] | None = None
    run: Callable[[Mapping[str, str], httpx.AsyncClient], Awaitable[CheckOutcome]] | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.label, str) or not self.label.strip():
            raise ValueError("Test de clé : nom de service affiché manquant")
        if isinstance(self.fields, str) or not self.fields:
            raise ValueError(f"Test de clé {self.label} : fields est un tuple de noms de clés")
        object.__setattr__(self, "fields", tuple(self.fields))
        if (self.probes is None) == (self.run is None):
            raise ValueError(f"Test de clé {self.label} : donner probes ou run (un seul des deux)")
