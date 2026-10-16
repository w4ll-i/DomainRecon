# =============================================================================
# DomainRecon - Scanner : règles déclarées par les modules (constats et score)
# =============================================================================
# Un module déclare dans son ModuleSpec (registry.py) :
#   - ses règles de constats (`findings`) : FindingRule, une par code de
#     message « À corriger » ; scanner/findings.py les applique à la lecture ;
#   - ses règles de score (`score_rules`) : ScoreRule (un critère du barème)
#     ou PenaltyRule (pénalité hors barème) ; scanner/score.py les applique en
#     fin de scan.
# Ce fichier ne dépend d'aucun autre du scanner : modules, constats et score
# l'importent sans risque de cycle.
# =============================================================================

import re
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from typing import NamedTuple

SEVERITIES = ("critical", "high", "medium", "low")

# Code de message du catalogue i18n (« finding.dmarc_missing », « hibp.breach »…).
_CODE_RE = re.compile(r"[a-z][a-z0-9_]*(\.[a-z0-9_]+)+")
# Clé d'un critère du barème (clé de security_score.breakdown).
_CRITERION_RE = re.compile(r"[a-z][a-z0-9_]*")


def is_message_code(value: object) -> bool:
    """Vrai pour un code de message bien formé (« famille.nom », minuscules)."""
    return isinstance(value, str) and _CODE_RE.fullmatch(value) is not None


# =============================================================================
# Constats
# =============================================================================


class FindingInput:
    """Ce qu'une règle de constat lit : le scan enregistré, vu depuis un module.

    - data : résultat enregistré du module (dict, liste…) ; None s'il manque ;
    - scan : le scan complet (dict, tel que relu en base) ;
    - measured(nom) : le module `nom` (par défaut, celui de la règle) a-t-il
      été mesuré (statut « ok ») ? Même règle que les familles ;
    - data_of(nom) : résultat enregistré d'un autre module.
    Toute donnée lue doit l'être défensivement (as_dict, as_list de score.py) :
    un ancien scan ou une donnée inattendue ne lève jamais d'erreur.
    """

    __slots__ = ("_data_of", "_measured", "module", "scan")

    def __init__(
        self,
        scan: dict,
        module: str,
        data_of: Callable[[dict, str], object],
        measured: Callable[[dict, str], bool],
    ) -> None:
        self.scan = scan
        self.module = module
        self._data_of = data_of
        self._measured = measured

    @property
    def data(self) -> object:
        return self._data_of(self.scan, self.module)

    def data_of(self, module: str) -> object:
        return self._data_of(self.scan, module)

    def measured(self, module: str | None = None) -> bool:
        return self._measured(self.scan, module or self.module)


@dataclass(frozen=True)
class Hit:
    """Un constat rendu par une règle : paramètres du message, et au besoin une
    gravité ou un module (de la même famille ou non) autres que ceux de la règle."""

    params: Mapping[str, object] = field(default_factory=dict)
    severity: str | None = None
    module: str | None = None


def hit(*, severity: str | None = None, module: str | None = None, **params) -> Hit:
    """Raccourci : hit(days=5, severity="high") = Hit({"days": 5}, "high")."""
    return Hit(params, severity, module)


# Ce que rend FindingRule.check : None, bool, dict de paramètres, Hit, ou liste de dict / Hit.
CheckResult = object


@dataclass(frozen=True, kw_only=True)
class FindingRule:
    """Règle de constat d'un module.

    - code : code du message (catalogue i18n, FR et EN), par exemple
      « finding.dmarc_missing » ou « hibp.breach_found » ;
    - severity : gravité par défaut (critical, high, medium, low) ;
    - check(entrée) : FindingInput -> rien (None, False, liste vide), un
      constat (True : message sans paramètre ; dict : ses paramètres ; Hit),
      ou plusieurs (liste de dict ou de Hit) ;
    - requires_measured : la règle n'est évaluée que si le module est mesuré
      (par défaut). False pour une règle qui recoupe plusieurs modules et fait
      ses propres contrôles (entrée.measured(...)).
    """

    code: str
    severity: str
    check: Callable[[FindingInput], CheckResult]
    requires_measured: bool = True

    def __post_init__(self) -> None:
        if not is_message_code(self.code):
            raise ValueError(f"Règle de constat : code de message invalide {self.code!r}")
        if self.severity not in SEVERITIES:
            raise ValueError(
                f"Règle {self.code} : gravité inconnue {self.severity!r} ({', '.join(SEVERITIES)})"
            )
        if not callable(self.check):
            raise ValueError(f"Règle {self.code} : check doit être appelable")


# =============================================================================
# Score
# =============================================================================


class Outcome(NamedTuple):
    """Évaluation d'un critère du barème.

    - points : points obtenus (bornés à 0..poids du critère) ;
    - detail : message traduisible (ou texte technique : « TLSv1.3 ») ;
    - measured : le critère a pu être évalué ; False : il sort du calcul ;
    - counted : le critère entre-t-il dans le dénominateur (False : bonus non obtenu) ;
    - cap_reason : message qui plafonne la note globale au grade D (vulnérabilité critique) ;
    - applicable : False : critère sans objet pour cette cible (hors couverture).
    """

    points: int
    detail: object
    measured: bool
    counted: bool = True
    cap_reason: object | None = None
    applicable: bool = True


@dataclass(frozen=True, kw_only=True)
class ScoreRule:
    """Critère du barème apporté par un module.

    - criterion : clé du critère (unique dans tout le registre) ;
    - weight : points du critère. Le score est normalisé sur les critères
      mesurés : ajouter un critère ne retire rien aux autres scans. Repères :
      contrôle de sécurité majeur 15 à 25, important 10, secondaire 5,
      réputation ou fuite 3 à 5 ;
    - evaluate(données) -> Outcome : `données` contient le résultat de chaque
      module lancé, par nom (données[« mon_module »]), et les entrées communes
      (is_ip_target, module_status, modules_launched). Elle n'est appelée que
      si le module a été lancé et mesuré ;
    - not_applicable_for_ip : critère sans objet pour une cible IP littérale ;
    - grade_by_points : note de la famille selon les points obtenus quand ce
      critère est le seul de sa famille (e-mail : 15 -> A, 12 -> B…) ;
    - rank : ordre d'affichage du critère dans le détail du score.
    """

    criterion: str
    weight: int
    evaluate: Callable[[dict], Outcome]
    not_applicable_for_ip: bool = False
    grade_by_points: Mapping[int, str] | None = field(default=None, hash=False, compare=False)
    rank: int = 100

    def __post_init__(self) -> None:
        if not isinstance(self.criterion, str) or not _CRITERION_RE.fullmatch(self.criterion):
            raise ValueError(f"Critère de score invalide : {self.criterion!r}")
        if isinstance(self.weight, bool) or not isinstance(self.weight, int) or not 0 < self.weight <= 100:
            raise ValueError(f"Critère {self.criterion} : poids invalide {self.weight!r} (entier de 1 à 100)")
        if not callable(self.evaluate):
            raise ValueError(f"Critère {self.criterion} : evaluate doit être appelable")


@dataclass(frozen=True, kw_only=True)
class PenaltyRule:
    """Pénalités hors barème apportées par un module (ports sensibles exposés…).

    evaluate(données) -> liste de dict {key, label, points, severity} ; appelée
    seulement si le module a été lancé et mesuré.
    """

    evaluate: Callable[[dict], list[dict]]

    def __post_init__(self) -> None:
        if not callable(self.evaluate):
            raise ValueError("Règle de pénalité : evaluate doit être appelable")
