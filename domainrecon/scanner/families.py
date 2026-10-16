# =============================================================================
# DomainRecon - Scanner : familles de modules
# =============================================================================
# Huit familles regroupent les modules pour l'écran « Résultat » : Web, TLS,
# E-mail, DNS & sous-domaines, Réseau, Identité, Réputation et Fuites de données.
# Pour chacune, calculés à la lecture d'un scan (jamais enregistrés : les
# anciens scans en bénéficient aussi) : état, note (critères du barème de la
# famille, tels qu'enregistrés avec le scan : un scan noté en v3 garde son
# barème) et résumé traduisible.
#
# Tout vient des déclarations des modules (ModuleSpec du registre) : leur
# famille (FAMILY_MODULES, MODULE_FAMILY), leurs critères de score
# (FAMILY_CRITERIA) et leur poids dans le verdict (ModuleSpec.verdict :
# FAMILY_VERDICT_MODULES). Ces quatre noms sont calculés à chaque lecture.
#
# Un module peut n'avoir pas été lancé (profil rapide ou personnalisé) : son
# statut est « not_launched », jamais « ok ». Une famille dont aucun module n'a
# été lancé, ou qui n'en a aucun, est « non mesurée » ; un module non lancé est
# signalé dans le résumé de sa famille.
# =============================================================================

import math
from fractions import Fraction

from ..i18n import msg
from .score import as_dict, grade_for_score, launched_modules

FAMILY_KEYS = ("web", "tls", "email", "dns", "network", "identity", "reputation", "leaks")

# Familles descriptives : état « info » dès qu'un module a mesuré, jamais de verdict.
INFO_FAMILIES = frozenset({"identity"})

# Statut d'un module qui n'a pas été lancé (hors profil) : ni mesuré, ni en échec.
NOT_LAUNCHED = "not_launched"

_MODULE_STATUSES = ("ok", "failed", "timeout", "skipped", NOT_LAUNCHED)
_FAILURE_STATUSES = frozenset({"failed", "timeout"})
# Modules sans résultat exploitable pour fonder un verdict : en échec, ou non lancés.
_UNAVAILABLE_STATUSES = _FAILURE_STATUSES | {NOT_LAUNCHED}
_STATE_RANK = {"ok": 0, "warning": 1, "critical": 2}
_FINDING_STATE = {"critical": "critical", "high": "warning", "medium": "warning", "low": "ok"}
_GRADE_STATE = {"A": "ok", "B": "ok", "C": "warning", "D": "warning", "F": "critical"}


# =============================================================================
# Ce que les modules déclarent
# =============================================================================


def _modules() -> dict:
    """Modules du registre (import local : le registre importe les modules, qui importent ce fichier)."""
    from . import registry

    return registry.MODULES


def _spec(module: str):
    """ModuleSpec d'un module : du registre, sinon des modules à colonne historique."""
    from . import registry

    return registry.MODULES.get(module) or registry.COLUMN_MODULES.get(module)


def family_modules() -> dict[str, tuple[str, ...]]:
    """Modules de chaque famille, dans l'ordre du registre (famille sans module : tuple vide)."""
    families: dict[str, list[str]] = {family: [] for family in FAMILY_KEYS}
    for spec in _modules().values():
        families.setdefault(spec.family, []).append(spec.name)
    return {family: tuple(names) for family, names in families.items()}


def module_family() -> dict[str, str]:
    """Famille de chaque module (clé de module_status)."""
    return {spec.name: spec.family for spec in _modules().values()}


def family_criteria() -> dict[str, tuple[str, ...]]:
    """Critères du barème (clés de security_score.breakdown) apportés par les modules de chaque famille."""
    from .score import score_criteria

    families: dict[str, list[str]] = {family: [] for family in FAMILY_KEYS}
    modules = _modules()
    for module, rule in score_criteria():
        families.setdefault(modules[module].family, []).append(rule.criterion)
    return {family: tuple(criteria) for family, criteria in families.items()}


def family_verdict_modules() -> dict[str, tuple[str, ...]]:
    """Modules qui fondent le verdict de chaque famille (ModuleSpec.verdict).

    Leur échec ou leur absence (non lancés), faute de note ni de constat par
    ailleurs, rend la famille « non mesurée ». Les autres modules sont
    descriptifs : leur échec reste signalé dans le résumé sans retirer son
    verdict à la famille.
    """
    families: dict[str, list[str]] = {family: [] for family in FAMILY_KEYS}
    for spec in _modules().values():
        if spec.verdict:
            families.setdefault(spec.family, []).append(spec.name)
    return {family: tuple(names) for family, names in families.items()}


def __getattr__(name: str):
    # Noms historiques, calculés à chaque lecture à partir du registre.
    if name == "FAMILY_MODULES":
        return family_modules()
    if name == "MODULE_FAMILY":
        return module_family()
    if name == "FAMILY_CRITERIA":
        return family_criteria()
    if name == "FAMILY_VERDICT_MODULES":
        return family_verdict_modules()
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


def module_value(scan: dict, module: str) -> object:
    """Résultat enregistré d'un module : sa colonne historique, sinon `modules[nom].data`."""
    spec = _spec(module)
    if spec is not None and spec.column is not None:
        return scan.get(spec.column)
    return as_dict(as_dict(scan.get("modules")).get(module)).get("data")


def _number(value) -> int | float | None:
    """Nombre fini (ni booléen, ni NaN, ni infini : Fraction les refuse), sinon None."""
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    if isinstance(value, float) and not math.isfinite(value):
        return None
    return value


def _takeover_never_checked(scan: dict) -> bool:
    """Scan antérieur : takeover jamais vérifié selon le barème (critère absent ou non mesuré).

    La colonne des takeovers est ajoutée à NULL aux anciens scans et relue en
    liste vide, indiscernable d'un « rien trouvé » : seul le score, calculé sur
    les données d'origine, le dit (même règle que l'interface, takeoverNeverChecked).
    """
    criterion = as_dict(as_dict(scan.get("security_score")).get("breakdown")).get("takeover")
    return not isinstance(criterion, dict) or criterion.get("measured") is False


def takeover_never_checked(scan: dict) -> bool:
    """Scan antérieur : takeover jamais vérifié selon le barème (critère absent ou non mesuré).

    La colonne des takeovers est ajoutée à NULL aux anciens scans et relue en
    liste vide, indiscernable d'un « rien trouvé » : seul le score, calculé sur
    les données d'origine, le dit (même règle que l'interface, takeoverNeverChecked).
    """
    return _takeover_never_checked(scan)


def _legacy_status(scan: dict, module: str) -> str:
    """Statut déduit d'un scan sans module_status (antérieur à la traçabilité des modules).

    Seuls les modules historiques (à colonne) existaient alors. Un module dont
    le résultat enregistré est absent, vide ou porte une erreur n'a pas été
    mesuré ; tout le scan l'est si son statut est « error ». Un module peut
    préciser la règle (ModuleSpec.legacy_measured).
    """
    if scan.get("status") == "error":
        return "failed"
    spec = _spec(module)
    if spec is None or spec.column is None:
        return "failed"
    value = scan.get(spec.column)
    if spec.legacy_measured is not None:
        return "ok" if spec.legacy_measured(scan, value) else "failed"
    if isinstance(spec.placeholder(None), list):
        return "ok" if isinstance(value, list) else "failed"
    if not isinstance(value, dict) or not value:
        return "failed"
    return "failed" if value.get("error") and value.get("measured") is not True else "ok"


def _launched(scan: dict) -> frozenset[str] | None:
    """Modules lancés par le scan, ou None quand il ne le dit pas (scan sans module_status).

    `modules_launched` d'abord (voir score.launched_modules) ; sinon
    `module_status`, qui ne liste que les modules lancés : les scans d'avant les
    profils de scan lançaient tous les modules et les y listaient tous.
    """
    declared = launched_modules(scan)
    if declared is not None:
        return declared
    module_status = as_dict(scan.get("module_status"))
    return frozenset(module_status) if module_status else None


def module_run_status(scan: dict, module: str) -> str:
    """Statut d'un module (« ok », « failed », « timeout », « skipped » ou « not_launched »).

    Seule règle, partagée par les familles et les constats (findings) : une famille
    « non mesurée » n'affiche jamais de constat. Un module absent de `module_status`
    et de `modules_launched` n'a pas été lancé : « not_launched », jamais « ok »,
    ni constat. Sinon, statut enregistré dans module_status (inconnu : « ok ») ;
    scan sans module_status : statut déduit de ses résultats (_legacy_status).
    """
    launched = _launched(scan)
    if launched is not None and module not in launched:
        return NOT_LAUNCHED
    module_status = as_dict(scan.get("module_status"))
    if not module_status:
        return _legacy_status(scan, module)
    status = as_dict(module_status.get(module)).get("status")
    return status if status in _MODULE_STATUSES else "ok"


def _module_statuses(scan: dict, family: str, modules: tuple[str, ...]) -> list[str]:
    """Statut de chaque module de la famille (voir module_run_status)."""
    return [module_run_status(scan, module) for module in modules]


def family_grade(scan: dict, family: str, criteria: tuple[str, ...] | None = None) -> str | None:
    """Lettre de la famille sur ses critères comptés du barème ; None sans critère noté."""
    from .score import criterion_rules

    if criteria is None:
        criteria = family_criteria().get(family, ())
    breakdown = as_dict(as_dict(scan.get("security_score")).get("breakdown"))
    obtained = maximum = 0
    counted_keys: list[str] = []
    for key in criteria:
        criterion = as_dict(breakdown.get(key))
        score, weight = _number(criterion.get("score")), _number(criterion.get("max"))
        # Ancien barème : ni counted ni measured, le critère est compté.
        counted = criterion.get("counted", criterion.get("measured", True))
        if score is None or weight is None or weight <= 0 or not counted:
            continue
        obtained += score
        maximum += weight
        counted_keys.append(key)
    if not maximum:
        return None
    # Critère seul de sa famille qui donne sa note selon ses points (e-mail : la
    # famille reprend la note du module ; les seuils globaux, appliqués aux points,
    # la dégraderaient d'un cran : C = 8/15 = 53 % -> D).
    if len(counted_keys) == 1:
        rule = criterion_rules().get(counted_keys[0])
        by_points = rule.grade_by_points if rule is not None else None
        if by_points and maximum == rule.weight and obtained in by_points:
            return by_points[obtained]
    # Arrondi au plus proche, moitié vers le haut (comme le score global).
    percent = math.floor(Fraction(obtained * 100) / Fraction(maximum) + Fraction(1, 2))
    return grade_for_score(percent)


def _verdict_unavailable(statuses: dict[str, str], verdict_modules: tuple[str, ...]) -> bool:
    """L'un des modules qui fondent le verdict de la famille est-il en échec, hors délai ou non lancé ?"""
    return any(statuses.get(module) in _UNAVAILABLE_STATUSES for module in verdict_modules)


def _worst(*states: str) -> str:
    return max(states, key=_STATE_RANK.__getitem__)


def _summary(findings_count: int, failed: int) -> dict:
    if findings_count and failed:
        return msg("family.summary_issues_partial", count=findings_count, failed=failed)
    if findings_count:
        return msg("family.summary_issues", count=findings_count)
    if failed:
        return msg("family.summary_partial", failed=failed)
    return msg("family.summary_ok")


def compute_families(scan: dict) -> dict[str, dict]:
    """État, note et résumé de chaque famille, dans l'ordre de FAMILY_KEYS."""
    # Import local : findings importe ce module (FAMILY_KEYS, MODULE_FAMILY).
    from .findings import compute_findings

    scan = as_dict(scan)
    findings = compute_findings(scan)
    members, criteria, verdicts = family_modules(), family_criteria(), family_verdict_modules()
    families: dict[str, dict] = {}
    for family in FAMILY_KEYS:
        modules = members.get(family, ())
        statuses = _module_statuses(scan, family, modules)
        # Seuls les modules lancés fondent l'état de la famille ; les autres sont signalés.
        launched = [status for status in statuses if status != NOT_LAUNCHED]
        not_launched = len(statuses) - len(launched)
        failed = sum(status in _FAILURE_STATUSES for status in launched)
        own = [finding for finding in findings if finding["family"] == family]
        grade = family_grade(scan, family, criteria.get(family, ()))
        # Le résumé dit-il déjà que des modules n'ont pas été lancés ?
        says_not_launched = False
        if not launched:
            # Aucun module lancé : famille écartée par le profil, ou sans module. Jamais un verdict.
            state, grade, summary = "unmeasured", None, msg("family.summary_not_launched")
            says_not_launched = True
        elif all(status == "skipped" for status in launched):
            state, grade, summary = "skipped", None, msg("family.summary_skipped")
        elif all(status != "ok" for status in launched):
            state, grade, summary = "unmeasured", None, msg("family.summary_unmeasured", failed=failed)
        elif family in INFO_FAMILIES:
            state, grade, summary = "info", None, msg("family.summary_info")
        elif (
            grade is None
            and not own
            and _verdict_unavailable(dict(zip(modules, statuses, strict=True)), verdicts.get(family, ()))
        ):
            # Un module qui fonde le verdict a échoué ou n'a pas été lancé, sans note ni
            # constat par ailleurs : aucun verdict honnête. Le sort d'un module descriptif
            # ne suffit pas.
            state, grade = "unmeasured", None
            if failed:
                summary = msg("family.summary_unmeasured", failed=failed)
            else:
                summary, says_not_launched = msg("family.summary_not_launched"), True
        else:
            state = _worst(
                _GRADE_STATE.get(grade, "ok"),
                *(_FINDING_STATE[finding["severity"]] for finding in own),
            )
            summary = _summary(len(own), failed)
        if not_launched and not says_not_launched:
            summary = msg(
                "common.join", items=[summary, msg("family.modules_not_launched", count=not_launched)]
            )
        families[family] = {"state": state, "grade": grade, "summary": summary}
    return families
