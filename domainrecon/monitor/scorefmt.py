# =============================================================================
# DomainRecon - Surveillance : note et score tels que l'interface les affiche
# =============================================================================
# Même règle que l'Historique et la timeline (api/routes/history.py) : un score
# n'est montré que s'il est mesuré (couverture non nulle, note valable ou
# critères comptés) ; une note A à F stockée sans score, ou sur une couverture
# inférieure à MIN_GRADED_COVERAGE, s'affiche « N/A ».
# =============================================================================

from ..scanner.score import MIN_GRADED_COVERAGE

GRADES = ("A", "B", "C", "D", "F")


def _number(value: object) -> int | float | None:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    return value


def display_score(security_score: object) -> dict:
    """{score, grade, coverage} affichés ; score None et note « N/A » quand rien n'est mesuré."""
    data = security_score if isinstance(security_score, dict) else {}
    grade = data.get("grade") if isinstance(data.get("grade"), str) else None
    coverage = _number(data.get("coverage"))
    measured_max = _number(data.get("measured_max"))
    low = coverage is not None and coverage < MIN_GRADED_COVERAGE
    measured = coverage != 0 and (
        (grade != "N/A" and not low) or (measured_max is not None and measured_max > 0)
    )
    score = _number(data.get("score")) if measured else None
    shown = grade if grade in GRADES and not low and score is not None else "N/A"
    return {"score": score, "grade": shown, "coverage": coverage}


def grade_rank(grade: object) -> int | None:
    """Rang d'une note (A = 0 … F = 4) ; None pour « N/A » ou une valeur inconnue."""
    return GRADES.index(grade) if grade in GRADES else None
