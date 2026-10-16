# =============================================================================
# DomainRecon - Ligne de commande : aides communes aux sous-commandes
# =============================================================================
# Codes de sortie : 0 succès ; 1 note sous le seuil demandé (--fail-under) ;
# 2 erreur d'usage ou d'exécution (cible refusée, scan en échec, fichier
# illisible…) ; 130 interruption.
# =============================================================================

from __future__ import annotations

import argparse
import asyncio
import sys
from collections.abc import Callable, Sequence
from pathlib import Path

EXIT_OK = 0
EXIT_BELOW_THRESHOLD = 1
EXIT_ERROR = 2

GRADE_ORDER = ("A", "B", "C", "D", "F")
PROFILES = ("rapide", "complet", "personnalise")


class CliError(Exception):
    """Erreur affichée sur la sortie d'erreur ; `code` est le code de sortie."""

    def __init__(self, message: str, code: int = EXIT_ERROR) -> None:
        super().__init__(message)
        self.code = code


# --- Arguments communs -----------------------------------------------------


def add_lang(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--lang", choices=("fr", "en"), default="fr", help="langue des textes (défaut : fr)")


def add_scan_options(parser: argparse.ArgumentParser) -> None:
    """Options de lancement d'un scan, communes à `scan` et `batch`."""
    parser.add_argument(
        "--profile",
        choices=PROFILES,
        default="complet",
        help="profil de scan (défaut : complet) ; « personnalise » exige --modules",
    )
    parser.add_argument("--modules", help="modules du profil personnalisé, séparés par des virgules")
    parser.add_argument(
        "--authorized",
        action="store_true",
        help="je déclare avoir l'autorisation de tester la cible (modules actifs ou sensibles)",
    )
    parser.add_argument(
        "--fail-under",
        metavar="NOTE",
        type=str.upper,
        choices=GRADE_ORDER,
        help="code de sortie 1 si la note est inférieure à NOTE (A, B, C, D ou F ; « N/A » compte comme inférieure)",
    )
    parser.add_argument("-q", "--quiet", action="store_true", help="pas d'avancement sur la sortie d'erreur")
    add_lang(parser)


# --- Aides ------------------------------------------------------------------


def parse_modules(value: str | None) -> list[str]:
    """Noms séparés par des virgules (espaces et doublons ignorés)."""
    names = [part.strip() for part in (value or "").split(",") if part.strip()]
    return list(dict.fromkeys(names))


def below_threshold(grade: str | None, threshold: str | None) -> bool:
    """Vrai si `grade` est strictement sous `threshold` ; une note absente ou N/A est sous tout seuil."""
    if threshold is None:
        return False
    if grade not in GRADE_ORDER:
        return True
    return GRADE_ORDER.index(grade) > GRADE_ORDER.index(threshold)


def grade_of(payload: dict) -> str:
    """Note affichée d'un scan (A à F, sinon « N/A »)."""
    score = payload.get("security_score")
    score = score if isinstance(score, dict) else {}
    grade = score.get("grade")
    value = score.get("score")
    if grade in GRADE_ORDER and isinstance(value, (int, float)) and not isinstance(value, bool):
        return grade
    return "N/A"


def table(headers: Sequence[str], rows: Sequence[Sequence[object]]) -> str:
    """Tableau texte aligné à gauche, colonnes séparées de deux espaces."""
    cells = [[str(c) for c in headers]] + [["" if c is None else str(c) for c in row] for row in rows]
    widths = [max(len(row[i]) for row in cells) for i in range(len(headers))]

    def line(row: list[str]) -> str:
        return "  ".join(cell.ljust(widths[i]) for i, cell in enumerate(row)).rstrip()

    out = [line(cells[0]), "  ".join("-" * w for w in widths)]
    out += [line(row) for row in cells[1:]]
    return "\n".join(out)


def info(text: str) -> None:
    print(text, file=sys.stderr)


def write_output(content: bytes, output: str | None, fmt: str) -> None:
    """Écrit un rapport dans `output`, sinon sur la sortie standard (le PDF exige un fichier)."""
    if output:
        path = Path(output)
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(content)
        except OSError as exc:
            raise CliError(f"Écriture impossible dans {path} : {exc.strerror or exc}") from exc
        info(f"Rapport écrit : {path}")
        return
    if fmt == "pdf":
        raise CliError("Le format pdf est binaire : indiquez un fichier avec -o.")
    sys.stdout.write(content.decode("utf-8-sig"))
    sys.stdout.flush()


# --- Stockage et exécution -----------------------------------------------------


def open_storage() -> None:
    """Prépare la base (tables, schéma) comme le fait le serveur au démarrage."""
    try:
        from ..api import storage

        storage.prepare_storage()
    except Exception as exc:
        raise CliError(f"Base de données inaccessible : {type(exc).__name__}: {exc}") from exc


def error_text(exc: BaseException, lang: str) -> str:
    """Texte d'une erreur du scanner (message traduisible porté, sinon str)."""
    from ..i18n import render
    from ..scanner.errors import message_of

    value = message_of(exc)
    if value is None:
        return str(exc)
    rendered = render(value, lang)
    return rendered if isinstance(rendered, str) else str(rendered)


def execute_scan(
    domain: str,
    *,
    profile: str,
    modules: str | None,
    authorized: bool,
    lang: str,
    quiet: bool,
    runner: Callable | None = None,
) -> int:
    """Lance un scan, l'enregistre et renvoie son identifiant.

    L'autorisation des modules actifs ou sensibles est exigée comme par l'API
    (plan_scan) ; la politique de cibles (anti-SSRF) et le proxy sortant sont
    ceux du scanner. `runner` remplace perform_full_scan (tests).
    """
    from ..api import storage
    from ..api.jobs import plan_scan
    from ..core.settings_store import load_secrets
    from ..scanner import perform_full_scan

    selected = parse_modules(modules)
    if profile == "personnalise" and not selected:
        raise CliError("Le profil « personnalise » exige --modules a,b,…")
    try:
        secrets = load_secrets()
        plan = plan_scan(profile, selected, authorized, secrets)
    except ValueError as exc:
        raise CliError(error_text(exc, lang)) from exc

    total = len(plan.modules)
    done = 0

    def progress(name: str, status: str, duration: float) -> None:
        nonlocal done
        done += 1
        if not quiet:
            info(f"  [{done}/{total}] {name:<28}{status:<9}{duration:.1f} s")

    if not quiet:
        info(f"Scan de {domain} : profil {plan.profile}, {total} module(s)")
    scan = runner or perform_full_scan
    try:
        result = asyncio.run(
            scan(
                domain,
                on_module=progress,
                profile=plan.profile,
                authorized_target=plan.authorized_target,
                selected=plan.selected,
                available_keys=plan.available_keys,
            )
        )
    except ValueError as exc:  # cible invalide ou refusée, profil ou proxy inutilisable
        raise CliError(error_text(exc, lang)) from exc
    except Exception as exc:
        # Aucun détail : le texte d'une exception réseau peut contenir une URL avec une clé.
        raise CliError(f"Scan de {domain} échoué ({type(exc).__name__}).") from exc
    # Profil et modules lancés enregistrés avec le scan, comme par l'API (ceux du résultat priment).
    result = {"profile": plan.profile, "modules_launched": list(plan.modules), **result}
    try:
        return storage.save_scan(result)
    except storage.ScanSaveError as exc:
        raise CliError(f"Scan de {domain} terminé mais impossible à enregistrer.") from exc
