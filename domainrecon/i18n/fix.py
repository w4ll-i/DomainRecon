# =============================================================================
# DomainRecon - « Comment corriger » d'un module : convention, chargement, contrôle
# =============================================================================
# Chaque module peut fournir, dans ses fragments de catalogue
# (i18n/modules/<clé>.fr.json et <clé>.en.json), trois textes :
#   module.<clé>.fix          étapes concrètes de correction, une par ligne ("\n") ;
#   module.<clé>.fix_snippet  extrait prêt à copier ; plusieurs variantes séparées
#                             par une ligne d'en-tête « # nginx », « # Apache »… ;
#   module.<clé>.fix_ref      URL https de la documentation officielle.
#
# Ce sont des textes LITTÉRAUX, pas des gabarits str.format : jamais de paramètre
# {nom}, accolades gardées telles quelles (un extrait nginx ou JSON en est plein, et
# un « : » dans des accolades serait pris pour une spécification de format). Ils ne
# passent donc jamais par render() : fix_texts() les lit dans le catalogue, et
# GET /api/modules les expose (champs absents quand le module ne les renseigne pas).
#
# Ce fichier porte aussi les contrôles de forme que le test de contrat applique aux
# textes écrits (fix_problems, fix_pair_problems) : une seule définition de la
# convention, celle du contrat des modules (docs/contrat-modules.md §9.1).
# =============================================================================

import re
import unicodedata
from collections.abc import Callable, Mapping
from urllib.parse import urlsplit

from . import DEFAULT_LANG, SUPPORTED_LANGS, catalog

# Parties du « Comment corriger » : étapes, extrait prêt à copier, documentation officielle.
FIX_PARTS = ("fix", "fix_snippet", "fix_ref")

# Bornes de bon sens que l'interface suppose (reprises dans le contrat des modules).
MAX_STEPS = 10
MAX_STEP_LENGTH = 500
MAX_SNIPPET_LENGTH = 2500
MAX_VARIANTS = 6
MAX_LABEL_LENGTH = 40
MAX_REF_LENGTH = 300

# En-tête de variante d'un extrait : « # » suivi d'une espace, en première colonne,
# puis le libellé (nom de produit ou de format : nginx, Apache, IIS, DNS…).
SNIPPET_HEADER = "# "

_FIX_CODE = re.compile(r"module\.[a-z][a-z0-9_]*\.(?:" + "|".join(FIX_PARTS) + r")")
# Numéro ou puce en tête d'étape (« 1. », « 2) », « - », « • », « Étape 3 : »…) : l'interface numérote.
_LIST_MARKER = re.compile(r"(?:\d{1,3}[.)]\s|[-*+•–—]\s|(?:étape|etape|step)\s*\d+\s*[:.)-])", re.IGNORECASE)
# Caractères refusés dans une URL, en plus des espaces et des caractères non ASCII.
_URL_FORBIDDEN = "<>\"'`\\"


def fix_codes(name: str) -> dict[str, str]:
    """Codes i18n du « Comment corriger » du module `name`, par partie."""
    return {part: f"module.{name}.{part}" for part in FIX_PARTS}


def is_fix_code(code: str) -> bool:
    """Vrai pour module.<clé>.fix, .fix_snippet et .fix_ref : textes littéraux, pas des gabarits."""
    return _FIX_CODE.fullmatch(code) is not None


# =============================================================================
# Chargement
# =============================================================================


def fix_texts(name: str, lang: str, *, fallback: bool = True) -> dict[str, str]:
    """Textes renseignés du « Comment corriger » du module `name` dans `lang`, par partie.

    Une partie sans texte (clé absente ou vide) est omise. Textes littéraux : rendus tels
    quels, sans str.format. `fallback` : une partie absente de `lang` est prise en français,
    comme tous les textes (False : la langue seule, pour contrôler un fragment).
    """
    if lang not in SUPPORTED_LANGS:
        lang = DEFAULT_LANG
    texts: dict[str, str] = {}
    for part, code in fix_codes(name).items():
        text = catalog(lang).get(code)
        if not (text and text.strip()) and fallback:
            text = catalog(DEFAULT_LANG).get(code)
        if text and text.strip():
            texts[part] = text
    return texts


def fix_steps(text: str) -> list[str]:
    """Étapes d'un `fix` : une par ligne non vide, espaces de bord retirés."""
    return [line.strip() for line in text.split("\n") if line.strip()]


def snippet_variants(text: str) -> list[tuple[str | None, str]]:
    """Variantes d'un `fix_snippet` : [(libellé, code)].

    Une ligne qui commence par « # » et une espace ouvre une variante (libellé = le reste de
    la ligne). Sans aucun en-tête : une seule variante, de libellé None. Le code est rendu
    sans lignes vides de bord, lignes intérieures intactes.
    """
    variants: list[tuple[str | None, list[str]]] = []
    for line in text.split("\n"):
        if line.startswith(SNIPPET_HEADER):
            variants.append((line[len(SNIPPET_HEADER) :].strip(), []))
            continue
        if not variants:
            variants.append((None, []))
        variants[-1][1].append(line)
    return [(label, "\n".join(lines).strip("\n")) for label, lines in variants]


def is_https_url(text: object) -> bool:
    """Vrai pour une URL https absolue sur une ligne : ASCII imprimable, hôte à point, sans identifiants."""
    if not isinstance(text, str) or not text.startswith("https://") or len(text) > MAX_REF_LENGTH:
        return False
    if not all("!" <= c <= "~" and c not in _URL_FORBIDDEN for c in text):
        return False
    try:
        parts = urlsplit(text)
        _ = parts.port  # lève ValueError si le port est invalide
    except ValueError:
        return False
    return bool(parts.hostname) and "." in parts.hostname and "@" not in parts.netloc


# =============================================================================
# Contrôle de forme (test de contrat)
# =============================================================================


def _character_problems(value: str, *, ascii_only: bool) -> list[str]:
    problems = []
    if "\r" in value:
        problems.append("retour chariot (\\r) : lignes séparées par \\n seulement")
    if "\t" in value:
        problems.append("tabulation : indenter avec des espaces")
    others = [c for c in value if c not in "\n\r\t"]
    if ascii_only:
        # Copier-coller sûr : guillemets droits, espaces simples, aucune typographie.
        odd = {c for c in others if not " " <= c <= "~"}
    else:
        odd = {c for c in others if unicodedata.category(c) in ("Cc", "Cf")}
    if odd:
        names = ", ".join(f"U+{ord(c):04X}" for c in sorted(odd))
        problems.append(f"caractères interdits ({names})" + (" : ASCII seulement" if ascii_only else ""))
    return problems


def _steps_problems(value: str) -> list[str]:
    problems = []
    steps = 0
    for number, line in enumerate(value.split("\n"), start=1):
        if not line.strip():
            problems.append(f"ligne {number} vide : une étape par ligne, sans ligne vide")
            continue
        steps += 1
        if line != line.strip():
            problems.append(f"ligne {number} : espaces en début ou en fin de ligne")
        if _LIST_MARKER.match(line.strip()):
            problems.append(f"ligne {number} : ni numéro ni puce en tête d'étape (l'interface numérote)")
        if len(line) > MAX_STEP_LENGTH:
            problems.append(f"ligne {number} : {len(line)} caractères (maximum {MAX_STEP_LENGTH})")
        if "```" in line:
            problems.append(
                f"ligne {number} : pas de bloc de code ``` (le code à copier va dans fix_snippet)"
            )
        elif line.count("`") % 2:
            problems.append(f"ligne {number} : accents graves ` en nombre impair (code en ligne `ainsi`)")
    if steps > MAX_STEPS:
        problems.append(f"{steps} étapes (maximum {MAX_STEPS})")
    return problems


def _label_problems(label: str, seen: set[str]) -> list[str]:
    """Défauts du libellé d'une variante ; `seen` garde les libellés déjà vus (minuscules)."""
    if not label:
        return [f"en-tête « {SNIPPET_HEADER.strip()} » sans libellé"]
    problems = []
    if len(label) > MAX_LABEL_LENGTH:
        problems.append(f"libellé « {label} » de plus de {MAX_LABEL_LENGTH} caractères")
    if label.startswith("#"):
        problems.append(f"libellé « {label} » : ne commence pas par « # »")
    if label.casefold() in seen:
        problems.append(f"libellé « {label} » en double")
    seen.add(label.casefold())
    return problems


def _snippet_problems(value: str) -> list[str]:
    problems = []
    if len(value) > MAX_SNIPPET_LENGTH:
        problems.append(f"{len(value)} caractères (maximum {MAX_SNIPPET_LENGTH})")
    variants = snippet_variants(value)
    if len(variants) > MAX_VARIANTS:
        problems.append(f"{len(variants)} variantes (maximum {MAX_VARIANTS})")
    if variants[0][0] is None and len(variants) > 1:
        problems.append(
            f"du code précède le premier en-tête « {SNIPPET_HEADER}libellé » : chaque variante en a un"
        )
    seen: set[str] = set()
    for label, code in variants:
        if label is None:
            continue
        problems += _label_problems(label, seen)
        if label and not code:
            problems.append(f"variante « {label} » sans code")
    return problems


def _ref_problems(value: str) -> list[str]:
    return [] if is_https_url(value) else ["URL https absolue attendue (ASCII, sans espace ni identifiants)"]


# Contrôles propres à chaque partie : (extrait en ASCII seulement ?, contrôle de structure).
_CHECKS: dict[str, tuple[bool, Callable[[str], list[str]]]] = {
    "fix": (False, _steps_problems),
    "fix_snippet": (True, _snippet_problems),
    "fix_ref": (False, _ref_problems),
}


def fix_problems(texts: Mapping[str, object]) -> list[str]:
    """Défauts de forme des textes d'UNE langue (parties présentes, par nom) ; liste vide : conforme."""
    problems = [f"{part} : partie inconnue" for part in texts if part not in FIX_PARTS]
    for part, (ascii_only, check_structure) in _CHECKS.items():
        if part not in texts:
            continue
        value = texts[part]
        if not isinstance(value, str):
            own = [f"texte attendu, pas {type(value).__name__}"]
        elif not value.strip():
            own = ["texte vide : omettre la clé plutôt que la laisser vide"]
        else:
            own = _character_problems(value, ascii_only=ascii_only) + check_structure(value)
            if value != value.strip():
                own.insert(0, "espace ou saut de ligne en début ou en fin de texte")
        problems += [f"{part} : {problem}" for problem in own]
    if "fix" not in texts and ("fix_snippet" in texts or "fix_ref" in texts):
        problems.append("fix_snippet ou fix_ref sans fix : les étapes sont la base du conseil")
    return problems


def fix_pair_problems(fr: Mapping[str, str], en: Mapping[str, str]) -> list[str]:
    """Écarts entre les deux langues : partie présente d'un seul côté, nombre d'étapes, variantes."""
    problems = []
    for part in FIX_PARTS:
        if (part in fr) != (part in en):
            have, lack = ("fr", "en") if part in fr else ("en", "fr")
            problems.append(f"{part} présent en {have} mais absent en {lack}")
    if "fix" in fr and "fix" in en:
        steps_fr, steps_en = len(fix_steps(fr["fix"])), len(fix_steps(en["fix"]))
        if steps_fr != steps_en:
            problems.append(f"fix : {steps_fr} étape(s) en fr, {steps_en} en en (mêmes étapes dans les deux)")
    if "fix_snippet" in fr and "fix_snippet" in en:
        labels_fr = [label for label, _ in snippet_variants(fr["fix_snippet"])]
        labels_en = [label for label, _ in snippet_variants(en["fix_snippet"])]
        if labels_fr != labels_en:
            problems.append(f"fix_snippet : variantes {labels_fr} en fr, {labels_en} en en (mêmes libellés)")
    return problems
