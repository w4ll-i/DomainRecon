# =============================================================================
# DomainRecon - Contenu web : comparaison de versions (sans dépendance)
# =============================================================================
# Sert aux modules js_dependencies et tech_cves. Une comparaison naïve :
#   - compterait « vulnérable » une version égale à la version CORRIGÉE (borne
#     inclusive : jQuery 3.5.0 et Bootstrap 4.3.1 seraient signalés à tort) ;
#   - jugerait vulnérable une version non numérique (« latest », « 3.x »).
# Ici, une version illisible rend None (« indéterminé ») : jamais un constat.
# =============================================================================

import re

# Version « 1.2.3 », « v2.0 », « 3.5.0-beta.1 », « 1.0.0rc2 » : numéros, puis suite facultative.
_VERSION_RE = re.compile(r"v?(\d+(?:\.\d+){0,3})(?:[-_.+]?([A-Za-z][A-Za-z0-9.\-]*))?\Z")

# Qualificatifs d'avant-version : la version finale leur est supérieure.
_PRE_RE = re.compile(r"(alpha|beta|rc|pre|preview|dev|snapshot|canary|next)|[abc]\d*\Z")


def parse_version(text: object) -> tuple[tuple[int, ...], bool] | None:
    """Version lue : (numéros, avant-version) ; None si le texte n'est pas une version numérique."""
    if not isinstance(text, str):
        return None
    match = _VERSION_RE.match(text.strip())
    if not match:
        return None
    numbers = tuple(int(part) for part in match.group(1).split("."))
    suffix = (match.group(2) or "").lower()
    if suffix in ("x", "*"):
        return None  # « 3.x » : une plage, pas une version
    pre = bool(suffix) and _PRE_RE.match(suffix) is not None
    return numbers, pre


def _padded(numbers: tuple[int, ...], size: int) -> tuple[int, ...]:
    return numbers + (0,) * (size - len(numbers))


def compare_versions(left: object, right: object) -> int | None:
    """-1, 0 ou 1 selon l'ordre de deux versions ; None si l'une est illisible."""
    a, b = parse_version(left), parse_version(right)
    if a is None or b is None:
        return None
    size = max(len(a[0]), len(b[0]))
    key_a = (_padded(a[0], size), not a[1])
    key_b = (_padded(b[0], size), not b[1])
    return (key_a > key_b) - (key_a < key_b)


def is_affected(version: object, introduced: str | None, fixed: str | None) -> bool | None:
    """La version est-elle dans [introduced, fixed[ ?

    - `introduced` : première version touchée (None ou « 0 » : depuis toujours) ;
    - `fixed` : première version CORRIGÉE, exclue (None : jamais corrigée).
    Rend None si la version, ou une borne, est illisible : le doute n'est pas un constat.
    """
    if parse_version(version) is None:
        return None
    if introduced not in (None, "", "0"):
        lower = compare_versions(version, introduced)
        if lower is None:
            return None
        if lower < 0:
            return False
    if fixed is None:
        return True
    upper = compare_versions(version, fixed)
    if upper is None:
        return None
    return upper < 0


def clean_version(text: object) -> str | None:
    """Version utilisable (numéros, au plus 4 groupes) extraite d'un texte, ou None."""
    if not isinstance(text, str):
        return None
    match = re.search(r"\d+(?:\.\d+){0,3}(?:-(?:alpha|beta|rc)[.\d]*)?", text)
    if not match or len(match.group(0)) > 24:
        return None
    return match.group(0)


def highest_version(values) -> str | None:
    """La plus grande des versions lisibles (celle qui corrige toutes les failles listées), ou None."""
    best = None
    for value in values:
        if parse_version(value) is None:
            continue
        if best is None or compare_versions(value, best) == 1:
            best = value
    return best
