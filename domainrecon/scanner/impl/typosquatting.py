# =============================================================================
# DomainRecon - Génération des variantes de typosquatting (logique pure, sans réseau)
# =============================================================================
# Le module scanner/modules/typosquatting.py résout et classe ces variantes. Ici :
#   - découpage correct du domaine en NOM + SUFFIXE PUBLIC (liste PSL) : pour
#     example.co.uk, le nom est « example » et le suffixe « co.uk » (l'ancien
#     module coupait au dernier point : « example.co » + « uk ») ;
#   - génération déterministe des variantes (omission, répétition, permutation,
#     touche voisine d'un clavier QWERTY, homoglyphes ASCII, homoglyphes IDN en
#     punycode, tiret, erreur de bit, voyelles, affixes courants, suffixes
#     alternatifs) ;
#   - plafond du nombre de variantes appliqué en alternant les types, pour que la
#     troncature ne supprime pas un type entier (pas de coupe au hasard dans un
#     ensemble).
# =============================================================================

import re
from collections.abc import Iterator

from ..targets import registrable_domain

MAX_VARIANTS = 300

_LABEL_RE = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")
_ALPHABET = frozenset("abcdefghijklmnopqrstuvwxyz0123456789-")

# Suffixes alternatifs fréquents dans les domaines d'usurpation.
ALTERNATIVE_SUFFIXES = (
    "com", "net", "org", "info", "biz", "co", "io", "app", "dev", "online", "site", "store", "shop", "xyz",
    "club", "top", "tech", "cloud", "ai", "me", "cc", "us", "uk", "ca", "de", "fr", "eu", "es", "it", "nl",
    "ch", "be", "pro", "email", "support", "help", "finance", "bank", "security", "network",
)  # fmt: skip

AFFIXES = (
    "login",
    "secure",
    "support",
    "mail",
    "my",
    "app",
    "online",
    "official",
    "web",
    "portal",
    "account",
    "help",
    "pay",
    "service",
)
# Affixes aussi collés au nom (« loginexample »).
GLUED_AFFIXES = ("login", "mail", "secure", "online", "support", "my", "the", "get")

# Homoglyphes ASCII : sous-chaîne -> remplacement (aspect proche à l'écran).
ASCII_HOMOGLYPHS = (
    ("rn", "m"), ("m", "rn"), ("vv", "w"), ("w", "vv"), ("cl", "d"), ("d", "cl"), ("nn", "m"),
    ("l", "1"), ("1", "l"), ("i", "l"), ("l", "i"), ("o", "0"), ("0", "o"), ("g", "q"), ("q", "g"),
)  # fmt: skip

# Homoglyphes Unicode (cyrillique, latin accentué) : lettre -> caractères proches.
IDN_HOMOGLYPHS = {
    "a": ("а", "á"),
    "c": ("с",),
    "e": ("е", "é"),
    "i": ("і", "í"),
    "j": ("ј",),
    "o": ("о", "ö"),
    "p": ("р",),
    "s": ("ѕ",),
    "u": ("ü",),
    "x": ("х",),
    "y": ("у",),
}

_KEY_ROWS = ("1234567890", "qwertyuiop", "asdfghjkl", "zxcvbnm")
_VOWELS = "aeiou"

# Types de variantes, dans l'ordre d'alternance du plafond.
TYPES = (
    "tld_swap",
    "omission",
    "transposition",
    "ascii_homoglyph",
    "idn_homoglyph",
    "replacement",
    "repetition",
    "hyphenation",
    "affix",
    "bitsquat",
    "vowel_swap",
    "plural",
)


def split_domain(domain: str) -> tuple[str, str] | None:
    """(nom, suffixe public) d'un domaine enregistrable, ou None s'il n'en a pas.

    « example.co.uk » -> (« example », « co.uk »). Un sous-domaine est ramené à son
    domaine enregistrable.
    """
    registrable = registrable_domain(domain.strip(".").lower())
    label, _, suffix = registrable.partition(".")
    if not label or not suffix or not _LABEL_RE.match(label):
        return None
    return label, suffix


def _neighbors() -> dict[str, str]:
    """Touches voisines d'un clavier QWERTY (même rangée, rangées voisines décalées)."""
    found: dict[str, set[str]] = {}
    for r, row in enumerate(_KEY_ROWS):
        for i, key in enumerate(row):
            near = set(row[max(0, i - 1) : i + 2]) - {key}
            for other in (r - 1, r + 1):
                if 0 <= other < len(_KEY_ROWS):
                    for j in (i - 1, i, i + 1):
                        if 0 <= j < len(_KEY_ROWS[other]):
                            near.add(_KEY_ROWS[other][j])
            found[key] = near
    return {key: "".join(sorted(near)) for key, near in found.items()}


KEYBOARD = _neighbors()


def _valid(label: str) -> bool:
    return bool(_LABEL_RE.match(label))


def _label_variants(label: str) -> dict[str, list[str]]:
    """Variantes du NOM seul (le suffixe est ajouté ensuite), par type."""
    out: dict[str, list[str]] = {t: [] for t in TYPES}
    n = len(label)
    if n > 3:
        out["omission"] = [label[:i] + label[i + 1 :] for i in range(n)]
    out["transposition"] = [
        label[:i] + label[i + 1] + label[i] + label[i + 2 :] for i in range(n - 1) if label[i] != label[i + 1]
    ]
    for src, dst in ASCII_HOMOGLYPHS:
        start = 0
        while (at := label.find(src, start)) != -1:
            out["ascii_homoglyph"].append(label[:at] + dst + label[at + len(src) :])
            start = at + 1
    for i, ch in enumerate(label):
        for alt in IDN_HOMOGLYPHS.get(ch, ()):
            out["idn_homoglyph"].append(label[:i] + alt + label[i + 1 :])
        for key in KEYBOARD.get(ch, ""):
            out["replacement"].append(label[:i] + key + label[i + 1 :])
        out["repetition"].append(label[:i] + ch + ch + label[i + 1 :])
        for bit in range(8):
            flipped = chr(ord(ch) ^ (1 << bit))
            if flipped in _ALPHABET and flipped != ch:
                out["bitsquat"].append(label[:i] + flipped + label[i + 1 :])
        if ch in _VOWELS:
            out["vowel_swap"].extend(label[:i] + v + label[i + 1 :] for v in _VOWELS if v != ch)
    out["hyphenation"] = [label[:i] + "-" + label[i:] for i in range(1, n)]
    for affix in AFFIXES:
        out["affix"] += [f"{affix}-{label}", f"{label}-{affix}"]
    for affix in GLUED_AFFIXES:
        out["affix"] += [f"{affix}{label}", f"{label}{affix}"]
    out["affix"].append(f"www{label}")
    out["plural"] = [label + "s"] if not label.endswith("s") else []
    return out


def _alternative_suffixes(suffix: str) -> list[str]:
    """Suffixes de remplacement : les usuels et, pour « co.uk », ses composants (« uk », « com »…)."""
    found = [s for s in ALTERNATIVE_SUFFIXES if s != suffix]
    last = suffix.rsplit(".", 1)[-1]
    if "." in suffix and last not in found:
        found.insert(0, last)
    return found


def _ascii_domain(label: str, suffix: str) -> str | None:
    """Nom de domaine ASCII (punycode pour un nom Unicode), ou None s'il est invalide."""
    try:
        domain = f"{label}.{suffix}".encode("idna").decode("ascii")
    except UnicodeError:
        return None
    first = domain.split(".", 1)[0]
    return domain if first and len(first) <= 63 and (first.startswith("xn--") or _valid(first)) else None


def generate(domain: str, limit: int = MAX_VARIANTS) -> list[tuple[str, str]]:
    """Variantes (domaine, type) d'un domaine, au plus `limit`, dans un ordre déterministe.

    Les types sont alternés (une variante de chaque type à tour de rôle) : le
    plafond n'élimine jamais un type entier. Le domaine d'origine n'y figure pas.
    """
    parts = split_domain(domain)
    if parts is None:
        return []
    label, suffix = parts
    original = f"{label}.{suffix}"
    queues: dict[str, list[str]] = {t: [] for t in TYPES}
    queues["tld_swap"] = [f"{label}.{s}" for s in _alternative_suffixes(suffix)]
    for kind, labels in _label_variants(label).items():
        for variant in labels:
            candidate = _ascii_domain(variant, suffix)
            if candidate and candidate != original:
                queues[kind].append(candidate)

    seen = {original}
    result: list[tuple[str, str]] = []
    iterators: dict[str, Iterator[str]] = {t: iter(q) for t, q in queues.items()}
    active = list(TYPES)
    while active and len(result) < limit:
        for kind in list(active):
            for candidate in iterators[kind]:
                if candidate not in seen:
                    seen.add(candidate)
                    result.append((candidate, kind))
                    break
            else:
                active.remove(kind)
            if len(result) >= limit:
                break
    return result
