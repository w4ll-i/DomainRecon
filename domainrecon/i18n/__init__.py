# =============================================================================
# DomainRecon - Messages traduisibles (FR / EN)
# =============================================================================
# Le scanner et l'API ne produisent plus de texte destiné à l'utilisateur
# mais des messages : {"$t": "<code>", "p": {<paramètres>}}. La clé « $t »
# ne peut pas entrer en collision avec les données collectées. Le code est
# une entrée des catalogues fr.json et en.json (gabarits str.format à
# paramètres nommés). Les messages sont enregistrés tels quels et rendus à la
# lecture, dans la langue demandée (render) ; un texte brut (ancien scan) est
# rendu tel quel.
#
# Paramètres : texte, nombre, None (rendu vide), autre message (rendu dans la
# même langue), ou liste de ces valeurs, jointe par le paramètre réservé
# « sep » du message (à défaut « ; », selon la typographie de la langue).
# =============================================================================

import json
import logging
import string
from functools import cache

from ..core import paths

logger = logging.getLogger(__name__)

SUPPORTED_LANGS = ("fr", "en")
DEFAULT_LANG = "fr"

# Séparateur des listes, par langue (typographie française : espace avant « ; »).
_DEFAULT_SEPARATORS = {"fr": " ; ", "en": "; "}
_CODE = "$t"
_PARAMS = "p"


def msg(code: str, **params) -> dict:
    """Message traduisible : code du catalogue et paramètres nommés."""
    return {_CODE: code, _PARAMS: params}


def message(code: str, params: dict | None = None) -> dict:
    """Message dont le code n'est pas écrit en littéral ici : celui d'une règle déclarée
    (FindingRule.code). Les tests de contrat vérifient que ces codes existent en FR et EN.
    """
    return {_CODE: code, _PARAMS: dict(params or {})}


def is_msg(value: object) -> bool:
    """Vrai si `value` est un message produit par msg()."""
    return (
        isinstance(value, dict)
        and value.keys() == {_CODE, _PARAMS}
        and isinstance(value[_CODE], str)
        and isinstance(value[_PARAMS], dict)
    )


# Fragments de catalogue des modules : i18n/modules/<clé>.<langue>.json, un par
# module et par langue, fusionnés au catalogue principal (fr.json, en.json).
# Leur « Comment corriger » (module.<clé>.fix, .fix_snippet, .fix_ref) y figure aussi,
# mais en textes littéraux, lus par fix.py et non rendus par render().
FRAGMENTS_DIR = "modules"


def _read_catalog(path) -> dict[str, str]:
    """Catalogue JSON plat {code: gabarit} ; {} (avec avertissement) s'il manque ou est illisible."""
    try:
        with path.open(encoding="utf-8") as handle:
            data = json.load(handle)
    except FileNotFoundError:
        logger.warning("Catalogue de messages introuvable : %s", path)
        return {}
    except ValueError as e:
        logger.error("Catalogue de messages illisible : %s (%s)", path, e)
        return {}
    if not isinstance(data, dict):
        logger.error("Catalogue de messages invalide (objet JSON attendu) : %s", path)
        return {}
    return {str(code): str(template) for code, template in data.items()}


def catalog_fragments(lang: str) -> dict[str, dict[str, str]]:
    """Fragments d'une langue, par module : {clé du module: {code: gabarit}} (sans cache)."""
    if lang not in SUPPORTED_LANGS:
        return {}
    folder = paths.i18n_dir() / FRAGMENTS_DIR
    if not folder.is_dir():
        return {}
    suffix = f".{lang}.json"
    return {
        path.name[: -len(suffix)]: _read_catalog(path)
        for path in sorted(folder.glob(f"*{suffix}"))
        if path.is_file()
    }


@cache
def catalog(lang: str) -> dict[str, str]:
    """Catalogue {code: gabarit} d'une langue, fragments des modules compris (lu une fois, puis gardé).

    Un code d'un fragment qui existe déjà (catalogue principal ou autre fragment)
    est ignoré avec un avertissement : le premier l'emporte.
    """
    if lang not in SUPPORTED_LANGS:
        return {}
    merged = _read_catalog(paths.i18n_dir() / f"{lang}.json")
    for module, fragment in catalog_fragments(lang).items():
        for code, template in fragment.items():
            if code in merged:
                logger.warning("Message %s du fragment %s.%s.json déjà défini : ignoré", code, module, lang)
                continue
            merged[code] = template
    return merged


class _KeepUnknown(dict):
    """Paramètres d'un gabarit : un paramètre absent laisse « {nom} » tel quel."""

    def __missing__(self, key: str) -> str:
        return "{" + key + "}"


def _template(code: str, lang: str) -> str:
    return catalog(lang).get(code) or catalog(DEFAULT_LANG).get(code) or code


def _param_text(value: object, lang: str, sep: str) -> object:
    if is_msg(value):
        return _render_message(value, lang)
    if isinstance(value, (list, tuple)):
        return sep.join(str(_param_text(item, lang, sep)) for item in value)
    if value is None:
        return ""
    return value


def _render_message(message: dict, lang: str) -> str:
    params = message[_PARAMS]
    sep = params.get("sep")
    if not isinstance(sep, str):
        sep = _DEFAULT_SEPARATORS[lang]
    values = _KeepUnknown({name: _param_text(value, lang, sep) for name, value in params.items()})
    template = _template(message[_CODE], lang)
    try:
        return template.format_map(values)
    except (ValueError, IndexError, KeyError, AttributeError, TypeError):
        return template


def render(value: object, lang: str) -> object:
    """Copie de `value` où chaque message est remplacé par son texte dans `lang`.

    Parcourt dicts, listes et tuples (namedtuple conservés) ; toute autre
    valeur, textes bruts compris, est rendue telle quelle.
    """
    if lang not in SUPPORTED_LANGS:
        lang = DEFAULT_LANG
    if is_msg(value):
        return _render_message(value, lang)
    if isinstance(value, dict):
        return {key: render(item, lang) for key, item in value.items()}
    if isinstance(value, list):
        return [render(item, lang) for item in value]
    if isinstance(value, tuple):
        items = [render(item, lang) for item in value]
        make = getattr(type(value), "_make", None)
        return make(items) if make is not None else tuple(items)
    return value


def _primary_tag(tag: str) -> str:
    return tag.strip().lower().replace("_", "-").split("-", 1)[0]


def _zero_quality(params: str) -> bool:
    """Vrai si les paramètres d'une langue d'Accept-Language portent q=0 (langue refusée)."""
    for param in params.split(";"):
        name, _, value = param.strip().partition("=")
        if name.strip().lower() == "q":
            try:
                return float(value) == 0
            except ValueError:
                return False
    return False


def negotiate_lang(query_lang: str | None, accept_language: str | None) -> str:
    """Langue des messages : ?lang= d'abord, puis Accept-Language (ordre d'apparition), sinon le français."""
    if query_lang and _primary_tag(query_lang) in SUPPORTED_LANGS:
        return _primary_tag(query_lang)
    for item in (accept_language or "").split(","):
        tag, _, params = item.partition(";")
        if _zero_quality(params):
            continue
        primary = _primary_tag(tag)
        if primary in SUPPORTED_LANGS:
            return primary
    return DEFAULT_LANG


def unique(items: list) -> list:
    """Éléments sans doublon (messages compris), dans l'ordre d'apparition."""
    seen: set[str] = set()
    result = []
    for item in items:
        key = json.dumps(item, sort_keys=True, ensure_ascii=False, default=str)
        if key not in seen:
            seen.add(key)
            result.append(item)
    return result


def dumps_message(value: object) -> str | None:
    """Texte à ranger dans une colonne TEXT : un message y est stocké en JSON."""
    if value is None or isinstance(value, str):
        return value
    return json.dumps(value, ensure_ascii=False)


def loads_message(text: object) -> object:
    """Inverse de dumps_message : un texte ordinaire (ancien scan) est rendu tel quel."""
    if isinstance(text, str) and text.startswith('{"$t"'):
        try:
            value = json.loads(text)
        except ValueError:
            return text
        if is_msg(value):
            return value
    return text


def placeholders(template: str) -> set[str]:
    """Noms des paramètres d'un gabarit."""
    return {name for _, name, _, _ in string.Formatter().parse(template) if name}
