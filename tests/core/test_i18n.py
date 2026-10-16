# =============================================================================
# DomainRecon - Tests des messages traduisibles (i18n)
# =============================================================================
# Mécanique de rendu sur des catalogues de test, puis complétude des vrais
# catalogues : chaque msg("code", …) du code source existe en français et en
# anglais, avec exactement les paramètres passés.
# =============================================================================

import ast
import json
import string
from collections import namedtuple

import pytest

from domainrecon.core import paths
from domainrecon.i18n import (
    DEFAULT_LANG,
    FRAGMENTS_DIR,
    SUPPORTED_LANGS,
    catalog,
    catalog_fragments,
    dumps_message,
    is_msg,
    loads_message,
    msg,
    negotiate_lang,
    placeholders,
    render,
    unique,
)
from domainrecon.i18n.fix import is_fix_code

CATALOGUE_FR = {
    "t.simple": "Bonjour",
    "t.param": "Port {port} ouvert",
    "t.imbrique": "Échec : {cause}",
    "t.liste": "Erreurs ({errors})",
    "t.fr_seul": "Seulement en français",
}
CATALOGUE_EN = {
    "t.simple": "Hello",
    "t.param": "Port {port} open",
    "t.imbrique": "Failure: {cause}",
    "t.liste": "Errors ({errors})",
}


@pytest.fixture
def catalogues(tmp_path, monkeypatch):
    """Catalogues de test à la place de domainrecon/i18n/*.json."""
    (tmp_path / "fr.json").write_text(json.dumps(CATALOGUE_FR, ensure_ascii=False), encoding="utf-8")
    (tmp_path / "en.json").write_text(json.dumps(CATALOGUE_EN), encoding="utf-8")
    monkeypatch.setattr(paths, "i18n_dir", lambda: tmp_path)
    catalog.cache_clear()
    yield
    catalog.cache_clear()


def test_constantes():
    assert SUPPORTED_LANGS == ("fr", "en")
    assert DEFAULT_LANG == "fr"


def test_msg_et_is_msg():
    message = msg("t.param", port=22)
    assert message == {"$t": "t.param", "p": {"port": 22}}
    assert is_msg(message)
    for valeur in (
        "texte",
        None,
        {"$t": "x"},
        {"$t": "x", "p": {}, "autre": 1},
        {"$t": 1, "p": {}},
        {"$t": "x", "p": []},
    ):
        assert not is_msg(valeur), valeur


def test_rendu_simple_et_parametres(catalogues):
    assert render(msg("t.simple"), "fr") == "Bonjour"
    assert render(msg("t.simple"), "en") == "Hello"
    assert render(msg("t.param", port=22), "en") == "Port 22 open"


def test_rendu_imbrique_et_listes(catalogues):
    cause = msg("t.param", port=443)
    assert render(msg("t.imbrique", cause=cause), "en") == "Failure: Port 443 open"
    erreurs = [msg("t.simple"), "brut"]
    assert render(msg("t.liste", errors=erreurs), "fr") == "Erreurs (Bonjour ; brut)"
    assert render(msg("t.liste", errors=erreurs), "en") == "Errors (Hello; brut)"
    assert render(msg("t.liste", errors=erreurs, sep=", "), "en") == "Errors (Hello, brut)"


def test_replis(catalogues):
    # Gabarit absent en anglais : français ; absent partout : le code.
    assert render(msg("t.fr_seul"), "en") == "Seulement en français"
    assert render(msg("t.inconnu"), "fr") == "t.inconnu"
    # Langue inconnue : français.
    assert render(msg("t.simple"), "de") == "Bonjour"
    # Paramètre manquant : l'accolade reste ; None : texte vide.
    assert render(msg("t.param"), "fr") == "Port {port} ouvert"
    assert render(msg("t.param", port=None), "fr") == "Port  ouvert"


def test_rendu_profond_sans_modifier_l_original(catalogues):
    Paire = namedtuple("Paire", "a b")
    donnees = {
        "error": msg("t.simple"),
        "texte": "ancien texte, rendu tel quel",
        "liste": [msg("t.param", port=80), 3, None],
        "tuple": Paire(msg("t.simple"), "x"),
        "imbrique": {"notes": [msg("t.simple")]},
    }
    rendu = render(donnees, "en")
    assert rendu == {
        "error": "Hello",
        "texte": "ancien texte, rendu tel quel",
        "liste": ["Port 80 open", 3, None],
        "tuple": Paire("Hello", "x"),
        "imbrique": {"notes": ["Hello"]},
    }
    assert isinstance(rendu["tuple"], Paire)
    assert donnees["error"] == msg("t.simple")  # original intact


def test_accolades_des_donnees_non_interpretees(catalogues):
    assert render(msg("t.param", port="{0} {x}"), "fr") == "Port {0} {x} ouvert"
    assert render("{texte brut}", "fr") == "{texte brut}"


@pytest.mark.parametrize(
    ("query", "accept", "attendu"),
    [
        ("en", None, "en"),
        ("EN-us", "fr", "en"),
        ("de", "en", "en"),
        (None, "en-US,en;q=0.9", "en"),
        (None, "de-DE, fr;q=0.8", "fr"),
        (None, "en;q=0, fr", "fr"),
        (None, "de", "fr"),
        (None, "*", "fr"),
        (None, None, "fr"),
        ("", "", "fr"),
    ],
)
def test_negociation_de_la_langue(query, accept, attendu):
    assert negotiate_lang(query, accept) == attendu


def test_unique_garde_l_ordre():
    assert unique([msg("a"), "x", msg("a"), msg("a", p=1), "x"]) == [msg("a"), "x", msg("a", p=1)]


def test_stockage_d_un_message_en_texte():
    message = msg("t.param", port=22)
    texte = dumps_message(message)
    assert isinstance(texte, str) and texte.startswith('{"$t"')
    assert loads_message(texte) == message
    assert dumps_message("ancien texte") == "ancien texte"
    assert dumps_message(None) is None
    assert loads_message("ancien texte") == "ancien texte"
    assert loads_message('{"$t" cassé') == '{"$t" cassé'
    # JSON valide mais pas un message : texte d'origine.
    assert loads_message('{"$t": "x"}') == '{"$t": "x"}'
    assert loads_message(None) is None


def test_placeholders():
    assert placeholders("Port {port} ({service})") == {"port", "service"}
    assert placeholders("aucun") == set()


# --- Complétude des vrais catalogues (domainrecon/i18n/*.json) -------------


def _nom_appele(func) -> str | None:
    if isinstance(func, ast.Name):
        return func.id
    if isinstance(func, ast.Attribute):
        return func.attr
    return None


def _appels_msg():
    """(fichier, nœud) de chaque appel msg(...) du code source du package."""
    for fichier in sorted(paths.package_dir().rglob("*.py")):
        arbre = ast.parse(fichier.read_text(encoding="utf-8"), filename=str(fichier))
        for noeud in ast.walk(arbre):
            if isinstance(noeud, ast.Call) and _nom_appele(noeud.func) == "msg":
                yield fichier, noeud


def test_msg_toujours_appele_avec_un_code_litteral():
    for fichier, appel in _appels_msg():
        premier = appel.args[0] if appel.args else None
        assert isinstance(premier, ast.Constant) and isinstance(premier.value, str), (
            f"{fichier}:{appel.lineno}"
        )


def test_chaque_code_du_source_existe_avec_ses_parametres():
    fr, en = catalog("fr"), catalog("en")
    for fichier, appel in _appels_msg():
        code = appel.args[0].value
        ou = f"{fichier.name}:{appel.lineno} {code}"
        assert code in fr and code in en, ou
        if any(mot.arg is None for mot in appel.keywords):  # **params : non vérifiable
            continue
        passes = {mot.arg for mot in appel.keywords} - {"sep"}
        assert placeholders(fr[code]) == passes, ou
        assert placeholders(en[code]) == passes, ou


def test_catalogues_memes_codes_memes_parametres():
    fr, en = catalog("fr"), catalog("en")
    assert set(fr) == set(en)
    for code, gabarit in fr.items():
        # « Comment corriger » : texte littéral (code, accolades), pas un gabarit.
        if is_fix_code(code):
            continue
        assert placeholders(gabarit) == placeholders(en[code]), code


def _codes_declares() -> set[str]:
    """Codes employés hors des appels msg() : règles de constats (FindingRule.code) et aide des modules."""
    from domainrecon.scanner import registry

    codes: set[str] = set()
    for spec in registry.MODULES.values():
        codes.update(rule.code for rule in spec.findings)
        codes.update(spec.help_codes.values())
    return codes


def _codes_facultatifs() -> set[str]:
    """Codes que chaque module PEUT définir (« Comment corriger ») : absents sans faute, jamais inutilisés."""
    from domainrecon.scanner import registry

    return {code for spec in registry.MODULES.values() for code in spec.fix_codes.values()}


def test_aucun_code_inutilise():
    utilises = {appel.args[0].value for _, appel in _appels_msg()} | _codes_declares() | _codes_facultatifs()
    assert set(catalog("fr")) - utilises == set()


def test_codes_declares_par_les_modules_existent():
    fr, en = catalog("fr"), catalog("en")
    for code in _codes_declares():
        assert code in fr and code in en, code


# --- Fragments des modules (domainrecon/i18n/modules/<clé>.<langue>.json) ----


def _fichiers_fragments():
    dossier = paths.i18n_dir() / FRAGMENTS_DIR
    return sorted(dossier.glob("*.json")) if dossier.is_dir() else []


def test_fragments_nommes_cle_point_langue_et_par_paires():
    from domainrecon.scanner import registry

    noms = {lang: set(catalog_fragments(lang)) for lang in SUPPORTED_LANGS}
    for fichier in _fichiers_fragments():
        cle, _, reste = fichier.name.partition(".")
        assert reste in {f"{lang}.json" for lang in SUPPORTED_LANGS}, fichier.name
        # Un fragment par module enregistré (un module écarté au chargement est signalé par le test de contrat).
        assert cle in registry.MODULES or cle in registry.BROKEN_MODULES, fichier.name
    assert noms["fr"] == noms["en"]


def test_fragments_au_format_des_catalogues():
    """UTF-8 sans BOM, fins de ligne LF, clés triées, indentation de 2, objet plat de textes."""
    for fichier in _fichiers_fragments():
        brut = fichier.read_bytes()
        assert not brut.startswith(b"\xef\xbb\xbf"), fichier.name
        assert b"\r" not in brut, fichier.name
        donnees = json.loads(brut.decode("utf-8"))
        assert isinstance(donnees, dict) and donnees, fichier.name
        assert all(isinstance(v, str) and v.strip() for v in donnees.values()), fichier.name
        attendu = json.dumps(dict(sorted(donnees.items())), ensure_ascii=False, indent=2) + "\n"
        assert brut.decode("utf-8") == attendu, fichier.name


def test_fragments_codes_prefixes_par_leur_module():
    """Un fragment ne définit que les codes de son module : module.<clé>.*, <clé>.* ou finding.<clé>.*."""
    for lang in SUPPORTED_LANGS:
        for cle, fragment in catalog_fragments(lang).items():
            prefixes = (f"module.{cle}.", f"{cle}.", f"finding.{cle}.")
            for code in fragment:
                assert code.startswith(prefixes), f"{cle}.{lang}.json : {code}"


def test_conseils_de_correction_seulement_dans_les_fragments():
    """Le « Comment corriger » d'un module va dans son fragment (préfixe vérifié plus haut), jamais dans fr.json / en.json."""
    for lang in SUPPORTED_LANGS:
        principal = json.loads((paths.i18n_dir() / f"{lang}.json").read_text(encoding="utf-8"))
        assert [code for code in principal if is_fix_code(code)] == [], lang


def test_fragments_sans_collision():
    """Aucun code d'un fragment ne redéfinit un code du catalogue principal ni d'un autre fragment."""
    for lang in SUPPORTED_LANGS:
        principal = json.loads((paths.i18n_dir() / f"{lang}.json").read_text(encoding="utf-8"))
        vus: dict[str, str] = {}
        for cle, fragment in catalog_fragments(lang).items():
            for code in fragment:
                assert code not in principal, f"{cle}.{lang}.json : {code} déjà dans {lang}.json"
                assert code not in vus, f"{code} : {cle} et {vus.get(code)}"
                vus[code] = cle


def test_fragments_fusionnes_au_catalogue(tmp_path, monkeypatch):
    (tmp_path / "fr.json").write_text(json.dumps({"a.b": "principal"}), encoding="utf-8")
    (tmp_path / "en.json").write_text(json.dumps({"a.b": "main"}), encoding="utf-8")
    (tmp_path / "modules").mkdir()
    (tmp_path / "modules" / "demo.fr.json").write_text(
        json.dumps({"module.demo.title": "Démo", "a.b": "ignoré"}), encoding="utf-8"
    )
    (tmp_path / "modules" / "demo.en.json").write_text(
        json.dumps({"module.demo.title": "Demo"}), encoding="utf-8"
    )
    (tmp_path / "modules" / "casse.fr.json").write_text("{pas du JSON", encoding="utf-8")
    monkeypatch.setattr(paths, "i18n_dir", lambda: tmp_path)
    catalog.cache_clear()
    try:
        assert catalog("fr") == {"a.b": "principal", "module.demo.title": "Démo"}
        assert catalog("en") == {"a.b": "main", "module.demo.title": "Demo"}
        assert render(msg("module.demo.title"), "en") == "Demo"
    finally:
        catalog.cache_clear()


def test_gabarits_sans_format_ni_conversion():
    for lang in SUPPORTED_LANGS:
        for code, gabarit in catalog(lang).items():
            # Texte littéral : un extrait nginx ou JSON est plein d'accolades et de « : ».
            if is_fix_code(code):
                continue
            for _, nom, spec, conversion in string.Formatter().parse(gabarit):
                if nom is not None:
                    assert not spec and conversion is None, f"{lang} {code}"
