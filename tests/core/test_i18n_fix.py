# =============================================================================
# DomainRecon - Tests du « Comment corriger » des modules (i18n/fix.py)
# =============================================================================
# Convention des trois textes facultatifs d'un module (fix, fix_snippet, fix_ref) :
# codes, chargement littéral depuis les fragments, découpage des étapes et des
# variantes d'extrait, contrôles de forme que le test de contrat applique aux textes
# écrits. GET /api/modules : tests/api/test_modules_api.py ; textes réels :
# tests/scanner/modules/test_contrat_modules.py.
# =============================================================================

import json

import pytest

from domainrecon.core import paths
from domainrecon.i18n import catalog, catalog_fragments, message, render
from domainrecon.i18n.fix import (
    FIX_PARTS,
    MAX_LABEL_LENGTH,
    MAX_REF_LENGTH,
    MAX_SNIPPET_LENGTH,
    MAX_STEP_LENGTH,
    MAX_STEPS,
    MAX_VARIANTS,
    fix_codes,
    fix_pair_problems,
    fix_problems,
    fix_steps,
    fix_texts,
    is_fix_code,
    is_https_url,
    snippet_variants,
)
from domainrecon.scanner import registry

BON = {
    "fix": (
        "Ajoutez l'en-tête `X-Frame-Options: DENY` à toutes les réponses HTTPS.\n"
        "Rechargez la configuration du serveur.\n"
        "Relancez le scan pour vérifier."
    ),
    "fix_snippet": (
        '# nginx\nadd_header X-Frame-Options "DENY" always;\n\n# Apache\nHeader always set X-Frame-Options "DENY"'
    ),
    "fix_ref": "https://developer.mozilla.org/fr/docs/Web/HTTP/Headers/X-Frame-Options",
}


@pytest.fixture
def fragments(tmp_path, monkeypatch):
    """Catalogues de test : fournit une fonction qui écrit les fragments FR et EN du module « demo »."""
    (tmp_path / "fr.json").write_text("{}", encoding="utf-8")
    (tmp_path / "en.json").write_text("{}", encoding="utf-8")
    (tmp_path / "modules").mkdir()
    monkeypatch.setattr(paths, "i18n_dir", lambda: tmp_path)

    def ecrire(fr: dict, en: dict) -> None:
        for lang, textes in (("fr", fr), ("en", en)):
            donnees = {f"module.demo.{part}": texte for part, texte in textes.items()}
            (tmp_path / "modules" / f"demo.{lang}.json").write_text(
                json.dumps(donnees, ensure_ascii=False), encoding="utf-8"
            )
        catalog.cache_clear()

    catalog.cache_clear()
    yield ecrire
    catalog.cache_clear()


# --- Codes -------------------------------------------------------------------


def test_parties_et_codes():
    assert FIX_PARTS == ("fix", "fix_snippet", "fix_ref")
    assert fix_codes("hibp") == {
        "fix": "module.hibp.fix",
        "fix_snippet": "module.hibp.fix_snippet",
        "fix_ref": "module.hibp.fix_ref",
    }


def test_codes_du_module_et_de_l_aide_distincts():
    spec = registry.MODULES["hibp"]
    assert spec.fix_codes == fix_codes("hibp")
    # L'aide obligatoire reste inchangée : le « Comment corriger » est une partie à côté, facultative.
    assert set(spec.help_codes) == {"title", "checks", "why"}
    assert not set(spec.help_codes.values()) & set(spec.fix_codes.values())


@pytest.mark.parametrize(
    ("code", "attendu"),
    [
        ("module.hibp.fix", True),
        ("module.hibp.fix_snippet", True),
        ("module.github_leaks.fix_ref", True),
        ("module.hibp.title", False),
        ("module.hibp.fix_titre", False),
        ("module.hibp.fix.x", False),
        ("module.Hibp.fix", False),
        ("finding.hibp.fix", False),
        ("hibp.fix", False),
        ("fix", False),
    ],
)
def test_is_fix_code(code, attendu):
    assert is_fix_code(code) is attendu


def test_fix_codes_de_tous_les_modules_sont_reconnus():
    for spec in registry.MODULES.values():
        assert all(is_fix_code(code) for code in spec.fix_codes.values()), spec.name


# --- Chargement : textes littéraux ---------------------------------------------


def test_textes_rendus_tels_quels_dans_l_ordre_des_parties(fragments):
    fragments({"fix_ref": BON["fix_ref"], "fix": BON["fix"], "fix_snippet": BON["fix_snippet"]}, BON)

    textes = fix_texts("demo", "fr")

    assert list(textes) == list(FIX_PARTS)
    assert textes == BON
    assert fix_texts("demo", "en") == BON


def test_parties_absentes_ou_vides_omises(fragments):
    fragments({"fix": "Faire ceci", "fix_snippet": "   ", "fix_ref": ""}, {"fix": "Do this"})

    assert fix_texts("demo", "fr") == {"fix": "Faire ceci"}
    assert fix_texts("demo", "en") == {"fix": "Do this"}


def test_module_sans_conseil_ou_inconnu(fragments):
    fragments({}, {})
    assert fix_texts("demo", "fr") == {}
    assert fix_texts("inconnu", "fr") == {}


def test_accolades_et_deux_points_gardes_tels_quels(fragments):
    """Un extrait nginx, JSON ou Helm n'est pas un gabarit str.format : aucune accolade n'est interprétée."""
    extrait = (
        "# nginx\nserver {\n  add_header Content-Security-Policy \"default-src 'self'; img-src https:\" always;\n}\n\n"
        '# JSON\n{"Version": "2012-10-17"}\n\n# Helm\n{{ .Values.x }} et ${HOME:-/root} et }'
    )
    etapes = "Dans le bloc `server { }`, ajoutez la directive {nom}.\nEnregistrez ; rechargez."
    fragments({"fix": etapes, "fix_snippet": extrait}, {"fix": etapes, "fix_snippet": extrait})

    assert fix_texts("demo", "fr") == {"fix": etapes, "fix_snippet": extrait}
    assert fix_texts("demo", "en") == {"fix": etapes, "fix_snippet": extrait}


def test_render_formaterait_les_accolades_d_ou_le_chargeur_dedie(fragments):
    """render() applique str.format : « {{ » deviendrait « { » et « {nom} » resterait un paramètre."""
    extrait = "{{ .Values.x }}"
    fragments({"fix_snippet": extrait}, {"fix_snippet": extrait})

    assert render(message("module.demo.fix_snippet"), "fr") == "{ .Values.x }"
    assert fix_texts("demo", "fr")["fix_snippet"] == extrait


def test_repli_sur_le_francais_par_partie(fragments):
    fragments(
        {"fix": "Faire ceci", "fix_snippet": "code", "fix_ref": "https://example.com/fr"}, {"fix": "Do this"}
    )

    assert fix_texts("demo", "en") == {
        "fix": "Do this",
        "fix_snippet": "code",
        "fix_ref": "https://example.com/fr",
    }
    # Sans repli : la langue seule (contrôle d'un fragment).
    assert fix_texts("demo", "en", fallback=False) == {"fix": "Do this"}
    assert fix_texts("demo", "fr", fallback=False) == fix_texts("demo", "fr")


def test_langue_inconnue_en_francais(fragments):
    fragments({"fix": "Faire ceci"}, {"fix": "Do this"})
    assert fix_texts("demo", "de") == {"fix": "Faire ceci"}


def test_pas_de_texte_en_francais_ni_ailleurs(fragments):
    fragments({}, {"fix": "Do this"})
    assert fix_texts("demo", "fr") == {}
    assert fix_texts("demo", "en") == {"fix": "Do this"}


def test_fragment_illisible_donne_aucun_conseil(fragments, tmp_path):
    fragments({}, {})
    (tmp_path / "modules" / "demo.fr.json").write_text("{pas du JSON", encoding="utf-8")
    catalog.cache_clear()
    assert fix_texts("demo", "fr") == {}


def test_conseils_ajoutes_au_fragment_d_un_module_existant(fragments, tmp_path):
    """Les clés s'ajoutent au fragment du module (aide comprise), sans toucher au catalogue principal."""
    (tmp_path / "fr.json").write_text(json.dumps({"autre.code": "x"}), encoding="utf-8")
    fragments({}, {})
    (tmp_path / "modules" / "demo.fr.json").write_text(
        json.dumps({"module.demo.title": "Démo", "module.demo.fix": "Faire ceci"}), encoding="utf-8"
    )
    catalog.cache_clear()

    assert fix_texts("demo", "fr") == {"fix": "Faire ceci"}
    assert catalog("fr")["module.demo.title"] == "Démo"
    assert catalog_fragments("fr")["demo"]["module.demo.fix"] == "Faire ceci"


# --- Découpage ---------------------------------------------------------------


def test_fix_steps():
    assert fix_steps("a\nb\nc") == ["a", "b", "c"]
    assert fix_steps("  a  \n\n b \n") == ["a", "b"]
    assert fix_steps("une seule étape") == ["une seule étape"]
    assert fix_steps("") == []


@pytest.mark.parametrize(
    ("extrait", "attendu"),
    [
        ("# nginx\na;\n\n# Apache\nb", [("nginx", "a;"), ("Apache", "b")]),
        ("a\nb", [(None, "a\nb")]),
        ("# nginx\nl1\n\nl3\n", [("nginx", "l1\n\nl3")]),
        ("#!/bin/sh\necho ok", [(None, "#!/bin/sh\necho ok")]),
        ("  # indenté : du code\nx", [(None, "  # indenté : du code\nx")]),
        ("code\n# Apache\nb", [(None, "code"), ("Apache", "b")]),
        ("# nginx\n# Apache\nb", [("nginx", ""), ("Apache", "b")]),
        ("#   IIS  \nx", [("IIS", "x")]),
        ("# \nx", [("", "x")]),
    ],
)
def test_snippet_variants(extrait, attendu):
    assert snippet_variants(extrait) == attendu


# --- URL de documentation ------------------------------------------------------------


@pytest.mark.parametrize(
    "url",
    [
        "https://developer.mozilla.org/fr/docs/Web/HTTP/CSP",
        "https://www.rfc-editor.org/rfc/rfc6797",
        "https://cyber.gouv.fr/x?y=1&z=2#ancre",
        "https://example.com:8443/doc",
        "https://example.com",
    ],
)
def test_url_https_valide(url):
    assert is_https_url(url)


@pytest.mark.parametrize(
    "url",
    [
        "http://example.com/doc",
        "HTTPS://example.com/doc",
        "javascript:alert(1)",
        "ftp://example.com/x",
        "//example.com/x",
        "https://",
        "https:///chemin",
        "https://localhost/doc",
        "https://user:mdp@example.com/",
        "https://example.com/a b",
        "https://example.com/é",
        "https://example.com/<x>",
        'https://example.com/"x"',
        "https://example.com/`x`",
        "https://exa mple.com",
        " https://example.com",
        "https://example.com\n",
        "https://example.com:99999/",
        "https://example.com:abc/",
        "https://[::1/",
        "https://" + "a" * MAX_REF_LENGTH + ".com",
        "",
        None,
        3,
    ],
)
def test_url_refusee(url):
    assert not is_https_url(url)


# --- Contrôle de forme d'une langue ---------------------------------------------------


def _cherche(problemes: list[str], morceau: str) -> bool:
    return any(morceau in probleme for probleme in problemes)


def test_conseil_complet_conforme():
    assert fix_problems(BON) == []


@pytest.mark.parametrize(
    "texte",
    [
        {"fix": "Faire ceci"},
        {"fix": "Faire ceci", "fix_ref": "https://example.com/doc"},
        {"fix": "Faire ceci", "fix_snippet": "add_header X-Frame-Options 'DENY';"},
        {"fix": "Étape un\nÉtape deux"},
        {"fix": "301 vers HTTPS\n2FA obligatoire\n1.1.1.1 est un résolveur"},
        {"fix": "Dans le bloc `server { }`, ajoutez `${HOME:-/x}` : {nom}"},
        {"fix": "Faire ceci", "fix_snippet": "#!/bin/sh\necho ok"},
        {
            "fix": "Faire ceci",
            "fix_snippet": 'server {\n  add_header A "b: c" always;\n\n  listen 443;\n}',
        },
        {"fix": "Faire ceci", "fix_snippet": '# DNS\nexample.com. IN TXT "v=spf1 -all"'},
        {"fix": "\n".join(f"Faire {i}" for i in range(MAX_STEPS))},
        {"fix": "x" * MAX_STEP_LENGTH},
        {"fix": "Faire ceci", "fix_snippet": "x" * MAX_SNIPPET_LENGTH},
        {"fix": "Faire ceci", "fix_snippet": "\n".join(f"# v{i}\ncode" for i in range(MAX_VARIANTS))},
        {"fix": "Faire ceci", "fix_snippet": "# " + "x" * MAX_LABEL_LENGTH + "\ncode"},
        {"fix": "Espace insécable avant ; la ponctuation : autorisé en prose"},
    ],
)
def test_textes_conformes(texte):
    assert fix_problems(texte) == []


@pytest.mark.parametrize(
    ("texte", "morceau"),
    [
        ({"fix": ""}, "texte vide"),
        ({"fix": "   "}, "texte vide"),
        ({"fix": 3}, "texte attendu"),
        ({"fix": "Faire ceci\n\nPuis cela"}, "ligne 2 vide"),
        ({"fix": "\nFaire ceci"}, "début ou en fin de texte"),
        ({"fix": "Faire ceci\n"}, "début ou en fin de texte"),
        ({"fix": "Faire ceci\n Puis cela"}, "ligne 2 : espaces"),
        ({"fix": "1. Faire ceci"}, "ni numéro ni puce"),
        ({"fix": "12) Faire ceci"}, "ni numéro ni puce"),
        ({"fix": "- Faire ceci"}, "ni numéro ni puce"),
        ({"fix": "* Faire ceci"}, "ni numéro ni puce"),
        ({"fix": "• Faire ceci"}, "ni numéro ni puce"),
        ({"fix": "Faire ceci\n– Puis cela"}, "ligne 2 : ni numéro"),
        ({"fix": "Étape 1 : faire ceci"}, "ni numéro ni puce"),
        ({"fix": "Etape 2. Faire ceci"}, "ni numéro ni puce"),
        ({"fix": "Step 3: do this"}, "ni numéro ni puce"),
        ({"fix": "\n".join(["Faire"] * (MAX_STEPS + 1))}, f"{MAX_STEPS + 1} étapes"),
        ({"fix": "x" * (MAX_STEP_LENGTH + 1)}, f"ligne 1 : {MAX_STEP_LENGTH + 1} caractères"),
        ({"fix": "Ajoutez `X-Frame-Options"}, "accents graves"),
        ({"fix": "Ajoutez ```bloc```"}, "pas de bloc de code"),
        ({"fix": "Faire\r\nPuis"}, "retour chariot"),
        ({"fix": "Faire\tceci"}, "tabulation"),
        ({"fix": "Faire​ceci"}, "U+200B"),
        ({"fix": "Faire‮ceci"}, "U+202E"),
        ({"fix": "Faire\x00ceci"}, "U+0000"),
        ({"fix_snippet": "add_header A b;"}, "sans fix"),
        ({"fix_ref": "https://example.com/doc"}, "sans fix"),
        ({"fix": "Faire", "fix_title": "x"}, "fix_title : partie inconnue"),
        ({"fix": "Faire", "fix_ref": "http://example.com/doc"}, "fix_ref : URL https"),
        ({"fix": "Faire", "fix_ref": "javascript:alert(1)"}, "fix_ref : URL https"),
        ({"fix": "Faire", "fix_ref": "https://example.com/doc "}, "fix_ref"),
        ({"fix": "Faire", "fix_ref": ""}, "fix_ref : texte vide"),
        ({"fix": "Faire", "fix_snippet": ""}, "fix_snippet : texte vide"),
        ({"fix": "Faire", "fix_snippet": "“DENY”"}, "ASCII seulement"),
        ({"fix": "Faire", "fix_snippet": "add_header A b;"}, "U+00A0"),
        ({"fix": "Faire", "fix_snippet": "server {\n\tlisten 443;\n}"}, "tabulation"),
        ({"fix": "Faire", "fix_snippet": "a\r\nb"}, "retour chariot"),
        ({"fix": "Faire", "fix_snippet": "\n# nginx\na"}, "début ou en fin de texte"),
        ({"fix": "Faire", "fix_snippet": "x" * (MAX_SNIPPET_LENGTH + 1)}, "caractères (maximum"),
        (
            {"fix": "Faire", "fix_snippet": "\n".join(f"# v{i}\ncode" for i in range(MAX_VARIANTS + 1))},
            f"{MAX_VARIANTS + 1} variantes",
        ),
        ({"fix": "Faire", "fix_snippet": "# nginx\n# Apache\nHeader x"}, "variante « nginx » sans code"),
        ({"fix": "Faire", "fix_snippet": "# nginx"}, "variante « nginx » sans code"),
        ({"fix": "Faire", "fix_snippet": "code\n# Apache\nHeader x"}, "du code précède le premier en-tête"),
        ({"fix": "Faire", "fix_snippet": "# nginx\na\n# NGINX\nb"}, "en double"),
        ({"fix": "Faire", "fix_snippet": "# \na"}, "sans libellé"),
        ({"fix": "Faire", "fix_snippet": "# # nginx\na"}, "ne commence pas par"),
        ({"fix": "Faire", "fix_snippet": "# " + "x" * (MAX_LABEL_LENGTH + 1) + "\na"}, "de plus de"),
    ],
)
def test_textes_non_conformes(texte, morceau):
    problemes = fix_problems(texte)
    assert _cherche(problemes, morceau), problemes


# --- Concordance entre le français et l'anglais ------------------------------------------


def test_langues_concordantes():
    assert fix_pair_problems(BON, dict(BON)) == []
    assert fix_pair_problems({}, {}) == []
    # Le code d'un extrait et l'URL peuvent différer d'une langue à l'autre ; les étapes, non.
    en = {**BON, "fix_ref": "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options"}
    assert fix_pair_problems(BON, en) == []


@pytest.mark.parametrize("partie", FIX_PARTS)
def test_partie_presente_d_un_seul_cote(partie):
    seul = {key: value for key, value in BON.items() if key != partie}
    assert _cherche(fix_pair_problems(BON, seul), f"{partie} présent en fr mais absent en en")
    assert _cherche(fix_pair_problems(seul, BON), f"{partie} présent en en mais absent en fr")


def test_nombre_d_etapes_different():
    en = {**BON, "fix": "Add the header.\nReload the server."}
    problemes = fix_pair_problems(BON, en)
    assert _cherche(problemes, "3 étape(s) en fr, 2 en en")


def test_libelles_de_variantes_differents():
    en = {**BON, "fix_snippet": '# nginx\nadd_header X-Frame-Options "DENY" always;'}
    assert _cherche(fix_pair_problems(BON, en), "variantes ['nginx', 'Apache'] en fr, ['nginx'] en en")
    en = {**BON, "fix_snippet": BON["fix_snippet"].replace("# Apache", "# Apache2")}
    assert _cherche(fix_pair_problems(BON, en), "mêmes libellés")
    # Un extrait sans variante nommée des deux côtés : rien à comparer.
    sans = {"fix": "Faire", "fix_snippet": "code"}
    assert fix_pair_problems(sans, {"fix": "Do", "fix_snippet": "code"}) == []
