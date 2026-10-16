# =============================================================================
# DomainRecon - Tests du module « csp_grade » (sans réseau)
# =============================================================================

import pytest

from domainrecon.i18n import render
from domainrecon.scanner.errors import ModuleError
from domainrecon.scanner.impl import csp_grade as logic
from domainrecon.scanner.modules.csp_grade import SPEC
from domainrecon.scanner.rules import FindingInput, Hit

URL = "https://example.com/"
STRICTE = "script-src 'nonce-abc123' 'strict-dynamic'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'"


def _entree(data):
    return FindingInput({"csp_grade": data}, "csp_grade", lambda scan, m: scan.get(m), lambda s, m: True)


def _constat(code, data):
    return next(r for r in SPEC.findings if r.code == code).check(_entree(data))


def _note(csp, **options):
    return logic.grade_policies([(p, False) for p in logic.parse_policies(csp)], **options)


def _lancer(http_simule, contexte, outils, en_tetes=None, corps="<html></html>"):
    http_simule({URL: (200, en_tetes or {}, corps)})
    valeur = outils.executer(SPEC, contexte())
    outils.verifier_sortie(valeur)
    return valeur


# --- Notation -----------------------------------------------------------------


def test_politique_stricte_a_nonce_et_strict_dynamic():
    note = _note(STRICTE)
    # Seul défaut : pas de default-src (les autres ressources ne sont pas limitées).
    assert note["grade"] == "A" and note["score"] == 95
    assert [i["code"] for i in note["issues"]] == ["default_src_missing"]


def test_ancien_faux_positif_script_src_etoile_n_est_plus_un_a():
    """L'ancienne notation donnait A à « script-src * » avec object-src 'none'."""
    note = _note("default-src 'self'; script-src *; object-src 'none'")
    assert note["grade"] in ("D", "F") and note["critical"] is True
    assert "script_wildcard" in {i["code"] for i in note["issues"]}


def test_default_src_self_avec_etoile_est_critique():
    assert _note("default-src 'self' *")["grade"] in ("D", "F")


def test_unsafe_inline_annule_par_un_nonce():
    """Avec un nonce, 'unsafe-inline' est ignoré par les navigateurs : pas de défaut."""
    note = _note(
        "script-src 'nonce-x' 'unsafe-inline'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'"
    )
    assert "unsafe_inline" not in {i["code"] for i in note["issues"]}
    assert note["grade"] == "A"


def test_unsafe_inline_seul_plafonne_a_d():
    note = _note("default-src 'self'; script-src 'self' 'unsafe-inline'; object-src 'none'; base-uri 'none'")
    assert note["critical"] is True and note["grade"] in ("D", "F")


def test_unsafe_inline_des_styles_est_un_defaut_mineur():
    """L'ancienne notation cherchait unsafe-inline dans toutes les directives, styles compris."""
    note = _note(
        "default-src 'none'; script-src 'self'; style-src 'self' 'unsafe-inline'; base-uri 'none'; frame-ancestors 'none'; form-action 'none'"
    )
    assert note["grade"] == "A" and [i["code"] for i in note["issues"]] == ["style_unsafe_inline"]


def test_schema_http_et_data_et_hote_de_contournement():
    codes = {
        i["code"] for i in _note("script-src https: data: cdnjs.cloudflare.com; object-src 'none'")["issues"]
    }
    assert {"script_scheme", "script_data", "script_bypass_host"} <= codes


def test_sans_regle_de_script():
    note = _note("img-src 'self'")
    assert "no_script_policy" in {i["code"] for i in note["issues"]} and note["grade"] in ("D", "F")


def test_frame_ancestors_couvert_par_x_frame_options():
    sans = _note("default-src 'none'; base-uri 'none'; form-action 'none'")
    avec = _note("default-src 'none'; base-uri 'none'; form-action 'none'", framed_protected=True)
    assert "frame_ancestors_missing" in {i["code"] for i in sans["issues"]}
    assert avec["score"] > sans["score"]


def test_plusieurs_politiques_la_meilleure_compte():
    note = _note("default-src *, " + STRICTE)
    assert note["grade"] == "A" and note["policies"] == 2


def test_directive_repetee_la_premiere_compte():
    assert logic.parse_policies("script-src 'none'; script-src *")[0]["script-src"] == ["'none'"]


def test_meta_csp_extraite():
    html = '<html><head><meta http-equiv="Content-Security-Policy" content="default-src \'self\'"><meta name="x" content="y"></head></html>'
    assert logic.meta_policies(html) == ["default-src 'self'"]
    assert logic.meta_policies("<<<pas du html") == []


# --- Module --------------------------------------------------------------------


def test_succes_en_tete_stricte(http_simule, contexte, outils):
    valeur = _lancer(http_simule, contexte, outils, {"Content-Security-Policy": STRICTE})
    assert valeur["present"] is True and valeur["grade"] == "A" and valeur["source"] == "header"
    assert SPEC.score_rules[0].evaluate({"csp_grade": valeur}).points == 5
    assert not _constat("finding.csp_grade.weak", valeur)


def test_csp_permissive_constat_et_score(http_simule, contexte, outils):
    valeur = _lancer(
        http_simule, contexte, outils, {"Content-Security-Policy": "default-src * 'unsafe-inline'"}
    )
    assert valeur["grade"] in ("D", "F")
    constat = _constat("finding.csp_grade.weak", valeur)
    assert isinstance(constat, Hit) and constat.severity in ("medium", "high")
    assert render(constat.params["issues"], "fr")
    assert SPEC.score_rules[0].evaluate({"csp_grade": valeur}).points <= 1


def test_csp_absente_sans_objet_pour_le_score(http_simule, contexte, outils):
    valeur = _lancer(http_simule, contexte, outils, {"Server": "x"})
    assert valeur["present"] is False and valeur["grade"] is None
    assert SPEC.score_rules[0].evaluate({"csp_grade": valeur}).applicable is False
    assert not any(_constat(r.code, valeur) for r in SPEC.findings)


def test_report_only_n_est_pas_notee(http_simule, contexte, outils):
    valeur = _lancer(
        http_simule, contexte, outils, {"Content-Security-Policy-Report-Only": "default-src 'none'"}
    )
    assert valeur["present"] is False and valeur["report_only"] is True
    assert _constat("finding.csp_grade.report_only", valeur) is True
    resultat = SPEC.score_rules[0].evaluate({"csp_grade": valeur})
    assert resultat.points == 0 and resultat.applicable


def test_csp_en_balise_meta(http_simule, contexte, outils):
    corps = "<meta http-equiv=\"content-security-policy\" content=\"default-src 'none'; script-src 'self'; base-uri 'none'; form-action 'none'\">"
    valeur = _lancer(http_simule, contexte, outils, corps=corps)
    assert valeur["source"] == "meta" and valeur["grade"] == "A"


def test_x_frame_options_evite_le_defaut_frame_ancestors(http_simule, contexte, outils):
    csp = "default-src 'none'; script-src 'self'; base-uri 'none'; form-action 'none'"
    avec = _lancer(http_simule, contexte, outils, {"Content-Security-Policy": csp, "X-Frame-Options": "DENY"})
    sans = _lancer(http_simule, contexte, outils, {"Content-Security-Policy": csp})
    assert avec["score"] > sans["score"]


def test_cible_injoignable(http_simule, contexte, outils):
    http_simule({})
    with pytest.raises(ModuleError):
        outils.executer(SPEC, contexte())


def test_donnees_inattendues_ne_levent_pas():
    for donnees in (
        None,
        [],
        {"present": True, "grade": "F", "issues": "x"},
        {"present": True, "grade": "D", "issues": [3, None]},
    ):
        for regle in SPEC.findings:
            regle.check(_entree(donnees))
    assert SPEC.score_rules[0].evaluate({"csp_grade": None}).applicable is False
