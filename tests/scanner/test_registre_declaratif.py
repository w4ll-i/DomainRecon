# =============================================================================
# DomainRecon - Tests du registre déclaratif : découverte des fichiers de
# modules, clés API, règles de constats et de score, familles dérivées
# =============================================================================
# Registre de démonstration à la place de MODULES : rien ici ne dépend des
# modules réels ni de leur nombre.
# =============================================================================

import asyncio
import sys
import textwrap

import pytest

from domainrecon.i18n import msg
from domainrecon.scanner import families, findings, modules, registry, score
from domainrecon.scanner.keys import ApiKey, KeyTest, Probe
from domainrecon.scanner.registry import ModuleSpec, ScanContext
from domainrecon.scanner.rules import FindingRule, Outcome, PenaltyRule, ScoreRule, hit
from rendu import fr

OK = {"measured": True, "error": None}


async def _run(context):
    return dict(OK)


def spec(name="demo", **fields) -> ModuleSpec:
    fields = {"family": "web", "category": "passif", "run": _run, **fields}
    return ModuleSpec(name=name, **fields)


@pytest.fixture
def registre(monkeypatch):
    """Registre vide (et modules à colonne vides) le temps du test ; renvoie la fonction d'ajout."""
    monkeypatch.setattr(registry, "MODULES", {})
    monkeypatch.setattr(registry, "BROKEN_MODULES", {})
    monkeypatch.setattr(registry, "COLUMN_MODULES", {})

    def add(*specs):
        for item in specs:
            registry.register(item)
        registry.validate_registry()
        return registry.MODULES

    return add


# =============================================================================
# ModuleSpec : déclarations
# =============================================================================


def test_categorie_api_key_ramenee_a_cle_api():
    module = spec(category="api_key", api_key="virustotal_key")

    assert module.category == "cle_api"
    assert module.required_keys == ("virustotal_key",)
    assert module.keys[0].service == "virustotal"


def test_plusieurs_identifiants_et_cle_facultative():
    module = spec(
        category="cle_api",
        keys=(
            ApiKey(name="censys_id", service="censys", label="Censys", free_text=True),
            ApiKey(name="censys_secret", service="censys", label="Censys"),
            ApiKey(name="bonus_key", service="bonus", label="Bonus", required=False),
        ),
    )

    assert module.required_keys == ("censys_id", "censys_secret")
    assert module.optional_keys == ("bonus_key",)
    assert module.key_names == ("censys_id", "censys_secret", "bonus_key")


@pytest.mark.parametrize(
    "fields",
    [
        {"name": "status"},  # champ du résultat d'un scan
        {"name": "modules"},
        {"family": "fuites"},
        {"timeout": registry.MAX_TIMEOUT + 1},
        {"category": "cle_api"},  # sans clé requise
        {"category": "cle_api", "keys": (ApiKey(name="x_key", service="x", label="X", required=False),)},
        {"keys": ApiKey(name="x_key", service="x", label="X")},  # pas un tuple
        {"keys": ("x_key",)},  # pas des ApiKey
        {"keys": (ApiKey(name="x_key", service="x", label="X"),) * 2},
        {"findings": ("finding.x",)},
        {"score_rules": (ScoreRule(criterion="c", weight=5, evaluate=lambda d: None),) * 2},
        {"order": "1"},
        {"optional": "oui"},
        {"placeholder": None},
        {"finalize": "non"},
        {"key_tests": {"svc": "pas un test"}},
        {
            "keys": (ApiKey(name="x_key", service="x", label="X"),),
            "key_tests": {"x": KeyTest("X", ("autre_key",), probes=lambda s: [])},
        },
    ],
    ids=repr,
)
def test_declaration_invalide_refusee(fields):
    with pytest.raises(ValueError):
        spec(**fields)


@pytest.mark.parametrize(
    "kwargs",
    [
        {"name": "Majuscule", "service": "x", "label": "X"},
        {"name": "x", "service": "x", "label": "X"},  # trop court
        {"name": "x_key", "service": "Pas-Valide", "label": "X"},
        {"name": "x_key", "service": "x", "label": " "},
    ],
)
def test_cle_api_invalide_refusee(kwargs):
    with pytest.raises(ValueError):
        ApiKey(**kwargs)


def test_regles_invalides_refusees():
    with pytest.raises(ValueError):
        FindingRule(code="pas un code", severity="high", check=bool)
    with pytest.raises(ValueError):
        FindingRule(code="finding.x", severity="grave", check=bool)
    with pytest.raises(ValueError):
        ScoreRule(criterion="c", weight=0, evaluate=bool)
    with pytest.raises(ValueError):
        ScoreRule(criterion="c", weight=True, evaluate=bool)
    with pytest.raises(ValueError):
        KeyTest("X", ("x_key",))  # ni probes ni run


def test_codes_d_aide():
    assert spec("hibp").help_codes == {
        "title": "module.hibp.title",
        "checks": "module.hibp.checks",
        "why": "module.hibp.why",
    }


def test_module_hachable_et_immuable():
    module = spec(
        key_tests={"x": KeyTest("X", ("x_key",), probes=lambda s: [])},
        keys=(ApiKey(name="x_key", service="x", label="X"),),
    )
    assert hash(module)
    with pytest.raises(TypeError):
        module.key_tests["y"] = None


# =============================================================================
# Registre : cohérence, ordre, profils
# =============================================================================


def test_cle_declaree_autrement_par_deux_modules(registre):
    registry.register(spec("a", keys=(ApiKey(name="x_key", service="x", label="X"),)))
    registry.register(spec("b", keys=(ApiKey(name="x_key", service="x", label="Autre"),)))

    assert set(registry.registry_problems()) == {"b"}


def test_meme_cle_requise_ici_facultative_la(registre):
    registre(
        spec("a", category="cle_api", keys=(ApiKey(name="x_key", service="x", label="X"),)),
        spec("b", keys=(ApiKey(name="x_key", service="x", label="X", required=False),)),
    )
    assert registry.declared_keys()["x_key"].label == "X"


def test_critere_revendique_par_deux_modules(registre):
    rule = ScoreRule(criterion="commun", weight=5, evaluate=lambda d: Outcome(5, "ok", True))
    registry.register(spec("a", score_rules=(rule,)))
    registry.register(spec("b", score_rules=(rule,)))

    with pytest.raises(ValueError, match="critère"):
        registry.validate_registry()


def test_ecarter_les_modules_incoherents_et_leurs_dependants(registre):
    registry.register(spec("orphelin", depends_on=("absent",)))
    registry.register(spec("suiveur", depends_on=("orphelin",)))
    registry.register(spec("sain"))

    removed = registry.prune_registry()

    assert set(removed) == {"orphelin", "suiveur"}
    assert list(registry.MODULES) == ["sain"]


def test_ordre_declare_puis_nom(registre):
    registry.register(spec("zeta"))
    registry.register(spec("alpha"))
    registry.register(spec("premier", order=5))
    registry.sort_registry()

    assert list(registry.MODULES) == ["premier", "alpha", "zeta"]


def test_profil_complet_exige_toutes_les_cles_requises(registre):
    registre(
        spec(
            "censys",
            category="cle_api",
            keys=(
                ApiKey(name="censys_id", service="censys", label="Censys"),
                ApiKey(name="censys_secret", service="censys", label="Censys"),
            ),
        ),
        spec("facultatif", keys=(ApiKey(name="bonus_key", service="bonus", label="Bonus", required=False),)),
    )

    names = lambda keys: [m.name for m in registry.get_modules("complet", keys)]  # noqa: E731
    assert names([]) == ["facultatif"]
    assert names(["censys_id"]) == ["facultatif"]
    assert names(["censys_id", "censys_secret"]) == ["censys", "facultatif"]


# =============================================================================
# Découverte des fichiers de modules
# =============================================================================


@pytest.fixture
def paquet(tmp_path, monkeypatch, registre):
    """Paquet de modules temporaire : écrit des fichiers, les découvre avec modules.discover()."""
    root = tmp_path / "paquet_demo_modules"
    root.mkdir()
    (root / "__init__.py").write_text("", encoding="utf-8")
    monkeypatch.syspath_prepend(str(tmp_path))

    def write(name: str, body: str) -> None:
        (root / f"{name}.py").write_text(textwrap.dedent(body), encoding="utf-8")

    yield write, (lambda: modules.discover([str(root)], "paquet_demo_modules"))
    for name in list(sys.modules):
        if name.startswith("paquet_demo_modules"):
            del sys.modules[name]


_BON = """
from domainrecon.scanner.registry import ModuleSpec

async def run(context):
    return {"measured": True, "error": None}

SPEC = ModuleSpec(name="{name}", family="leaks", category="passif", run=run)
"""


def test_decouverte_automatique_sans_liste(paquet):
    write, discover = paquet
    write("fuite_b", _BON.replace("{name}", "fuite_b"))
    write("fuite_a", _BON.replace("{name}", "fuite_a"))
    write("_aide", "VALEUR = 1\n")  # fichier privé : ignoré

    assert discover() == ["fuite_a", "fuite_b"]
    assert list(registry.MODULES) == ["fuite_a", "fuite_b"]
    assert registry.BROKEN_MODULES == {}
    assert families.family_modules()["leaks"] == ("fuite_a", "fuite_b")


def test_fichier_defectueux_ecarte_sans_bloquer_les_autres(paquet):
    write, discover = paquet
    write("sain", _BON.replace("{name}", "sain"))
    write("casse", "import module_qui_n_existe_pas\n")
    write("sans_spec", "VALEUR = 1\n")
    write("mauvais_nom", _BON.replace("{name}", "autre_nom"))
    write(
        "dependance",
        _BON.replace("{name}", "dependance").replace("run=run)", 'run=run, depends_on=("absent",))'),
    )

    discover()

    assert list(registry.MODULES) == ["sain"]
    assert set(registry.BROKEN_MODULES) == {"casse", "sans_spec", "mauvais_nom", "dependance"}
    assert "ModuleNotFoundError" in registry.BROKEN_MODULES["casse"]


# =============================================================================
# Constats, score et familles dérivés des déclarations
# =============================================================================


def _check_breche(f):
    data = f.data if isinstance(f.data, dict) else {}
    return [{"count": n} for n in data.get("breches", [])]


def _evaluate(data):
    module = data.get("fuites") if isinstance(data.get("fuites"), dict) else {}
    return Outcome(0 if module.get("breches") else 5, "détail", True)


FUITES = spec(
    "fuites",
    family="leaks",
    verdict=True,
    findings=(
        FindingRule(code="finding.dmarc_missing", severity="high", check=_check_breche),
        FindingRule(code="finding.spf_missing", severity="low", check=lambda f: hit(severity="critical")),
    ),
    score_rules=(
        ScoreRule(criterion="fuites", weight=5, evaluate=_evaluate),
        PenaltyRule(evaluate=lambda d: [{"key": "fuite", "label": "x", "points": 7, "severity": "high"}]),
    ),
)


def _scan(data, status="ok"):
    return {
        "module_status": {"fuites": {"status": status, "error": None}},
        "modules_launched": ["fuites"],
        "modules": {"fuites": {"status": status, "data": data, "duration": 0.1, "error": None}},
    }


def test_constats_declares(registre):
    registre(FUITES)

    found = findings.compute_findings(_scan({**OK, "breches": [3]}))

    assert [(f["severity"], f["family"], f["module"]) for f in found] == [
        ("critical", "leaks", "fuites"),
        ("high", "leaks", "fuites"),
    ]
    assert found[1]["message"] == {"$t": "finding.dmarc_missing", "p": {"count": 3}}


def test_constats_ignores_si_module_non_mesure(registre):
    registre(FUITES)
    assert findings.compute_findings(_scan({**OK, "breches": [3]}, status="failed")) == []


def test_regle_qui_leve_est_ignoree(registre, caplog):
    def boom(f):
        raise RuntimeError("bogue")

    registre(spec("fragile", findings=(FindingRule(code="finding.spf_weak", severity="low", check=boom),)))
    scan = {"module_status": {"fragile": {"status": "ok", "error": None}}, "modules": {}}

    assert findings.compute_findings(scan) == []
    assert "en échec" in caplog.text


def test_score_et_penalites_declares(registre):
    registre(FUITES)

    result = score.compute_security_score(
        {
            "fuites": {**OK, "breches": [1]},
            "module_status": {"fuites": {"status": "ok"}},
            "modules_launched": ["fuites"],
        }
    )

    assert list(result["breakdown"]) == ["fuites"]
    assert result["breakdown"]["fuites"]["score"] == 0 and result["breakdown"]["fuites"]["max"] == 5
    assert [p["key"] for p in result["penalties"]] == ["fuite"]
    assert score.CRITERIA_WEIGHTS == {"fuites": 5}
    assert score.CRITERIA_MODULES == {"fuites": "fuites"}
    assert families.family_criteria()["leaks"] == ("fuites",)


def test_critere_d_un_module_a_cle_non_lance_omis(registre):
    rule = ScoreRule(criterion="vt", weight=5, evaluate=lambda d: Outcome(5, "ok", True))
    registre(
        spec("vt", category="cle_api", api_key="virustotal_key", score_rules=(rule,)),
        spec(
            "passif_lent",
            score_rules=(ScoreRule(criterion="lent", weight=5, evaluate=lambda d: Outcome(5, "ok", True)),),
        ),
    )

    result = score.compute_security_score({"module_status": {}, "modules_launched": []})

    # Le module à clé non lancé ne fait pas baisser la couverture ; le passif non lancé, si.
    assert list(result["breakdown"]) == ["lent"]
    assert result["breakdown"]["lent"]["launched"] is False


def test_evaluateur_qui_leve_rend_le_critere_non_mesure(registre):
    def boom(data):
        raise KeyError("x")

    registre(spec("fragile", score_rules=(ScoreRule(criterion="fragile", weight=5, evaluate=boom),)))
    result = score.compute_security_score(
        {"module_status": {"fragile": {"status": "ok"}}, "modules_launched": ["fragile"]}
    )

    assert result["breakdown"]["fragile"]["measured"] is False
    assert fr(result["breakdown"]["fragile"]["detail"]) == fr(msg("score.unmeasured_unreadable"))


def test_famille_fuites_calculee(registre):
    registre(FUITES)
    scan = _scan({**OK, "breches": []})
    scan["security_score"] = score.compute_security_score(
        {
            "fuites": {**OK, "breches": []},
            "module_status": scan["module_status"],
            "modules_launched": ["fuites"],
        }
    )

    family = families.compute_families(scan)["leaks"]

    assert family["grade"] == "A"
    # Le constat « critical » déclaré sans condition fixe l'état.
    assert family["state"] == "critical"


def test_valeur_d_un_module_sans_colonne(registre):
    registre(FUITES)
    assert families.module_value(_scan({"x": 1}), "fuites") == {"x": 1}
    assert families.module_value({}, "fuites") is None


# =============================================================================
# ScanContext
# =============================================================================


def test_contexte_secrets_et_page_par_defaut():
    context = ScanContext(domain="example.com")

    assert dict(context.secrets) == {}
    assert "secrets" not in repr(context) and "shared" not in repr(context)


def test_page_partagee_entre_copies_du_contexte(monkeypatch):
    import dataclasses

    from domainrecon.scanner import page

    calls = []

    async def fake(domain):
        calls.append(domain)
        return page.HomePage(url="https://example.com/", status_code=200)

    monkeypatch.setattr(page, "fetch_homepage", fake)
    context = ScanContext(domain="example.com")
    copy = dataclasses.replace(context, results={})

    async def both():
        return await asyncio.gather(context.homepage(), copy.homepage())

    first, second = asyncio.run(both())
    assert first is second and calls == ["example.com"]
    assert first.reachable and first.https


def test_page_d_accueil_reelle_simulee(monkeypatch):
    """fetch_homepage passe par le client de la cible : en-têtes en minuscules, texte décodé."""
    import httpx

    from domainrecon.scanner import common, page

    def handler(request):
        if request.url.scheme == "https":
            return httpx.Response(
                200, headers={"Content-Type": "text/html; charset=utf-8", "X-Test": "1"}, text="été"
            )
        raise httpx.ConnectError("non", request=request)

    original = common._guarded_client
    monkeypatch.setattr(
        common, "_guarded_client", lambda transport, **kw: original(httpx.MockTransport(handler), **kw)
    )

    async def allowed(host):
        return ["93.184.216.34"]

    monkeypatch.setattr(common, "ensure_target_allowed", allowed)
    home = asyncio.run(page.fetch_homepage("example.com"))

    assert home.status_code == 200 and home.text == "été"
    assert home.headers["x-test"] == "1"
    assert home.url.startswith("https://example.com")


def test_page_d_accueil_injoignable(monkeypatch):
    import httpx

    from domainrecon.scanner import common, page

    def handler(request):
        raise httpx.ConnectError("refus", request=request)

    original = common._guarded_client
    monkeypatch.setattr(
        common, "_guarded_client", lambda transport, **kw: original(httpx.MockTransport(handler), **kw)
    )

    async def allowed(host):
        return ["93.184.216.34"]

    monkeypatch.setattr(common, "ensure_target_allowed", allowed)
    home = asyncio.run(page.fetch_homepage("example.com"))

    assert not home.reachable and home.error is not None and home.text == ""


def test_probe_reexportee_par_le_test_des_cles():
    from domainrecon.api import service_checks

    assert service_checks.Probe is Probe and service_checks.ServiceCheck is KeyTest
