# =============================================================================
# DomainRecon - Tests du module « github_dork » (sans réseau : réponses simulées conformes à
# https://docs.github.com/en/rest/search/search#search-code)
# =============================================================================

import time

import httpx
import pytest

from domainrecon.i18n import render
from domainrecon.scanner.errors import ModuleError
from domainrecon.scanner.impl import github_dork as impl
from domainrecon.scanner.modules.github_dork import SPEC
from domainrecon.scanner.rules import FindingInput

RECHERCHE = "https://api.github.com/search/code"
JETON = "ghp_JetonDeTestSecret0123456789abcdefghijkl"


@pytest.fixture(autouse=True)
def sans_attente(monkeypatch):
    """Cadence nulle et attentes simulées : les tests ne dorment pas."""
    monkeypatch.setattr(impl, "SEARCH_INTERVAL", 0)
    monkeypatch.setattr(impl, "_next_slot", 0.0)
    attentes: list[float] = []

    async def faux_sommeil(duree, *args):
        attentes.append(duree)

    monkeypatch.setattr(impl.asyncio, "sleep", faux_sommeil)
    return attentes


def element(chemin, *, depot="acme/site", fragment="host = db.example.com", prive=False):
    nom = chemin.rsplit("/", 1)[-1]
    return {
        "name": nom,
        "path": chemin,
        "html_url": f"https://github.com/{depot}/blob/main/{chemin}",
        "repository": {"full_name": depot, "html_url": f"https://github.com/{depot}", "private": prive},
        "text_matches": [{"property": "content", "fragment": fragment}] if fragment is not None else [],
    }


def _routes(elements=None, *, par_requete=None):
    def repondre(requete):
        q = requete.url.params["q"]
        if par_requete and q in par_requete:
            return httpx.Response(200, json={"total_count": 1, "items": par_requete[q]})
        return httpx.Response(200, json={"total_count": len(elements or []), "items": elements or []})

    return {RECHERCHE: repondre}


def _constats(data):
    entree = FindingInput({}, "github_dork", lambda scan, module: data, lambda scan, module: True)
    return {rule.code: rule.check(entree) for rule in SPEC.findings}


def _score(data):
    return SPEC.score_rules[0].evaluate({"github_dork": data})


def test_declaration():
    assert SPEC.category == "sensible" and SPEC.family == "leaks"
    assert [(k.name, k.service, k.required) for k in SPEC.keys] == [("github_token", "github", True)]


def test_succes_secret_masque(http_simule, contexte, outils):
    secret = "Sup3rS3cretValue99"
    env = element(".env", fragment=f"HOST=db.example.com\nDB_PASSWORD={secret}\n")
    readme = element("docs/README.md", fragment="voir https://example.com/aide")
    requetes = http_simule(
        _routes(par_requete={'"example.com"': [readme], '"example.com" filename:.env': [env]})
    )
    resultat = outils.executer(SPEC, contexte(secrets={"github_token": JETON}))
    outils.verifier_sortie(resultat, [JETON])
    assert resultat["total_count"] == 2 and resultat["critical_count"] == 1
    assert resultat["queries_run"] == resultat["queries_total"] == 12 and resultat["complete"] is True
    premier = resultat["results"][0]
    assert premier["severity"] == "critical" and premier["file"] == ".env"
    assert premier["secrets"] == [{"type": "password_assignment", "masked": "DB_PASSWORD=****"}]
    assert secret not in str(resultat) and secret not in premier["snippet"]
    assert resultat["results"][1]["severity"] == "low"
    assert requetes[0].headers["authorization"] == f"Bearer {JETON}"
    assert "text-match" in requetes[0].headers["accept"]


def test_contenu_brut_sans_jeton_et_secret_masque(http_simule, contexte, outils):
    cle_aws = "AKIAABCDEFGHIJKLMNOP"
    fichier = element("deploy/config.json", fragment='{"url": "https://api.example.com"}')
    routes = _routes(par_requete={'"example.com" filename:config.json': [fichier]})
    routes["https://raw.githubusercontent.com/acme/site/main/deploy/config.json"] = (
        200,
        {},
        f'{{"url": "https://api.example.com", "aws": "{cle_aws}"}}',
    )
    requetes = http_simule(routes)
    resultat = outils.executer(SPEC, contexte(secrets={"github_token": JETON}))
    entree = resultat["results"][0]
    assert entree["severity"] == "critical" and entree["secrets"] == [
        {"type": "aws_access_key", "masked": "AKIA****"}
    ]
    assert cle_aws not in str(resultat)
    brut = [r for r in requetes if r.url.host == "raw.githubusercontent.com"]
    assert len(brut) == 1 and "authorization" not in brut[0].headers  # le jeton ne quitte pas api.github.com


def test_depot_prive_non_lu_en_brut(http_simule, contexte, outils):
    prive = element(".env", depot="acme/interne", prive=True)
    requetes = http_simule(_routes(par_requete={'"example.com" filename:.env': [prive]}))
    resultat = outils.executer(SPEC, contexte(secrets={"github_token": JETON}))
    assert resultat["results"][0]["private"] is True and resultat["results"][0]["severity"] == "high"
    assert not [r for r in requetes if r.url.host == "raw.githubusercontent.com"]


def test_faux_positifs_ecartes(http_simule, contexte, outils):
    autre_domaine = element("notes.txt", fragment="contact : bob@notexample.com et example.community")
    exemple = element(".env.sample", fragment="DB_PASSWORD=changeme # example.com")
    modele = element("config.yml", fragment="password: ${DB_PASSWORD}  # api.example.com")
    http_simule(_routes([autre_domaine, exemple, modele]))
    resultat = outils.executer(SPEC, contexte(secrets={"github_token": JETON}))
    fichiers = {r["file"]: r for r in resultat["results"]}
    assert "notes.txt" not in fichiers  # le domaine n'est qu'une partie d'un autre nom
    # Valeurs d'exemple : aucun secret, donc aucune gravité « critique ».
    assert fichiers[".env.sample"]["secrets"] == [] and fichiers["config.yml"]["secrets"] == []
    assert resultat["critical_count"] == 0


def test_limite_atteinte_garde_les_resultats_partiels(http_simule, contexte, outils):
    appels = []

    def repondre(requete):
        appels.append(requete.url.params["q"])
        if len(appels) <= 2:
            return httpx.Response(200, json={"items": [element(f"f{len(appels)}.txt")]})
        reset = str(int(time.time()) + 3600)
        return httpx.Response(
            403, headers={"x-ratelimit-remaining": "0", "x-ratelimit-reset": reset}, json={}
        )

    http_simule({RECHERCHE: repondre})
    resultat = outils.executer(SPEC, contexte(secrets={"github_token": JETON}))
    assert resultat["rate_limited"] is True and resultat["complete"] is False
    assert resultat["total_count"] == 2 and resultat["queries_run"] == 2
    assert len(appels) == 3  # 2 réussies, puis la limite : arrêt sans attente de 3600 s ni 12 appels


def test_limite_courte_reprise_apres_attente(http_simule, contexte, outils, sans_attente):
    appels = []

    def repondre(requete):
        appels.append(1)
        if len(appels) == 1:
            return httpx.Response(429, headers={"retry-after": "3"}, json={})
        return httpx.Response(200, json={"items": []})

    http_simule({RECHERCHE: repondre})
    resultat = outils.executer(SPEC, contexte(secrets={"github_token": JETON}))
    assert resultat["rate_limited"] is False and resultat["complete"] is True
    assert 4 in sans_attente  # Retry-After + 1 s de marge


def test_limite_des_la_premiere_requete(http_simule, contexte, outils):
    http_simule({RECHERCHE: (429, {"retry-after": "3600"}, "")})
    with pytest.raises(ModuleError) as erreur:
        outils.executer(SPEC, contexte(secrets={"github_token": JETON}))
    assert "Quota" in render(erreur.value.message, "fr")


@pytest.mark.parametrize(
    ("route", "attendu"),
    [
        ((401, {}, '{"message": "Bad credentials"}'), "Jeton GitHub refusé"),
        ((422, {}, "{}"), "aucune recherche"),
        ((502, {}, ""), "aucune recherche"),
        ((200, {}, "<html>"), "aucune recherche"),
        (httpx.ReadTimeout("lent"), "délai"),
        (httpx.ConnectError("refusé"), "ConnectError"),
    ],
)
def test_echecs(http_simule, contexte, outils, route, attendu):
    http_simule({RECHERCHE: route})
    with pytest.raises(ModuleError) as erreur:
        outils.executer(SPEC, contexte(secrets={"github_token": JETON}))
    texte = render(erreur.value.message, "fr")
    assert attendu in texte and JETON not in texte


def test_jeton_absent(contexte, outils):
    with pytest.raises(ModuleError) as erreur:
        outils.executer(SPEC, contexte())
    assert "non renseigné" in render(erreur.value.message, "fr")


def test_rien_trouve(http_simule, contexte, outils):
    http_simule(_routes([]))
    resultat = outils.executer(SPEC, contexte(secrets={"github_token": JETON}))
    outils.verifier_sortie(resultat, [JETON])
    assert resultat["total_count"] == 0 and resultat["results"] == []
    assert _score(resultat).points == 5
    assert _constats(resultat) == {
        "finding.github_dork.secrets": None,
        "finding.github_dork.sensitive_files": None,
        "finding.github_dork.mentions": None,
    }


def test_plateforme_mutualisee_cherche_l_hote(http_simule, contexte, outils):
    requetes = http_simule(_routes([]))
    outils.executer(
        SPEC, contexte(domain="monsite.github.io", apex="github.io", secrets={"github_token": JETON})
    )
    assert requetes[0].url.params["q"] == '"monsite.github.io"'


def test_classification_par_nom_de_fichier():
    assert impl.classify(".env", ".env") == "high"
    assert impl.classify(".env.production", "a/.env.production") == "high"
    assert impl.classify("id_rsa", "ssh/id_rsa") == "high"
    assert impl.classify("wp-config.php", "wp-config.php") == "high"
    assert impl.classify("dump.sql", "backup/dump.sql") == "medium"
    assert impl.classify("README.md", "README.md") == "low"
    assert impl.classify("keyboard.js", "src/keyboard.js") == "low"


def test_url_du_contenu_brut():
    assert (
        impl.raw_url("https://github.com/acme/site/blob/main/a/b.env")
        == "https://raw.githubusercontent.com/acme/site/main/a/b.env"
    )
    assert impl.raw_url("https://evil.example/acme/site/blob/main/x") is None
    assert impl.raw_url("") is None


def test_constats_et_score():
    donnees = {"total_count": 5, "high_count": 2, "critical_count": 1, "secrets_count": 3}
    constats = _constats(donnees)
    assert constats["finding.github_dork.secrets"] == {"files": 1, "secrets": 3}
    assert constats["finding.github_dork.sensitive_files"] == {"count": 2}
    assert constats["finding.github_dork.mentions"] == {"count": 5}
    assert _score(donnees).points == 0
    assert _score({"total_count": 5, "high_count": 2}).points == 1
    assert _score({"total_count": 5}).points == 3


def test_lecture_defensive():
    for donnees in (None, [], {"total_count": "x", "critical_count": None}):
        assert all(v is None for v in _constats(donnees).values())
        _score(donnees if isinstance(donnees, dict) else {})
