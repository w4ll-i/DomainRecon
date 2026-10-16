# =============================================================================
# DomainRecon - Tests du module « paste » (sans réseau : flux Sourcegraph, API GitHub et
# Intelligence X simulés conformément à leurs documentations)
# =============================================================================

import json

import httpx
import pytest

from domainrecon.i18n import render
from domainrecon.scanner.errors import ModuleError
from domainrecon.scanner.impl import github_dork
from domainrecon.scanner.impl import intelx as intelx_impl
from domainrecon.scanner.impl import paste as impl
from domainrecon.scanner.modules.paste import SPEC
from domainrecon.scanner.rules import FindingInput

SOURCEGRAPH = "https://sourcegraph.com/.api/search/stream"
GITHUB = "https://api.github.com/search/code"
INTELX = "https://free.intelx.io/intelligent/search"
JETON = "ghp_JetonDeTestSecret0123456789abcdefghijkl"
CLE = "00000000-aaaa-bbbb-cccc-cle-intelx-secrete"


@pytest.fixture(autouse=True)
def sans_attente(monkeypatch):
    monkeypatch.setattr(github_dork, "SEARCH_INTERVAL", 0)
    monkeypatch.setattr(github_dork, "_next_slot", 0.0)
    monkeypatch.setattr(intelx_impl, "POLL_INTERVAL", 0)
    monkeypatch.setattr(intelx_impl, "SEARCH_WAIT", 1)

    async def faux_sommeil(duree, *args):
        return None

    monkeypatch.setattr(github_dork.asyncio, "sleep", faux_sommeil)


def flux(*correspondances):
    """Corps d'un flux d'événements Sourcegraph (SSE)."""
    corps = "event: filters\ndata: []\n\n"
    if correspondances:
        corps += f"event: matches\ndata: {json.dumps(list(correspondances))}\n\n"
    return corps + "event: done\ndata: {}\n\n"


def fichier(chemin, *lignes, depot="github.com/acme/site"):
    return {
        "type": "content",
        "path": chemin,
        "repository": depot,
        "lineMatches": [
            {"line": ligne, "lineNumber": numero, "offsetAndLengths": [[0, 3]]}
            for numero, ligne in enumerate(lignes, 1)
        ],
    }


FUITE = fichier(
    "conf/app.env", "MAIL_HOST=smtp.example.com PASSWORD=Sup3rS3cr3tValue", "autre ligne sans le domaine"
)
SIMPLE = fichier("docs/notes.txt", "serveur: www.example.com")


def _constats(data):
    entree = FindingInput({}, "paste", lambda scan, module: data, lambda scan, module: True)
    return {rule.code: rule.check(entree) for rule in SPEC.findings}


def _score(data):
    return SPEC.score_rules[0].evaluate({"paste": data})


def test_declaration():
    assert SPEC.category == "sensible" and SPEC.family == "leaks"
    assert [(k.name, k.service, k.required) for k in SPEC.keys] == [
        ("github_token", "github", False),
        ("intelx_key", "intelx", False),
    ]
    assert SPEC.required_keys == ()


def test_succes_sans_cle_sourcegraph_seul(http_simule, contexte, outils):
    requetes = http_simule({SOURCEGRAPH: (200, {"content-type": "text/event-stream"}, flux(FUITE, SIMPLE))})
    resultat = outils.executer(SPEC, contexte())
    outils.verifier_sortie(resultat)
    assert resultat["sources"] == {"sourcegraph": "ok", "github": "skipped", "intelx": "skipped"}
    assert resultat["total_found"] == 2 and resultat["high_count"] == 1
    grave = resultat["pastes"][0]
    assert (
        grave["severity"] == "high"
        and grave["url"] == "https://sourcegraph.com/github.com/acme/site/-/blob/conf/app.env"
    )
    assert "Sup3rS3cr3tValue" not in str(resultat) and "****" in grave["snippet"]
    # Sans clé, seul Sourcegraph est interrogé.
    assert {r.url.host for r in requetes} == {"sourcegraph.com"}
    assert (
        "file:\\.(txt|log" in requetes[0].url.params["q"] and '"example.com"' in requetes[0].url.params["q"]
    )


def test_faux_positif_ligne_sans_le_domaine_entier(http_simule, contexte, outils):
    etranger = fichier("a.txt", "contact@notexample.com", "voir example.community")
    http_simule({SOURCEGRAPH: (200, {}, flux(etranger))})
    resultat = outils.executer(SPEC, contexte())
    assert resultat["total_found"] == 0 and resultat["pastes"] == []
    assert _score(resultat).points == 3


def test_rien_trouve(http_simule, contexte, outils):
    http_simule({SOURCEGRAPH: (200, {}, flux())})
    resultat = outils.executer(SPEC, contexte())
    outils.verifier_sortie(resultat)
    assert resultat["total_found"] == 0
    assert _constats(resultat) == {"finding.paste.credentials": None, "finding.paste.mentions": None}


@pytest.mark.parametrize(
    "route",
    [
        (200, {"content-type": "text/html"}, "<html><title>Just a moment...</title></html>"),
        (429, {}, ""),
        (503, {}, ""),
        httpx.ReadTimeout("lent"),
        httpx.ConnectError("refusé"),
    ],
)
def test_aucune_source_disponible(http_simule, contexte, outils, route):
    http_simule({SOURCEGRAPH: route})
    with pytest.raises(ModuleError) as erreur:
        outils.executer(SPEC, contexte())
    assert "Aucune source" in render(erreur.value.message, "fr")


def _toutes_sources(fuite_github):
    return {
        SOURCEGRAPH: (200, {}, flux(FUITE)),
        GITHUB: lambda requete: httpx.Response(200, json={"items": fuite_github}),
        INTELX: {"id": "id-1", "status": 0},
        INTELX + "/result": {
            "records": [
                {
                    "storageid": "p1",
                    "media": 1,
                    "date": "2026-02-03T00:00:00Z",
                    "name": "paste de jean@example.com",
                    "bucket": "pastes",
                }
            ],
            "status": 1,
        },
        INTELX + "/terminate": (200, {}, ""),
    }


def test_fusion_des_trois_sources(http_simule, contexte, outils):
    element = {
        "name": "dump.sql",
        "path": "backup/dump.sql",
        "html_url": "https://github.com/acme/site/blob/main/backup/dump.sql",
        "repository": {"full_name": "acme/site", "html_url": "https://github.com/acme/site"},
        "text_matches": [{"fragment": "INSERT INTO users VALUES ('bob@example.com', 'secretpass')"}],
    }
    requetes = http_simule(_toutes_sources([element]))
    resultat = outils.executer(SPEC, contexte(secrets={"github_token": JETON, "intelx_key": CLE}))
    outils.verifier_sortie(resultat, [JETON, CLE])
    assert resultat["sources"] == {"sourcegraph": "ok", "github": "ok", "intelx": "ok"}
    assert {p["source"] for p in resultat["pastes"]} == {"sourcegraph", "github", "intelx"}
    texte = str(resultat)
    assert "jean@example.com" not in texte and "bob@example.com" not in texte and "secretpass" not in texte
    # Les clés ne partent que vers leur service, en en-tête.
    for requete in requetes:
        if requete.url.host == "api.github.com":
            assert requete.headers["authorization"] == f"Bearer {JETON}"
        elif requete.url.host.endswith("intelx.io"):
            assert requete.headers["x-key"] == CLE
        else:
            assert "authorization" not in requete.headers and "x-key" not in requete.headers
    # Pastes d'Intelligence X : media 1.
    corps = next(r for r in requetes if r.method == "POST").content
    assert json.loads(corps)["media"] == 1


def test_source_en_panne_ne_fait_pas_echouer_le_module(http_simule, contexte, outils):
    routes = _toutes_sources([])
    routes[GITHUB] = (401, {}, '{"message": "Bad credentials"}')
    routes[INTELX] = (401, {}, "")
    routes["https://2.intelx.io/intelligent/search"] = (401, {}, "")
    http_simule(routes)
    resultat = outils.executer(SPEC, contexte(secrets={"github_token": JETON, "intelx_key": CLE}))
    assert resultat["sources"] == {"sourcegraph": "ok", "github": "error", "intelx": "error"}
    assert resultat["total_found"] == 1


def test_limite_github_signalee(http_simule, contexte, outils):
    routes = _toutes_sources([])
    routes[GITHUB] = (429, {"retry-after": "3600"}, "")
    http_simule(routes)
    resultat = outils.executer(SPEC, contexte(secrets={"github_token": JETON}))
    assert resultat["sources"]["github"] == "rate_limited" and resultat["sources"]["sourcegraph"] == "ok"


def test_adresse_ip_sans_objet(contexte):
    assert SPEC.skip_reason(contexte(domain="93.184.216.34")) is not None
    assert SPEC.skip_reason(contexte()) is None


def test_flux_invalide_refuse():
    with pytest.raises(ValueError):
        impl.parse_sourcegraph_stream("<html>Just a moment</html>", "example.com")


def test_analyse_du_flux_ignore_le_hors_sujet():
    corps = flux(
        {"type": "path", "path": "x", "repository": "r"},
        {"type": "repo", "repository": "r"},
        fichier("a.log", "example.com 1", "example.com 2", "example.com 3"),
    )
    pastes = impl.parse_sourcegraph_stream(corps + "event: matches\ndata: pas du json\n\n", "example.com")
    assert len(pastes) == impl.MAX_LINES_PER_FILE


def test_fusion_sans_doublon_et_bornee():
    base = {"source": "github", "date": "", "line": None}
    liste = [
        {**base, "url": f"https://x/{i}", "title": f"t{i}", "snippet": "s", "severity": "low"}
        for i in range(60)
    ]
    liste.append(dict(liste[0]))
    liste.append({**base, "url": "https://x/h", "title": "h", "snippet": "s", "severity": "high"})
    fusion = impl.merge(liste)
    assert len(fusion) == impl.MAX_PASTES and fusion[0]["severity"] == "high"
    assert len({p["url"] for p in fusion}) == len(fusion)


def test_constats_et_score():
    donnees = {"total_found": 4, "high_count": 1}
    constats = _constats(donnees)
    assert constats["finding.paste.credentials"] == {"count": 1}
    assert constats["finding.paste.mentions"] == {"count": 4}
    assert _score(donnees).points == 0
    assert _score({"total_found": 2, "high_count": 0}).points == 1


def test_lecture_defensive():
    for donnees in (None, [], {"total_found": "x", "high_count": None}):
        assert all(v is None for v in _constats(donnees).values())
        _score(donnees if isinstance(donnees, dict) else {})
