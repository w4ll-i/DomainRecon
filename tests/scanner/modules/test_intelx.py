# =============================================================================
# DomainRecon - Tests du module « intelx » (sans réseau : réponses simulées conformes à
# https://github.com/IntelligenceX/SDK et https://help.intelx.io/api/)
# =============================================================================

import httpx
import pytest

from domainrecon.i18n import render
from domainrecon.scanner.errors import ModuleError
from domainrecon.scanner.impl import intelx as impl
from domainrecon.scanner.modules.intelx import SPEC
from domainrecon.scanner.rules import FindingInput

CLE = "00000000-aaaa-bbbb-cccc-cle-intelx-secrete"
GRATUIT = "https://free.intelx.io"
PAYANT = "https://2.intelx.io"
IDENTIFIANT = "6e4e2a3c-0000-4d6f-9d1a-123456789abc"

RECORDS = [
    {
        "systemid": "a1",
        "storageid": "s-1",
        "size": 2048,
        "type": 1,
        "media": 24,
        "added": "2026-01-01T00:00:00Z",
        "date": "2025-12-30T10:00:00Z",
        "name": "combo-jean.dupont@example.com.txt",
        "bucket": "leaks.public.general",
        "xscore": 50,
    },
    {"storageid": "s-2", "media": 1, "date": "2026-02-03T00:00:00Z", "name": "paste 42", "bucket": "pastes"},
]


@pytest.fixture(autouse=True)
def attentes_courtes(monkeypatch):
    monkeypatch.setattr(impl, "POLL_INTERVAL", 0)
    monkeypatch.setattr(impl, "SEARCH_WAIT", 0.05)


def _routes(base, *, records=RECORDS, resultat=None):
    return {
        f"{base}/intelligent/search": {"id": IDENTIFIANT, "status": 0, "softselectorwarning": False},
        f"{base}/intelligent/search/result": resultat or {"records": records, "status": 1},
        f"{base}/intelligent/search/terminate": (200, {}, ""),
    }


def _constats(data):
    entree = FindingInput({}, "intelx", lambda scan, module: data, lambda scan, module: True)
    return {rule.code: rule.check(entree) for rule in SPEC.findings}


def _score(data):
    return SPEC.score_rules[0].evaluate({"intelx": data})


def test_declaration():
    assert SPEC.category == "sensible" and SPEC.family == "leaks"
    assert [(k.name, k.service, k.required) for k in SPEC.keys] == [("intelx_key", "intelx", True)]


def test_succes_offre_gratuite(http_simule, contexte, outils):
    requetes = http_simule(_routes(GRATUIT))
    resultat = outils.executer(SPEC, contexte(secrets={"intelx_key": CLE}))
    outils.verifier_sortie(resultat, [CLE])
    assert resultat["plan"] == "free" and resultat["term"] == "@example.com"
    assert resultat["total_found"] == 2 and resultat["credential_records"] == 1
    assert resultat["buckets"] == {"leaks.public.general": 1, "pastes": 1}
    # Métadonnées seulement, nom masqué ; la clé voyage uniquement dans l'en-tête x-key.
    assert "jean.dupont" not in str(resultat) and resultat["results"][0]["name"].startswith("c***@")
    assert all(r.headers["x-key"] == CLE for r in requetes)
    assert all(CLE not in str(r.url) and "k=" not in str(r.url.query) for r in requetes)
    assert requetes[0].method == "POST" and b"@example.com" in requetes[0].content
    # La recherche est libérée à la fin.
    assert requetes[-1].url.path.endswith("/terminate") and requetes[-1].url.params["id"] == IDENTIFIANT


def test_repli_sur_l_offre_payante(http_simule, contexte, outils):
    routes = _routes(PAYANT)
    routes[f"{GRATUIT}/intelligent/search"] = (401, {}, "")
    http_simule(routes)
    resultat = outils.executer(SPEC, contexte(secrets={"intelx_key": CLE}))
    assert resultat["plan"] == "paid" and resultat["total_found"] == 2


def test_hote_gratuit_qui_coupe_la_connexion_puis_hote_payant(http_simule, contexte, outils):
    # Constaté en réel : free.intelx.io ferme la connexion devant une clé payante.
    routes = _routes(PAYANT)
    routes[f"{GRATUIT}/intelligent/search"] = httpx.RemoteProtocolError("Server disconnected")
    http_simule(routes)
    resultat = outils.executer(SPEC, contexte(secrets={"intelx_key": CLE}))
    assert resultat["plan"] == "paid"


def test_attente_des_resultats(http_simule, contexte, outils, monkeypatch):
    monkeypatch.setattr(impl, "SEARCH_WAIT", 5)
    reponses = iter(
        [
            {"records": None, "status": 3},
            {"records": RECORDS[:1], "status": 0},
            {"records": RECORDS[1:], "status": 1},
        ]
    )
    routes = _routes(GRATUIT)
    routes[f"{GRATUIT}/intelligent/search/result"] = lambda requete: httpx.Response(200, json=next(reponses))
    http_simule(routes)
    resultat = outils.executer(SPEC, contexte(secrets={"intelx_key": CLE}))
    assert resultat["total_found"] == 2


def test_rien_trouve_apres_delai(http_simule, contexte, outils):
    http_simule(_routes(GRATUIT, resultat={"records": None, "status": 3}))
    resultat = outils.executer(SPEC, contexte(secrets={"intelx_key": CLE}))
    outils.verifier_sortie(resultat, [CLE])
    assert resultat["total_found"] == 0 and resultat["results"] == []
    assert _score(resultat).points == 5
    assert _constats(resultat)["finding.intelx.leaks"] is None


@pytest.mark.parametrize(
    ("changement", "attendu"),
    [
        ({"search": (401, {}, "")}, "refusée"),
        ({"search": (402, {}, "")}, "Crédits"),
        ({"search": (429, {}, "")}, "Quota"),
        ({"search": (500, {}, "")}, "500"),
        ({"search": (200, {}, "pas du JSON")}, "illisible"),
        ({"search": {"id": "", "status": 1}}, "Recherche refusée"),
        ({"search": {"id": IDENTIFIANT, "status": 2}}, "Recherche refusée"),
        ({"result": (503, {}, "")}, "503"),
        ({"result": (200, {}, "<html>")}, "illisible"),
        ({"search": (403, {}, "")}, "refusée"),
        ({"search": httpx.ReadTimeout("lent"), "payant": httpx.ReadTimeout("lent")}, "délai"),
        ({"result": httpx.ConnectError("refusé")}, "ConnectError"),
    ],
)
def test_echecs(http_simule, contexte, outils, changement, attendu):
    routes = _routes(GRATUIT)
    routes[f"{PAYANT}/intelligent/search"] = (401, {}, "")
    for nom, valeur in changement.items():
        if nom == "payant":
            routes[f"{PAYANT}/intelligent/search"] = valeur
        else:
            routes[f"{GRATUIT}/intelligent/search" + ("/result" if nom == "result" else "")] = valeur
    http_simule(routes)
    with pytest.raises(ModuleError) as erreur:
        outils.executer(SPEC, contexte(secrets={"intelx_key": CLE}))
    texte = render(erreur.value.message, "fr")
    assert attendu in texte and CLE not in texte


def test_cle_absente(contexte, outils):
    with pytest.raises(ModuleError) as erreur:
        outils.executer(SPEC, contexte())
    assert "non renseignée" in render(erreur.value.message, "fr")


def test_adresse_ip_sans_objet(contexte):
    assert SPEC.skip_reason(contexte(domain="93.184.216.34")) is not None
    assert SPEC.skip_reason(contexte()) is None


def test_constats_et_score(http_simule, contexte, outils):
    http_simule(_routes(GRATUIT))
    resultat = outils.executer(SPEC, contexte(secrets={"intelx_key": CLE}))
    constat = _constats(resultat)["finding.intelx.leaks"]
    assert constat.severity == "high" and constat.params == {"count": 2, "credentials": 1}
    assert _score(resultat).points == 0


def test_score_pastes_seulement():
    donnees = {"measured": True, "total_found": 3, "credential_records": 0, "buckets": {"pastes": 3}}
    assert _score(donnees).points == 2
    assert _constats(donnees)["finding.intelx.leaks"].severity == "medium"


def test_lecture_defensive():
    for donnees in (None, [], {"total_found": "x", "credential_records": None}):
        assert _constats(donnees)["finding.intelx.leaks"] is None
        _score(donnees if isinstance(donnees, dict) else {})


def test_enregistrement_sanitise_borne_les_champs():
    brut = {"name": "x" * 500, "bucket": 12, "media": "x", "storageid": None}
    propre = impl.sanitize_record(brut)
    assert len(propre["name"]) <= 100 and propre["media"] is None and propre["storageid"] == ""
    assert impl.sanitize_record("pas un dict")["name"] == ""
