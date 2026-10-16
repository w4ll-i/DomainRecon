# =============================================================================
# DomainRecon - Tests du module « js_secrets » (sans réseau)
# =============================================================================
# Les faux secrets sont assemblés à l'exécution : le dépôt ne contient aucune chaîne
# qu'un analyseur de secrets (GitHub, GitGuardian…) prendrait pour une fuite réelle.

import asyncio
import base64
import json

import httpx
import pytest

from domainrecon.i18n import render
from domainrecon.scanner.errors import ModuleError
from domainrecon.scanner.impl import wc_js_scan as logic
from domainrecon.scanner.modules.js_secrets import SPEC
from domainrecon.scanner.rules import FindingInput

HOME = "https://example.com/"
AWS = "AKIA" + "Z5T3Q7WPLMN4XYAB"
STRIPE = "sk_" + "live_" + "Q9x2LmN7vB3pR8tYk5WcZ4aD"
GITHUB = "gh" + "p_" + "a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q7R8"
SLACK = "xo" + "xb-" + "1234567890-abcdefghij"
PEM = "-----BEGIN RSA " + "PRIVATE KEY-----"
PASSWORD = "Sup3rS3cret!x9"
API_KEY = "A1b2C3d4E5f6G7h8I9j0K1l2"


def _jwt(payload):
    def morceau(objet):
        return base64.urlsafe_b64encode(json.dumps(objet).encode()).decode().rstrip("=")

    return f"{morceau({'alg': 'HS256', 'typ': 'JWT'})}.{morceau(payload)}.c2lnbmF0dXJlLWRlLXRlc3Q"


JWT = _jwt({"sub": "42", "admin": True})
JWT_ANON = _jwt({"iss": "supabase", "role": "anon"})

APP_JS = f"""
const cfg = {{ aws: "{AWS}", stripe: '{STRIPE}', token: "{GITHUB}", slack: "{SLACK}" }};
var jwt = "{JWT}"; var pub = "{JWT_ANON}";
const password = "{PASSWORD}"; const apiKey = "{API_KEY}";
const pem = "{PEM}";
fetch("/api/users"); axios.get('/v1/orders'); fetch("/admin/config");
const ext = "https://api.stripe.com/v1/charges"; const doc = "https://www.w3.org/2000/svg";
const same = "https://example.com/api/internal/list";
//# sourceMappingURL=app.js.map
"""

PROPRE_JS = """
const a = { password: "Enter your password", api_key: "your_api_key_here_1234567890" };
const b = { password: "changeme123", aws: "AKIAIOSFODNN7EXAMPLE", user_password: "motdepasse" };
const c = "Bearer " + token; const d = { apiKey: "xxxxxxxxxxxxxxxxxxxxxxxx" };
"""

PAGE = """<html><head>
<script src="/static/app.js"></script>
<script src="https://www.example.com/static/clean.js"></script>
<script src="https://cdn.jsdelivr.net/npm/lib@1.0.0/index.js"></script>
<script src="https://evilexample.com/steal.js"></script>
<script>var firebaseConfig = { apiKey: "inline" };</script>
</head><body></body></html>"""


def _routes(**plus):
    routes = {
        HOME: (200, {}, PAGE),
        "https://example.com/static/app.js": (200, {"Content-Type": "application/javascript"}, APP_JS),
        "https://www.example.com/static/clean.js": (200, {}, PROPRE_JS),
        "https://example.com/static/app.js.map": (
            200,
            {},
            '{"version":3,"sources":["a.ts"],"mappings":"AAAA"}',
        ),
    }
    routes.update(plus)
    return routes


def _lancer(http_simule, contexte, outils, routes=None):
    requetes = http_simule(routes or _routes())
    valeur = outils.executer(SPEC, contexte())
    outils.verifier_sortie(valeur, [AWS, STRIPE, GITHUB, SLACK, PASSWORD, API_KEY, JWT])
    return valeur, requetes


def _constat(code, data):
    regle = next(r for r in SPEC.findings if r.code == code)
    entree = FindingInput({SPEC.name: data}, SPEC.name, lambda scan, m: scan.get(m), lambda s, m: True)
    return regle.check(entree)


# --- Motifs (sans réseau) ------------------------------------------------------------------


def test_seize_motifs():
    assert len(logic.PATTERNS) == 16
    assert len({key for key, *_ in logic.PATTERNS}) == 16


def test_valeurs_masquees():
    assert logic.redact(AWS) == "AKIA****XYAB"
    assert logic.redact("court") == "****"
    assert logic.redact(PEM, "private_key") == "****"


def test_chaque_motif_trouve_sa_cible():
    texte = APP_JS
    types = {s["type"] for s in logic.scan_secrets(texte, "app.js")}
    assert {
        "aws_access_key",
        "stripe_live_key",
        "github_token",
        "slack_token",
        "jwt",
        "hardcoded_password",
        "generic_api_key",
        "private_key",
    } <= types


@pytest.mark.parametrize(
    ("texte", "type_"),
    [
        ('aws_secret_access_key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYzR3dK9sLmQ"', "aws_secret_key"),
        ("SG." + "Ab3dEf6hIj9lMn2pQr5tUv.Xy1Za4Cd7Fg0Hi3Jk6Lm9No2Pq5Rs8Tu1Vw4Yz7Bc0D", "sendgrid_key"),
        ("key-" + "3a9f1c7e5b2d4086a1c3e5f7092b4d6e", "mailgun_key"),
        ("AC" + "1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d", "twilio_sid"),
        ("AIza" + "SyA1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q", "google_api_key"),
        ("pk_" + "live_" + "Q9x2LmN7vB3pR8tYk5WcZ4aD", "stripe_publishable_key"),
        ("const firebaseConfig = {", "firebase_config"),
        ('headers: { Authorization: "Bearer ' + "k8Jd92Lq0PzXc4VbN7mAs1WeR" + '" }', "bearer_token"),
    ],
)
def test_autres_motifs(texte, type_):
    assert type_ in {s["type"] for s in logic.scan_secrets(texte, "x.js")}


def test_valeurs_d_exemple_ecartees():
    """Les motifs génériques ne signalent pas les valeurs d'exemple et les intitulés de champs."""
    assert logic.scan_secrets(PROPRE_JS, "propre.js") == []


def test_jwt_anon_supabase_ecarte_mais_pas_un_autre_jwt():
    trouves = [s for s in logic.scan_secrets(f'a="{JWT_ANON}"; b="{JWT}"', "x.js") if s["type"] == "jwt"]
    assert len(trouves) == 1 and trouves[0]["value_redacted"].startswith(JWT[:4])


def test_faux_jwt_ecarte():
    assert logic.scan_secrets("eyJhbGciOi.eyJzdWIiOjF9.abcdefghijk", "x.js") == []
    assert logic.scan_secrets("eyJxxxxxxxxxxxxxx.eyJyyyyyyyyyyyyyyyy.zzzzzzzzzzzz", "x.js") == []


def test_fichier_minifie_d_une_seule_ligne_sans_lenteur():
    texte = ("a=" + '"password",' * 20000 + "z" * 200000)[:1_000_000]
    assert logic.scan_secrets(texte, "min.js") == []


def test_extraction_des_endpoints():
    internes, hotes, apis = logic.extract_endpoints(APP_JS, "example.com")
    assert {"/api/users", "/v1/orders", "/admin/config"} <= internes
    assert "/api/internal/list" in internes  # URL absolue du site : devient un chemin interne
    assert "api.stripe.com" in apis and "api.stripe.com" in hotes
    assert "www.w3.org" not in hotes  # simple espace de noms
    assert logic.sensitive_endpoints(internes) == ["/admin/config", "/api/internal/list"]


def test_endpoints_faux_positifs_ecartes():
    internes, _, _ = logic.extract_endpoints(
        'fetch("/a.png"); fetch("/*"); url = "//cdn/x"; path: "/x{y}"', "example.com"
    )
    assert internes == set()


def test_reference_de_carte_de_source():
    assert logic.source_map_reference("x\n//# sourceMappingURL=app.js.map\n") == "app.js.map"
    assert logic.source_map_reference("//# sourceMappingURL=data:application/json;base64,AAAA") is None
    assert logic.source_map_reference("rien") is None


# --- Module ----------------------------------------------------------------------------------


def test_succes(http_simule, contexte, outils):
    valeur, requetes = _lancer(http_simule, contexte, outils)
    assert valeur["files_found"] == 2 and valeur["files_scanned"] == 2 and valeur["inline_scanned"] is True
    types = {s["type"] for s in valeur["secrets"]}
    assert {"aws_access_key", "stripe_live_key", "github_token", "private_key"} <= types
    assert valeur["secret_counts"]["critical"] >= 4 and valeur["secret_counts"]["high"] >= 2
    aws = next(s for s in valeur["secrets"] if s["type"] == "aws_access_key")
    assert (
        aws["value_redacted"] == "AKIA****XYAB"
        and aws["source"].endswith("/static/app.js")
        and aws["line"] > 1
    )
    # Les scripts d'un CDN ou d'un domaine ressemblant ne sont pas lus.
    assert not any(r.url.host in ("cdn.jsdelivr.net", "evilexample.com") for r in requetes)


def test_endpoints_et_api_externes(http_simule, contexte, outils):
    valeur, _ = _lancer(http_simule, contexte, outils)
    assert {"/api/users", "/v1/orders", "/admin/config"} <= set(valeur["endpoints"])
    assert valeur["external_apis"] == ["api.stripe.com"]
    assert valeur["sensitive_endpoints"] == ["/admin/config", "/api/internal/list"]
    assert [f["url"] for f in valeur["js_files"]][0].endswith("/static/app.js")
    assert valeur["js_files"][0]["size_bytes"] == len(APP_JS.encode())


def test_carte_de_source_exposee(http_simule, contexte, outils):
    valeur, _ = _lancer(http_simule, contexte, outils)
    assert valeur["source_maps"] == ["https://example.com/static/app.js.map"]


def test_carte_de_source_absente(http_simule, contexte, outils):
    valeur, _ = _lancer(
        http_simule, contexte, outils, _routes(**{"https://example.com/static/app.js.map": (404, {}, "")})
    )
    assert valeur["source_maps"] == []


def test_carte_de_source_qui_est_une_page_html(http_simule, contexte, outils):
    routes = _routes(**{"https://example.com/static/app.js.map": (200, {}, "<html>accueil</html>")})
    assert _lancer(http_simule, contexte, outils, routes)[0]["source_maps"] == []


def test_page_sans_javascript(http_simule, contexte, outils):
    valeur, requetes = _lancer(
        http_simule, contexte, outils, {HOME: (200, {}, "<html><body>Bonjour</body></html>")}
    )
    assert valeur["files_found"] == 0 and valeur["secrets"] == [] and valeur["inline_scanned"] is False
    assert len(requetes) == 1


def test_un_fichier_en_erreur_ne_perd_pas_les_autres(http_simule, contexte, outils):
    routes = _routes(**{"https://www.example.com/static/clean.js": (500, {}, "oups")})
    valeur, _ = _lancer(http_simule, contexte, outils, routes)
    assert valeur["files_scanned"] == 1 and valeur["files_failed"] == 1 and valeur["secrets"]


def test_aucun_fichier_lisible(http_simule, contexte):
    http_simule({HOME: (200, {}, PAGE)})
    with pytest.raises(ModuleError) as erreur:
        asyncio.run(SPEC.run(contexte()))
    assert "2" in render(erreur.value.message, "fr")


def test_delai_depasse_sur_les_fichiers(http_simule, contexte):
    http_simule(
        {
            HOME: (200, {}, PAGE),
            "https://example.com/static/app.js": httpx.ReadTimeout("délai"),
            "https://www.example.com/static/clean.js": httpx.ReadTimeout("délai"),
        }
    )
    with pytest.raises(ModuleError):
        asyncio.run(SPEC.run(contexte()))


def test_site_injoignable(http_simule, contexte):
    http_simule({})
    with pytest.raises(ModuleError):
        asyncio.run(SPEC.run(contexte()))


def test_plafond_de_fichiers(http_simule, contexte, outils):
    scripts = "".join(f'<script src="/s{i}.js"></script>' for i in range(30))
    routes = {HOME: (200, {}, f"<html>{scripts}</html>")}
    routes.update({f"https://example.com/s{i}.js": (200, {}, "var a=1;") for i in range(30)})
    valeur, _ = _lancer(http_simule, contexte, outils, routes)
    assert valeur["files_found"] == 30 and valeur["files_scanned"] == 15 and valeur["truncated"] is True


def test_aucune_valeur_complete_dans_le_resultat(http_simule, contexte, outils):
    valeur, _ = _lancer(http_simule, contexte, outils)
    texte = json.dumps(render(valeur, "fr"), ensure_ascii=False)
    for secret in (AWS, STRIPE, GITHUB, SLACK, PASSWORD, API_KEY, JWT, PEM):
        assert secret not in texte


# --- Constats et score -------------------------------------------------------------------------


def test_constats(http_simule, contexte, outils):
    donnees, _ = _lancer(http_simule, contexte, outils)
    exposes = {h.severity: h for h in _constat("finding.js_secrets.exposed", donnees)}
    assert exposes["critical"].params["count"] >= 4
    assert render(exposes["critical"].params["types"][0], "fr")
    assert exposes["critical"].params["source"].endswith("/static/app.js")
    assert _constat("finding.js_secrets.source_maps", donnees)["count"] == 1
    assert _constat("finding.js_secrets.sensitive_endpoints", donnees) == {
        "count": 2,
        "examples": ["/admin/config", "/api/internal/list"],
    }


def test_constats_rien_a_signaler():
    vide = {"secrets": [], "source_maps": [], "sensitive_endpoints": []}
    for code in (r.code for r in SPEC.findings):
        assert _constat(code, vide) is None


def test_donnee_inattendue_ne_leve_pas():
    for code in (r.code for r in SPEC.findings):
        for donnees in (
            None,
            3,
            [],
            {"secrets": [None, 4, {"severity": "?"}], "source_maps": "x", "sensitive_endpoints": 3},
        ):
            _constat(code, donnees)


@pytest.mark.parametrize(
    ("donnees", "points"),
    [
        ({"secret_counts": {"critical": 1}}, 0),
        ({"secret_counts": {"high": 2}}, 0),
        ({"secret_counts": {"medium": 1}}, 2),
        ({"secret_counts": {"low": 3}}, 4),
        ({"secret_counts": {}}, 5),
        ({"secret_counts": {}, "source_maps": ["x"]}, 4),
    ],
)
def test_score(donnees, points):
    assert SPEC.score_rules[0].evaluate({"js_secrets": donnees}).points == points


def test_declaration():
    assert SPEC.family == "web" and SPEC.category == "sensible" and SPEC.requires_authorization
