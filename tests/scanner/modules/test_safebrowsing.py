# =============================================================================
# DomainRecon - Tests du module « safebrowsing » (API v5, sans réseau)
# =============================================================================

import base64
import hashlib

import httpx
import pytest

from domainrecon.i18n import render
from domainrecon.scanner.errors import ModuleError
from domainrecon.scanner.modules import safebrowsing
from domainrecon.scanner.rules import FindingInput

CLE = "AIzaSy-cle-secrete-0123456789abcdef"
SPEC = safebrowsing.SPEC
URL = "https://safebrowsing.googleapis.com/v5/hashes:search"


def _b64(octets: bytes) -> str:
    return base64.b64encode(octets).decode()


def _reponse_pour(expression, menaces=("MALWARE",), attributs=(), url_safe=False):
    """Réponse hashes:search conforme à la doc v5 : l'empreinte complète de l'expression et ses détails."""
    full = hashlib.sha256(expression.encode()).digest()
    texte = _b64(full)
    if url_safe:
        texte = texte.replace("+", "-").replace("/", "_").rstrip("=")
    details = [{"threatType": t, "attributes": list(attributs)} for t in menaces]
    return {"fullHashes": [{"fullHash": texte, "fullHashDetails": details}], "cacheDuration": "300s"}


def _lancer(contexte, outils, http_simule, route, **champs):
    requetes = http_simule({URL: route})
    context = contexte(secrets={"safebrowsing_key": CLE}, **champs)
    return outils.executer(SPEC, context), requetes


def test_expressions():
    assert safebrowsing.host_expressions("a.b.example.com") == [
        "a.b.example.com/",
        "b.example.com/",
        "example.com/",
    ]
    assert safebrowsing.host_expressions("93.184.216.34") == ["93.184.216.34/"]
    assert safebrowsing.target_expressions("example.com", "example.com") == [
        "example.com/",
        "www.example.com/",
    ]
    assert safebrowsing.target_expressions("blog.example.com", "example.com") == [
        "blog.example.com/",
        "example.com/",
    ]


def test_succes_menace(contexte, outils, http_simule):
    sortie, requetes = _lancer(contexte, outils, http_simule, _reponse_pour("example.com/"))
    outils.verifier_sortie(sortie, [CLE])
    assert sortie["safe"] is False and sortie["threat_types"] == ["MALWARE"]
    assert sortie["threats"][0]["expression"] == "example.com/" and sortie["api_version"] == 5
    requete = requetes[0]
    # Clé en en-tête, jamais dans l'URL ; préfixes de 4 octets uniquement.
    assert requete.headers["x-goog-api-key"] == CLE and CLE not in str(requete.url)
    prefixes = requete.url.params.get_list("hashPrefixes")
    assert len(prefixes) == 2 and all(len(base64.b64decode(p)) == 4 for p in prefixes)
    assert b"example.com" not in bytes(requete.url.query)


def test_empreinte_en_base64_url_et_attribut_trame(contexte, outils, http_simule):
    reponse = _reponse_pour("www.example.com/", ("SOCIAL_ENGINEERING",), ["FRAME_ONLY"], url_safe=True)
    sortie, _ = _lancer(contexte, outils, http_simule, reponse)
    assert sortie["threat_types"] == ["SOCIAL_ENGINEERING"]
    assert sortie["threats"][0]["attributes"] == ["FRAME_ONLY"]


def test_rien_trouve_et_collision_de_prefixe(contexte, outils, http_simule):
    sortie, _ = _lancer(contexte, outils, http_simule, {"cacheDuration": "300s"})
    assert sortie["safe"] is True and sortie["threats"] == []
    assert SPEC.score_rules[0].evaluate({"safebrowsing": sortie}).points == 5
    # Une empreinte de même préfixe mais d'une autre URL n'est pas la nôtre.
    from domainrecon.scanner import cache

    cache.clear_cache()
    sortie, _ = _lancer(contexte, outils, http_simule, _reponse_pour("autre-site.test/"))
    assert sortie["safe"] is True


def test_canari_et_types_inconnus_ignores(contexte, outils, http_simule):
    reponse = _reponse_pour("example.com/", ("MALWARE",), ["CANARY"])
    sortie, _ = _lancer(contexte, outils, http_simule, reponse)
    assert sortie["safe"] is True
    from domainrecon.scanner import cache

    cache.clear_cache()
    sortie, _ = _lancer(contexte, outils, http_simule, _reponse_pour("example.com/", ("NOUVEAU_TYPE",)))
    assert sortie["safe"] is True


@pytest.mark.parametrize(
    ("statut", "code"),
    [(400, "network.http_status"), (403, "network.http_status"), (429, "network.quota")],
)
def test_echecs_http(contexte, outils, http_simule, statut, code):
    with pytest.raises(ModuleError) as erreur:
        _lancer(contexte, outils, http_simule, (statut, {}, '{"error":{"message":"API key not valid"}}'))
    assert erreur.value.message["$t"] == code and CLE not in str(erreur.value)


def test_illisible_delai_connexion(contexte, outils, http_simule):
    with pytest.raises(ModuleError) as erreur:
        _lancer(contexte, outils, http_simule, (200, {}, "<html>"))
    assert erreur.value.message["$t"] == "safebrowsing.unreadable"
    with pytest.raises(ModuleError):
        _lancer(contexte, outils, http_simule, {"fullHashes": "pas une liste"})
    with pytest.raises(ModuleError) as erreur:
        _lancer(contexte, outils, http_simule, httpx.ConnectTimeout("lent " + CLE))
    assert CLE not in str(render(erreur.value.message, "fr"))
    with pytest.raises(ModuleError):
        outils.executer(SPEC, contexte(secrets={"safebrowsing_key": CLE}))


def test_cle_requise():
    assert SPEC.required_keys == ("safebrowsing_key",) and SPEC.category == "cle_api"


def _entree(donnees):
    scan = {"modules": {"safebrowsing": {"data": donnees}}}
    return FindingInput(scan, "safebrowsing", lambda s, m: s["modules"][m]["data"], lambda s, m: True)


def test_constats_et_score():
    regle = SPEC.findings[0]
    grave = {"safe": False, "threat_types": ["MALWARE", "UNWANTED_SOFTWARE"]}
    assert regle.check(_entree(grave)).severity == "critical"
    assert regle.check(_entree({"safe": False, "threat_types": ["UNWANTED_SOFTWARE"]})).severity == "high"
    assert regle.check(_entree({"safe": True, "threat_types": []})) is None
    assert regle.check(_entree(None)) is None
    sortie = SPEC.score_rules[0].evaluate({"safebrowsing": grave})
    assert sortie.points == 0 and sortie.cap_reason is not None
    mineur = SPEC.score_rules[0].evaluate(
        {"safebrowsing": {"safe": False, "threat_types": ["UNWANTED_SOFTWARE"]}}
    )
    assert mineur.cap_reason is None
    assert SPEC.score_rules[0].evaluate({"safebrowsing": {}}).measured is False
