# =============================================================================
# DomainRecon - Tests du module « builtwith » (réponses simulées, sans réseau)
# =============================================================================
# Format de réponse : documentation de l'API Domain de BuiltWith (v26).

import asyncio

import httpx
import pytest

from domainrecon.i18n import is_msg, render
from domainrecon.scanner.errors import ModuleError
from domainrecon.scanner.modules.builtwith import SPEC, parse

CLE = "bw-cle-secrete-de-test-0123456789"
API = "https://api.builtwith.com/v26/api.json"

REPONSE = {
    "Results": [
        {
            "Lookup": "example.com",
            "Result": {
                "IsDB": "misc",
                "Paths": [
                    {
                        "Domain": "example.com",
                        "Url": "",
                        "SubDomain": "",
                        "Technologies": [
                            {
                                "Name": "Nginx",
                                "Tag": "Web Server",
                                "Link": "https://nginx.org",
                                "FirstDetected": 1420070400000,
                                "LastDetected": 1735689600000,
                                "IsPremium": "no",
                            },
                            {"Name": "WordPress", "Tag": "cms", "IsPremium": "yes"},
                            {"Name": "Nginx", "Tag": "Web Server"},
                            {"Tag": "javascript"},
                        ],
                    }
                ],
            },
        }
    ],
    "Errors": [],
}


def _lancer(http_simule, contexte, outils, reponse, **champs):
    requetes = http_simule({API: reponse})
    valeur = outils.executer(SPEC, contexte(secrets={"builtwith_key": CLE}, **champs))
    outils.verifier_sortie(valeur, [CLE])
    return valeur, requetes


# --- Succès -------------------------------------------------------------------------


def test_succes(http_simule, contexte, outils):
    valeur, requetes = _lancer(http_simule, contexte, outils, REPONSE)
    assert valeur["measured"] is True and valeur["count"] == 2 and valeur["paths"] == 1
    nginx = valeur["technologies"][0]
    assert nginx == {
        "name": "Nginx",
        "category": "web server",
        "first_detected": "2015-01-01",
        "last_detected": "2025-01-01",
        "premium": False,
    }
    assert (
        valeur["technologies"][1]["premium"] is True and valeur["technologies"][1]["first_detected"] is None
    )
    assert valeur["categories"] == {"cms": ["WordPress"], "web server": ["Nginx"]}
    assert dict(requetes[0].url.params) == {"KEY": CLE, "LOOKUP": "example.com"}


def test_aucun_resultat(http_simule, contexte, outils):
    valeur, _ = _lancer(http_simule, contexte, outils, {"Results": [], "Errors": []})
    assert valeur["technologies"] == [] and valeur["count"] == 0


def test_resultat_sans_chemin(http_simule, contexte, outils):
    valeur, _ = _lancer(http_simule, contexte, outils, {"Results": [{"Result": {}}]})
    assert valeur["technologies"] == [] and valeur["paths"] == 0


def test_resultat_garde_en_memoire(http_simule, contexte, outils):
    _, requetes = _lancer(http_simule, contexte, outils, REPONSE)
    outils.executer(SPEC, contexte(secrets={"builtwith_key": CLE}))
    assert len(requetes) == 1  # cache de 24 h : chaque appel consomme des crédits


# --- Clé facultative --------------------------------------------------------------------


def test_sans_cle_module_sans_objet(contexte):
    raison = SPEC.skip_reason(contexte())
    assert is_msg(raison) and "BuiltWith" in render(raison, "fr")


def test_avec_cle_le_module_s_applique(contexte):
    assert SPEC.skip_reason(contexte(secrets={"builtwith_key": CLE})) is None


def test_adresse_ip_sans_objet(contexte):
    raison = SPEC.skip_reason(contexte(domain="93.184.216.34", secrets={"builtwith_key": CLE}))
    assert "adresse IP" in render(raison, "fr")


def test_lance_sans_cle_echoue_proprement(contexte):
    with pytest.raises(ModuleError):
        asyncio.run(SPEC.run(contexte()))


def test_la_cle_est_facultative_et_nommee_comme_les_reglages():
    (cle,) = SPEC.keys
    assert cle.name == "builtwith_key" and cle.service == "builtwith" and cle.required is False
    assert SPEC.category == "passif"  # « cle_api » exigerait une clé requise


# --- Erreurs -------------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("reponse", "extrait"),
    [
        ((200, {}, '{"Errors":[{"Code":-2,"Message":"API Key is wrong"}]}'), "refusé la clé"),
        ((200, {}, '{"Results":[],"Errors":[{"Code":-3,"Message":"out of credits"}]}'), "Quota"),
        ((200, {}, '{"Results":[{"Errors":[{"Code":-9}]}]}'), "code d'erreur -9"),
        ((401, {}, ""), "refusé la clé"),
        ((403, {}, ""), "refusé la clé"),
        ((429, {}, ""), "Quota"),
        ((500, {}, "oups"), "HTTP 500"),
        ((200, {}, "<html>pas du json</html>"), "BuiltWith"),
    ],
)
def test_erreurs_du_service(http_simule, contexte, reponse, extrait):
    http_simule({API: reponse})
    with pytest.raises(ModuleError) as erreur:
        asyncio.run(SPEC.run(contexte(secrets={"builtwith_key": CLE})))
    texte = render(erreur.value.message, "fr")
    assert extrait in texte
    assert CLE not in texte


@pytest.mark.parametrize("exception", [httpx.ConnectError("refus"), httpx.ReadTimeout("délai")])
def test_erreur_reseau_sans_fuite_de_la_cle(http_simule, contexte, exception):
    """Le texte d'une erreur httpx cite l'URL (donc la clé en paramètre) : seul le nom de l'exception est gardé."""
    http_simule({API: exception})
    with pytest.raises(ModuleError) as erreur:
        asyncio.run(SPEC.run(contexte(secrets={"builtwith_key": CLE})))
    texte = render(erreur.value.message, "fr")
    assert type(exception).__name__ in texte
    assert CLE not in texte and "api.builtwith.com" not in texte


# --- Lecture défensive --------------------------------------------------------------------------


@pytest.mark.parametrize(
    "donnees", [None, [], "x", {"Results": "x"}, {"Results": [None]}, {"Results": [{"Result": []}]}]
)
def test_lecture_defensive(donnees):
    assert parse(donnees)["technologies"] == []


def test_dates_invalides():
    donnees = {
        "Results": [
            {
                "Result": {
                    "Paths": [{"Technologies": [{"Name": "X", "FirstDetected": -5, "LastDetected": "x"}]}]
                }
            }
        ]
    }
    technologie = parse(donnees)["technologies"][0]
    assert technologie["first_detected"] is None and technologie["last_detected"] is None


def test_declaration():
    assert SPEC.family == "web" and SPEC.optional is True and not SPEC.findings
