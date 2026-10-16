# =============================================================================
# DomainRecon - Tests : la réponse 422 ne renvoie jamais la valeur soumise
# =============================================================================
# Pydantic joint à chaque erreur l'entrée fautive (input) et un contexte (ctx)
# qui peut la répéter. Sur PUT /api/settings, c'est une clef d'API ou un mot de
# passe de proxy : le corps du 422 n'en garde que loc, msg et type, et les
# messages des règles de l'application restent traduits.
# =============================================================================

import json

import pytest
from fastapi.testclient import TestClient

from domainrecon.api.app import app
from domainrecon.api.errors import _public_errors

SECRET = "SECRET-a1b2c3d4e5f6g7h8"


@pytest.fixture
def client():
    with TestClient(app) as c:
        yield c


def _verifier_corps_sans_secret(response, secret=SECRET):
    assert response.status_code == 422, response.text
    assert secret not in response.text
    # Le secret ne se cache pas non plus derrière un échappement JSON ou une casse.
    assert secret not in json.dumps(response.json(), ensure_ascii=True)
    assert secret.lower() not in response.text.lower()
    erreurs = response.json()["errors"]
    assert erreurs
    for erreur in erreurs:
        # Seuls loc, msg et type servent à l'affichage : ni input, ni ctx, ni url.
        assert set(erreur) == {"loc", "msg", "type"}


@pytest.mark.parametrize(
    "corps",
    [
        {"shodan_key": SECRET + "\navec retour"},  # règle de l'application : caractères interdits
        {"shodan_key": "cle avec espace " + SECRET},
        {"circl_password": SECRET + "\x07"},
        {"proxy_url": "ftp://alice:" + SECRET + "@proxy.local"},  # règle de l'application : proxy invalide
        {"proxy_url": "http://alice:" + SECRET + "@proxy.local:99999"},
        {"shodan_key": SECRET * 40},  # type Pydantic : string_too_long
        {"scan_timeout": SECRET},  # type Pydantic : int_parsing
        {"screenshot_enabled": SECRET},  # type Pydantic : bool_parsing
        {"champ_inconnu": SECRET},  # type Pydantic : extra_forbidden
        {"shodan_key": [SECRET]},  # type Pydantic : string_type
        {"censys_secret": {"clef": SECRET}},
    ],
    ids=[
        "clef-retour",
        "clef-espace",
        "mot-de-passe-bel",
        "proxy-schema",
        "proxy-port",
        "clef-trop-longue",
        "delai-texte",
        "booleen-texte",
        "champ-inconnu",
        "clef-liste",
        "secret-objet",
    ],
)
def test_put_settings_422_ne_renvoie_pas_la_valeur(client, corps):
    for langue in ("fr", "en"):
        _verifier_corps_sans_secret(client.put(f"/api/settings?lang={langue}", json=corps))


def test_regles_de_l_application_restent_traduites(client):
    francais = client.put("/api/settings?lang=fr", json={"proxy_url": "ftp://" + SECRET})
    anglais = client.put("/api/settings?lang=en", json={"proxy_url": "ftp://" + SECRET})
    _verifier_corps_sans_secret(francais)
    _verifier_corps_sans_secret(anglais)

    fr, en = francais.json(), anglais.json()
    assert fr["code"] == en["code"] == "api.settings_invalid_proxy"
    assert "URL de proxy invalide" in fr["detail"]
    assert "Invalid proxy URL" in en["detail"]
    # La liste détaillée porte le même message traduit, sans le contexte.
    assert fr["errors"][0]["msg"] == fr["detail"]
    assert en["errors"][0]["msg"] == en["detail"]
    assert fr["errors"][0]["type"] == "api.settings_invalid_proxy"
    assert fr["errors"][0]["loc"][0] == "body"


def test_regle_a_parametres_traduite_et_params_conserves(client):
    """Le contexte d'une règle sert à rendre le message (params) puis est retiré de errors."""
    for langue, attendu in (("fr", "20 tags au maximum."), ("en", "At most 20 tags.")):
        response = client.patch(
            f"/api/scan/1/meta?lang={langue}", json={"tags": [f"{SECRET}{i}" for i in range(21)]}
        )
        _verifier_corps_sans_secret(response)
        corps = response.json()
        assert (corps["detail"], corps["code"], corps["params"]) == (
            attendu,
            "api.meta_too_many_tags",
            {"max": 20},
        )
        assert corps["errors"][0]["msg"] == attendu
        assert corps["errors"][0]["loc"][:2] == ["body", "tags"]


def test_erreur_de_type_garde_loc_msg_type_et_le_message_generique(client):
    response = client.patch("/api/scan/1/meta?lang=en", json={"notes": [SECRET]})
    _verifier_corps_sans_secret(response)
    corps = response.json()
    assert corps["code"] == "api.validation_error"
    assert corps["detail"] == "Invalid request (notes)"
    assert corps["params"] == {"fields": "notes"}
    assert corps["errors"][0]["loc"] == ["body", "notes"]
    assert corps["errors"][0]["type"] == "string_type"
    assert corps["errors"][0]["msg"]


def test_requete_post_invalide_ne_renvoie_pas_la_valeur(client):
    # Types refusés par Pydantic avant toute analyse : aucun scan n'est lancé.
    for domaine in ({"x": SECRET}, [SECRET]):
        _verifier_corps_sans_secret(client.post("/api/scan?lang=en", json={"domain": domaine}))


def test_public_errors_projette_et_n_altere_pas_l_entree():
    erreurs = [
        {
            "type": "string_too_long",
            "loc": ("body", "shodan_key"),
            "msg": "String should have at most 512 characters",
            "input": SECRET,
            "ctx": {"max_length": 512},
            "url": "https://errors.pydantic.dev/2/v/string_too_long",
        },
        {
            "type": "value_error",
            "loc": ("body", "x"),
            "msg": f"Value error, valeur refusée : {SECRET}",
            "input": SECRET,
            "ctx": {"error": ValueError(SECRET)},
        },
        {
            "type": "assertion_error",
            "loc": ("body", "y"),
            "msg": f"Assertion failed, {SECRET}",
            "input": SECRET,
        },
    ]
    publiques = _public_errors(erreurs)
    assert all(set(erreur) == {"loc", "msg", "type"} for erreur in publiques)
    assert SECRET not in repr(publiques)
    assert publiques[0]["msg"] == "String should have at most 512 characters"
    assert publiques[1]["msg"] == "Value error" and publiques[2]["msg"] == "Assertion failed"
    assert erreurs[0]["input"] == SECRET  # l'entrée n'est pas modifiée
