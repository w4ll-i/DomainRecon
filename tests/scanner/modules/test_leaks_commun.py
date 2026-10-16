# =============================================================================
# DomainRecon - Tests des outils communs de la famille « leaks » (masquage, domaines, requêtes)
# =============================================================================

import asyncio
import time

import httpx
import pytest

from domainrecon.i18n import render
from domainrecon.scanner.impl import leaks_commun as commun


def test_masquage_des_adresses():
    assert commun.mask_email("jean.dupont@Example.COM") == "j***@example.com"
    assert commun.mask_email("sans-arobase") == "****"


def test_masquage_des_secrets():
    assert commun.mask_secret("AKIAABCDEFGHIJKLMNOP") == "AKIA****"
    assert commun.mask_secret("court") == "****"


def test_masque_du_texte():
    texte = "mail bob.martin@example.com password: Sup3rS3cr3t token=abcdef1234567890 DB_PASSWORD=hunter22x"
    masque = commun.mask_text(texte)
    for secret in ("bob.martin", "Sup3rS3cr3t", "abcdef1234567890", "hunter22x"):
        assert secret not in masque
    assert "b***@example.com" in masque and "password: ****" in masque
    assert len(commun.mask_text("x " * 500, limit=50)) == 50
    assert commun.mask_text("a\x00b\x1fc") == "a b c"
    assert "mot-de-passe" not in commun.mask_text("INSERT INTO t VALUES ('x@example.com', 'mot-de-passe')")


def test_reconnaissance_des_secrets():
    contenu = (
        "AWS_SECRET_ACCESS_KEY = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\n"
        "key=AKIAABCDEFGHIJKLMNOP\n"
        "-----BEGIN RSA PRIVATE KEY-----\n"
        "gh=ghp_" + "a" * 36 + "\n"
        "stripe: sk_live_" + "b" * 24 + "\n"
    )
    types = {s["type"] for s in commun.find_secrets(contenu)}
    assert types == {"password_assignment", "aws_access_key", "private_key", "github_token", "stripe_key"}
    assert "wJalrXUtnFEMI" not in str(commun.find_secrets(contenu))


@pytest.mark.parametrize(
    "exemple",
    [
        "password=changeme",
        "PASSWORD=${DB_PASSWORD}",
        "secret: <votre-secret>",
        "api_key = your_api_key_here",
        "pwd=xxxxxxxx",
    ],
)
def test_valeurs_d_exemple_ignorees(exemple):
    assert commun.find_secrets(exemple) == []


def test_recherche_de_secrets_bornee_dans_le_temps():
    debut = time.monotonic()
    commun.find_secrets("a" * 50000 + " " + "b.c-" * 12500)
    assert time.monotonic() - debut < 5


def test_domaine_en_entier():
    assert commun.mentions_domain("host=api.example.com:443", "example.com")
    assert commun.mentions_domain("EXAMPLE.COM", "example.com")
    assert not commun.mentions_domain("notexample.com", "example.com")
    assert not commun.mentions_domain("example.community", "example.com")
    assert not commun.mentions_domain("", "example.com")


def test_texte_sans_balises():
    assert commun.strip_html("<p>Un <b>test</b></p>   ici") == "Un test ici"
    assert len(commun.strip_html("x" * 1000, limit=10)) == 10


def test_requete_bornee_et_json(http_simule, contexte):
    http_simule(
        {"https://api.example.org/gros": (200, {}, "x" * 5000), "https://api.example.org/json": {"a": 1}}
    )
    client = contexte().http

    async def scenario():
        gros = await commun.request(client, "GET", "https://api.example.org/gros", max_bytes=100)
        petit = await commun.request(client, "GET", "https://api.example.org/json")
        return gros, petit

    gros, petit = asyncio.run(scenario())
    assert gros.truncated and len(gros.body) == 100
    with pytest.raises(ValueError):
        gros.json()
    assert petit.json() == {"a": 1} and petit.headers["content-type"] == "application/json"


def test_erreurs_sans_url_ni_cle():
    requete = httpx.Request("GET", "https://api.example.org/x?key=SECRETE")
    erreur = commun.network_error(
        "Service", httpx.ConnectError("échec pour https://api.example.org/x?key=SECRETE", request=requete)
    )
    assert "SECRETE" not in render(erreur.message, "fr") and "ConnectError" in render(erreur.message, "fr")
    assert "délai" in render(commun.network_error("S", httpx.ReadTimeout("t")).message, "fr")
    assert "Quota" in render(commun.status_error("S", 429).message, "fr")
    assert "503" in render(commun.status_error("S", 503).message, "fr")


def test_retry_after():
    assert commun.retry_after(commun.Reply(429, {"retry-after": "7"})) == 7
    assert commun.retry_after(commun.Reply(429, {"retry-after": "demain"}), 1.5) == 1.5
    assert commun.retry_after(commun.Reply(429, {})) == 0.0
