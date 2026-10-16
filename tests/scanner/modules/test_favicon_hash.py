# =============================================================================
# DomainRecon - Tests du module « favicon_hash » (sans réseau)
# =============================================================================

import asyncio
import base64
import hashlib

import httpx
import pytest

from domainrecon.scanner.errors import ModuleError
from domainrecon.scanner.impl import wc_favicon as logic
from domainrecon.scanner.modules.favicon_hash import SPEC

HOME = "https://example.com/"
# Mini-PNG factice : l'empreinte attendue a été calculée avec la bibliothèque de référence `mmh3`.
PNG = b"\x89PNG\r\n\x1a\n" + bytes(range(40))
PNG_MMH3 = -1059765740
ICO = b"\x00\x00\x01\x00" + bytes(range(60))


# --- MurmurHash3 -----------------------------------------------------------------------


@pytest.mark.parametrize(
    ("donnees", "attendu"),
    [(b"", 0), (b"foo", -156908512), (b"Hello, world!", -1070186941)],
)
def test_murmurhash3_vecteurs_de_reference(donnees, attendu):
    """Valeurs de la bibliothèque `mmh3` (MurmurHash3 x86 32 bits, graine 0, signé)."""
    assert logic.mmh3_32(donnees) == attendu


def test_empreinte_shodan_base64_avec_retours_a_la_ligne():
    assert logic.shodan_hash(PNG) == PNG_MMH3
    # base64.encodebytes coupe tous les 76 caractères et termine par un retour à la ligne.
    assert logic.shodan_hash(PNG) == logic.mmh3_32(base64.encodebytes(PNG))
    assert logic.shodan_hash(PNG) != logic.mmh3_32(base64.b64encode(PNG))


def test_empreintes_et_requetes_de_pivot():
    empreintes = logic.fingerprints(PNG)
    assert empreintes["md5"] == hashlib.md5(PNG).hexdigest()
    assert empreintes["sha256"] == hashlib.sha256(PNG).hexdigest()
    assert empreintes["queries"]["shodan"] == f"http.favicon.hash:{PNG_MMH3}"
    assert empreintes["queries"]["fofa"] == f'icon_hash="{PNG_MMH3}"'
    assert empreintes["md5"] in empreintes["queries"]["censys"]


# --- Reconnaissance d'image et candidats ----------------------------------------------------


@pytest.mark.parametrize(
    ("contenu", "type_"),
    [
        (PNG, "image/png"),
        (ICO, "image/x-icon"),
        (b"GIF89a....", "image/gif"),
        (b"\xff\xd8\xff\xe0....", "image/jpeg"),
        (b"RIFF\x00\x00\x00\x00WEBPVP8 ", "image/webp"),
        (b'<?xml version="1.0"?><svg xmlns="http://www.w3.org/2000/svg"/>', "image/svg+xml"),
        (b"<!DOCTYPE html><html><body>Page introuvable</body></html>", None),
        (b"", None),
        (b"texte", None),
    ],
)
def test_reconnaissance_d_image(contenu, type_):
    assert logic.sniff_image(contenu) == type_


def test_candidats_dans_l_ordre():
    html = (
        '<link rel="apple-touch-icon" href="/apple.png"><link rel="shortcut icon" href="/img/f.ico">'
        '<link rel="stylesheet" href="/a.css"><link rel="icon" href="//cdn.exemple.net/i.png">'
    )
    urls = [c["url"] for c in logic.candidates(html, HOME, "https://example.com/favicon.ico")]
    assert urls == [
        "https://example.com/img/f.ico",
        "https://cdn.exemple.net/i.png",
        "https://example.com/apple.png",
        "https://example.com/favicon.ico",
    ]


def test_candidat_data_uri():
    donnees = base64.b64encode(PNG).decode()
    html = f'<link rel="icon" href="data:image/png;base64,{donnees}">'
    premier = logic.candidates(html, HOME, "https://example.com/favicon.ico")[0]
    assert premier == {"data": PNG, "source": "data"}


# --- Module -------------------------------------------------------------------------------------


def _lancer(http_simule, contexte, outils, routes):
    http_simule(routes)
    valeur = outils.executer(SPEC, contexte())
    outils.verifier_sortie(valeur)
    return valeur


def test_succes_icone_declaree(http_simule, contexte, outils):
    valeur = _lancer(
        http_simule,
        contexte,
        outils,
        {
            HOME: (200, {}, '<html><head><link rel="icon" href="/static/fav.png"></head></html>'),
            "https://example.com/static/fav.png": (200, {"Content-Type": "image/png"}, PNG),
        },
    )
    assert valeur["found"] is True and valeur["source"] == "link"
    assert valeur["hash_mmh3"] == PNG_MMH3 and valeur["size_bytes"] == len(PNG)
    assert valeur["queries"]["shodan"] == f"http.favicon.hash:{PNG_MMH3}"
    assert valeur["content_type"] == "image/png"


def test_repli_sur_favicon_ico(http_simule, contexte, outils):
    valeur = _lancer(
        http_simule,
        contexte,
        outils,
        {HOME: (200, {}, "<html></html>"), "https://example.com/favicon.ico": (200, {}, ICO)},
    )
    assert valeur["found"] is True and valeur["source"] == "default"
    assert valeur["favicon_url"] == "https://example.com/favicon.ico"


def test_page_html_servie_a_la_place_du_favicon_n_est_pas_hachee(http_simule, contexte, outils):
    """Un « soft 404 » (HTML, code 200) ne doit pas donner de fausse empreinte."""
    valeur = _lancer(
        http_simule,
        contexte,
        outils,
        {
            HOME: (200, {}, "<html></html>"),
            "https://example.com/favicon.ico": (
                200,
                {"Content-Type": "text/html"},
                "<html>Introuvable</html>",
            ),
        },
    )
    assert valeur["found"] is False and valeur["tried"][0]["status"] == 200
    assert "hash_mmh3" not in valeur


def test_favicon_absent_404(http_simule, contexte, outils):
    valeur = _lancer(
        http_simule,
        contexte,
        outils,
        {HOME: (200, {}, "<html></html>"), "https://example.com/favicon.ico": (404, {}, "")},
    )
    assert valeur["found"] is False


def test_favicon_trop_gros_ignore(http_simule, contexte, outils):
    gros = b"\x00\x00\x01\x00" + b"0" * (logic.MAX_FAVICON_BYTES + 10)
    valeur = _lancer(
        http_simule,
        contexte,
        outils,
        {HOME: (200, {}, "<html></html>"), "https://example.com/favicon.ico": (200, {}, gros)},
    )
    assert valeur["found"] is False


def test_icone_data_sans_requete(http_simule, contexte, outils):
    donnees = base64.b64encode(PNG).decode()
    requetes = http_simule({HOME: (200, {}, f'<link rel="icon" href="data:image/png;base64,{donnees}">')})
    valeur = outils.executer(SPEC, contexte())
    assert valeur["found"] is True and valeur["source"] == "data" and valeur["hash_mmh3"] == PNG_MMH3
    assert [str(r.url).rstrip("/") for r in requetes] == ["https://example.com"]


def test_aucune_adresse_ne_repond(http_simule, contexte):
    http_simule(
        {HOME: (200, {}, "<html></html>"), "https://example.com/favicon.ico": httpx.ReadTimeout("délai")}
    )
    with pytest.raises(ModuleError):
        asyncio.run(SPEC.run(contexte()))


def test_site_injoignable(http_simule, contexte):
    http_simule({})
    with pytest.raises(ModuleError):
        asyncio.run(SPEC.run(contexte()))


def test_declaration():
    assert SPEC.family == "web" and SPEC.category == "passif" and not SPEC.findings
