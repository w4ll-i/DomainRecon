# =============================================================================
# DomainRecon - Tests de l'analyseur multipart/form-data (api/multipart.py)
# =============================================================================
# Frontière, en-têtes, découpage du corps en morceaux quelconques (la frontière
# peut être coupée n'importe où), corps tronqués ou mal formés. Les corps réalistes
# sont fabriqués par httpx, qui encode les formulaires comme le fait un client.
# =============================================================================

import random

import httpx
import pytest

from domainrecon.api.multipart import (
    MultipartError,
    MultipartParser,
    PartData,
    PartStart,
    boundary_of,
    header_params,
)

BOUNDARY = b"frontiere-de-test"


def _corps(*parties: tuple[dict[str, str], bytes], boundary: bytes = BOUNDARY, avant=b"", apres=b"") -> bytes:
    """Corps multipart écrit à la main : une partie = (en-têtes, contenu)."""
    sortie = bytearray(avant)
    for en_tetes, contenu in parties:
        sortie += b"--" + boundary + b"\r\n"
        for nom, valeur in en_tetes.items():
            sortie += f"{nom}: {valeur}\r\n".encode()
        sortie += b"\r\n" + contenu + b"\r\n"
    sortie += b"--" + boundary + b"--\r\n" + apres
    return bytes(sortie)


def _lire(corps: bytes, *, boundary: bytes = BOUNDARY, morceau: int | None = None, **options):
    """Passe le corps à l'analyseur par morceaux de `morceau` octets (d'un coup par défaut) ; renvoie [(en-têtes, contenu)]."""
    analyseur = MultipartParser(boundary, **options)
    morceau = morceau or max(1, len(corps))
    parties: list[tuple[dict, bytearray]] = []
    for debut in range(0, len(corps), morceau):
        for evenement in analyseur.feed(corps[debut : debut + morceau]):
            if isinstance(evenement, PartStart):
                parties.append((evenement.headers, bytearray()))
            elif isinstance(evenement, PartData):
                parties[-1][1].extend(evenement.data)
    analyseur.finish()
    assert analyseur.complete
    return [(en_tetes, bytes(contenu)) for en_tetes, contenu in parties]


DISPOSITION = {"Content-Disposition": 'form-data; name="file"; filename="ancienne.db"'}


# --- Frontière et paramètres d'en-tête -----------------------------------------------------


@pytest.mark.parametrize(
    ("valeur", "attendu"),
    [
        ("multipart/form-data; boundary=abc123", b"abc123"),
        ("Multipart/Form-Data; Boundary=abc123", b"abc123"),
        ('multipart/form-data; boundary="abc 123"', b"abc 123"),
        (
            "multipart/form-data; charset=utf-8; boundary=----WebKitFormBoundaryAbC9",
            b"----WebKitFormBoundaryAbC9",
        ),
        ("multipart/form-data;boundary=a-b_c.d=", b"a-b_c.d="),
        ('multipart/form-data; boundary="a\\"b"', b'a"b'),
        # Invalide : autre type, frontière absente, vide, trop longue, non ASCII, saut de ligne.
        ("multipart/mixed; boundary=abc", None),
        ("application/json", None),
        ("multipart/form-data", None),
        ("multipart/form-data; boundary=", None),
        ('multipart/form-data; boundary=""', None),
        (f"multipart/form-data; boundary={'x' * 201}", None),
        ('multipart/form-data; boundary="é"', None),
        ('multipart/form-data; boundary="a\nb"', None),
        ("", None),
        (None, None),
    ],
)
def test_frontiere_du_content_type(valeur, attendu):
    assert boundary_of(valeur) == attendu


def test_parametres_d_en_tete():
    assert header_params('form-data; name="file"; filename="a b.db"') == {
        "name": "file",
        "filename": "a b.db",
    }
    assert header_params("form-data; NAME=file") == {"name": "file"}
    assert header_params('form-data; name="a\\"b\\\\c"') == {"name": 'a"b\\c'}
    assert header_params('form-data; name="un"; name="deux"') == {"name": "un"}
    assert header_params("form-data") == {}
    assert header_params("") == {}


# --- Analyse ----------------------------------------------------------------------------------


def test_un_fichier():
    contenu = bytes(range(256)) * 20
    ((en_tetes, recu),) = _lire(_corps((DISPOSITION | {"Content-Type": "application/octet-stream"}, contenu)))
    assert recu == contenu
    assert en_tetes["content-disposition"] == DISPOSITION["Content-Disposition"]
    assert en_tetes["content-type"] == "application/octet-stream"


def test_nom_du_champ():
    analyseur = MultipartParser(BOUNDARY)
    debut = [e for e in analyseur.feed(_corps((DISPOSITION, b"x"))) if isinstance(e, PartStart)]
    assert [p.name for p in debut] == ["file"]
    assert PartStart({}).name is None
    assert PartStart({"content-disposition": "attachment"}).name is None


def test_plusieurs_parties_dans_l_ordre():
    corps = _corps(
        ({"Content-Disposition": 'form-data; name="titre"'}, "Ancienne base é".encode()),
        (DISPOSITION, b"\x00\x01\r\n\x02"),
        ({"Content-Disposition": 'form-data; name="vide"'}, b""),
    )
    parties = _lire(corps)
    assert [(header_params(h["content-disposition"])["name"], c) for h, c in parties] == [
        ("titre", "Ancienne base é".encode()),
        ("file", b"\x00\x01\r\n\x02"),
        ("vide", b""),
    ]


def test_preambule_et_epilogue_ignores():
    corps = _corps(
        (DISPOSITION, b"donnees"),
        avant=b"ceci est un preambule\r\nsans importance\r\n",
        apres=b"\r\nepilogue",
    )
    ((en_tetes, contenu),) = _lire(corps)
    assert contenu == b"donnees" and header_params(en_tetes["content-disposition"])["name"] == "file"
    # Aussi lorsque le préambule et l'épilogue arrivent par petits morceaux.
    assert _lire(corps, morceau=3)[0][1] == b"donnees"


def test_corps_commencant_par_un_saut_de_ligne():
    assert _lire(b"\r\n" + _corps((DISPOSITION, b"abc")))[0][1] == b"abc"


def test_partie_sans_en_tete():
    corps = b"--" + BOUNDARY + b"\r\n\r\ncontenu brut\r\n--" + BOUNDARY + b"--\r\n"
    assert _lire(corps) == [({}, b"contenu brut")]


def test_espaces_apres_la_frontiere_toleres():
    corps = (
        b"--"
        + BOUNDARY
        + b"  \t\r\n"
        + b'Content-Disposition: form-data; name="a"\r\n\r\nx\r\n--'
        + BOUNDARY
        + b"--"
    )
    assert _lire(corps)[0][1] == b"x"


def test_en_tete_replie_sur_deux_lignes():
    corps = _corps(({"Content-Disposition": 'form-data;\r\n name="file"'}, b"x"))
    # « \r\n » dans la valeur écrite par _corps termine la ligne : l'en-tête suivant commence par un espace.
    ((en_tetes, _),) = _lire(corps)
    assert header_params(en_tetes["content-disposition"]) == {"name": "file"}


def test_contenu_qui_ressemble_a_une_frontiere():
    """Un début de frontière dans les données (tirets, CRLF, préfixe de la frontière) ne coupe pas la partie."""
    pieges = [
        b"\r\n--",
        b"\r\n--frontiere",
        b"\r\n-",
        b"--" + BOUNDARY,  # sans CRLF devant : pas une frontière
        b"\r\n--" + BOUNDARY[:-1],  # frontière incomplète
        b"\r\n\r\n--",
        b"\r",
        b"\n--" + BOUNDARY,
    ]
    contenu = b"debut" + b"#".join(pieges) + b"fin\r\n"
    assert b"\r\n--" + BOUNDARY not in contenu  # aucun piège ne forme une vraie frontière
    for morceau in (None, 1, 2, 3, 7, 64):
        assert _lire(_corps((DISPOSITION, contenu)), morceau=morceau)[0][1] == contenu, morceau


def test_frontiere_coupee_a_chaque_position():
    contenu = b"AAAA" + b"x" * 50 + b"ZZZZ"
    corps = _corps((DISPOSITION, contenu), (DISPOSITION | {}, b"second"))
    for morceau in range(1, len(corps) + 1):
        parties = _lire(corps, morceau=morceau)
        assert [c for _, c in parties] == [contenu, b"second"], morceau


def test_decoupages_aleatoires_d_un_corps_binaire():
    hasard = random.Random(20261015)
    for _ in range(40):
        contenu = hasard.randbytes(hasard.randrange(0, 3000))
        # Des séquences proches de la frontière, pour la mettre à l'épreuve.
        for _ in range(hasard.randrange(0, 6)):
            position = hasard.randrange(0, len(contenu) + 1)
            piege = hasard.choice(
                [b"\r\n--" + BOUNDARY[: hasard.randrange(0, len(BOUNDARY))], b"\r\n", b"--"]
            )
            contenu = contenu[:position] + piege + contenu[position:]
        if b"\r\n--" + BOUNDARY in contenu:  # un piège qui forme une vraie frontière : sans objet
            continue
        corps = _corps((DISPOSITION, contenu))
        analyseur = MultipartParser(BOUNDARY)
        recu = bytearray()
        position = 0
        while position < len(corps):
            taille = hasard.randrange(1, 200)
            for evenement in analyseur.feed(corps[position : position + taille]):
                if isinstance(evenement, PartData):
                    recu.extend(evenement.data)
            position += taille
        analyseur.finish()
        assert bytes(recu) == contenu


@pytest.mark.parametrize("taille", [0, 1, 1000, 70_000, 300_000])
def test_formulaire_fabrique_par_httpx(taille):
    contenu = random.Random(taille).randbytes(taille)
    requete = httpx.Request(
        "POST",
        "http://testserver/api/import",
        files={"file": ("ancienne base.db", contenu, "application/octet-stream")},
        data={"commentaire": "é"},
    )
    boundary = boundary_of(requete.headers["content-type"])
    assert boundary is not None
    corps = requete.read()
    for morceau in (None, 4096, 65536, 7):
        parties = _lire(corps, boundary=boundary, morceau=morceau)
        champs = {header_params(h["content-disposition"])["name"]: c for h, c in parties}
        assert champs == {"file": contenu, "commentaire": "é".encode()}


def test_aucune_partie():
    assert _lire(b"--" + BOUNDARY + b"--\r\n") == []


# --- Corps invalides ----------------------------------------------------------------------------


def test_corps_tronque_refuse():
    corps = _corps((DISPOSITION, b"x" * 100))
    # Les deux dernières coupes laissent la frontière finale incomplète (un octet de la frontière
    # manque, puis un seul des deux tirets).
    for coupe in (0, 5, 40, len(corps) // 2, len(corps) - 6, len(corps) - 3):
        analyseur = MultipartParser(BOUNDARY)
        analyseur.feed(corps[:coupe])
        assert not analyseur.complete
        with pytest.raises(MultipartError, match="tronqué"):
            analyseur.finish()


def test_frontiere_suivie_de_donnees_refusee():
    corps = b"--" + BOUNDARY + b"suffixe\r\n\r\nx\r\n--" + BOUNDARY + b"--"
    with pytest.raises(MultipartError):
        _lire(corps)
    # Frontière que rien ne termine : trop d'octets sans fin de ligne.
    analyseur = MultipartParser(BOUNDARY)
    with pytest.raises(MultipartError):
        analyseur.feed(b"--" + BOUNDARY + b" " * 500)


def test_en_tete_mal_forme_refuse():
    corps = b"--" + BOUNDARY + b"\r\nsans deux-points\r\n\r\nx\r\n--" + BOUNDARY + b"--"
    with pytest.raises(MultipartError, match="en-tête"):
        _lire(corps)


def test_en_tetes_trop_longs_refuses():
    corps = b"--" + BOUNDARY + b"\r\nX-Gros: " + b"a" * 5000 + b"\r\n\r\nx\r\n--" + BOUNDARY + b"--"
    with pytest.raises(MultipartError, match="trop longs"):
        _lire(corps, max_header_bytes=1000)
    with pytest.raises(MultipartError, match="trop longs"):
        _lire(corps, max_header_bytes=1000, morceau=16)
    assert _lire(corps, max_header_bytes=10_000)[0][1] == b"x"


def test_trop_de_parties_refusees():
    parties = [({"Content-Disposition": f'form-data; name="p{i}"'}, b"x") for i in range(5)]
    corps = _corps(*parties)
    with pytest.raises(MultipartError, match="trop de parties"):
        _lire(corps, max_parts=4)
    assert len(_lire(corps, max_parts=5)) == 5


def test_rien_n_est_garde_en_memoire_au_dela_du_morceau_en_cours():
    analyseur = MultipartParser(BOUNDARY)
    analyseur.feed(b"--" + BOUNDARY + b"\r\n" + b'Content-Disposition: form-data; name="file"\r\n\r\n')
    for _ in range(200):
        analyseur.feed(b"x" * 65_536)
        assert len(analyseur._buffer) < len(BOUNDARY) + 8


def test_donnees_apres_la_frontiere_finale_ignorees():
    analyseur = MultipartParser(BOUNDARY)
    analyseur.feed(_corps((DISPOSITION, b"x")))
    assert analyseur.complete
    assert analyseur.feed(b"n'importe quoi" * 1000) == []
    analyseur.finish()


def test_frontiere_vide_refusee():
    with pytest.raises(ValueError):
        MultipartParser(b"")
