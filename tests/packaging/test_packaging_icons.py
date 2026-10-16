"""Icônes de DomainRecon : dessin, PNG, ICO et fichiers générés."""

import struct
import zlib
from pathlib import Path

from pkgload import load

ROOT = Path(__file__).resolve().parents[2]
ICONS = ROOT / "packaging" / "icons"


make_icons = load("make_icons", "icons/make_icons.py")


def _png_size(data: bytes) -> tuple[int, int]:
    assert data[:8] == b"\x89PNG\r\n\x1a\n"
    assert data[12:16] == b"IHDR"
    return struct.unpack(">II", data[16:24])


def test_render_taille_transparence_et_dessin():
    rgba = make_icons.render(64)
    assert len(rgba) == 64 * 64 * 4
    assert rgba[3] == 0  # coin haut gauche : hors du carré arrondi, transparent
    pixels = {tuple(rgba[i : i + 4]) for i in range(0, len(rgba), 4)}
    assert (*make_icons.BACKGROUND, 255) in pixels  # pastille
    assert (*make_icons.MARK, 255) in pixels  # traits du logo
    assert len(pixels) > 3  # bords anticrénelés, pas un aplat


def test_logo_source_et_svg():
    shapes = make_icons.load_shapes()
    assert len(shapes) == 5  # les 5 chemins du logo d'origine
    assert sum(1 for _, evenodd in shapes if evenodd) == 1  # l'anneau central, creux
    svg = make_icons.svg_text()
    assert svg.startswith('<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 64 64"')
    assert svg.count("<path") == 5 and 'fill-rule="evenodd"' in svg
    for target in make_icons.LOGO_SVG_TARGETS:
        assert target.read_text(encoding="utf-8") == svg  # fichiers à jour


def test_png_decodable():
    data = make_icons.png_bytes(16, make_icons.render(16))
    assert _png_size(data) == (16, 16)
    (idat_length,) = struct.unpack(">I", data[33:37])
    assert data[37:41] == b"IDAT"
    raw = zlib.decompress(data[41 : 41 + idat_length])
    assert len(raw) == 16 * (1 + 16 * 4)


def test_ico_repertoire_bmp_et_png():
    data = make_icons.ico_bytes({16: make_icons.render(16), 256: make_icons.render(256)})
    assert struct.unpack("<HHH", data[:6]) == (0, 1, 2)
    first = struct.unpack("<BBBBHHII", data[6:22])
    second = struct.unpack("<BBBBHHII", data[22:38])
    assert first[:2] == (16, 16)
    assert second[:2] == (0, 0)  # 0 = 256 px
    dib = data[first[7] : first[7] + first[6]]
    assert struct.unpack("<Iii", dib[:12]) == (40, 16, 32)  # BITMAPINFOHEADER, hauteur doublée (masque)
    png = data[second[7] : second[7] + second[6]]
    assert _png_size(png) == (256, 256)


def test_fichiers_generes():
    for size in make_icons.PNG_SIZES:
        assert _png_size((ICONS / f"domainrecon-{size}.png").read_bytes()) == (size, size)
    ico = (ICONS / "domainrecon.ico").read_bytes()
    (count,) = struct.unpack("<H", ico[4:6])
    sizes = sorted(ico[6 + 16 * index] or 256 for index in range(count))
    assert sizes == sorted(make_icons.ICO_SIZES)
    assert _png_size((ROOT / "domainrecon" / "desktop" / "icon.png").read_bytes()) == (256, 256)
