#!/usr/bin/env python3
"""Génère les icônes de DomainRecon : ICO (Windows), PNG (Linux, fenêtre), SVG (interface, README).

Source unique : `logo.svg`, le logo vectoriel d'origine (traits blancs, fond
transparent, grille de 250 x 250). Il est posé sur une pastille sombre aux
coins arrondis. Les PNG et l'ICO sont tracés par un petit rasteriseur intégré
(courbes de Bézier aplaties, remplissage non nul ou pair-impair, anticrénelage),
sans dépendance externe. Après un changement de `logo.svg` :
    python packaging/icons/make_icons.py
"""

from __future__ import annotations

import argparse
import math
import re
import struct
import sys
import zlib
from pathlib import Path
from xml.etree import ElementTree

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
SOURCE = HERE / "logo.svg"

BACKGROUND = (0x11, 0x11, 0x11)  # pastille
MARK = (0xFF, 0xFF, 0xFF)  # logo

ICO_SIZES = (16, 24, 32, 48, 64, 128, 256)
PNG_SIZES = (256, 128, 48)
GRID = 64.0  # grille de sortie (viewBox du SVG produit)
MARK_SIZE = 0.85  # part de la pastille occupée par le logo
SOURCE_SIZE = 250.0  # grille du SVG d'origine
LOGO_SVG_TARGETS = (
    ROOT / "frontend" / "src" / "assets" / "favicon.svg",
    ROOT / "docs" / "assets" / "logo-badge.svg",
)

Point = tuple[float, float]
Shape = tuple[list[list[Point]], bool]  # contours, True si remplissage pair-impair


def _flatten_path(d: str, steps: int = 20) -> list[list[Point]]:
    """Contours d'un chemin SVG (commandes absolues M, L, H, V, C, Z), courbes aplaties en segments."""
    tokens = re.findall(r"[MLHVCZ]|-?\d*\.?\d+(?:e-?\d+)?", d)
    contours: list[list[Point]] = []
    current: list[Point] = []
    index = 0
    command = ""
    while index < len(tokens):
        if tokens[index].isalpha():
            command = tokens[index]
            index += 1
            if command == "Z":
                if current:
                    contours.append(current)
                    current = []
                continue
        if command == "M":
            if current:
                contours.append(current)
            current = [(float(tokens[index]), float(tokens[index + 1]))]
            index += 2
            command = "L"
        elif command == "L":
            current.append((float(tokens[index]), float(tokens[index + 1])))
            index += 2
        elif command == "H":
            current.append((float(tokens[index]), current[-1][1]))
            index += 1
        elif command == "V":
            current.append((current[-1][0], float(tokens[index])))
            index += 1
        elif command == "C":
            x0, y0 = current[-1]
            x1, y1, x2, y2, x3, y3 = (float(tokens[index + k]) for k in range(6))
            index += 6
            for step in range(1, steps + 1):
                t = step / steps
                u = 1 - t
                current.append(
                    (
                        u**3 * x0 + 3 * u * u * t * x1 + 3 * u * t * t * x2 + t**3 * x3,
                        u**3 * y0 + 3 * u * u * t * y1 + 3 * u * t * t * y2 + t**3 * y3,
                    )
                )
        else:
            raise ValueError(f"commande de chemin SVG non prise en charge : {command!r}")
    if current:
        contours.append(current)
    return contours


def load_shapes(path: Path = SOURCE) -> list[Shape]:
    """Formes du logo (contours et règle de remplissage de chaque chemin)."""
    root = ElementTree.parse(path).getroot()
    shapes: list[Shape] = []
    for element in root.iter("{http://www.w3.org/2000/svg}path"):
        evenodd = element.get("fill-rule") == "evenodd"
        shapes.append((_flatten_path(element.get("d", "")), evenodd))
    return shapes


def _to_grid(point: Point) -> Point:
    """Du repère du SVG d'origine à la grille de 64 x 64, logo centré dans la pastille."""
    k = GRID * MARK_SIZE / SOURCE_SIZE
    return (GRID / 2 + (point[0] - SOURCE_SIZE / 2) * k, GRID / 2 + (point[1] - SOURCE_SIZE / 2) * k)


def _spans(shape: Shape, y: float, scale: float) -> list[tuple[float, float]]:
    """Intervalles de x (en pixels de sortie) couverts par la forme sur la ligne horizontale `y`."""
    contours, evenodd = shape
    crossings: list[tuple[float, int]] = []
    for contour in contours:
        count = len(contour)
        for i in range(count):
            ax, ay = _to_grid(contour[i])
            bx, by = _to_grid(contour[(i + 1) % count])
            ax, ay, bx, by = ax * scale, ay * scale, bx * scale, by * scale
            if ay == by:
                continue
            if (ay <= y < by) or (by <= y < ay):
                crossings.append((ax + (y - ay) / (by - ay) * (bx - ax), 1 if by > ay else -1))
    crossings.sort()
    spans: list[tuple[float, float]] = []
    winding = 0
    start = 0.0
    for x, direction in crossings:
        inside_before = (winding % 2 != 0) if evenodd else (winding != 0)
        winding += direction
        inside_after = (winding % 2 != 0) if evenodd else (winding != 0)
        if not inside_before and inside_after:
            start = x
        elif inside_before and not inside_after:
            spans.append((start, x))
    return spans


def _coverage_rows(size: int) -> list[list[float]]:
    """Couverture du logo (0 à 1) pour chaque pixel d'une image `size` x `size`."""
    shapes = load_shapes()
    sub = 6  # lignes de balayage par pixel
    scale = size / GRID
    rows: list[list[float]] = []
    for j in range(size):
        row = [0.0] * size
        for k in range(sub):
            y = j + (k + 0.5) / sub
            merged: list[tuple[float, float]] = []
            for shape in shapes:
                merged.extend(_spans(shape, y, scale))
            merged.sort()
            union: list[list[float]] = []
            for a, b in merged:  # union des formes : un recouvrement ne compte qu'une fois
                if union and a <= union[-1][1]:
                    union[-1][1] = max(union[-1][1], b)
                else:
                    union.append([a, b])
            for a, b in union:
                a, b = max(a, 0.0), min(b, float(size))
                if b <= a:
                    continue
                first, last = int(a), min(int(b), size - 1)
                for i in range(first, last + 1):
                    row[i] += (min(b, i + 1) - max(a, i)) / sub
        rows.append(row)
    return rows


def _rounded_square(x: float, y: float, half: float, radius: float) -> float:
    qx = abs(x) - half + radius
    qy = abs(y) - half + radius
    return math.hypot(max(qx, 0.0), max(qy, 0.0)) + min(max(qx, qy), 0.0) - radius


def _tile_coverage(distance: float) -> float:
    return min(1.0, max(0.0, 0.5 - distance))


def render(size: int) -> bytes:
    """Dessine l'icône en `size` x `size` pixels ; octets RGBA, alpha non prémultiplié."""
    s = float(size)
    mark = _coverage_rows(size)
    out = bytearray()
    for j in range(size):
        for i in range(size):
            clip = _tile_coverage(_rounded_square(i + 0.5 - s / 2, j + 0.5 - s / 2, s * 0.47, s * 0.2))
            ink = min(1.0, mark[j][i])
            color = [round(BACKGROUND[k] + (MARK[k] - BACKGROUND[k]) * ink) for k in range(3)]
            out += bytes((*color, round(clip * 255)))
    return bytes(out)


def svg_text() -> str:
    """Le même dessin en SVG (viewBox 64 x 64) : pastille arrondie sombre, chemins d'origine en blanc."""
    root = ElementTree.parse(SOURCE).getroot()
    k = GRID * MARK_SIZE / SOURCE_SIZE
    offset = GRID / 2 - SOURCE_SIZE / 2 * k
    paths = "".join(
        f'<path d="{element.get("d")}"'
        + (' fill-rule="evenodd"' if element.get("fill-rule") == "evenodd" else "")
        + "/>"
        for element in root.iter("{http://www.w3.org/2000/svg}path")
    )
    background = "#{:02x}{:02x}{:02x}".format(*BACKGROUND)
    mark = "#{:02x}{:02x}{:02x}".format(*MARK)
    return (
        '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 64 64" role="img" aria-label="DomainRecon">'
        f'<rect width="64" height="64" rx="14" fill="{background}"/>'
        f'<g fill="{mark}" transform="translate({offset:.3f} {offset:.3f}) scale({k:.5f})">{paths}</g></svg>\n'
    )


def png_bytes(size: int, rgba: bytes) -> bytes:
    """Encode une image RGBA carrée en PNG (filtre « None » sur chaque ligne)."""
    row = size * 4
    raw = b"".join(b"\x00" + rgba[y * row : (y + 1) * row] for y in range(size))

    def chunk(kind: bytes, data: bytes) -> bytes:
        crc = zlib.crc32(kind + data) & 0xFFFFFFFF
        return struct.pack(">I", len(data)) + kind + data + struct.pack(">I", crc)

    header = struct.pack(">IIBBBBB", size, size, 8, 6, 0, 0, 0)
    return (
        b"\x89PNG\r\n\x1a\n"
        + chunk(b"IHDR", header)
        + chunk(b"IDAT", zlib.compress(raw, 9))
        + chunk(b"IEND", b"")
    )


def _dib_bytes(size: int, rgba: bytes) -> bytes:
    """Image BMP 32 bits d'un ICO : BITMAPINFOHEADER, pixels BGRA de bas en haut, masque AND."""
    header = struct.pack("<IiiHHIIiiII", 40, size, size * 2, 1, 32, 0, 0, 0, 0, 0, 0)
    pixels = bytearray()
    mask = bytearray()
    mask_row = ((size + 31) // 32) * 4
    for y in range(size - 1, -1, -1):
        bits = bytearray(mask_row)
        for x in range(size):
            r, g, b, a = rgba[(y * size + x) * 4 : (y * size + x) * 4 + 4]
            pixels += bytes((b, g, r, a))
            if a < 128:
                bits[x // 8] |= 0x80 >> (x % 8)
        mask += bits
    return header + bytes(pixels) + bytes(mask)


def ico_bytes(images: dict[int, bytes]) -> bytes:
    """Assemble un .ico : PNG pour 256 px (format Vista+), BMP 32 bits pour les autres tailles."""
    sizes = sorted(images)
    payloads = [png_bytes(s, images[s]) if s >= 256 else _dib_bytes(s, images[s]) for s in sizes]
    directory = b""
    offset = 6 + 16 * len(sizes)
    for size, data in zip(sizes, payloads, strict=True):
        dimension = 0 if size >= 256 else size
        directory += struct.pack("<BBBBHHII", dimension, dimension, 0, 0, 1, 32, len(data), offset)
        offset += len(data)
    return struct.pack("<HHH", 0, 1, len(sizes)) + directory + b"".join(payloads)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="make_icons.py", description="Génère les icônes de DomainRecon.")
    parser.add_argument(
        "--output", type=Path, default=HERE, help="dossier des icônes (défaut : packaging/icons)"
    )
    parser.add_argument(
        "--window-icon",
        type=Path,
        default=ROOT / "domainrecon" / "desktop" / "icon.png",
        help="icône de la fenêtre pywebview (défaut : domainrecon/desktop/icon.png)",
    )
    args = parser.parse_args(argv)
    args.output.mkdir(parents=True, exist_ok=True)
    images = {size: render(size) for size in ICO_SIZES}
    (args.output / "domainrecon.ico").write_bytes(ico_bytes(images))
    for size in PNG_SIZES:
        (args.output / f"domainrecon-{size}.png").write_bytes(png_bytes(size, images[size]))
    args.window_icon.parent.mkdir(parents=True, exist_ok=True)
    args.window_icon.write_bytes(png_bytes(256, images[256]))
    for target in LOGO_SVG_TARGETS:
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(svg_text(), encoding="utf-8", newline="\n")
    print(f"Icônes écrites dans {args.output}, {args.window_icon} et {len(LOGO_SVG_TARGETS)} SVG")
    return 0


if __name__ == "__main__":
    sys.exit(main())
