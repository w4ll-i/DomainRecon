# =============================================================================
# DomainRecon - Contenu web : empreinte du favicon (logique sans réseau)
# =============================================================================
# L'empreinte « Shodan » d'un favicon est le MurmurHash3 32 bits SIGNÉ du contenu
# encodé en base64 AVEC retours à la ligne tous les 76 caractères (base64.encodebytes
# de Python, comme le fait la bibliothèque `requests` + `codecs.encode(..., "base64")`
# des outils d'OSINT). La requête de pivot est alors `http.favicon.hash:<empreinte>`
# (Shodan), `icon_hash="<empreinte>"` (FOFA) ou, pour Censys, l'empreinte MD5.
#
# Implémentation Python pure du MurmurHash3 (aucune dépendance) ; vérifiée contre
# la bibliothèque `mmh3` (voir tests). Deux précautions :
# une page HTML (« soft 404 » rendue avec le code 200) n'est pas prise pour un
# favicon, et les icônes déclarées par la page (<link rel="icon">,
# apple-touch-icon, data:) sont essayées avant /favicon.ico.
# =============================================================================

import base64
import hashlib
import re

from .wc_html_facts import PageFacts

# Taille maximale d'un favicon lu, et nombre de candidats essayés.
MAX_FAVICON_BYTES = 512 * 1024
MAX_CANDIDATES = 4

_C1 = 0xCC9E2D51
_C2 = 0x1B873593


def mmh3_32(data: bytes, seed: int = 0) -> int:
    """MurmurHash3 x86 32 bits, rendu signé (comme `mmh3.hash`)."""
    h1 = seed & 0xFFFFFFFF
    length = len(data)
    rounded_end = length & ~3
    for i in range(0, rounded_end, 4):
        k1 = int.from_bytes(data[i : i + 4], "little")
        k1 = (k1 * _C1) & 0xFFFFFFFF
        k1 = ((k1 << 15) | (k1 >> 17)) & 0xFFFFFFFF
        k1 = (k1 * _C2) & 0xFFFFFFFF
        h1 ^= k1
        h1 = ((h1 << 13) | (h1 >> 19)) & 0xFFFFFFFF
        h1 = (h1 * 5 + 0xE6546B64) & 0xFFFFFFFF
    tail = data[rounded_end:]
    k1 = 0
    if len(tail) >= 3:
        k1 ^= tail[2] << 16
    if len(tail) >= 2:
        k1 ^= tail[1] << 8
    if len(tail) >= 1:
        k1 ^= tail[0]
        k1 = (k1 * _C1) & 0xFFFFFFFF
        k1 = ((k1 << 15) | (k1 >> 17)) & 0xFFFFFFFF
        k1 = (k1 * _C2) & 0xFFFFFFFF
        h1 ^= k1
    h1 ^= length
    h1 ^= h1 >> 16
    h1 = (h1 * 0x85EBCA6B) & 0xFFFFFFFF
    h1 ^= h1 >> 13
    h1 = (h1 * 0xC2B2AE35) & 0xFFFFFFFF
    h1 ^= h1 >> 16
    return h1 - 0x100000000 if h1 >= 0x80000000 else h1


def shodan_hash(content: bytes) -> int:
    """Empreinte `http.favicon.hash` d'un contenu de favicon."""
    return mmh3_32(base64.encodebytes(content))


def fingerprints(content: bytes) -> dict:
    """Empreintes d'un favicon et requêtes de pivot pour les moteurs d'OSINT."""
    value = shodan_hash(content)
    md5 = hashlib.md5(content, usedforsecurity=False).hexdigest()
    return {
        "hash_mmh3": value,
        "md5": md5,
        "sha256": hashlib.sha256(content).hexdigest(),
        "queries": {
            "shodan": f"http.favicon.hash:{value}",
            "fofa": f'icon_hash="{value}"',
            "censys": f"services.http.response.favicons.md5_hash={md5}",
        },
    }


# --- Reconnaissance d'une image -------------------------------------------------------------------

_MAGIC = (
    (b"\x00\x00\x01\x00", "image/x-icon"),
    (b"\x00\x00\x02\x00", "image/x-icon"),
    (b"\x89PNG\r\n\x1a\n", "image/png"),
    (b"GIF87a", "image/gif"),
    (b"GIF89a", "image/gif"),
    (b"\xff\xd8\xff", "image/jpeg"),
    (b"BM", "image/bmp"),
)
_SVG_RE = re.compile(rb"<svg[\s>]", re.I)


def sniff_image(body: bytes) -> str | None:
    """Type d'image d'après les premiers octets, ou None (page HTML, texte, vide…)."""
    head = body[:16]
    for magic, kind in _MAGIC:
        if head.startswith(magic):
            return kind
    if head[:4] == b"RIFF" and body[8:12] == b"WEBP":
        return "image/webp"
    if _SVG_RE.search(body[:2048]) and b"<html" not in body[:512].lower():
        return "image/svg+xml"
    return None


# --- Candidats ----------------------------------------------------------------------------------------


def candidates(html: str, page_url: str, default_url: str) -> list[dict]:
    """Adresses de favicon à essayer, par ordre de préférence : {url, source} ou {data, source}.

    1. <link rel="icon"> et « shortcut icon » ; 2. apple-touch-icon, mask-icon ;
    3. /favicon.ico (celui du navigateur). Une icône « data: » est lue sans requête.
    """
    facts = PageFacts.parse(html or "", page_url)
    primary: list[dict] = []
    secondary: list[dict] = []
    for link in facts.links:
        rels = link["rel"].split()
        if not link["href"] or "icon" not in " ".join(rels):
            continue
        href = link["href"]
        if href.lower().startswith("data:"):
            decoded = _decode_data_uri(href)
            if decoded is not None:
                primary.append({"data": decoded, "source": "data"})
            continue
        url = facts.resolve(href)
        if not url:
            continue
        bucket = secondary if any(r.startswith(("apple-touch", "mask")) for r in rels) else primary
        bucket.append({"url": url, "source": "link"})
    default = [{"url": default_url, "source": "default"}]
    ordered: list[dict] = []
    seen: set[str] = set()
    for item in [*primary, *secondary, *default]:
        key = item.get("url") or "data"
        if key in seen:
            continue
        seen.add(key)
        ordered.append(item)
    return ordered[:MAX_CANDIDATES]


_DATA_URI_RE = re.compile(r"data:([^;,]*)(;base64)?,(.*)", re.S | re.I)


def _decode_data_uri(href: str) -> bytes | None:
    match = _DATA_URI_RE.match(href.strip())
    if not match or not match.group(2):
        return None
    try:
        data = base64.b64decode(match.group(3), validate=False)
    except ValueError:
        return None
    return data if 0 < len(data) <= MAX_FAVICON_BYTES else None
