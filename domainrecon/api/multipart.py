# =============================================================================
# DomainRecon - API : lecture en flux d'un corps multipart/form-data
# =============================================================================
# Starlette lit les formulaires avec python-multipart, qui n'est pas une
# dépendance du projet (un module de plus à embarquer dans les livrables) : la
# route d'import (routes/importer.py) lit donc son corps elle-même, avec cet
# analyseur en flux, strict et sans dépendance. Il ne garde en mémoire que le
# morceau en cours : un fichier de plusieurs centaines de Mio ne gonfle pas le
# processus. Le corps doit être complet : sans frontière finale (envoi coupé), il
# est refusé, pour qu'un fichier tronqué ne soit jamais pris pour entier.
#
# Format lu (RFC 7578, RFC 2046) :
#     [préambule] --frontière CRLF en-têtes CRLF CRLF corps CRLF --frontière … CRLF --frontière-- [épilogue]
# Les fins de ligne sont CRLF, comme dans tout envoi de navigateur ou de client HTTP.
# =============================================================================

import re
from dataclasses import dataclass

# Bornes d'un formulaire : taille des en-têtes d'une partie, nombre de parties,
# longueur de la frontière (la RFC 2046 en autorise 70) et blancs tolérés après une frontière.
MAX_HEADER_BYTES = 16 * 1024
MAX_PARTS = 16
MAX_BOUNDARY_LENGTH = 200
_MAX_PADDING = 128


class MultipartError(ValueError):
    """Corps multipart/form-data mal formé, tronqué ou hors des bornes."""


# --- En-têtes ------------------------------------------------------------------------------

# Paramètre d'un en-tête : `; nom="valeur entre guillemets"` ou `; nom=jeton`.
_PARAM_RE = re.compile(r';\s*([^\s=;"]+)\s*=\s*(?:"((?:[^"\\]|\\.)*)"|([^\s;"]*))')
_ESCAPE_RE = re.compile(r"\\(.)")


def header_params(value: str) -> dict[str, str]:
    """Paramètres d'un en-tête (`form-data; name="file"; filename="a.db"`), noms en minuscules."""
    params: dict[str, str] = {}
    _, _, rest = value.partition(";")
    for match in _PARAM_RE.finditer(";" + rest):
        name = match.group(1).lower()
        if name in params:
            continue
        quoted, token = match.group(2), match.group(3)
        params[name] = _ESCAPE_RE.sub(r"\1", quoted) if quoted is not None else token
    return params


def boundary_of(content_type: str | None) -> bytes | None:
    """Frontière déclarée par un `Content-Type: multipart/form-data; boundary=…`, ou None si elle manque ou est invalide."""
    if not content_type:
        return None
    media_type, _, _ = content_type.partition(";")
    if media_type.strip().lower() != "multipart/form-data":
        return None
    value = header_params(content_type).get("boundary")
    # ASCII imprimable (RFC 2046) : ni saut de ligne, ni octet de commande, ni accent.
    if not value or len(value) > MAX_BOUNDARY_LENGTH or not value.isascii() or not value.isprintable():
        return None
    return value.encode("ascii")


def _parse_headers(block: bytes) -> dict[str, str]:
    """En-têtes d'une partie : noms en minuscules, valeur UTF-8 ; une ligne repliée prolonge la précédente."""
    headers: dict[str, str] = {}
    last: str | None = None
    for line in block.decode("utf-8", "replace").split("\r\n"):
        if line[:1] in (" ", "\t") and last is not None:
            headers[last] += " " + line.strip()
            continue
        name, separator, value = line.partition(":")
        name = name.strip().lower()
        if not separator or not name:
            raise MultipartError("en-tête de partie mal formé")
        headers[name] = value.strip()
        last = name
    return headers


# --- Événements ------------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class PartStart:
    """Début d'une partie : ses en-têtes (noms en minuscules)."""

    headers: dict[str, str]

    @property
    def name(self) -> str | None:
        """Nom du champ (paramètre `name` de Content-Disposition)."""
        return header_params(self.headers.get("content-disposition", "")).get("name")


@dataclass(frozen=True, slots=True)
class PartData:
    """Un morceau du corps de la partie en cours."""

    data: bytes


@dataclass(frozen=True, slots=True)
class PartEnd:
    """Fin de la partie en cours."""


Event = PartStart | PartData | PartEnd

# États de l'analyseur.
_PREAMBLE, _AFTER_BOUNDARY, _HEADERS, _BODY, _DONE = range(5)


class MultipartParser:
    """Analyseur incrémental : `feed()` reçoit les morceaux du corps et renvoie les événements reconnus.

    `finish()` s'appelle à la fin du flux et lève MultipartError si la frontière finale n'est pas
    venue. Tout ce qui suit la frontière finale (épilogue) est ignoré.
    """

    def __init__(
        self, boundary: bytes, *, max_header_bytes: int = MAX_HEADER_BYTES, max_parts: int = MAX_PARTS
    ):
        if not boundary:
            raise ValueError("frontière vide")
        self._delimiter = b"\r\n--" + boundary
        # Fin du tampon qui pourrait être le début d'une frontière coupée entre deux morceaux.
        self._keep = len(self._delimiter) - 1
        # La première frontière n'est pas précédée d'un CRLF : on le suppose, pour la chercher comme les autres.
        self._buffer = bytearray(b"\r\n")
        self._state = _PREAMBLE
        self._max_header_bytes = max_header_bytes
        self._max_parts = max_parts
        self._parts = 0

    @property
    def complete(self) -> bool:
        """Vrai une fois la frontière finale lue."""
        return self._state == _DONE

    def feed(self, data: bytes) -> list[Event]:
        """Événements que ce morceau de corps permet de reconnaître (MultipartError si le corps est invalide)."""
        events: list[Event] = []
        if self._state == _DONE:
            return events
        self._buffer += data
        while self._advance(events):
            pass
        return events

    def finish(self) -> None:
        """Fin du flux : MultipartError si le corps est tronqué."""
        if self._state != _DONE:
            raise MultipartError("corps tronqué : frontière finale absente")

    def _advance(self, events: list[Event]) -> bool:
        """Franchit une étape ; faux quand il faut attendre la suite du corps."""
        buffer = self._buffer
        if self._state == _PREAMBLE:
            index = buffer.find(self._delimiter)
            if index < 0:
                del buffer[: max(0, len(buffer) - self._keep)]  # le préambule est ignoré
                return False
            del buffer[: index + len(self._delimiter)]
            self._state = _AFTER_BOUNDARY
            return True

        if self._state == _AFTER_BOUNDARY:
            if len(buffer) < 2:
                return False
            if buffer[:2] == b"--":  # frontière finale : l'épilogue est ignoré
                buffer.clear()
                self._state = _DONE
                return False
            end = buffer.find(b"\r\n")
            if end < 0:
                if len(buffer) > _MAX_PADDING:
                    raise MultipartError("frontière suivie de données inattendues")
                return False
            if buffer[:end].strip(b" \t"):
                raise MultipartError("frontière suivie de données inattendues")
            del buffer[: end + 2]
            self._parts += 1
            if self._parts > self._max_parts:
                raise MultipartError("trop de parties dans le formulaire")
            self._state = _HEADERS
            return True

        if self._state == _HEADERS:
            if buffer.startswith(b"\r\n"):  # partie sans en-tête
                del buffer[:2]
                events.append(PartStart({}))
                self._state = _BODY
                return True
            end = buffer.find(b"\r\n\r\n")
            if end < 0 or end > self._max_header_bytes:
                if len(buffer) > self._max_header_bytes:
                    raise MultipartError("en-têtes de partie trop longs")
                return False
            block = bytes(buffer[:end])
            del buffer[: end + 4]
            events.append(PartStart(_parse_headers(block)))
            self._state = _BODY
            return True

        if self._state == _BODY:
            index = buffer.find(self._delimiter)
            if index < 0:
                safe = len(buffer) - self._keep
                if safe > 0:
                    events.append(PartData(bytes(buffer[:safe])))
                    del buffer[:safe]
                return False
            if index:
                events.append(PartData(bytes(buffer[:index])))
            events.append(PartEnd())
            del buffer[: index + len(self._delimiter)]
            self._state = _AFTER_BOUNDARY
            return True

        buffer.clear()
        return False
