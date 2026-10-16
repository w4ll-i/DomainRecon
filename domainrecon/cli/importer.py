# =============================================================================
# DomainRecon - Ligne de commande : domainrecon import <ancienne base .db>
# =============================================================================
# Importe les scans d'une ancienne base DomainRecon (SQLite, table « scans »).
# La base source est ouverte en lecture seule. Les colonnes du schéma d'origine
# sont rapprochées de celles du schéma actuel (même nom, ancien nom, alias) ;
# les valeurs JSON stockées en texte sont décodées, celles qui n'ont pas la forme
# attendue sont laissées vides. Un scan déjà présent (même domaine, même
# horodatage) est ignoré : l'import peut être relancé sans doublon. Les captures
# d'écran ne sont pas importées (leurs fichiers ne sont pas dans cette base).
#
# La même logique sert l'interface : POST /api/import (api/routes/importer.py)
# copie la base envoyée dans un fichier temporaire et appelle import_scans(). Les
# lignes sont lues au fil de l'eau (pas toute la base en mémoire) et une base
# inutilisable lève ImportSourceError, dont `reason` donne la cause.
# =============================================================================

from __future__ import annotations

import argparse
import json
import sqlite3
from collections.abc import Iterator
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from ._common import CliError, open_storage

BATCH_SIZE = 200

# Les 16 premiers octets de tout fichier SQLite.
SQLITE_HEADER = b"SQLite format 3\x00"

# Causes d'un refus (ImportSourceError.reason).
REASON_NOT_FOUND = "not_found"
REASON_CURRENT = "current_database"
REASON_NOT_SQLITE = "not_sqlite"
REASON_NOT_DOMAINRECON = "not_domainrecon"

# Anciens noms de colonnes -> colonne actuelle (appliqué si la cible manque à la source).
ALIASES = {
    "reverse_dns_data": "reverse_dns",
    "target": "domain",
    "hostname": "domain",
    "url": "domain",
    "ip": "ip_address",
    "timestamp": "scan_timestamp",
    "created_at": "scan_timestamp",
    "scanned_at": "scan_timestamp",
    "date": "scan_timestamp",
    "whois": "whois_data",
    "geo": "geo_data",
    "geolocation": "geo_data",
    "ssl": "tls_certificate",
    "ssl_certificate": "tls_certificate",
    "tls": "tls_certificate",
    "ports": "open_ports",
    "headers": "security_headers",
    "dns": "dns_records",
    "score": "security_score",
    "duration": "scan_duration",
    "error": "error_message",
}

LIST_COLUMNS = frozenset(
    {"subdomains", "open_ports", "technologies", "subdomain_takeover", "tags", "modules_launched"}
)
TEXT_COLUMNS = frozenset({"notes", "profile"})
# Colonnes jamais reprises : identifiant propre à la base d'origine, fichiers de capture absents.
SKIPPED_COLUMNS = frozenset({"id", "screenshot_path"})


class ImportSourceError(CliError):
    """Base à importer inutilisable ; `reason` dit pourquoi (REASON_*), le message est celui de la ligne de commande."""

    def __init__(self, message: str, reason: str) -> None:
        super().__init__(message)
        self.reason = reason


@dataclass
class ImportStats:
    read: int = 0
    imported: int = 0
    duplicates: int = 0
    ignored: int = 0
    mapped: list[str] = field(default_factory=list)
    unknown: list[str] = field(default_factory=list)


def register(subparsers) -> None:
    parser = subparsers.add_parser(
        "import",
        help="importe les scans d'une ancienne base DomainRecon",
        description="Importe les scans d'une ancienne base SQLite DomainRecon ; les doublons sont ignorés.",
    )
    parser.add_argument("database", metavar="base.db", help="ancienne base SQLite (lue en lecture seule)")
    parser.add_argument("--dry-run", action="store_true", help="compte seulement, sans rien écrire")
    parser.set_defaults(handler=run)


# --- Conversion des valeurs -------------------------------------------------------


def _json_value(value: object, want_list: bool) -> object:
    """Valeur JSON décodée si elle a la forme attendue (liste ou objet), sinon None."""
    if isinstance(value, (bytes, bytearray)):
        value = bytes(value).decode("utf-8", "replace")
    if isinstance(value, str):
        try:
            value = json.loads(value)
        except (ValueError, RecursionError):  # JSON invalide, ou imbriqué au point de dépasser la pile
            return None
    return value if isinstance(value, list if want_list else dict) else None


def _timestamp(value: object) -> datetime | None:
    """Horodatage UTC naïf (format de stockage), ou None s'il est illisible."""
    if isinstance(value, bool):
        return None
    if isinstance(value, (int, float)):
        try:
            return datetime.fromtimestamp(value, timezone.utc).replace(tzinfo=None)
        except (OverflowError, OSError, ValueError):
            return None
    if isinstance(value, str):
        text = value.strip().replace("Z", "+00:00")
        try:
            parsed = datetime.fromisoformat(text)
        except ValueError:
            return None
        if parsed.tzinfo is not None:
            parsed = parsed.astimezone(timezone.utc).replace(tzinfo=None)
        return parsed
    return None


def _number(value: object) -> float | None:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    return float(value)


def map_row(row: dict, json_columns: frozenset[str]) -> dict | None:
    """Valeurs d'un Scan actuel d'après une ligne de l'ancienne base, ou None si elle est inexploitable."""
    from ..scanner import is_valid_target, normalize_target

    values: dict = {}
    for name, raw in row.items():
        if name in SKIPPED_COLUMNS:
            continue
        values[name] = raw
    domain = values.get("domain")
    if not isinstance(domain, str) or not domain.strip():
        return None
    target = normalize_target(domain)
    domain = target if is_valid_target(target) else domain.strip()
    stamp = _timestamp(values.get("scan_timestamp"))
    if stamp is None:
        return None

    out: dict = {"domain": domain[:255], "scan_timestamp": stamp}
    ip = values.get("ip_address")
    out["ip_address"] = ip.strip()[:45] if isinstance(ip, str) and ip.strip() else None
    status = values.get("status")
    out["status"] = status.strip()[:50] if isinstance(status, str) and status.strip() else "success"
    out["scan_duration"] = _number(values.get("scan_duration"))
    error = values.get("error_message")
    if isinstance(error, (dict, list)):
        error = json.dumps(error, ensure_ascii=False)
    out["error_message"] = error if isinstance(error, str) and error else None

    for name in json_columns:
        if name not in values:
            continue
        raw = values[name]
        if name == "security_score" and isinstance(raw, (int, float)) and not isinstance(raw, bool):
            out[name] = {"score": raw}
        elif name == "tags":
            decoded = _json_value(raw, True)
            out[name] = [str(t) for t in decoded] if decoded is not None else None
        elif name == "modules_launched":
            decoded = _json_value(raw, True)
            ok = decoded is not None and all(isinstance(n, str) for n in decoded)
            out[name] = decoded if ok else None
        else:
            out[name] = _json_value(raw, name in LIST_COLUMNS)
    for name in TEXT_COLUMNS:
        raw = values.get(name)
        out[name] = raw if isinstance(raw, str) and raw else None
    return out


# --- Import -----------------------------------------------------------------------


def _current_columns() -> tuple[set[str], frozenset[str]]:
    """Colonnes (noms d'attributs) du modèle actuel, et celles de type JSON."""
    from sqlalchemy import JSON

    from ..core.models import Scan

    columns = {a.key for a in Scan.__mapper__.column_attrs}
    json_columns = frozenset(
        a.key for a in Scan.__mapper__.column_attrs if isinstance(a.columns[0].type, JSON)
    )
    return columns, json_columns


class _Source:
    """Ancienne base ouverte en lecture seule : colonnes rapprochées du schéma actuel, lignes lues au fil de l'eau.

    Le fichier doit commencer par l'en-tête SQLite et contenir une vraie table « scans » avec une colonne de
    domaine et une de date (nom actuel, ancien nom ou alias). `trusted_schema` est coupé : le schéma d'un
    fichier reçu ne peut pas appeler de fonction SQL dangereuse (vue, déclencheur, colonne calculée).
    À fermer (`with`) avant de supprimer le fichier : Windows ne supprime pas un fichier ouvert.
    """

    def __init__(self, path: Path, current: set[str]) -> None:
        self.path = path
        self.rename: dict[str, str] = {}
        self.unknown: list[str] = []
        self._check_header()
        try:
            self._conn = sqlite3.connect(f"{path.resolve().as_uri()}?mode=ro", uri=True)
        except sqlite3.Error as exc:
            raise ImportSourceError(f"Base illisible : {exc}", REASON_NOT_SQLITE) from exc
        try:
            self._conn.row_factory = sqlite3.Row
            # Un texte qui n'est pas de l'UTF-8 valide (ancienne base, fichier abîmé) ne doit pas arrêter l'import.
            self._conn.text_factory = lambda raw: raw.decode("utf-8", "replace")
            self._match_columns(current)
        except BaseException:
            self._conn.close()
            raise

    def __enter__(self) -> _Source:
        return self

    def __exit__(self, *exc_info) -> None:
        self.close()

    def close(self) -> None:
        self._conn.close()

    def _unreadable(self, exc: sqlite3.DatabaseError) -> ImportSourceError:
        return ImportSourceError(
            f"{self.path.name} n'est pas une base SQLite lisible ({exc}).", REASON_NOT_SQLITE
        )

    def _check_header(self) -> None:
        try:
            with self.path.open("rb") as handle:
                header = handle.read(len(SQLITE_HEADER))
        except OSError as exc:
            raise ImportSourceError(f"Base illisible : {exc.strerror or exc}", REASON_NOT_SQLITE) from exc
        if header != SQLITE_HEADER:
            raise ImportSourceError(
                f"{self.path.name} n'est pas une base SQLite lisible (en-tête SQLite absent).",
                REASON_NOT_SQLITE,
            )

    def _match_columns(self, current: set[str]) -> None:
        conn = self._conn
        try:
            conn.execute("PRAGMA trusted_schema = OFF")
            kind = conn.execute(
                "SELECT type FROM sqlite_master WHERE name = 'scans' COLLATE NOCASE"
            ).fetchone()
            columns = [r["name"] for r in conn.execute("PRAGMA table_info(scans)")]
        except sqlite3.DatabaseError as exc:
            raise self._unreadable(exc) from exc
        if kind is None or kind["type"] != "table" or not columns:
            raise ImportSourceError(
                f"Aucune table « scans » dans {self.path.name} : ce n'est pas une base DomainRecon.",
                REASON_NOT_DOMAINRECON,
            )
        # Rapprochement : nom actuel d'abord, sinon ancien nom ou alias.
        for name in columns:
            if name in SKIPPED_COLUMNS:
                continue
            target = name if name in current else ALIASES.get(name.lower())
            if target is None or target not in current or target in self.rename.values():
                self.unknown.append(name)
            else:
                self.rename[name] = target
        if not {"domain", "scan_timestamp"} <= set(self.rename.values()):
            raise ImportSourceError(
                f"La table « scans » de {self.path.name} n'a pas de colonne de domaine ou de date reconnue : "
                "ce n'est pas une base DomainRecon.",
                REASON_NOT_DOMAINRECON,
            )

    def rows(self) -> Iterator[dict]:
        """Lignes de la table scans dans l'ordre d'insertion, réduites aux colonnes rapprochées."""
        try:
            for row in self._conn.execute("SELECT * FROM scans ORDER BY rowid"):
                yield {self.rename[key]: row[key] for key in row.keys() if key in self.rename}
        except sqlite3.DatabaseError as exc:
            raise self._unreadable(exc) from exc


def import_scans(path: str | Path, dry_run: bool = False) -> ImportStats:
    """Importe les scans de la base `path` dans la base courante (ImportSourceError si elle est inutilisable)."""
    from ..core.database import SessionLocal, engine
    from ..core.models import Scan

    source = Path(path)
    if not source.is_file():
        raise ImportSourceError(f"Fichier introuvable : {source}", REASON_NOT_FOUND)
    own = engine.url.database
    if own and Path(own).exists() and Path(own).resolve() == source.resolve():
        raise ImportSourceError("La base à importer est la base courante.", REASON_CURRENT)

    current, json_columns = _current_columns()
    stats = ImportStats()
    with _Source(source, current) as old, SessionLocal() as db:
        stats.mapped = [
            f"{name}->{target}" if name != target else name for name, target in old.rename.items()
        ]
        stats.unknown = old.unknown
        seen = {(d, t) for d, t in db.query(Scan.domain, Scan.scan_timestamp)}
        pending = []
        for row in old.rows():
            stats.read += 1
            values = map_row(row, json_columns)
            if values is None:
                stats.ignored += 1
                continue
            key = (values["domain"], values["scan_timestamp"])
            if key in seen:
                stats.duplicates += 1
                continue
            seen.add(key)
            stats.imported += 1
            if not dry_run:
                pending.append(Scan(**values))
                if len(pending) >= BATCH_SIZE:
                    db.add_all(pending)
                    db.commit()
                    pending = []
        if pending:
            db.add_all(pending)
            db.commit()
    return stats


def run(args: argparse.Namespace) -> int:
    open_storage()
    stats = import_scans(args.database, args.dry_run)
    verb = "à importer" if args.dry_run else "importé(s)"
    print(
        f"{stats.read} scan(s) lu(s) : {stats.imported} {verb}, {stats.duplicates} doublon(s) ignoré(s), "
        f"{stats.ignored} inexploitable(s)."
    )
    if stats.unknown:
        print(f"Colonnes sans équivalent, ignorées : {', '.join(stats.unknown)}")
    return 0
