# =============================================================================
# DomainRecon - Logique du module « smtp_security » : sonde SMTP des serveurs MX
# =============================================================================
# Connexion directe (jamais par le proxy) au port 25 de chaque MX, par une adresse IP déjà
# validée par la politique de cibles. Relève : bannière et logiciel, extensions EHLO, STARTTLS
# (version TLS, suite, certificat vérifié contre le nom du MX), méthodes AUTH annoncées avant
# et après TLS, détection d'un domaine « catch-all » et, SEULEMENT si on l'active, test de
# relais ouvert.
#
# Choix d'implémentation :
#   - smtplib n'expose pas de lecture de bannière fiable : la session est écrite à la
#     main, avec des lectures bornées ;
#   - STARTTLS : le certificat est ici validé, et une seconde connexion
#     non vérifiée en explique la raison (expiré, auto-signé, nom différent…) ;
#   - catch-all : un seul 250 ne suffit pas ; deux adresses aléatoires, et une réponse
#     temporaire (4xx, liste grise) reste « indéterminé » ;
#   - le test de relais n'usurpe jamais le domaine cible ; il est DÉSACTIVÉ
#     par défaut, n'emploie que des domaines réservés (example.org / example.net) et ne
#     va jamais jusqu'à DATA.
# Le port 25 sortant est souvent bloqué (FAI, cloud, pare-feu) : message clair, puis repli sur 587.
# Le code est bloquant (sockets) : à lancer dans un thread, avec ses propres bornes de temps.
# =============================================================================

import ipaddress
import re
import secrets
import socket
import ssl
import time
from datetime import datetime, timezone

from cryptography import x509
from cryptography.x509.oid import NameOID

from ...core import config
from ...i18n import msg
from .. import common
from .mail_provider import KIND_FORWARDING, KIND_GATEWAY, provider_of_mx

# Nom annoncé dans EHLO : domaine réservé (RFC 2606), jamais celui de la cible.
HELO_NAME = "scanner.example.org"
# Expéditeur et destinataire du test de relais : domaines réservés, distincts de la cible.
RELAY_SENDER = "relay-test@example.org"
RELAY_RECIPIENT = "relay-test@example.net"

# Variable d'environnement qui active le test de relais (désactivé par défaut).
RELAY_TEST_ENV = config.SMTP_RELAY_TEST_ENV

CONNECT_TIMEOUT = 8.0
IO_TIMEOUT = 8.0
# Durée maximale d'une sonde sur un serveur (hors établissement de la connexion TLS).
HOST_BUDGET = 25.0
MAX_REPLY_LINES = 64
MAX_REPLY_BYTES = 16384
BANNER_MAX_CHARS = 200
MAX_HOSTS = 3

# Méthodes AUTH qui transmettent le secret (ou un équivalent rejouable) en clair sans TLS.
CLEARTEXT_AUTH = frozenset({"PLAIN", "LOGIN"})

# Codes d'erreur de vérification OpenSSL (X509_V_ERR_*) regroupés.
_VERIFY_EXPIRED = {10}
_VERIFY_SELF_SIGNED = {18, 19}
_VERIFY_UNTRUSTED = {20, 21}
_VERIFY_HOSTNAME = {62}

# Messages d'erreur d'une sonde, par code (littéraux : msg() exige un code littéral).
ERRORS = {
    "timeout": msg("smtp_security.err_timeout"),
    "refused": msg("smtp_security.err_refused"),
    "unreachable": msg("smtp_security.err_unreachable"),
    "blocked": msg("smtp_security.err_blocked"),
    "banner_refused": msg("smtp_security.err_banner_refused"),
    "protocol": msg("smtp_security.err_protocol"),
    "closed": msg("smtp_security.err_closed"),
    "ehlo_rejected": msg("smtp_security.err_ehlo_rejected"),
}
# Erreurs de connexion : le port est filtré ou fermé, le serveur n'a pas été examiné.
CONNECTION_ERRORS = frozenset({"timeout", "refused", "unreachable"})

_BANNER_PATTERNS = (
    ("Postfix", re.compile(r"\bpostfix\b", re.I)),
    ("Exim", re.compile(r"\bexim\s+(\d[\w.]*)", re.I)),
    ("Sendmail", re.compile(r"\bsendmail\s+(\d[\w./]*)", re.I)),
    ("Microsoft Exchange", re.compile(r"microsoft esmtp mail service(?:,\s*version:\s*(\d[\w.]*))?", re.I)),
    ("qmail", re.compile(r"\bqmail\b", re.I)),
    ("OpenSMTPD", re.compile(r"\bopensmtpd\b", re.I)),
    ("Haraka", re.compile(r"\bharaka\b", re.I)),
    ("Zimbra", re.compile(r"\bzimbra\b", re.I)),
    ("Courier", re.compile(r"\bcourier\b", re.I)),
    ("hMailServer", re.compile(r"\bhmailserver\b", re.I)),
    ("IceWarp", re.compile(r"\bicewarp\b", re.I)),
    ("MailEnable", re.compile(r"\bmailenable\b", re.I)),
    ("Google", re.compile(r"\bgsmtp\b", re.I)),
)


class SmtpError(Exception):
    """Échec du dialogue SMTP ; `code` : timeout, closed ou protocol."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


def relay_test_enabled() -> bool:
    """Le test de relais ouvert est-il activé ? Non par défaut (DOMAINRECON_SMTP_RELAY_TEST=1)."""
    return config.smtp_relay_test_enabled()


# =============================================================================
# Connexion et dialogue
# =============================================================================


def connect_socket(ip: str, port: int, timeout: float) -> socket.socket:
    """Connexion TCP directe à une IP déjà validée. Point d'injection des tests."""
    family = socket.AF_INET6 if ipaddress.ip_address(ip).version == 6 else socket.AF_INET
    sock = socket.socket(family, socket.SOCK_STREAM)
    try:
        sock.settimeout(timeout)
        sock.connect((ip, port))
    except BaseException:
        sock.close()
        raise
    return sock


class Session:
    """Dialogue SMTP sur une socket (claire ou TLS), avec lectures bornées et échéance globale."""

    def __init__(self, sock: socket.socket, deadline: float) -> None:
        self.sock = sock
        self.deadline = deadline
        self._buffer = b""

    def _timeout(self) -> float:
        remaining = self.deadline - time.monotonic()
        if remaining <= 0:
            raise SmtpError("timeout")
        return min(IO_TIMEOUT, remaining)

    def _read_line(self, received: int) -> bytes:
        while b"\n" not in self._buffer:
            if received + len(self._buffer) > MAX_REPLY_BYTES:
                raise SmtpError("protocol")
            self.sock.settimeout(self._timeout())
            try:
                chunk = self.sock.recv(4096)
            except TimeoutError:
                raise SmtpError("timeout") from None
            except OSError:
                raise SmtpError("closed") from None
            if not chunk:
                raise SmtpError("closed")
            self._buffer += chunk
        line, _, self._buffer = self._buffer.partition(b"\n")
        return line.rstrip(b"\r")

    def read_reply(self) -> tuple[int, list[str]]:
        """Réponse complète (lignes « 250- » puis « 250 ») : (code, textes sans le code)."""
        lines: list[str] = []
        received = 0
        while len(lines) < MAX_REPLY_LINES:
            raw = self._read_line(received)
            received += len(raw) + 2
            text = raw.decode("utf-8", errors="replace")
            if len(text) < 3 or not text[:3].isdigit():
                raise SmtpError("protocol")
            lines.append(text[4:] if len(text) > 3 else "")
            if text[3:4] != "-":
                return int(text[:3]), lines
        raise SmtpError("protocol")

    def command(self, text: str) -> tuple[int, list[str]]:
        self.sock.settimeout(self._timeout())
        try:
            self.sock.sendall(text.encode("ascii", errors="replace") + b"\r\n")
        except TimeoutError:
            raise SmtpError("timeout") from None
        except OSError:
            raise SmtpError("closed") from None
        return self.read_reply()


def parse_ehlo(lines: list[str]) -> dict:
    """Extensions annoncées par EHLO (la première ligne est le nom du serveur).

    Gère les deux écritures de AUTH : « AUTH PLAIN LOGIN » et l'ancienne « AUTH=PLAIN LOGIN ».
    """
    extensions: dict[str, str] = {}
    auth: set[str] = set()
    for line in lines[1:]:
        text = line.strip()
        keyword, _, params = text.partition(" ")
        if "=" in keyword:
            keyword, _, first = keyword.partition("=")
            params = f"{first} {params}".strip()
        keyword = keyword.upper()
        if not keyword:
            continue
        extensions.setdefault(keyword, params.strip())
        if keyword == "AUTH":
            auth.update(params.upper().split())
    size = extensions.get("SIZE", "").split(" ")[0]
    return {
        "extensions": sorted(extensions),
        "starttls": "STARTTLS" in extensions,
        "auth": sorted(auth),
        "size": int(size) if size.isdigit() else None,
    }


def parse_banner(text: str) -> dict:
    """Logiciel et version laissés par la bannière 220 (version : None si non divulguée)."""
    for name, pattern in _BANNER_PATTERNS:
        match = pattern.search(text)
        if match:
            version = match.group(1) if match.groups() and match.group(1) else None
            return {"software": name, "version": version}
    return {"software": None, "version": None}


def verify_reason(error: ssl.SSLCertVerificationError) -> str:
    """Catégorie d'un échec de vérification du certificat : expired, self_signed, untrusted, hostname, other."""
    code = getattr(error, "verify_code", None)
    if code in _VERIFY_EXPIRED:
        return "expired"
    if code in _VERIFY_SELF_SIGNED:
        return "self_signed"
    if code in _VERIFY_UNTRUSTED:
        return "untrusted"
    if code in _VERIFY_HOSTNAME:
        return "hostname"
    return "other"


def _name_value(name: x509.Name, oid) -> str | None:
    values = name.get_attributes_for_oid(oid)
    return str(values[0].value) if values else None


def _hostname_matches(names: list[str], host: str) -> bool:
    host = host.lower().rstrip(".")
    for name in names:
        if name == host or (
            name.startswith("*.") and host.endswith(name[1:]) and "." not in host[: -len(name) + 1]
        ):
            return True
    return False


def describe_certificate(der: bytes, host: str, now: datetime | None = None) -> dict:
    """Résumé du certificat présenté (DER) : sujet, émetteur, expiration, auto-signé, correspondance au nom."""
    now = now or datetime.now(timezone.utc)
    try:
        cert = x509.load_der_x509_certificate(der)
    except ValueError:
        return {}
    try:
        san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
        names = [n.lower() for n in san.get_values_for_type(x509.DNSName)]
    except x509.ExtensionNotFound:
        names = []
    common_name = _name_value(cert.subject, NameOID.COMMON_NAME)
    if not names and common_name:
        names = [common_name.lower()]
    return {
        "subject": common_name,
        "issuer": _name_value(cert.issuer, NameOID.ORGANIZATION_NAME)
        or _name_value(cert.issuer, NameOID.COMMON_NAME),
        "not_after": cert.not_valid_after_utc.date().isoformat(),
        "days_left": (cert.not_valid_after_utc - now).days,
        "self_signed": cert.issuer == cert.subject,
        "name_matches": _hostname_matches(names, host),
        "names": names[:10],
    }


def _ssl_context(verify: bool) -> ssl.SSLContext:
    """Contexte TLS client : magasin certifi du projet (identique sur tous les systèmes) ou sans vérification."""
    if verify:
        # Le magasin de Windows se remplit à la demande : il ferait refuser des certificats légitimes.
        return common._verified_ssl_context()
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    return context


# =============================================================================
# Sonde d'un serveur
# =============================================================================


def _random_recipient(domain: str) -> str:
    return f"dr-{secrets.token_hex(6)}@{domain}"


def _accepts(code: int) -> bool | None:
    """250 ou 251 : accepté ; 4xx : réponse temporaire (liste grise), indéterminé ; autre : refusé."""
    if code in (250, 251):
        return True
    return None if 400 <= code < 500 else False


def probe_catch_all(session: Session, domain: str) -> bool | None:
    """Le serveur accepte-t-il n'importe quel destinataire du domaine ? Deux adresses aléatoires."""
    code, _ = session.command("MAIL FROM:<>")
    if code != 250:
        return None
    answers = []
    for _ in range(2):
        code, _ = session.command(f"RCPT TO:<{_random_recipient(domain)}>")
        answers.append(_accepts(code))
    session.command("RSET")
    if all(answer is True for answer in answers):
        return True
    if all(answer is False for answer in answers):
        return False
    return None


def probe_relay(session: Session) -> str:
    """Test de relais (opt-in) : « open » si un destinataire externe est accepté d'un expéditeur externe.

    Aucune commande DATA n'est envoyée. Un serveur qui accepte tout destinataire avant de
    refuser le message peut être signalé à tort : le résultat est une suspicion.
    """
    session.command("RSET")
    code, _ = session.command(f"MAIL FROM:<{RELAY_SENDER}>")
    if code != 250:
        return "closed"
    code, _ = session.command(f"RCPT TO:<{RELAY_RECIPIENT}>")
    session.command("RSET")
    answer = _accepts(code)
    return "unknown" if answer is None else "open" if answer else "closed"


def empty_host(host: str, ip: str | None, port: int, priority: int | None) -> dict:
    return {
        "host": host,
        "priority": priority,
        "ip": ip,
        "port": port,
        "reachable": False,
        "error_code": None,
        "error": None,
        "banner": None,
        "software": None,
        "version": None,
        "extensions": [],
        "size": None,
        "starttls": None,
        "auth_before_tls": [],
        "auth_after_tls": [],
        "tls": None,
        "catch_all": None,
        "relay": None,
        "gateway": None,
    }


def fail(info: dict, code: str) -> dict:
    info["error_code"] = code
    info["error"] = ERRORS.get(code, ERRORS["protocol"])
    return info


def _connect_error(error: OSError) -> str:
    if isinstance(error, TimeoutError):
        return "timeout"
    if isinstance(error, ConnectionRefusedError):
        return "refused"
    return "unreachable"


def probe_host(
    host: str,
    ip: str,
    port: int,
    domain: str,
    priority: int | None = None,
    *,
    probes: bool = True,
    relay_test: bool = False,
) -> dict:
    """Examine un serveur MX (bloquant). Ne lève jamais d'erreur réseau : elle est rendue dans le résultat."""
    info = _probe(host, ip, port, domain, priority, verify=True, probes=probes, relay_test=relay_test)
    reason = info.pop("_verify_failed", None)
    if reason is not None:
        # Certificat refusé : seconde connexion, sans vérification, pour poursuivre l'examen.
        info = _probe(host, ip, port, domain, priority, verify=False, probes=probes, relay_test=relay_test)
        if info.get("tls") is not None:
            info["tls"]["verified"] = False
            info["tls"]["verify_error"] = reason
    return info


def _probe(
    host: str,
    ip: str,
    port: int,
    domain: str,
    priority: int | None,
    *,
    verify: bool,
    probes: bool,
    relay_test: bool,
) -> dict:
    info = empty_host(host, ip, port, priority)
    deadline = time.monotonic() + HOST_BUDGET
    try:
        sock = connect_socket(ip, port, CONNECT_TIMEOUT)
    except OSError as error:
        return fail(info, _connect_error(error))
    info["reachable"] = True
    # Sockets à fermer : l'originale, puis la socket TLS qui l'enveloppe après STARTTLS.
    opened = [sock]
    try:
        _dialogue(info, opened, host, domain, deadline, verify=verify, probes=probes, relay_test=relay_test)
    except SmtpError as error:
        fail(info, error.code if error.code in ERRORS else "protocol")
    finally:
        for opened_socket in opened:
            try:
                opened_socket.close()
            except OSError:
                pass
    return info


def _dialogue(
    info: dict,
    opened: list[socket.socket],
    host: str,
    domain: str,
    deadline: float,
    *,
    verify: bool,
    probes: bool,
    relay_test: bool,
) -> None:
    session = Session(opened[0], deadline)
    code, lines = session.read_reply()
    banner = " ".join(lines).strip()
    info["banner"] = banner[:BANNER_MAX_CHARS]
    info.update(parse_banner(banner))
    if code != 220:
        # 554 « liste noire » ou « trop de connexions » : le serveur refuse NOTRE adresse, pas un défaut du domaine.
        info["error_code"], info["error"] = "banner_refused", ERRORS["banner_refused"]
        return
    code, lines = session.command(f"EHLO {HELO_NAME}")
    if code != 250:
        code, lines = session.command(f"HELO {HELO_NAME}")
        if code != 250:
            info["error_code"], info["error"] = "ehlo_rejected", ERRORS["ehlo_rejected"]
            return
        lines = [""]
    ehlo = parse_ehlo(lines)
    info.update(extensions=ehlo["extensions"], size=ehlo["size"], starttls=ehlo["starttls"],
                auth_before_tls=ehlo["auth"])  # fmt: skip
    usable = True
    if ehlo["starttls"]:
        session, usable = _start_tls(info, session, opened, host, deadline, verify)
        if info.get("_verify_failed"):
            return
    if not usable:
        return
    if probes:
        info["catch_all"] = probe_catch_all(session, domain)
        if relay_test:
            info["relay"] = probe_relay(session)
    try:
        session.command("QUIT")
    except SmtpError:
        pass


def _start_tls(
    info: dict, session: Session, opened: list[socket.socket], host: str, deadline: float, verify: bool
) -> tuple[Session, bool]:
    """Négocie STARTTLS. Rend (session à employer ensuite, session utilisable)."""
    tls: dict = {
        "attempted": True,
        "version": None,
        "cipher": None,
        "bits": None,
        "verified": None,
        "verify_error": None,
        "error": None,
        "certificate": None,
    }
    info["tls"] = tls
    code, _ = session.command("STARTTLS")
    if code != 220:
        tls["error"] = "refused"
        return session, True
    try:
        context = _ssl_context(verify)
        opened[0].settimeout(IO_TIMEOUT)
        secured = context.wrap_socket(opened[0], server_hostname=host)
    except ssl.SSLCertVerificationError as error:
        if verify:
            info["_verify_failed"] = verify_reason(error)
            return session, False
        tls["error"] = "handshake_failed"
        return session, False
    except (ssl.SSLError, OSError):
        tls["error"] = "handshake_failed"
        return session, False
    # Connexion chiffrée : la session reprend sur la socket TLS, fermée avec l'originale par l'appelant.
    opened.append(secured)
    tls["verified"] = True if verify else None
    tls["version"] = secured.version()
    cipher = secured.cipher()
    if cipher:
        tls["cipher"], _, tls["bits"] = cipher[0], cipher[1], cipher[2]
    der = secured.getpeercert(binary_form=True)
    if der:
        tls["certificate"] = describe_certificate(der, host)
    encrypted = Session(secured, deadline)
    try:
        code, lines = encrypted.command(f"EHLO {HELO_NAME}")
    except SmtpError:
        return encrypted, False
    if code == 250:
        info["auth_after_tls"] = parse_ehlo(lines)["auth"]
    return encrypted, True


# =============================================================================
# Synthèse
# =============================================================================


def _address_preference(address: str) -> tuple[int, str]:
    """IPv4 d'abord : beaucoup de réseaux n'ont pas d'IPv6 sortant."""
    return (0 if ":" not in address else 1, address)


def pick_address(addresses: list[str]) -> str | None:
    """Adresse à contacter parmi celles du MX (IPv4 en priorité)."""
    return min(addresses, key=_address_preference) if addresses else None


def summarize(hosts: list[dict]) -> dict:
    """Constats globaux à partir des serveurs examinés.

    Une passerelle de sécurité ou un relais de redirection (Mimecast, Cloudflare Email Routing…)
    accepte tout destinataire par construction : son « catch-all » n'est pas celui du domaine et
    n'entre pas dans la synthèse. Chaque serveur reçoit `gateway` (clé du fournisseur ou None).
    """
    for host in hosts:
        provider = provider_of_mx(str(host.get("host")))
        gateway = provider is not None and provider.kind in (KIND_GATEWAY, KIND_FORWARDING)
        host["gateway"] = provider.key if gateway else None
    reachable = [h for h in hosts if h.get("reachable") and not h.get("error_code")]
    primary_catch_all = next(
        (h["catch_all"] for h in reachable if h.get("catch_all") is not None and not h["gateway"]), None
    )
    return {
        "tested": len(hosts),
        "reachable": len([h for h in hosts if h.get("reachable")]),
        "examined": len(reachable),
        "starttls_all": all(h.get("starttls") for h in reachable) if reachable else None,
        "catch_all": primary_catch_all,
        "relay_open": any(h.get("relay") == "open" for h in reachable),
    }
