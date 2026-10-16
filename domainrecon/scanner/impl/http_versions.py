# =============================================================================
# DomainRecon - Logique du module « http_versions » (HTTP/1.1, HTTP/2, HTTP/3)
# =============================================================================
# - HTTP/2 et HTTP/1.1 : négociation ALPN (RFC 7301) lors d'une poignée de main TLS
#   sur le port 443, SANS vérifier le certificat : sinon un certificat invalide
#   donnerait « HTTP/2 absent » à tort. HTTP/1.1 est réellement testé.
# - HTTP/3 : annoncé par l'en-tête Alt-Svc (RFC 7838) de la réponse HTTPS, ou par
#   l'enregistrement DNS HTTPS (RFC 9460, paramètre alpn). Aucune connexion QUIC
#   n'est tentée : le résultat dit « annoncé », pas « vérifié ».
# Les fonctions d'analyse sont pures ; la sonde ALPN est bloquante (à lancer dans
# un thread) et ne se connecte qu'aux adresses déjà validées par la politique de cibles.
# =============================================================================

import re
import socket
import ssl

from ..targets import ensure_ip_allowed

TLS_PORT = 443
PROBE_TIMEOUT = 5.0
MAX_ADDRESSES = 3

# Jetons ALPN d'HTTP/3 : « h3 » et les brouillons « h3-29 », « h3-Q050 »… ; « quic » est l'ancien Google QUIC.
_H3_TOKEN = re.compile(r"^h3(-[a-z0-9]+)?$", re.IGNORECASE)
_AUTHORITY = re.compile(r'^([^=]+)="([^"]*)"')


def probe_alpn(
    sni: str | None, addresses: list[str], offered: list[str], timeout: float = PROBE_TIMEOUT
) -> dict:
    """Poignée de main TLS avec ALPN ; renvoie {alpn, tls_version}.

    `sni` : nom d'hôte pour SNI (None pour une adresse IP littérale). `addresses` : adresses de la
    cible déjà validées ; chacune est revalidée (ensure_ip_allowed) avant la connexion. Lève OSError
    (connexion impossible) ou ssl.SSLError (poignée de main refusée, aucun protocole commun).
    """
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    context.set_alpn_protocols(offered)
    last_error: OSError = OSError("aucune adresse")
    for address in addresses[:MAX_ADDRESSES]:
        try:
            ip = ensure_ip_allowed(address)
            sock = socket.create_connection((ip, TLS_PORT), timeout=timeout)
        except OSError as e:
            last_error = e
            continue
        with sock, context.wrap_socket(sock, server_hostname=sni) as tls:
            return {"alpn": tls.selected_alpn_protocol(), "tls_version": tls.version()}
    raise last_error


def parse_alt_svc(value: str | None) -> dict:
    """Analyse un en-tête Alt-Svc : protocoles annoncés, HTTP/3, durée de validité, « clear ».

    Chaque alternative a la forme `protocole="[hôte]:port"; ma=secondes; persist=1`.
    """
    result = {"protocols": [], "http3": False, "ma": None, "cleared": False, "authorities": []}
    if not value or not value.strip():
        return result
    if value.strip().lower() == "clear":
        result["cleared"] = True
        return result
    # Une alternative par élément séparé par une virgule ; les guillemets ne contiennent pas de virgule.
    for item in value.split(","):
        parts = [p.strip() for p in item.split(";") if p.strip()]
        if not parts:
            continue
        found = _AUTHORITY.match(parts[0])
        if not found:
            continue
        protocol = found.group(1).strip().lower()
        if protocol not in result["protocols"]:
            result["protocols"].append(protocol)
        authority = found.group(2)[:120]
        if authority not in result["authorities"]:
            result["authorities"].append(authority)
        if _H3_TOKEN.match(protocol):
            result["http3"] = True
        for extra in parts[1:]:
            name, _, raw = extra.partition("=")
            if name.strip().lower() == "ma" and raw.strip().isdigit() and result["ma"] is None:
                result["ma"] = int(raw.strip())
    result["protocols"] = result["protocols"][:10]
    result["authorities"] = result["authorities"][:10]
    return result


def alpn_from_https_record(text: str) -> list[str]:
    """Identifiants ALPN d'un enregistrement DNS HTTPS/SVCB rendu en texte (« 1 . alpn=h2,h3 »)."""
    found = re.search(r'alpn="?([^\s"]+)"?', text, re.IGNORECASE)
    if not found:
        return []
    return [token.strip().lower() for token in found.group(1).split(",") if token.strip()][:10]
