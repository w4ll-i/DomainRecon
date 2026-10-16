# =============================================================================
# DomainRecon - Logique du module « dkim » : clés DKIM des sélecteurs courants
# =============================================================================
# Les sélecteurs DKIM ne sont pas énumérables : on interroge <sélecteur>._domainkey.<domaine>
# pour une liste étendue de sélecteurs courants (fusion des listes des anciennes
# versions : 11, 28 et 69 sélecteurs, complétée des fournisseurs actuels) et on analyse
# chaque clé trouvée : type, taille RSA, mode test (t=y), algorithmes de hachage, services.
# Les requêtes DNS sont parallélisées (bornées par un budget total). Une clé
# introuvable ne prouve donc pas l'absence de DKIM : le sélecteur peut être personnalisé.
# Un joker *._domainkey est détecté par un sélecteur aléatoire pour éviter les faux positifs.
# =============================================================================

import base64
import binascii
import re
import secrets
from concurrent.futures import ThreadPoolExecutor

from cryptography.hazmat.primitives.asymmetric import ed25519, rsa
from cryptography.hazmat.primitives.serialization import load_der_public_key

from ..dns import DnsQuerier, txt_record_text
from ..email_security import parse_tags

# Fournisseurs et usages courants, regroupés pour la lisibilité. Les sélecteurs uniques
# d'un tenant (Amazon SES, Mimecast daté…) ne peuvent pas être devinés.
DKIM_SELECTORS: tuple[str, ...] = (
    # Génériques
    "default", "dkim", "mail", "email", "key1", "key2", "key3", "dkim1", "dkim2", "dk", "mx",
    "smtp", "auth", "authenticate", "dkimkey", "m1", "m2", "mta", "mailer", "sig1", "sig2",
    # Google Workspace
    "google", "google2048", "google1024", "gsuite", "workspace",
    # Microsoft 365
    "selector1", "selector2", "selector3", "office365", "o365", "exchange",
    # SendGrid, Mailchimp / Mandrill, Mailgun
    "s1", "s2", "s3", "sm", "k1", "k2", "k3", "mandrill", "mailchimp", "mg", "mailgun", "krs",
    # Amazon SES, Postmark, Brevo (Sendinblue), Mailjet, SparkPost, SendPulse
    "amazonses", "ses", "pm", "pm1", "postmark", "brevo1", "brevo2", "sendinblue", "mailjet",
    "sparkpost", "sendpulse", "sendgrid",
    # Proton, Zoho, Fastmail, OVH, Cloudflare
    "protonmail", "protonmail2", "protonmail3", "pm2", "pm3", "zoho", "zmail", "fm1", "fm2", "fm3",
    "ovh", "cf2024-1",
    # Passerelles et services de support / marketing
    "mimecast", "mxvault", "zendesk1", "zendesk2", "hs1", "hs2", "salesforce", "sf1", "ctct1",
    "ctct2", "kl", "kl2", "cm", "intercom", "fd",
    # Sélecteurs datés fréquents
    "20161025", "20200301", "20210112", "20220601", "20230601", "2020", "2021", "2022", "2023",
    "2024", "2025",
)  # fmt: skip

# Requêtes DNS en parallèle ; délai par requête et budget total (inférieur au délai du module).
DNS_WORKERS = 10
QUERY_TIMEOUT = 3.0
DNS_BUDGET = 40.0
MAX_KEYS = 50

_GRADE_WEAK_BITS = 1024  # clés RSA strictement inférieures à 1024 bits : cassables


def _random_selector() -> str:
    """Sélecteur aléatoire, jamais publié : seul un joker *._domainkey y répond."""
    return f"dr-{secrets.token_hex(8)}"


def analyze_key(text: str) -> dict | None:
    """Analyse un TXT DKIM (RFC 6376 §3.6.1) : None si ce n'est pas une clé, sinon ses caractéristiques.

    `status` : « valid » ou « revoked » (p= vide). Pour une clé valide : `key_type` (rsa, ed25519 ou
    autre), `key_bits` (None si la clé n'est pas lisible), `valid_key` (la clé se décode), `testing`
    (t=y), `strict` (t=s), `hash_algorithms`, `services`.
    """
    tags = parse_tags(text)
    version = tags.get("v")
    if (version is not None and version.upper() != "DKIM1") or "p" not in tags:
        return None
    encoded = re.sub(r"\s+", "", tags["p"])
    flags = {flag.strip().lower() for flag in tags.get("t", "").split(":") if flag.strip()}
    entry: dict = {
        "status": "valid" if encoded else "revoked",
        "key_type": tags.get("k", "rsa").lower() or "rsa",
        "key_bits": None,
        "valid_key": False,
        "testing": "y" in flags,
        "strict": "s" in flags,
        "hash_algorithms": [h.strip().lower() for h in tags.get("h", "").split(":") if h.strip()],
        "services": [s.strip().lower() for s in tags.get("s", "").split(":") if s.strip()],
    }
    if not encoded:
        return entry
    try:
        raw = base64.b64decode(encoded + "=" * (-len(encoded) % 4), validate=True)
    except (binascii.Error, ValueError):
        return entry
    if entry["key_type"] == "ed25519":
        # RFC 8463 : la clé brute de 32 octets, pas une structure DER.
        if len(raw) == 32:
            entry.update(key_bits=256, valid_key=True)
        return entry
    try:
        public = load_der_public_key(raw)
    except (ValueError, TypeError):
        return entry
    entry["valid_key"] = True
    if isinstance(public, rsa.RSAPublicKey):
        entry.update(key_type="rsa", key_bits=public.key_size)
    elif isinstance(public, ed25519.Ed25519PublicKey):
        entry.update(key_type="ed25519", key_bits=256)
    return entry


def _answer_status(texts: frozenset[str]) -> str | None:
    """« valid » si une réponse est une clé, « revoked » si toutes les clés sont révoquées, sinon None."""
    statuses = {(analyze_key(text) or {}).get("status") for text in texts}
    if "valid" in statuses:
        return "valid"
    return "revoked" if "revoked" in statuses else None


def _probe(querier: DnsQuerier, domain: str, selector: str, wildcard: frozenset[str] | None) -> dict:
    name = f"{selector}._domainkey.{domain}"
    result = querier.lookup(name, "TXT")
    if result.status == "error":
        return {"selector": selector, "error": True}
    texts = frozenset(map(txt_record_text, result.answers))
    if wildcard and texts == wildcard:
        return {"selector": selector, "wildcard": True}
    keys = [key for key in map(analyze_key, sorted(texts)) if key is not None]
    if not keys:
        return {"selector": selector}
    entry = next((k for k in keys if k["status"] == "valid"), keys[0])
    entry = dict(entry, selector=selector, delegated_to=None)
    if entry["status"] == "valid":
        cname = querier.lookup(name, "CNAME")
        if cname.status == "ok" and cname.answers:
            entry["delegated_to"] = str(cname.answers[0].target).rstrip(".").lower()
    return entry


def scan(querier: DnsQuerier, domain: str, selectors: tuple[str, ...] = DKIM_SELECTORS) -> dict:
    """Interroge tous les sélecteurs de `domain` et rend le résultat du module (sans `measured` final)."""
    probe = querier.lookup(f"{_random_selector()}._domainkey.{domain}", "TXT")
    wildcard_texts = frozenset(map(txt_record_text, probe.answers)) if probe.status == "ok" else frozenset()
    wildcard_status = _answer_status(wildcard_texts) if wildcard_texts else None

    with ThreadPoolExecutor(max_workers=DNS_WORKERS) as pool:
        probes = list(pool.map(lambda s: _probe(querier, domain, s, wildcard_texts or None), selectors))

    failed = sum(1 for p in probes if p.get("error"))
    keys = [p for p in probes if p.get("status") == "valid"][:MAX_KEYS]
    revoked = [p["selector"] for p in probes if p.get("status") == "revoked"][:MAX_KEYS]
    return {
        "measured": failed < len(selectors),
        "error": None,
        "domain": domain,
        "found": None if failed == len(selectors) else bool(keys) or wildcard_status == "valid",
        "selectors_tested": len(selectors),
        "selectors_failed": failed,
        "keys": [
            {
                "selector": k["selector"],
                "key_type": k["key_type"],
                "key_bits": k["key_bits"],
                "valid_key": k["valid_key"],
                "testing": k["testing"],
                "strict": k["strict"],
                "hash_algorithms": k["hash_algorithms"],
                "services": k["services"],
                "delegated_to": k["delegated_to"],
            }
            for k in keys
        ],
        "revoked_selectors": revoked,
        "wildcard": wildcard_status,
    }


def weak_rsa_bits(key: dict) -> int | None:
    """Taille d'une clé RSA trop courte (≤ 1024 bits), sinon None."""
    bits = key.get("key_bits")
    if key.get("key_type") == "rsa" and isinstance(bits, int) and bits <= _GRADE_WEAK_BITS:
        return bits
    return None
