# =============================================================================
# DomainRecon - Logique du module « mail_provider » : fournisseur de messagerie réel
# =============================================================================
# Le MX d'un domaine désigne souvent une PASSERELLE (Mimecast, Proofpoint,
# Barracuda…) ou un relais de redirection, pas la boîte aux lettres réelle. Ce
# fichier recoupe plusieurs indices DNS pour retrouver le fournisseur derrière :
#   - les MX (poids 3) ;
#   - les include/redirect du SPF, les CNAME autodiscover et DKIM, les jetons de
#     vérification de domaine publiés en TXT (poids 1 à 2).
# Il fournit aussi la liste des MX (lookup_mail_exchangers), partagée avec les
# modules mta_sts et smtp_security.
# Les indices sont des heuristiques : le niveau de confiance est rendu avec le résultat.
# =============================================================================

import re
from typing import NamedTuple

from ..dns import DnsQuerier, txt_record_text
from ..targets import registrable_domain

# Types de fournisseurs.
KIND_MAILBOX = "mailbox"  # boîtes aux lettres hébergées (Google, Microsoft 365…)
KIND_GATEWAY = "gateway"  # passerelle de sécurité qui filtre puis relaie (Mimecast…)
KIND_FORWARDING = "forwarding"  # redirection d'adresses, sans boîte (Cloudflare Email Routing…)
KIND_SENDING = "sending"  # service d'envoi (SPF seulement : SendGrid, Mailgun…)

# Poids des indices.
WEIGHT_MX = 3
WEIGHT_STRONG = 2
WEIGHT_WEAK = 1
# Poids minimal pour retenir un fournisseur « réel » trouvé hors des MX.
MIN_INFERRED_WEIGHT = 2
# Poids total à partir duquel la confiance est « haute ».
HIGH_CONFIDENCE_WEIGHT = 4

# Plafonds : un domaine peut publier des dizaines de MX ou de TXT.
MAX_MX_HOSTS = 20
MAX_RESOLVED_HOSTS = 10
MAX_EVIDENCE = 30


class Provider(NamedTuple):
    """Fournisseur reconnaissable. Les suffixes valent pour le nom lui-même et ses sous-domaines."""

    key: str
    name: str
    kind: str
    mx: tuple[str, ...] = ()
    spf: tuple[str, ...] = ()
    cname: tuple[str, ...] = ()
    txt: tuple[str, ...] = ()


PROVIDERS: tuple[Provider, ...] = (
    # --- Boîtes aux lettres ---------------------------------------------------
    Provider(
        "google",
        "Google Workspace / Gmail",
        KIND_MAILBOX,
        mx=("aspmx.l.google.com", "googlemail.com", "smtp.google.com", "gmr-smtp-in.l.google.com"),
        spf=("_spf.google.com", "spf.google.com", "_netblocks.google.com"),
        txt=("google-site-verification=",),
    ),
    Provider(
        "microsoft365",
        "Microsoft 365 / Exchange Online",
        KIND_MAILBOX,
        mx=("mail.protection.outlook.com", "mail.eo.outlook.com"),
        spf=("spf.protection.outlook.com",),
        cname=("autodiscover.outlook.com", "onmicrosoft.com", "outlook.com"),
        txt=("ms=ms",),
    ),
    Provider(
        "proton",
        "Proton Mail",
        KIND_MAILBOX,
        mx=("mail.protonmail.ch", "mailsec.protonmail.ch"),
        spf=("_spf.protonmail.ch",),
        cname=("domains.proton.ch", "protonmail.ch"),
        txt=("protonmail-verification=",),
    ),
    Provider(
        "zoho",
        "Zoho Mail",
        KIND_MAILBOX,
        mx=("zoho.com", "zoho.eu", "zoho.in", "zoho.com.au", "zoho.jp", "zoho.sa", "zoho.ca"),
        spf=("zoho.com", "zoho.eu", "zoho.in", "zoho.com.au", "zohomail.com"),
        txt=("zoho-verification=",),
    ),
    Provider(
        "fastmail",
        "Fastmail",
        KIND_MAILBOX,
        mx=("messagingengine.com",),
        spf=("spf.messagingengine.com",),
        cname=("dkim.fmhosted.com", "fmhosted.com"),
    ),
    Provider(
        "icloud",
        "iCloud Mail",
        KIND_MAILBOX,
        mx=("mail.icloud.com",),
        spf=("icloud.com",),
    ),
    Provider("yahoo", "Yahoo Mail", KIND_MAILBOX, mx=("yahoodns.net",), spf=("yahoo.com",)),
    Provider(
        "yandex",
        "Yandex 360",
        KIND_MAILBOX,
        mx=("mx.yandex.net", "yandex.ru"),
        spf=("_spf.yandex.net",),
    ),
    Provider("mailbox_org", "mailbox.org", KIND_MAILBOX, mx=("mailbox.org",), spf=("mailbox.org",)),
    Provider(
        "tuta", "Tuta (Tutanota)", KIND_MAILBOX, mx=("tutanota.de", "tuta.com"), spf=("spf.tutanota.de",)
    ),
    Provider("migadu", "Migadu", KIND_MAILBOX, mx=("migadu.com",), spf=("spf.migadu.com",)),
    Provider("infomaniak", "Infomaniak", KIND_MAILBOX, mx=("infomaniak.ch",), spf=("spf.infomaniak.ch",)),
    Provider(
        "ovh", "OVHcloud", KIND_MAILBOX, mx=("mail.ovh.net", "mx.ovh.net", "ovh.net"), spf=("mx.ovh.com",)
    ),
    Provider("gandi", "Gandi Mail", KIND_MAILBOX, mx=("mail.gandi.net",), spf=("_mailcust.gandi.net",)),
    Provider(
        "ionos",
        "IONOS (1&1)",
        KIND_MAILBOX,
        mx=("ionos.com", "ionos.fr", "ionos.de", "ionos.es", "ionos.co.uk", "kundenserver.de", "1and1.com"),
        spf=("_spf.perfora.net", "_spf.kundenserver.de", "_spf.ionos.com"),
    ),
    Provider("godaddy", "GoDaddy", KIND_MAILBOX, mx=("secureserver.net",), spf=("secureserver.net",)),
    Provider("hostinger", "Hostinger", KIND_MAILBOX, mx=("hostinger.com",), spf=("_spf.mail.hostinger.com",)),
    Provider(
        "namecheap",
        "Namecheap Private Email",
        KIND_MAILBOX,
        mx=("privateemail.com",),
        spf=("spf.privateemail.com",),
    ),
    Provider("rackspace", "Rackspace Email", KIND_MAILBOX, mx=("emailsrvr.com",), spf=("emailsrvr.com",)),
    Provider("strato", "STRATO", KIND_MAILBOX, mx=("rzone.de",), spf=("spf.strato.com",)),
    Provider("hetzner", "Hetzner", KIND_MAILBOX, mx=("your-server.de",), spf=("spf.your-server.de",)),
    Provider("laposte", "La Poste (laposte.net)", KIND_MAILBOX, mx=("laposte.net",)),
    Provider("free", "Free", KIND_MAILBOX, mx=("free.fr",), spf=("spf.free.fr",)),
    Provider("orange", "Orange", KIND_MAILBOX, mx=("orange.fr", "wanadoo.fr")),
    # --- Passerelles de sécurité ------------------------------------------------
    Provider(
        "mimecast",
        "Mimecast",
        KIND_GATEWAY,
        mx=("mimecast.com", "mimecast-offshore.com"),
        spf=("_netblocks.mimecast.com", "mimecast.com"),
    ),
    Provider(
        "proofpoint",
        "Proofpoint",
        KIND_GATEWAY,
        mx=("pphosted.com", "ppe-hosted.com"),
        spf=("pphosted.com", "ppe-hosted.com"),
    ),
    Provider(
        "barracuda",
        "Barracuda Email Security",
        KIND_GATEWAY,
        mx=("barracudanetworks.com", "cudasvc.com"),
        spf=("spf.ess.barracudanetworks.com", "barracudanetworks.com"),
    ),
    Provider(
        "cisco_ironport", "Cisco Secure Email (IronPort)", KIND_GATEWAY, mx=("iphmx.com",), spf=("iphmx.com",)
    ),
    Provider(
        "trend_micro",
        "Trend Micro Email Security",
        KIND_GATEWAY,
        mx=("tmes.trendmicro.com", "tmes.trendmicro.eu", "tmes.dlp.trendmicro.com"),
    ),
    Provider(
        "cloudflare_email_security",
        "Cloudflare Email Security (Area 1)",
        KIND_GATEWAY,
        mx=("cf-emailsecurity.net", "mailstream-eu1.mxrecord.io"),
        spf=("_spf.area1.com", "spf.area1.com"),
    ),
    Provider("sophos", "Sophos Email", KIND_GATEWAY, mx=("reflexion.net", "sophos.com")),
    Provider(
        "broadcom",
        "Broadcom / Symantec Email Security",
        KIND_GATEWAY,
        mx=("messagelabs.com",),
        spf=("messagelabs.com",),
    ),
    Provider(
        "hornetsecurity",
        "Hornetsecurity",
        KIND_GATEWAY,
        mx=("hornetsecurity.com",),
        spf=("spf.hornetsecurity.com",),
    ),
    Provider("vade", "Vade Secure", KIND_GATEWAY, mx=("vadesecure.com",)),
    Provider("mailinblack", "Mailinblack", KIND_GATEWAY, mx=("mailinblack.com",)),
    Provider("retarus", "Retarus", KIND_GATEWAY, mx=("retarus.com", "retarus.de")),
    Provider("libraesva", "Libraesva", KIND_GATEWAY, mx=("libraesva.com",)),
    Provider("fortinet", "Fortinet FortiMail Cloud", KIND_GATEWAY, mx=("fortimailcloud.com",)),
    Provider("google_postini", "Google Postini (hérité)", KIND_GATEWAY, mx=("psmtp.com",)),
    # --- Redirection d'adresses ------------------------------------------------
    Provider(
        "cloudflare_routing",
        "Cloudflare Email Routing",
        KIND_FORWARDING,
        mx=("mx.cloudflare.net",),
        spf=("_spf.mx.cloudflare.net",),
    ),
    Provider("improvmx", "ImprovMX", KIND_FORWARDING, mx=("improvmx.com",), spf=("spf.improvmx.com",)),
    Provider(
        "forwardemail",
        "Forward Email",
        KIND_FORWARDING,
        mx=("forwardemail.net",),
        spf=("spf.forwardemail.net",),
    ),
    Provider(
        "mailgun_inbound", "Mailgun (réception)", KIND_FORWARDING, mx=("mailgun.org",), spf=("mailgun.org",)
    ),
    # --- Services d'envoi (indices SPF seulement) ---------------------------------
    Provider("sendgrid", "SendGrid", KIND_SENDING, spf=("sendgrid.net",)),
    Provider("amazon_ses", "Amazon SES", KIND_SENDING, spf=("amazonses.com",)),
    Provider("mandrill", "Mailchimp Transactional (Mandrill)", KIND_SENDING, spf=("mandrillapp.com",)),
    Provider("mailchimp", "Mailchimp", KIND_SENDING, spf=("mcsv.net", "servers.mcsv.net")),
    Provider("brevo", "Brevo (Sendinblue)", KIND_SENDING, spf=("sendinblue.com", "brevo.com")),
    Provider("mailjet", "Mailjet", KIND_SENDING, spf=("mailjet.com",)),
    Provider("postmark", "Postmark", KIND_SENDING, spf=("spf.mtasv.net", "postmarkapp.com")),
    Provider("sparkpost", "SparkPost", KIND_SENDING, spf=("sparkpostmail.com",)),
    Provider("zendesk", "Zendesk", KIND_SENDING, spf=("zendesk.com",)),
    Provider("salesforce", "Salesforce", KIND_SENDING, spf=("salesforce.com", "exacttarget.com")),
    Provider("hubspot", "HubSpot", KIND_SENDING, spf=("hubspotemail.net", "hubspot.com")),
    Provider("freshdesk", "Freshdesk", KIND_SENDING, spf=("email.freshdesk.com", "freshdesk.com")),
    Provider("intercom", "Intercom", KIND_SENDING, spf=("_spf.intercom.io", "intercom.io")),
    Provider("helpscout", "Help Scout", KIND_SENDING, spf=("helpscoutemail.com",)),
    Provider("constant_contact", "Constant Contact", KIND_SENDING, spf=("constantcontact.com",)),
    Provider("klaviyo", "Klaviyo", KIND_SENDING, spf=("klaviyo.com",)),
)

PROVIDERS_BY_KEY = {provider.key: provider for provider in PROVIDERS}


def host_matches(host: str, suffix: str) -> bool:
    """Le nom d'hôte est `suffix` ou l'un de ses sous-domaines."""
    host = host.strip().lower().rstrip(".")
    return host == suffix or host.endswith("." + suffix)


def provider_of_mx(host: str) -> Provider | None:
    """Fournisseur reconnu à partir du nom d'un MX, sinon None."""
    for provider in PROVIDERS:
        if any(host_matches(host, suffix) for suffix in provider.mx):
            return provider
    return None


def providers_of_spf_target(target: str) -> list[Provider]:
    """Fournisseurs désignés par la cible d'un include/redirect SPF."""
    return [p for p in PROVIDERS if any(host_matches(target, suffix) for suffix in p.spf)]


def spf_targets(record: str) -> list[str]:
    """Cibles des include: et redirect= d'un enregistrement SPF, sans doublon."""
    found: list[str] = []
    for term in record.split()[1:]:
        low = term.lower().lstrip("+-~?")
        if low.startswith("include:"):
            target = low[len("include:") :]
        elif low.startswith("redirect="):
            target = low[len("redirect=") :]
        else:
            continue
        target = target.rstrip(".")
        if target and "%" not in target and target not in found:
            found.append(target)
    return found


# =============================================================================
# MX du domaine (partagé avec mta_sts et smtp_security)
# =============================================================================


class MailExchangers(NamedTuple):
    """MX d'un domaine : nom du domaine qui les porte, liste triée, MX nul, erreur éventuelle."""

    domain: str | None
    hosts: list[dict]
    null_mx: bool
    error: object | None


def lookup_mail_exchangers(querier: DnsQuerier, host: str, apex: str) -> MailExchangers:
    """MX de `host`, avec repli sur le domaine enregistrable `apex` si `host` n'en publie aucun.

    Les MX sont triés par priorité puis par nom ; `hosts` : [{priority, host}] (au plus MAX_MX_HOSTS).
    `error` n'est renseigné que si une requête a échoué sans qu'on ait pu conclure.
    """
    candidates = [host] if apex in ("", host) else [host, apex]
    error = None
    for name in candidates:
        result = querier.lookup(name, "MX")
        if result.status == "error":
            error = result.error
            continue
        if not result.answers:
            continue
        exchanges = [(int(mx.preference), str(mx.exchange).rstrip(".").lower()) for mx in result.answers]
        if len(exchanges) == 1 and exchanges[0][1] == "":
            return MailExchangers(name, [], True, None)  # MX nul (RFC 7505) : racine « . »
        hosts = [{"priority": priority, "host": exchange} for priority, exchange in sorted(set(exchanges))]
        return MailExchangers(name, hosts[:MAX_MX_HOSTS], False, None)
    return MailExchangers(None, [], False, error)


# =============================================================================
# Analyse
# =============================================================================


def _add_evidence(
    evidence: list[dict], weights: dict[str, int], provider: Provider, kind: str, value: str, weight: int
) -> None:
    entry = {"type": kind, "value": value, "provider": provider.key, "weight": weight}
    if entry in evidence:
        return  # même indice relevé deux fois (deux TXT de vérification identiques)
    if len(evidence) < MAX_EVIDENCE:
        evidence.append(entry)
    weights[provider.key] = weights.get(provider.key, 0) + weight


def _cname_target(querier: DnsQuerier, name: str) -> str | None:
    result = querier.lookup(name, "CNAME")
    if result.status != "ok" or not result.answers:
        return None
    return str(result.answers[0].target).rstrip(".").lower()


def resolution_state(querier: DnsQuerier, host: str) -> str:
    """'ok' (adresse trouvée), 'nxdomain' (nom inexistant), 'no_address' (nom sans A ni AAAA), 'unknown'."""
    states = [querier.lookup(host, rtype) for rtype in ("A", "AAAA")]
    if any(state.status == "ok" for state in states):
        return "ok"
    if any(state.status == "error" for state in states):
        return "unknown"
    return "nxdomain" if all(state.status == "nxdomain" for state in states) else "no_address"


def analyze(querier: DnsQuerier, domain: str, apex: str, spf_record: str | None = None) -> dict:
    """Fournisseur de messagerie de `domain` (nom d'hôte) ; `apex` : domaine enregistrable.

    `spf_record` : SPF déjà connu (module email_security) ; sinon il est lu ici.
    """
    mx = lookup_mail_exchangers(querier, domain, apex)
    mail_domain = mx.domain or apex or domain
    result: dict = {
        "measured": True,
        "error": None,
        "domain": domain,
        "mail_domain": mx.domain,
        "null_mx": mx.null_mx,
        "mx": [],
        "unresolved_mx": [],
        "mx_provider": None,
        "gateway": None,
        "real_provider": None,
        "confidence": "none",
        "self_hosted": False,
        "evidence": [],
        "sending_services": [],
    }
    if mx.error is not None and not mx.hosts and not mx.null_mx:
        result.update(measured=False, error=mx.error)
        return result
    if mx.null_mx or not mx.hosts:
        return result

    evidence: list[dict] = []
    weights: dict[str, int] = {}
    own_domain = registrable_domain(mail_domain) or mail_domain

    # --- MX ----------------------------------------------------------------------
    direct: dict[str, int] = {}
    for index, entry in enumerate(mx.hosts):
        host = entry["host"]
        provider = provider_of_mx(host)
        item = {
            "priority": entry["priority"],
            "host": host,
            "provider": provider.key if provider else None,
            "kind": provider.kind if provider else None,
            "resolution": None,
        }
        if index < MAX_RESOLVED_HOSTS:
            item["resolution"] = resolution_state(querier, host)
            if item["resolution"] in ("nxdomain", "no_address"):
                result["unresolved_mx"].append(host)
        result["mx"].append(item)
        if provider is not None:
            direct[provider.key] = direct.get(provider.key, 0) + 1
    for key in direct:
        first = next(entry["host"] for entry in result["mx"] if entry["provider"] == key)
        _add_evidence(evidence, weights, PROVIDERS_BY_KEY[key], "mx", first, WEIGHT_MX)
    if direct:
        # À égalité, le premier rencontré (priorité la plus basse) l'emporte.
        main_key = max(direct, key=direct.__getitem__)
        main_provider = PROVIDERS_BY_KEY[main_key]
        result["mx_provider"] = {"key": main_key, "name": main_provider.name, "kind": main_provider.kind}
    result["self_hosted"] = not direct and all(
        (registrable_domain(entry["host"]) or entry["host"]) == own_domain for entry in mx.hosts
    )

    # --- SPF (include/redirect) et jetons de vérification TXT ----------------------
    txt_lookup = querier.lookup(mail_domain, "TXT")
    texts = [txt_record_text(rdata) for rdata in txt_lookup.answers] if txt_lookup.status == "ok" else []
    spf = spf_record or next((t for t in texts if t.lower().startswith("v=spf1")), None)
    sending: dict[str, str] = {}
    for target in spf_targets(spf or ""):
        for provider in providers_of_spf_target(target):
            if provider.kind == KIND_SENDING:
                sending.setdefault(provider.key, provider.name)
            _add_evidence(evidence, weights, provider, "spf_include", target, WEIGHT_STRONG)
    for text in texts:
        low = text.lower()
        for provider in PROVIDERS:
            for prefix in provider.txt:
                if low.startswith(prefix):
                    weight = WEIGHT_WEAK if prefix == "google-site-verification=" else WEIGHT_STRONG
                    _add_evidence(
                        evidence, weights, provider, "txt_verification", prefix.rstrip("=:"), weight
                    )

    # --- CNAME autodiscover et DKIM (délégation à un fournisseur) --------------------
    for name, kind in (
        (f"autodiscover.{mail_domain}", "autodiscover"),
        (f"selector1._domainkey.{mail_domain}", "dkim_cname"),
        (f"selector2._domainkey.{mail_domain}", "dkim_cname"),
        (f"fm1._domainkey.{mail_domain}", "dkim_cname"),
    ):
        target = _cname_target(querier, name)
        if not target:
            continue
        for provider in PROVIDERS:
            if any(host_matches(target, suffix) for suffix in provider.cname):
                _add_evidence(evidence, weights, provider, kind, target, WEIGHT_STRONG)
                break
    google_key = querier.lookup(f"google._domainkey.{mail_domain}", "TXT")
    if google_key.status == "ok" and any(
        "v=dkim1" in txt_record_text(rdata).lower()
        and "p=" in txt_record_text(rdata).lower()
        and txt_record_text(rdata).lower().split("p=", 1)[1].strip(" ;") != ""
        for rdata in google_key.answers
    ):
        _add_evidence(evidence, weights, PROVIDERS_BY_KEY["google"], "dkim_selector", "google", WEIGHT_STRONG)

    # --- Conclusion -------------------------------------------------------------
    main = PROVIDERS_BY_KEY.get(result["mx_provider"]["key"]) if result["mx_provider"] else None
    if main is not None and main.kind == KIND_GATEWAY:
        result["gateway"] = {"key": main.key, "name": main.name}
    gateways = sorted(key for key in direct if PROVIDERS_BY_KEY[key].kind == KIND_GATEWAY)
    if gateways and result["gateway"] is None:
        result["gateway"] = {"key": gateways[0], "name": PROVIDERS_BY_KEY[gateways[0]].name}

    real: Provider | None = None
    if main is not None and main.kind in (KIND_MAILBOX,):
        real = main
    else:
        candidates = [
            (weight, key)
            for key, weight in weights.items()
            if PROVIDERS_BY_KEY[key].kind == KIND_MAILBOX and weight >= MIN_INFERRED_WEIGHT
        ]
        if candidates:
            real = PROVIDERS_BY_KEY[max(candidates)[1]]
    if real is not None:
        total = weights.get(real.key, 0)
        result["real_provider"] = {"key": real.key, "name": real.name, "kind": real.kind}
        # Un MX qui désigne directement le fournisseur suffit ; sinon il faut plusieurs indices concordants.
        direct_mx = main is not None and main.key == real.key
        result["confidence"] = "high" if direct_mx or total >= HIGH_CONFIDENCE_WEIGHT else "medium"
    elif result["self_hosted"]:
        result["confidence"] = "medium"
    elif main is not None:
        result["confidence"] = "low"
    result["evidence"] = evidence
    result["sending_services"] = [{"key": key, "name": name} for key, name in sorted(sending.items())]
    return result


_SPF_RE = re.compile(r"^v=spf1(\s|$)", re.IGNORECASE)


def spf_from_email_security(value: object) -> str | None:
    """SPF publié, lu dans le résultat du module email_security (None si absent)."""
    spf = value.get("spf") if isinstance(value, dict) else None
    record = spf.get("record") if isinstance(spf, dict) else None
    return record if isinstance(record, str) and _SPF_RE.match(record) else None
