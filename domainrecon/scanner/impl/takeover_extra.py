# =============================================================================
# DomainRecon - Takeover : empreintes complémentaires
# =============================================================================
# Le moteur principal liste 20 services (retrait volontaire des services jugés
# non exploitables). Cette table en ajoute une trentaine et réévalue chaque
# service d'après le registre public can-i-take-over-xyz (état du 15/10/2026,
# https://github.com/EdOverflow/can-i-take-over-xyz) :
#
#   - RÉTABLIS (« Vulnerable » ou « Edge case ») : Readme.io, Cargo Collective,
#     Webflow et les services ajoutés depuis (Agile CRM, Anima, Campaign Monitor,
#     Canny, Discourse, Frontify, Gemfury, GetResponse, HatenaBlog, Intercom,
#     JetBrains YouTrack, Landingi, Mashery, Pingdom, ReadTheDocs, Short.io,
#     Strikingly, SurveySparrow, Uberflip, Uptimerobot, Wix, Worksites, Airee).
#   - ÉCARTÉS (« Not vulnerable ») : Fastly, Kinsta, UserVoice, Zendesk, Statuspage,
#     Acquia, Fly.io, CloudFront, Render, Railway, Freshdesk, Mailchimp… : leur page
#     d'erreur ne prouve rien (le fournisseur exige une preuve de propriété ou
#     ne permet pas de réclamer le nom). Les garder serait produire des faux positifs.
#
# Même format que scanner.takeover.TAKEOVER_FINGERPRINTS (`cname` : expression sur
# la cible du CNAME ; `fingerprint` : page « site inexistant », None pour un nom
# réclamable dont seul le NXDOMAIN fait foi ; `edge` : preuve de propriété exigée,
# donc exploitation à vérifier). install() les ajoute à la table du scanner.
# =============================================================================

import re

from .. import takeover

EXTRA_FINGERPRINTS: dict[str, dict] = {
    "agilecrm.com": {
        "service": "Agile CRM",
        "cname": r"\.agilecrm\.com$",
        "fingerprint": r"Sorry, this page is no longer available\.",
    },
    "airee.ru": {
        "service": "Airee.ru",
        "cname": r"\.airee\.ru$",
        "fingerprint": r"Ошибка 402\. Сервис Айри\.рф не оплачен",
    },
    "animaapp.io": {
        "service": "Anima",
        "cname": r"\.animaapp\.io$",
        "fingerprint": r"The page you were looking for does not exist\.",
    },
    "createsend.com": {
        "service": "Campaign Monitor",
        "cname": r"(^|\.)createsend\.com$",
        "fingerprint": r"Trying to access your account\?",
    },
    "canny.io": {
        "service": "Canny",
        "cname": r"(^|\.)cname\.canny\.io$",
        "fingerprint": r"Company Not Found|There is no such company",
    },
    "cargocollective.com": {
        # « 404 Not Found » est une page banale : preuve faible, à vérifier.
        "service": "Cargo Collective",
        "cname": r"\.cargocollective\.com$",
        "fingerprint": r"<title>\s*404 Not Found\s*</title>",
        "edge": True,
    },
    "trydiscourse.com": {
        "service": "Discourse",
        "cname": r"\.trydiscourse\.com$",
        "fingerprint": None,
    },
    "frontify.com": {
        "service": "Frontify",
        "cname": r"\.frontify\.com$",
        "fingerprint": r"404 - Page Not Found|Oops\W+looks like you got lost",
        "edge": True,
    },
    "furyns.com": {
        "service": "Gemfury",
        "cname": r"(^|\.)furyns\.com$",
        "fingerprint": r"404: This page could not be found\.",
    },
    "getresponse.com": {
        "service": "GetResponse",
        "cname": r"\.(gr8|getresponse)\.com$",
        "fingerprint": r"With GetResponse Landing Pages, lead generation has never been easier",
    },
    "hatenablog.com": {
        "service": "HatenaBlog",
        "cname": r"\.hatenablog\.(com|jp)$",
        "fingerprint": r"404 Blog is not found",
    },
    "intercom.help": {
        "service": "Intercom",
        "cname": r"(^|\.)intercom\.help$",
        "fingerprint": r"Uh oh\. That page doesn.t exist\.",
        "edge": True,
    },
    "youtrack.cloud": {
        "service": "JetBrains YouTrack",
        "cname": r"\.youtrack\.cloud$",
        "fingerprint": r"is not a registered InCloud YouTrack",
    },
    "landingi.com": {
        "service": "Landingi",
        "cname": r"\.landingi\.(com|io)$",
        "fingerprint": r"It looks like you.re lost",
        "edge": True,
    },
    "mashery.com": {
        "service": "Mashery",
        "cname": r"\.mashery\.com$",
        "fingerprint": r"Unrecognized domain",
        "edge": True,
    },
    "pingdom.com": {
        "service": "Pingdom",
        "cname": r"(^|\.)stats\.pingdom\.com$",
        "fingerprint": r"Sorry, couldn.t find the status page",
    },
    "readme.io": {
        "service": "Readme.io",
        "cname": r"\.readme\.io$",
        "fingerprint": r"The creators of this project are still working on making everything perfect!",
    },
    "readthedocs.io": {
        "service": "Read the Docs",
        "cname": r"\.readthedocs\.(io|org)$",
        "fingerprint": r"The link you have followed or the URL that you entered does not exist\.",
    },
    "short.io": {
        "service": "Short.io",
        "cname": r"(^|\.)short\.(io|cm)$",
        "fingerprint": r"Link does not exist",
    },
    "strikingly.com": {
        "service": "Strikingly",
        "cname": r"\.(strikinglydns|mystrikingly)\.com$",
        "fingerprint": r"PAGE NOT FOUND\.",
    },
    "surveysparrow.com": {
        "service": "SurveySparrow",
        "cname": r"\.surveysparrow\.com$",
        "fingerprint": r"Account not found\.",
    },
    "uberflip.com": {
        "service": "Uberflip",
        "cname": r"\.uberflip\.com$",
        "fingerprint": r"The URL you.ve accessed does not provide a hub\.",
    },
    "uptimerobot.com": {
        "service": "UptimeRobot",
        "cname": r"(^|\.)stats\.uptimerobot\.com$",
        "fingerprint": r"<title>[^<]*page not found",
    },
    "webflow.io": {
        "service": "Webflow",
        "cname": r"(\.webflow\.io|(^|\.)proxy-ssl\.webflow\.com)$",
        "fingerprint": r"The page you are looking for doesn.t exist or has been moved\.",
        "edge": True,
    },
    "wixdns.net": {
        "service": "Wix",
        "cname": r"\.wixdns\.net$",
        "fingerprint": r"Looks Like This Domain Isn.t Connected To A Website Yet!",
        "edge": True,
    },
    "worksites.net": {
        "service": "Worksites",
        "cname": r"\.worksites\.net$",
        "fingerprint": r"the website you(&rsquo;|.)re looking for doesn.t exist",
    },
}


def install() -> int:
    """Ajoute à la table du scanner les services absents ; renvoie le nombre ajouté (0 au 2e appel)."""
    added = 0
    for key, info in EXTRA_FINGERPRINTS.items():
        if key in takeover.TAKEOVER_FINGERPRINTS:
            continue
        takeover.TAKEOVER_FINGERPRINTS[key] = info
        takeover._COMPILED.append(
            (
                key,
                info,
                re.compile(info["cname"], re.I),
                re.compile(info["fingerprint"], re.I) if info["fingerprint"] else None,
            )
        )
        added += 1
    return added
