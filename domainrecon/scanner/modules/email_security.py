# =============================================================================
# DomainRecon - Module « email_security » : SPF, DKIM, DMARC, MTA-STS, TLS-RPT
# =============================================================================
# MODULE D'EXEMPLE (contrat : docs/contrat-modules.md). Tout ce que
# l'application sait de ce module est déclaré dans CE fichier :
#   - le ModuleSpec en bas (SPEC), découvert automatiquement par modules/__init__.py ;
#   - ses constats « À corriger » (EMAIL_FINDINGS) ;
#   - son critère du score (score.EMAIL_RULE : 15 points, évaluateur partagé
#     avec les familles dans score.py) ;
#   - ses textes : domainrecon/i18n/modules/email_security.fr.json et .en.json
#     (titre, ce que le module vérifie, pourquoi c'est important). Les messages
#     des constats « finding.* » sont, pour ce module historique, dans le
#     catalogue principal ; un nouveau module met les siens dans ses fragments.
#
# Le travail réel (requêtes DNS, analyse des enregistrements) est dans
# scanner/email_security.py : l'adaptateur reste court et se teste sans réseau.
# Le domaine enregistrable (ScanContext.apex) porte SPF et DKIM, DMARC s'évalue
# sur la cible avec repli sur l'apex. Sans objet pour une adresse IP ni pour un
# hôte de plateforme mutualisée, dont l'email relève de la plateforme.
# =============================================================================

from ...i18n import msg
from .. import email_security, score
from ..registry import ModuleSpec, ScanContext, skip_for_ip_target
from ..rules import FindingInput, FindingRule
from ..score import as_dict

# -----------------------------------------------------------------------------
# 1. Exécution : run(contexte) -> dict JSON
# -----------------------------------------------------------------------------
# Contrat (orchestrator.py) : renvoyer un dict avec `measured` (bool) et `error`
# (message traduisible ou None) ; lever ModuleError(msg(...)) en cas d'échec
# réel ; ne jamais avaler asyncio.CancelledError ; uniquement des types JSON.


async def run(context: ScanContext) -> dict:
    return await email_security.analyze_email_security(context.apex, dmarc_domain=context.domain)


# -----------------------------------------------------------------------------
# 2. Cible sans objet : skip_reason(contexte) -> message ou None
# -----------------------------------------------------------------------------
# Évaluée juste avant le départ : un message rend le module « sans objet »
# (statut skipped, statut global intact) sans l'exécuter.


def skip_reason(context: ScanContext) -> object | None:
    if context.shared_platform:
        return msg("orchestrator.skip_shared_platform")
    return skip_for_ip_target(context)


# -----------------------------------------------------------------------------
# 3. Valeur de repli : ce qui est enregistré si le module n'a pas de résultat
# -----------------------------------------------------------------------------
# (échec, délai, sans objet, non lancé). Par défaut {measured: False, error} ;
# celui-ci y ajoute la note « N/A » que l'interface historique lit.


def placeholder(error: object) -> dict:
    return {"measured": False, "error": error, "overall_grade": "N/A"}


# -----------------------------------------------------------------------------
# 4. Constats « À corriger » : une FindingRule par code de message
# -----------------------------------------------------------------------------
# check(entrée) lit entrée.data (résultat enregistré du module, relu de la base :
# lecture défensive avec as_dict / as_list) et renvoie None/False (rien), True
# (constat sans paramètre), un dict (paramètres du message) ou une liste. Les
# règles ne sont évaluées que si le module est mesuré (statut « ok »).


def _email(f: FindingInput) -> dict | None:
    email = as_dict(f.data)
    return None if email.get("measured") is False else email


def _check_dmarc_missing(f: FindingInput) -> bool:
    email = _email(f)
    return email is not None and as_dict(email.get("dmarc")).get("found") is False


def _check_dmarc_not_enforced(f: FindingInput) -> bool:
    email = _email(f)
    dmarc = as_dict(email.get("dmarc")) if email is not None else {}
    return dmarc.get("found") is True and dmarc.get("policy") in (None, "none")


def _check_spf_missing(f: FindingInput) -> bool:
    email = _email(f)
    return email is not None and as_dict(email.get("spf")).get("found") is False


def _check_spf_weak(f: FindingInput) -> bool:
    email = _email(f)
    spf = as_dict(email.get("spf")) if email is not None else {}
    return spf.get("found") is True and spf.get("grade") == "F"


EMAIL_FINDINGS = (
    FindingRule(code="finding.dmarc_missing", severity="high", check=_check_dmarc_missing),
    FindingRule(code="finding.dmarc_not_enforced", severity="high", check=_check_dmarc_not_enforced),
    FindingRule(code="finding.spf_missing", severity="medium", check=_check_spf_missing),
    FindingRule(code="finding.spf_weak", severity="medium", check=_check_spf_weak),
)


# -----------------------------------------------------------------------------
# 5. Déclaration
# -----------------------------------------------------------------------------

SPEC = ModuleSpec(
    # Clé : celle du fichier, de module_status et des textes i18n (module.email_security.*).
    name="email_security",
    family="email",
    # passif : aucune requête vers la cible au-delà d'un usage normal (ici, DNS public).
    category="passif",
    run=run,
    skip_reason=skip_reason,
    # Vague 1 : indépendant des autres modules ; délai : celui du profil (Réglages).
    wave=1,
    # Profil « rapide » : contrôle essentiel et rapide.
    quick=True,
    # Ordre d'exécution et d'affichage (les 18 historiques : 10 à 180).
    order=90,
    # Son échec ou son absence, faute de note et de constat, rend la famille E-mail « non mesurée ».
    verdict=True,
    findings=EMAIL_FINDINGS,
    score_rules=(score.EMAIL_RULE,),
    placeholder=placeholder,
    # Module historique : colonne dédiée du scan (un nouveau module n'en a pas).
    column="email_security",
)
