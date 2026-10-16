# =============================================================================
# DomainRecon - Module « whois_data » : enregistrement du domaine (RDAP puis WHOIS)
# =============================================================================
# Sur le domaine enregistrable (ScanContext.apex), seul nom connu du registre.
#
#   1. RDAP en priorité (impl/whois_rdap.py) : protocole structuré que les
#      registres doivent servir (le WHOIS TCP/43 disparaît : Nominet l'a coupé en
#      février 2025) ; serveur trouvé par la table d'amorçage de l'IANA ;
#   2. WHOIS en repli (scanner/whois_lookup.py, python-whois) quand le RDAP est
#      injoignable, inconnu pour l'extension, ou quand il laisse le registrar,
#      l'expiration ou les serveurs de noms vides ; il complète alors les champs
#      manquants (source « rdap+whois »).
#   Un 404 RDAP n'est cru qu'après vérification par le WHOIS (évite de déclarer
#   « non enregistré » un domaine sur la foi d'un serveur RDAP défaillant).
#
# Champs du résultat : ceux de whois_lookup (registrar, dates, name_servers,
# status en codes EPP, dnssec, registrant, emails, registered, queried_domain)
# plus whois_server, source (« rdap », « whois » ou « rdap+whois ») et
# days_to_expiry. Les données personnelles masquées (RGPD) restent masquées.
#
# Constats : domaine expiré ou proche de l'expiration, absence de verrou de
# transfert (domaines à statuts EPP seulement : les ccTLD sans EPP ne sont pas
# jugés). Critère de score « whois » (5 points).
#
# Sans objet pour une adresse IP. Hors du profil « rapide » : les serveurs sont
# lents et capricieux.
# =============================================================================

from ...i18n import msg
from .. import whois_lookup
from ..impl import whois_rdap
from ..registry import ModuleSpec, ScanContext, skip_for_ip_target
from ..rules import FindingInput, FindingRule, Outcome, ScoreRule, hit
from ..score import as_dict, as_list

# Jours avant expiration : en dessous, constat (gravité croissante).
EXPIRY_HIGH_DAYS = 14
EXPIRY_MEDIUM_DAYS = 30
EXPIRY_LOW_DAYS = 60


# -----------------------------------------------------------------------------
# Exécution
# -----------------------------------------------------------------------------


def _incomplete(parsed: dict) -> bool:
    """Le RDAP a répondu mais sans l'essentiel : registrar, expiration ou serveurs de noms."""
    return not (parsed.get("registrar") and parsed.get("expiration_date") and parsed.get("name_servers"))


def _stamp(result: dict, source: str, apex: str) -> dict:
    result["source"] = source
    result.setdefault("whois_server", None)
    result.setdefault("queried_domain", apex)
    result["days_to_expiry"] = whois_rdap.days_until(result.get("expiration_date"))
    return result


async def run(context: ScanContext) -> dict:
    apex = context.apex
    rdap = whois_rdap.RdapOutcome("unavailable")
    if context.http is not None:
        rdap = await whois_rdap.lookup(context.http, apex)

    if rdap.kind == "ok" and rdap.data is not None:
        parsed = {
            **rdap.data,
            "queried_domain": apex,
            "registered": True,
            "measured": True,
            "error": None,
        }
        if not _incomplete(parsed):
            return _stamp(parsed, "rdap", apex)
        # Champs manquants : le WHOIS les complète s'il répond (sinon le RDAP seul suffit).
        legacy = await whois_lookup.get_whois_data(apex)
        if isinstance(legacy, dict) and legacy.get("measured") and legacy.get("registered"):
            return _stamp(whois_rdap.merge(parsed, legacy), "rdap+whois", apex)
        return _stamp(parsed, "rdap", apex)

    legacy = await whois_lookup.get_whois_data(apex)
    if not isinstance(legacy, dict):
        return legacy
    if rdap.kind == "not_found" and not legacy.get("measured"):
        # Le WHOIS n'a rien dit : le 404 du registre fait foi.
        return _stamp({**legacy, "registered": False, "measured": True, "error": None}, "rdap", apex)
    return _stamp(legacy, "whois", apex)


# -----------------------------------------------------------------------------
# Constats « À corriger »
# -----------------------------------------------------------------------------
# Lecture défensive : un ancien scan n'a pas days_to_expiry ni source.


def _days(data: dict) -> int | None:
    return whois_rdap.days_until(data.get("expiration_date"))


def _check_expired(f: FindingInput) -> bool:
    data = as_dict(f.data)
    days = _days(data)
    return data.get("registered") is not False and days is not None and days < 0


def _check_expires_soon(f: FindingInput):
    data = as_dict(f.data)
    days = _days(data)
    if data.get("registered") is False or days is None or not 0 <= days <= EXPIRY_LOW_DAYS:
        return None
    if days <= EXPIRY_HIGH_DAYS:
        return hit(severity="high", days=days)
    if days <= EXPIRY_MEDIUM_DAYS:
        return hit(severity="medium", days=days)
    return hit(severity="low", days=days)


def _check_no_transfer_lock(f: FindingInput) -> bool:
    data = as_dict(f.data)
    statuses = [s for s in as_list(data.get("status")) if isinstance(s, str)]
    if data.get("registered") is False or not whois_rdap.has_epp_status(statuses):
        return False
    return not whois_rdap.has_transfer_lock(statuses)


WHOIS_FINDINGS = (
    FindingRule(code="finding.whois_data.expired", severity="critical", check=_check_expired),
    FindingRule(code="finding.whois_data.expires_soon", severity="medium", check=_check_expires_soon),
    FindingRule(code="finding.whois_data.no_transfer_lock", severity="low", check=_check_no_transfer_lock),
)


# -----------------------------------------------------------------------------
# Critère de score « whois » (5 points, famille identité)
# -----------------------------------------------------------------------------


def _score(data: dict) -> Outcome:
    whois = as_dict(data.get("whois_data"))
    if whois.get("registered") is False:
        return Outcome(0, msg("whois_data.score_unregistered"), False, applicable=False)
    days = _days(whois)
    if days is None:
        # Pas de date d'expiration (ccTLD sans donnée publique) : rien à évaluer.
        return Outcome(0, msg("whois_data.score_no_date"), False, applicable=False)
    if days < 0:
        return Outcome(0, msg("whois_data.score_expired", days=-days), True)
    if days <= EXPIRY_HIGH_DAYS:
        return Outcome(1, msg("whois_data.score_soon", days=days), True)
    if days <= EXPIRY_MEDIUM_DAYS:
        return Outcome(3, msg("whois_data.score_soon", days=days), True)
    statuses = [s for s in as_list(whois.get("status")) if isinstance(s, str)]
    if whois_rdap.has_epp_status(statuses) and not whois_rdap.has_transfer_lock(statuses):
        return Outcome(4, msg("whois_data.score_no_lock"), True)
    return Outcome(5, msg("whois_data.score_ok", days=days), True)


WHOIS_SCORE_RULE = ScoreRule(criterion="whois", weight=5, evaluate=_score)

SPEC = ModuleSpec(
    name="whois_data",
    family="identity",
    category="passif",
    run=run,
    skip_reason=skip_for_ip_target,
    order=70,
    column="whois_data",
    findings=WHOIS_FINDINGS,
    score_rules=(WHOIS_SCORE_RULE,),
)
