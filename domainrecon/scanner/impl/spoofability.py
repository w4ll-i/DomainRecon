# =============================================================================
# DomainRecon - Logique du module « spoofability » : score d'usurpabilité du domaine
# =============================================================================
# Calcul PUR (aucune requête) à partir du résultat du module email_security. Score
# 0-100 (100 = usurpation triviale) et niveaux de risque, selon ces principes :
#   - DMARC est le facteur dominant, car lui seul protège l'adresse « From: » visible ;
#   - SPF ne compte que pour ce qu'il autorise réellement (+all rend DMARC contournable) ;
#   - DKIM et catch-all n'interviennent pas : ils n'empêchent ni n'autorisent l'usurpation ;
#   - une politique de sous-domaines plus faible (sp=) est évaluée à part ;
#   - un verdict clair (usurpable, partiel, protégé) et des scénarios d'attaque en clair.
# =============================================================================

from ...i18n import msg

# Points de départ selon la politique DMARC (plus c'est haut, plus l'usurpation est facile).
_DMARC_BASE = {"reject": 5, "quarantine": 15, "partial": 40, "monitor": 70, "invalid": 75, "absent": 85}
# Messages par niveau DMARC (code littéral, comme tout msg()).
_DMARC_FACTORS = {
    "reject": msg("spoofability.dmarc_reject"),
    "quarantine": msg("spoofability.dmarc_quarantine"),
    "monitor": msg("spoofability.dmarc_monitor"),
    "invalid": msg("spoofability.dmarc_invalid"),
    "absent": msg("spoofability.dmarc_absent"),
}
# Ajustement selon SPF quand DMARC est appliqué ou non.
_SPF_ENFORCED = {"open": 75, "broken": 5}
_SPF_UNENFORCED = {"strict": -20, "soft": -10, "neutral": 0, "open": 15, "broken": 5, "absent": 10}
_SPF_FACTORS = {
    "strict": msg("spoofability.spf_strict"),
    "soft": msg("spoofability.spf_soft"),
    "neutral": msg("spoofability.spf_neutral"),
    "open": msg("spoofability.spf_open"),
    "broken": msg("spoofability.spf_broken"),
    "absent": msg("spoofability.spf_absent"),
}
_SPF_ALL = {"-all": "strict", "~all": "soft", "?all": "neutral"}
_ENFORCED = ("reject", "quarantine", "partial")
# Part du score d'un sous-domaine mal protégé qui pèse sur le score global.
_SUBDOMAIN_WEIGHT = 0.6
# Un sous-domaine est « exposé » s'il est nettement plus facile à usurper que le domaine.
_SUBDOMAIN_GAP = 20
_SPF_OPEN_CODES = frozenset({"email.spf_pass_all", "email.spf_include_pass_all"})


def _issue_codes(issues: object) -> set[str]:
    """Codes des messages d'une liste de constats stockés ({"$t": code, "p": {...}})."""
    if not isinstance(issues, list):
        return set()
    return {item["$t"] for item in issues if isinstance(item, dict) and isinstance(item.get("$t"), str)}


def spf_level(spf: object) -> str:
    """strict, soft, neutral, open (autorise tout expéditeur), broken (erreur), absent ou unknown."""
    if not isinstance(spf, dict) or spf.get("error") or spf.get("found") is None:
        return "unknown"
    if spf["found"] is False:
        return "absent"
    if spf.get("all") == "+all" or _issue_codes(spf.get("issues")) & _SPF_OPEN_CODES:
        return "open"
    if spf.get("grade") == "F":
        return "broken"
    return _SPF_ALL.get(spf.get("all"), "neutral")


def dmarc_level(policy: str | None, found: bool | None, pct: object) -> str:
    """reject, quarantine, partial (appliqué sur une partie des messages), monitor, invalid, absent ou unknown."""
    if found is None:
        return "unknown"
    if found is False:
        return "absent"
    if policy not in ("none", "quarantine", "reject"):
        return "invalid"
    if policy == "none":
        return "monitor"
    if isinstance(pct, int) and not isinstance(pct, bool) and pct < 100:
        return "partial"
    return policy


def _risk(score: int) -> str:
    for limit, label in ((70, "critical"), (50, "high"), (30, "medium"), (10, "low")):
        if score >= limit:
            return label
    return "minimal"


def _factor_dmarc(level: str, pct: object) -> dict:
    if level == "partial":
        return msg("spoofability.dmarc_partial", pct=pct)
    return _DMARC_FACTORS[level]


def compute(domain: str, email: dict) -> dict:
    """Score d'usurpabilité de `domain` à partir du résultat du module email_security.

    Rend un dict conforme au contrat (`measured`, `error`) ; `measured` est faux si DMARC n'a pu
    être lu.
    """
    spf = email.get("spf") if isinstance(email.get("spf"), dict) else {}
    dmarc = email.get("dmarc") if isinstance(email.get("dmarc"), dict) else {}
    pct = dmarc.get("pct")
    level = dmarc_level(dmarc.get("policy"), None if dmarc.get("error") else dmarc.get("found"), pct)
    spf_state = spf_level(spf)
    result: dict = {
        "measured": False,
        "error": None,
        "domain": domain,
        "score": None,
        "risk": None,
        "verdict": None,
        "dmarc_level": level,
        "spf_level": spf_state,
        "subdomain_score": None,
        "subdomain_exposed": False,
        "factors": [],
        "scenarios": [],
    }
    if level == "unknown":
        result["error"] = msg("spoofability.no_dmarc_data")
        return result

    factors = result["factors"]
    scenarios = result["scenarios"]
    enforced = level in _ENFORCED
    score = _DMARC_BASE[level]
    factors.append({"detail": _factor_dmarc(level, pct), "points": score})
    adjust = (_SPF_ENFORCED if enforced else _SPF_UNENFORCED).get(spf_state, 0)
    if spf_state != "unknown" and (adjust or not enforced):
        factors.append({"detail": _SPF_FACTORS[spf_state], "points": adjust})
    score = max(0, min(100, score + adjust))

    # Sous-domaines : le SPF ne s'hérite pas, c'est la politique sp= qui joue.
    sub_level = dmarc_level(dmarc.get("subdomain_policy") or dmarc.get("policy"), True, pct)
    sub_score = min(100, _DMARC_BASE[sub_level] + (0 if sub_level in _ENFORCED else 10))
    result["subdomain_score"] = sub_score
    result["subdomain_exposed"] = sub_score >= score + _SUBDOMAIN_GAP
    total = max(score, round(sub_score * _SUBDOMAIN_WEIGHT)) if enforced else score
    result.update(
        measured=True,
        score=total,
        risk=_risk(total),
        verdict="spoofable" if total >= 50 else "partial" if total >= 20 else "protected",
    )

    if not enforced:
        scenarios.append(msg("spoofability.scenario_from", domain=domain))
    if level == "partial":
        scenarios.append(msg("spoofability.scenario_partial", pct=pct))
    if enforced and spf_state == "open":
        scenarios.append(msg("spoofability.scenario_spf_open"))
    if result["subdomain_exposed"]:
        scenarios.append(
            msg("spoofability.scenario_subdomains", policy=dmarc.get("subdomain_policy") or "none")
        )
    return result
