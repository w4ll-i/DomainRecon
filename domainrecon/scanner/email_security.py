# =============================================================================
# DomainRecon - Scanner : sécurité email (SPF, DKIM, DMARC)
# =============================================================================
# Chaque partie (spf, dmarc, dkim…) porte son propre `error` : un échec de
# requête DNS n'est jamais présenté comme une absence d'enregistrement, et la
# partie en erreur est exclue de la note globale.
# SPF, MX nul et DMARC sont évalués sur l'hôte scanné (domaine d'enveloppe et
# d'en-tête From:) ; DKIM, MTA-STS et TLS-RPT sur le domaine racine.
# =============================================================================

import asyncio
import re
import secrets

from ..i18n import msg
from .dns import DnsLookup, DnsQuerier, find_dmarc, has_null_mx, txt_record_text
from .targets import is_ip_literal

# Délai d'une requête DNS et budget total de l'analyse (inférieur à MODULE_TIMEOUT).
EMAIL_QUERY_TIMEOUT = 3.0
EMAIL_DNS_BUDGET = 40.0

# RFC 7208 §4.6.4 : au plus 10 termes provoquant une requête DNS.
SPF_MAX_DNS_LOOKUPS = 10

# Les sélecteurs DKIM ne sont pas énumérables : seuls les plus courants sont testés.
DKIM_SELECTORS = (
    "default",
    "google",
    "selector1",
    "selector2",
    "k1",
    "mail",
    "dkim",
    "s1",
    "s2",
    "protonmail",
    "zoho",
)

_GRADE_POINTS = {"A": 4, "B": 3, "C": 2, "D": 1, "F": 0}
_DMARC_POLICIES = ("none", "quarantine", "reject")
# RFC 7489 §6.6.4 : politique appliquée aux mails hors de l'échantillon pct=.
_DMARC_WEAKER = {"reject": "quarantine", "quarantine": "none"}
_SPF_MECHANISMS = frozenset({"all", "include", "a", "mx", "ptr", "ip4", "ip6", "exists"})
_SPF_LOOKUP_MECHANISMS = frozenset({"include", "a", "mx", "ptr", "exists"})
_SPF_MODIFIER_RE = re.compile(r"[a-z][a-z0-9_.-]*=")


# =============================================================================
# Analyse syntaxique (sans requête DNS)
# =============================================================================


def parse_tags(text: str) -> dict[str, str]:
    """Liste tag=valeur (DMARC, DKIM) : noms en minuscules, blancs autour de « = » ignorés."""
    tags: dict[str, str] = {}
    for part in text.split(";"):
        name, sep, value = part.partition("=")
        name = name.strip().lower()
        if sep and name and name not in tags:
            tags[name] = value.strip()
    return tags


def is_spf_record(text: str) -> bool:
    """Un enregistrement SPF commence par « v=spf1 » (RFC 7208 §4.5, insensible à la casse)."""
    parts = text.split(maxsplit=1)
    return bool(parts) and parts[0].lower() == "v=spf1"


def parse_spf(record: str) -> dict:
    """Analyse un enregistrement SPF terme par terme.

    `all` : qualificatif du mécanisme all (+, -, ~, ?) ou None s'il est absent.
    `redirect` : cible de redirect=, ignorée quand all est présent.
    `includes` : cibles des include ; `pass_includes` : celles de qualificatif +.
    `lookups` : termes de cet enregistrement qui consomment une requête DNS.
    `ptr` : mécanisme ptr évalué, déconseillé par la RFC 7208 §5.5.
    `errors` : erreurs de syntaxe, termes placés après all compris.
    """
    all_qualifier = None
    redirect = None
    includes: list[str] = []
    pass_includes: list[str] = []
    lookups = 0
    uses_ptr = False
    errors: list[object] = []

    for term in record.split()[1:]:
        low = term.lower()
        if _SPF_MODIFIER_RE.match(low):
            name, _, value = low.partition("=")
            if name == "redirect" and value:
                redirect = value.rstrip(".")
            continue  # exp= et modificateurs inconnus : sans effet sur la note
        qualifier = "+"
        if low[0] in "+-~?":
            qualifier, low = low[0], low[1:]
        mechanism = re.split(r"[:/]", low, maxsplit=1)[0]
        target = low.partition(":")[2].split("/")[0].rstrip(".") if mechanism == "include" else None
        if mechanism not in _SPF_MECHANISMS or target == "":
            errors.append(msg("email.spf_invalid_term", term=term))
            continue
        if all_qualifier is not None:
            # Terme après all : jamais évalué, mais une erreur de syntaxe où
            # que ce soit dans l'enregistrement est un permerror (RFC 7208 §4.6).
            continue
        if mechanism == "all":
            all_qualifier = qualifier
            continue
        if mechanism in _SPF_LOOKUP_MECHANISMS:
            lookups += 1
        if mechanism == "ptr":
            uses_ptr = True
        if target:
            includes.append(target)
            if qualifier == "+":
                pass_includes.append(target)

    if all_qualifier is not None:
        redirect = None  # RFC 7208 §6.1 : redirect ignoré en présence de all
    elif redirect:
        lookups += 1
    return {
        "all": all_qualifier,
        "redirect": redirect,
        "includes": includes,
        "pass_includes": pass_includes,
        "lookups": lookups,
        "ptr": uses_ptr,
        "errors": errors,
    }


def _dkim_key_status(text: str) -> str | None:
    """'valid', 'revoked' (p= vide) ou None si le TXT n'est pas une clé DKIM (RFC 6376 §3.6.1)."""
    tags = parse_tags(text)
    version = tags.get("v")
    if (version is not None and version.upper() != "DKIM1") or "p" not in tags:
        return None
    return "valid" if re.sub(r"\s+", "", tags["p"]) else "revoked"


# =============================================================================
# SPF
# =============================================================================


class _SpfEvaluation:
    """Suit include et redirect pour compter les requêtes DNS de tout l'arbre SPF."""

    def __init__(self, querier: DnsQuerier):
        self.querier = querier
        self.lookups = 0
        self.problems: list[object] = []
        self.unresolved_redirect: object | None = None
        # include du SPF du domaine qui autorisent tout expéditeur (+all).
        self.pass_all_includes: list[str] = []
        # Mécanisme ptr dans le SPF du domaine (ou sa chaîne de redirect=) ;
        # celui d'un include tiers n'est pas du ressort du domaine.
        self.uses_ptr = False
        self._cache: dict[str, DnsLookup] = {}
        self._stack: list[str] = []

    def walk(self, record: str, decides_all: bool = True) -> str | None:
        """Ajoute le coût de `record` et renvoie le qualificatif all effectif.

        `decides_all` : l'enregistrement est sur la chaîne de redirect= partie du
        SPF du domaine, donc son all est celui du domaine (pas celui d'un include).
        Dans un include, renvoie « + » si l'enregistrement autorise tout
        expéditeur, y compris par un include imbriqué.
        """
        parsed = parse_spf(record)
        self.lookups += parsed["lookups"]
        self.problems.extend(parsed["errors"])
        self.uses_ptr = self.uses_ptr or (decides_all and parsed["ptr"])
        passes_all = False
        for target in parsed["includes"]:
            included_all = self._follow(target, "include", decides_all=False)
            # Un include « + » dont l'enregistrement se termine par +all
            # correspond à tout expéditeur : le all qui suit n'est jamais
            # atteint (RFC 7208 §5.2).
            if included_all == "+" and target in parsed["pass_includes"]:
                passes_all = True
                if decides_all and target not in self.pass_all_includes:
                    self.pass_all_includes.append(target)
        if passes_all and not decides_all:
            return "+"
        if parsed["all"] is not None:
            return parsed["all"]
        if parsed["redirect"]:
            return self._follow(parsed["redirect"], "redirect", decides_all)
        return None

    def _follow(self, target: str, kind: str, decides_all: bool) -> str | None:
        # Limite déjà dépassée (permerror acquis) ou macro connue seulement à
        # l'évaluation : inutile d'interroger davantage.
        if self.lookups > SPF_MAX_DNS_LOOKUPS or "%" in target:
            return None
        if target in self._stack:
            self.problems.append(msg("email.spf_loop", kind=kind, target=target))
            return None
        if target not in self._cache:
            self._cache[target] = self.querier.lookup(target, "TXT")
        result = self._cache[target]
        if result.status == "error":
            if kind == "redirect" and decides_all:
                self.unresolved_redirect = msg("email.spf_redirect_error", target=target, error=result.error)
            return None  # décompte incomplet, sans conclusion sur le domaine
        records = [t for t in map(txt_record_text, result.answers) if is_spf_record(t)]
        if len(records) != 1:
            if records:
                self.problems.append(msg("email.spf_include_many", kind=kind, target=target))
            else:
                self.problems.append(msg("email.spf_include_none", kind=kind, target=target))
            return None
        self._stack.append(target)
        try:
            return self.walk(records[0], decides_all)
        finally:
            self._stack.pop()


def _empty_spf() -> dict:
    return {
        # Nom interrogé : l'hôte scanné (domaine d'enveloppe), le SPF ne
        # s'héritant pas du domaine parent (RFC 7208 §4.4).
        "domain": None,
        # Sous-domaine scanné : SPF du domaine racine, à titre d'information.
        "apex_domain": None,
        "apex_record": None,
        "found": None,
        "record": None,
        "records": [],
        "all": None,
        "dns_lookups": None,
        "issues": [],
        "grade": None,
        "error": None,
    }


def _analyze_spf(querier: DnsQuerier, txt: DnsLookup, recommendations: list[object]) -> dict:
    spf = _empty_spf()
    if txt.status == "error":
        spf["error"] = msg("email.spf_query_failed", error=txt.error)
        return spf

    records = [t for t in map(txt_record_text, txt.answers) if is_spf_record(t)]
    spf["records"] = records
    if not records:
        spf.update(found=False, grade="F")
        spf["issues"].append(msg("email.spf_missing"))
        recommendations.append(msg("email.rec_add_spf"))
        return spf

    spf.update(found=True, record=records[0])
    issues = spf["issues"]
    if len(records) > 1:
        spf["grade"] = "F"
        issues.append(msg("email.spf_multiple", count=len(records)))
        recommendations.append(msg("email.rec_single_spf"))
        return spf

    evaluation = _SpfEvaluation(querier)
    qualifier = evaluation.walk(records[0])
    spf["dns_lookups"] = evaluation.lookups
    if qualifier is None and evaluation.unresolved_redirect:
        spf["error"] = msg("email.spf_query_failed", error=evaluation.unresolved_redirect)
        return spf

    spf["all"] = f"{qualifier}all" if qualifier else None
    issues.extend(evaluation.problems)
    if evaluation.lookups > SPF_MAX_DNS_LOOKUPS:
        issues.append(msg("email.spf_too_many_lookups", count=evaluation.lookups, max=SPF_MAX_DNS_LOOKUPS))
    permerror = bool(evaluation.problems) or evaluation.lookups > SPF_MAX_DNS_LOOKUPS

    if qualifier == "-":
        grade = "A"
    elif qualifier == "~":
        grade = "B"
        issues.append(msg("email.spf_softfail"))
    elif qualifier == "?":
        grade = "D"
        issues.append(msg("email.spf_neutral"))
    elif qualifier == "+":
        grade = "F"
        issues.append(msg("email.spf_pass_all"))
    else:
        grade = "D"
        issues.append(msg("email.spf_no_all"))
    for target in evaluation.pass_all_includes:
        grade = "F"
        issues.append(msg("email.spf_include_pass_all", target=target))
    if evaluation.uses_ptr:
        # Signalé sans effet sur la note : le mécanisme reste valide.
        issues.append(msg("email.spf_ptr"))

    spf["grade"] = "F" if permerror else grade
    if permerror:
        recommendations.append(msg("email.rec_fix_spf"))
    elif evaluation.pass_all_includes:
        recommendations.append(msg("email.rec_remove_pass_all"))
    elif grade in ("D", "F"):
        recommendations.append(msg("email.rec_end_spf"))
    return spf


# =============================================================================
# DMARC
# =============================================================================


def _empty_dmarc() -> dict:
    return {
        "found": None,
        "record": None,
        "policy": None,
        "subdomain_policy": None,
        "pct": None,
        # Alignements DKIM et SPF (adkim=, aspf= : « r » relâché par défaut, « s » strict)
        # et adresses des rapports d'échec (ruf=), lus à titre d'information.
        "adkim": None,
        "aspf": None,
        "ruf": [],
        "source": None,
        "inherited": False,
        "issues": [],
        "grade": None,
        "error": None,
    }


def _analyze_dmarc(querier: DnsQuerier, domain: str, recommendations: list[object]) -> dict:
    dmarc = _empty_dmarc()
    lookup = find_dmarc(querier, domain)
    if lookup.error:
        dmarc["error"] = msg("email.dmarc_query_failed", error=lookup.error)
        return dmarc
    if not lookup.records:
        dmarc.update(found=False, grade="F")
        dmarc["issues"].append(msg("email.dmarc_missing"))
        recommendations.append(msg("email.rec_add_dmarc"))
        return dmarc

    dmarc.update(found=True, record=lookup.records[0], source=lookup.source, inherited=lookup.inherited)
    issues = dmarc["issues"]
    if len(lookup.records) > 1:
        dmarc["grade"] = "F"
        issues.append(msg("email.dmarc_multiple"))
        recommendations.append(msg("email.rec_single_dmarc"))
        return dmarc

    tags = parse_tags(lookup.records[0])
    p = tags.get("p", "").lower()
    sp = tags.get("sp", "").lower()
    policy = p if p in _DMARC_POLICIES else None
    invalid_sp = bool(sp) and sp not in _DMARC_POLICIES
    if invalid_sp:
        issues.append(msg("email.dmarc_invalid_sp", value=tags["sp"]))
    subdomain_policy = sp if sp in _DMARC_POLICIES else policy
    dmarc["subdomain_policy"] = subdomain_policy
    # Politique héritée du domaine organisationnel : c'est sp= qui s'applique.
    effective = subdomain_policy if lookup.inherited else policy
    dmarc["policy"] = effective
    has_rua = bool(tags.get("rua"))
    dmarc["adkim"] = "s" if tags.get("adkim", "").strip().lower() == "s" else "r"
    dmarc["aspf"] = "s" if tags.get("aspf", "").strip().lower() == "s" else "r"
    dmarc["ruf"] = [uri.strip()[:200] for uri in tags.get("ruf", "").split(",") if uri.strip()][:5]

    raw_pct = tags.get("pct")
    pct = int(raw_pct) if raw_pct is not None and raw_pct.isdigit() and int(raw_pct) <= 100 else None
    # RFC 7489 §6.6.4 : les mails hors de l'échantillon pct= reçoivent la
    # politique immédiatement moins stricte ; la note retient la plus faible.
    applied = _DMARC_WEAKER.get(effective, effective) if pct is not None and pct < 100 else effective

    if policy is None or invalid_sp:
        # RFC 7489 §6.6.3 : un p= ou un sp= invalide rend l'enregistrement
        # invalide. Avec rua=, le destinataire applique p=none ; sinon rien.
        if policy is None:
            issues.append(msg("email.dmarc_invalid_p"))
            recommendations.append(msg("email.rec_fix_dmarc_p"))
        else:
            recommendations.append(msg("email.rec_fix_dmarc_sp"))
        dmarc["policy"] = dmarc["subdomain_policy"] = None
        grade = "D" if has_rua else "F"
    elif effective == "none":
        grade = "D"
        issues.append(msg("email.dmarc_none"))
        recommendations.append(msg("email.rec_dmarc_enforce"))
    else:
        grade = {"reject": "A", "quarantine": "B"}.get(applied, "D")
        if applied != effective:
            recommendations.append(msg("email.rec_dmarc_pct"))
        if not lookup.inherited and sp == "none":
            issues.append(msg("email.dmarc_sp_none"))

    if pct is not None:
        dmarc["pct"] = pct
        if pct < 100:
            if dmarc["policy"] is not None and applied != effective:
                issues.append(msg("email.dmarc_pct_weaker", pct=pct, policy=applied))
            else:
                issues.append(msg("email.dmarc_pct", pct=pct))
    elif raw_pct is not None:
        issues.append(msg("email.dmarc_invalid_pct", value=raw_pct))
    if not has_rua:
        issues.append(msg("email.dmarc_no_rua"))

    dmarc["grade"] = grade
    return dmarc


# =============================================================================
# DKIM, MTA-STS, TLS-RPT
# =============================================================================


def _random_dkim_selector() -> str:
    """Sélecteur aléatoire, jamais publié : seul un joker *._domainkey y répond."""
    return f"dr-{secrets.token_hex(8)}"


def _dkim_answer_status(texts: frozenset[str]) -> str | None:
    """'valid' si l'une des réponses est une clé, 'revoked' si toutes sont révoquées, sinon None."""
    statuses = {_dkim_key_status(text) for text in texts}
    if "valid" in statuses:
        return "valid"
    return "revoked" if "revoked" in statuses else None


def _analyze_dkim(
    querier: DnsQuerier, domain: str, recommendations: list[object], expects_signing: bool = True
) -> dict:
    """Clés DKIM des sélecteurs courants de `domain`.

    `expects_signing` faux (domaine sans messagerie) : une clé absente n'est
    ni un problème ni une recommandation.
    """
    dkim = {
        "found": None,
        "selectors_found": [],
        "revoked_selectors": [],
        "selectors_tested": list(DKIM_SELECTORS),
        # Joker *._domainkey : "revoked" (p= vide), "valid" ou None (aucun, ou sonde en échec).
        "wildcard": None,
        "issues": [],
        "error": None,
    }
    # Sonde d'un sélecteur aléatoire, une seule fois : un sélecteur courant qui
    # renvoie la même réponse que le joker n'est pas une clé publiée pour lui.
    probe = querier.lookup(f"{_random_dkim_selector()}._domainkey.{domain}", "TXT")
    wildcard_answer = frozenset(map(txt_record_text, probe.answers)) if probe.status == "ok" else frozenset()
    dkim["wildcard"] = _dkim_answer_status(wildcard_answer)

    failures = []
    for selector in DKIM_SELECTORS:
        result = querier.lookup(f"{selector}._domainkey.{domain}", "TXT")
        if result.status == "error":
            failures.append(result.error)
            continue
        answer = frozenset(map(txt_record_text, result.answers))
        if dkim["wildcard"] and answer == wildcard_answer:
            continue
        # Seul un TXT qui est réellement une clé compte : un TXT joker
        # (*.example.com) ou une clé révoquée ne prouve pas DKIM.
        status = _dkim_answer_status(answer)
        if status == "valid":
            dkim["selectors_found"].append(selector)
        elif status == "revoked":
            dkim["revoked_selectors"].append(selector)

    if dkim["selectors_found"] or dkim["wildcard"] == "valid":
        dkim["found"] = True
    elif len(failures) == len(DKIM_SELECTORS):
        dkim["error"] = msg("email.dkim_query_failed", error=failures[0])
    else:
        dkim["found"] = False
        if expects_signing:
            dkim["issues"].append(msg("email.dkim_missing"))
            recommendations.append(msg("email.rec_check_dkim"))
    if dkim["wildcard"] == "valid":
        dkim["issues"].append(msg("email.dkim_wildcard"))
    for selector in dkim["revoked_selectors"]:
        dkim["issues"].append(msg("email.dkim_revoked", selector=selector))
    return dkim


def _lookup_policy_record(querier: DnsQuerier, name: str, version: str) -> dict:
    """Présence d'un enregistrement TXT versionné (MTA-STS, TLS-RPT) : informatif, non noté."""
    result = querier.lookup(name, "TXT")
    if result.status == "error":
        return {
            "found": None,
            "record": None,
            "error": msg("email.policy_query_failed", name=name, error=result.error),
        }
    records = [
        text
        for text in map(txt_record_text, result.answers)
        if parse_tags(text).get("v", "").lower() == version.lower()
    ]
    return {"found": bool(records), "record": records[0] if records else None, "error": None}


# =============================================================================
# Module 9 : Email Security (SPF/DKIM/DMARC Analysis)
# =============================================================================


def _overall_grade(spf: dict, dmarc: dict, dkim: dict) -> str:
    """Moyenne des parties mesurées. DKIM ne peut qu'améliorer la note : une clé
    non trouvée sur les sélecteurs courants ne prouve pas l'absence de DKIM.

    Sans DMARC appliqué (quarantine ou reject), la note est plafonnée à C.
    """
    points = [_GRADE_POINTS[g] for g in (spf["grade"], dmarc["grade"]) if g is not None]
    if not points:
        return "N/A"
    if dkim["found"]:
        points.append(_GRADE_POINTS["A"])
    avg = sum(points) / len(points)
    if avg >= 3.5:
        grade = "A"
    elif avg >= 2.5:
        grade = "B"
    elif avg >= 1.5:
        grade = "C"
    elif avg >= 0.5:
        grade = "D"
    else:
        grade = "F"
    # Seul DMARC protège l'adresse From: visible : SPF vérifie l'expéditeur
    # d'enveloppe et DKIM seul n'impose rien au destinataire. DMARC absent,
    # invalide ou sans effet (none) : l'usurpation reste possible.
    if dmarc["grade"] in ("D", "F") and grade in ("A", "B"):
        return "C"
    return grade


def _add_apex_spf(querier: DnsQuerier, spf: dict, apex: str, host: str) -> None:
    """SPF du domaine racine, à titre d'information : il ne couvre pas `host` (RFC 7208 §4.4)."""
    txt = querier.lookup(apex, "TXT")
    records = [t for t in map(txt_record_text, txt.answers) if is_spf_record(t)]
    spf["apex_domain"] = apex
    spf["apex_record"] = records[0] if records else None
    if spf["found"] is False and records:
        spf["issues"].append(msg("email.spf_not_inherited", apex=apex, host=host))


def _analyze_email_security_sync(domain: str, dmarc_domain: str | None = None) -> dict:
    """Analyse approfondie de la sécurité email - SPF, DKIM, DMARC.

    `dmarc_domain` est l'hôte scanné (`domain` par défaut). SPF (évalué sur le
    domaine d'enveloppe exact, sans héritage du parent), MX nul et DMARC y sont
    évalués ; DMARC avec repli sur le domaine organisationnel si c'est un
    sous-domaine : même recherche que l'onglet DNS. DKIM, MTA-STS et TLS-RPT
    sont cherchés sur `domain` (domaine racine), dont le SPF est seulement
    rapporté (spf.apex_record) quand l'hôte est un sous-domaine. `measured`
    est vrai dès que SPF ou DMARC a obtenu une réponse DNS exploitable.
    """
    domain = (domain or "").strip().lower().rstrip(".")
    host = (dmarc_domain or "").strip().lower().rstrip(".") or domain
    result = {
        "domain": domain,
        # Hôte scanné : SPF, MX nul et DMARC (sp= s'applique s'il en hérite).
        "dmarc_domain": host,
        # MX nul (RFC 7505) sur l'hôte : aucun courrier accepté (None : non mesuré).
        "null_mx": None,
        "spf": _empty_spf(),
        "dmarc": _empty_dmarc(),
        "dkim": {
            "found": None,
            "selectors_found": [],
            "revoked_selectors": [],
            "selectors_tested": [],
            "wildcard": None,
            "issues": [],
            "error": None,
        },
        "mta_sts": {"found": None, "record": None, "error": None},
        "tls_rpt": {"found": None, "record": None, "error": None},
        "overall_grade": "N/A",
        "recommendations": [],
        # Constats favorables ou informatifs (ni problème ni recommandation).
        "notes": [],
        "measured": False,
        # Vrai si la note globale a été calculée sans SPF ou sans DMARC (requête en échec).
        "partial": False,
        "error": None,
    }
    if not domain:
        result["error"] = msg("email.no_domain")
        return result
    if is_ip_literal(domain):
        result["error"] = msg("email.not_for_ip")
        return result

    querier = DnsQuerier(EMAIL_QUERY_TIMEOUT, EMAIL_DNS_BUDGET)
    txt = querier.lookup(host, "TXT")
    if txt.status == "nxdomain":
        result["error"] = msg("dns.nxdomain_note", domain=host)
        return result

    recommendations = result["recommendations"]
    spf = result["spf"] = _analyze_spf(querier, txt, recommendations)
    spf["domain"] = host
    if host != domain:
        _add_apex_spf(querier, spf, domain, host)
    dmarc = result["dmarc"] = _analyze_dmarc(querier, host, recommendations)
    if spf["grade"] is None and dmarc["grade"] is None:
        # Résolveur indisponible : inutile d'interroger DKIM, rien n'est noté.
        result["error"] = msg("email.failed", errors=[e for e in (spf["error"], dmarc["error"]) if e])
        recommendations.clear()
        return result

    mx = querier.lookup(host, "MX")
    result["null_mx"] = None if mx.status == "error" else has_null_mx(mx.answers)
    # Domaine qui déclare ne recevoir ni n'envoyer aucun courrier (MX nul,
    # SPF -all, DMARC reject) : aucune signature DKIM n'est attendue.
    no_mail = result["null_mx"] is True and spf["grade"] == "A" and dmarc["grade"] == "A"
    dkim = result["dkim"] = _analyze_dkim(querier, domain, recommendations, expects_signing=not no_mail)
    if no_mail:
        result["notes"].append(msg("email.no_mail_domain"))
    elif dkim["wildcard"] == "revoked":
        result["notes"].append(msg("email.dkim_wildcard_revoked"))
    result["mta_sts"] = _lookup_policy_record(querier, f"_mta-sts.{domain}", "STSv1")
    result["tls_rpt"] = _lookup_policy_record(querier, f"_smtp._tls.{domain}", "TLSRPTv1")
    result["overall_grade"] = _overall_grade(spf, dmarc, dkim)
    result["measured"] = True
    result["partial"] = spf["grade"] is None or dmarc["grade"] is None
    return result


async def analyze_email_security(domain: str, dmarc_domain: str | None = None) -> dict:
    """Analyse de sécurité email (SPF/DKIM/DMARC) ; SPF et DMARC évalués pour `dmarc_domain`."""
    return await asyncio.to_thread(_analyze_email_security_sync, domain, dmarc_domain)
