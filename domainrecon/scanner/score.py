# =============================================================================
# DomainRecon - Scanner : score de sécurité
# =============================================================================
# Barème v4, sur 100 points, normalisé sur les seuls critères mesurés :
#   - un critère non mesurable (module en échec ou hors délai, aucun
#     sous-domaine testé) sort du dénominateur au lieu d'être compté comme
#     conforme ou à 0 ; un critère sans objet (cible IP, aucun cookie posé,
#     module sans objet) sort aussi du calcul de la couverture ;
#   - un module non lancé (profil rapide ou personnalisé, voir launched_modules)
#     n'est jamais compté comme réussi : son critère n'est pas mesuré, donc hors
#     du dénominateur, mais il reste dans le barème applicable, si bien que la
#     couverture baisse (`launched: False` dans son critère). Les 18 modules
#     d'origine tous lancés donnent le même résultat qu'au barème v3, dont
#     seule `version` change ;
#   - les critères sont DÉCLARÉS par les modules (ModuleSpec.score_rules :
#     ScoreRule, PenaltyRule de rules.py) ; ce fichier n'en garde aucune liste.
#     Le score est normalisé sur les points des critères mesurés : un critère
#     ajouté par un nouveau module ne change rien aux autres. Les 18 modules
#     historiques déclarent les 8 critères d'origine (100 points) avec les
#     évaluateurs de ce fichier. Un critère d'un module à clé API, actif ou
#     sensible qui n'a pas été lancé (clé absente, autorisation refusée) est
#     omis du barème : il ne fait pas baisser la couverture ;
#   - Réputation (et fuites) : REPUTATION_POINTS donne l'ordre de grandeur du
#     total des critères de la famille (3 à 5 points chacun) ;
#   - couverture inférieure à 50 % : grade N/A, le score n'est qu'indicatif ;
#   - TLS : un certificat invalide ou l'absence de HTTPS valent 0/20 ;
#   - en-têtes : valeurs validées (voir headers.py), HSTS compté seulement en
#     HTTPS, et jamais sur une cible IP ;
#   - WAF : bonus, un site sans WAF n'est pas pénalisé ;
#   - CORS : « * » sans credentials (ressource publique) n'est pas pénalisé ;
#   - redirection : une URL HTTPS redirigée vers HTTP vaut 0 ;
#   - pénalités hors barème : ports sensibles exposés ;
#   - plafond de grade (D) : takeover confirmé, CORS reflété avec credentials.
# Arrondis au plus proche, moitié vers le haut. Score final borné dans [0, 100].
# Les textes destinés à l'utilisateur (détails, raisons, libellés) sont des
# messages traduisibles (voir domainrecon.i18n), rendus à la lecture.
#
# Un scan noté avec un barème antérieur est relu tel qu'il a été enregistré :
# le score n'est calculé qu'à la fin d'un scan (orchestrator), jamais recalculé
# à la lecture. Seuls les nouveaux scans portent le barème v4.
# =============================================================================

import math
import re
from fractions import Fraction
from typing import TypedDict
from urllib.parse import urlsplit

from ..i18n import msg
from .common import logger
from .headers import evaluate_security_headers
from .rules import Outcome, PenaltyRule, ScoreRule
from .targets import is_ip_literal

# Version du barème, enregistrée avec chaque score : elle dit avec quel barème un
# scan a été noté. v4 : 7e famille (Réputation) et modules non lancés (profils de
# scan). Un scan noté en v3 (ou avant) garde son score, il n'est pas recalculé.
SCORE_VERSION = 4

# Réputation : ordre de grandeur du total des critères de la famille (VirusTotal,
# AbuseIPDB, DNSBL…), à répartir en critères de 3 à 5 points. Le score étant
# normalisé sur les points des critères mesurés, un scan sans module de
# réputation n'en est pas pénalisé.
REPUTATION_POINTS = 15

# =============================================================================
# Module 18 : Security Score Computation
# =============================================================================

# Poids des 8 critères des modules historiques (100 points), déclarés par leurs
# ModuleSpec (modules/*.py). CRITERIA_WEIGHTS et CRITERIA_MODULES (plus bas)
# sont, eux, calculés à partir du registre : tous les critères déclarés.
HEADERS_POINTS = 25
TLS_POINTS = 20
EMAIL_TOTAL_POINTS = 15
WAF_POINTS = 10
COOKIES_POINTS = 10
CORS_POINTS = 10
HTTPS_REDIRECT_POINTS = 5
TAKEOVER_POINTS = 5

# Statuts de module qui rendent le critère non mesuré.
_UNAVAILABLE_DETAILS = {
    "failed": msg("score.unavailable_failed"),
    "timeout": msg("score.unavailable_timeout"),
    "skipped": msg("score.unavailable_skipped"),
}

GRADE_THRESHOLDS = (("A", 90), ("B", 75), ("C", 55), ("D", 35), ("F", 0))

# Couverture minimale (en % du barème applicable) pour attribuer un grade : en
# dessous, le score repose sur trop peu de critères pour se lire comme une note.
MIN_GRADED_COVERAGE = 50

# Grade maximal en présence d'une vulnérabilité critique.
CRITICAL_GRADE_CAP = "D"

EMAIL_POINTS = {"A": 15, "B": 12, "C": 8, "D": 4, "F": 0}
COOKIE_POINTS = {"A": 10, "B": 7, "C": 4, "D": 2, "F": 0}
# CORS : origine arbitraire reflétée sans credentials, ou « * » avec
# credentials (combinaison refusée par les navigateurs).
CORS_PARTIAL_POINTS = 4
# Takeover non confirmé (« à vérifier »), selon le risque annoncé.
TAKEOVER_UNCONFIRMED_POINTS = {"medium": 2, "low": 4}

# Services qui ne devraient jamais être exposés sur Internet : (nom, sévérité).
SENSITIVE_PORTS = {
    23: ("Telnet", "critical"),
    445: ("SMB", "critical"),
    2375: ("API Docker", "critical"),
    6379: ("Redis", "critical"),
    9200: ("Elasticsearch", "critical"),
    11211: ("Memcached", "critical"),
    27017: ("MongoDB", "critical"),
    135: ("MS-RPC", "high"),
    139: ("NetBIOS", "high"),
    1433: ("SQL Server", "high"),
    1521: ("Oracle", "high"),
    2049: ("NFS", "high"),
    3306: ("MySQL", "high"),
    3389: ("RDP", "high"),
    5432: ("PostgreSQL", "high"),
    5900: ("VNC", "high"),
    5984: ("CouchDB", "high"),
    5985: ("WinRM", "high"),
    5986: ("WinRM", "high"),
    21: ("FTP", "medium"),
}
PORT_PENALTY_POINTS = {"critical": 15, "high": 10, "medium": 5}


class _CriterionScoreBase(TypedDict):
    score: int
    max: int
    # Message traduisible ; texte brut pour le détail « donnée » d'un scan antérieur
    # au barème v2 (par exemple « 3/7 »).
    detail: object
    measured: bool
    # Le critère entre-t-il dans le dénominateur ? (False : non mesuré, ou
    # bonus WAF non obtenu)
    counted: bool
    # False : critère sans objet pour cette cible, hors calcul de la couverture
    # (à distinguer d'un critère applicable mais non mesuré).
    applicable: bool


class CriterionScore(_CriterionScoreBase, total=False):
    # Présent, à False, quand le module du critère n'a pas été lancé (profil de
    # scan) : le critère n'est alors ni mesuré ni compté, mais reste applicable (la
    # couverture baisse). Absent sinon : un scan dont tous les modules ont tourné
    # garde exactement la forme du barème v3.
    launched: bool


class Penalty(TypedDict):
    key: str
    label: object
    points: int
    severity: str


class SecurityScore(TypedDict):
    version: int
    score: int
    max_score: int
    grade: str
    # Raison d'un grade « N/A » (None quand un grade est attribué).
    grade_reason: object | None
    breakdown: dict[str, CriterionScore]
    coverage: int
    measured_points: int
    measured_max: int
    confidence: str
    penalties: list[Penalty]
    grade_cap: str | None
    grade_cap_reasons: list[object]


# Évaluation d'un critère (rules.Outcome, nom historique conservé).
_Outcome = Outcome


_UNMEASURED = _Outcome(0, msg("score.unmeasured"), False)
# Module non lancé : jamais compté comme réussi (non mesuré), mais le critère reste
# applicable, donc dans le dénominateur de la couverture.
_NOT_LAUNCHED = _Outcome(0, msg("score.not_launched"), False)


# =============================================================================
# Lecture défensive des données (les scans sont relus depuis la base en JSON)
# =============================================================================
# Publique : findings.py et families.py relisent les mêmes données que le
# barème et doivent en tirer les mêmes conclusions (aucune lecture dupliquée).


def as_dict(value) -> dict:
    return value if isinstance(value, dict) else {}


def as_list(value) -> list:
    return value if isinstance(value, list) else []


def as_int(value) -> int | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, str) and value.strip().isascii() and value.strip().isdigit():
        return int(value)
    return None


def launched_modules(scan) -> frozenset[str] | None:
    """Modules que le scan déclare avoir lancés (`modules_launched`), ou None s'il ne les liste pas.

    La liste est réunie à `module_status` : un statut prouve que le module a
    tourné. Un module absent des deux n'a pas été lancé, et n'est jamais compté
    comme réussi.

    None (appel direct du barème, scan d'avant les profils de scan) : tous les
    modules sont supposés lancés. Pour un scan enregistré, families.py se rabat
    alors sur `module_status`, qui ne liste que les modules lancés.
    """
    scan = as_dict(scan)
    declared = scan.get("modules_launched")
    if not isinstance(declared, (list, tuple, set, frozenset)):
        return None
    status_names = {name for name in as_dict(scan.get("module_status")) if isinstance(name, str)}
    return frozenset({name for name in declared if isinstance(name, str)} | status_names)


def _clamp(value, low, high):
    return max(low, min(high, value))


def _round_half_up(value: Fraction) -> int:
    """Arrondi au plus proche, moitié vers le haut (42,5 → 43).

    round() arrondit les moitiés au pair (42,5 → 42, mais 37,5 → 38) ; les
    fractions gardent le calcul exact.
    """
    return math.floor(value + Fraction(1, 2))


def _url_scheme(url: str) -> str:
    try:
        return urlsplit(url).scheme.lower()
    except ValueError:
        return ""


def _url_hostname(url: str) -> str:
    try:
        return urlsplit(url).hostname or ""
    except ValueError:
        return ""


def grade_for_score(score: float) -> str:
    """Grade correspondant à un score sur 100 (hors cas « N/A »)."""
    for grade, threshold in GRADE_THRESHOLDS:
        if score >= threshold:
            return grade
    return "F"


def _grade_ceiling(grade: str) -> int:
    """Score maximal compatible avec un grade (D → 54)."""
    ceiling = 100
    for letter, threshold in GRADE_THRESHOLDS:
        if letter == grade:
            return ceiling
        ceiling = threshold - 1
    return ceiling


def _module_state(module_status: dict, module: str) -> str | None:
    status = as_dict(module_status.get(module)).get("status")
    return status if status in _UNAVAILABLE_DETAILS else None


# =============================================================================
# Critères
# =============================================================================


def _headers_rating(sec: dict) -> tuple[Fraction, object] | None:
    """Part conforme des en-têtes, dans [0, 1], et libellé ; None si illisible."""
    counts = sec.get("counts")
    found, url = sec.get("headers_found"), sec.get("url")
    if not isinstance(counts, dict) and isinstance(found, dict) and found and isinstance(url, str):
        # Scan antérieur au barème v2 : on réévalue les valeurs enregistrées.
        counts = evaluate_security_headers(
            found,
            https=_url_scheme(url) == "https",
            ip_target=is_ip_literal(_url_hostname(url)),
        )["counts"]

    if isinstance(counts, dict):
        ok, weak, total = (as_int(counts.get(key)) for key in ("ok", "weak", "total"))
        if ok is not None and total is not None and total > 0:
            weak = weak or 0
            detail = (
                msg("score.headers_rating_weak", ok=ok, total=total, weak=weak)
                if weak
                else msg("score.headers_rating", ok=ok, total=total)
            )
            return _clamp(Fraction(2 * ok + weak, 2 * total), 0, 1), detail

    raw = sec.get("score")
    match = re.fullmatch(r"\s*(\d+)\s*/\s*(\d+)\s*", raw) if isinstance(raw, str) else None
    if match and int(match[2]) > 0:
        return _clamp(Fraction(int(match[1]), int(match[2])), 0, 1), raw.strip()
    return None


def _score_headers(data: dict) -> _Outcome:
    sec = as_dict(data.get("security_headers"))
    if not sec.get("measured", bool(sec.get("headers_found"))):
        return _UNMEASURED
    rating = _headers_rating(sec)
    if rating is None:
        return _Outcome(0, msg("score.unmeasured_unreadable"), False)
    ratio, detail = rating
    return _Outcome(_round_half_up(ratio * HEADERS_POINTS), detail, True)


def tls_legacy_invalid(tls) -> bool:
    """Scan antérieur : erreur de vérification du certificat, classée alors « non mesurée ».

    C'est un constat (certificat invalide), pas un échec de mesure.
    """
    error = as_dict(tls).get("error")
    return isinstance(error, str) and "certificate verify failed" in error.lower()


def tls_measured(tls) -> bool:
    """Résultat TLS exploitable : mesuré, ou certificat refusé (voir tls_legacy_invalid)."""
    tls = as_dict(tls)
    measured = tls.get("measured")
    if measured is None:
        measured = bool(tls) and not tls.get("error")
    return bool(measured) or tls_legacy_invalid(tls)


def _score_tls(data: dict) -> _Outcome:
    tls = as_dict(data.get("tls_certificate"))
    if not tls_measured(tls):
        return _UNMEASURED
    error = tls.get("error")
    legacy_invalid = tls_legacy_invalid(tls)

    reason = tls.get("verify_error")
    if tls.get("https") is False:
        return _Outcome(0, reason or msg("score.tls_no_https"), True)
    if tls.get("valid") is False or legacy_invalid:
        return _Outcome(0, msg("score.tls_invalid", reason=reason or error or msg("score.tls_refused")), True)

    points = 10  # certificat valide
    days = as_int(tls.get("days_remaining"))
    if days is not None and days > 30:
        points += 5
    elif days is not None and days > 7:
        points += 2
    protocol = str(tls.get("protocol") or "")
    if "1.3" in protocol:
        points += 5
    elif "1.2" in protocol:
        points += 3
    if protocol and days is not None:
        detail = msg("score.tls_protocol_days", protocol=protocol, days=days)
    elif days is not None:
        detail = msg("score.tls_days", days=days)
    else:
        # Protocole seul : donnée technique, identique dans toutes les langues.
        detail = protocol or msg("score.tls_valid")
    return _Outcome(points, detail, True)


def _score_email(data: dict) -> _Outcome:
    email = as_dict(data.get("email_security"))
    if not email.get("measured", bool(email)):
        return _UNMEASURED
    grade = email.get("overall_grade", "F")
    # « Partiel » : note calculée sans SPF ou sans DMARC (requête DNS en échec).
    detail = (
        msg("score.email_grade_partial", grade=grade)
        if email.get("partial")
        else msg("score.grade", grade=grade)
    )
    return _Outcome(EMAIL_POINTS.get(grade, 0), detail, True)


def _score_waf(data: dict) -> _Outcome:
    waf = as_dict(data.get("waf"))
    if not waf.get("measured", bool(waf)):
        return _UNMEASURED
    if waf.get("detected"):
        return _Outcome(WAF_POINTS, waf.get("waf_name") or msg("score.waf_detected"), True)
    # Bonus : l'absence de WAF n'est pas une mauvaise configuration, le critère
    # sort donc du dénominateur au lieu de coûter 10 points. Un simple CDN
    # (`cdn_detected`) n'est pas un WAF et ne rapporte rien.
    if waf.get("cdn_detected") and waf.get("cdn_name"):
        detail = msg("score.waf_none_cdn", cdn=waf["cdn_name"])
    else:
        detail = msg("score.waf_none")
    return _Outcome(0, detail, True, counted=False)


def _score_cookies(data: dict) -> _Outcome:
    cookies = as_dict(data.get("cookie_security"))
    if not cookies.get("measured", bool(cookies) and not cookies.get("error")):
        return _UNMEASURED
    grade = cookies.get("score", "N/A")
    # Sans objet (et non « non mesuré ») si le site ne pose aucun cookie.
    if not cookies.get("cookies_present", bool(cookies.get("cookies")) and grade != "N/A"):
        return _Outcome(0, msg("score.cookies_none"), False, applicable=False)
    return _Outcome(COOKIE_POINTS.get(grade, 0), msg("score.grade", grade=grade), True)


def cors_credentials_checked(cors) -> bool:
    """Le test « origine reflétée avec credentials » figure-t-il au résultat ? (absent : ancien format)"""
    return "reflects_with_credentials" in as_dict(cors)


def _score_cors(data: dict) -> _Outcome:
    cors = as_dict(data.get("cors"))
    if not cors.get("measured", bool(cors)):
        return _UNMEASURED
    if cors.get("reflects_with_credentials"):
        return _Outcome(
            0,
            msg("score.cors_reflect_credentials"),
            True,
            cap_reason=msg("score.cap_cors"),
        )
    if cors.get("reflects_origin"):
        if cors_credentials_checked(cors):
            return _Outcome(CORS_PARTIAL_POINTS, msg("score.cors_reflect_no_credentials"), True)
        # Ancien format : credentials non vérifiés, on garde la sanction d'origine.
        return _Outcome(0, msg("score.cors_reflect_legacy"), True)
    if cors.get("allows_any_origin") and cors.get("allows_credentials_with_wildcard"):
        detail = msg("score.cors_wildcard_credentials")
        return _Outcome(CORS_PARTIAL_POINTS, detail, True)
    if cors.get("misconfigured"):
        return _Outcome(0, msg("score.cors_misconfigured"), True)
    if cors.get("partial"):
        # Tests de reflet d'origine en échec : aucune conclusion « conforme ».
        return _Outcome(0, msg("score.cors_partial"), False)
    if cors.get("allows_any_origin"):
        # Ressource publique : « * » sans credentials n'expose aucune donnée authentifiée.
        return _Outcome(CORS_POINTS, msg("score.cors_wildcard_public"), True)
    return _Outcome(CORS_POINTS, msg("score.ok"), True)


def _score_https_redirect(data: dict) -> _Outcome:
    redir = as_dict(data.get("redirect_chain"))
    if not redir.get("measured", bool(redir.get("chain"))):
        return _UNMEASURED
    if redir.get("https_downgrade"):
        return _Outcome(0, msg("score.redirect_downgrade"), True)
    if "forces_https" in redir and redir["forces_https"] is None:
        # HTTP sans réponse (délai, connexion impossible) : redirection inconnue.
        return _Outcome(0, msg("score.redirect_http_silent"), False)
    forces_https = bool(redir.get("forces_https"))
    final_url = redir.get("final_url")
    if forces_https and isinstance(final_url, str) and _url_scheme(final_url) != "https":
        return _Outcome(0, msg("score.redirect_final_http"), True)
    if forces_https:
        return _Outcome(HTTPS_REDIRECT_POINTS, msg("score.yes"), True)
    return _Outcome(0, msg("score.no"), True)


def takeover_confirmed(entry: dict) -> bool:
    """Takeover confirmé (empreinte propre au service, ou CNAME pendant réclamable)."""
    if "confirmed" in entry:
        return bool(entry["confirmed"])
    # Scans antérieurs au champ `confirmed`.
    return entry.get("risk", "high") == "high" and entry.get("fingerprint_matched", True) is not False


def _score_takeover(data: dict) -> _Outcome:
    entries = [e for e in as_list(data.get("subdomain_takeover")) if isinstance(e, dict)]
    checked = as_int(data.get("subdomains_checked"))
    # Non applicable sans sous-domaine testé.
    if not (checked or entries):
        return _Outcome(0, msg("score.takeover_none_tested"), False)

    confirmed = [e for e in entries if takeover_confirmed(e)]
    if confirmed:
        names = ", ".join(str(e.get("subdomain") or "?") for e in confirmed[:3])
        if len(confirmed) > 3:
            names += "…"
        return _Outcome(
            0,
            msg("score.takeover_confirmed", count=len(confirmed)),
            True,
            cap_reason=msg("score.cap_takeover", names=names),
        )
    if entries:
        points = min(TAKEOVER_UNCONFIRMED_POINTS.get(e.get("risk"), 2) for e in entries)
        return _Outcome(points, msg("score.takeover_to_check", count=len(entries)), True)
    # Le takeover ne teste qu'une partie des sous-domaines : le nombre testé
    # accompagne le verdict.
    detail = msg("score.takeover_none_checked", checked=checked) if checked else msg("score.takeover_none")
    return _Outcome(TAKEOVER_POINTS, detail, True)


# Critères des modules historiques, déclarés par leurs ModuleSpec (score_rules).
# rank : ordre du détail du score (celui du barème v3).
HEADERS_RULE = ScoreRule(criterion="headers", weight=HEADERS_POINTS, evaluate=_score_headers, rank=10)
TLS_RULE = ScoreRule(criterion="tls", weight=TLS_POINTS, evaluate=_score_tls, rank=20)
EMAIL_RULE = ScoreRule(
    criterion="email",
    weight=EMAIL_TOTAL_POINTS,
    evaluate=_score_email,
    not_applicable_for_ip=True,
    # La famille reprend la note du module : les seuils globaux, appliqués aux
    # points (C = 8/15 = 53 %), la dégraderaient d'un cran (C -> D, D -> F).
    grade_by_points={points: grade for grade, points in EMAIL_POINTS.items()},
    rank=30,
)
WAF_RULE = ScoreRule(criterion="waf", weight=WAF_POINTS, evaluate=_score_waf, rank=40)
COOKIES_RULE = ScoreRule(criterion="cookies", weight=COOKIES_POINTS, evaluate=_score_cookies, rank=50)
CORS_RULE = ScoreRule(criterion="cors", weight=CORS_POINTS, evaluate=_score_cors, rank=60)
HTTPS_REDIRECT_RULE = ScoreRule(
    criterion="https_redirect", weight=HTTPS_REDIRECT_POINTS, evaluate=_score_https_redirect, rank=70
)
TAKEOVER_RULE = ScoreRule(
    criterion="takeover",
    weight=TAKEOVER_POINTS,
    evaluate=_score_takeover,
    not_applicable_for_ip=True,
    rank=80,
)


def sensitive_open_ports(open_ports) -> list[tuple[int, str, str]]:
    """Services sensibles exposés : (port, service, sévérité), par port croissant.

    Tolère les formats enregistrés : entiers, chaînes (« 6379 ») ou dicts
    « port » / « state » (seuls les ports « open » comptent) ; toute autre
    entrée est ignorée.
    """
    ports: set[int] = set()
    for entry in as_list(open_ports):
        if isinstance(entry, dict):
            if entry.get("state", "open") != "open":
                continue
            entry = entry.get("port")
        port = as_int(entry)
        if port is not None:
            ports.add(port)
    return [(port, *SENSITIVE_PORTS[port]) for port in sorted(ports & SENSITIVE_PORTS.keys())]


def _port_penalties(data: dict) -> list[Penalty]:
    """Pénalité par service sensible exposé (voir sensitive_open_ports).

    Règle de pénalité du module open_ports : appelée seulement si le scan de
    ports a été lancé et mesuré (la valeur d'un module non lancé ou en échec ne
    dit rien des ports).
    """
    open_ports = as_dict(data).get("open_ports")
    return [
        {
            "key": f"port_{port}",
            "label": msg("score.penalty_port", port=port, service=service),
            "points": PORT_PENALTY_POINTS[severity],
            "severity": severity,
        }
        for port, service, severity in sensitive_open_ports(open_ports)
    ]


PORT_PENALTY_RULE = PenaltyRule(evaluate=_port_penalties)


# =============================================================================
# Critères du registre
# =============================================================================


def _registry_modules() -> dict:
    """Modules du registre (import local : le registre importe les modules, qui importent ce fichier)."""
    from . import registry

    return registry.MODULES


def score_criteria() -> list[tuple[str, ScoreRule]]:
    """(module, critère) de tous les critères déclarés, dans l'ordre du détail du score."""
    modules = _registry_modules()
    order = {name: index for index, name in enumerate(modules)}
    pairs = [(spec.name, rule) for spec in modules.values() for rule in spec.criteria]
    return sorted(pairs, key=lambda pair: (pair[1].rank, order[pair[0]]))


def criterion_rules() -> dict[str, ScoreRule]:
    """Critère -> règle, pour tous les critères déclarés."""
    return {rule.criterion: rule for _, rule in score_criteria()}


def __getattr__(name: str):
    # Calculés à chaque lecture à partir du registre (voir l'en-tête) :
    #   CRITERIA_WEIGHTS : critère -> poids ; CRITERIA_MODULES : critère -> module.
    if name == "CRITERIA_WEIGHTS":
        return {rule.criterion: rule.weight for _, rule in score_criteria()}
    if name == "CRITERIA_MODULES":
        return {rule.criterion: module for module, rule in score_criteria()}
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


def _module_ran(spec, data: dict, module_status: dict, launched: frozenset[str] | None) -> bool | None:
    """Le module a-t-il été lancé ? True, False (critère « non lancé »), None (critère omis).

    Sans liste des modules lancés (scan d'avant les profils, appel direct du
    barème), seuls les 18 modules historiques et ceux présents dans les données
    sont supposés lancés. Un module à clé, actif ou sensible non lancé n'est pas
    un manque du profil : son critère est omis.
    """
    if launched is None:
        present = spec.column is not None or spec.name in data or spec.name in module_status
        return True if present else None
    if spec.name in launched:
        return True
    return False if spec.category == "passif" else None


def _evaluate(rule: ScoreRule, data: dict) -> Outcome:
    """Évalue un critère ; une erreur de l'évaluateur rend le critère non mesuré (le scan est gardé)."""
    try:
        outcome = rule.evaluate(data)
        if not isinstance(outcome, tuple) or len(outcome) < 3:
            raise TypeError(f"Outcome attendu, {type(outcome).__name__} reçu")
        return Outcome(*outcome)
    except Exception:
        logger.exception("Critère de score %s : évaluation en échec", rule.criterion)
        return _Outcome(0, msg("score.unmeasured_unreadable"), False)


def _penalties(rule: PenaltyRule, data: dict, module: str) -> list[Penalty]:
    """Pénalités d'une règle ; une erreur de la règle n'en donne aucune (le scan est gardé)."""
    try:
        found = rule.evaluate(data)
        return [
            penalty
            for penalty in found or []
            if isinstance(penalty, dict) and isinstance(penalty.get("points"), int) and penalty.get("key")
        ]
    except Exception:
        logger.exception("Pénalités du module %s : évaluation en échec", module)
        return []


def compute_security_score(scan_data: dict) -> SecurityScore:
    """Calcule un score de sécurité 0-100 à partir des critères réellement mesurés.

    Un critère non mesurable est exclu du calcul au lieu d'être compté comme
    conforme : le score est normalisé sur les seuls points évaluables, et
    `coverage` indique quelle part du barème applicable (critères sans objet
    exclus) a pu être mesurée. Sous MIN_GRADED_COVERAGE, le grade vaut « N/A »
    (raison dans `grade_reason`) et le score n'est qu'indicatif. Entrées
    facultatives : `open_ports`, `is_ip_target`, `module_status`,
    `modules_launched` (noms des modules lancés : un module absent de cette liste
    et de `module_status` n'a pas été lancé, son critère n'est pas mesuré ; sans
    elle, tous les modules sont supposés lancés).
    """
    data = as_dict(scan_data)
    module_status = as_dict(data.get("module_status"))
    is_ip_target = bool(data.get("is_ip_target"))
    launched = launched_modules(data)

    modules = _registry_modules()
    breakdown: dict[str, CriterionScore] = {}
    cap_reasons: list[object] = []
    for module, rule in score_criteria():
        key = rule.criterion
        ran = _module_ran(modules[module], data, module_status, launched)
        if ran is None:
            continue
        if is_ip_target and rule.not_applicable_for_ip:
            outcome = _Outcome(0, msg("score.not_applicable_ip"), False, applicable=False)
        elif not ran:
            outcome = _NOT_LAUNCHED
        elif state := _module_state(module_status, module):
            detail = _UNAVAILABLE_DETAILS[state]
            reason = as_dict(module_status.get(module)).get("error")
            if state == "skipped" and reason:
                detail = msg("score.unavailable_skipped_reason", reason=reason)
            # « skipped » : module sans objet pour cette cible, pas une mesure manquée.
            outcome = _Outcome(0, detail, False, applicable=state != "skipped")
        else:
            outcome = _evaluate(rule, data)

        weight = rule.weight
        measured = bool(outcome.measured)
        criterion: CriterionScore = {
            "score": _clamp(int(outcome.points), 0, weight) if measured else 0,
            "max": weight,
            "detail": outcome.detail,
            "measured": measured,
            "counted": measured and outcome.counted,
            "applicable": measured or outcome.applicable,
        }
        if not ran:
            criterion["launched"] = False
        breakdown[key] = criterion
        if measured and outcome.cap_reason:
            cap_reasons.append(outcome.cap_reason)

    measured_max = sum(c["max"] for c in breakdown.values() if c["counted"])
    obtained = sum(c["score"] for c in breakdown.values() if c["counted"])
    # Couverture : part mesurée du barème applicable. Le bonus WAF non obtenu
    # reste mesuré ; un critère sans objet n'est pas une mesure manquante.
    measured_weight = sum(c["max"] for c in breakdown.values() if c["measured"])
    applicable_weight = sum(c["max"] for c in breakdown.values() if c["applicable"])
    coverage = _round_half_up(Fraction(measured_weight * 100, applicable_weight)) if applicable_weight else 0

    penalties: list[Penalty] = []
    for spec in modules.values():
        if not spec.penalties or _module_state(module_status, spec.name):
            continue
        if not _module_ran(spec, data, module_status, launched):
            continue
        for rule in spec.penalties:
            penalties.extend(_penalties(rule, data, spec.name))
    grade_cap = CRITICAL_GRADE_CAP if cap_reasons else None

    score = 0
    if measured_max:
        score = _round_half_up(Fraction(obtained * 100, measured_max)) - sum(p["points"] for p in penalties)
        score = _clamp(score, 0, 100)
        if grade_cap:
            score = min(score, _grade_ceiling(grade_cap))

    if coverage < MIN_GRADED_COVERAGE:
        grade, grade_reason = "N/A", msg("score.reason_low_coverage", coverage=coverage)
    elif not measured_max:
        grade, grade_reason = "N/A", msg("score.reason_only_waf")
    else:
        grade, grade_reason = grade_for_score(score), None

    return {
        "version": SCORE_VERSION,
        # Indicatif seulement quand le grade vaut « N/A » (voir grade_reason).
        "score": score,
        "max_score": 100,
        "grade": grade,
        "grade_reason": grade_reason,
        "breakdown": breakdown,
        # Transparence du calcul : sur quelle part du barème le score repose.
        "coverage": coverage,
        "measured_points": obtained,
        "measured_max": measured_max,
        "confidence": "low" if grade == "N/A" else "high" if coverage >= 80 else "medium",
        "penalties": penalties,
        "grade_cap": grade_cap,
        "grade_cap_reasons": cap_reasons,
    }
