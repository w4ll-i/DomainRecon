# =============================================================================
# DomainRecon - Logique du module « csp_grade » (note de la Content-Security-Policy)
# =============================================================================
# Notation par pénalités (100 points moins les défauts) d'une politique CSP,
# note de A à F. Une notation par critères « positifs » serait trop superficielle :
# « script-src * » y obtiendrait un A, « default-src 'self' * » un B, nonces,
# hashes et 'strict-dynamic' ne seraient pas compris, et 'unsafe-inline' serait
# recherché dans toutes les directives, style-src compris.
#
# Principes (CSP niveau 3, https://www.w3.org/TR/CSP3/) :
#   - script-src, à défaut default-src, décide de l'exécution des scripts ;
#   - 'unsafe-inline' est ignoré dès qu'un nonce, un hash ou 'strict-dynamic'
#     est présent ; avec 'strict-dynamic' + nonce/hash, les sources d'hôte et de
#     schéma sont ignorées ;
#   - base-uri, frame-ancestors et form-action ne retombent pas sur default-src :
#     leur absence est un défaut ; object-src, lui, y retombe ;
#   - plusieurs politiques s'appliquent TOUTES : la plus stricte protège, on
#     retient donc la meilleure note ;
#   - une politique « report-only » ne protège pas : elle n'est pas notée.
# Fonctions pures, sans réseau.
# =============================================================================

from collections.abc import Mapping
from html.parser import HTMLParser

from ...i18n import msg

# Seuils des notes (score sur 100).
_GRADE_THRESHOLDS = (("A", 90), ("B", 75), ("C", 60), ("D", 40))
# Un défaut critique plafonne la note à D, quel que soit le reste.
_CAP_GRADE = "D"
_GRADE_ORDER = "ABCDF"

_HASH_PREFIXES = ("'nonce-", "'sha256-", "'sha384-", "'sha512-")
_SCHEME_SOURCES = {"http:", "https:"}
# Hôtes de confiance courants qui hébergent des points d'entrée de contournement (JSONP,
# bibliothèques à gadgets, dépôts de fichiers publics) : une liste blanche qui les contient
# ne retient pas un script injecté.
_BYPASS_HOSTS = (
    "ajax.googleapis.com",
    "www.google.com",
    "accounts.google.com",
    "www.googletagmanager.com",
    "googletagmanager.com",
    "cdnjs.cloudflare.com",
    "cdn.jsdelivr.net",
    "unpkg.com",
    "raw.githubusercontent.com",
    "gist.githubusercontent.com",
    "*.googleapis.com",
    "*.cloudfront.net",
    "*.amazonaws.com",
    "*.appspot.com",
    "*.herokuapp.com",
    "*.firebaseapp.com",
)


def parse_policies(value: str) -> list[dict[str, list[str]]]:
    """Découpe un en-tête CSP en politiques (séparées par des virgules) puis en directives.

    Une directive répétée est ignorée au-delà de la première (CSP3 §2.2.1). Les
    noms et mots-clés sont en minuscules ; les nonces et hashes aussi, ce qui
    suffit à les reconnaître.
    """
    policies = []
    for raw in value.split(","):
        directives: dict[str, list[str]] = {}
        for part in raw.split(";"):
            tokens = part.strip().lower().split()
            if tokens:
                directives.setdefault(tokens[0], tokens[1:])
        if directives:
            policies.append(directives)
    return policies


class _MetaCsp(HTMLParser):
    """Relève les <meta http-equiv="Content-Security-Policy" content="…"> d'une page."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.values: list[str] = []

    def handle_starttag(self, tag: str, attrs) -> None:
        if tag != "meta":
            return
        found = {name: value for name, value in attrs if value is not None}
        if str(found.get("http-equiv", "")).strip().lower() == "content-security-policy":
            content = str(found.get("content", "")).strip()
            if content:
                self.values.append(content)


def meta_policies(html: str) -> list[str]:
    """Politiques CSP déclarées en balises <meta> (au plus 4, dans les 200 premiers Kio)."""
    parser = _MetaCsp()
    try:
        parser.feed(html[:200_000])
        parser.close()
    except Exception:  # HTML invalide : on garde ce qui a été lu
        pass
    return parser.values[:4]


def _issue(code: str, points: int, severity: str, label: object, *, critical: bool = False) -> dict:
    return {"code": code, "points": points, "severity": severity, "label": label, "critical": critical}


def _grade_letter(score: int, critical: bool) -> str:
    letter = "F"
    for candidate, threshold in _GRADE_THRESHOLDS:
        if score >= threshold:
            letter = candidate
            break
    if critical and _GRADE_ORDER.index(letter) < _GRADE_ORDER.index(_CAP_GRADE):
        letter = _CAP_GRADE
    return letter


def _bypass_host(sources: list[str]) -> str | None:
    for source in sources:
        host = source.split("://", 1)[-1].split("/", 1)[0].split(":", 1)[0]
        for known in _BYPASS_HOSTS:
            if host == known or (known.startswith("*.") and host.endswith(known[1:])):
                return host
            if host.startswith("*.") and known.endswith(host[1:]):
                return host
    return None


def _script_issues(directives: dict[str, list[str]]) -> list[dict]:
    name = "script-src" if "script-src" in directives else "default-src"
    sources = directives.get(name)
    if sources is None:
        return [
            _issue("no_script_policy", 40, "high", msg("csp_grade.issue_no_script_policy"), critical=True)
        ]
    if sources == ["'none'"]:
        return []
    issues: list[dict] = []
    protected = any(s.startswith(_HASH_PREFIXES) for s in sources)
    strict_dynamic = "'strict-dynamic'" in sources
    # Avec nonce/hash + 'strict-dynamic', les sources d'hôte et de schéma sont ignorées.
    hosts_ignored = protected and strict_dynamic

    if "*" in sources and not hosts_ignored:
        label = msg("csp_grade.issue_script_wildcard", directive=name)
        issues.append(_issue("script_wildcard", 40, "high", label, critical=True))
    if "'unsafe-inline'" in sources and not protected and not strict_dynamic:
        label = msg("csp_grade.issue_unsafe_inline", directive=name)
        issues.append(_issue("unsafe_inline", 30, "high", label, critical=True))
    if "'unsafe-eval'" in sources:
        issues.append(_issue("unsafe_eval", 15, "medium", msg("csp_grade.issue_unsafe_eval", directive=name)))
    if "'unsafe-hashes'" in sources:
        issues.append(_issue("unsafe_hashes", 5, "low", msg("csp_grade.issue_unsafe_hashes", directive=name)))
    if hosts_ignored:
        return issues
    if any(s in _SCHEME_SOURCES for s in sources):
        issues.append(
            _issue("script_scheme", 20, "high", msg("csp_grade.issue_script_scheme", directive=name))
        )
    if "data:" in sources:
        label = msg("csp_grade.issue_script_data", directive=name)
        issues.append(_issue("script_data", 25, "high", label, critical=True))
    elif any(s in ("blob:", "filesystem:") for s in sources):
        issues.append(_issue("script_blob", 10, "medium", msg("csp_grade.issue_script_blob", directive=name)))
    bypass = _bypass_host(sources)
    if bypass:
        label = msg("csp_grade.issue_script_bypass_host", directive=name, host=bypass)
        issues.append(_issue("script_bypass_host", 10, "medium", label))
    if any(s.startswith("http://") for s in sources):
        label = msg("csp_grade.issue_script_insecure", directive=name)
        issues.append(_issue("script_insecure_source", 5, "low", label))
    return issues


def grade_policy(
    directives: Mapping[str, list[str]], *, meta: bool = False, framed_protected: bool = False
) -> dict:
    """Note une politique (directives déjà découpées).

    `meta` : politique d'une balise <meta>, qui ignore frame-ancestors (pas de pénalité pour son
    absence). `framed_protected` : la page est protégée du cadrage par X-Frame-Options.
    """
    directives = dict(directives)
    issues = _script_issues(directives)

    if "default-src" not in directives:
        issues.append(_issue("default_src_missing", 5, "low", msg("csp_grade.issue_default_src_missing")))

    objects = directives.get("object-src", directives.get("default-src"))
    if objects is None:
        issues.append(_issue("object_src_missing", 10, "medium", msg("csp_grade.issue_object_src_missing")))
    elif any(s == "*" or s in _SCHEME_SOURCES for s in objects):
        issues.append(_issue("object_src_open", 12, "medium", msg("csp_grade.issue_object_src_open")))

    base = directives.get("base-uri")
    if base is None:
        issues.append(_issue("base_uri_missing", 8, "medium", msg("csp_grade.issue_base_uri_missing")))
    elif any(s == "*" or s in _SCHEME_SOURCES for s in base):
        issues.append(_issue("base_uri_open", 8, "medium", msg("csp_grade.issue_base_uri_open")))

    if not meta:
        ancestors = directives.get("frame-ancestors")
        if ancestors is None:
            if not framed_protected:
                label = msg("csp_grade.issue_frame_ancestors_missing")
                issues.append(_issue("frame_ancestors_missing", 6, "low", label))
        elif "*" in ancestors:
            label = msg("csp_grade.issue_frame_ancestors_any")
            issues.append(_issue("frame_ancestors_any", 10, "medium", label))

    form = directives.get("form-action")
    if form is None or "*" in form:
        issues.append(_issue("form_action_open", 4, "low", msg("csp_grade.issue_form_action_open")))

    styles = directives.get("style-src", directives.get("default-src")) or []
    if "'unsafe-inline'" in styles and not any(s.startswith(_HASH_PREFIXES) for s in styles):
        issues.append(_issue("style_unsafe_inline", 3, "low", msg("csp_grade.issue_style_unsafe_inline")))

    score = max(0, 100 - sum(issue["points"] for issue in issues))
    critical = any(issue["critical"] for issue in issues)
    return {"score": score, "grade": _grade_letter(score, critical), "issues": issues, "critical": critical}


def grade_policies(
    policies: list[tuple[dict[str, list[str]], bool]], *, framed_protected: bool = False
) -> dict:
    """Note l'ensemble des politiques appliquées : la meilleure, car toutes s'appliquent.

    `policies` : liste de (directives, vient d'une balise <meta>).
    """
    graded = [grade_policy(d, meta=meta, framed_protected=framed_protected) for d, meta in policies]
    best = max(graded, key=lambda g: (g["score"], -len(g["issues"])))
    return {**best, "policies": len(graded)}
