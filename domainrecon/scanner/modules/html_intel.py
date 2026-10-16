# =============================================================================
# DomainRecon - Module « html_intel » : renseignements laissés dans le HTML
# =============================================================================
# Meta generator, commentaires, e-mails, actions de formulaire, adresses IP
# internes, chemins de serveur, champs cachés sensibles et messages d'erreur techniques (PHP, Python,
# Java, .NET, SQL) affichés à l'internaute. Voir impl/wc_html_intel.py.
#
# Source : la page d'accueil partagée du scan (aucune requête de plus). Passif.
# RGPD : les adresses e-mail du site audité sont conservées, celles d'un tiers sont
# masquées (« j***@exemple.org »).
#
# Constats : formulaire à mot de passe soumis en clair, formulaire vers une adresse
# http://, message d'erreur technique, adresse IP interne, chemins de serveur,
# commentaires sensibles, générateur qui annonce sa version.
# Critère de score : « html_intel » (3 points).
# =============================================================================

from ...i18n import msg
from ..impl import wc_html_intel
from ..impl.wc_runtime import require_homepage
from ..registry import ModuleSpec, ScanContext
from ..rules import FindingInput, FindingRule, Outcome, ScoreRule
from ..score import as_dict, as_list


async def run(context: ScanContext) -> dict:
    home = await require_homepage(context)
    intel = wc_html_intel.analyze(home.text, home.url or "", context.site)
    return {"measured": True, "error": None, "url": home.url, "truncated": home.truncated, **intel}


# -----------------------------------------------------------------------------
# Constats et score
# -----------------------------------------------------------------------------


def _forms(f: FindingInput) -> list[dict]:
    return [as_dict(form) for form in as_list(as_dict(f.data).get("forms"))]


def _password_forms_in_clear(data: dict) -> list[dict]:
    return [
        form
        for form in as_list(data.get("forms"))
        if as_dict(form).get("has_password") and as_dict(form).get("insecure")
    ]


def _check_password_in_clear(f: FindingInput):
    found = [form for form in _forms(f) if form.get("has_password") and form.get("insecure")]
    return {"count": len(found)} if found else None


def _check_form_in_clear(f: FindingInput):
    # Le formulaire à mot de passe a son propre constat, plus grave.
    found = [form for form in _forms(f) if form.get("insecure") and not form.get("has_password")]
    return {"count": len(found)} if found else None


def _check_error_disclosure(f: FindingInput):
    kinds = [k for k in as_list(as_dict(f.data).get("error_disclosures")) if isinstance(k, str)]
    return {"kinds": [_ERROR_KINDS.get(k, k) for k in kinds]} if kinds else None


def _check_internal_ip(f: FindingInput):
    ips = [ip for ip in as_list(as_dict(f.data).get("internal_ips")) if isinstance(ip, str)]
    return {"count": len(ips), "example": ips[0]} if ips else None


def _check_server_paths(f: FindingInput):
    paths = [p for p in as_list(as_dict(f.data).get("server_paths")) if isinstance(p, str)]
    return {"count": len(paths), "example": paths[0]} if paths else None


def _check_sensitive_comments(f: FindingInput):
    count = as_dict(f.data).get("suspicious_comments")
    return {"count": count} if isinstance(count, int) and not isinstance(count, bool) and count > 0 else None


def _check_generator_version(f: FindingInput):
    data = as_dict(f.data)
    generator = data.get("generator")
    return (
        {"generator": generator} if data.get("generator_has_version") and isinstance(generator, str) else None
    )


# Natures d'erreurs techniques, lisibles par l'utilisateur.
_ERROR_KINDS = {
    "php_error": msg("html_intel.error_php"),
    "python_traceback": msg("html_intel.error_python"),
    "java_stacktrace": msg("html_intel.error_java"),
    "dotnet_error": msg("html_intel.error_dotnet"),
    "sql_error": msg("html_intel.error_sql"),
}


def _score(data: dict) -> Outcome:
    intel = as_dict(data.get("html_intel"))
    if _password_forms_in_clear(intel):
        return Outcome(0, msg("html_intel.score_password_clear"), True)
    if intel.get("error_disclosures"):
        return Outcome(1, msg("html_intel.score_error"), True)
    minor = (
        bool(intel.get("internal_ips"))
        or bool(intel.get("server_paths"))
        or bool(intel.get("suspicious_comments"))
        or bool(intel.get("generator_has_version"))
        or any(as_dict(form).get("insecure") for form in as_list(intel.get("forms")))
    )
    if minor:
        return Outcome(2, msg("html_intel.score_minor"), True)
    return Outcome(3, msg("html_intel.score_ok"), True)


SPEC = ModuleSpec(
    name="html_intel",
    family="web",
    category="passif",
    run=run,
    order=212,
    findings=(
        FindingRule(
            code="finding.html_intel.password_in_clear", severity="high", check=_check_password_in_clear
        ),
        FindingRule(code="finding.html_intel.form_in_clear", severity="medium", check=_check_form_in_clear),
        FindingRule(
            code="finding.html_intel.error_disclosure", severity="medium", check=_check_error_disclosure
        ),
        FindingRule(code="finding.html_intel.internal_ip", severity="low", check=_check_internal_ip),
        FindingRule(code="finding.html_intel.server_paths", severity="low", check=_check_server_paths),
        FindingRule(
            code="finding.html_intel.sensitive_comments", severity="low", check=_check_sensitive_comments
        ),
        FindingRule(
            code="finding.html_intel.generator_version", severity="low", check=_check_generator_version
        ),
    ),
    score_rules=(ScoreRule(criterion="html_intel", weight=3, evaluate=_score),),
)
