# =============================================================================
# DomainRecon - Logique du module « dast_data » (divulgations légères)
# =============================================================================
# Analyses pures (sans réseau) :
#   - en-têtes qui divulguent une version (Server, X-Powered-By, X-AspNet-Version…)
#     ou qui trahissent un mode débogage (X-Debug-Token-Link…) ;
#   - page « 404 » bavarde : trace d'appels, page de débogage d'un framework,
#     chemin de fichier PHP, signature de serveur avec version.
# Des empreintes trop larges seraient trompeuses : le simple mot « laravel » ou
# « Django » dans une page, ou « Warning: » seul, ne suffit pas. Chaque empreinte
# exige une signature propre au
# message d'erreur du framework. Une page servie en 200 qui ressemble à la page
# d'accueil (serveur « fourre-tout », application monopage) n'est pas analysée.
# =============================================================================

import difflib
import re

from ...i18n import msg

# En-têtes qui peuvent divulguer le logiciel et sa version.
VERSION_HEADERS = ("Server", "X-Powered-By", "X-AspNet-Version", "X-AspNetMvc-Version", "X-Generator")
# En-têtes de débogage : gravité par en-tête (minuscules).
DEBUG_HEADERS = {
    "x-debug-token": "medium",
    "x-debug-token-link": "high",
    "x-debug": "medium",
    "x-wt-ttl": "medium",
    "x-wt-ts": "medium",
}

_VERSION = re.compile(r"\d+\.\d+|/\d")

# Empreintes de pages d'erreur : (identifiant, motif, gravité). Le motif est cherché dans les
# 8 premiers Kio de la page, sans tenir compte de la casse.
_FINGERPRINTS: tuple[tuple[str, re.Pattern, str], ...] = tuple(
    (name, re.compile(pattern, re.IGNORECASE | re.DOTALL), severity)
    for name, pattern, severity in (
        ("werkzeug", r"Werkzeug Debugger|interactive debugger", "high"),
        ("django", r"Using the URLconf defined in|because you have <code>DEBUG = True", "medium"),
        (
            "laravel",
            r"Whoops! There was an error|facade/ignition|Illuminate\\+(?:Foundation|Routing|Http)",
            "medium",
        ),
        ("symfony", r"Symfony\\+Component\\+|sf-exceptionreset|Symfony Profiler", "medium"),
        ("rails", r"ActionController::RoutingError|<h1>\s*Routing Error|No route matches \[", "medium"),
        ("spring", r"Whitelabel Error Page|has no explicit mapping for /error", "low"),
        ("express", r"<pre>Cannot (?:GET|POST) /", "low"),
        ("node_trace", r"at Layer\.handle|node_modules[/\\]", "medium"),
        (
            "php",
            r"<b>(?:Fatal error|Parse error|Warning|Notice|Deprecated)</b>:|"
            r"(?:Fatal error|Parse error|Warning|Notice): [^\n]{0,300} in (?:/|[A-Za-z]:\\)[^\n]{0,200}\.php on line \d+",
            "medium",
        ),
        (
            "aspnet",
            r"Server Error in '[^']*' Application|Version Information:\s*Microsoft \.NET Framework",
            "medium",
        ),
        ("java", r"java\.lang\.\w+(?:Exception|Error)|\bat (?:org|com|java)\.[\w.$]+\(", "medium"),
        ("python", r"Traceback \(most recent call last\)", "medium"),
        ("tomcat", r"Apache Tomcat/\d+\.\d+", "low"),
        ("server_signature", r"\b(?:Apache|nginx|Microsoft-IIS|LiteSpeed|OpenResty)/\d+\.\d+", "low"),
    )
)

SEVERITIES = ("critical", "high", "medium", "low", "info")


def _banner_has_version(value: str) -> bool:
    return bool(_VERSION.search(value))


def analyze_headers(headers: dict[str, str]) -> dict:
    """Examine les en-têtes (noms en minuscules) : divulgations de version et en-têtes de débogage.

    Renvoie `banners` ([{header, value, version}], tous les en-têtes présents) et `findings`
    ([{type, severity, header, value, label}]). Une bannière sans version (« cloudflare ») n'est
    qu'un renseignement, jamais un constat.
    """
    banners: list[dict] = []
    findings: list[dict] = []
    for name in VERSION_HEADERS:
        value = headers.get(name.lower())
        if not value:
            continue
        value = value.strip()[:100]
        version = _banner_has_version(value)
        banners.append({"header": name, "value": value, "version": version})
        if version:
            findings.append(
                {
                    "type": "version_disclosure",
                    "severity": "low",
                    "header": name,
                    "value": value,
                    "label": msg("dast_data.version_disclosure", header=name, value=value),
                }
            )
    for name, severity in DEBUG_HEADERS.items():
        value = headers.get(name)
        if value:
            findings.append(
                {
                    "type": "debug_header",
                    "severity": severity,
                    "header": name,
                    "value": value.strip()[:100],
                    "label": msg("dast_data.debug_header", header=name),
                }
            )
    return {"banners": banners, "findings": findings}


def similar_pages(page: str, reference: str) -> bool:
    """Deux pages sont-elles (quasi) identiques ? Sert à reconnaître un serveur « fourre-tout »."""
    if not page.strip() or not reference.strip():
        return not page.strip() and not reference.strip()
    a, b = page[:3000], reference[:3000]
    if a == b:
        return True
    return difflib.SequenceMatcher(None, a, b).quick_ratio() >= 0.92 and abs(
        len(page) - len(reference)
    ) <= max(200, len(reference) // 5)


def analyze_not_found(status_code: int, body: str, home_text: str) -> dict:
    """Examine la réponse à une URL inexistante.

    Renvoie `catch_all` (la réponse ressemble à la page d'accueil : rien n'est analysé),
    `analyzed` et `findings` ([{type, severity, framework, status_code, label}]).
    """
    # Redirection sans corps, ou page d'accueil resservie à toute URL : aucun renseignement.
    if status_code < 400 and (not body.strip() or similar_pages(body, home_text)):
        return {"catch_all": status_code == 200, "analyzed": False, "findings": []}
    text = body[:8000]
    findings = []
    for name, pattern, severity in _FINGERPRINTS:
        if pattern.search(text):
            findings.append(
                {
                    "type": "verbose_404",
                    "severity": severity,
                    "framework": name,
                    "status_code": status_code,
                    "label": msg("dast_data.verbose_404", framework=name),
                }
            )
    return {"catch_all": False, "analyzed": True, "findings": findings[:6]}


def summarize(findings: list[dict]) -> dict[str, int]:
    """Nombre de constats par gravité (toutes les gravités, même à zéro)."""
    summary = {severity: 0 for severity in SEVERITIES}
    for finding in findings:
        severity = finding.get("severity")
        if severity in summary:
            summary[severity] += 1
    return summary
