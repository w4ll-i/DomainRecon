# =============================================================================
# DomainRecon - Module « admin_panels » : panneaux d'administration découverts
# =============================================================================
# Sonde une liste de chemins d'administration courants en écartant les faux
# positifs :
#   - une page « introuvable » servie en 200 à toute URL (fourre-tout) n'est
#     jamais prise pour un panneau ;
#   - une redirection qui ne fait qu'ajouter la barre oblique finale (/admin ->
#     /admin/) n'est pas un signal ;
#   - un 401/403 n'est retenu que si le serveur ne répond pas ainsi à toute URL
#     inconnue (mesuré sur la ligne de base) ;
#   - un 200 n'est « confiance haute » que si le corps a une signature de produit
#     connu (phpMyAdmin, WordPress, Grafana, Jenkins…) ou des mots-clés d'authentification.
# Découplé de tout déclenchement d'un autre module.
# Catégorie « actif » : chemins forgés au-delà d'une visite normale.
# =============================================================================

import re

from ..impl import web_exposure as probe
from ..registry import ModuleSpec, ScanContext
from ..rules import FindingInput, FindingRule, hit
from ..score import as_dict, as_list

PATHS: tuple[str, ...] = (
    "/admin", "/administrator", "/admin/login", "/wp-admin/", "/wp-login.php",
    "/backend", "/manage", "/dashboard", "/panel", "/control", "/cpanel",
    "/phpmyadmin/", "/pma/", "/dbadmin/", "/myadmin/", "/adminer.php",
    "/manager/html", "/management", "/console", "/system", "/user/login",
    "/auth/login", "/cms", "/administration", "/webadmin", "/filemanager",
    "/grafana/login", "/kibana", "/jenkins/", "/.well-known/admin",
)  # fmt: skip

# Signatures de produit dans le corps d'une réponse 200 (confiance haute).
_PRODUCTS = {
    "phpMyAdmin": re.compile(r"phpmyadmin", re.IGNORECASE),
    "Adminer": re.compile(r"adminer", re.IGNORECASE),
    "WordPress": re.compile(r"wp-login|user_login|wordpress", re.IGNORECASE),
    "Grafana": re.compile(r"grafana", re.IGNORECASE),
    "Kibana": re.compile(r"kibana", re.IGNORECASE),
    "Jenkins": re.compile(r"jenkins|hudson", re.IGNORECASE),
    "Tomcat Manager": re.compile(r"tomcat|catalina", re.IGNORECASE),
}
_AUTH_WORDS = re.compile(
    r"\b(login|log in|sign in|password|mot de passe|connexion|username|identifiant|console|dashboard)\b",
    re.IGNORECASE,
)
_AUTH_REDIRECT = re.compile(r"(login|signin|sign-in|auth|sso|connexion|compte|account)", re.IGNORECASE)


def _redirect_location(fetched) -> str:
    return (fetched.headers.get("location") or "").strip()


def _is_trailing_slash(path: str, location: str) -> bool:
    """La redirection ne fait qu'ajouter / (ou l'enlever) au même chemin ?"""
    loc = location.split("?", 1)[0].rstrip("/")
    return loc.endswith(path.rstrip("/")) and loc != "" and "//" not in loc[8:]


def _classify(path: str, fetched, baseline: probe.Baseline) -> dict | None:
    status = fetched.status_code
    if status in (401, 403):
        # Le serveur répond-il 401/403 à toute URL inconnue ? Alors ce n'est pas un signal.
        if baseline.status_code in (401, 403):
            return None
        return {"path": path, "status_code": status, "confidence": "medium", "reason": "access_denied"}
    if status in (301, 302, 307, 308):
        location = _redirect_location(fetched)
        if not location or _is_trailing_slash(path, location):
            return None
        confidence = "high" if _AUTH_REDIRECT.search(location) else "low"
        return {"path": path, "status_code": status, "confidence": confidence, "reason": "redirect"}
    if status == 200:
        text = fetched.text
        if baseline.same_page(text, len(fetched.body)) or len(text.strip()) < 80:
            return None
        for product, pattern in _PRODUCTS.items():
            if pattern.search(text):
                return {
                    "path": path, "status_code": 200, "confidence": "high",
                    "reason": "product", "product": product,
                }  # fmt: skip
        if _AUTH_WORDS.search(text[:5000]):
            return {"path": path, "status_code": 200, "confidence": "medium", "reason": "auth_keywords"}
    return None


async def run(context: ScanContext) -> dict:
    home = await probe.homepage_or_fail(context)
    host = context.domain
    origin = probe.origin_of(home, host)

    async with await probe.open_client() as client:
        baseline = await probe.measure_baseline(client, origin, host)

        def handle(path, fetched, error):
            if fetched is None:
                return None
            return _classify(path, fetched, baseline)

        panels = await probe.probe_paths(client, origin, host, PATHS, handle)

    return {
        "measured": True,
        "error": None,
        "url": home.url,
        "panels": panels,
        "count": len(panels),
        "checked": len(PATHS),
        "catch_all": baseline.catch_all,
    }


def _check_panels(f: FindingInput) -> object:
    panels = [
        str(p.get("path"))
        for p in as_list(as_dict(f.data).get("panels"))
        if isinstance(p, dict) and p.get("confidence") in ("high", "medium")
    ]
    return hit(paths=", ".join(panels), count=len(panels)) if panels else None


SPEC = ModuleSpec(
    name="admin_panels",
    family="web",
    category="actif",
    run=run,
    order=145,
    timeout=60,
    findings=(FindingRule(code="finding.admin_panels.found", severity="low", check=_check_panels),),
)
