# =============================================================================
# DomainRecon - Module « web_files_extra » : fichiers informatifs et .well-known
# =============================================================================
# Complète « web_files » (robots.txt, sitemap.xml, security.txt) avec les autres
# fichiers conventionnels : humans.txt, ads.txt, app-ads.txt, manifeste d'application
# web (déclaré par la page ou aux emplacements usuels), .well-known (OpenID Connect,
# OAuth, change-password, assetlinks.json, apple-app-site-association, host-meta,
# NodeInfo, gpc.json), crossdomain.xml et clientaccesspolicy.xml.
# Fichiers informatifs que web_files ne lit pas. Ce ne sont pas des « fichiers
# sensibles exposés », et un simple code 200 ne suffit pas : un fichier n'est
# trouvé que si son contenu a la forme attendue, et une réponse identique à la page
# « introuvable » du site est écartée.
# Les fichiers sensibles (.git, .env, sauvegardes) ne sont pas recherchés ici.
# =============================================================================

import asyncio
import difflib
import secrets as _secrets

from ...i18n import msg
from .. import common
from ..errors import ModuleError
from ..http_utils import FETCH_ERRORS, describe_error, fetch
from ..impl import web_files_extra as logic
from ..registry import ModuleSpec, ScanContext
from ..rules import FindingInput, FindingRule
from ..score import as_dict, as_list

_REQUEST_TIMEOUT = 8.0
_KEY_BUDGET = 15.0
_CONCURRENCY = 5
_REDIRECTS = 3


def _same_as_baseline(text: str, baseline: dict) -> bool:
    """La réponse est-elle la page « introuvable » du site (servie en 200 pour toute URL) ?"""
    if baseline.get("status_code") != 200:
        return False
    reference = baseline.get("text") or ""
    a, b = text.strip()[:2000], reference.strip()[:2000]
    return a == b or (bool(a) and bool(b) and difflib.SequenceMatcher(None, a, b).quick_ratio() >= 0.95)


async def _fetch(client, origin: str, path: str, host: str, redirects: int = _REDIRECTS):
    return await fetch(
        client,
        origin + path,
        site=host,
        max_bytes=logic.MAX_BODY,
        max_redirects=redirects,
    )


async def _probe(client, origin: str, host: str, path: str, kind: str, baseline: dict) -> dict:
    """Interroge un chemin : {found: True|False|None, ...}. None : impossible à vérifier (réseau)."""
    try:
        if kind == "change_password":
            return await _probe_change_password(client, origin, host, path)
        fetched = await _fetch(client, origin, path, host)
    except FETCH_ERRORS as e:
        return {"found": None, "path": path, "error": describe_error(e)}
    if fetched.status_code != 200:
        return {"found": False, "path": path, "status_code": fetched.status_code}
    text = fetched.text
    details = logic.validate(kind, text, fetched.headers.get("content-type", ""))
    if details is None or _same_as_baseline(text, baseline):
        return {"found": False, "path": path, "status_code": 200}
    return {
        "found": True,
        "path": path,
        "url": fetched.url,
        "status_code": 200,
        "size": len(fetched.body),
        "truncated": fetched.truncated,
        "details": details,
    }


async def _probe_change_password(client, origin: str, host: str, path: str) -> dict:
    """URL standard de changement de mot de passe : redirection ou page, alors qu'une URL absente donne 4xx."""
    main = await _fetch(client, origin, path, host, 0)
    reference = await _fetch(client, origin, f"/.well-known/dr-{_secrets.token_hex(6)}", host, 0)
    found = 200 <= main.status_code < 400 and reference.status_code >= 400
    result: dict = {"found": found, "path": path, "status_code": main.status_code}
    if found:
        result["url"] = main.url
        result["details"] = {"redirect": 300 <= main.status_code < 400}
    return result


async def _probe_key(client, semaphore, origin, host, candidates, baseline) -> dict:
    """Essaie les chemins d'une même clé, dans l'ordre, jusqu'au premier trouvé (durée bornée)."""
    state: dict = {"unverified": None, "last": {"found": False}}

    async def walk() -> dict | None:
        for path, kind in candidates:
            async with semaphore:
                result = await _probe(client, origin, host, path, kind, baseline)
            if result["found"] is True:
                return result
            if result["found"] is None:
                state["unverified"] = state["unverified"] or result
            else:
                state["last"] = result
        return None

    try:
        found = await asyncio.wait_for(walk(), timeout=_KEY_BUDGET)
    except (asyncio.TimeoutError, TimeoutError):
        return {"found": None, "path": candidates[0][0], "error": msg("net.timeout")}
    return found or state["unverified"] or state["last"]


async def run(context: ScanContext) -> dict:
    home = await context.homepage()
    if not home.reachable:
        raise ModuleError(home.error or msg("orchestrator.module_failed"))
    host = context.domain
    origin = f"{'https' if home.https else 'http'}://{common.url_host(host)}"

    grouped: dict[str, list[tuple[str, str]]] = {}
    for key, path, kind in logic.CANDIDATES:
        grouped.setdefault(key, []).append((path, kind))
    declared = logic.manifest_path(home.text, home.url, host)
    if declared:
        grouped["manifest"].insert(0, (declared, "manifest"))

    async with common._http_client(timeout=_REQUEST_TIMEOUT, follow_redirects=False) as client:
        baseline: dict = {"status_code": None, "text": ""}
        try:
            reference = await _fetch(client, origin, f"/dr-{_secrets.token_hex(6)}.txt", host)
            baseline = {"status_code": reference.status_code, "text": reference.text}
        except FETCH_ERRORS:
            pass
        semaphore = asyncio.Semaphore(_CONCURRENCY)
        outcomes = await asyncio.gather(
            *(
                _probe_key(client, semaphore, origin, host, candidates, baseline)
                for candidates in grouped.values()
            )
        )

    files = dict(zip(grouped, outcomes, strict=True))
    found = [key for key, entry in files.items() if entry["found"] is True]
    return {
        "measured": True,
        "error": None,
        "url": home.url,
        "files": files,
        "found": found,
        "found_count": len(found),
        "checked": len(files),
        "unverified": sum(1 for entry in files.values() if entry["found"] is None),
        "permissive": [
            key for key in found if logic.is_permissive(_kind_of(key), as_dict(files[key]).get("details"))
        ],
        "catch_all": baseline["status_code"] == 200,
    }


def _kind_of(key: str) -> str:
    return next((kind for k, _, kind in logic.CANDIDATES if k == key), "")


def _check_permissive(f: FindingInput) -> object:
    keys = [str(k) for k in as_list(as_dict(f.data).get("permissive"))]
    return {"files": ", ".join(keys)} if keys else None


def _check_alg_none(f: FindingInput) -> bool:
    files = as_dict(as_dict(f.data).get("files"))
    for key in ("openid_configuration", "oauth_authorization_server"):
        entry = as_dict(files.get(key))
        if entry.get("found") is True and as_dict(entry.get("details")).get("alg_none") is True:
            return True
    return False


SPEC = ModuleSpec(
    name="web_files_extra",
    family="web",
    category="passif",
    run=run,
    order=125,
    timeout=60,
    findings=(
        FindingRule(
            code="finding.web_files_extra.permissive_policy", severity="medium", check=_check_permissive
        ),
        FindingRule(code="finding.web_files_extra.oidc_alg_none", severity="medium", check=_check_alg_none),
    ),
)
