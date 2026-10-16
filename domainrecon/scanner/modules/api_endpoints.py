# =============================================================================
# DomainRecon - Module « api_endpoints » : endpoints API et de développement
# =============================================================================
# Sonde une liste de chemins d'API et d'outils de développement en écartant les
# faux positifs : un chemin n'est
# retenu que si son CONTENU a la forme attendue, jamais sur un simple code 200 :
#   - OpenAPI/Swagger : JSON contenant « openapi » ou « swagger » ;
#   - Spring Actuator : JSON avec « _links » (HATEOAS) ;
#   - Prometheus/metrics : corps texte commençant par « # HELP » ou « # TYPE » ;
#   - GraphQL : introspection confirmée par une requête POST {__schema} ;
#   - endpoint protégé (401/403) : retenu seulement si le serveur ne répond pas
#     ainsi à toute URL (ligne de base).
# La page « introuvable » de référence écarte les serveurs « fourre-tout ».
# L'introspection GraphQL activée est « high » (schéma exposé), pas « critical »
# Catégorie « actif ».
# =============================================================================

import json as _json
import re

from ..impl import web_exposure as probe
from ..registry import ModuleSpec, ScanContext
from ..rules import FindingInput, FindingRule, hit
from ..score import as_dict, as_list

_SWAGGER_PATHS = (
    "/swagger-ui.html", "/swagger.json", "/openapi.json", "/api-docs", "/v3/api-docs",
    "/swagger/v1/swagger.json", "/api/swagger.json",
)  # fmt: skip
_ACTUATOR_PATHS = ("/actuator", "/actuator/health", "/actuator/env", "/actuator/mappings")
_GRAPHQL_PATHS = ("/graphql", "/api/graphql", "/v1/graphql")
_METRICS_PATHS = ("/metrics", "/actuator/prometheus", "/federate")
_GENERIC_PATHS = (
    "/api", "/api/v1", "/api/v2", "/wp-json/", "/telescope", "/horizon",
    "/_cat/indices", "/_cluster/health", "/v1/sys/health",
)  # fmt: skip

ALL_PATHS = _SWAGGER_PATHS + _ACTUATOR_PATHS + _GRAPHQL_PATHS + _METRICS_PATHS + _GENERIC_PATHS

_PROMETHEUS = re.compile(r"^#\s*(HELP|TYPE)\s", re.MULTILINE)


def _json_body(fetched):
    content_type = fetched.headers.get("content-type", "").lower()
    if "json" not in content_type:
        return None
    try:
        return _json.loads(fetched.text)
    except ValueError:
        return None


def _classify(path: str, fetched, baseline: probe.Baseline) -> dict | None:
    status = fetched.status_code
    if status in (401, 403):
        if baseline.status_code in (401, 403):
            return None
        return {"path": path, "status_code": status, "type": "protected", "severity": "low"}
    if status != 200 or baseline.same_page(fetched.text, len(fetched.body)):
        return None
    body = _json_body(fetched)
    text = fetched.text
    if isinstance(body, dict) and ("openapi" in body or "swagger" in body):
        return {"path": path, "status_code": 200, "type": "openapi", "severity": "high"}
    if isinstance(body, dict) and "_links" in body and path in _ACTUATOR_PATHS:
        return {"path": path, "status_code": 200, "type": "actuator", "severity": "high"}
    if path in _METRICS_PATHS and _PROMETHEUS.search(text):
        return {"path": path, "status_code": 200, "type": "metrics", "severity": "medium"}
    if path in _GRAPHQL_PATHS and isinstance(body, dict) and ("data" in body or "errors" in body):
        # Endpoint GraphQL repéré : l'introspection est vérifiée séparément.
        return {"path": path, "status_code": 200, "type": "graphql", "severity": "medium"}
    if isinstance(body, (dict, list)):
        return {"path": path, "status_code": 200, "type": "json_api", "severity": "medium"}
    return None


async def _graphql_introspection(client, origin: str, path: str, host: str) -> bool:
    """POST d'une requête d'introspection minimale ; True si le schéma est renvoyé."""
    from ..http_utils import FETCH_ERRORS, fetch

    try:
        fetched = await fetch(
            client,
            origin + path,
            method="POST",
            headers={"Content-Type": "application/json"},
            site=host,
            max_bytes=probe.MAX_BODY,
            max_redirects=0,
        )
    except FETCH_ERRORS:
        return False
    return fetched.status_code == 200 and "__schema" in fetched.text


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

        endpoints = await probe.probe_paths(client, origin, host, ALL_PATHS, handle)

        # Introspection GraphQL : seulement pour les endpoints GraphQL repérés.
        for entry in endpoints:
            if entry["type"] == "graphql" and await _graphql_introspection(
                client, origin, entry["path"], host
            ):
                entry["introspection"] = True
                entry["severity"] = "high"

    return {
        "measured": True,
        "error": None,
        "url": home.url,
        "endpoints": endpoints,
        "count": len(endpoints),
        "checked": len(ALL_PATHS),
        "catch_all": baseline.catch_all,
    }


def _exposed(f: FindingInput, severity: str) -> object:
    paths = [
        str(e.get("path"))
        for e in as_list(as_dict(f.data).get("endpoints"))
        if isinstance(e, dict) and e.get("severity") == severity
    ]
    return hit(paths=", ".join(paths)) if paths else None


SPEC = ModuleSpec(
    name="api_endpoints",
    family="web",
    category="actif",
    run=run,
    order=148,
    timeout=60,
    findings=(
        FindingRule(
            code="finding.api_endpoints.exposed", severity="high", check=lambda f: _exposed(f, "high")
        ),
        FindingRule(
            code="finding.api_endpoints.found", severity="low", check=lambda f: _exposed(f, "medium")
        ),
    ),
)
