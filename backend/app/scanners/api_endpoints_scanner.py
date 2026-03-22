# backend/app/scanners/api_endpoints_scanner.py
"""
API Endpoints Scanner — discover exposed API / developer endpoints on a domain.

Probes a curated list of well-known paths and classifies each hit by type and
severity:

  - GraphQL introspection enabled  → critical
  - Swagger / OpenAPI exposed      → high
  - Spring Boot Actuator           → high
  - Auth / OAuth endpoints         → medium
  - Generic JSON API               → medium
  - 401 / 403 (endpoint exists)    → low
"""
import asyncio
import json as _json
import httpx


# ─── Path list ───────────────────────────────────────────────────────────────

PATHS: list[str] = [
    # GraphQL
    "/graphql", "/graphiql", "/api/graphql", "/v1/graphql",
    # OpenAPI / Swagger
    "/swagger-ui.html", "/swagger-ui/", "/swagger.json", "/swagger.yaml",
    "/openapi.json", "/openapi.yaml", "/api-docs", "/api-docs/",
    "/api/swagger", "/docs/", "/redoc/",
    # Spring Boot Actuator
    "/actuator", "/actuator/health", "/actuator/info", "/actuator/env",
    "/actuator/metrics", "/actuator/mappings", "/actuator/beans",
    # Generic API
    "/api/v1/", "/api/v2/", "/api/v3/", "/api/", "/v1/", "/v2/",
    # Auth / OAuth
    "/.well-known/openid-configuration", "/.well-known/oauth-authorization-server",
    "/oauth/token", "/auth/token", "/oauth2/token",
    # Debug / Monitoring
    "/debug/", "/metrics", "/health", "/healthz", "/status",
    "/ping", "/info", "/__debug__/", "/console/",
    # PHP
    "/phpinfo.php", "/info.php", "/test.php",
    # Django / Rails
    "/rails/info/properties",
    # Misc
    "/wp-json/", "/api/swagger.json", "/v1/api-docs",
    # FastAPI extras
    "/docs", "/redoc",
    # Laravel
    "/telescope", "/telescope/requests", "/horizon", "/nova", "/nova-api/metrics",
    # Django
    "/admin/", "/silk/", "/silk/requests/",
    # Kubernetes probes
    "/livez", "/readyz", "/healthz/ping",
    # Prometheus
    "/federate", "/api/v1/targets", "/api/v1/rules",
    # Consul
    "/v1/agent/members", "/v1/catalog/services", "/v1/kv/",
    # Vault
    "/v1/sys/health", "/v1/sys/seal-status", "/v1/sys/leader",
    # Elasticsearch
    "/_cat/indices", "/_cluster/health", "/_nodes", "/_stats",
    # MongoDB Express
    "/db/admin", "/db/local",
    # phpMyAdmin
    "/pma/", "/dbadmin/", "/phpmyadmin/", "/myadmin/",
    # Additional REST versioning
    "/api/v4", "/api/v5",
    "/rest/v1", "/rest/v2", "/rest/api/v1", "/rest/api/v2",
    # Admin panels
    "/wp-login.php", "/backend/",
    "/cpanel", "/plesk", "/webmin", "/directadmin",
    # Debug / monitoring extras
    "/server-status", "/server-info", "/.env.local", "/.env.production",
    "/debug/default/view", "/debug/toolbar",
    # Spring Boot Actuator extras
    "/actuator/conditions", "/actuator/configprops",
    "/actuator/loggers", "/actuator/threaddump", "/actuator/heapdump",
    # GraphQL extras
    "/playground", "/graphql/console",
    # Git / VCS exposure
    "/.git/HEAD", "/.git/config", "/.svn/entries",
    # Config / backup files
    "/config.php.bak", "/wp-config.php.bak", "/database.yml",
]

# Semaphore cap for concurrent probes
_CONCURRENCY = 25

# Timeout per request (seconds)
_TIMEOUT = 8


# ─── Type / severity classifiers ─────────────────────────────────────────────

_GRAPHQL_PATHS = {"/graphql", "/graphiql", "/api/graphql", "/v1/graphql"}

_SWAGGER_PATHS = {
    "/swagger-ui.html", "/swagger-ui/", "/swagger.json", "/swagger.yaml",
    "/openapi.json", "/openapi.yaml", "/api-docs", "/api-docs/",
    "/api/swagger", "/docs/", "/redoc/", "/api/swagger.json", "/v1/api-docs",
}

_ACTUATOR_PATHS = {
    "/actuator", "/actuator/health", "/actuator/info", "/actuator/env",
    "/actuator/metrics", "/actuator/mappings", "/actuator/beans",
}

_AUTH_PATHS = {
    "/.well-known/openid-configuration", "/.well-known/oauth-authorization-server",
    "/oauth/token", "/auth/token", "/oauth2/token",
}


def _is_json_response(response: httpx.Response) -> bool:
    ct = response.headers.get("content-type", "")
    return "application/json" in ct or "application/vnd.api+json" in ct


def _try_parse_json(response: httpx.Response) -> dict | list | None:
    try:
        return response.json()
    except Exception:
        return None


def _is_swagger_body(body: dict | list | None) -> bool:
    if not isinstance(body, dict):
        return False
    return "openapi" in body or "swagger" in body


def _is_actuator_body(body: dict | list | None) -> bool:
    if not isinstance(body, dict):
        return False
    return "_links" in body or "status" in body


def _is_graphql_body(body: dict | list | None) -> bool:
    if not isinstance(body, dict):
        return False
    return "data" in body or "errors" in body


# ─── GraphQL introspection probe ─────────────────────────────────────────────

async def _graphql_introspection(client: httpx.AsyncClient, base_url: str, path: str) -> bool:
    """
    POST a minimal introspection query.  Returns True if the schema is exposed.
    """
    url = f"{base_url}{path}"
    query = {"query": "{__schema{types{name}}}"}
    try:
        r = await client.post(
            url,
            json=query,
            headers={"Content-Type": "application/json"},
        )
        if r.status_code == 200 and "__schema" in r.text:
            return True
    except Exception:
        pass
    return False


# ─── Single path probe ───────────────────────────────────────────────────────

async def _probe_path(
    sem: asyncio.Semaphore,
    client: httpx.AsyncClient,
    base_url: str,
    path: str,
) -> dict | None:
    """
    Probe one path under *base_url*.  Returns a finding dict or None.
    """
    async with sem:
        url = f"{base_url}{path}"
        try:
            r = await client.get(url)
        except Exception:
            return None

        status = r.status_code

        # ── 401 / 403 — endpoint exists but requires auth ──────────────────
        if status in (401, 403):
            return {
                "path":     path,
                "status":   status,
                "type":     "Protected endpoint",
                "severity": "low",
                "note":     f"Endpoint returned HTTP {status} — exists but requires authentication",
            }

        if status != 200:
            return None

        # ── HTTP 200 — classify by path and body ───────────────────────────
        is_json = _is_json_response(r)
        body = _try_parse_json(r) if is_json else None

        # GraphQL — path hint or body hint
        if path in _GRAPHQL_PATHS or _is_graphql_body(body):
            introspection = await _graphql_introspection(client, base_url, path)
            if introspection:
                return {
                    "path":                 path,
                    "status":               200,
                    "type":                 "GraphQL",
                    "introspection_enabled": True,
                    "severity":             "critical",
                    "note":                 "GraphQL introspection is enabled — schema fully exposed",
                }
            return {
                "path":                 path,
                "status":               200,
                "type":                 "GraphQL",
                "introspection_enabled": False,
                "severity":             "medium",
                "note":                 "GraphQL endpoint found — introspection disabled",
            }

        # Swagger / OpenAPI
        if path in _SWAGGER_PATHS or _is_swagger_body(body):
            return {
                "path":     path,
                "status":   200,
                "type":     "Swagger/OpenAPI",
                "severity": "high",
                "note":     "API documentation exposed publicly",
            }

        # Spring Boot Actuator
        if path in _ACTUATOR_PATHS or _is_actuator_body(body):
            return {
                "path":     path,
                "status":   200,
                "type":     "Spring Actuator",
                "severity": "high",
                "note":     "Spring Boot Actuator endpoint exposed — may leak env/metrics/beans",
            }

        # Auth / OAuth
        if path in _AUTH_PATHS:
            return {
                "path":     path,
                "status":   200,
                "type":     "Auth/OAuth",
                "severity": "medium",
                "note":     "Auth/OAuth configuration endpoint is publicly accessible",
            }

        # Generic JSON API
        if is_json:
            return {
                "path":     path,
                "status":   200,
                "type":     "JSON API",
                "severity": "medium",
                "note":     "JSON API endpoint accessible without authentication",
            }

        # 200 but not JSON / recognised — low value, skip to reduce noise
        return None


# ─── Main entry point ────────────────────────────────────────────────────────

async def scan_api_endpoints(domain: str) -> dict:
    """
    Discover exposed API / developer endpoints on *domain*.

    Returns a dict with keys:
        enriched, endpoints, count, critical_count, high_count
    """
    result: dict = {
        "enriched":       False,
        "endpoints":      [],
        "count":          0,
        "critical_count": 0,
        "high_count":     0,
    }

    try:
        base_url = f"https://{domain}"
        sem = asyncio.Semaphore(_CONCURRENCY)

        async with httpx.AsyncClient(
            verify=False,
            timeout=_TIMEOUT,
            follow_redirects=False,
            headers={"User-Agent": "Mozilla/5.0 (DomainRecon/7.0)"},
        ) as client:
            tasks = [_probe_path(sem, client, base_url, path) for path in PATHS]
            raw_results = await asyncio.gather(*tasks)

        endpoints = [r for r in raw_results if r is not None]

        critical_count = sum(1 for e in endpoints if e.get("severity") == "critical")
        high_count = sum(1 for e in endpoints if e.get("severity") == "high")

        result.update({
            "enriched":       bool(endpoints),
            "endpoints":      endpoints,
            "count":          len(endpoints),
            "critical_count": critical_count,
            "high_count":     high_count,
        })

    except Exception:
        pass

    return result
