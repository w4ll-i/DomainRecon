# backend/app/scanners/github_dork_scanner.py
"""
GitHub Code Search - finds public repositories mentioning a domain.
Useful for detecting credential leaks, hardcoded secrets, config files, etc.
Unauthenticated: 10 req/min. With token: 30 req/min + higher result limits.
https://docs.github.com/en/rest/search/search#search-code
"""
import re
import httpx

# Filename patterns that indicate sensitive files
_HIGH_SEVERITY_NAMES = re.compile(
    r"(\.env|config|settings|credentials?|secrets?|keys?|passwords?|tokens?)",
    re.IGNORECASE,
)
_MEDIUM_SEVERITY_PATHS = re.compile(
    r"(backup|dump|export)",
    re.IGNORECASE,
)

_DORK_TEMPLATES = [
    '"{domain}"',
    '"{domain}" password OR secret OR key OR token',
    '"{domain}" filename:.env',
    '"{domain}" BEGIN RSA PRIVATE KEY',
    '"{domain}" database_url OR db_password',
    '"{domain}" ssh-rsa',
    '"{domain}" Authorization Bearer',
    '"{domain}" filename:config.yml OR filename:config.json',
    '"{domain}" webhook OR webhook_url',
    '"{domain}" AKIA',
    '"{domain}" sk_live OR pk_live',
    '"{domain}" filename:docker-compose.yml',
]

_EXTRACT_PATTERNS = [
    ("AWS Access Key",  r"AKIA[0-9A-Z]{16}"),
    ("GitHub PAT",      r"ghp_[A-Za-z0-9]{36}"),
    ("Stripe Key",      r"sk_live_[0-9A-Za-z]{24,}"),
    ("Private Key PEM", r"-----BEGIN (?:RSA |EC )?PRIVATE KEY-----"),
    ("Bearer Token",    r"Bearer\s+[A-Za-z0-9_\-\.]{20,}"),
]


async def _fetch_raw_content(client: "httpx.AsyncClient", item: dict, headers: dict) -> str:
    """
    Fetch the raw file content from GitHub using the raw content API.
    Only fetches the first 32KB to avoid large binary files.
    """
    # item["git_url"] points to the blob API - use raw URL instead
    html_url = item.get("html_url", "")
    if not html_url:
        return ""
    # Convert github.com/user/repo/blob/branch/path → raw.githubusercontent.com/user/repo/branch/path
    raw_url = html_url.replace("github.com", "raw.githubusercontent.com").replace("/blob/", "/")
    try:
        r = await client.get(raw_url, timeout=8, headers=headers)
        if r.status_code == 200:
            return r.text[:32768]
    except Exception:
        pass
    return ""


def _scan_content_for_secrets(content: str) -> list:
    """Scan file content for secret patterns. Returns list of findings."""
    found = []
    seen = set()
    for name, pattern in _EXTRACT_PATTERNS:
        import re
        for m in re.finditer(pattern, content):
            val = m.group()
            if val not in seen:
                seen.add(val)
                # Redact middle of the value
                redacted = val[:6] + "****" + val[-4:] if len(val) > 12 else "****"
                found.append({"type": name, "value_redacted": redacted})
    return found


def _classify_severity(filename: str, path: str) -> str:
    if _HIGH_SEVERITY_NAMES.search(filename):
        return "high"
    if _MEDIUM_SEVERITY_PATHS.search(path):
        return "medium"
    return "low"


def _normalize_item(item: dict) -> dict:
    repo = item.get("repository", {})
    filename = item.get("name", "")
    path = item.get("path", "")
    return {
        "repo": repo.get("full_name", ""),
        "repo_url": repo.get("html_url", ""),
        "file": filename,
        "path": path,
        "url": item.get("html_url", ""),
        "severity": _classify_severity(filename, path),
    }


async def github_dork(domain: str, github_token: str = None) -> dict:
    """
    Search GitHub public code for mentions of the domain.

    Runs twelve dork queries with up to 3 pages of 100 results each.

    Returns a normalized dict:
      {
        enriched: True,
        results: [{repo, repo_url, file, path, url, severity}],
        total_count: int,
        high_count: int,
        rate_limited: False,
      }
    """
    if not domain:
        return {"enriched": False, "error": "No domain provided"}

    headers = {
        "Accept": "application/vnd.github.v3+json",
        "User-Agent": "DomainRecon/7.0",
    }
    if github_token:
        headers["Authorization"] = f"Bearer {github_token}"

    queries = [t.format(domain=domain) for t in _DORK_TEMPLATES]

    seen_urls: set = set()
    all_results: list = []

    try:
        async with httpx.AsyncClient(timeout=10) as client:
            for query in queries:
                for page in range(1, 4):
                    r = await client.get(
                        "https://api.github.com/search/code",
                        params={"q": query, "per_page": 100, "page": page},
                        headers=headers,
                    )

                    if r.status_code in (403, 422):
                        return {
                            "enriched": False,
                            "rate_limited": True,
                            "note": "GitHub rate limit - add a token in settings for more results",
                        }

                    if r.status_code != 200:
                        break

                    data = r.json()
                    items = data.get("items", [])
                    if not items:
                        break

                    for item in items:
                        url = item.get("html_url", "")
                        if url in seen_urls:
                            continue
                        seen_urls.add(url)
                        norm = _normalize_item(item)
                        # Fetch and scan content for high-severity files only
                        if norm["severity"] == "high" and github_token:
                            content = await _fetch_raw_content(client, item, headers)
                            if content:
                                extracted = _scan_content_for_secrets(content)
                                if extracted:
                                    norm["extracted_secrets"] = extracted
                                    norm["severity"] = "critical"
                        all_results.append(norm)

                    if len(items) < 100:
                        break

        if not all_results:
            return {"enriched": False, "rate_limited": False, "total_count": 0}

        high_count = sum(1 for r in all_results if r["severity"] == "high")
        critical_count = sum(1 for r in all_results if r["severity"] == "critical")

        return {
            "enriched": True,
            "results": all_results,
            "total_count": len(all_results),
            "high_count": high_count,
            "critical_count": critical_count,
            "rate_limited": False,
        }

    except httpx.TimeoutException:
        return {"enriched": False, "error": "GitHub request timed out", "rate_limited": False}
    except Exception as e:
        return {"enriched": False, "error": str(e)[:200], "rate_limited": False}
