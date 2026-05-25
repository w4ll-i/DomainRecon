"""Paste Leak Scanner - psbdmp, GitHub code search, optional Google CSE."""
import re
import httpx
import asyncio

SEVERITY_KEYWORDS = {
    "high":   ["password", "credentials", "secret", "private_key", "token", "api_key"],
    "medium": ["email", "username", "login", "user", "auth"],
}


def _severity(snippet: str) -> str:
    low = snippet.lower()
    for sev, kws in SEVERITY_KEYWORDS.items():
        if any(k in low for k in kws):
            return sev
    return "low"


def _snippet(text: str, domain: str, size: int = 80) -> str:
    idx = text.lower().find(domain.lower())
    if idx < 0:
        return text[:size]
    start = max(0, idx - size // 2)
    return text[start:start + size]


async def _psbdmp(domain: str, client: httpx.AsyncClient) -> list:
    pastes = []
    try:
        r = await client.get(
            f"https://psbdmp.ws/api/search/v3/{domain}", timeout=15
        )
        data = r.json()
        for item in (data.get("data") or [])[:10]:
            text = item.get("text", "")
            pastes.append({
                "url": f"https://pastebin.com/{item.get('id', '')}",
                "source": "psbdmp",
                "date": item.get("time", ""),
                "snippet": _snippet(text, domain),
                "severity": _severity(text),
            })
    except Exception:
        pass
    return pastes


async def _github_code(domain: str, github_token: str, client: httpx.AsyncClient) -> list:
    pastes = []
    headers = {"Accept": "application/vnd.github.v3+json"}
    if github_token:
        headers["Authorization"] = f"token {github_token}"
    try:
        r = await client.get(
            "https://api.github.com/search/code",
            params={"q": domain, "per_page": 10},
            headers=headers, timeout=15,
        )
        for item in (r.json().get("items") or []):
            repo = item.get("repository", {}).get("full_name", "")
            path = item.get("path", "")
            pastes.append({
                "url": item.get("html_url", ""),
                "source": "github_code",
                "date": "",
                "snippet": f"{repo} - {path}",
                "severity": "medium",
            })
    except Exception:
        pass
    return pastes


async def _google_cse(domain: str, cse_key: str, client: httpx.AsyncClient) -> list:
    pastes = []
    try:
        r = await client.get(
            "https://www.googleapis.com/customsearch/v1",
            params={
                "key": cse_key, "q": domain,
                "siteSearch": "pastebin.com OR paste.ee OR hastebin.com",
                "num": 10,
            },
            timeout=15,
        )
        for item in (r.json().get("items") or []):
            pastes.append({
                "url": item.get("link", ""),
                "source": "google_cse",
                "date": "",
                "snippet": item.get("snippet", "")[:80],
                "severity": "low",
            })
    except Exception:
        pass
    return pastes


async def scan_paste(domain: str, settings: dict = {}) -> dict:
    sources_checked = ["psbdmp", "github_code"]
    github_token = settings.get("github_token", "")
    google_cse_key = settings.get("google_cse_key", "")

    async with httpx.AsyncClient(verify=False) as client:
        tasks = [_psbdmp(domain, client), _github_code(domain, github_token, client)]
        if google_cse_key:
            tasks.append(_google_cse(domain, google_cse_key, client))
            sources_checked.append("google_cse")
        results = await asyncio.gather(*tasks, return_exceptions=True)

    all_pastes = []
    for r in results:
        if isinstance(r, list):
            all_pastes.extend(r)

    seen, unique = set(), []
    for p in all_pastes:
        if p["url"] not in seen:
            seen.add(p["url"])
            unique.append(p)

    return {
        "enriched": bool(unique),
        "total_found": len(unique[:20]),
        "sources_checked": sources_checked,
        "pastes": unique[:20],
    }
