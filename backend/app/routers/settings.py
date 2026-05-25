# backend/app/routers/settings.py
"""Settings CRUD + API-key validation."""

from datetime import datetime, timezone

import httpx
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from ..database import get_db
from ..helpers import get_or_create_settings, settings_response
from ..schemas import SettingsRequest, SettingsResponse

router = APIRouter(prefix="/api/settings", tags=["Settings"])


@router.get("", response_model=SettingsResponse)
async def get_settings(db: Session = Depends(get_db)):
    """Return settings with keys masked."""
    return settings_response(get_or_create_settings(db))


# Fields where an empty string means "erase the key" and None means "don't touch".
_NULLABLE_KEYS = (
    "shodan_key", "virustotal_key", "securitytrails_key", "censys_id",
    "censys_secret", "urlscan_key", "builtwith_key", "circl_user",
    "circl_password", "abuseipdb_key", "intelx_key", "safebrowsing_key",
    "phishtank_key", "leakix_key", "github_token", "google_cse_key",
)


@router.put("")
async def update_settings(request: SettingsRequest, db: Session = Depends(get_db)):
    """Persist settings. Send an empty string to clear a key; `None` leaves it untouched."""
    s = get_or_create_settings(db)

    for field in _NULLABLE_KEYS:
        value = getattr(request, field, None)
        if value is not None:
            setattr(s, field, value or None)

    s.screenshot_enabled = request.screenshot_enabled
    s.scan_timeout = request.scan_timeout
    if request.quick_timeout is not None:
        s.quick_timeout = request.quick_timeout
    if request.full_timeout is not None:
        s.full_timeout = request.full_timeout
    s.updated_at = datetime.now(timezone.utc)

    db.commit()
    db.refresh(s)
    return settings_response(s)


# ─── API-key validation ──────────────────────────────────────────────────────
# Each service has its own probe. The dispatch map below keeps each probe
# isolated as a small async function - easy to add a new service by adding
# one entry.

async def _probe_shodan(s, client):
    if not s.shodan_key:
        return False, "Clé non configurée"
    r = await client.get("https://api.shodan.io/api-info", params={"key": s.shodan_key})
    if r.status_code == 200:
        return True, f"OK, {r.json().get('query_credits', '?')} crédits restants"
    return False, f"Erreur {r.status_code}"


async def _probe_virustotal(s, client):
    if not getattr(s, "virustotal_key", None):
        return False, "Clé non configurée"
    r = await client.get(
        "https://www.virustotal.com/api/v3/users/me",
        headers={"x-apikey": s.virustotal_key},
    )
    return r.status_code == 200, "OK" if r.status_code == 200 else f"Erreur {r.status_code}"


async def _probe_builtwith(s, client):
    if not getattr(s, "builtwith_key", None):
        return False, "Clé non configurée"
    r = await client.get(
        "https://api.builtwith.com/v21/api.json",
        params={"KEY": s.builtwith_key, "LOOKUP": "builtwith.com"},
    )
    return r.status_code == 200, "OK" if r.status_code == 200 else f"Erreur {r.status_code}"


async def _probe_securitytrails(s, client):
    if not s.securitytrails_key:
        return False, "Clé non configurée"
    r = await client.get(
        "https://api.securitytrails.com/v1/ping",
        headers={"APIKEY": s.securitytrails_key},
    )
    return r.status_code == 200, "OK" if r.status_code == 200 else f"Erreur {r.status_code}"


async def _probe_censys(s, client):
    if not s.censys_id or not s.censys_secret:
        return False, "ID ou Secret non configuré"
    r = await client.get(
        "https://search.censys.io/api/v2/account",
        auth=(s.censys_id, s.censys_secret),
    )
    return r.status_code == 200, "OK" if r.status_code == 200 else f"Erreur {r.status_code}"


async def _probe_urlscan(s, client):
    if not s.urlscan_key:
        return False, "Clé non configurée"
    r = await client.get("https://urlscan.io/user/", headers={"API-Key": s.urlscan_key})
    return r.status_code == 200, "OK" if r.status_code == 200 else f"Erreur {r.status_code}"


async def _probe_abuseipdb(s, client):
    key = getattr(s, "abuseipdb_key", None)
    if not key:
        return False, "Clé non configurée"
    r = await client.get(
        "https://api.abuseipdb.com/api/v2/check",
        params={"ipAddress": "8.8.8.8", "maxAgeInDays": 1},
        headers={"Key": key, "Accept": "application/json"},
    )
    if r.status_code == 200:
        score = r.json().get("data", {}).get("abuseConfidenceScore", "?")
        return True, f"OK, score : {score}%"
    return False, f"Erreur {r.status_code}"


async def _probe_intelx(s, client):
    key = getattr(s, "intelx_key", None)
    if not key:
        return False, "Clé non configurée"
    r = await client.post("https://2.intelx.io/authenticate/info", headers={"x-key": key})
    if r.status_code == 200:
        info = r.json()
        accounts = info.get("accounts") or [{}]
        level = accounts[0].get("level", "?")
        return True, f"OK, niveau de compte : {level}"
    return False, f"Erreur {r.status_code}"


async def _probe_safebrowsing(s, client):
    key = getattr(s, "safebrowsing_key", None)
    if not key:
        return False, "Clé non configurée"
    r = await client.post(
        f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={key}",
        json={
            "client": {"clientId": "test", "clientVersion": "1"},
            "threatInfo": {
                "threatTypes": ["MALWARE"],
                "platformTypes": ["ANY_PLATFORM"],
                "threatEntryTypes": ["URL"],
                "threatEntries": [{"url": "http://example.com"}],
            },
        },
    )
    return r.status_code == 200, "OK, API opérationnelle" if r.status_code == 200 else f"Erreur {r.status_code}"


async def _probe_leakix(s, client):
    key = getattr(s, "leakix_key", None)
    headers = {"Accept": "application/json"}
    if key:
        headers["api-key"] = key
    r = await client.get("https://leakix.net/api/domain/example.com", headers=headers)
    ok = r.status_code in (200, 404)
    return ok, "OK, API accessible" if ok else f"Erreur {r.status_code}"


async def _probe_github(s, client):
    token = getattr(s, "github_token", None)
    if not token:
        return False, "Token non configuré"
    r = await client.get(
        "https://api.github.com/user",
        headers={"Authorization": f"Bearer {token}", "Accept": "application/vnd.github.v3+json"},
    )
    if r.status_code == 200:
        return True, f"OK, connecté en tant que {r.json().get('login', '?')}"
    return False, f"Erreur {r.status_code}"


_PROBES = {
    "shodan":         _probe_shodan,
    "virustotal":     _probe_virustotal,
    "builtwith":      _probe_builtwith,
    "securitytrails": _probe_securitytrails,
    "censys":         _probe_censys,
    "urlscan":        _probe_urlscan,
    "abuseipdb":      _probe_abuseipdb,
    "intelx":         _probe_intelx,
    "safebrowsing":   _probe_safebrowsing,
    "leakix":         _probe_leakix,
    "github":         _probe_github,
}


@router.post("/test/{service}")
async def test_api_key(service: str, db: Session = Depends(get_db)):
    """Validate the configured API key for a given service."""
    probe = _PROBES.get(service)
    if not probe:
        raise HTTPException(status_code=400, detail=f"Service inconnu: {service}")

    s = get_or_create_settings(db)
    valid, detail = False, ""
    try:
        async with httpx.AsyncClient(timeout=8.0) as client:
            valid, detail = await probe(s, client)
    except httpx.RequestError as e:
        detail = f"Erreur réseau: {str(e)[:80]}"
    return {"valid": valid, "service": service, "detail": detail}
