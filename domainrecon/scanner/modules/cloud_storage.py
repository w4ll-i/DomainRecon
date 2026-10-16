# =============================================================================
# DomainRecon - Module « cloud_storage » : buckets de stockage exposés
# =============================================================================
# Recherche des buckets de stockage (AWS S3, Google Cloud Storage, Azure Blob,
# DigitalOcean Spaces) liés au domaine :
#   - les noms de buckets CITÉS dans la page d'accueil de la cible sont testés en
#     priorité et signalés avec confiance ; les noms DEVINÉS à partir du domaine
#     ne sont retenus que si la réponse est un vrai listing (XML ListBucketResult) ;
#   - Firebase Hosting (appspot.com, firebaseapp.com) n'est plus pris pour un
#     bucket (l'ancien faux positif) ; seule la base temps réel Firebase (.json)
#     est sondée ;
#   - la concurrence est bornée, aucun objet n'est jamais lu (listing seulement).
# Accès à des hôtes tiers (pas la cible) : catégorie « sensible », autorisation
# de la cible requise. Un bucket deviné qui n'appartient pas à la cible n'est pas
# affirmé comme sien (confiance « guessed »).
# =============================================================================

import asyncio
import re

from ..http_utils import FETCH_ERRORS, fetch, site_of
from ..impl import web_exposure as probe
from ..registry import ModuleSpec, ScanContext
from ..rules import FindingInput, FindingRule, hit
from ..score import as_dict, as_list

_PROBE_TIMEOUT = 6.0
_CONCURRENCY = 8
_MAX_CANDIDATES = 24

# Listing public reconnu (sans lire les objets).
_LISTING = re.compile(r"<listbucketresult|<enumerationresults", re.IGNORECASE)
# Références de buckets dans la page d'accueil (URL de stockage).
_REFERENCED = re.compile(
    r"""https?://
    (?:
        ([a-z0-9][a-z0-9.\-]{1,61})\.s3[.\-][a-z0-9.\-]*amazonaws\.com
      | s3[.\-][a-z0-9.\-]*amazonaws\.com/([a-z0-9][a-z0-9.\-]{1,61})
      | storage\.googleapis\.com/([a-z0-9][a-z0-9._\-]{1,61})
      | ([a-z0-9][a-z0-9.\-]{1,61})\.storage\.googleapis\.com
      | ([a-z0-9][a-z0-9.\-]{1,61})\.blob\.core\.windows\.net
      | ([a-z0-9][a-z0-9.\-]{1,61})\.[a-z0-9]+\.digitaloceanspaces\.com
    )""",
    re.IGNORECASE | re.VERBOSE,
)


def _candidates(domain: str) -> list[str]:
    """Noms de buckets devinés à partir du domaine enregistrable."""
    base = site_of(domain).split(".")[0] if site_of(domain) else domain.split(".")[0]
    if not base:
        return []
    prefixes = ("assets", "static", "media", "backup", "cdn", "files", "data")
    envs = ("dev", "staging", "prod", "backup")
    names = [base]
    names += [f"{base}-{s}" for s in prefixes]
    names += [f"{s}-{base}" for s in prefixes]
    names += [f"{base}-{e}" for e in envs]
    seen: list[str] = []
    for name in names:
        if name not in seen:
            seen.append(name)
    return seen[:_MAX_CANDIDATES]


def _urls(bucket: str) -> list[tuple[str, str]]:
    return [
        ("AWS S3", f"https://{bucket}.s3.amazonaws.com/"),
        ("GCS", f"https://storage.googleapis.com/{bucket}/"),
        ("Azure Blob", f"https://{bucket}.blob.core.windows.net/?comp=list"),
        ("DigitalOcean Spaces", f"https://{bucket}.nyc3.digitaloceanspaces.com/"),
        ("Firebase RTDB", f"https://{bucket}-default-rtdb.firebaseio.com/.json"),
    ]


def _referenced_buckets(html: str) -> set[str]:
    found: set[str] = set()
    for match in _REFERENCED.finditer(html or ""):
        for group in match.groups():
            if group:
                found.add(group.lower())
    return found


async def _probe(client, bucket, provider, url, referenced: bool) -> dict | None:
    try:
        fetched = await fetch(
            client, url, site=None, max_bytes=probe.MAX_BODY, max_redirects=0, timeout=_PROBE_TIMEOUT
        )
    except FETCH_ERRORS:
        return None
    status = fetched.status_code
    confidence = "referenced" if referenced else "guessed"
    if status == 200:
        if provider == "Firebase RTDB":
            body = fetched.text.strip()
            if body in ("null",) or body.startswith(("{", "[")):
                return {"bucket": bucket, "provider": provider, "status": "exposed", "confidence": confidence}
            return None
        if _LISTING.search(fetched.text):
            return {"bucket": bucket, "provider": provider, "status": "exposed", "confidence": confidence}
        return None
    if status == 403 and referenced:
        # Bucket cité par le site mais fermé : il existe, propriété probable.
        return {"bucket": bucket, "provider": provider, "status": "exists_private", "confidence": confidence}
    return None


async def run(context: ScanContext) -> dict:
    home = await context.homepage()
    referenced = _referenced_buckets(home.text if home.reachable else "")
    guessed = [b for b in _candidates(context.apex) if b not in referenced]

    tasks = []
    for bucket in sorted(referenced):
        for provider, url in _urls(bucket):
            tasks.append((bucket, provider, url, True))
    for bucket in guessed:
        for provider, url in _urls(bucket):
            tasks.append((bucket, provider, url, False))

    semaphore = asyncio.Semaphore(_CONCURRENCY)

    async def one(bucket, provider, url, ref):
        async with semaphore:
            return await _probe(context.http, bucket, provider, url, ref)

    results = await asyncio.gather(*(one(*t) for t in tasks))
    buckets: dict[tuple[str, str], dict] = {}
    for entry in results:
        if entry is None:
            continue
        key = (entry["bucket"], entry["provider"])
        if key not in buckets or entry["status"] == "exposed":
            buckets[key] = entry
    found = list(buckets.values())
    return {
        "measured": True,
        "error": None,
        "referenced": sorted(referenced),
        "candidates_checked": len(referenced) + len(guessed),
        "buckets": found,
        "exposed_count": sum(1 for b in found if b["status"] == "exposed"),
    }


def _check_exposed(f: FindingInput) -> object:
    data = as_dict(f.data)
    exposed = [
        f"{b.get('bucket')} ({b.get('provider')})"
        for b in as_list(data.get("buckets"))
        if isinstance(b, dict) and b.get("status") == "exposed"
    ]
    return hit(buckets=", ".join(exposed)) if exposed else None


SPEC = ModuleSpec(
    name="cloud_storage",
    family="web",
    category="sensible",
    run=run,
    order=149,
    timeout=60,
    optional=True,
    findings=(FindingRule(code="finding.cloud_storage.exposed", severity="high", check=_check_exposed),),
)
