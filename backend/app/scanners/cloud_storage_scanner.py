# backend/app/scanners/cloud_storage_scanner.py
"""
Cloud Storage Bucket Scanner - detect exposed S3, Azure Blob, GCS, and
DigitalOcean Spaces buckets associated with a domain.

Checks:
  - Candidate bucket names derived from domain parts
  - HTTP 200 → publicly readable ("exposed", HIGH)
  - HTTP 403 → bucket exists but private ("exists_private", MEDIUM)
  - Deduplication: same bucket on multiple provider URLs consolidated
"""
import asyncio
import httpx


# ─── Candidate generation ────────────────────────────────────────────────────

def _generate_candidates(domain: str) -> list[str]:
    """
    Derive candidate bucket names from a domain string.

    e.g. "app.example.com"  → base = "example", parts include "app"
         "example.com"      → base = "example"
    """
    # Strip common TLDs - take everything up to the last two labels
    labels = domain.lower().split(".")
    # base = second-to-last label (the registered name)
    base = labels[-2] if len(labels) >= 2 else labels[0]
    # sub-parts: any labels before the last two
    sub_parts = labels[:-2] if len(labels) > 2 else []

    prefixes = [
        "www", "assets", "static", "media", "backup",
        "cdn", "files", "data", "dev", "staging", "prod",
    ]
    suffixes = [
        "assets", "static", "media", "backup",
        "cdn", "files", "data",
    ]

    candidates: list[str] = [base]

    # prefix-base patterns  e.g. "assets-example"
    for p in prefixes:
        candidates.append(f"{p}-{base}")

    # base-suffix patterns  e.g. "example-assets"
    for s in suffixes:
        candidates.append(f"{base}-{s}")

    # sub-domain parts and their combined forms  e.g. "app", "app-example"
    for part in sub_parts:
        part_clean = part.replace(".", "-")
        candidates.append(part_clean)
        candidates.append(f"{part_clean}-{base}")

    env_suffixes = ["staging", "prod", "dev", "backup", "test", "demo"]
    for env in env_suffixes:
        candidates.append(f"{base}-{env}")

    # deduplicate while preserving order
    seen: set[str] = set()
    unique: list[str] = []
    for c in candidates:
        if c not in seen:
            seen.add(c)
            unique.append(c)
    return unique


# ─── Provider URL templates ──────────────────────────────────────────────────

def _build_urls(bucket: str) -> list[tuple[str, str]]:
    """Return (provider_name, url) pairs for a given bucket name."""
    return [
        ("AWS S3",              f"https://{bucket}.s3.amazonaws.com"),
        ("AWS S3",              f"https://s3.amazonaws.com/{bucket}"),
        ("Azure Blob",          f"https://{bucket}.blob.core.windows.net"),
        ("GCS",                 f"https://storage.googleapis.com/{bucket}"),
        ("GCS",                 f"https://{bucket}.storage.googleapis.com"),
        ("DigitalOcean Spaces", f"https://{bucket}.nyc3.digitaloceanspaces.com"),
        ("DigitalOcean Spaces", f"https://{bucket}.ams3.digitaloceanspaces.com"),
        ("DigitalOcean Spaces", f"https://{bucket}.sfo3.digitaloceanspaces.com"),
        ("DigitalOcean Spaces", f"https://{bucket}.sgp1.digitaloceanspaces.com"),
        ("DigitalOcean Spaces", f"https://{bucket}.lon1.digitaloceanspaces.com"),
        ("DigitalOcean Spaces", f"https://{bucket}.blr1.digitaloceanspaces.com"),
        ("Firebase",            f"https://{bucket}.appspot.com"),
        ("Firebase RTDB",       f"https://{bucket}-default-rtdb.firebaseio.com/.json"),
        ("Firebase App",        f"https://{bucket}.firebaseapp.com"),
        ("Backblaze B2",        f"https://f001.backblazeb2.com/file/{bucket}/"),
        ("Backblaze B2",        f"https://f002.backblazeb2.com/file/{bucket}/"),
        ("Backblaze B2",        f"https://f003.backblazeb2.com/file/{bucket}/"),
    ]


# ─── Single URL probe ────────────────────────────────────────────────────────

def _is_real_bucket_response(provider: str, url: str, body: str, status: int) -> bool:
    """
    Validate that a 200 response is actually an exposed bucket, not a homepage.
    Firebase App and Backblaze return 200 for non-existent/private buckets.
    """
    body_lower = body.lower()

    # Firebase App - a 200 from firebaseapp.com is usually just the hosted app homepage
    if "Firebase App" in provider or "firebaseapp.com" in url:
        return False  # Skip - not a storage bucket

    # Firebase RTDB - real exposures return JSON with data or null
    if "Firebase RTDB" in provider:
        stripped = body.strip()
        # "null" is a valid empty RTDB (not necessarily dangerous but exists)
        return stripped in ("null",) or stripped.startswith("{") or stripped.startswith("[")

    # Backblaze B2 - real exposed bucket shows XML listing or file list
    if "Backblaze" in provider:
        return "<listbucketresult" in body_lower or "<contents>" in body_lower

    # AWS S3 XML listing
    if "AWS S3" in provider:
        return "<listbucketresult" in body_lower or "<contents>" in body_lower or "<?xml" in body_lower

    # GCS XML listing
    if "GCS" in provider:
        return "<listbucketresult" in body_lower or "<?xml" in body_lower

    # Azure Blob - container listing
    if "Azure" in provider:
        return "<enumerationresults" in body_lower or "<?xml" in body_lower

    # DigitalOcean Spaces (S3-compatible)
    if "DigitalOcean" in provider:
        return "<listbucketresult" in body_lower or "<?xml" in body_lower

    return status == 200


async def _probe(client: httpx.AsyncClient, bucket: str, provider: str, url: str) -> dict | None:
    """
    Probe one URL.  Returns a finding dict or None if nothing interesting.
    """
    try:
        r = await client.get(url)
        if r.status_code == 200:
            body = r.text[:4096]
            if not _is_real_bucket_response(provider, url, body, 200):
                return None
            # Count approximate number of exposed files
            file_count = body.count("<Key>") + body.count("<Contents>")
            return {
                "name":       bucket,
                "provider":   provider,
                "url":        url,
                "status":     "exposed",
                "severity":   "high",
                "file_count": file_count if file_count > 0 else None,
            }
        if r.status_code == 403:
            # 403 = bucket exists but private - only valid for real storage providers
            if any(p in provider for p in ["AWS S3", "GCS", "Azure", "DigitalOcean", "Backblaze"]):
                return {
                    "name":     bucket,
                    "provider": provider,
                    "url":      url,
                    "status":   "exists_private",
                    "severity": "medium",
                }
    except Exception:
        pass
    return None


# ─── Deduplication ───────────────────────────────────────────────────────────

def _deduplicate(raw: list[dict]) -> list[dict]:
    """
    Consolidate multiple hits for the same (bucket, provider) pair.
    Prefer "exposed" over "exists_private".  Keep the first URL seen.
    """
    seen: dict[tuple[str, str], dict] = {}
    for finding in raw:
        key = (finding["name"], finding["provider"])
        if key not in seen:
            seen[key] = finding
        else:
            # upgrade status if this hit is "exposed"
            if finding["status"] == "exposed":
                seen[key] = finding
    return list(seen.values())


# ─── Main entry point ────────────────────────────────────────────────────────

async def cloud_storage_scan(domain: str) -> dict:
    """
    Detect exposed cloud storage buckets associated with *domain*.

    Returns a dict with keys:
        enriched, buckets_found, exposed_count, private_count, candidates_checked
    """
    result: dict = {
        "enriched":          False,
        "buckets_found":     [],
        "exposed_count":     0,
        "private_count":     0,
        "candidates_checked": 0,
    }

    try:
        candidates = _generate_candidates(domain)
        result["candidates_checked"] = len(candidates)

        async with httpx.AsyncClient(
            verify=False,
            timeout=6,
            follow_redirects=False,
            headers={"User-Agent": "Mozilla/5.0 (DomainRecon/7.0)"},
        ) as client:
            tasks = []
            for bucket in candidates:
                for provider, url in _build_urls(bucket):
                    tasks.append(_probe(client, bucket, provider, url))

            raw_results = await asyncio.gather(*tasks)

        raw_findings = [r for r in raw_results if r is not None]
        buckets_found = _deduplicate(raw_findings)

        exposed_count = sum(1 for b in buckets_found if b["status"] == "exposed")
        private_count = sum(1 for b in buckets_found if b["status"] == "exists_private")

        result.update({
            "enriched":      bool(buckets_found),
            "buckets_found": buckets_found,
            "exposed_count": exposed_count,
            "private_count": private_count,
        })

    except Exception:
        pass

    return result
