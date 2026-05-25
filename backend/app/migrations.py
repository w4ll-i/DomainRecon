# backend/app/migrations.py
"""
Legacy idempotent schema migrations.

These ALTER TABLE statements catch up any pre-Alembic database to the
current set of columns expected by `models.py`. They are safe to run
repeatedly (each column is checked before adding).

New schema changes should go through Alembic (see `backend/alembic/`).
This module exists so legacy databases continue to work after the
Alembic transition, and is called once on app startup.
"""
from sqlalchemy import inspect, text
from sqlalchemy.engine import Engine


# Legacy columns that used to be added unnamed (plain JSON) - keep for back-compat.
LEGACY_SCAN_COLUMNS = [
    "urlscan_data", "wayback_data", "threat_intel",
    "js_analysis", "favicon_hash", "linked_domains",
    "email_blacklist", "hsts_preload", "vuln_data",
]

SCAN_COLUMNS: list[tuple[str, str]] = [
    ("zone_transfer",        "JSON"),
    ("wildcard_dns",         "JSON"),
    ("dns_rebinding",        "JSON"),
    ("tls_deep",             "JSON"),
    ("csp_grade",            "JSON"),
    ("hsts_deep",            "JSON"),
    ("admin_panels",         "JSON"),
    ("html_intelligence",    "JSON"),
    ("http_methods",         "JSON"),
    ("smtp_security",        "JSON"),
    ("banners",              "JSON"),
    ("typosquatting",        "JSON"),
    ("scan_profile",         "VARCHAR(10) DEFAULT 'full'"),
    ("robtex",               "JSON"),
    ("shodan_data",          "JSON"),
    ("bgpview_data",         "JSON"),
    ("certsh_data",          "JSON"),
    ("builtwith_data",       "JSON"),
    ("dast_data",            "JSON"),
    ("pdns_data",            "JSON"),
    ("emailrep_data",        "JSON"),
    ("abuseipdb_data",       "JSON"),
    ("observatory_data",     "JSON"),
    ("cert_pinning",         "JSON"),
    ("crypto_audit",         "JSON"),
    ("intelx_data",          "JSON"),
    ("dnssec_data",          "JSON"),
    ("http_versions",        "JSON"),
    ("safebrowsing_data",    "JSON"),
    ("phishtank_data",       "JSON"),
    ("doh_comparison",       "JSON"),
    ("cloud_storage",        "JSON"),
    ("api_endpoints",        "JSON"),
    ("cms_data",             "JSON"),
    ("subdomain_bruteforce", "JSON"),
    ("leakix_data",          "JSON"),
    ("github_dork",          "JSON"),
    ("hibp_data",            "JSON"),
    ("js_deps_data",         "JSON"),
    ("censys_data",          "JSON"),
    ("nuclei_data",          "JSON"),
    ("js_secrets_data",      "JSON"),
    ("dnsbl_data",           "JSON"),
    ("paste_data",           "JSON"),
    ("mta_sts",              "JSON"),
    ("bimi",                 "JSON"),
    ("reverse_ip",           "JSON"),
]

SETTINGS_COLUMNS: list[tuple[str, str]] = [
    ("quick_timeout",    "INTEGER DEFAULT 60"),
    ("full_timeout",     "INTEGER DEFAULT 300"),
    ("builtwith_key",    "VARCHAR(100)"),
    ("circl_user",       "VARCHAR(100)"),
    ("circl_password",   "VARCHAR(200)"),
    ("abuseipdb_key",    "VARCHAR(100)"),
    ("intelx_key",       "VARCHAR(100)"),
    ("safebrowsing_key", "VARCHAR(100)"),
    ("phishtank_key",    "VARCHAR(100)"),
    ("leakix_key",       "VARCHAR(100)"),
    ("github_token",     "VARCHAR(200)"),
    ("google_cse_key",   "VARCHAR(100)"),
]


def apply_legacy_migrations(engine: Engine) -> None:
    """Idempotently add every known column to `scans` and `settings`.

    Called at app startup. Safe on both fresh and existing databases:
    `Base.metadata.create_all()` (run before this) handles new installs;
    this function just catches up DBs that predate certain columns.
    """
    inspector = inspect(engine)
    existing_tables = set(inspector.get_table_names())
    if "scans" not in existing_tables or "settings" not in existing_tables:
        # Fresh DB - create_all already built the full schema.
        return

    existing_scan_cols = {c["name"] for c in inspector.get_columns("scans")}
    existing_settings_cols = {c["name"] for c in inspector.get_columns("settings")}

    with engine.connect() as conn:
        for col in LEGACY_SCAN_COLUMNS:
            if col not in existing_scan_cols:
                conn.execute(text(f"ALTER TABLE scans ADD COLUMN {col} JSON"))
        for col, dtype in SCAN_COLUMNS:
            if col not in existing_scan_cols:
                conn.execute(text(f"ALTER TABLE scans ADD COLUMN {col} {dtype}"))
        for col, dtype in SETTINGS_COLUMNS:
            if col not in existing_settings_cols:
                conn.execute(text(f"ALTER TABLE settings ADD COLUMN {col} {dtype}"))
        conn.commit()
