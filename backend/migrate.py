# backend/migrate.py
"""Idempotent migration — adds all missing columns to scans and settings tables."""
import sys
import os

sys.path.insert(0, os.path.dirname(__file__))

from app.database import engine
from sqlalchemy import text

ALL_COLUMNS = [
    ("scans",    "zone_transfer",     "JSON"),
    ("scans",    "wildcard_dns",      "JSON"),
    ("scans",    "dns_rebinding",     "JSON"),
    ("scans",    "tls_deep",          "JSON"),
    ("scans",    "csp_grade",         "JSON"),
    ("scans",    "hsts_deep",         "JSON"),
    ("scans",    "admin_panels",      "JSON"),
    ("scans",    "html_intelligence", "JSON"),
    ("scans",    "http_methods",      "JSON"),
    ("scans",    "smtp_security",     "JSON"),
    ("scans",    "banners",           "JSON"),
    ("scans",    "typosquatting",     "JSON"),
    ("scans",    "scan_profile",      "VARCHAR(10) DEFAULT 'full'"),
    ("scans",    "robtex",            "JSON"),
    ("scans",    "shodan_data",       "JSON"),
    ("settings", "quick_timeout",     "INTEGER DEFAULT 30"),
    ("settings", "full_timeout",      "INTEGER DEFAULT 180"),
    ("scans",    "bgpview_data",      "JSON"),
    ("scans",    "certsh_data",       "JSON"),
    ("scans",    "builtwith_data",    "JSON"),
    ("scans",    "dast_data",         "JSON"),
    ("scans",    "pdns_data",         "JSON"),
    ("settings", "builtwith_key",     "VARCHAR(100)"),
    ("settings", "circl_user",        "VARCHAR(100)"),
    ("settings", "circl_password",    "VARCHAR(200)"),
    ("scans",    "emailrep_data",     "JSON"),
    ("scans",    "abuseipdb_data",    "JSON"),
    ("scans",    "observatory_data",  "JSON"),
    ("scans",    "cert_pinning",      "JSON"),
    ("settings", "abuseipdb_key",     "VARCHAR(100)"),
    ("settings", "intelx_key",        "VARCHAR(100)"),
    ("settings", "safebrowsing_key",  "VARCHAR(100)"),
    ("settings", "phishtank_key",     "VARCHAR(100)"),
    ("scans",    "crypto_audit",      "JSON"),
    ("scans",    "intelx_data",       "JSON"),
    ("scans",    "dnssec_data",       "JSON"),
    ("scans",    "http_versions",     "JSON"),
    ("scans",    "safebrowsing_data", "JSON"),
    ("scans",    "phishtank_data",    "JSON"),
    ("scans",    "doh_comparison",    "JSON"),
    ("settings", "leakix_key",        "VARCHAR(100)"),
    ("settings", "github_token",      "VARCHAR(200)"),
    ("scans",    "cloud_storage",     "JSON"),
    ("scans",    "api_endpoints",     "JSON"),
    ("scans",    "cms_data",          "JSON"),
    ("scans",    "subdomain_bruteforce", "JSON"),
    ("scans",    "leakix_data",       "JSON"),
    ("scans",    "github_dork",       "JSON"),
    ("scans",    "hibp_data",         "JSON"),
    ("scans",    "js_deps_data",      "JSON"),
    ("scans",    "censys_data",       "JSON"),
    ("scans",    "nuclei_data",       "JSON"),
    ("scans",    "js_secrets_data", "JSON"),
    ("scans",    "dnsbl_data",      "JSON"),
    ("scans",    "paste_data",      "JSON"),
    ("settings", "google_cse_key",  "VARCHAR(100)"),
]


def migrate():
    with engine.connect() as conn:
        for table, col, dtype in ALL_COLUMNS:
            try:
                conn.execute(text(f"ALTER TABLE {table} ADD COLUMN {col} {dtype}"))
                print(f"  + {table}.{col}")
            except Exception as e:
                msg = str(e).lower()
                if "duplicate column" in msg or "already exists" in msg:
                    print(f"  = {table}.{col} (already exists)")
                else:
                    print(f"  ! {table}.{col}: {e}")
        conn.commit()
    print("Migration complete.")


if __name__ == "__main__":
    migrate()
