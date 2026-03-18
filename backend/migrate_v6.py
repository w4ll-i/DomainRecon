# backend/migrate_v6.py
"""Run once to add v6.0 columns to an existing database."""
import sys
import os

sys.path.insert(0, os.path.dirname(__file__))

from app.database import engine
from sqlalchemy import text

V6_COLUMNS = [
    ("scans", "zone_transfer",     "JSON"),
    ("scans", "wildcard_dns",      "JSON"),
    ("scans", "dns_rebinding",     "JSON"),
    ("scans", "tls_deep",          "JSON"),
    ("scans", "csp_grade",         "JSON"),
    ("scans", "hsts_deep",         "JSON"),
    ("scans", "admin_panels",      "JSON"),
    ("scans", "html_intelligence", "JSON"),
    ("scans", "http_methods",      "JSON"),
    ("scans", "smtp_security",     "JSON"),
    ("scans", "banners",           "JSON"),
    ("scans", "typosquatting",     "JSON"),
    ("scans", "scan_profile",      "VARCHAR(10) DEFAULT 'full'"),
    ("scans", "robtex",            "JSON"),
    ("settings", "quick_timeout",  "INTEGER DEFAULT 30"),
    ("settings", "full_timeout",   "INTEGER DEFAULT 180"),
]


def migrate():
    with engine.connect() as conn:
        for table, col, dtype in V6_COLUMNS:
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
