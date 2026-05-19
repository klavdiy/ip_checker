#!/usr/bin/env python3
"""
Validate or maintain asn_database.json for FieldNet Kit.

Used by CI and operators; delegates to fnkit.load_database / maintain_asn_database.

Examples:
  python3 scripts/validate_asn_db.py           # read-only validate (exit 1 on hard errors)
  python3 scripts/validate_asn_db.py --fix   # dedupe, prune /8, refresh metadata, save
  python3 scripts/validate_asn_db.py --json    # machine-readable report on stdout
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from paths import DATABASE_FILE, ensure_data_layout, ensure_lib_path  # noqa: E402

ensure_data_layout()
ensure_lib_path()

from fnkit import (  # noqa: E402
    load_database,
    maintain_asn_database,
    save_database,
    validate_asn_database,
)


def main() -> int:
    parser = argparse.ArgumentParser(description="Validate or maintain asn_database.json")
    parser.add_argument(
        "--fix",
        action="store_true",
        help="Run maintenance (dedupe ASN rows, prune pools wider than /20, fix metadata) and save.",
    )
    parser.add_argument("--json", action="store_true", help="Print JSON report to stdout.")
    args = parser.parse_args()

    if args.fix:
        database = load_database()
        report = maintain_asn_database(database, refresh_pools=True)
        save_database(database)
    else:
        try:
            database = json.loads(DATABASE_FILE.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            print(f"Cannot read {DATABASE_FILE}: {exc}", file=sys.stderr)
            return 1
        report = validate_asn_database(database)

    if args.json:
        print(json.dumps(report, ensure_ascii=False, indent=2))
    else:
        issues = report.get("issues") or []
        stats = report.get("stats") or {}
        maint = report.get("maintenance") or {}
        print(f"asn_database.json: ok={report.get('ok')}")
        print(f"  ASN rows: {stats.get('asn_rows', '?')}")
        print(f"  Acceptable pools: {stats.get('acceptable_pools', '?')}")
        print(f"  Empty-pool ASNs: {len(stats.get('empty_pool_asns') or [])}")
        if maint:
            print(f"  Merged duplicate groups: {maint.get('merge_groups', 0)}")
            print(f"  Coarse pools removed: {maint.get('coarse_pools_removed', 0)}")
        if issues:
            print("  Issues:")
            for line in issues:
                print(f"    - {line}")

    return 0 if report.get("ok") else 1


if __name__ == "__main__":
    sys.exit(main())
