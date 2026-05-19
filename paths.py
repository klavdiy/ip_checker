"""
FieldNet Kit — repository layout and runtime paths.

Layout:
  fnkit.py              CLI entry (repo root)
  paths.py              path constants (repo root)
  lib/                  Python modules
  data/                 databases, config, sessions, cache
  scripts/              maintenance / install helpers
  tools/                SBOM generator
  docs/                 documentation
"""

from __future__ import annotations

import shutil
from pathlib import Path
from typing import List, Tuple

REPO_ROOT = Path(__file__).resolve().parent
LIB_DIR = REPO_ROOT / "lib"
DATA_DIR = REPO_ROOT / "data"
CONFIG_DIR = DATA_DIR / "config"
SESSIONS_DIR = DATA_DIR / "sessions"
CACHE_DIR = DATA_DIR / "cache"

DATABASE_FILE = DATA_DIR / "asn_database.json"
RESULTS_FILE = DATA_DIR / "scan_results.json"
LANGUAGE_FILE = CONFIG_DIR / ".language_config"
ENRICHMENT_CONFIG_FILE = CONFIG_DIR / ".enrichment_config.json"

OWASP_SESSIONS_DIR = SESSIONS_DIR / "owasp"
DNS_SESSIONS_DIR = SESSIONS_DIR / "dns"
DNS_GRAPH_DIR = DATA_DIR / "dns_graph"
TRACE_SESSIONS_DIR = SESSIONS_DIR / "trace"
PTR_SESSIONS_DIR = SESSIONS_DIR / "ptr"
NETWORK_CAPTURE_DIR = DATA_DIR / "pcap"
TOR_CACHE_DIR = CACHE_DIR / "tor"

# Legacy paths (pre data/ layout) → new location
_LEGACY_MOVES: Tuple[Tuple[Path, Path], ...] = (
    (REPO_ROOT / "asn_database.json", DATABASE_FILE),
    (REPO_ROOT / "scan_results.json", RESULTS_FILE),
    (REPO_ROOT / ".language_config", LANGUAGE_FILE),
    (REPO_ROOT / ".enrichment_config.json", ENRICHMENT_CONFIG_FILE),
    (REPO_ROOT / "owasp_sessions", OWASP_SESSIONS_DIR),
    (REPO_ROOT / "dns_sessions", DNS_SESSIONS_DIR),
    (REPO_ROOT / "dns_graph", DNS_GRAPH_DIR),
    (REPO_ROOT / "trace_sessions", TRACE_SESSIONS_DIR),
    (REPO_ROOT / "ptr_sessions", PTR_SESSIONS_DIR),
    (REPO_ROOT / "network capture", NETWORK_CAPTURE_DIR),
    (REPO_ROOT / ".cache", CACHE_DIR),
)


def ensure_data_layout() -> None:
    """Create data/ tree and migrate files from old root locations once."""
    for d in (
        DATA_DIR,
        CONFIG_DIR,
        SESSIONS_DIR,
        CACHE_DIR,
        DNS_GRAPH_DIR,
        OWASP_SESSIONS_DIR,
        DNS_SESSIONS_DIR,
        TRACE_SESSIONS_DIR,
        PTR_SESSIONS_DIR,
        NETWORK_CAPTURE_DIR,
        TOR_CACHE_DIR,
    ):
        d.mkdir(parents=True, exist_ok=True)

    for src, dst in _LEGACY_MOVES:
        if not src.exists():
            continue
        if dst.exists():
            if src.is_dir() and dst.is_dir():
                for child in src.iterdir():
                    target = dst / child.name
                    if not target.exists():
                        shutil.move(str(child), str(target))
                try:
                    src.rmdir()
                except OSError:
                    pass
            continue
        shutil.move(str(src), str(dst))

    try:
        from schema import run_startup_migrations

        upgraded = run_startup_migrations()
        if upgraded:
            import sys

            print(
                f"[fnkit] Migrated {len(upgraded)} data file(s) to current schema.",
                file=sys.stderr,
            )
    except Exception as exc:
        import sys

        print(f"[fnkit] Schema migration warning: {exc}", file=sys.stderr)


def ensure_lib_path() -> None:
    """Allow ``import network_diag`` from ``lib/`` and ``import schema`` from repo root."""
    import sys

    for entry in (str(REPO_ROOT), str(LIB_DIR)):
        if entry not in sys.path:
            sys.path.insert(0, entry)
