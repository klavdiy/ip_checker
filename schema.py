"""
FieldNet Kit — schema versions, migrations, and compatibility layer.

All persisted JSON documents use ``metadata.schema_version`` (ASN DB, scan results)
or top-level ``format`` (sessions). Legacy ``ip_checker_*`` and pre-schema files
are upgraded on load and optionally at startup via ``run_startup_migrations()``.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple, Union

# --- Canonical schema IDs (current) -------------------------------------------------

SCHEMA_ASN_DATABASE_V2 = "fnkit.asn_database/2"
SCHEMA_ASN_DATABASE_V1 = "fnkit.asn_database/1"

SCHEMA_SCAN_RESULTS_V1 = "fnkit.scan_results/1"

FORMAT_TRACE_V1 = "fnkit_trace_v1"
FORMAT_DNS_V1 = "fnkit_dns_v1"
FORMAT_OWASP_V1 = "fnkit_owasp_v1"
FORMAT_PTR_V1 = "fnkit_ptr_v1"

LEGACY_FORMAT_TRACE_V1 = "ip_checker_trace_v1"
LEGACY_FORMAT_DNS_V1 = "ip_checker_dns_v1"
LEGACY_FORMAT_OWASP_V1 = "ip_checker_owasp_v1"

CURRENT_SCHEMA: Dict[str, str] = {
    "asn_database": SCHEMA_ASN_DATABASE_V2,
    "scan_results": SCHEMA_SCAN_RESULTS_V1,
    "trace_session": FORMAT_TRACE_V1,
    "dns_session": FORMAT_DNS_V1,
    "owasp_session": FORMAT_OWASP_V1,
    "ptr_session": FORMAT_PTR_V1,
}

SESSION_FORMAT_ALIASES: Dict[str, str] = {
    LEGACY_FORMAT_TRACE_V1: FORMAT_TRACE_V1,
    LEGACY_FORMAT_DNS_V1: FORMAT_DNS_V1,
    LEGACY_FORMAT_OWASP_V1: FORMAT_OWASP_V1,
}

ACCEPTABLE_SESSION_FORMATS: Dict[str, Tuple[str, ...]] = {
    "trace_session": (FORMAT_TRACE_V1, LEGACY_FORMAT_TRACE_V1),
    "dns_session": (FORMAT_DNS_V1, LEGACY_FORMAT_DNS_V1),
    "owasp_session": (FORMAT_OWASP_V1, LEGACY_FORMAT_OWASP_V1),
    "ptr_session": (FORMAT_PTR_V1,),
}


class DocumentKind:
    ASN_DATABASE = "asn_database"
    SCAN_RESULTS = "scan_results"
    TRACE_SESSION = "trace_session"
    DNS_SESSION = "dns_session"
    OWASP_SESSION = "owasp_session"
    PTR_SESSION = "ptr_session"


MigrationFn = Callable[[Dict[str, Any]], Dict[str, Any]]


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def parse_schema_id(schema_id: Optional[str]) -> Tuple[Optional[str], int]:
    """Parse ``fnkit.kind/N`` → (kind, version). Returns (None, 0) if invalid."""
    if not schema_id or not isinstance(schema_id, str):
        return None, 0
    if "/" not in schema_id:
        return None, 0
    name, ver_s = schema_id.rsplit("/", 1)
    try:
        return name, int(ver_s)
    except ValueError:
        return name, 0


def detect_asn_database_schema(doc: Dict[str, Any]) -> str:
    meta = doc.get("metadata") if isinstance(doc.get("metadata"), dict) else {}
    explicit = meta.get("schema_version")
    if isinstance(explicit, str) and explicit.startswith("fnkit.asn_database/"):
        return explicit
    if isinstance(doc.get("asn_data"), list) and meta:
        return SCHEMA_ASN_DATABASE_V1
    if isinstance(doc.get("asn_data"), list):
        return SCHEMA_ASN_DATABASE_V1
    return SCHEMA_ASN_DATABASE_V1


def detect_scan_results_schema(doc: Dict[str, Any]) -> str:
    if doc.get("schema_version") == SCHEMA_SCAN_RESULTS_V1:
        return SCHEMA_SCAN_RESULTS_V1
    if doc.get("format") == SCHEMA_SCAN_RESULTS_V1:
        return SCHEMA_SCAN_RESULTS_V1
    if "results" in doc:
        return "fnkit.scan_results/0"
    return SCHEMA_SCAN_RESULTS_V1


def detect_session_schema(doc: Dict[str, Any], kind: str) -> str:
    fmt = doc.get("format")
    if isinstance(fmt, str):
        if fmt in SESSION_FORMAT_ALIASES:
            return SESSION_FORMAT_ALIASES[fmt]
        if fmt in (CURRENT_SCHEMA.get(kind),):
            return fmt
        return fmt
    return CURRENT_SCHEMA[kind]


def detect_schema(doc: Dict[str, Any], kind: str) -> str:
    if kind == DocumentKind.ASN_DATABASE:
        return detect_asn_database_schema(doc)
    if kind == DocumentKind.SCAN_RESULTS:
        return detect_scan_results_schema(doc)
    if kind in ACCEPTABLE_SESSION_FORMATS:
        return detect_session_schema(doc, kind)
    return CURRENT_SCHEMA.get(kind, "")


def _migrate_asn_v1_to_v2(doc: Dict[str, Any]) -> Dict[str, Any]:
    meta = doc.setdefault("metadata", {})
    if not isinstance(meta.get("quarantine_cases"), list):
        meta["quarantine_cases"] = meta.get("quarantine_cases") or []
    if "last_maintenance" not in meta:
        meta["last_maintenance"] = meta.get("last_maintenance") or {}
    meta["schema_version"] = SCHEMA_ASN_DATABASE_V2
    meta["schema_migrated_at"] = _utc_now()
    if "version" not in meta:
        meta["version"] = "2.0"
    if not isinstance(doc.get("asn_data"), list):
        doc["asn_data"] = []
    return doc


def _migrate_asn_v0_to_v1(doc: Dict[str, Any]) -> Dict[str, Any]:
    if "asn_data" not in doc:
        doc["asn_data"] = []
    meta = doc.setdefault("metadata", {})
    meta.setdefault("version", "2.0")
    meta.setdefault("last_updated", datetime.now().strftime("%Y-%m-%d"))
    meta.setdefault("quarantine_cases", [])
    return doc


def _migrate_scan_v0_to_v1(doc: Dict[str, Any]) -> Dict[str, Any]:
    doc["schema_version"] = SCHEMA_SCAN_RESULTS_V1
    doc["format"] = SCHEMA_SCAN_RESULTS_V1
    doc.setdefault("results", [])
    doc.setdefault("mismatches_found", 0)
    if "timestamp" not in doc:
        doc["timestamp"] = _utc_now()
    return doc


def _normalize_session(doc: Dict[str, Any], kind: str) -> Dict[str, Any]:
    canonical = CURRENT_SCHEMA[kind]
    fmt = doc.get("format")
    if isinstance(fmt, str) and fmt in SESSION_FORMAT_ALIASES:
        doc = dict(doc)
        doc["format"] = SESSION_FORMAT_ALIASES[fmt]
        doc["legacy_format"] = fmt
    elif not fmt:
        doc = dict(doc)
        doc["format"] = canonical
    return doc


ASN_MIGRATIONS: List[Tuple[str, str, MigrationFn]] = [
    (SCHEMA_ASN_DATABASE_V1, SCHEMA_ASN_DATABASE_V2, _migrate_asn_v1_to_v2),
]

# Treat undetected legacy as v1 before v2 chain
_ASN_PRE_MIGRATIONS: List[Tuple[str, MigrationFn]] = [
    ("fnkit.asn_database/0", _migrate_asn_v0_to_v1),
]


def _apply_chain(
    doc: Dict[str, Any],
    current: str,
    target: str,
    chain: List[Tuple[str, str, MigrationFn]],
    pre: Optional[List[Tuple[str, MigrationFn]]] = None,
) -> Dict[str, Any]:
    if current == target:
        return doc
    if pre and current.endswith("/0"):
        for from_id, fn in pre:
            if current == from_id:
                doc = fn(doc)
                current = detect_schema(doc, DocumentKind.ASN_DATABASE)
                break
    guard = 0
    while current != target and guard < 10:
        guard += 1
        progressed = False
        for src, dst, fn in chain:
            if current == src:
                doc = fn(doc)
                current = dst
                progressed = True
                break
        if not progressed:
            break
    return doc


def migrate_document(doc: Dict[str, Any], kind: str, *, target: Optional[str] = None) -> Dict[str, Any]:
    """Upgrade *doc* to *target* (or CURRENT_SCHEMA[kind]). Returns same dict, mutated."""
    target = target or CURRENT_SCHEMA[kind]
    current = detect_schema(doc, kind)

    if kind == DocumentKind.ASN_DATABASE:
        if current == SCHEMA_ASN_DATABASE_V1 and not (
            isinstance(doc.get("metadata"), dict) and doc["metadata"].get("schema_version")
        ):
            doc = _migrate_asn_v0_to_v1(doc)
            current = SCHEMA_ASN_DATABASE_V1
        return _apply_chain(
            doc, current, target, ASN_MIGRATIONS, pre=_ASN_PRE_MIGRATIONS
        )

    if kind == DocumentKind.SCAN_RESULTS:
        if current == "fnkit.scan_results/0":
            return _migrate_scan_v0_to_v1(doc)
        return doc

    if kind in ACCEPTABLE_SESSION_FORMATS:
        return _normalize_session(doc, kind)

    return doc


def stamp_document(doc: Dict[str, Any], kind: str) -> Dict[str, Any]:
    """Ensure document carries current schema / format before save."""
    doc = migrate_document(doc, kind)
    if kind == DocumentKind.ASN_DATABASE:
        meta = doc.setdefault("metadata", {})
        meta["schema_version"] = SCHEMA_ASN_DATABASE_V2
    elif kind == DocumentKind.SCAN_RESULTS:
        doc["schema_version"] = SCHEMA_SCAN_RESULTS_V1
        doc["format"] = SCHEMA_SCAN_RESULTS_V1
    elif kind in CURRENT_SCHEMA:
        doc["format"] = CURRENT_SCHEMA[kind]
    return doc


def is_session_format_valid(doc: Dict[str, Any], kind: str) -> bool:
    fmt = doc.get("format")
    if not isinstance(fmt, str):
        return False
    allowed = ACCEPTABLE_SESSION_FORMATS.get(kind, ())
    return fmt in allowed or fmt in SESSION_FORMAT_ALIASES


def compatibility_view(doc: Dict[str, Any], kind: str) -> Dict[str, Any]:
    """
    Return a normalized in-memory view (legacy aliases resolved, schema at current).
    Does not mutate the original dict unless migration runs on a copy.
    """
    import copy

    view = migrate_document(copy.deepcopy(doc), kind)
    if kind in ACCEPTABLE_SESSION_FORMATS:
        view = _normalize_session(view, kind)
    return view


def load_json_file(
    path: Union[str, Path],
    kind: str,
    *,
    migrate: bool = True,
) -> Dict[str, Any]:
    path = Path(path)
    with open(path, encoding="utf-8") as f:
        doc = json.load(f)
    if migrate:
        doc = migrate_document(doc, kind)
    return doc


def save_json_file(
    path: Union[str, Path],
    kind: str,
    doc: Dict[str, Any],
    *,
    indent: int = 2,
) -> None:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    stamped = stamp_document(doc, kind)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(stamped, f, indent=indent, ensure_ascii=False)


def validate_schema_version(doc: Dict[str, Any], kind: str) -> List[str]:
    """Return human-readable issues if document schema is behind current."""
    issues: List[str] = []
    current = detect_schema(doc, kind)
    target = CURRENT_SCHEMA.get(kind, "")
    if kind == DocumentKind.ASN_DATABASE:
        if current != target:
            issues.append(f"schema_version {current!r} → upgrade to {target!r}")
        meta = doc.get("metadata", {})
        if meta.get("schema_version") != SCHEMA_ASN_DATABASE_V2:
            issues.append("metadata.schema_version missing or outdated")
    elif kind == DocumentKind.SCAN_RESULTS:
        if current != target:
            issues.append(f"scan results schema {current!r} → {target!r}")
    elif kind in ACCEPTABLE_SESSION_FORMATS:
        if not is_session_format_valid(doc, kind):
            issues.append(f"unknown session format: {doc.get('format')!r}")
    return issues


def run_startup_migrations() -> List[str]:
    """
    Migrate known data files under ``data/`` after layout migration.
    Returns list of paths that were upgraded and written.
    """
    from paths import (
        DATABASE_FILE,
        DNS_SESSIONS_DIR,
        OWASP_SESSIONS_DIR,
        PTR_SESSIONS_DIR,
        RESULTS_FILE,
        TRACE_SESSIONS_DIR,
    )

    upgraded: List[str] = []

    def _needs_write(raw: Dict[str, Any], after: Dict[str, Any], kind: str) -> bool:
        target = CURRENT_SCHEMA[kind]
        if detect_schema(raw, kind) != target or detect_schema(after, kind) != target:
            return True
        if kind == DocumentKind.ASN_DATABASE:
            return raw.get("metadata", {}).get("schema_version") != SCHEMA_ASN_DATABASE_V2
        if kind == DocumentKind.SCAN_RESULTS:
            return raw.get("schema_version") != SCHEMA_SCAN_RESULTS_V1
        if kind in ACCEPTABLE_SESSION_FORMATS:
            return raw.get("format") in SESSION_FORMAT_ALIASES
        return False

    def _maybe_migrate_file(path: Path, kind: str) -> None:
        if not path.is_file():
            return
        try:
            raw = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return
        if not isinstance(raw, dict):
            return
        after_doc = migrate_document(raw, kind)
        if _needs_write(raw, after_doc, kind):
            save_json_file(path, kind, after_doc)
            upgraded.append(str(path))

    _maybe_migrate_file(DATABASE_FILE, DocumentKind.ASN_DATABASE)
    _maybe_migrate_file(RESULTS_FILE, DocumentKind.SCAN_RESULTS)

    for directory, kind in (
        (TRACE_SESSIONS_DIR, DocumentKind.TRACE_SESSION),
        (DNS_SESSIONS_DIR, DocumentKind.DNS_SESSION),
        (OWASP_SESSIONS_DIR, DocumentKind.OWASP_SESSION),
        (PTR_SESSIONS_DIR, DocumentKind.PTR_SESSION),
    ):
        if not directory.is_dir():
            continue
        for path in directory.glob("*.json"):
            _maybe_migrate_file(path, kind)

    return upgraded
