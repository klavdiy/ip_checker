#!/usr/bin/env python3
"""
Bulk reverse DNS (PTR) sweep for an IP range with rate limiting.

Uses ``socket.gethostbyaddr`` (system resolver). No dnspython required.
"""

from __future__ import annotations

import ipaddress
import json
import socket
import time
from collections import Counter
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FuturesTimeout
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple

from paths import PTR_SESSIONS_DIR
PTR_FORMAT_V1 = "fnkit_ptr_v1"

STRINGS: Dict[str, Dict[str, str]] = {
    "en": {
        "title": "Reverse DNS (PTR) sweep",
        "scanning": "PTR sweep: {n} address(es) at {qps:.1f} qps…",
        "progress": "  [{done}/{total}] {ip} → {ptr}",
        "progress_none": "  [{done}/{total}] {ip} → (no PTR)",
        "progress_err": "  [{done}/{total}] {ip} → error: {err}",
        "summary_title": "PTR summary",
        "sum_scanned": "Scanned: ",
        "sum_with_ptr": "With PTR: ",
        "sum_no_ptr": "No PTR: ",
        "sum_errors": "Errors: ",
        "unique_names": "Unique PTR names: ",
        "top_suffixes": "Top PTR suffixes (infrastructure hints):",
        "suffix_row": "  {suffix}: {n}",
        "table_title": "Addresses with PTR (sample):",
        "table_row": "  {ip}  {ptr}",
        "table_more": "  … and {n} more with PTR",
        "invalid_range": "Invalid IP range",
        "save_ok": "PTR session saved: {path}",
        "save_fail": "PTR session save failed: {err}",
    },
    "ru": {
        "title": "Обход reverse DNS (PTR)",
        "scanning": "PTR-обход: {n} адрес(ов), {qps:.1f} qps…",
        "progress": "  [{done}/{total}] {ip} → {ptr}",
        "progress_none": "  [{done}/{total}] {ip} → (нет PTR)",
        "progress_err": "  [{done}/{total}] {ip} → ошибка: {err}",
        "summary_title": "Сводка PTR",
        "sum_scanned": "Проверено: ",
        "sum_with_ptr": "С PTR: ",
        "sum_no_ptr": "Без PTR: ",
        "sum_errors": "Ошибки: ",
        "unique_names": "Уникальных PTR: ",
        "top_suffixes": "Частые суффиксы PTR (подсказки по инфраструктуре):",
        "suffix_row": "  {suffix}: {n}",
        "table_title": "Адреса с PTR (выборка):",
        "table_row": "  {ip}  {ptr}",
        "table_more": "  … ещё {n} с PTR",
        "invalid_range": "Неверный диапазон IP",
        "save_ok": "Сессия PTR сохранена: {path}",
        "save_fail": "Не удалось сохранить сессию PTR: {err}",
    },
}


def msg(lang: str, key: str, **kwargs: Any) -> str:
    table = STRINGS.get(lang if lang in STRINGS else "en", STRINGS["en"])
    return table.get(key, key).format(**kwargs)


def iter_range_ips(start: str, end: str, *, max_ips: int) -> List[str]:
    start_ip = ipaddress.ip_address(start)
    end_ip = ipaddress.ip_address(end)
    if start_ip.version != end_ip.version or start_ip > end_ip:
        raise ValueError("invalid range")
    out: List[str] = []
    current = start_ip
    limit = max(1, max_ips)
    while current <= end_ip and len(out) < limit:
        out.append(str(current))
        current += 1
    return out


def lookup_ptr(ip: str, *, timeout: float = 4.0) -> Dict[str, Any]:
    """Reverse lookup for one IP via system resolver."""
    try:
        ipaddress.ip_address(ip)
    except ValueError:
        return {"ok": False, "error": "invalid IP"}

    def _resolve() -> Tuple[str, List[str]]:
        host, aliases, _addrlist = socket.gethostbyaddr(ip)
        return host, list(aliases or [])

    try:
        with ThreadPoolExecutor(max_workers=1) as pool:
            fut = pool.submit(_resolve)
            host, aliases = fut.result(timeout=max(0.5, timeout))
        ptr = (host or "").strip().rstrip(".")
        if not ptr:
            return {"ok": False, "no_ptr": True}
        return {"ok": True, "ptr": ptr, "aliases": aliases}
    except FuturesTimeout:
        return {"ok": False, "error": "timeout"}
    except socket.herror:
        return {"ok": False, "no_ptr": True}
    except socket.gaierror as exc:
        return {"ok": False, "error": str(exc)}
    except OSError as exc:
        return {"ok": False, "error": str(exc)}


def _ptr_suffix(hostname: str) -> str:
    """Coarse label for grouping (last two DNS labels)."""
    parts = hostname.lower().rstrip(".").split(".")
    if len(parts) >= 2:
        return ".".join(parts[-2:])
    return hostname.lower()


def summarize_ptr_results(rows: List[Dict[str, Any]]) -> Dict[str, Any]:
    with_ptr = [r for r in rows if r.get("ptr")]
    no_ptr = [r for r in rows if r.get("no_ptr")]
    errors = [r for r in rows if r.get("error")]
    names = [r["ptr"] for r in with_ptr if r.get("ptr")]
    suffix_counts = Counter(_ptr_suffix(n) for n in names)
    return {
        "scanned": len(rows),
        "with_ptr": len(with_ptr),
        "no_ptr": len(no_ptr),
        "errors": len(errors),
        "unique_ptr_count": len(set(names)),
        "top_suffixes": suffix_counts.most_common(12),
        "unique_names": sorted(set(names)),
    }


def scan_ptr_range(
    start: str,
    end: str,
    *,
    max_ips: int = 256,
    qps: float = 10.0,
    timeout: float = 4.0,
    show_progress: bool = True,
    lang: str = "en",
    on_progress: Optional[Callable[[Dict[str, Any]], None]] = None,
) -> Dict[str, Any]:
    """Walk an IP range and collect PTR records with rate limiting."""
    try:
        ips = iter_range_ips(start, end, max_ips=max_ips)
    except ValueError:
        return {"success": False, "error": msg(lang, "invalid_range")}

    qps = max(0.1, float(qps))
    interval = 1.0 / qps
    rows: List[Dict[str, Any]] = []

    if show_progress:
        print(msg(lang, "scanning", n=len(ips), qps=qps))

    last_at = time.monotonic()
    for idx, ip in enumerate(ips, start=1):
        elapsed = time.monotonic() - last_at
        if elapsed < interval:
            time.sleep(interval - elapsed)

        res = lookup_ptr(ip, timeout=timeout)
        row: Dict[str, Any] = {"ip": ip, "index": idx}
        if res.get("ok"):
            row["ptr"] = res["ptr"]
            row["aliases"] = res.get("aliases") or []
        elif res.get("no_ptr"):
            row["no_ptr"] = True
        else:
            row["error"] = res.get("error", "unknown")

        rows.append(row)
        last_at = time.monotonic()

        if on_progress:
            on_progress(row)
        elif show_progress and idx <= 30:
            if row.get("ptr"):
                print(msg(lang, "progress", done=idx, total=len(ips), ip=ip, ptr=row["ptr"]))
            elif row.get("no_ptr"):
                print(msg(lang, "progress_none", done=idx, total=len(ips), ip=ip))
            else:
                print(msg(lang, "progress_err", done=idx, total=len(ips), ip=ip, err=row.get("error")))

    summary = summarize_ptr_results(rows)
    return {
        "success": True,
        "format": PTR_FORMAT_V1,
        "start": start,
        "end": end,
        "max_ips": max_ips,
        "qps": qps,
        "timestamp": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "rows": rows,
        "summary": summary,
    }


def print_ptr_scan_report(
    session: Dict[str, Any],
    *,
    lang: str = "en",
    colors: Optional[Dict[str, str]] = None,
    table_limit: int = 40,
) -> None:
    c = colors or {}
    bold = c.get("bold", "")
    ok = c.get("ok", "")
    dim = c.get("dim", "")
    end = c.get("end", "")

    if not session.get("success"):
        print(f"{c.get('fail', '')}{session.get('error', 'PTR scan failed')}{end}")
        return

    summary = session.get("summary") or {}
    print(f"\n{bold}{msg(lang, 'title')}{end}")
    print(f"  {msg(lang, 'sum_scanned')}{summary.get('scanned', 0)}")
    print(f"  {msg(lang, 'sum_with_ptr')}{ok}{summary.get('with_ptr', 0)}{end}")
    print(f"  {msg(lang, 'sum_no_ptr')}{summary.get('no_ptr', 0)}")
    print(f"  {msg(lang, 'sum_errors')}{summary.get('errors', 0)}")
    print(f"  {msg(lang, 'unique_names')}{summary.get('unique_ptr_count', 0)}")

    top = summary.get("top_suffixes") or []
    if top:
        print(f"\n{msg(lang, 'top_suffixes')}")
        for suffix, count in top:
            print(msg(lang, "suffix_row", suffix=suffix, n=count))

    with_ptr_rows = [r for r in session.get("rows") or [] if r.get("ptr")]
    if with_ptr_rows:
        print(f"\n{msg(lang, 'table_title')}")
        shown = with_ptr_rows[:table_limit]
        for row in shown:
            print(msg(lang, "table_row", ip=row["ip"], ptr=row["ptr"]))
        if len(with_ptr_rows) > len(shown):
            print(f"{dim}{msg(lang, 'table_more', n=len(with_ptr_rows) - len(shown))}{end}")


def save_ptr_session(session: Dict[str, Any], path: Optional[Path] = None) -> Path:
    PTR_SESSIONS_DIR.mkdir(parents=True, exist_ok=True)
    if path is None:
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        path = PTR_SESSIONS_DIR / f"ptr_{session.get('start', 'x')}_{ts}.json"
    path = Path(path)
    path.write_text(json.dumps(session, indent=2, ensure_ascii=False), encoding="utf-8")
    return path
