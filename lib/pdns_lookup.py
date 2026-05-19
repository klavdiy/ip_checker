#!/usr/bin/env python3
"""
Passive / historical DNS and routing context for an IP address.

Sources (best-effort, no extra pip deps):
  - RIPE Stat ``dns-chain`` — current forward/reverse names (free)
  - RIPE Stat ``routing-history`` — BGP origin timelines for covering prefixes (free)
  - VirusTotal v3 ``/ip_addresses/{ip}/resolutions`` — historical hostnames (API key)
  - SecurityTrails ``/history/ip/{ip}/dns/a`` — historical A records (API key, optional)
"""

from __future__ import annotations

import ipaddress
import json
import os
import urllib.error
import urllib.request
from datetime import datetime, timezone
from typing import Any, Callable, Dict, List, Optional, Set

RIPESTAT_BASE = "https://stat.ripe.net/data"
VT_API = "https://www.virustotal.com/api/v3"
ST_API = "https://api.securitytrails.com/v1"

STRINGS: Dict[str, Dict[str, str]] = {
    "en": {
        "title": "Passive DNS / historical context",
        "fetching": "Querying passive DNS sources…",
        "no_data": "No passive DNS data returned.",
        "current_ptr": "Current reverse (RIPE dns-chain): ",
        "current_forward": "Current forward names: ",
        "routing_title": "BGP origin history (RIPE, prefixes covering this IP):",
        "routing_row": "  {asn} via {prefix}  {start} → {end}",
        "routing_more": "  … and {n} more timeline row(s)",
        "res_title": "Historical hostnames (passive DNS):",
        "res_row": "  {host}  last seen {date}  [{source}]",
        "res_more": "  … and {n} more hostname(s)",
        "vt_need_key": "VirusTotal: set API key in menu 7 or VIRUSTOTAL_API_KEY",
        "vt_error": "VirusTotal: ",
        "st_error": "SecurityTrails: ",
        "signal_multi_asn": "Multiple origin ASNs in routing history ({n}) — possible prefix re-homing",
        "signal_many_hosts": "{n} historical hostnames — high DNS churn / shared hosting",
        "signal_old_span": "Passive DNS span {years:.1f} years — IP role may have rotated",
        "signals_title": "Rotation / reuse signals:",
    },
    "ru": {
        "title": "Passive DNS / исторический контекст",
        "fetching": "Запрос passive DNS…",
        "no_data": "Passive DNS данные не получены.",
        "current_ptr": "Текущий reverse (RIPE dns-chain): ",
        "current_forward": "Текущие forward-имена: ",
        "routing_title": "История BGP origin (RIPE, префиксы с этим IP):",
        "routing_row": "  {asn} через {prefix}  {start} → {end}",
        "routing_more": "  … ещё {n} записей timeline",
        "res_title": "Исторические hostname (passive DNS):",
        "res_row": "  {host}  последний раз {date}  [{source}]",
        "res_more": "  … ещё {n} hostname(s)",
        "vt_need_key": "VirusTotal: укажите API key в меню 7 или VIRUSTOTAL_API_KEY",
        "vt_error": "VirusTotal: ",
        "st_error": "SecurityTrails: ",
        "signal_multi_asn": "Несколько origin ASN в routing-history ({n}) — возможна смена анонса",
        "signal_many_hosts": "{n} исторических hostname — высокая смена DNS / shared hosting",
        "signal_old_span": "Passive DNS за {years:.1f} лет — роль IP могла меняться",
        "signals_title": "Признаки ротации / переиспользования:",
    },
}


def msg(lang: str, key: str, **kwargs: Any) -> str:
    table = STRINGS.get(lang if lang in STRINGS else "en", STRINGS["en"])
    return table.get(key, key).format(**kwargs)


def _fetch_json(
    url: str,
    *,
    timeout: float = 15.0,
    headers: Optional[Dict[str, str]] = None,
) -> Dict[str, Any]:
    hdrs = {"User-Agent": "FNkit/1.0 (passive-dns)"}
    if headers:
        hdrs.update(headers)
    req = urllib.request.Request(url, headers=hdrs)
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read().decode("utf-8", errors="replace"))


def ripestat_dns_chain(ip: str, *, timeout: float = 12.0) -> Dict[str, Any]:
    url = f"{RIPESTAT_BASE}/dns-chain/data.json?resource={urllib.request.quote(ip)}"
    try:
        body = _fetch_json(url, timeout=timeout)
    except Exception as exc:
        return {"ok": False, "error": str(exc), "source": "ripestat-dns-chain"}
    if body.get("status") != "ok":
        return {"ok": False, "error": body.get("status_code"), "source": "ripestat-dns-chain"}
    data = body.get("data") or {}
    reverse = data.get("reverse_nodes") or {}
    ptr_names: List[str] = []
    if ip in reverse:
        ptr_names = list(reverse.get(ip) or [])
    elif reverse:
        for names in reverse.values():
            ptr_names.extend(names or [])
    forward: Set[str] = set()
    for names in (data.get("forward_nodes") or {}).values():
        for n in names or []:
            forward.add(str(n))
    return {
        "ok": True,
        "source": "ripestat-dns-chain",
        "ptr_names": sorted(set(ptr_names)),
        "forward_names": sorted(forward),
        "query_time": data.get("query_time"),
    }


def _routing_rows_for_ip(ip: str, by_origin: List[Dict[str, Any]], *, limit: int = 48) -> List[Dict[str, Any]]:
    try:
        ip_obj = ipaddress.ip_address(ip)
    except ValueError:
        return []
    rows: List[Dict[str, Any]] = []
    for block in by_origin or []:
        origin = block.get("origin")
        asn = f"AS{origin}" if origin is not None and str(origin).isdigit() else str(origin or "")
        for pref_entry in block.get("prefixes") or []:
            prefix = pref_entry.get("prefix")
            if not prefix:
                continue
            try:
                net = ipaddress.ip_network(str(prefix), strict=False)
            except ValueError:
                continue
            if ip_obj not in net:
                continue
            for tl in pref_entry.get("timelines") or []:
                rows.append(
                    {
                        "asn": asn,
                        "prefix": str(prefix),
                        "prefixlen": int(net.prefixlen),
                        "start": tl.get("starttime"),
                        "end": tl.get("endtime"),
                        "peers": tl.get("full_peers_seeing"),
                    }
                )
    rows.sort(key=lambda r: (-int(r.get("prefixlen") or 0), str(r.get("start") or "")))
    return rows[:limit]


def ripestat_routing_history(ip: str, *, timeout: float = 20.0) -> Dict[str, Any]:
    url = f"{RIPESTAT_BASE}/routing-history/data.json?resource={urllib.request.quote(ip)}"
    try:
        body = _fetch_json(url, timeout=timeout)
    except Exception as exc:
        return {"ok": False, "error": str(exc), "source": "ripestat-routing-history"}
    if body.get("status") != "ok":
        return {"ok": False, "error": body.get("status_code"), "source": "ripestat-routing-history"}
    data = body.get("data") or {}
    rows = _routing_rows_for_ip(ip, data.get("by_origin") or [])
    origins = sorted({r["asn"] for r in rows if r.get("asn")})
    return {
        "ok": True,
        "source": "ripestat-routing-history",
        "routing_origins": rows,
        "unique_origin_asns": origins,
        "query_start": data.get("query_starttime"),
        "query_end": data.get("query_endtime"),
    }


def virustotal_resolutions(
    ip: str,
    api_key: str,
    *,
    limit: int = 40,
    timeout: float = 20.0,
) -> Dict[str, Any]:
    key = (api_key or "").strip()
    if not key:
        return {"ok": False, "skipped": True, "reason": "no_api_key", "source": "virustotal"}
    url = f"{VT_API}/ip_addresses/{urllib.request.quote(ip)}/resolutions?limit={min(limit, 40)}"
    try:
        body = _fetch_json(url, timeout=timeout, headers={"x-apikey": key, "Accept": "application/json"})
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode("utf-8", errors="replace")[:200]
        return {"ok": False, "error": f"HTTP {exc.code}: {detail}", "source": "virustotal"}
    except Exception as exc:
        return {"ok": False, "error": str(exc), "source": "virustotal"}
    out: List[Dict[str, Any]] = []
    for item in body.get("data") or []:
        attrs = item.get("attributes") or {}
        host = (attrs.get("host_name") or "").strip().lower()
        if not host:
            continue
        ts = attrs.get("date")
        seen = None
        if isinstance(ts, (int, float)) and ts > 0:
            seen = datetime.fromtimestamp(int(ts), tz=timezone.utc).strftime("%Y-%m-%d")
        out.append({"hostname": host, "last_seen": seen, "source": "virustotal"})
    return {
        "ok": True,
        "source": "virustotal",
        "resolutions": out,
        "total_meta": (body.get("meta") or {}).get("count"),
    }


def securitytrails_ip_history(
    ip: str,
    api_key: str,
    *,
    timeout: float = 15.0,
) -> Dict[str, Any]:
    key = (api_key or "").strip()
    if not key:
        return {"ok": False, "skipped": True, "reason": "no_api_key", "source": "securitytrails"}
    url = f"{ST_API}/history/ip/{urllib.request.quote(ip)}/dns/a"
    try:
        body = _fetch_json(url, timeout=timeout, headers={"APIKEY": key, "Accept": "application/json"})
    except urllib.error.HTTPError as exc:
        if exc.code == 404:
            return {"ok": True, "source": "securitytrails", "resolutions": []}
        detail = exc.read().decode("utf-8", errors="replace")[:200]
        return {"ok": False, "error": f"HTTP {exc.code}: {detail}", "source": "securitytrails"}
    except Exception as exc:
        return {"ok": False, "error": str(exc), "source": "securitytrails"}
    out: List[Dict[str, Any]] = []
    for rec in body.get("records") or []:
        values = rec.get("values") or []
        host = (values[0] if values else rec.get("hostname") or "").strip().lower()
        if not host or host == ip:
            continue
        first = rec.get("first_seen")
        last = rec.get("last_seen")
        out.append(
            {
                "hostname": host,
                "first_seen": first,
                "last_seen": last,
                "source": "securitytrails",
            }
        )
    return {"ok": True, "source": "securitytrails", "resolutions": out}


def _merge_resolutions(parts: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    by_host: Dict[str, Dict[str, Any]] = {}
    for block in parts:
        for row in block.get("resolutions") or []:
            host = (row.get("hostname") or "").lower()
            if not host:
                continue
            prev = by_host.get(host)
            if not prev:
                by_host[host] = dict(row)
                continue
            sources = {prev.get("source"), row.get("source")} - {None}
            prev["source"] = "+".join(sorted(sources))
            if row.get("last_seen") and (not prev.get("last_seen") or row["last_seen"] > prev["last_seen"]):
                prev["last_seen"] = row["last_seen"]
    merged = list(by_host.values())
    merged.sort(key=lambda r: (r.get("last_seen") or "", r.get("hostname") or ""), reverse=True)
    return merged


def analyze_rotation_signals(report: Dict[str, Any], *, lang: str = "en") -> List[str]:
    signals: List[str] = []
    origins = report.get("unique_origin_asns") or []
    if len(origins) > 1:
        signals.append(msg(lang, "signal_multi_asn", n=len(origins)))
    resolutions = report.get("resolutions") or []
    if len(resolutions) >= 8:
        signals.append(msg(lang, "signal_many_hosts", n=len(resolutions)))
    years: List[float] = []
    for row in resolutions:
        for key in ("last_seen", "first_seen"):
            raw = row.get(key)
            if not raw:
                continue
            try:
                dt = datetime.strptime(str(raw)[:10], "%Y-%m-%d").replace(tzinfo=timezone.utc)
                years.append(dt.timestamp())
            except ValueError:
                continue
    if len(years) >= 2:
        span = (max(years) - min(years)) / (365.25 * 86400)
        if span >= 2.0 and len(resolutions) >= 3:
            signals.append(msg(lang, "signal_old_span", years=span))
    return signals


def lookup_passive_dns(
    ip: str,
    *,
    virustotal_api_key: Optional[str] = None,
    securitytrails_api_key: Optional[str] = None,
    include_ripe: bool = True,
    timeout: float = 15.0,
    lang: str = "en",
) -> Dict[str, Any]:
    """Aggregate passive DNS / routing history for an IP."""
    try:
        ipaddress.ip_address(ip)
    except ValueError:
        return {"success": False, "ip": ip, "error": "invalid IP"}

    sources: Dict[str, Any] = {}
    resolution_parts: List[Dict[str, Any]] = []

    if include_ripe:
        sources["ripe_dns_chain"] = ripestat_dns_chain(ip, timeout=timeout)
        sources["ripe_routing_history"] = ripestat_routing_history(ip, timeout=max(timeout, 18.0))

    vt_key = (virustotal_api_key or os.getenv("VIRUSTOTAL_API_KEY") or "").strip()
    vt = virustotal_resolutions(ip, vt_key, timeout=timeout)
    sources["virustotal"] = vt
    if vt.get("ok"):
        resolution_parts.append(vt)

    st_key = (securitytrails_api_key or os.getenv("SECURITYTRAILS_API_KEY") or "").strip()
    st = securitytrails_ip_history(ip, st_key, timeout=timeout)
    sources["securitytrails"] = st
    if st.get("ok") and st.get("resolutions"):
        resolution_parts.append(st)

    merged = _merge_resolutions(resolution_parts)
    rh = sources.get("ripe_routing_history") or {}
    routing_rows = rh.get("routing_origins") or []
    unique_asns = rh.get("unique_origin_asns") or sorted({r.get("asn") for r in routing_rows if r.get("asn")})

    report: Dict[str, Any] = {
        "success": True,
        "ip": ip,
        "sources": sources,
        "resolutions": merged,
        "routing_origins": routing_rows,
        "unique_origin_asns": unique_asns,
        "ptr_names": (sources.get("ripe_dns_chain") or {}).get("ptr_names") or [],
        "forward_names": (sources.get("ripe_dns_chain") or {}).get("forward_names") or [],
    }
    report["rotation_signals"] = analyze_rotation_signals(report, lang=lang if lang in STRINGS else "en")
    return report


def print_pdns_report(
    report: Dict[str, Any],
    *,
    lang: str = "en",
    print_fn: Optional[Callable[[str], None]] = None,
    colors: Optional[Dict[str, str]] = None,
) -> Dict[str, Any]:
    """Print passive DNS summary; returns the same report dict."""
    out = print_fn or print
    c = colors or {}
    bold = c.get("bold", "")
    ok = c.get("ok", "")
    warn = c.get("warn", "")
    fail = c.get("fail", "")
    end = c.get("end", "")

    if not report.get("success"):
        out(f"{warn}{msg(lang, 'no_data')} {report.get('error', '')}{end}")
        return report

    out(f"\n{bold}{msg(lang, 'title')}{end}")

    ptr = report.get("ptr_names") or []
    fwd = report.get("forward_names") or []
    if ptr:
        out(f"  {msg(lang, 'current_ptr')}{ok}{', '.join(ptr[:8])}{end}")
    if fwd:
        out(f"  {msg(lang, 'current_forward')}{', '.join(fwd[:8])}")

    signals = report.get("rotation_signals") or []
    if signals:
        out(f"\n{warn}{msg(lang, 'signals_title')}{end}")
        for s in signals:
            out(f"  {warn}• {s}{end}")

    routing = report.get("routing_origins") or []
    if routing:
        out(f"\n{msg(lang, 'routing_title')}")
        shown = routing[:12]
        for row in shown:
            out(
                msg(
                    lang,
                    "routing_row",
                    asn=row.get("asn", "?"),
                    prefix=row.get("prefix", "?"),
                    start=(row.get("start") or "?")[:10],
                    end=(row.get("end") or "?")[:10],
                )
            )
        if len(routing) > len(shown):
            out(msg(lang, "routing_more", n=len(routing) - len(shown)))

    resolutions = report.get("resolutions") or []
    if resolutions:
        out(f"\n{msg(lang, 'res_title')}")
        shown_r = resolutions[:20]
        for row in shown_r:
            out(
                msg(
                    lang,
                    "res_row",
                    host=row.get("hostname", "?"),
                    date=row.get("last_seen") or row.get("first_seen") or "?",
                    source=row.get("source", "?"),
                )
            )
        if len(resolutions) > len(shown_r):
            out(msg(lang, "res_more", n=len(resolutions) - len(shown_r)))

    vt = (report.get("sources") or {}).get("virustotal") or {}
    if vt.get("skipped"):
        out(f"\n{warn}{msg(lang, 'vt_need_key')}{end}")
    elif not vt.get("ok") and vt.get("error"):
        out(f"{warn}{msg(lang, 'vt_error')}{vt['error']}{end}")

    st = (report.get("sources") or {}).get("securitytrails") or {}
    if st.get("error") and not st.get("skipped"):
        out(f"{warn}{msg(lang, 'st_error')}{st['error']}{end}")

    if not routing and not resolutions and not ptr and not fwd:
        out(f"  {warn}{msg(lang, 'no_data')}{end}")

    return report
