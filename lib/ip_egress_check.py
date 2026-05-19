#!/usr/bin/env python3
"""
Egress / NAT context: Tor exit, VPN-proxy, datacenter, mobile, bogon.

Sources (stdlib only):
  - ip-api.com ``proxy``, ``hosting``, ``mobile`` (merged into geo fetch in fnkit)
  - Tor Project bulk exit list (cached locally)
  - ipinfo.io ``bogon`` (optional, free tier)
  - ASN/org name heuristics (ISP vs hosting keywords)
"""

from __future__ import annotations

import json
import os
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Set, Tuple

from paths import TOR_CACHE_DIR
TOR_CACHE_FILE = TOR_CACHE_DIR / "tor_exit_nodes.txt"
TOR_CACHE_MAX_AGE_SEC = 6 * 3600
TOR_EXIT_URL = "https://check.torproject.org/torbulkexitlist"

HOSTING_KEYWORDS = (
    "hosting",
    "datacenter",
    "data center",
    "data centre",
    " cloud",
    "cloud ",
    "vps",
    "dedicated",
    "server",
    "amazon",
    " aws",
    "google cloud",
    "gcp",
    "azure",
    "digitalocean",
    "linode",
    "vultr",
    "ovh",
    "hetzner",
    "cloudflare",
    "akamai",
    "fastly",
    "cdn",
    "colocation",
    " colo",
    "equinix",
    "rackspace",
    "leaseweb",
    "choopa",
    "m247",
    "psychz",
)

ISP_KEYWORDS = (
    "telecom",
    "communications",
    "communication",
    "broadband",
    " cable ",
    "fiber",
    "fibre",
    "wireless",
    " mobile ",
    "cellular",
    " isp",
    "internet service",
    "pty ltd",
    "inc.",
    " gmbh",
)

STRINGS: Dict[str, Dict[str, str]] = {
    "en": {
        "title": "Egress / NAT context",
        "verdict_clean": "Likely clean egress (no Tor / proxy / datacenter flags)",
        "verdict_tor": "Tor exit node — not a clean residential egress",
        "verdict_proxy": "Proxy / VPN / anonymizer detected (ip-api)",
        "verdict_hosting": "Hosting / datacenter (ip-api)",
        "verdict_mobile": "Mobile cellular connection",
        "verdict_bogon": "Bogon / non-routable (ipinfo)",
        "verdict_as_hosting": "Likely datacenter ASN (name heuristic)",
        "verdict_isp": "Likely ISP / residential (heuristic, no proxy/hosting flags)",
        "row_tor": "Tor exit: ",
        "row_proxy": "ip-api proxy/VPN/Tor: ",
        "row_hosting": "ip-api hosting/datacenter: ",
        "row_mobile": "ip-api mobile: ",
        "row_bogon": "ipinfo bogon: ",
        "row_as_type": "ASN type (heuristic): ",
        "yes": "yes",
        "no": "no",
        "tor_cache": "Tor exit list: {n} nodes (cached)",
        "tor_fetch": "Downloading Tor exit list…",
        "ipinfo_skip": "ipinfo bogon: skipped (set IPINFO_TOKEN for higher limits)",
        "ipinfo_err": "ipinfo: ",
    },
    "ru": {
        "title": "Контекст egress / NAT",
        "verdict_clean": "Вероятно «чистый» egress (нет Tor / proxy / datacenter)",
        "verdict_tor": "Tor exit — не residential egress",
        "verdict_proxy": "Обнаружен proxy / VPN / anonymizer (ip-api)",
        "verdict_hosting": "Hosting / datacenter (ip-api)",
        "verdict_mobile": "Мобильная сеть (cellular)",
        "verdict_bogon": "Bogon / нерoutable (ipinfo)",
        "verdict_as_hosting": "Вероятно datacenter ASN (эвристика по имени)",
        "verdict_isp": "Вероятно ISP / residential (эвристика, без proxy/hosting)",
        "row_tor": "Tor exit: ",
        "row_proxy": "ip-api proxy/VPN/Tor: ",
        "row_hosting": "ip-api hosting/datacenter: ",
        "row_mobile": "ip-api mobile: ",
        "row_bogon": "ipinfo bogon: ",
        "row_as_type": "Тип ASN (эвристика): ",
        "yes": "да",
        "no": "нет",
        "tor_cache": "Список Tor exit: {n} узлов (кэш)",
        "tor_fetch": "Загрузка списка Tor exit…",
        "ipinfo_skip": "ipinfo bogon: пропуск (для лимитов задайте IPINFO_TOKEN)",
        "ipinfo_err": "ipinfo: ",
    },
}


def msg(lang: str, key: str, **kwargs: Any) -> str:
    table = STRINGS.get(lang if lang in STRINGS else "en", STRINGS["en"])
    return table.get(key, key).format(**kwargs)


def _fetch_text(url: str, *, timeout: float = 25.0, headers: Optional[Dict[str, str]] = None) -> str:
    hdrs = {"User-Agent": "FNkit/1.0 (egress-check)"}
    if headers:
        hdrs.update(headers)
    req = urllib.request.Request(url, headers=hdrs)
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return resp.read().decode("utf-8", errors="replace")


def _download_tor_exit_set(*, force_refresh: bool = False) -> Set[str]:
    TOR_CACHE_DIR.mkdir(parents=True, exist_ok=True)
    if not force_refresh and TOR_CACHE_FILE.is_file():
        age = time.time() - TOR_CACHE_FILE.stat().st_mtime
        if age < TOR_CACHE_MAX_AGE_SEC:
            text = TOR_CACHE_FILE.read_text(encoding="utf-8", errors="replace")
            return {ln.strip() for ln in text.splitlines() if ln.strip()}

    raw = _fetch_text(TOR_EXIT_URL, timeout=45.0)
    TOR_CACHE_FILE.write_text(raw, encoding="utf-8")
    return {ln.strip() for ln in raw.splitlines() if ln.strip()}


def check_tor_exit(ip: str, *, tor_set: Optional[Set[str]] = None) -> Dict[str, Any]:
    try:
        exits = tor_set if tor_set is not None else _download_tor_exit_set()
        return {
            "ok": True,
            "is_tor_exit": ip in exits,
            "source": "torproject-bulk-exitlist",
            "list_size": len(exits),
        }
    except Exception as exc:
        return {"ok": False, "error": str(exc), "is_tor_exit": False, "source": "torproject-bulk-exitlist"}


def check_ipinfo_bogon(ip: str, *, token: Optional[str] = None, timeout: float = 8.0) -> Dict[str, Any]:
    url = f"https://ipinfo.io/{urllib.request.quote(ip)}/json"
    tok = (token or os.getenv("IPINFO_TOKEN") or "").strip()
    headers: Dict[str, str] = {}
    if tok:
        headers["Authorization"] = f"Bearer {tok}"
    try:
        body = json.loads(_fetch_text(url, timeout=timeout, headers=headers or None))
        return {
            "ok": True,
            "bogon": bool(body.get("bogon")),
            "org": body.get("org"),
            "hostname": body.get("hostname"),
            "source": "ipinfo.io",
        }
    except Exception as exc:
        return {"ok": False, "error": str(exc), "bogon": None, "source": "ipinfo.io"}


def infer_as_name_type(isp: Optional[str], org: Optional[str], asn: Optional[str]) -> str:
    """Return ``hosting``, ``isp``, or ``unknown`` from organization strings."""
    blob = " ".join(filter(None, [isp, org, asn])).lower()
    if not blob.strip():
        return "unknown"
    for kw in HOSTING_KEYWORDS:
        if kw in blob:
            return "hosting"
    for kw in ISP_KEYWORDS:
        if kw in blob:
            return "isp"
    return "unknown"


def classify_egress(report: Dict[str, Any], *, lang: str = "en") -> Tuple[str, str]:
    """Return (category_id, human verdict) — order matters (most specific first)."""
    if report.get("bogon"):
        return "bogon", msg(lang, "verdict_bogon")
    if report.get("tor_exit"):
        return "tor", msg(lang, "verdict_tor")
    if report.get("proxy"):
        return "proxy_vpn", msg(lang, "verdict_proxy")
    if report.get("hosting"):
        return "datacenter", msg(lang, "verdict_hosting")
    if report.get("mobile"):
        return "mobile", msg(lang, "verdict_mobile")
    if report.get("as_type_heuristic") == "hosting":
        return "datacenter_heuristic", msg(lang, "verdict_as_hosting")
    if report.get("as_type_heuristic") == "isp":
        return "isp", msg(lang, "verdict_isp")
    return "clean", msg(lang, "verdict_clean")


def lookup_egress_context(
    ip: str,
    geo_data: Optional[Dict[str, Any]] = None,
    *,
    check_tor: bool = True,
    check_ipinfo: bool = True,
    tor_set: Optional[Set[str]] = None,
    lang: str = "en",
) -> Dict[str, Any]:
    """Build egress/NAT context using geo_data (ip-api) plus Tor and ipinfo."""
    geo = geo_data or {}
    proxy = bool(geo.get("proxy"))
    hosting = bool(geo.get("hosting"))
    mobile = bool(geo.get("mobile"))

    as_type = infer_as_name_type(geo.get("isp"), geo.get("org"), geo.get("asn"))

    tor_exit = False
    tor_block: Dict[str, Any] = {"ok": False, "skipped": True}
    if check_tor:
        tor_block = check_tor_exit(ip, tor_set=tor_set)
        tor_exit = bool(tor_block.get("is_tor_exit"))

    bogon = None
    ipinfo_block: Dict[str, Any] = {"ok": False, "skipped": not check_ipinfo}
    if check_ipinfo:
        ipinfo_block = check_ipinfo_bogon(ip)
        if ipinfo_block.get("ok"):
            bogon = bool(ipinfo_block.get("bogon"))

    report: Dict[str, Any] = {
        "success": True,
        "ip": ip,
        "proxy": proxy,
        "hosting": hosting,
        "mobile": mobile,
        "tor_exit": tor_exit,
        "bogon": bogon,
        "as_type_heuristic": as_type,
        "sources": {
            "ip_api": {
                "proxy": proxy,
                "hosting": hosting,
                "mobile": mobile,
            },
            "tor": tor_block,
            "ipinfo": ipinfo_block,
        },
        "is_clean_egress": not (tor_exit or proxy or hosting or bogon),
    }
    cat, verdict = classify_egress(report, lang=lang)
    report["category"] = cat
    report["verdict"] = verdict
    return report


def print_egress_report(
    report: Dict[str, Any],
    *,
    lang: str = "en",
    colors: Optional[Dict[str, str]] = None,
    verbose_tor_cache: bool = False,
) -> Dict[str, Any]:
    c = colors or {}
    bold, ok, warn, fail, end = (
        c.get("bold", ""),
        c.get("ok", ""),
        c.get("warn", ""),
        c.get("fail", ""),
        c.get("end", ""),
    )
    yn = lambda v: msg(lang, "yes") if v else msg(lang, "no")

    if not report.get("success"):
        print(f"{warn}{report.get('error', 'egress check failed')}{end}")
        return report

    print(f"\n{bold}{msg(lang, 'title')}{end}")

    cat = report.get("category", "")
    verdict = report.get("verdict", "")
    if report.get("is_clean_egress"):
        print(f"  {ok}{verdict}{end}")
    elif cat in ("tor", "proxy_vpn", "bogon"):
        print(f"  {fail}{verdict}{end}")
    else:
        print(f"  {warn}{verdict}{end}")

    print(f"  {msg(lang, 'row_tor')}{fail if report.get('tor_exit') else ok}{yn(report.get('tor_exit'))}{end}")
    print(f"  {msg(lang, 'row_proxy')}{warn if report.get('proxy') else ok}{yn(report.get('proxy'))}{end}")
    print(f"  {msg(lang, 'row_hosting')}{warn if report.get('hosting') else ok}{yn(report.get('hosting'))}{end}")
    print(f"  {msg(lang, 'row_mobile')}{yn(report.get('mobile'))}")
    if report.get("bogon") is not None:
        print(f"  {msg(lang, 'row_bogon')}{fail if report.get('bogon') else ok}{yn(report.get('bogon'))}{end}")
    print(f"  {msg(lang, 'row_as_type')}{report.get('as_type_heuristic', 'unknown')}")

    tor_src = (report.get("sources") or {}).get("tor") or {}
    if verbose_tor_cache and tor_src.get("list_size"):
        print(f"  {msg(lang, 'tor_cache', n=tor_src['list_size'])}")

    ipinfo_src = (report.get("sources") or {}).get("ipinfo") or {}
    if ipinfo_src.get("skipped"):
        pass
    elif not ipinfo_src.get("ok") and ipinfo_src.get("error"):
        print(f"  {warn}{msg(lang, 'ipinfo_err')}{ipinfo_src['error']}{end}")

    return report
