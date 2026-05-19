#!/usr/bin/env python3
"""
DNS-analysis: graph, subdomains, HTML, PCAP→DNS

Phases:
  1 — BFS over A/AAAA/CNAME/MX/NS/TXT/SOA, JSON sessions, TTY summary
  2 — optional IP geo enrichment, wordlist subdomains, rate limits, graph metrics
  3 — HTML graph export, multi-resolver compare, passive subdomains (crt.sh)
  4 — extract DNS names from PCAP via tshark (optional)
"""

from __future__ import annotations

import ipaddress
import json
import re
import shutil
import subprocess
import time
import urllib.error
import urllib.request
from collections import deque
from datetime import datetime, timezone
from html import escape
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Set, Tuple

try:
    import dns.exception
    import dns.name
    import dns.rdata
    import dns.resolver
    import dns.reversename

    HAS_DNSPYTHON = True
except ImportError:
    HAS_DNSPYTHON = False

from paths import DNS_GRAPH_DIR, DNS_SESSIONS_DIR
DNS_FORMAT_V1 = "fnkit_dns_v1"
LEGACY_DNS_FORMAT_V1 = "ip_checker_dns_v1"

C_RESET = "\033[0m"
C_BOLD = "\033[1m"
C_CYAN = "\033[96m"
C_GREEN = "\033[92m"
C_WARN = "\033[93m"
C_FAIL = "\033[91m"
C_DIM = "\033[2m"

STRINGS: Dict[str, Dict[str, str]] = {
    "en": {
        "need_dnspython": "dnspython is required: pip install dnspython",
        "invalid_domain": "Invalid domain name: {name}",
        "crawl_start": "DNS crawl from seed: {seed}",
        "crawl_done": "Crawl finished: {domains} domains, {ips} IPs, {edges} edges (depth ≤ {depth})",
        "crawl_limit": "Stopped: domain limit ({n}) reached.",
        "table_title": "DNS graph summary",
        "col_name": "Name",
        "col_type": "Type",
        "col_depth": "Depth",
        "col_records": "Records",
        "save_ok": "Session saved: {path}",
        "save_fail": "Save failed: {err}",
        "load_fail": "Cannot load session: {err}",
        "metrics_title": "Graph metrics",
        "metric_shared_ip": "Domains sharing an IP (top groups):",
        "metric_cname_loops": "CNAME loops detected: {n}",
        "metric_max_depth": "Max BFS depth: {n}",
        "metric_external_ns": "External NS hosts: {n}",
        "metric_resolver_conflicts": "Resolver answer conflicts: {n}",
        "wordlist_start": "Wordlist scan ({count} labels)…",
        "wordlist_hit": "  + {fqdn}",
        "crt_fetch": "Fetching passive subdomains (crt.sh)…",
        "crt_found": "crt.sh: {n} unique names",
        "html_ok": "HTML graph written: {path}",
        "html_fail": "HTML export failed: {err}",
        "pcap_no_tshark": "tshark not found — install Wireshark CLI for PCAP DNS extract.",
        "pcap_extract": "PCAP DNS names: {n} (seed queue expanded)",
        "menu_title": "DNS analysis",
        "menu_1": "1. Crawl domain (build graph)",
        "menu_2": "2. Open saved session (summary + metrics)",
        "menu_3": "3. Export session to HTML graph",
        "menu_4": "4. Compare resolvers (system vs public)",
        "menu_5": "5. Build graph from PCAP (tshark DNS fields)",
        "menu_0": "0. Back",
        "menu_prompt": "Select (0-5): ",
        "prompt_pcap": "Path to .pcap file: ",
        "prompt_domain": "Domain (e.g. example.com): ",
        "prompt_session": "Session file path or number from list (0 cancel): ",
        "prompt_wordlist": "Wordlist path (Enter = skip): ",
        "prompt_crt": "Also query crt.sh passive subdomains? (y/n) [n]: ",
        "empty_sessions": "(No JSON in data/sessions/dns/ yet.)",
        "file_not_found": "File not found: {path}",
    },
    "ru": {
        "need_dnspython": "Нужен dnspython: pip install dnspython",
        "invalid_domain": "Неверное имя домена: {name}",
        "crawl_start": "Обход DNS от seed: {seed}",
        "crawl_done": "Готово: {domains} доменов, {ips} IP, {edges} рёбер (глубина ≤ {depth})",
        "crawl_limit": "Остановка: лимит доменов ({n}).",
        "table_title": "Сводка DNS-графа",
        "col_name": "Имя",
        "col_type": "Тип",
        "col_depth": "Глубина",
        "col_records": "Записи",
        "save_ok": "Сессия сохранена: {path}",
        "save_fail": "Ошибка сохранения: {err}",
        "load_fail": "Не удалось загрузить сессию: {err}",
        "metrics_title": "Метрики графа",
        "metric_shared_ip": "Домены на одном IP (топ групп):",
        "metric_cname_loops": "Циклы CNAME: {n}",
        "metric_max_depth": "Макс. глубина BFS: {n}",
        "metric_external_ns": "Внешние NS-хосты: {n}",
        "metric_resolver_conflicts": "Конфликты резолверов: {n}",
        "wordlist_start": "Перебор wordlist ({count} меток)…",
        "wordlist_hit": "  + {fqdn}",
        "crt_fetch": "Пассивные поддомены (crt.sh)…",
        "crt_found": "crt.sh: {n} уникальных имён",
        "html_ok": "HTML-граф записан: {path}",
        "html_fail": "Ошибка HTML: {err}",
        "pcap_no_tshark": "tshark не найден — установите Wireshark CLI для DNS из PCAP.",
        "pcap_extract": "Имена из PCAP: {n} (добавлены в очередь)",
        "menu_title": "DNS-анализ",
        "menu_1": "1. Обход домена (построить граф)",
        "menu_2": "2. Открыть сохранённую сессию",
        "menu_3": "3. Экспорт сессии в HTML-граф",
        "menu_4": "4. Сравнить резолверы (системный vs публичный)",
        "menu_5": "5. Граф из PCAP (поля DNS через tshark)",
        "menu_0": "0. Назад",
        "menu_prompt": "Выберите (0-5): ",
        "prompt_pcap": "Путь к .pcap: ",
        "prompt_domain": "Домен (например example.com): ",
        "prompt_session": "Путь к JSON или номер из списка (0 отмена): ",
        "prompt_wordlist": "Путь к wordlist (Enter — пропустить): ",
        "prompt_crt": "Запросить поддомены на crt.sh? (y/n) [n]: ",
        "empty_sessions": "(В data/sessions/dns/ пока нет JSON.)",
        "file_not_found": "Файл не найден: {path}",
    },
}

RE_FQDN = re.compile(
    r"^(?=.{1,253}$)(?!-)([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)(?:\.(?!-)([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?))*$",
    re.IGNORECASE,
)


def msg(lang: str, key: str, **kwargs: Any) -> str:
    table = STRINGS.get(lang if lang in STRINGS else "en", STRINGS["en"])
    return table.get(key, key).format(**kwargs)


def ensure_dirs() -> None:
    DNS_SESSIONS_DIR.mkdir(parents=True, exist_ok=True)
    DNS_GRAPH_DIR.mkdir(parents=True, exist_ok=True)


def normalize_domain(raw: str) -> Optional[str]:
    s = (raw or "").strip().lower().rstrip(".")
    if not s or " " in s or "/" in s:
        return None
    if s.startswith("http://") or s.startswith("https://"):
        s = re.sub(r"^https?://", "", s).split("/")[0]
    if "@" in s:
        return None
    if not RE_FQDN.match(s):
        return None
    return s


def node_id_domain(fqdn: str) -> str:
    return f"domain:{fqdn.lower().rstrip('.')}"


def node_id_ip(addr: str) -> str:
    return f"ip:{addr}"


def default_session_path(seed: str) -> Path:
    safe = re.sub(r"[^a-z0-9.-]+", "_", seed.lower())[:80]
    ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    return DNS_SESSIONS_DIR / f"{safe}_{ts}.json"


def list_session_files() -> List[Path]:
    ensure_dirs()
    files = sorted(DNS_SESSIONS_DIR.glob("*.json"), key=lambda p: p.stat().st_mtime, reverse=True)
    return files


class DnsGraph:
    """Mutable DNS graph for one crawl session."""

    def __init__(self, seed: str) -> None:
        self.seed = seed
        self.nodes: Dict[str, Dict[str, Any]] = {}
        self.edges: List[Dict[str, Any]] = []
        self._edge_keys: Set[Tuple[str, str, str]] = set()

    def add_node(self, nid: str, ntype: str, label: str, **meta: Any) -> None:
        if nid not in self.nodes:
            self.nodes[nid] = {"id": nid, "type": ntype, "label": label, **meta}
        else:
            self.nodes[nid].update({k: v for k, v in meta.items() if v is not None})

    def add_edge(
        self,
        src: str,
        dst: str,
        rtype: str,
        *,
        ttl: Optional[int] = None,
        resolver: Optional[str] = None,
        extra: Optional[Dict[str, Any]] = None,
    ) -> None:
        key = (src, dst, rtype)
        if key in self._edge_keys:
            return
        self._edge_keys.add(key)
        e: Dict[str, Any] = {"from": src, "to": dst, "rtype": rtype}
        if ttl is not None:
            e["ttl"] = ttl
        if resolver:
            e["resolver"] = resolver
        if extra:
            e.update(extra)
        self.edges.append(e)

    def to_session_dict(
        self,
        *,
        stats: Optional[Dict[str, Any]] = None,
        resolver_conflicts: Optional[List[Dict[str, Any]]] = None,
        passive_names: Optional[List[str]] = None,
    ) -> Dict[str, Any]:
        return {
            "format": DNS_FORMAT_V1,
            "created_at": datetime.now(timezone.utc).isoformat(),
            "seed": self.seed,
            "nodes": list(self.nodes.values()),
            "edges": self.edges,
            "stats": stats or {},
            "resolver_conflicts": resolver_conflicts or [],
            "passive_subdomains": passive_names or [],
        }


def _require_dnspython(lang: str) -> bool:
    if HAS_DNSPYTHON:
        return True
    print(f"{C_FAIL}{msg(lang, 'need_dnspython')}{C_RESET}")
    return False


def make_resolver(nameserver: Optional[str] = None, timeout: float = 5.0) -> "dns.resolver.Resolver":
    res = dns.resolver.Resolver(configure=(nameserver is None))
    if nameserver:
        res.nameservers = [nameserver]
    res.lifetime = timeout
    return res


def _fqdn_from_rdata(target: Any, origin: str) -> str:
    try:
        name = target.to_text().rstrip(".")
    except Exception:
        name = str(target).rstrip(".")
    if name.endswith("."):
        name = name[:-1]
    origin_name = origin.lower().rstrip(".")
    if not name or name == "@":
        return origin_name
    if "." not in name and origin_name:
        return f"{name}.{origin_name}".lower()
    return name.lower()


def query_domain_records(
    fqdn: str,
    resolver: "dns.resolver.Resolver",
    *,
    lang: str = "en",
) -> Dict[str, List[Any]]:
    """Return rtype -> list of string values for display/storage."""
    out: Dict[str, List[Any]] = {}
    for rtype in ("A", "AAAA", "CNAME", "MX", "NS", "TXT", "SOA"):
        try:
            ans = resolver.resolve(fqdn, rtype)
            rows: List[Any] = []
            for rdata in ans:
                if rtype == "MX":
                    rows.append({"priority": rdata.preference, "host": _fqdn_from_rdata(rdata.exchange, fqdn)})
                elif rtype == "SOA":
                    rows.append(
                        {
                            "mname": _fqdn_from_rdata(rdata.mname, fqdn),
                            "rname": str(rdata.rname).rstrip("."),
                            "serial": rdata.serial,
                        }
                    )
                elif rtype == "TXT":
                    txt = rdata.to_text().strip('"')
                    if len(txt) > 200:
                        txt = txt[:200] + "…"
                    rows.append(txt)
                elif rtype == "CNAME":
                    rows.append(_fqdn_from_rdata(rdata.target, fqdn))
                elif rtype == "NS":
                    rows.append(_fqdn_from_rdata(rdata.target, fqdn))
                elif rtype in ("A", "AAAA"):
                    rows.append(str(rdata))
                else:
                    rows.append(rdata.to_text())
            if rows:
                out[rtype] = rows
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers):
            continue
        except dns.exception.Timeout:
            continue
        except Exception:
            continue
    return out


def expand_queue_from_records(
    fqdn: str,
    records: Dict[str, List[Any]],
    graph: DnsGraph,
    *,
    depth: int,
    resolver_label: str,
    seed_zone: str,
) -> List[str]:
    """Add nodes/edges; return new FQDNs to enqueue."""
    dom_id = node_id_domain(fqdn)
    graph.add_node(dom_id, "domain", fqdn, depth=depth, records=records)
    new_names: List[str] = []
    zone = seed_zone.lower().rstrip(".")

    for rtype, rows in records.items():
        for row in rows:
            if rtype in ("A", "AAAA"):
                ip = str(row)
                ip_id = node_id_ip(ip)
                graph.add_node(ip_id, "ip", ip)
                graph.add_edge(dom_id, ip_id, rtype, resolver=resolver_label)
            elif rtype == "CNAME":
                target = str(row).lower().rstrip(".")
                tid = node_id_domain(target)
                graph.add_node(tid, "domain", target, depth=depth + 1)
                graph.add_edge(dom_id, tid, "CNAME", resolver=resolver_label)
                new_names.append(target)
            elif rtype == "MX":
                if isinstance(row, dict):
                    host = str(row.get("host", "")).lower().rstrip(".")
                    pr = row.get("priority")
                else:
                    host = str(row).lower().rstrip(".")
                    pr = None
                if host:
                    hid = node_id_domain(host)
                    graph.add_node(hid, "domain", host, depth=depth + 1, role="mx")
                    extra = {"priority": pr} if pr is not None else None
                    graph.add_edge(dom_id, hid, "MX", extra=extra, resolver=resolver_label)
                    new_names.append(host)
            elif rtype == "NS":
                host = str(row).lower().rstrip(".")
                hid = node_id_domain(host)
                graph.add_node(hid, "domain", host, depth=depth + 1, role="ns")
                graph.add_edge(dom_id, hid, "NS", resolver=resolver_label)
                external = not (host == zone or host.endswith("." + zone))
                graph.nodes[hid]["external_ns"] = external
                new_names.append(host)

    return new_names


def detect_cname_loops(graph: DnsGraph) -> List[List[str]]:
    """Find cycles among domain nodes linked by CNAME edges."""
    adj: Dict[str, List[str]] = {}
    for e in graph.edges:
        if e.get("rtype") != "CNAME":
            continue
        adj.setdefault(e["from"], []).append(e["to"])

    loops: List[List[str]] = []
    visited: Set[str] = set()
    stack: Set[str] = set()
    path: List[str] = []

    def dfs(n: str) -> None:
        if n in stack:
            if n in path:
                i = path.index(n)
                loops.append(path[i:] + [n])
            return
        if n in visited:
            return
        visited.add(n)
        stack.add(n)
        path.append(n)
        for nxt in adj.get(n, []):
            dfs(nxt)
        path.pop()
        stack.remove(n)

    for start in adj:
        dfs(start)
    return loops


def compute_metrics(graph: DnsGraph, session: Dict[str, Any]) -> Dict[str, Any]:
    ip_to_domains: Dict[str, List[str]] = {}
    max_depth = 0
    external_ns = 0
    for nid, node in graph.nodes.items():
        if node.get("type") == "domain":
            d = int(node.get("depth") or 0)
            max_depth = max(max_depth, d)
            if node.get("external_ns"):
                external_ns += 1
        if node.get("type") == "ip":
            continue
    for e in graph.edges:
        if e.get("rtype") in ("A", "AAAA"):
            dom = e["from"]
            ip = e["to"]
            label = graph.nodes.get(dom, {}).get("label", dom)
            ip_to_domains.setdefault(ip, []).append(label)

    shared = {ip: names for ip, names in ip_to_domains.items() if len(names) > 1}
    shared_sorted = sorted(shared.items(), key=lambda x: -len(x[1]))[:15]
    loops = detect_cname_loops(graph)
    return {
        "domain_count": sum(1 for n in graph.nodes.values() if n.get("type") == "domain"),
        "ip_count": sum(1 for n in graph.nodes.values() if n.get("type") == "ip"),
        "edge_count": len(graph.edges),
        "max_depth": max_depth,
        "shared_ip_groups": [{"ip": ip, "domains": names} for ip, names in shared_sorted],
        "cname_loop_count": len(loops),
        "cname_loops": loops[:5],
        "external_ns_hosts": external_ns,
        "resolver_conflict_count": len(session.get("resolver_conflicts") or []),
    }


def apply_wordlist(
    seed: str,
    graph: DnsGraph,
    wordlist_path: Path,
    resolver: "dns.resolver.Resolver",
    *,
    max_queries: int = 500,
    qps: float = 20.0,
    lang: str = "en",
) -> int:
    if not wordlist_path.is_file():
        return 0
    labels: List[str] = []
    with open(wordlist_path, encoding="utf-8", errors="replace") as f:
        for line in f:
            lab = line.strip().split()[0] if line.strip() else ""
            if lab and re.match(r"^[a-z0-9][a-z0-9.-]*$", lab, re.I):
                labels.append(lab.lower())
    if not labels:
        return 0
    print(f"{C_CYAN}{msg(lang, 'wordlist_start', count=len(labels))}{C_RESET}")
    delay = 1.0 / max(qps, 0.1)
    hits = 0
    zone = seed.lower().rstrip(".")
    for i, lab in enumerate(labels):
        if i >= max_queries:
            break
        fqdn = f"{lab}.{zone}"
        if node_id_domain(fqdn) in graph.nodes:
            continue
        try:
            resolver.resolve(fqdn, "A")
            print(f"{C_GREEN}{msg(lang, 'wordlist_hit', fqdn=fqdn)}{C_RESET}")
            rec = query_domain_records(fqdn, resolver, lang=lang)
            expand_queue_from_records(fqdn, rec, graph, depth=1, resolver_label="wordlist", seed_zone=zone)
            hits += 1
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers):
            pass
        except Exception:
            pass
        time.sleep(delay)
    return hits


def fetch_crtsh_subdomains(domain: str, *, timeout: float = 15.0) -> List[str]:
    url = f"https://crt.sh/?q=%25.{domain}&output=json"
    req = urllib.request.Request(url, headers={"User-Agent": "fnkit-dns_diag/1.0"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            data = json.loads(resp.read().decode("utf-8", errors="replace"))
    except (urllib.error.URLError, json.JSONDecodeError, TimeoutError):
        return []
    names: Set[str] = set()
    if not isinstance(data, list):
        return []
    for row in data:
        if not isinstance(row, dict):
            continue
        val = row.get("name_value") or row.get("common_name") or ""
        for part in str(val).split("\n"):
            n = normalize_domain(part.strip())
            if n and (n == domain or n.endswith("." + domain)):
                names.add(n)
    return sorted(names)


def merge_passive_names(
    names: List[str],
    graph: DnsGraph,
    resolver: "dns.resolver.Resolver",
    *,
    seed: str,
    max_new: int = 100,
    lang: str = "en",
) -> None:
    zone = seed.lower().rstrip(".")
    added = 0
    for fqdn in names:
        if added >= max_new:
            break
        if node_id_domain(fqdn) in graph.nodes:
            continue
        rec = query_domain_records(fqdn, resolver, lang=lang)
        if not rec:
            continue
        expand_queue_from_records(fqdn, rec, graph, depth=1, resolver_label="passive", seed_zone=zone)
        added += 1


def compare_resolvers(fqdn: str, *, lang: str = "en") -> List[Dict[str, Any]]:
    """Compare A/AAAA sets: system resolver vs 1.1.1.1 vs 8.8.8.8."""
    if not _require_dnspython(lang):
        return []
    configs = [
        ("system", None),
        ("cloudflare", "1.1.1.1"),
        ("google", "8.8.8.8"),
    ]
    snapshots: Dict[str, Set[str]] = {}
    for label, ns in configs:
        res = make_resolver(ns)
        vals: Set[str] = set()
        for rtype in ("A", "AAAA"):
            try:
                ans = res.resolve(fqdn, rtype)
                for r in ans:
                    vals.add(str(r))
            except Exception:
                pass
        snapshots[label] = vals

    conflicts: List[Dict[str, Any]] = []
    keys = list(snapshots.keys())
    for i in range(len(keys)):
        for j in range(i + 1, len(keys)):
            a, b = keys[i], keys[j]
            if snapshots[a] != snapshots[b]:
                conflicts.append(
                    {
                        "domain": fqdn,
                        "resolver_a": a,
                        "resolver_b": b,
                        "answers_a": sorted(snapshots[a]),
                        "answers_b": sorted(snapshots[b]),
                    }
                )
    return conflicts


def crawl_dns(
    seed: str,
    *,
    max_depth: int = 4,
    max_domains: int = 500,
    nameserver: Optional[str] = None,
    wordlist: Optional[Path] = None,
    wordlist_max: int = 500,
    qps: float = 20.0,
    use_crtsh: bool = False,
    enrich_ip: Optional[Callable[[str, Dict[str, Any]], None]] = None,
    lang: str = "en",
    verbose: bool = True,
) -> Dict[str, Any]:
    if not _require_dnspython(lang):
        return {}
    seed_norm = normalize_domain(seed)
    if not seed_norm:
        if verbose:
            print(f"{C_FAIL}{msg(lang, 'invalid_domain', name=seed)}{C_RESET}")
        return {}

    ensure_dirs()
    resolver = make_resolver(nameserver)
    resolver_label = nameserver or "system"
    graph = DnsGraph(seed_norm)
    queue: deque[Tuple[str, int]] = deque([(seed_norm, 0)])
    seen: Set[str] = {seed_norm}
    delay = 1.0 / max(qps, 0.1)

    if verbose:
        print(f"\n{C_CYAN}{msg(lang, 'crawl_start', seed=seed_norm)}{C_RESET}")

    while queue:
        fqdn, depth = queue.popleft()
        if depth > max_depth:
            continue
        if sum(1 for n in graph.nodes.values() if n.get("type") == "domain") >= max_domains:
            if verbose:
                print(f"{C_WARN}{msg(lang, 'crawl_limit', n=max_domains)}{C_RESET}")
            break

        records = query_domain_records(fqdn, resolver, lang=lang)
        new_names = expand_queue_from_records(
            fqdn, records, graph, depth=depth, resolver_label=resolver_label, seed_zone=seed_norm
        )

        if enrich_ip:
            for rtype in ("A", "AAAA"):
                for ip in records.get(rtype, []):
                    ip_id = node_id_ip(str(ip))
                    if ip_id in graph.nodes:
                        enrich_ip(str(ip), graph.nodes[ip_id])

        for name in new_names:
            if name not in seen and depth + 1 <= max_depth:
                seen.add(name)
                queue.append((name, depth + 1))
        time.sleep(delay)

    passive: List[str] = []
    if use_crtsh:
        if verbose:
            print(f"{C_CYAN}{msg(lang, 'crt_fetch')}{C_RESET}")
        passive = fetch_crtsh_subdomains(seed_norm)
        if verbose:
            print(f"{C_GREEN}{msg(lang, 'crt_found', n=len(passive))}{C_RESET}")
        merge_passive_names(passive, graph, resolver, seed=seed_norm, lang=lang)

    if wordlist and wordlist.is_file():
        apply_wordlist(seed_norm, graph, wordlist, resolver, max_queries=wordlist_max, qps=qps, lang=lang)

    # Synthetic same-ip edges between domains
    ip_domains: Dict[str, List[str]] = {}
    for e in graph.edges:
        if e.get("rtype") in ("A", "AAAA"):
            ip_domains.setdefault(e["to"], []).append(e["from"])
    for ip_id, doms in ip_domains.items():
        if len(doms) < 2:
            continue
        for i in range(len(doms)):
            for j in range(i + 1, len(doms)):
                graph.add_edge(doms[i], doms[j], "same_ip", extra={"via": ip_id})

    resolver_conflicts = compare_resolvers(seed_norm, lang=lang)
    session = graph.to_session_dict(passive_names=passive, resolver_conflicts=resolver_conflicts)
    session["stats"] = compute_metrics(graph, session)

    if verbose:
        st = session["stats"]
        print(
            f"{C_GREEN}{msg(lang, 'crawl_done', domains=st.get('domain_count', 0), ips=st.get('ip_count', 0), edges=st.get('edge_count', 0), depth=st.get('max_depth', 0))}{C_RESET}"
        )
    return session


def save_session(session: Dict[str, Any], path: Optional[Path] = None) -> Path:
    ensure_dirs()
    out = path or default_session_path(str(session.get("seed", "unknown")))
    out.parent.mkdir(parents=True, exist_ok=True)
    with open(out, "w", encoding="utf-8") as f:
        json.dump(session, f, indent=2, ensure_ascii=False)
    return out


def load_session(path: Path) -> Dict[str, Any]:
    with open(path, encoding="utf-8") as f:
        data = json.load(f)
    if data.get("format") not in (DNS_FORMAT_V1, LEGACY_DNS_FORMAT_V1):
        raise ValueError("unknown session format")
    return data


def session_to_graph(session: Dict[str, Any]) -> DnsGraph:
    g = DnsGraph(str(session.get("seed", "")))
    for node in session.get("nodes", []):
        nid = node["id"]
        g.nodes[nid] = dict(node)
    g.edges = list(session.get("edges", []))
    g._edge_keys = {(e["from"], e["to"], e["rtype"]) for e in g.edges}
    return g


def print_session_summary(session: Dict[str, Any], *, lang: str = "en") -> None:
    graph = session_to_graph(session)
    stats = session.get("stats") or compute_metrics(graph, session)
    print(f"\n{C_BOLD}{msg(lang, 'table_title')}{C_RESET}")
    print(f"  seed: {session.get('seed')}")
    print(f"  domains: {stats.get('domain_count')}  IPs: {stats.get('ip_count')}  edges: {stats.get('edge_count')}")
    print(f"\n{C_DIM}{'─' * 72}{C_RESET}")
    print(f"{C_BOLD}{msg(lang, 'col_name'):<36} {msg(lang, 'col_depth'):>5}  {msg(lang, 'col_records')}{C_RESET}")
    domains = [n for n in graph.nodes.values() if n.get("type") == "domain"]
    domains.sort(key=lambda n: (n.get("depth", 0), n.get("label", "")))
    for node in domains[:40]:
        rec = node.get("records") or {}
        brief: List[str] = []
        for rtype in ("A", "AAAA", "CNAME", "NS", "MX"):
            if rtype in rec:
                val = rec[rtype]
                if isinstance(val, list) and val:
                    if rtype == "MX" and isinstance(val[0], dict):
                        brief.append(f"MX→{val[0].get('host', '?')}")
                    else:
                        brief.append(f"{rtype}={val[0] if not isinstance(val[0], dict) else val[0]}")
        if node.get("geo_country"):
            brief.append(f"geo={node['geo_country']}")
        line = ", ".join(brief)[:48]
        print(f"  {node.get('label', '')[:36]:<36} {int(node.get('depth', 0)):>5}  {line}")
    if len(domains) > 40:
        print(f"  {C_DIM}… +{len(domains) - 40} more domains{C_RESET}")

    print_metrics(session, lang=lang)


def print_metrics(session: Dict[str, Any], *, lang: str = "en") -> None:
    stats = session.get("stats") or {}
    print(f"\n{C_BOLD}{msg(lang, 'metrics_title')}{C_RESET}")
    print(f"  {msg(lang, 'metric_max_depth', n=stats.get('max_depth', 0))}")
    print(f"  {msg(lang, 'metric_cname_loops', n=stats.get('cname_loop_count', 0))}")
    print(f"  {msg(lang, 'metric_external_ns', n=stats.get('external_ns_hosts', 0))}")
    print(f"  {msg(lang, 'metric_resolver_conflicts', n=stats.get('resolver_conflict_count', 0))}")
    shared = stats.get("shared_ip_groups") or []
    if shared:
        print(f"  {msg(lang, 'metric_shared_ip')}")
        for grp in shared[:8]:
            ip_label = grp.get("ip", "").replace("ip:", "")
            doms = ", ".join(grp.get("domains", [])[:4])
            print(f"    {C_CYAN}{ip_label}{C_RESET} ← {doms}")
    conflicts = session.get("resolver_conflicts") or []
    for c in conflicts[:5]:
        print(
            f"    {C_WARN}{c.get('domain')}: {c.get('resolver_a')} {c.get('answers_a')} vs "
            f"{c.get('resolver_b')} {c.get('answers_b')}{C_RESET}"
        )


def export_html(session: Dict[str, Any], out_path: Optional[Path] = None, *, lang: str = "en") -> Path:
    ensure_dirs()
    seed = str(session.get("seed", "graph"))
    safe = re.sub(r"[^a-z0-9.-]+", "_", seed.lower())[:60]
    path = out_path or (DNS_GRAPH_DIR / f"{safe}.html")
    nodes_json = json.dumps(session.get("nodes", []), ensure_ascii=False)
    edges_json = json.dumps(session.get("edges", []), ensure_ascii=False)
    title = escape(seed)
    nc = len(session.get("nodes", []))
    ec = len(session.get("edges", []))
    path.write_text(
        f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8"/>
  <title>DNS graph — {title}</title>
  <script src="https://unpkg.com/vis-network/standalone/umd/vis-network.min.js"></script>
  <style>
    body {{ font-family: system-ui, sans-serif; margin: 0; }}
    #header {{ padding: 12px 16px; background: #1a1a2e; color: #eee; }}
    #mynetwork {{ width: 100%; height: calc(100vh - 56px); }}
  </style>
</head>
<body>
  <div id="header"><strong>DNS graph</strong> — {title}
    <span style="opacity:.7"> · {nc} nodes · {ec} edges</span>
  </div>
  <div id="mynetwork"></div>
  <script>
    const nodes = new vis.DataSet({nodes_json}.map(n => ({{
      id: n.id,
      label: (n.label || n.id).slice(0, 48),
      title: JSON.stringify(n, null, 1),
      color: n.type === 'ip' ? '#4ecdc4' : (n.external_ns ? '#ff6b6b' : '#95e1d3'),
      shape: n.type === 'ip' ? 'box' : 'dot',
    }})));
    const edges = new vis.DataSet({edges_json}.map((e, i) => ({{
      id: i, from: e.from, to: e.to, label: e.rtype, arrows: 'to',
      dashes: e.rtype === 'same_ip',
    }})));
    new vis.Network(document.getElementById('mynetwork'), {{ nodes, edges }},
      {{ physics: {{ stabilization: true }}, edges: {{ smooth: true }} }});
  </script>
</body>
</html>""".replace('<div id="header">', '<div id="header">'),
        encoding="utf-8",
    )
    return path

def extract_dns_from_pcap(pcap_path: Path, *, lang: str = "en") -> List[str]:
    if not shutil.which("tshark"):
        if lang:
            print(f"{C_WARN}{msg(lang, 'pcap_no_tshark')}{C_RESET}")
        return []
    cmd = [
        "tshark",
        "-r",
        str(pcap_path),
        "-Y",
        "dns",
        "-T",
        "fields",
        "-e",
        "dns.qname",
        "-e",
        "dns.resp.name",
    ]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
    except (subprocess.TimeoutExpired, OSError):
        return []
    names: Set[str] = set()
    for line in (proc.stdout or "").splitlines():
        for col in line.split("\t"):
            n = normalize_domain(col.strip())
            if n:
                names.add(n)
    return sorted(names)


def crawl_from_pcap_seed(
    pcap_path: Path,
    seed: Optional[str],
    *,
    enrich_ip: Optional[Callable[[str, Dict[str, Any]], None]] = None,
    lang: str = "en",
    **kwargs: Any,
) -> Dict[str, Any]:
    names = extract_dns_from_pcap(pcap_path, lang=lang)
    if lang:
        print(f"{C_CYAN}{msg(lang, 'pcap_extract', n=len(names))}{C_RESET}")
    if not names:
        return {}
    primary = seed or names[0]
    # pick shortest suffix domain as seed heuristic
    if not seed:
        names_sorted = sorted(names, key=len)
        for n in names_sorted:
            if n.count(".") >= 1:
                primary = n
                break
    session = crawl_dns(primary, enrich_ip=enrich_ip, lang=lang, use_crtsh=False, **kwargs)
    if not session:
        return {}
    graph = session_to_graph(session)
    merge_passive_names(
        [n for n in names if n != primary][:200],
        graph,
        make_resolver(kwargs.get("nameserver")),
        seed=primary,
        lang=lang,
    )
    session = graph.to_session_dict(
        passive_names=sorted(set(names)),
        resolver_conflicts=session.get("resolver_conflicts") or [],
    )
    session["stats"] = compute_metrics(graph, session)
    return session


def pick_session_interactive(lang: str) -> Optional[Path]:
    files = list_session_files()
    if not files:
        print(f"{C_DIM}{msg(lang, 'empty_sessions')}{C_RESET}")
        return None
    print()
    for i, p in enumerate(files[:20], start=1):
        print(f"  {i}. {p.name}")
    try:
        raw = input(f"{C_CYAN}{msg(lang, 'prompt_session')}{C_RESET}").strip()
    except (EOFError, KeyboardInterrupt):
        print()
        return None
    if raw == "0" or not raw:
        return None
    if raw.isdigit():
        idx = int(raw) - 1
        if 0 <= idx < len(files):
            return files[idx]
    p = Path(raw).expanduser()
    return p if p.is_file() else None


def run_dns_menu(
    lang: str,
    *,
    enrich_ip: Optional[Callable[[str, Dict[str, Any]], None]] = None,
) -> None:
    """Interactive DNS analysis submenu."""
    if not _require_dnspython(lang):
        return
    ensure_dirs()
    while True:
        print(f"\n{C_BOLD}{msg(lang, 'menu_title')}{C_RESET}")
        print(msg(lang, "menu_1"))
        print(msg(lang, "menu_2"))
        print(msg(lang, "menu_3"))
        print(msg(lang, "menu_4"))
        print(msg(lang, "menu_5"))
        print(msg(lang, "menu_0"))
        try:
            choice = input(f"{C_CYAN}{msg(lang, 'menu_prompt')}{C_RESET}").strip()
        except (EOFError, KeyboardInterrupt):
            print()
            return

        if choice == "0":
            return
        if choice == "1":
            try:
                domain = input(f"{C_CYAN}{msg(lang, 'prompt_domain')}{C_RESET}").strip()
            except (EOFError, KeyboardInterrupt):
                print()
                continue
            if not domain:
                continue
            try:
                crt = input(f"{C_CYAN}{msg(lang, 'prompt_crt')}{C_RESET}").strip().lower()
            except (EOFError, KeyboardInterrupt):
                crt = "n"
            try:
                wl = input(f"{C_CYAN}{msg(lang, 'prompt_wordlist')}{C_RESET}").strip()
            except (EOFError, KeyboardInterrupt):
                wl = ""
            session = crawl_dns(
                domain,
                use_crtsh=crt in ("y", "yes", "д"),
                wordlist=Path(wl).expanduser() if wl else None,
                enrich_ip=enrich_ip,
                lang=lang,
            )
            if not session:
                continue
            print_session_summary(session, lang=lang)
            try:
                save = input(f"{C_WARN}Save session JSON? (y/n): {C_RESET}").strip().lower()
            except (EOFError, KeyboardInterrupt):
                save = "y"
            if save in ("y", "yes", "д"):
                path = save_session(session)
                print(f"{C_GREEN}{msg(lang, 'save_ok', path=path)}{C_RESET}")
        elif choice == "2":
            sel = pick_session_interactive(lang)
            if not sel:
                continue
            if not sel.exists():
                print(f"{C_FAIL}{msg(lang, 'file_not_found', path=sel)}{C_RESET}")
                continue
            try:
                session = load_session(sel)
                print_session_summary(session, lang=lang)
            except (OSError, ValueError, json.JSONDecodeError) as exc:
                print(f"{C_FAIL}{msg(lang, 'load_fail', err=exc)}{C_RESET}")
        elif choice == "3":
            sel = pick_session_interactive(lang)
            if not sel or not sel.exists():
                if sel:
                    print(f"{C_FAIL}{msg(lang, 'file_not_found', path=sel)}{C_RESET}")
                continue
            try:
                session = load_session(sel)
                out = export_html(session, lang=lang)
                print(f"{C_GREEN}{msg(lang, 'html_ok', path=out)}{C_RESET}")
            except (OSError, ValueError, json.JSONDecodeError) as exc:
                print(f"{C_FAIL}{msg(lang, 'html_fail', err=exc)}{C_RESET}")
        elif choice == "4":
            try:
                domain = input(f"{C_CYAN}{msg(lang, 'prompt_domain')}{C_RESET}").strip()
            except (EOFError, KeyboardInterrupt):
                continue
            dom = normalize_domain(domain)
            if not dom:
                print(f"{C_FAIL}{msg(lang, 'invalid_domain', name=domain)}{C_RESET}")
                continue
            conflicts = compare_resolvers(dom, lang=lang)
            for c in conflicts:
                print(
                    f"  {C_WARN}{c['resolver_a']}: {c['answers_a']}  vs  "
                    f"{c['resolver_b']}: {c['answers_b']}{C_RESET}"
                )
            if not conflicts:
                print(f"{C_GREEN}  A/AAAA agree across system, 1.1.1.1, 8.8.8.8{C_RESET}")
        elif choice == "5":
            try:
                pcap = input(f"{C_CYAN}{msg(lang, 'prompt_pcap')}{C_RESET}").strip()
            except (EOFError, KeyboardInterrupt):
                continue
            if not pcap:
                continue
            p = Path(pcap).expanduser()
            if not p.is_file():
                print(f"{C_FAIL}{msg(lang, 'file_not_found', path=p)}{C_RESET}")
                continue
            session = crawl_from_pcap_seed(p, None, enrich_ip=enrich_ip, lang=lang)
            if session:
                print_session_summary(session, lang=lang)
                try:
                    save = input(f"{C_WARN}Save session JSON? (y/n): {C_RESET}").strip().lower()
                except (EOFError, KeyboardInterrupt):
                    save = "n"
                if save in ("y", "yes", "д"):
                    path = save_session(session)
                    print(f"{C_GREEN}{msg(lang, 'save_ok', path=path)}{C_RESET}")
        else:
            print(f"{C_WARN} ?{C_RESET}")
