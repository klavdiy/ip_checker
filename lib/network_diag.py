#!/usr/bin/env python3
"""
CLI-network tools: trace monitor and approximate speedtest via Cloudflare public endpoints (HTTP).
"""

from __future__ import annotations

import ipaddress
import json
import os
import platform
import re
import shutil
import statistics
import subprocess
import sys
import time
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from contextlib import contextmanager, nullcontext
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple, Union

try:
    import select
except ImportError:
    select = None  # type: ignore[misc, assignment]

try:
    import termios
    import tty
except ImportError:
    termios = None  # type: ignore[assignment]
    tty = None  # type: ignore[assignment]

try:
    import msvcrt
except ImportError:
    msvcrt = None  # type: ignore[assignment]

# --- minimal ANSI (избегаем циклического импорта fnkit.Colors)
C_RESET = "\033[0m"
C_BOLD = "\033[1m"
C_CYAN = "\033[96m"
C_GREEN = "\033[92m"
C_WARN = "\033[93m"
C_FAIL = "\033[91m"

from paths import TRACE_SESSIONS_DIR
from schema import (
    DocumentKind,
    FORMAT_TRACE_V1 as TRACE_FORMAT_V1,
    LEGACY_FORMAT_TRACE_V1 as LEGACY_TRACE_FORMAT_V1,
    is_session_format_valid,
    load_json_file,
    save_json_file,
)

# pick_active_interface_for_trace_save() returns this if user aborts during selection
_TRACE_IFACE_PICK_CANCELLED = object()

STRINGS: Dict[str, Dict[str, str]] = {
    "en": {
        "trace_need_tr": "Traceroute/tracert is required but not found in PATH.",
        "trace_need_ping": "ping command not found in PATH.",
        "trace_discover": "Discovering route to {host} (traceroute)...",
        "trace_no_hops": "Could not parse any hops (check host / permissions).",
        "trace_header": "Hop RTT / loss by hop  (× = timeout / loss in sparkline)",
        "trace_log_hint": "Scroll log (screen is not cleared). Keys: p pause · q stop · Ctrl+C stop",
        "trace_dashboard_hint": "Table refreshes in place (same window). Keys: p pause · q stop · Ctrl+C stop",
        "trace_col_trend": "Trend (RTT)",
        "trace_legend": "interval {sec}s  |  rediscover every {n} rounds  |  parallel ping (MTR-style)",
        "trace_round": "Round {n}",
        "trace_pause_mark": "PAUSE",
        "trace_dashboard_title": "Route latency monitor → {target}",
        "trace_paused": "— PAUSED (p resume, q stop) —",
        "trace_resumed": "— resumed —",
        "trace_stopped": "Session stopped.",
        "trace_save_offer": "Save this session ({rounds} rounds) to JSON for later replay? (y/n): ",
        "trace_save_path": "File path [Enter = {default}]: ",
        "trace_save_ok": "Saved: {path}",
        "trace_save_skip": "Not saved.",
        "trace_save_fail": "Save failed: {err}",
        "trace_replay_title": "Replaying saved session → {target}  ({rounds} rounds)",
        "trace_replay_done": "Replay finished.",
        "trace_replay_fail": "Cannot load session: {err}",
        "trace_replay_bad": "Unknown or invalid session format.",
        "trace_replay_hint": "Recorded session playback (same layout as live log).",
        "trace_replay_iface": "Recorded capture interface: {iface}",
        "trace_iface_pick_title": "Select the active interface this session used (saved in JSON):",
        "trace_iface_pick_prompt": "Number [1] (or interface name): ",
        "trace_iface_pick_invalid": "Invalid choice — enter 1–{n} or an interface name from the list.",
        "trace_iface_list_empty": "No active interfaces detected — JSON will omit capture_iface.",
        "trace_iface_auto": "Default-route interface (capture_iface in JSON): {iface}",
        "trace_iface_auto_fail": "Could not detect default-route interface — pick from the list.",
        "speed_title": "Channel check (Cloudflare HTTP, approximate)",
        "speed_ping": "ICMP ping median to {target}: {ms:.1f} ms (from {count} probes)",
        "speed_ping_fail": "ICMP ping unavailable or failed ({reason}).",
        "speed_dl": "Download: ~{mbps:.1f} Mbps ({mb:.2f} MB in {sec:.2f}s)",
        "speed_ul": "Upload:   ~{mbps:.1f} Mbps ({mb:.2f} MB in {sec:.2f}s)",
        "speed_ul_fail": "Upload test failed: {err}",
        "speed_parallel": "Parallel HTTP streams: {n}",
        "speed_footer": "Figures depend on the CDN path, parallelism, Wi‑Fi, and DPI.",
        "invalid_host": "Invalid host/IP: {host}",
        "invalid_yes_no": "Please enter y or n.",
        "iface_title": "Network interfaces on this machine",
        "iface_hint": "Names and addresses come from the OS; “kind” is a heuristic from the interface name.",
        "iface_none": "No interfaces could be enumerated.",
        "iface_cmd_fail": "Could not run system command: {cmd} ({err})",
        "iface_name": "Interface",
        "iface_kind": "Kind (guess)",
        "iface_state": "State",
        "iface_mtu": "MTU",
        "iface_mac": "MAC",
        "iface_ips": "IPv4 / IPv6",
        "iface_desc": "OS description",
        "iface_kind_loopback": "loopback",
        "iface_kind_wifi": "Wi‑Fi (likely)",
        "iface_kind_ethernet": "Ethernet / wired (likely)",
        "iface_kind_bridge": "bridge / virtual switch",
        "iface_kind_tunnel": "tunnel / VPN (likely)",
        "iface_kind_virtual": "virtual / container",
        "iface_kind_other": "other",
        "iface_section_active": "Active interfaces",
        "iface_section_inactive": "Inactive / down interfaces",
        "iface_prompt_inactive": "Also list inactive interfaces? (y/n): ",
        "iface_skip_inactive": "Inactive interfaces omitted.",
        "iface_no_active_bucket": "No interfaces classified as active; listing all entries.",
        "iface_press_zero": "Enter 0 to return to the main menu: ",
        "iface_press_zero_invalid": "Only 0 is accepted here — return to the main menu.",
    },
    "ru": {
        "trace_need_tr": "Нужны traceroute/tracert — команда не найдена в PATH.",
        "trace_need_ping": "Не найдена команда ping в PATH.",
        "trace_discover": "Построение маршрута до {host} (traceroute)...",
        "trace_no_hops": "Не удалось разобрать хопы (проверьте хост / права).",
        "trace_header": "Задержка и потери по узлам  (× — таймаут в мини-графике)",
        "trace_log_hint": "Лог копится, экран не очищается. Клавиши: p пауза · q стоп · Ctrl+C стоп",
        "trace_dashboard_hint": "Таблица обновляется на месте (одно окно). Клавиши: p пауза · q стоп · Ctrl+C стоп",
        "trace_col_trend": "Тренд (RTT)",
        "trace_legend": "интервал {sec}s  |  повторный traceroute каждые {n} циклов  |  параллельный ping (MTR)",
        "trace_round": "Цикл {n}",
        "trace_pause_mark": "ПАУЗА",
        "trace_dashboard_title": "Монитор задержки по маршруту → {target}",
        "trace_paused": "— ПАУЗА (p продолжить, q выход) —",
        "trace_resumed": "— продолжение —",
        "trace_stopped": "Сессия остановлена.",
        "trace_save_offer": "Сохранить сессию ({rounds} циклов) в JSON для последующего просмотра? (y/n): ",
        "trace_save_path": "Путь к файлу [Enter = {default}]: ",
        "trace_save_ok": "Сохранено: {path}",
        "trace_save_skip": "Не сохранено.",
        "trace_save_fail": "Ошибка сохранения: {err}",
        "trace_replay_title": "Воспроизведение сохранённой сессии → {target}  ({rounds} циклов)",
        "trace_replay_done": "Воспроизведение завершено.",
        "trace_replay_fail": "Не удалось загрузить сессию: {err}",
        "trace_replay_bad": "Неизвестный или повреждённый формат сессии.",
        "trace_replay_hint": "Просмотр записанной сессии (тот же формат, что и при живой проверке).",
        "trace_replay_iface": "Записанный интерфейс захвата: {iface}",
        "trace_iface_pick_title": "Выберите активный интерфейс, с которого велась сессия (пишется в JSON):",
        "trace_iface_pick_prompt": "Номер [1] (или имя интерфейса): ",
        "trace_iface_pick_invalid": "Неверный ввод — укажите 1–{n} или имя из списка.",
        "trace_iface_list_empty": "Активные интерфейсы не найдены — в JSON не будет поля capture_iface.",
        "trace_iface_auto": "Интерфейс маршрута по умолчанию (capture_iface в JSON): {iface}",
        "trace_iface_auto_fail": "Не удалось определить интерфейс маршрута по умолчанию — выберите из списка.",
        "speed_title": "Проверка канала (HTTP Cloudflare, ориентировочно)",
        "speed_ping": "ICMP ping (медиана) до {target}: {ms:.1f} мс ({count} зондов)",
        "speed_ping_fail": "ICMP ping недоступен или ошибка ({reason}).",
        "speed_dl": "Загрузка: ~{mbps:.1f} Мбит/с ({mb:.2f} МБ за {sec:.2f} с)",
        "speed_ul": "Отдача:   ~{mbps:.1f} Мбит/с ({mb:.2f} МБ за {sec:.2f} с)",
        "speed_ul_fail": "Тест отдачи не удался: {err}",
        "speed_parallel": "Параллельных HTTP-потоков: {n}",
        "speed_footer": "Оценка зависит от CDN, Wi‑Fi, DPI и текущей загрузки сети.",
        "invalid_host": "Некорректный хост/IP: {host}",
        "invalid_yes_no": "Введите y или n.",
        "iface_title": "Сетевые интерфейсы на этой машине",
        "iface_hint": "Имена и адреса берутся из ОС; «тип» — эвристика по имени интерфейса.",
        "iface_none": "Не удалось получить список интерфейсов.",
        "iface_cmd_fail": "Не удалось выполнить команду: {cmd} ({err})",
        "iface_name": "Интерфейс",
        "iface_kind": "Тип (оценка)",
        "iface_state": "Состояние",
        "iface_mtu": "MTU",
        "iface_mac": "MAC",
        "iface_ips": "IPv4 / IPv6",
        "iface_desc": "Описание в ОС",
        "iface_kind_loopback": "loopback",
        "iface_kind_wifi": "Wi‑Fi (вероятно)",
        "iface_kind_ethernet": "Ethernet / провод (вероятно)",
        "iface_kind_bridge": "мост / виртуальный коммутатор",
        "iface_kind_tunnel": "туннель / VPN (вероятно)",
        "iface_kind_virtual": "виртуальный / контейнер",
        "iface_kind_other": "другое",
        "iface_section_active": "Активные интерфейсы",
        "iface_section_inactive": "Неактивные / выключенные интерфейсы",
        "iface_prompt_inactive": "Показать неактивные интерфейсы? (y/n): ",
        "iface_skip_inactive": "Неактивные интерфейсы не выводятся.",
        "iface_no_active_bucket": "Нет интерфейсов, классифицированных как активные; ниже полный список.",
        "iface_press_zero": "Введите 0 для возврата в главное меню: ",
        "iface_press_zero_invalid": "Нужна только цифра 0 — возврат в главное меню.",
    },
}

HTTP_UA = (
    "Mozilla/5.0 (compatible; fnkit/1.0; fieldnetkit) "
    "AppleWebKit/537.36 (KHTML, like Gecko)"
)
CLOUDFLARE_SPEED_DOWN = "https://speed.cloudflare.com/__down"
CLOUDFLARE_SPEED_UP = "https://speed.cloudflare.com/__up"
DEFAULT_SPEED_HTTP_STREAMS = 4
SPARK = "▁▂▃▄▅▆▇█"
# Alternate screen + cursor home (TTY): one-window trace dashboard
ANSI_ALT_ENTER = "\033[?1049h\033[2J\033[H"
ANSI_ALT_LEAVE = "\033[?1049l"
ANSI_HOME = "\033[H"
ANSI_CLEAR_ALL = "\033[2J\033[H"
IPV4_RE = re.compile(r"\b(\d{1,3}(?:\.\d{1,3}){3})\b")


def localized(lang: str, key: str, **kwargs: object) -> str:
    d = STRINGS.get(lang, STRINGS["en"])
    return d.get(key, key).format(**kwargs)


def _is_windows() -> bool:
    return platform.system().lower().startswith("win")


def _traceroute_bin() -> Optional[str]:
    for name in ("traceroute", "traceroute6", "tracert"):
        if shutil.which(name):
            return name
    return None


def _traceroute_cmd(host: str, max_hops: int) -> List[str]:
    if _is_windows():
        return ["tracert", "-d", "-h", str(max_hops), host]
    return ["traceroute", "-n", "-m", str(max_hops), "-q", "1", "-w", "2", host]


def _parse_hop_line_unix(line: str) -> Optional[Tuple[int, Optional[str]]]:
    m = re.match(r"^\s*(\d+)\s+", line)
    if not m:
        return None
    hop = int(m.group(1))
    rest = line[m.end() :]
    if re.search(r"^\s*\*\s*\*\s*\*", rest):
        return hop, None
    ips = IPV4_RE.findall(rest)
    if not ips:
        return hop, None
    return hop, ips[0]


def _parse_hop_line_win(line: str) -> Optional[Tuple[int, Optional[str]]]:
    m = re.match(r"^\s*(\d+)\s+", line)
    if not m:
        return None
    hop = int(m.group(1))
    rest = line[m.end() :]
    low = rest.lower()
    if "request timed out" in low or re.match(r"^\s*\*\s+", rest):
        return hop, None
    ips = IPV4_RE.findall(rest)
    if not ips:
        return hop, None
    return hop, ips[-1]


def discover_hops(host: str, max_hops: int = 30) -> List[Tuple[int, Optional[str]]]:
    """Один прогон traceroute: список (номер_хопа, IPv4 или None)."""
    tr = _traceroute_bin()
    if not tr:
        return []
    cmd = _traceroute_cmd(host, max_hops)
    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=max(60, max_hops * 4),
            errors="replace",
        )
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
        return []
    out = (proc.stdout or "") + "\n" + (proc.stderr or "")
    parser = _parse_hop_line_win if _is_windows() else _parse_hop_line_unix
    hops: List[Tuple[int, Optional[str]]] = []
    seen: set[int] = set()
    for line in out.splitlines():
        parsed = parser(line)
        if not parsed:
            continue
        hop, ip = parsed
        if hop in seen:
            continue
        seen.add(hop)
        hops.append((hop, ip))
    hops.sort(key=lambda x: x[0])
    return hops


def _ping_cmd(ip: str) -> List[str]:
    if _is_windows():
        return ["ping", "-n", "1", "-w", "2500", ip]
    if sys.platform == "darwin":
        return ["ping", "-c", "1", "-W", "2500", ip]
    return ["ping", "-c", "1", "-W", "2", ip]


def ping_rtt_ms(ip: str) -> Optional[float]:
    cmd = _ping_cmd(ip)
    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=6,
            errors="replace",
        )
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
        return None
    text = (proc.stdout or "") + (proc.stderr or "")
    m = re.search(r"time[=<](\d+(?:\.\d+)?)\s*ms", text, re.I)
    if m:
        return float(m.group(1))
    if re.search(r"<1\s*ms", text, re.I):
        return 0.2
    if proc.returncode == 0 and "ttl=" in text.lower():
        return 1.0
    return None


def ping_hops_parallel(
    hops: List[Tuple[int, Optional[str]]],
    *,
    max_workers: Optional[int] = None,
) -> Dict[int, Optional[float]]:
    """
    MTR-style probe round: ping every hop with an address at the same time.
    Returns hop number -> RTT ms (None on timeout / no address).
    """
    result: Dict[int, Optional[float]] = {}
    targets: List[Tuple[int, str]] = []
    for hop, ip in hops:
        if not ip:
            result[hop] = None
        else:
            targets.append((hop, ip))

    if not targets:
        return result

    workers = max_workers if max_workers is not None else min(32, max(1, len(targets)))

    def _probe(item: Tuple[int, str]) -> Tuple[int, Optional[float]]:
        hop_num, addr = item
        return hop_num, ping_rtt_ms(addr)

    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = [pool.submit(_probe, item) for item in targets]
        for fut in as_completed(futures):
            hop_num, ms = fut.result()
            result[hop_num] = ms
    return result


def icmp_median_ms(target: str, count: int = 5, gap: float = 0.12) -> Optional[float]:
    samples: List[float] = []
    for _ in range(count):
        v = ping_rtt_ms(target)
        if v is not None:
            samples.append(v)
        time.sleep(gap)
    if not samples:
        return None
    return float(statistics.median(samples))


def sparkline(samples: Sequence[Optional[float]], width: int = 14) -> str:
    tail = list(samples[-width:])
    if not tail:
        return ""
    numeric = [v for v in tail if v is not None]
    if not numeric:
        return "×" * len(tail)
    lo, hi = min(numeric), max(numeric)
    if hi - lo < 1e-6:
        hi = lo + max(lo * 1e-3, 1.0)
    bars = []
    for v in tail:
        if v is None:
            bars.append("×")
        else:
            idx = int((v - lo) / (hi - lo) * (len(SPARK) - 1))
            idx = max(0, min(idx, len(SPARK) - 1))
            bars.append(SPARK[idx])
    return "".join(bars)


def _fmt_jitter(last_ok: List[float]) -> str:
    if len(last_ok) < 2:
        return "—"
    return f"{statistics.pstdev(last_ok):.1f}"


def _terminal_columns() -> int:
    try:
        import shutil as _sh

        return min(132, max(72, _sh.get_terminal_size(sys.stdout.fileno()).columns))
    except (OSError, TypeError, ValueError, AttributeError):
        return 100


@contextmanager
def _cbreak_stdin():
    if termios is None or tty is None or not sys.stdin.isatty():
        yield
        return
    fd = sys.stdin.fileno()
    old = termios.tcgetattr(fd)
    try:
        tty.setcbreak(fd)
        yield
    finally:
        termios.tcsetattr(fd, termios.TCSAFLUSH, old)


def poll_key(timeout_sec: float) -> Optional[str]:
    """Один символ ввода (TTY) или None по таймауту."""
    if _is_windows() and msvcrt is not None:
        deadline = time.monotonic() + timeout_sec
        while time.monotonic() < deadline:
            if msvcrt.kbhit():
                raw = msvcrt.getch()
                if isinstance(raw, bytes):
                    try:
                        return raw.decode("utf-8", errors="replace")
                    except Exception:
                        return "?"
                return str(raw)
            time.sleep(min(0.02, deadline - time.monotonic()))
        return None
    if select is None or not sys.stdin.isatty():
        time.sleep(timeout_sec)
        return None
    rlist, _, _ = select.select([sys.stdin], [], [], max(0.0, timeout_sec))
    if not rlist:
        return None
    return sys.stdin.read(1)


def _apply_trace_key(
    ctrl: Dict[str, bool],
    ch: Optional[str],
    resume_note: Optional[Dict[str, Any]],
) -> None:
    """resume_note: {\"lang\":\"en\"} печатает resumed при переходе с паузы."""
    if not ch:
        return
    lowered = ch.lower()
    oc = ord(ch[0])
    # Ctrl+C → стоп при чтении как символ может не прийти; обрабатываем и \x03
    if lowered == "q" or oc == 3:
        ctrl["stop"] = True
        return
    if lowered == "p":
        ctrl["paused"] = not ctrl["paused"]
        if resume_note and resume_note.get("silent_pause_msgs"):
            return
        if resume_note:
            lang = str(resume_note.get("lang", "en"))
            if ctrl["paused"]:
                print(f"{C_WARN}{localized(lang, 'trace_paused')}{C_RESET}", flush=True)
            else:
                print(f"{C_GREEN}{localized(lang, 'trace_resumed')}{C_RESET}", flush=True)


def dump_round_snapshot(
    round_id: int,
    hops: List[Tuple[int, Optional[str]]],
    rtt_by_hop: Dict[int, Optional[float]],
    sent: Optional[Dict[int, int]] = None,
    ok: Optional[Dict[int, int]] = None,
) -> Dict[str, Any]:
    """Serialize one monitor round; include cumulative sent/ok for faithful loss on replay."""
    rtt_serial: Dict[str, Any] = {}
    for hop, ip in hops:
        if not ip:
            continue
        v = rtt_by_hop.get(hop)
        rtt_serial[str(hop)] = v
    hops_serial = [[hop, ip] for hop, ip in hops]
    snap: Dict[str, Any] = {
        "n": round_id,
        "t": datetime.now(timezone.utc).isoformat(),
        "hops": hops_serial,
        "rtt": rtt_serial,
    }
    if sent is not None:
        snap["sent"] = {str(hop): int(sent.get(hop, 0)) for hop, _ in hops}
    if ok is not None:
        snap["ok"] = {str(hop): int(ok.get(hop, 0)) for hop, _ in hops}
    return snap


def _trend_width(term_w: int) -> int:
    """Spark / trend column width from terminal size."""
    return max(12, min(48, term_w - 52))


def _build_trace_view_lines(
    lang: str,
    target: str,
    round_id: int,
    hops: List[Tuple[int, Optional[str]]],
    history: Dict[int, List[Optional[float]]],
    sent: Dict[int, int],
    ok: Dict[int, int],
    *,
    interval_sec: float,
    rediscover_every: int,
    dashboard: bool,
    paused: bool,
) -> List[str]:
    term_w = _terminal_columns()
    bar = min(term_w, 72)
    tw = _trend_width(term_w)
    out: List[str] = []
    if dashboard:
        badge = ""
        if paused:
            badge = f"  {C_WARN}[{localized(lang, 'trace_pause_mark')}]{C_RESET}"
        out.append(
            f"{C_BOLD}{localized(lang, 'trace_dashboard_title', target=target)}{badge}{C_RESET}"
        )
        out.append(
            localized(
                lang,
                "trace_legend",
                sec=f"{interval_sec:.1f}",
                n=rediscover_every,
            )
        )
        out.append(f"{C_CYAN}{localized(lang, 'trace_dashboard_hint')}{C_RESET}")
    ts_display = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    out.append(f"{C_CYAN}{'═' * bar}{C_RESET}")
    out.append(
        f"{C_BOLD}{localized(lang, 'trace_round', n=round_id)}{C_RESET}"
        f"  ·  {target}  ·  {ts_display}"
    )
    out.append(localized(lang, "trace_header"))
    hdr = (
        f"{'Hop':>3}  {'Address':<16}  {'Last':>6}  {'Avg':>6}  "
        f"{'Jtr':>5}  {'Loss':>5}  {localized(lang, 'trace_col_trend')}"
    )
    out.append(hdr[:term_w])
    rule_len = max(58, min(term_w, len(hdr) + 6))
    out.append("-" * rule_len)
    for hop, ip in hops:
        hist = history.get(hop, [])
        last = hist[-1] if hist else None
        last_s = f"{last:.1f}" if last is not None else "—"
        ok_vals = [x for x in hist if x is not None]
        avg_s = f"{statistics.mean(ok_vals):.1f}" if ok_vals else "—"
        recent_ok = [x for x in hist[-12:] if x is not None]
        jtr = _fmt_jitter(recent_ok)
        s_cnt, o_cnt = sent.get(hop, 0), ok.get(hop, 0)
        loss = 100.0 * (1 - o_cnt / s_cnt) if s_cnt else 0.0
        loss_s = "  —" if (ip is None or s_cnt == 0) else f"{loss:5.0f}%"
        addr = ip or "—"
        spark = sparkline(hist, width=tw)
        line = f"{hop:3d}  {addr:<16}  {last_s:>6}  {avg_s:>6}  {jtr:>5}  {loss_s}  {spark}"
        out.append(line[:term_w])
    out.append("")
    return out


def print_round_scroll(
    lang: str,
    target: str,
    round_id: int,
    hops: List[Tuple[int, Optional[str]]],
    history: Dict[int, List[Optional[float]]],
    sent: Dict[int, int],
    ok: Dict[int, int],
) -> None:
    term_w = _terminal_columns()
    lines = _build_trace_view_lines(
        lang,
        target,
        round_id,
        hops,
        history,
        sent,
        ok,
        interval_sec=0.0,
        rediscover_every=0,
        dashboard=False,
        paused=False,
    )
    for ln in lines:
        print(ln[:term_w], flush=False)
    print("", flush=True)


def _emit_trace_dashboard(
    lang: str,
    target: str,
    round_id: int,
    hops: List[Tuple[int, Optional[str]]],
    history: Dict[int, List[Optional[float]]],
    sent: Dict[int, int],
    ok: Dict[int, int],
    *,
    interval_sec: float,
    rediscover_every: int,
    paused: bool,
    dash: Dict[str, Any],
) -> None:
    hop_sig = tuple((h[0], h[1]) for h in hops)
    hop_changed = dash.get("hop_sig") != hop_sig
    dash["hop_sig"] = hop_sig
    lines = _build_trace_view_lines(
        lang,
        target,
        round_id,
        hops,
        history,
        sent,
        ok,
        interval_sec=interval_sec,
        rediscover_every=rediscover_every,
        dashboard=True,
        paused=paused,
    )
    if not dash.get("entered"):
        sys.stdout.write(ANSI_ALT_ENTER)
        dash["entered"] = True
    elif hop_changed:
        sys.stdout.write(ANSI_CLEAR_ALL)
    sys.stdout.write(ANSI_HOME)
    tw = _terminal_columns()
    for ln in lines:
        sys.stdout.write(ln[:tw] + "\n")
    sys.stdout.flush()


def gather_interface_rows() -> List[Dict[str, Any]]:
    rows: Optional[List[Dict[str, Any]]] = None
    if _is_windows():
        rows = _windows_interfaces_ps()
    elif platform.system() == "Darwin":
        rows = _macos_interfaces_ifconfig()
    else:
        rows = _linux_interfaces_ip_json()
        if not rows:
            rows = _linux_interfaces_sys_fallback()
    return list(rows) if rows else []


def list_trace_session_json_files(limit: int = 100) -> List[Path]:
    TRACE_SESSIONS_DIR.mkdir(parents=True, exist_ok=True)
    if not TRACE_SESSIONS_DIR.is_dir():
        return []
    found = [p for p in TRACE_SESSIONS_DIR.glob("*.json") if p.is_file()]
    found.sort(key=lambda x: x.stat().st_mtime, reverse=True)
    return found[:limit]


def _subprocess_stdout_text(cmd: Sequence[str], *, timeout: float = 12.0) -> str:
    try:
        proc = subprocess.run(
            list(cmd),
            capture_output=True,
            text=True,
            timeout=timeout,
            errors="replace",
        )
    except (OSError, subprocess.TimeoutExpired):
        return ""
    if proc.returncode != 0:
        return ""
    return (proc.stdout or "").strip()


def _default_route_iface_macos() -> Optional[str]:
    for argv in (
        ["route", "-n", "get", "default"],
        ["route", "get", "default"],
        ["route", "-n", "get", "0.0.0.0"],
    ):
        out = _subprocess_stdout_text(argv, timeout=8.0)
        if not out:
            continue
        m = re.search(r"(?im)^\s*interface:\s*(\S+)", out)
        if m:
            name = m.group(1).strip()
            if name and name != "reject":
                return name
    return None


def _default_route_iface_linux() -> Optional[str]:
    data = _run_cmd_json(["ip", "-json", "route", "show", "default"], timeout=10.0)
    if isinstance(data, list) and data:
        scored: List[Tuple[int, int, str]] = []
        for row in data:
            if not isinstance(row, dict):
                continue
            dst = str(row.get("dst") or "")
            if dst not in ("default", "0.0.0.0/0"):
                continue
            dev = str(row.get("dev") or "").strip()
            if not dev:
                continue
            raw_m = row.get("metric")
            try:
                metric = int(raw_m) if raw_m is not None else 999_999
            except (TypeError, ValueError):
                metric = 999_999
            pri = int(row.get("priority") or 999_999)
            scored.append((metric + pri, metric, dev))
        if scored:
            scored.sort(key=lambda t: (t[0], t[1], t[2]))
            return scored[0][2]
    out = _subprocess_stdout_text(["ip", "route", "show", "default"], timeout=10.0)
    if out:
        best: Optional[Tuple[int, str]] = None
        for line in out.splitlines():
            line = line.strip()
            if not line.startswith("default"):
                continue
            m = re.search(r"\bdev\s+(\S+)", line)
            if not m:
                continue
            dev = m.group(1).strip()
            mm = re.search(r"\bmetric\s+(\d+)", line)
            metric = int(mm.group(1)) if mm else 999_999
            cand = (metric, dev)
            if best is None or cand[0] < best[0]:
                best = cand
        if best:
            return best[1]
    return None


def _default_route_iface_windows() -> Optional[str]:
    ps = shutil.which("powershell.exe") or shutil.which("pwsh.exe")
    if not ps:
        return None
    script = (
        "$r = @(Get-NetRoute -AddressFamily IPv4 -DestinationPrefix '0.0.0.0/0' "
        "-ErrorAction SilentlyContinue | Sort-Object RouteMetric, ifIndex); "
        "if ($r.Count -gt 0) { ($r | Select-Object -First 1).InterfaceAlias.Trim() }"
    )
    try:
        proc = subprocess.run(
            [ps, "-NoProfile", "-Command", script],
            capture_output=True,
            text=True,
            timeout=20,
            errors="replace",
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    if proc.returncode != 0:
        return None
    line = (proc.stdout or "").strip().splitlines()
    name = (line[0] if line else "").strip()
    return name or None


def guess_default_route_interface() -> Optional[str]:
    """
    OS-reported IPv4 default-route egress interface (e.g. en0, utun8 with VPN).
    Used as capture_iface metadata for trace JSON without asking the user.
    """
    if _is_windows():
        return _default_route_iface_windows()
    if platform.system() == "Darwin":
        return _default_route_iface_macos()
    if platform.system() == "Linux":
        return _default_route_iface_linux()
    return None


def pick_active_interface_for_trace_save(lang: str) -> Union[str, None, object]:
    """
    Interactive fallback: pick active (non-loopback preferred) interface for JSON metadata
    when guess_default_route_interface() could not determine the default route.
    Returns str, None if no candidates (omit field), or _TRACE_IFACE_PICK_CANCELLED.
    """
    lang = lang if lang in STRINGS else "en"
    rows = gather_interface_rows()
    active = [r for r in rows if _is_iface_row_active(r)]
    candidates = [
        r for r in active if _iface_kind_key(str(r.get("name") or "")) != "loopback"
    ]
    if not candidates:
        candidates = list(active)
    if not candidates:
        print(f"{C_WARN}{localized(lang, 'trace_iface_list_empty')}{C_RESET}\n")
        return None
    names = {str(r.get("name") or "").strip() for r in candidates if str(r.get("name") or "").strip()}
    print(f"\n{C_BOLD}{localized(lang, 'trace_iface_pick_title')}{C_RESET}")
    for i, r in enumerate(candidates, 1):
        nm = str(r.get("name") or "")
        print(f"  {i}) {nm}  ({r.get('state') or '?'})")
    nmax = len(candidates)
    while True:
        try:
            raw = input(
                f"{C_WARN}{localized(lang, 'trace_iface_pick_prompt')}{C_RESET}"
            ).strip()
        except (EOFError, KeyboardInterrupt):
            print()
            return _TRACE_IFACE_PICK_CANCELLED
        if raw == "":
            return str(candidates[0].get("name") or "")
        if raw.isdigit():
            idx = int(raw)
            if 1 <= idx <= nmax:
                return str(candidates[idx - 1].get("name") or "")
            print(
                f"{C_WARN}{localized(lang, 'trace_iface_pick_invalid', n=nmax)}{C_RESET}"
            )
            continue
        if raw in names:
            return raw
        low = raw.lower()
        for r in candidates:
            nm = str(r.get("name") or "")
            if nm.lower() == low:
                return nm
        print(f"{C_WARN}{localized(lang, 'trace_iface_pick_invalid', n=nmax)}{C_RESET}")


def offer_save_trace_session(
    rounds: List[Dict[str, Any]],
    *,
    lang: str,
    target: str,
    interval_sec: float,
    rediscover_every: int,
    max_hops: int,
    interactive_tty: bool,
) -> None:
    if not rounds:
        return
    if not interactive_tty:
        return
    while True:
        try:
            prompt = localized(lang, "trace_save_offer", rounds=len(rounds))
            ans = input(f"{prompt}").strip().lower()
        except (EOFError, KeyboardInterrupt):
            print()
            print(f"{C_CYAN}{localized(lang, 'trace_save_skip')}{C_RESET}")
            return
        if ans in ("y", "n"):
            break
        print(f"{C_WARN}{localized(lang, 'invalid_yes_no')}{C_RESET}")
    if ans != "y":
        print(f"{C_CYAN}{localized(lang, 'trace_save_skip')}{C_RESET}")
        return
    auto_iface = guess_default_route_interface()
    auto_s = auto_iface.strip() if isinstance(auto_iface, str) else ""
    capture_sel: Union[str, None, object]
    if auto_s:
        print(f"{C_CYAN}{localized(lang, 'trace_iface_auto', iface=auto_s)}{C_RESET}\n")
        capture_sel = auto_s
    else:
        print(f"{C_WARN}{localized(lang, 'trace_iface_auto_fail')}{C_RESET}")
        capture_sel = pick_active_interface_for_trace_save(lang)
    if capture_sel is _TRACE_IFACE_PICK_CANCELLED:
        print(f"{C_CYAN}{localized(lang, 'trace_save_skip')}{C_RESET}")
        return
    TRACE_SESSIONS_DIR.mkdir(parents=True, exist_ok=True)
    safe = re.sub(r"[^\w.\-]+", "_", target)[:72]
    iso = datetime.now().strftime("%Y%m%d_%H%M%S")
    default_name = f"trace_{safe}_{iso}.json"
    default_path = TRACE_SESSIONS_DIR / default_name
    try:
        path_raw = input(
            f"{localized(lang, 'trace_save_path', default=str(default_path))}"
        ).strip()
    except (EOFError, KeyboardInterrupt):
        print()
        print(f"{C_CYAN}{localized(lang, 'trace_save_skip')}{C_RESET}")
        return
    save_path = Path(path_raw).expanduser() if path_raw else default_path
    if save_path.parent:
        save_path.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "format": TRACE_FORMAT_V1,
        "target": target,
        "locale": lang,
        "interval_sec": interval_sec,
        "rediscover_every": rediscover_every,
        "max_hops": max_hops,
        "started_at": rounds[0].get("t") if rounds else None,
        "ended_at": datetime.now(timezone.utc).isoformat(),
        "rounds": rounds,
    }
    if isinstance(capture_sel, str) and capture_sel.strip():
        payload["capture_iface"] = capture_sel.strip()
    try:
        save_json_file(save_path, DocumentKind.TRACE_SESSION, payload)
        print(f"{C_GREEN}{localized(lang, 'trace_save_ok', path=str(save_path))}{C_RESET}")
    except OSError as e:
        print(f"{C_FAIL}{localized(lang, 'trace_save_fail', err=e)}{C_RESET}")


def load_trace_session_file(path: Path) -> Dict[str, Any]:
    return load_json_file(path, DocumentKind.TRACE_SESSION)


def replay_trace_session(
    data: Dict[str, Any],
    *,
    lang: str,
    delay_sec: float = 0.25,
    source_label: Optional[str] = None,
) -> bool:
    """Replay rounds from loaded session dict. Returns False if format invalid, True otherwise."""
    if not is_session_format_valid(data, DocumentKind.TRACE_SESSION):
        print(f"{C_FAIL}{localized(lang, 'trace_replay_bad')}{C_RESET}")
        return False
    target = data.get("target", "?")
    rounds = data.get("rounds") or []
    slab = (
        f" ({source_label})"
        if source_label
        else ""
    )
    print(
        f"{C_BOLD}{localized(lang, 'trace_replay_title', target=target, rounds=len(rounds))}{slab}{C_RESET}\n",
        flush=True,
    )

    lang_use = lang
    sess_lang = data.get("locale")
    if sess_lang in ("en", "ru"):
        lang_use = sess_lang

    cap = data.get("capture_iface")
    if isinstance(cap, str) and cap.strip():
        print(
            f"{C_CYAN}{localized(lang_use, 'trace_replay_iface', iface=cap.strip())}{C_RESET}\n",
            flush=True,
        )

    history: Dict[int, List[Optional[float]]] = {}
    sent: Dict[int, int] = {}
    okcnt: Dict[int, int] = {}

    print(f"{C_CYAN}{localized(lang_use, 'trace_replay_hint')}{C_RESET}\n")

    use_replay_dash = sys.stdout.isatty()
    interval_sec = float(data.get("interval_sec") or 3.0)
    rediscover = int(data.get("rediscover_every") or 0)
    rdash: Dict[str, Any] = {"entered": False, "hop_sig": None}

    def _parse_rtt_map(
        hops_list: List[Tuple[int, Optional[str]]],
        rtt_map: Dict[str, Any],
    ) -> Dict[int, Optional[float]]:
        out: Dict[int, Optional[float]] = {}
        for hop_num, ip in hops_list:
            if not ip:
                out[hop_num] = None
                continue
            key = str(hop_num)
            if key not in rtt_map:
                out[hop_num] = None
                continue
            raw_v = rtt_map[key]
            if raw_v is None:
                out[hop_num] = None
            else:
                out[hop_num] = float(raw_v)
        return out

    def _load_counters_from_snap(
        snap: Dict[str, Any],
        hops_list: List[Tuple[int, Optional[str]]],
    ) -> Optional[Tuple[Dict[int, int], Dict[int, int]]]:
        raw_sent = snap.get("sent")
        raw_ok = snap.get("ok")
        if not isinstance(raw_sent, dict) or not isinstance(raw_ok, dict):
            return None
        s_out = {int(k): int(v) for k, v in raw_sent.items()}
        o_out = {int(k): int(v) for k, v in raw_ok.items()}
        for hop_num, _ in hops_list:
            s_out.setdefault(hop_num, 0)
            o_out.setdefault(hop_num, 0)
        return s_out, o_out

    try:
        for snap in rounds:
            n = int(snap["n"])
            hops_raw = snap.get("hops") or []
            hops_list: List[Tuple[int, Optional[str]]] = [
                (int(h), (ip if ip is not None else None)) for h, ip in hops_raw
            ]
            rtt_parsed = _parse_rtt_map(hops_list, snap.get("rtt") or {})

            stored = _load_counters_from_snap(snap, hops_list)
            if stored is not None:
                sent, okcnt = stored
            else:
                for hop_num, ip in hops_list:
                    sent.setdefault(hop_num, 0)
                    okcnt.setdefault(hop_num, 0)
                    if not ip:
                        continue
                    sent[hop_num] += 1
                    if rtt_parsed.get(hop_num) is not None:
                        okcnt[hop_num] += 1

            for hop_num, ip in hops_list:
                history.setdefault(hop_num, [])
                if not ip:
                    history[hop_num].append(None)
                    continue
                history[hop_num].append(rtt_parsed.get(hop_num))

            if use_replay_dash:
                _emit_trace_dashboard(
                    lang_use,
                    target,
                    n,
                    hops_list,
                    history,
                    sent,
                    okcnt,
                    interval_sec=interval_sec,
                    rediscover_every=rediscover,
                    paused=False,
                    dash=rdash,
                )
            else:
                print_round_scroll(
                    lang_use, target, n, hops_list, history, sent, okcnt,
                )
            if delay_sec > 0:
                time.sleep(delay_sec)
        print(f"{C_GREEN}{localized(lang, 'trace_replay_done')}{C_RESET}")
        return True
    except KeyboardInterrupt:
        print(f"\n{C_WARN}{localized(lang, 'trace_stopped')}{C_RESET}")
        return True
    finally:
        if rdash.get("entered"):
            sys.stdout.write(ANSI_ALT_LEAVE)
            sys.stdout.flush()


def replay_trace_path(path_arg: str, *, lang: str, delay_sec: float) -> bool:
    """Load JSON and replay. Returns False on missing file / parse errors, True if replay ran."""
    p = Path(path_arg).expanduser()
    if not p.exists():
        print(f"{C_FAIL}{localized(lang, 'trace_replay_fail', err='file not found')}{C_RESET}")
        return False
    try:
        data = load_trace_session_file(p)
    except OSError as e:
        print(f"{C_FAIL}{localized(lang, 'trace_replay_fail', err=e)}{C_RESET}")
        return False
    except json.JSONDecodeError as e:
        print(f"{C_FAIL}{localized(lang, 'trace_replay_fail', err=e)}{C_RESET}")
        return False
    return bool(
        replay_trace_session(
            data, lang=lang, delay_sec=max(0.0, delay_sec), source_label=str(p)
        )
    )


def run_trace_monitor(
    host: str,
    lang: str = "en",
    interval: float = 3.0,
    max_hops: int = 30,
    rediscover_every: int = 45,
) -> None:
    """
    После traceroute пингуем все hop-IP параллельно каждый раунд (MTR-style).
    В TTY — одно «окно» (альтернативный экран) с перерисовкой таблицы; без TTY — лог.
    Управление: p — пауза, q или Ctrl+C — выход и предложение сохранить.
    """
    if shutil.which("ping") is None:
        print(f"{C_FAIL}{localized(lang, 'trace_need_ping')}{C_RESET}")
        return
    if _traceroute_bin() is None:
        print(f"{C_FAIL}{localized(lang, 'trace_need_tr')}{C_RESET}")
        return

    try:
        ipaddress.ip_address(host)
        target = host
    except ValueError:
        target = host.strip()

    print(f"{C_CYAN}{localized(lang, 'trace_discover', host=target)}{C_RESET}")
    hops = discover_hops(target, max_hops=max_hops)
    if not hops:
        print(f"{C_FAIL}{localized(lang, 'trace_no_hops')}{C_RESET}")
        return

    committed_rounds = 0
    history: Dict[int, List[Optional[float]]] = {h: [] for h, _ in hops}
    sent: Dict[int, int] = {h: 0 for h, _ in hops}
    ok: Dict[int, int] = {h: 0 for h, _ in hops}
    rounds_log: List[Dict[str, Any]] = []

    use_keys = sys.stdin.isatty() and sys.stdout.isatty()
    ctx = (
        nullcontext()
        if (_is_windows() or termios is None or not use_keys)
        else _cbreak_stdin()
    )
    ctrl = {"paused": False, "stop": False}
    resume_ctx: Dict[str, Any] = {"lang": lang, "silent_pause_msgs": use_keys}

    term_w = _terminal_columns()
    if not use_keys:
        print(f"{C_BOLD}{localized(lang, 'trace_header')} → {target}{C_RESET}")
        print(
            localized(
                lang,
                "trace_legend",
                sec=f"{interval:.1f}",
                n=rediscover_every,
            )
        )
        print(f"{C_CYAN}{localized(lang, 'trace_log_hint')}{C_RESET}")
        print(f"{'─' * min(term_w, 72)}\n", flush=True)

    dash: Dict[str, Any] = {"entered": False, "hop_sig": None}

    def apply_key(ch: Optional[str]) -> None:
        _apply_trace_key(ctrl, ch, resume_note=resume_ctx)

    try:
        with ctx:
            while not ctrl["stop"]:
                while ctrl["paused"] and not ctrl["stop"]:
                    ch = poll_key(0.08)
                    prev_p = ctrl["paused"]
                    apply_key(ch)
                    if (
                        use_keys
                        and dash.get("entered")
                        and dash.get("last_frame")
                        and (ch is not None or ctrl["paused"] != prev_p)
                    ):
                        dn, hp, hist, sn, okm = dash["last_frame"]
                        _emit_trace_dashboard(
                            lang,
                            target,
                            dn,
                            hp,
                            hist,
                            sn,
                            okm,
                            interval_sec=interval,
                            rediscover_every=rediscover_every,
                            paused=ctrl["paused"],
                            dash=dash,
                        )

                if (
                    rediscover_every > 0
                    and committed_rounds > 0
                    and committed_rounds % rediscover_every == 0
                ):
                    fresh = discover_hops(target, max_hops=max_hops)
                    if fresh:
                        hops = fresh
                        for hn, _ in hops:
                            history.setdefault(hn, [])
                            sent.setdefault(hn, 0)
                            ok.setdefault(hn, 0)

                rtt_snap: Dict[int, Optional[float]] = {}
                aborted_round = False
                while ctrl["paused"] and not ctrl["stop"]:
                    ch = poll_key(0.08)
                    prev_p = ctrl["paused"]
                    apply_key(ch)
                    if (
                        use_keys
                        and dash.get("entered")
                        and dash.get("last_frame")
                        and (ch is not None or ctrl["paused"] != prev_p)
                    ):
                        dn, hp, hist, sn, okm = dash["last_frame"]
                        _emit_trace_dashboard(
                            lang,
                            target,
                            dn,
                            hp,
                            hist,
                            sn,
                            okm,
                            interval_sec=interval,
                            rediscover_every=rediscover_every,
                            paused=ctrl["paused"],
                            dash=dash,
                        )
                if ctrl["stop"]:
                    aborted_round = True
                else:
                    ch = poll_key(0)
                    apply_key(ch)
                    if ctrl["stop"]:
                        aborted_round = True
                    else:
                        rtt_snap = ping_hops_parallel(hops)

                if aborted_round:
                    break

                committed_rounds += 1
                display_n = committed_rounds
                for hop, ip in hops:
                    history.setdefault(hop, [])
                    sent.setdefault(hop, 0)
                    ok.setdefault(hop, 0)
                    if not ip:
                        history[hop].append(None)
                        continue
                    sent[hop] += 1
                    ms = rtt_snap.get(hop)
                    if ms is not None:
                        ok[hop] += 1
                    history[hop].append(ms)

                rounds_log.append(
                    dump_round_snapshot(display_n, hops, rtt_snap, sent=sent, ok=ok)
                )
                if use_keys:
                    _emit_trace_dashboard(
                        lang,
                        target,
                        display_n,
                        hops,
                        history,
                        sent,
                        ok,
                        interval_sec=interval,
                        rediscover_every=rediscover_every,
                        paused=ctrl["paused"],
                        dash=dash,
                    )
                    dash["last_frame"] = (display_n, hops, history, sent, ok)
                else:
                    print_round_scroll(
                        lang, target, display_n, hops, history, sent, ok,
                    )

                slice_sec = 0.05
                elapsed = 0.0
                total_wait = max(0.0, interval)
                while elapsed < total_wait and not ctrl["stop"]:
                    chunk = min(slice_sec, total_wait - elapsed)
                    prev_p = ctrl["paused"]
                    ch = poll_key(chunk)
                    apply_key(ch)
                    if (
                        use_keys
                        and dash.get("entered")
                        and dash.get("last_frame")
                        and (ch is not None or ctrl["paused"] != prev_p)
                    ):
                        dn, hp, hist, sn, okm = dash["last_frame"]
                        _emit_trace_dashboard(
                            lang,
                            target,
                            dn,
                            hp,
                            hist,
                            sn,
                            okm,
                            interval_sec=interval,
                            rediscover_every=rediscover_every,
                            paused=ctrl["paused"],
                            dash=dash,
                        )
                    elapsed += chunk
                    while ctrl["paused"] and not ctrl["stop"]:
                        ch = poll_key(0.08)
                        pp = ctrl["paused"]
                        apply_key(ch)
                        if (
                            use_keys
                            and dash.get("entered")
                            and dash.get("last_frame")
                            and (ch is not None or ctrl["paused"] != pp)
                        ):
                            dn, hp, hist, sn, okm = dash["last_frame"]
                            _emit_trace_dashboard(
                                lang,
                                target,
                                dn,
                                hp,
                                hist,
                                sn,
                                okm,
                                interval_sec=interval,
                                rediscover_every=rediscover_every,
                                paused=ctrl["paused"],
                                dash=dash,
                            )

    except KeyboardInterrupt:
        ctrl["stop"] = True
        print()
    finally:
        if dash.get("entered"):
            sys.stdout.write(ANSI_ALT_LEAVE)
            sys.stdout.flush()

    print(f"{C_GREEN}{localized(lang, 'trace_stopped')}{C_RESET}")

    offer_save_trace_session(
        rounds_log,
        lang=lang,
        target=target,
        interval_sec=interval,
        rediscover_every=rediscover_every,
        max_hops=max_hops,
        interactive_tty=use_keys,
    )


def speed_http_stream_count() -> int:
    """Parallel Cloudflare HTTP streams (override with FNKIT_SPEED_STREAMS)."""
    raw = os.getenv("FNKIT_SPEED_STREAMS", "").strip()
    if raw:
        try:
            return max(1, min(16, int(raw)))
        except ValueError:
            pass
    return DEFAULT_SPEED_HTTP_STREAMS


def _split_byte_chunks(total_bytes: int, streams: int) -> List[int]:
    streams = max(1, streams)
    base = max(1, total_bytes) // streams
    rem = max(1, total_bytes) % streams
    sizes = [base + (1 if i < rem else 0) for i in range(streams)]
    return sizes


def _http_download_chunk(nbytes: int, *, timeout: float) -> int:
    url = f"{CLOUDFLARE_SPEED_DOWN}?bytes={nbytes}"
    req = urllib.request.Request(url, headers={"User-Agent": HTTP_UA})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return len(resp.read())


def _http_upload_chunk(nbytes: int, *, timeout: float) -> int:
    req = urllib.request.Request(
        CLOUDFLARE_SPEED_UP,
        data=b"\0" * nbytes,
        method="POST",
        headers={"User-Agent": HTTP_UA, "Content-Type": "application/octet-stream"},
    )
    with urllib.request.urlopen(req, timeout=timeout):
        return nbytes


def _parallel_cloudflare_transfer(
    total_bytes: int,
    *,
    direction: str,
    streams: int,
    timeout: float = 120.0,
) -> Tuple[int, float]:
    """Run download or upload across parallel HTTP streams; return (bytes, wall seconds)."""
    chunks = _split_byte_chunks(total_bytes, streams)
    worker = _http_download_chunk if direction == "down" else _http_upload_chunk
    t0 = time.perf_counter()
    transferred = 0
    with ThreadPoolExecutor(max_workers=len(chunks)) as pool:
        futures = [pool.submit(worker, size, timeout=timeout) for size in chunks]
        for fut in as_completed(futures):
            transferred += fut.result()
    return transferred, time.perf_counter() - t0


def run_speed_test(lang: str = "en", *, streams: Optional[int] = None) -> None:
    """Задержка ICMP + HTTP download/upload через speed.cloudflare.com (parallel HTTP)."""
    n_streams = streams if streams is not None else speed_http_stream_count()
    print(f"{C_BOLD}{localized(lang, 'speed_title')}{C_RESET}\n")
    print(f"{C_CYAN}{localized(lang, 'speed_parallel', n=n_streams)}{C_RESET}\n")

    ping_ip = icmp_median_ms("1.1.1.1", count=5)
    if ping_ip is not None:
        print(localized(lang, "speed_ping", target="1.1.1.1", ms=ping_ip, count=5))
    else:
        print(f"{C_WARN}{localized(lang, 'speed_ping_fail', reason='timeout / permission')}{C_RESET}")

    dl_bytes = 10_000_000
    try:
        nbytes, dt = _parallel_cloudflare_transfer(
            dl_bytes, direction="down", streams=n_streams, timeout=120.0
        )
        mb = nbytes / (1024 * 1024)
        mbps = nbytes * 8 / dt / 1_000_000 if dt > 0 else 0.0
        print(localized(lang, "speed_dl", mbps=mbps, mb=mb, sec=dt))
    except (urllib.error.URLError, OSError) as e:
        print(f"{C_FAIL}Download failed: {e}{C_RESET}")

    ul_bytes = 4_000_000
    try:
        nbytes, dt = _parallel_cloudflare_transfer(
            ul_bytes, direction="up", streams=n_streams, timeout=120.0
        )
        mb = nbytes / (1024 * 1024)
        mbps = nbytes * 8 / dt / 1_000_000 if dt > 0 else 0.0
        print(localized(lang, "speed_ul", mbps=mbps, mb=mb, sec=dt))
    except (urllib.error.URLError, OSError) as e:
        print(f"{C_FAIL}{localized(lang, 'speed_ul_fail', err=e)}{C_RESET}")

    print(f"\n{C_CYAN}{localized(lang, 'speed_footer')}{C_RESET}")


def validate_trace_host(host: str) -> bool:
    if not host or not str(host).strip():
        return False
    h = str(host).strip()
    if len(h) > 253:
        return False
    try:
        ipaddress.ip_address(h)
        return True
    except ValueError:
        pass
    if not re.match(r"^[A-Za-z0-9.\-]+$", h):
        return False
    if ".." in h or h.startswith(".") or h.endswith("."):
        return False
    return True


def _iface_kind_key(name: str) -> str:
    """Return STRINGS key suffix for iface_kind_* heuristic."""
    n = name.lower()
    if n == "lo" or n.startswith("lo:") or re.match(r"^lo\d+$", n):
        return "loopback"
    if n.startswith(("docker", "br-", "virbr", "veth", "cni", "awdl")):
        return "bridge"
    if n.startswith(("utun", "tun", "tap", "gif", "stf", "ipsec")):
        return "tunnel"
    if n.startswith(("vmnet", "vboxnet", "vethernet", "virbr")):
        return "virtual"
    if "wlan" in n or n.startswith(("wl", "wifi", "wlp", "wlan")):
        return "wifi"
    if n.startswith(("eth", "en", "em", "eno", "ens", "bond", "enx", "igb", "ix")):
        return "ethernet"
    return "other"


def _iface_kind_label(lang: str, name: str) -> str:
    key = f"iface_kind_{_iface_kind_key(name)}"
    return localized(lang, key)


def _is_iface_row_active(row: Dict[str, Any]) -> bool:
    """UP / RUNNING / ACTIVE (macOS status:) / loopback — активные; остальное — неактивное."""
    name = str(row.get("name") or "")
    st = str(row.get("state") or "").strip().upper()
    if _iface_kind_key(name) == "loopback":
        return True
    # macOS ifconfig sets e.g. "status: active" → ACTIVE; treat as up for bucketing.
    if st in ("UP", "RUNNING", "OPERATIONAL", "DORMANT", "LOWER_UP", "ACTIVE"):
        return True
    return False


def _print_iface_cards(lang: str, rows: List[Dict[str, Any]]) -> None:
    for r in rows:
        name = str(r.get("name") or "")
        print(f"{C_BOLD}{'─' * 58}{C_RESET}")
        print(f"{C_BOLD}{localized(lang, 'iface_name')}: {name}{C_RESET}")
        print(f"  {localized(lang, 'iface_kind')}: {_iface_kind_label(lang, name)}")
        print(f"  {localized(lang, 'iface_state')}: {r.get('state')}")
        mtu = r.get("mtu")
        if isinstance(mtu, int):
            print(f"  {localized(lang, 'iface_mtu')}: {mtu}")
        mac = r.get("mac")
        if mac:
            print(f"  {localized(lang, 'iface_mac')}: {mac}")
        v4 = r.get("ipv4") or []
        v6 = r.get("ipv6") or []
        if v4 or v6:
            joined = ", ".join(v4 + v6)
            if len(joined) > 220:
                joined = joined[:217] + "…"
            print(f"  {localized(lang, 'iface_ips')}: {joined}")
        else:
            print(f"  {localized(lang, 'iface_ips')}: —")
        desc = str(r.get("desc") or "").strip()
        if desc:
            print(f"  {localized(lang, 'iface_desc')}: {desc}")
        print()


def _prompt_show_inactive(lang: str) -> Optional[bool]:
    """True — показать неактивные; False — явный отказ; None — не-TTY, запрос не задавали."""
    if not (sys.stdin.isatty() and sys.stdout.isatty()):
        return None
    while True:
        try:
            ans = input(f"{C_WARN}{localized(lang, 'iface_prompt_inactive')}{C_RESET}").strip().lower()
        except (EOFError, KeyboardInterrupt):
            print()
            return False
        if ans == "y":
            return True
        if ans == "n":
            return False
        print(f"{C_WARN}{localized(lang, 'invalid_yes_no')}{C_RESET}")


def _wait_zero_main_menu(lang: str) -> None:
    """После просмотра активных/неактивных — только 0 возвращает в главное меню (TTY)."""
    if not (sys.stdin.isatty() and sys.stdout.isatty()):
        return
    while True:
        try:
            ans = input(f"{C_WARN}{localized(lang, 'iface_press_zero')}{C_RESET}").strip()
        except (EOFError, KeyboardInterrupt):
            print()
            return
        if ans == "0":
            return
        print(f"{C_WARN}{localized(lang, 'iface_press_zero_invalid')}{C_RESET}")


def print_network_interfaces(lang: str = "en") -> None:
    """Сначала активные интерфейсы; по y/n — опционально неактивные."""
    lang = lang if lang in STRINGS else "en"
    rows = gather_interface_rows()

    if not rows:
        print(f"{C_BOLD}{localized(lang, 'iface_title')}{C_RESET}\n")
        print(f"{C_CYAN}{localized(lang, 'iface_hint')}{C_RESET}\n")
        print(f"{C_WARN}{localized(lang, 'iface_none')}{C_RESET}")
        return

    active = [r for r in rows if _is_iface_row_active(r)]
    inactive = [r for r in rows if not _is_iface_row_active(r)]

    print(f"{C_BOLD}{localized(lang, 'iface_title')}{C_RESET}\n")
    print(f"{C_CYAN}{localized(lang, 'iface_hint')}{C_RESET}\n")

    if not active:
        print(f"{C_WARN}{localized(lang, 'iface_no_active_bucket')}{C_RESET}\n")
        _print_iface_cards(lang, rows)
        return

    print(f"{C_BOLD}{localized(lang, 'iface_section_active')}{C_RESET}\n")
    _print_iface_cards(lang, active)

    if not inactive:
        return

    choice = _prompt_show_inactive(lang)
    if choice is False:
        print(f"{C_CYAN}{localized(lang, 'iface_skip_inactive')}{C_RESET}\n")
        _wait_zero_main_menu(lang)
        return
    if choice is None:
        return

    print(f"\n{C_BOLD}{localized(lang, 'iface_section_inactive')}{C_RESET}\n")
    _print_iface_cards(lang, inactive)
    _wait_zero_main_menu(lang)


def _run_cmd_json(cmd: Sequence[str], timeout: float = 20.0) -> Optional[Any]:
    try:
        proc = subprocess.run(
            list(cmd),
            capture_output=True,
            text=True,
            timeout=timeout,
            errors="replace",
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    if proc.returncode != 0 or not (proc.stdout or "").strip():
        return None
    try:
        return json.loads(proc.stdout)
    except json.JSONDecodeError:
        return None


def _linux_interfaces_ip_json() -> Optional[List[Dict[str, Any]]]:
    data = _run_cmd_json(["ip", "-json", "addr", "show"], timeout=25.0)
    if not isinstance(data, list):
        return None
    rows: List[Dict[str, Any]] = []
    for item in data:
        if not isinstance(item, dict):
            continue
        name = str(item.get("ifname") or "").strip()
        if not name:
            continue
        oper = str(item.get("operstate") or "unknown")
        mtu = item.get("mtu")
        linkinfo = item.get("linkinfo")
        info_kind = ""
        if isinstance(linkinfo, dict):
            info_kind = str(linkinfo.get("info_kind") or "").strip()
        link_type = str(item.get("link_type") or info_kind or "").strip()
        addrs = item.get("addr_info") or []
        v4: List[str] = []
        v6: List[str] = []
        mac = str(item.get("address") or "").strip()
        if isinstance(addrs, list):
            for a in addrs:
                if not isinstance(a, dict):
                    continue
                fam = str(a.get("family") or "")
                loc = str(a.get("local") or a.get("address") or "").strip()
                if not loc:
                    continue
                plen = a.get("prefixlen")
                suf = f"/{plen}" if plen is not None else ""
                if fam == "inet":
                    v4.append(loc + suf)
                elif fam == "inet6":
                    if loc.startswith("fe80:"):
                        v6.append(loc + suf + " (link-local)")
                    else:
                        v6.append(loc + suf)
        desc_parts: List[str] = []
        if link_type:
            desc_parts.append(link_type)
        rows.append(
            {
                "name": name,
                "state": oper.upper(),
                "mtu": mtu if isinstance(mtu, int) else None,
                "mac": mac or None,
                "ipv4": v4,
                "ipv6": v6[:6],
                "desc": " · ".join(desc_parts) if desc_parts else "",
            }
        )
    rows.sort(key=lambda r: r["name"])
    return rows or None


def _linux_interfaces_sys_fallback() -> List[Dict[str, Any]]:
    base = Path("/sys/class/net")
    if not base.is_dir():
        return []
    rows: List[Dict[str, Any]] = []
    for child in sorted(base.iterdir(), key=lambda p: p.name):
        if not child.is_dir():
            continue
        name = child.name
        try:
            addr = (child / "address").read_text(encoding="utf-8", errors="replace").strip()
        except OSError:
            addr = ""
        try:
            oper = (child / "operstate").read_text(encoding="utf-8", errors="replace").strip()
        except OSError:
            oper = "unknown"
        mtu_val: Optional[int] = None
        try:
            mtu_raw = (child / "mtu").read_text(encoding="utf-8", errors="replace").strip()
            mtu_val = int(mtu_raw)
        except (OSError, ValueError):
            pass
        rows.append(
            {
                "name": name,
                "state": oper.upper(),
                "mtu": mtu_val,
                "mac": addr or None,
                "ipv4": [],
                "ipv6": [],
                "desc": "",
            }
        )
    return rows


def _parse_ifconfig_blocks(text: str) -> List[Dict[str, Any]]:
    """Parse BSD/macOS-style `ifconfig -a` into interface dicts."""
    rows: List[Dict[str, Any]] = []
    cur: Optional[Dict[str, Any]] = None
    for raw in text.splitlines():
        line = raw.rstrip()
        if not line:
            continue
        if not line[0].isspace():
            m = re.match(r"^([^:\s]+):\s", line)
            if not m:
                continue
            name = m.group(1)
            cur = {
                "name": name,
                "state": "UNKNOWN",
                "mtu": None,
                "mac": None,
                "ipv4": [],
                "ipv6": [],
                "desc": "",
            }
            rows.append(cur)
            mm = re.search(r"\bmtu\s+(\d+)", line)
            if mm:
                cur["mtu"] = int(mm.group(1))
            if "LOOPBACK" in line.upper():
                cur["desc"] = "LOOPBACK"
            if "RUNNING" in line.upper():
                cur["state"] = "RUNNING"
            if "UP" in line.upper() and "<" in line and "UP" in line.upper():
                cur["state"] = "UP"
        elif cur is not None:
            s = line.strip()
            if s.startswith("inet "):
                m = re.search(r"\binet\s+(\d{1,3}(?:\.\d{1,3}){3})\b", s)
                if m:
                    cur["ipv4"].append(m.group(1))
            elif s.startswith("inet6 "):
                m = re.search(r"\binet6\s+([0-9a-fA-F:]+)%?\S*", s)
                if m:
                    cur["ipv6"].append(m.group(1))
            elif s.startswith("ether "):
                m = re.search(r"\b([0-9a-fA-F:]{11,})\b", s)
                if m:
                    cur["mac"] = m.group(1)
            elif s.startswith("status: "):
                cur["state"] = s.split(":", 1)[1].strip().upper()
    return rows


def _macos_interfaces_ifconfig() -> List[Dict[str, Any]]:
    if not shutil.which("ifconfig"):
        return []
    try:
        proc = subprocess.run(
            ["ifconfig", "-a"],
            capture_output=True,
            text=True,
            timeout=30,
            errors="replace",
        )
    except (OSError, subprocess.TimeoutExpired):
        return []
    out = proc.stdout or ""
    return _parse_ifconfig_blocks(out)


def _windows_interfaces_ps() -> List[Dict[str, Any]]:
    ps = shutil.which("powershell.exe") or shutil.which("pwsh.exe")
    if not ps:
        return []
    script = (
        "$a = Get-NetAdapter | Select-Object Name,InterfaceDescription,ifIndex,Status,"
        "MacAddress,InterfaceType,MediaType,LinkSpeed;"
        "$b = Get-NetIPAddress -AddressFamily IPv4 | Select-Object InterfaceIndex,IPAddress,PrefixLength;"
        "$c = Get-NetIPAddress -AddressFamily IPv6 | Select-Object InterfaceIndex,IPAddress,PrefixLength;"
        "@{ adapters = @($a); ipv4 = @($b); ipv6 = @($c) } | ConvertTo-Json -Depth 8 -Compress"
    )
    try:
        proc = subprocess.run(
            [ps, "-NoProfile", "-Command", script],
            capture_output=True,
            text=True,
            timeout=45,
            errors="replace",
        )
    except (OSError, subprocess.TimeoutExpired):
        return []
    if proc.returncode != 0 or not (proc.stdout or "").strip():
        return []
    try:
        root = json.loads(proc.stdout)
    except json.JSONDecodeError:
        return []
    adapters = root.get("adapters") or []
    if isinstance(adapters, dict):
        adapters = [adapters]
    ipv4_list = root.get("ipv4") or []
    if isinstance(ipv4_list, dict):
        ipv4_list = [ipv4_list]
    ipv6_list = root.get("ipv6") or []
    if isinstance(ipv6_list, dict):
        ipv6_list = [ipv6_list]
    v4_map: Dict[int, List[str]] = {}
    for row in ipv4_list:
        if not isinstance(row, dict):
            continue
        idx = row.get("InterfaceIndex")
        if idx is None:
            continue
        ip = str(row.get("IPAddress") or "").strip()
        pl = row.get("PrefixLength")
        if not ip:
            continue
        suf = f"/{pl}" if pl is not None else ""
        v4_map.setdefault(int(idx), []).append(ip + suf)
    v6_map: Dict[int, List[str]] = {}
    for row in ipv6_list:
        if not isinstance(row, dict):
            continue
        idx = row.get("InterfaceIndex")
        if idx is None:
            continue
        ip = str(row.get("IPAddress") or "").strip()
        pl = row.get("PrefixLength")
        if not ip or ip.startswith("fe80:"):
            continue
        suf = f"/{pl}" if pl is not None else ""
        v6_map.setdefault(int(idx), []).append(ip + suf)
    rows: List[Dict[str, Any]] = []
    for ad in adapters:
        if not isinstance(ad, dict):
            continue
        name = str(ad.get("Name") or "").strip()
        if not name:
            continue
        idx = ad.get("ifIndex")
        desc = str(ad.get("InterfaceDescription") or "").strip()
        status = str(ad.get("Status") or "").strip().upper()
        mac = str(ad.get("MacAddress") or "").strip() or None
        media = str(ad.get("MediaType") or "").strip()
        itype = str(ad.get("InterfaceType") or "").strip()
        speed = ad.get("LinkSpeed")
        extra = " · ".join(x for x in (itype, media, str(speed) if speed else "") if x)
        iidx = int(idx) if idx is not None else -1
        rows.append(
            {
                "name": name,
                "state": status or "UNKNOWN",
                "mtu": None,
                "mac": mac,
                "ipv4": v4_map.get(iidx, []) if iidx >= 0 else [],
                "ipv6": (v6_map.get(iidx, []) or [])[:6],
                "desc": extra or desc,
            }
        )
    rows.sort(key=lambda r: r["name"])
    return rows
