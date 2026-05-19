#!/usr/bin/env python3
"""
PCAP: проверка файла, краткая статистика (classic pcap), просмотр как в Wireshark (tshark/tcpdump),
захват в .pcap через tcpdump (права root / BPF на интерфейсе обычно обязательны).
"""

from __future__ import annotations

import hashlib
import re
import shlex
import signal
import shutil
import struct
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from paths import NETWORK_CAPTURE_DIR

# Цвета согласованы с network_diag
C_RESET = "\033[0m"
C_BOLD = "\033[1m"
C_CYAN = "\033[96m"
C_GREEN = "\033[92m"
C_WARN = "\033[93m"
C_FAIL = "\033[91m"
C_DIM = "\033[2m"

PCAPNG_SHB = 0x0A0D0D0A
# Classic libpcap: first uint32 read as "<I" from file (same convention as libpcap on LE hosts).
PCAP_MAGIC_LE_USEC = 0xA1B2C3D4  # file often starts d4 c3 b2 a1 (tcpdump -w on macOS/Linux)
PCAP_MAGIC_BE_USEC = 0xD4C3B2A1  # swapped microsecond (file starts a1 b2 c3 d4)
PCAP_MAGIC_LE_NSEC = 0x4D3C2B1A
PCAP_MAGIC_BE_NSEC = 0x1A2B3C4D

DLT_NAMES: Dict[int, str] = {
    0: "DLT_NULL",
    1: "Ethernet",
    6: "Token Ring",
    9: "DLT_PPP",
    12: "Raw IP",
    101: "Raw IP (Linux)",
    108: "DLT_LOOP",
    113: "Linux cooked v1",
    127: "IEEE 802.11",
    276: "Linux cooked v2",
}

# Максимум записей пакетов при обходе classic PCAP (скорость / память).
CLASSIC_PCAP_SCAN_PACKET_CAP = 2_000_000

STRINGS: Dict[str, Dict[str, str]] = {
    "en": {
        "pcap_title_check": "PCAP file check",
        "pcap_title_show": "PCAP decode (Wireshark-style view)",
        "pcap_title_capture": "Live capture → {path}",
        "pcap_not_found": "File not found: {path}",
        "pcap_empty": "File is empty.",
        "pcap_valid_classic": "Format: classic pcap ({endian}, {ts})  link: {link} ({lt})",
        "pcap_valid_ng": "Format: PCAPNG (full statistics: use Wireshark/tshark)",
        "pcap_invalid": "Not a recognizable pcap/pcapng file.",
        "pcap_truncated": "Truncated / corrupt ({detail}).",
        "pcap_identity_title": "File fingerprint",
        "pcap_identity_path": "Path: {path}",
        "pcap_identity_size": "Size on disk: {size} bytes (~{mb:.3f} MiB)",
        "pcap_identity_sha256": "SHA-256: {sha}",
        "pcap_identity_sha_note": "  Same bytes → same hash; any edit or corruption changes it (handy for logs, tickets, or hand-off).",
        "pcap_expl_title": "What the numbers mean (quick structural read, not full protocol decode):",
        "pcap_expl_format": "• Container — classic PCAP (tcpdump/Wireshark compatible). Timestamps are stored with {ts} resolution; header fields use {endian} byte order.",
        "pcap_expl_link": "• Link type DLT {lt} ({link}) — how each frame’s raw bytes are interpreted at layer 2.",
        "pcap_expl_packets": "• Packets scanned: {n} — records read in this pass (safety cap {cap}; if the file has more packets, this number can be lower).",
        "pcap_expl_span": "• Time span {span} — last minus first capture timestamp among scanned packets (capture clock from the file, not “saved at” wall time).",
        "pcap_expl_snap": "• First stored length ~{slen} B — bytes stored for the first frame; may be less than on-wire if snaplen truncates.",
        "pcap_expl_ng_extra": "• PCAPNG — frame-level decode needs Wireshark/tshark; here we only confirm the container.",
        "pcap_scan_capped": "Note: scan stopped at the {cap}-packet cap; total packets in the file may be higher.",
        "pcap_endian_LE": "little-endian (LE)",
        "pcap_endian_BE": "big-endian (BE)",
        "pcap_need_tool": "Install Wireshark CLI (tshark) or tcpdump for packet listing.",
        "pcap_need_tcpdump_cap": "tcpdump not found — cannot capture.",
        "pcap_capture_hint": "Often requires sudo/root or «authorized» capture on macOS.",
        "pcap_capture_saved": "Capture finished → {path} ({hint})",
        "pcap_capture_err": "Capture failed or tcpdump exited early: {err}",
        "pcap_tshark_failed": "tshark failed ({code}). Trying tcpdump -r …",
        "pcap_filter_invalid": "Invalid BPF filter quoting.",
        "pcap_need_iface_out": "--pcap-capture needs --pcap-out and interface.",
    },
    "ru": {
        "pcap_title_check": "Проверка PCAP",
        "pcap_title_show": "Разбор PCAP (вид как в Wireshark)",
        "pcap_title_capture": "Захват в файл → {path}",
        "pcap_not_found": "Файл не найден: {path}",
        "pcap_empty": "Файл пустой.",
        "pcap_valid_classic": "Формат: classic pcap ({endian}, {ts})  канал: {link} ({lt})",
        "pcap_valid_ng": "Формат: PCAPNG (полная статистика — Wireshark/tshark)",
        "pcap_invalid": "Не похоже на pcap/pcapng.",
        "pcap_truncated": "Обрезан или повреждён ({detail}).",
        "pcap_identity_title": "Идентификация файла",
        "pcap_identity_path": "Путь: {path}",
        "pcap_identity_size": "Размер на диске: {size} байт (~{mb:.3f} МиБ)",
        "pcap_identity_sha256": "SHA-256: {sha}",
        "pcap_identity_sha_note": "  Один и тот же файл → тот же хэш; любое изменение байтов → другой хэш (целостность, тикеты, передача копии).",
        "pcap_expl_title": "Что означают строки ниже (быстрая структурная проверка, без разбора протоколов):",
        "pcap_expl_format": "• Контейнер — classic PCAP (как у tcpdump/Wireshark). Метки времени с точностью {ts}; поля заголовка в порядке байт {endian}.",
        "pcap_expl_link": "• Тип канала DLT {lt} ({link}) — как интерпретировать сырые байты кадра на 2-м уровне.",
        "pcap_expl_packets": "• Пакетов просмотрено: {n} — записей прочитано за этот проход (ограничение {cap}; если в файле больше записей, число может быть меньше).",
        "pcap_expl_span": "• Интервал {span} — разница между последней и первой меткой времени среди просмотренных пакетов (часы захвата из файла, не время сохранения на диск).",
        "pcap_expl_snap": "• Длина первого cap ~{slen} Б — сколько байт первого кадра реально записано в файл; может быть меньше «на проводе», если сработал snaplen.",
        "pcap_expl_ng_extra": "• PCAPNG — разбор полей кадров нужен в Wireshark/tshark; здесь только подтверждение типа контейнера.",
        "pcap_scan_capped": "Внимание: достигнут лимит обхода {cap} записей; всего пакетов в файле может быть больше.",
        "pcap_endian_LE": "от младшего байта к старшему (LE)",
        "pcap_endian_BE": "от старшего байта к младшему (BE)",
        "pcap_need_tool": "Нужен tshark (Wireshark CLI) или tcpdump для списка пакетов.",
        "pcap_need_tcpdump_cap": "tcpdump не найден — захват недоступен.",
        "pcap_capture_hint": "Обычно нужны root/sudo или разрешение на захват в macOS.",
        "pcap_capture_saved": "Захват завершён → {path} ({hint})",
        "pcap_capture_err": "Ошибка захвата или ранний выход tcpdump: {err}",
        "pcap_tshark_failed": "tshark завершился с кодом {code}. Пробуем tcpdump -r …",
        "pcap_filter_invalid": "Некорректное BPF-выражение.",
        "pcap_need_iface_out": "Для --pcap-capture нужны --pcap-out и интерфейс.",
    },
}


def msg(lang: str, key: str, **kwargs: Any) -> str:
    return STRINGS.get(lang, STRINGS["en"]).get(key, key).format(**kwargs)


def network_capture_dir() -> Path:
    return NETWORK_CAPTURE_DIR


def ensure_network_capture_dir() -> None:
    NETWORK_CAPTURE_DIR.mkdir(parents=True, exist_ok=True)


def default_capture_out_path() -> Path:
    ensure_network_capture_dir()
    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    return NETWORK_CAPTURE_DIR / f"capture_{stamp}.pcap"


def list_network_capture_files(limit: int = 100) -> List[Path]:
    d = NETWORK_CAPTURE_DIR
    if not d.is_dir():
        return []
    allowed = {".pcap", ".cap", ".pcapng", ".dmp"}
    found = [p for p in d.iterdir() if p.is_file() and p.suffix.lower() in allowed]
    found.sort(key=lambda x: x.stat().st_mtime, reverse=True)
    return found[:limit]


def _read_u32_be(b: bytes, off: int = 0) -> int:
    return struct.unpack_from(">I", b, off)[0]


def analyze_classic_pcap(
    path: Path, max_packets: int = CLASSIC_PCAP_SCAN_PACKET_CAP
) -> Tuple[Dict[str, Any], Optional[str]]:
    """
    Разбор classic pcap (без внешних библиотек). Возвращает (info, error_or_none).
    error_or_none=None если magic не classic pcap — вызывающий трактует как другой формат.
    """
    info: Dict[str, Any] = {
        "format": "pcap",
        "packet_count": 0,
        "first_ts": None,
        "last_ts": None,
        "first_snaplen": None,
        "linktype": None,
        "endian": None,
        "ts_resolution": "μs",
        "scan_cap": max_packets,
    }
    try:
        with path.open("rb") as f:
            gh = f.read(24)
            if len(gh) < 24:
                return info, "global header"
            m = struct.unpack_from("<I", gh, 0)[0]
            if m == PCAP_MAGIC_LE_USEC:
                endian, ts_mul = "<", 1e-6
                info["endian"] = "LE"
            elif m == PCAP_MAGIC_BE_USEC:
                endian, ts_mul = ">", 1e-6
                info["endian"] = "BE"
            elif m == PCAP_MAGIC_LE_NSEC:
                endian, ts_mul = "<", 1e-9
                info["endian"] = "LE"
                info["ts_resolution"] = "ns"
            elif m == PCAP_MAGIC_BE_NSEC:
                endian, ts_mul = ">", 1e-9
                info["endian"] = "BE"
                info["ts_resolution"] = "ns"
            else:
                return info, None

            struct.unpack_from(endian + "HH", gh, 4)
            struct.unpack_from(endian + "II", gh, 8)
            struct.unpack_from(endian + "I", gh, 16)[0]
            linktype = struct.unpack_from(endian + "I", gh, 20)[0]
            info["linktype"] = linktype

            n = 0
            while n < max_packets:
                ph = f.read(16)
                if len(ph) == 0:
                    break
                if len(ph) < 16:
                    return info, "packet header"
                ts_sec, ts_frac, incl_len, _orig_len = struct.unpack(endian + "IIII", ph)
                pkt_off = ts_sec + ts_frac * ts_mul
                chunk = f.read(incl_len)
                if len(chunk) < incl_len:
                    return info, "packet payload"
                if n == 0:
                    info["first_ts"] = pkt_off
                    info["first_snaplen"] = incl_len
                info["last_ts"] = pkt_off
                n += 1
            info["packet_count"] = n
            info["truncated_by_limit"] = n >= max_packets
            return info, ""
    except OSError as e:
        return info, str(e)


def _sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as bf:
        for block in iter(lambda: bf.read(1 << 20), b""):
            h.update(block)
    return h.hexdigest()


def _print_pcap_identity_block(path: Path, lang: str) -> None:
    sz = path.stat().st_size
    mb = sz / (1024 * 1024)
    sha = _sha256_file(path)
    print(f"{C_BOLD}{msg(lang, 'pcap_identity_title')}{C_RESET}")
    print(f"{C_CYAN}{msg(lang, 'pcap_identity_path', path=str(path))}{C_RESET}")
    print(msg(lang, "pcap_identity_size", size=sz, mb=mb))
    print(f"{C_GREEN}{msg(lang, 'pcap_identity_sha256', sha=sha)}{C_RESET}")
    print(f"{C_DIM}{msg(lang, 'pcap_identity_sha_note')}{C_RESET}\n")


def check_pcap_file(path: Path, lang: str = "en") -> int:
    """Печать результата проверки. Код выхода 0 если файл валиден."""
    print(f"{C_BOLD}{msg(lang, 'pcap_title_check')}{C_RESET}\n")
    if not path.exists():
        print(f"{C_FAIL}{msg(lang, 'pcap_not_found', path=path)}{C_RESET}")
        return 2
    if path.stat().st_size == 0:
        print(f"{C_FAIL}{msg(lang, 'pcap_empty')}{C_RESET}")
        return 2

    rp = path.expanduser().resolve()
    _print_pcap_identity_block(rp, lang)

    with rp.open("rb") as f:
        head = f.read(32)

    if len(head) < 4:
        print(f"{C_FAIL}{msg(lang, 'pcap_invalid')}{C_RESET}")
        return 2

    first32 = struct.unpack_from("<I", head, 0)[0]
    if first32 == PCAPNG_SHB:
        print(f"{C_GREEN}{msg(lang, 'pcap_valid_ng')}{C_RESET}")
        print(f"{C_DIM}{msg(lang, 'pcap_expl_ng_extra')}{C_RESET}\n")
        _pcapng_stats_tshark(rp, lang)
        return 0

    info, err = analyze_classic_pcap(rp)
    if err is None:
        print(f"{C_FAIL}{msg(lang, 'pcap_invalid')}{C_RESET}")
        return 2
    if err != "":
        print(f"{C_FAIL}{msg(lang, 'pcap_truncated', detail=err)}{C_RESET}")
        return 2
    if info.get("linktype") is None:
        print(f"{C_FAIL}{msg(lang, 'pcap_invalid')}{C_RESET}")
        return 2

    lt = info["linktype"]
    link_name = DLT_NAMES.get(lt, f"DLT_{lt}")
    print(
        f"{C_GREEN}{msg(lang, 'pcap_valid_classic', endian=info['endian'], ts=info['ts_resolution'], link=link_name, lt=lt)}{C_RESET}\n"
    )

    ed = (
        msg(lang, "pcap_endian_LE")
        if info.get("endian") == "LE"
        else msg(lang, "pcap_endian_BE")
    )
    cap = int(info.get("scan_cap") or CLASSIC_PCAP_SCAN_PACKET_CAP)

    n = info["packet_count"]
    first = info["first_ts"]
    last = info["last_ts"]
    span = "—"
    if first is not None and last is not None:
        span = f"{last - first:.6f} s"
    slen = int(info.get("first_snaplen") or 0)

    print(f"{C_DIM}{msg(lang, 'pcap_expl_title')}{C_RESET}")
    print(
        f"{C_DIM}{msg(lang, 'pcap_expl_format', ts=info.get('ts_resolution') or '?', endian=ed)}{C_RESET}"
    )
    print(f"{C_DIM}{msg(lang, 'pcap_expl_link', lt=lt, link=link_name)}{C_RESET}")
    print(f"{C_DIM}{msg(lang, 'pcap_expl_packets', n=n, cap=cap)}{C_RESET}")
    print(f"{C_DIM}{msg(lang, 'pcap_expl_span', span=span)}{C_RESET}")
    print(f"{C_DIM}{msg(lang, 'pcap_expl_snap', slen=slen)}{C_RESET}\n")

    if info.get("truncated_by_limit"):
        print(f"{C_WARN}{msg(lang, 'pcap_scan_capped', cap=cap)}{C_RESET}")
    return 0


def _pcapng_stats_tshark(path: Path, lang: str) -> None:
    tshark = shutil.which("tshark")
    if not tshark:
        return
    try:
        proc = subprocess.run(
            [tshark, "-r", str(path), "-q", "-z", "io,stat,0"],
            capture_output=True,
            text=True,
            timeout=120,
            errors="replace",
        )
        out = (proc.stdout or "").strip()
        if out:
            print(f"\n{C_CYAN}{out}{C_RESET}")
    except (subprocess.TimeoutExpired, OSError):
        pass


# tcpdump -r default line: HH:MM:SS.us PROTO payload…
_TCPDUMP_SUMMARY_LINE_RE = re.compile(
    r"^(\d{1,2}:\d{2}:\d{2}\.\d+)\s+(\S+)\s+(.*)$"
)
_READING_FROM_RE = re.compile(
    r"^(reading from file)\s+(.+?),\s*(link-type\s+.+)$",
    re.IGNORECASE,
)


def _terminal_columns() -> int:
    try:
        return max(48, shutil.get_terminal_size(fallback=(100, 24)).columns)
    except OSError:
        return 100


def _print_tcpdump_summary_pretty(stdout: str) -> None:
    """Цветной вывод tcpdump -nn -r (время / протокол / детали, усечение по ширине)."""
    cols = _terminal_columns()
    bar_w = min(max(cols - 2, 40), 88)
    bar = "─" * bar_w
    print(f"\n{C_CYAN}{bar}{C_RESET}")
    print(
        f"{C_BOLD}tcpdump{C_RESET} {C_DIM}−nn −r{C_RESET}  "
        f"{C_CYAN}· packet summary{C_RESET}"
    )
    print(f"{C_CYAN}{bar}{C_RESET}\n")

    for raw in (stdout or "").splitlines():
        line = raw.rstrip("\r")
        if not line:
            continue
        rm = _READING_FROM_RE.match(line)
        if rm:
            print(
                f"{C_DIM}{rm.group(1)}{C_RESET} {C_BOLD}{C_CYAN}{rm.group(2)}{C_RESET}"
                f"{C_DIM}, {rm.group(3)}{C_RESET}"
            )
            continue
        pm = _TCPDUMP_SUMMARY_LINE_RE.match(line)
        if not pm:
            print(f"{C_DIM}{line}{C_RESET}")
            continue
        ts, proto, rest = pm.group(1), pm.group(2), pm.group(3)
        overhead = len(ts) + len(proto) + 6
        max_rest = max(36, cols - overhead)
        rest_show = rest if len(rest) <= max_rest else rest[: max_rest - 1] + "…"
        print(
            f"{C_WARN}{ts}{C_RESET}  "
            f"{C_BOLD}{C_GREEN}{proto}{C_RESET}  "
            f"{rest_show}"
        )

    print(f"\n{C_CYAN}{bar}{C_RESET}\n")


def show_pcap_file(
    path: Path,
    lang: str = "en",
    max_packets: int = 80,
    hex_dump: bool = False,
) -> int:
    """Декодирование пакетов в терминал (tshark или tcpdump -r)."""
    print(f"{C_BOLD}{msg(lang, 'pcap_title_show')}{C_RESET}\n")
    if not path.exists():
        print(f"{C_FAIL}{msg(lang, 'pcap_not_found', path=path)}{C_RESET}")
        return 2

    tshark = shutil.which("tshark")
    tcpdump_r = shutil.which("tcpdump")

    cap = max(1, min(int(max_packets), 50_000))
    if tshark:
        args: List[str] = [tshark, "-r", str(path), "-n", "-c", str(cap)]
        if hex_dump:
            args.append("-x")
        else:
            args.extend(
                [
                    "-T",
                    "fields",
                    "-E",
                    "separator=\t",
                    "-e",
                    "frame.number",
                    "-e",
                    "frame.time_relative",
                    "-e",
                    "ip.src",
                    "-e",
                    "ip.dst",
                    "-e",
                    "ipv6.src",
                    "-e",
                    "ipv6.dst",
                    "-e",
                    "frame.len",
                    "-e",
                    "_ws.col.Protocol",
                    "-e",
                    "_ws.col.Info",
                ]
            )
        if not hex_dump:
            print(
                f"{C_CYAN}# frame # / t_rel / ip / len / proto / info (tshark -T fields){C_RESET}\n"
            )
        try:
            proc = subprocess.run(
                args,
                capture_output=False,
                text=True,
                timeout=300,
                errors="replace",
            )
            if proc.returncode == 0:
                return 0
            print(f"{C_WARN}{msg(lang, 'pcap_tshark_failed', code=proc.returncode)}{C_RESET}")
        except (subprocess.TimeoutExpired, OSError) as e:
            print(f"{C_WARN}{msg(lang, 'pcap_tshark_failed', code=e)}{C_RESET}")

    if tcpdump_r:
        try:
            proc = subprocess.run(
                [tcpdump_r, "-nn", "-r", str(path), "-c", str(cap)],
                capture_output=True,
                text=True,
                timeout=300,
                errors="replace",
                check=False,
            )
            _print_tcpdump_summary_pretty(proc.stdout or "")
            err = (proc.stderr or "").strip()
            if err:
                print(f"{C_DIM}{err}{C_RESET}")
            return 0
        except (subprocess.TimeoutExpired, OSError):
            pass

    print(f"{C_FAIL}{msg(lang, 'pcap_need_tool')}{C_RESET}")
    return 1


def _stop_tcpdump_gracefully(proc: Optional[subprocess.Popen]) -> None:
    """
    Завершить tcpdump так, чтобы файл -w успел корректно закрыться.
    SIGINT (как Ctrl+C) даёт libpcap дописать заголовок/трейлер; SIGTERM часто
    оставляет обрезанный файл → проверка «не похоже на pcap/pcapng».
    """
    if proc is None or proc.poll() is not None:
        return
    try:
        if sys.platform == "win32":
            proc.terminate()
            proc.wait(timeout=12)
            return
        proc.send_signal(signal.SIGINT)
        try:
            proc.wait(timeout=12)
        except subprocess.TimeoutExpired:
            proc.terminate()
            try:
                proc.wait(timeout=4)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait(timeout=3)
    except OSError:
        try:
            proc.kill()
        except OSError:
            pass


def capture_pcap(
    interface: str,
    outfile: Path,
    lang: str = "en",
    duration_sec: float = 10.0,
    bpf_filter: Optional[str] = None,
) -> int:
    """Захват через tcpdump -w (остановка по таймеру, корректное закрытие файла)."""
    print(
        f"{C_BOLD}{msg(lang, 'pcap_title_capture', path=outfile)}{C_RESET}\n"
        f"{C_WARN}{msg(lang, 'pcap_capture_hint')}{C_RESET}\n"
    )
    tcpdump = shutil.which("tcpdump")
    if not tcpdump:
        print(f"{C_FAIL}{msg(lang, 'pcap_need_tcpdump_cap')}{C_RESET}")
        return 1

    outfile = Path(outfile).expanduser()
    outfile.parent.mkdir(parents=True, exist_ok=True)

    cmd: List[str] = [tcpdump, "-i", interface, "-U", "-w", str(outfile)]
    if bpf_filter:
        try:
            cmd.extend(shlex.split(bpf_filter, posix=sys.platform != "win32"))
        except ValueError:
            print(f"{C_FAIL}{msg(lang, 'pcap_filter_invalid')}{C_RESET}")
            return 2

    dur = max(1.0, min(float(duration_sec), 3600.0))
    proc: Optional[subprocess.Popen] = None
    try:
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            text=True,
            errors="replace",
        )
        t0 = time.monotonic()
        while time.monotonic() - t0 < dur:
            ret = proc.poll()
            if ret is not None:
                print(
                    f"{C_FAIL}{msg(lang, 'pcap_capture_err', err=f'exit {ret} (try sudo or check interface name)')}{C_RESET}"
                )
                return 1
            time.sleep(0.2)
    except KeyboardInterrupt:
        print(f"\n{C_WARN}Interrupted.{C_RESET}")
    except OSError as e:
        print(f"{C_FAIL}{msg(lang, 'pcap_capture_err', err=e)}{C_RESET}")
        return 1
    finally:
        if proc is not None:
            _stop_tcpdump_gracefully(proc)

    time.sleep(0.08)
    size = outfile.stat().st_size if outfile.exists() else 0
    if size <= 24:
        print(
            f"{C_FAIL}{msg(lang, 'pcap_capture_err', err='empty or too small file (permission or wrong interface?)')}{C_RESET}"
        )
        return 1

    print(f"\n{C_GREEN}{msg(lang, 'pcap_capture_saved', path=outfile, hint=f'{size} bytes')}{C_RESET}")
    rc = check_pcap_file(outfile, lang=lang)
    if rc == 0:
        show_pcap_file(
            outfile,
            lang=lang,
            max_packets=min(40, max(10, int(dur))),
            hex_dump=False,
        )
    return rc


def validate_capture_interface(name: str) -> bool:
    n = name.strip()
    return 0 < len(n) <= 255 and "\x00" not in n and "\r" not in n and "\n" not in n


def validate_bpf_relaxed(s: Optional[str]) -> bool:
    if s is None or not str(s).strip():
        return True
    try:
        shlex.split(s, posix=sys.platform != "win32")
        return True
    except ValueError:
        return False


def sanitize_out_path(p: str) -> Optional[Path]:
    s = str(p).strip()
    if not s:
        return None
    return Path(s).expanduser()
