#!/usr/bin/env python3
"""
OWASP toolkit bridge for FieldNet Kit / FNkit (menu 11).

License model (see docs/OWASP_THIRD_PARTY.md):
  - This file is MIT (same as FieldNet Kit). It does NOT bundle Amass, Nettacker, WSTG, or Secure Headers content.
  - Amass / Nettacker: optional external CLIs invoked via subprocess when installed by the user.
  - Secure Headers: built-in HTTP checks (presence + minimal value rules for HSTS/CSP/X-Frame-Options).
  - TLS: stdlib ssl/socket — cert expiry, negotiated cipher/version, SSLv3/TLS1.0/1.1 probes.
  - Subdomain takeover: CNAME + HTTP fingerprints (~50 public services; needs dnspython).
  - WSTG: curated checklist with links only (no substantial reproduction of CC-BY-SA text).
"""

from __future__ import annotations

import json
import re
import shutil
import socket
import ssl
import subprocess
import sys
import urllib.error
import urllib.request
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple

import subdomain_takeover

from paths import OWASP_SESSIONS_DIR, REPO_ROOT
OWASP_FORMAT_V1 = "fnkit_owasp_v1"
LEGACY_OWASP_FORMAT_V1 = "ip_checker_owasp_v1"

C_RESET = "\033[0m"
C_BOLD = "\033[1m"
C_CYAN = "\033[96m"
C_GREEN = "\033[92m"
C_WARN = "\033[93m"
C_FAIL = "\033[91m"
C_DIM = "\033[2m"

# Public project URLs (attribution / further reading).
OWASP_LINKS = {
    "amass": "https://github.com/owasp-amass/amass",
    "nettacker": "https://github.com/OWASP/Nettacker",
    "wstg": "https://github.com/OWASP/wstg",
    "secure_headers": "https://github.com/OWASP/www-project-secure-headers",
    "cheat_sheets": "https://github.com/OWASP/CheatSheetSeries",
}

# Header names commonly recommended by OWASP Secure Headers Project (facts, not copied text).
SECURE_HEADER_CHECKS: Tuple[Tuple[str, str], ...] = (
    ("strict-transport-security", "high"),
    ("content-security-policy", "high"),
    ("x-frame-options", "medium"),
    ("x-content-type-options", "medium"),
    ("referrer-policy", "medium"),
    ("permissions-policy", "low"),
    ("cross-origin-opener-policy", "low"),
    ("cross-origin-resource-policy", "low"),
)

HSTS_MIN_MAX_AGE = 31_536_000  # 1 year (OWASP / common baseline)
VALUE_VALIDATED_HEADERS = frozenset(
    {"strict-transport-security", "content-security-policy", "x-frame-options"}
)

CERT_EXPIRY_WARN_DAYS = 30
TLS_DEFAULT_PORT = 443
TLS_CONNECT_TIMEOUT = 10.0
WEAK_CIPHER_RE = re.compile(
    r"NULL|EXPORT|\bDES\b|3DES|RC4|MD5|anon|PSK|SRP|IDEA|SEED",
    re.I,
)
LEGACY_TLS_PROBES: Tuple[Tuple[str, str], ...] = (
    ("SSLv3", "SSLv3"),
    ("TLSv1.0", "TLSv1"),
    ("TLSv1.1", "TLSv1_1"),
)

# Short WSTG pointers — titles are our summaries; full text stays on GitHub (CC-BY-SA).
WSTG_ITEMS: Tuple[Dict[str, str], ...] = (
    {
        "id": "WSTG-INFO-02",
        "en": "Fingerprint web server and frameworks (after open ports / HTTP).",
        "ru": "Определить веб-сервер и фреймворки (после открытых портов / HTTP).",
        "url": "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/01-Information_Gathering/02-Fingerprint_Web_Server",
    },
    {
        "id": "WSTG-INFO-05",
        "en": "Map execution paths and entry points on the target host.",
        "ru": "Карта путей и точек входа на целевом хосте.",
        "url": "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/01-Information_Gathering/05-Review_Webpage_Content_for_Information_Leakage",
    },
    {
        "id": "WSTG-CONF-02",
        "en": "Review security headers and transport (HSTS, CSP, framing).",
        "ru": "Проверить security-заголовки и транспорт (HSTS, CSP, framing).",
        "url": "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/02-Test_Application_Platform_Configuration",
    },
    {
        "id": "WSTG-INPV-11",
        "en": "Test for TLS misconfiguration if HTTPS is exposed.",
        "ru": "Проверить ошибки конфигурации TLS, если есть HTTPS.",
        "url": "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/11-Testing_for_SSL_TLS",
    },
    {
        "id": "WSTG-ATHN-04",
        "en": "Enumerate auth surfaces if login/admin ports are open.",
        "ru": "Перечислить поверхности аутентификации при открытых login/admin портах.",
        "url": "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/04-Authentication_Testing/04-Testing_for_Default_Credentials",
    },
)

_last_context: Dict[str, Optional[str]] = {"ip": None, "domain": None, "url": None}
_disclaimer_accepted = False

STRINGS: Dict[str, Dict[str, str]] = {
    "en": {
        "menu_title": "OWASP toolkit (external tools + built-in checks)",
        "menu_1": "1. Guided pipeline (context → headers / Amass / Nettacker / WSTG)",
        "menu_2": "2. Secure Headers check (built-in HTTP, OWASP-aligned)",
        "menu_3": "3. Run Amass (passive enum, needs `amass` in PATH)",
        "menu_4": "4. Run Nettacker (needs install; AGPL — see legal note)",
        "menu_5": "5. Print WSTG checklist (links only)",
        "menu_6": "6. List / open saved sessions",
        "menu_7": "7. Legal notice & third-party licenses",
        "menu_8": "8. TLS check (cert, cipher, legacy protocols; stdlib ssl)",
        "menu_9": "9. Subdomain takeover (CNAME + fingerprints, needs dnspython)",
        "menu_0": "0. Back",
        "menu_prompt": "Select (0-9): ",
        "prompt_takeover_file": "Host list file (one FQDN per line): ",
        "takeover_after_amass": "Run takeover check on {n} Amass hosts? (y/n): ",
        "disclaimer": (
            "Authorized use only: scan targets you own or have written permission to test. "
            "External tools (Amass, Nettacker) are your responsibility."
        ),
        "disclaimer_accept": "Continue? (y/n): ",
        "prompt_url": "HTTPS/HTTP URL (e.g. https://example.com): ",
        "prompt_domain": "Domain for Amass: ",
        "prompt_target": "Host/IP for Nettacker: ",
        "prompt_ip": "IP (optional, Enter = skip): ",
        "prompt_domain_opt": "Domain (optional, Enter = skip): ",
        "amass_missing": "Amass not found. Install: https://github.com/owasp-amass/amass",
        "nettacker_missing": "Nettacker not found. Install: https://github.com/OWASP/Nettacker (AGPL-3.0).",
        "cmd_run": "Running: {cmd}",
        "cmd_done": "External command finished (exit {code}).",
        "cmd_fail": "Command failed: {err}",
        "headers_title": "Secure Headers report",
        "headers_url": "URL: {url}",
        "headers_present": "  [+] {name}: {value}",
        "headers_warn": "  [!] {name}: {detail} ({severity})",
        "headers_fail": "  [-] {name}: {detail} — misconfiguration ({severity})",
        "headers_missing": "  [-] {name} ({severity}) — not set",
        "headers_fetch_fail": "HTTP request failed: {err}",
        "wstg_title": "WSTG pointers (read full guide on owasp.org)",
        "wstg_for": "Target context: {ctx}",
        "pipeline_title": "OWASP pipeline",
        "pipeline_ctx": "Context — IP: {ip}, domain: {domain}, URL: {url}",
        "pipeline_skip": "Skipped: {step}",
        "save_ok": "Session saved: {path}",
        "save_fail": "Save failed: {err}",
        "sessions_none": "No sessions in data/sessions/owasp/",
        "sessions_pick": "Session file: ",
        "legal_title": "Third-party OWASP components",
        "context_set": "Context updated from last IP check: {ip}",
        "invalid_url": "Invalid URL.",
        "invalid_domain": "Invalid domain.",
        "prompt_tls": "Host, URL, or host:port (default :443): ",
        "tls_title": "TLS report",
        "tls_target": "Target: {host}:{port} (SNI: {sni})",
        "tls_port_closed": "Port {port}/tcp is closed or unreachable.",
        "tls_line_pass": "  [+] {check}: {detail}",
        "tls_line_warn": "  [!] {check}: {detail}",
        "tls_line_fail": "  [-] {check}: {detail}",
        "tls_invalid_target": "Invalid host/URL.",
    },
    "ru": {
        "menu_title": "OWASP: внешние инструменты + встроенные проверки",
        "menu_1": "1. Сценарий pipeline (контекст → headers / Amass / Nettacker / WSTG)",
        "menu_2": "2. Secure Headers (встроенный HTTP, по рекомендациям OWASP)",
        "menu_3": "3. Запуск Amass (пассивный enum, нужен `amass` в PATH)",
        "menu_4": "4. Запуск Nettacker (отдельная установка; AGPL — см. legal)",
        "menu_5": "5. Чеклист WSTG (только ссылки)",
        "menu_6": "6. Список / просмотр сохранённых сессий",
        "menu_7": "7. Правовое уведомление и лицензии",
        "menu_8": "8. Проверка TLS (сертификат, cipher, устаревшие протоколы; stdlib ssl)",
        "menu_9": "9. Subdomain takeover (CNAME + отпечатки, нужен dnspython)",
        "menu_0": "0. Назад",
        "menu_prompt": "Выберите (0-9): ",
        "prompt_takeover_file": "Файл со списком хостов (по одному FQDN на строку): ",
        "takeover_after_amass": "Проверить takeover для {n} хостов из Amass? (y/n): ",
        "disclaimer": (
            "Только с разрешением: сканируйте свои цели или цели с письменным согласием. "
            "Внешние инструменты (Amass, Nettacker) — на вашей ответственности."
        ),
        "disclaimer_accept": "Продолжить? (y/n): ",
        "prompt_url": "URL HTTPS/HTTP (например https://example.com): ",
        "prompt_domain": "Домен для Amass: ",
        "prompt_target": "Хост/IP для Nettacker: ",
        "prompt_ip": "IP (необязательно, Enter — пропуск): ",
        "prompt_domain_opt": "Домен (необязательно, Enter — пропуск): ",
        "amass_missing": "Amass не найден. Установка: https://github.com/owasp-amass/amass",
        "nettacker_missing": "Nettacker не найден. https://github.com/OWASP/Nettacker (AGPL-3.0).",
        "cmd_run": "Запуск: {cmd}",
        "cmd_done": "Команда завершена (код {code}).",
        "cmd_fail": "Ошибка команды: {err}",
        "headers_title": "Отчёт Secure Headers",
        "headers_url": "URL: {url}",
        "headers_present": "  [+] {name}: {value}",
        "headers_warn": "  [!] {name}: {detail} ({severity})",
        "headers_fail": "  [-] {name}: {detail} — ошибка конфигурации ({severity})",
        "headers_missing": "  [-] {name} ({severity}) — отсутствует",
        "headers_fetch_fail": "Ошибка HTTP: {err}",
        "wstg_title": "Указатели WSTG (полный текст — на owasp.org)",
        "wstg_for": "Контекст цели: {ctx}",
        "pipeline_title": "OWASP pipeline",
        "pipeline_ctx": "Контекст — IP: {ip}, domain: {domain}, URL: {url}",
        "pipeline_skip": "Пропуск: {step}",
        "save_ok": "Сессия сохранена: {path}",
        "save_fail": "Ошибка сохранения: {err}",
        "sessions_none": "Нет сессий в data/sessions/owasp/",
        "sessions_pick": "Файл сессии: ",
        "legal_title": "Сторонние компоненты OWASP",
        "context_set": "Контекст из последней проверки IP: {ip}",
        "invalid_url": "Некорректный URL.",
        "invalid_domain": "Некорректный домен.",
        "prompt_tls": "Хост, URL или host:port (по умолчанию :443): ",
        "tls_title": "Отчёт TLS",
        "tls_target": "Цель: {host}:{port} (SNI: {sni})",
        "tls_port_closed": "Порт {port}/tcp закрыт или недоступен.",
        "tls_line_pass": "  [+] {check}: {detail}",
        "tls_line_warn": "  [!] {check}: {detail}",
        "tls_line_fail": "  [-] {check}: {detail}",
        "tls_invalid_target": "Некорректный хост/URL.",
    },
}


def msg(lang: str, key: str, **kwargs: Any) -> str:
    table = STRINGS.get(lang, STRINGS["en"])
    text = table.get(key, key)
    return text.format(**kwargs) if kwargs else text


def ensure_dirs() -> None:
    OWASP_SESSIONS_DIR.mkdir(parents=True, exist_ok=True)


def set_context(
    *,
    ip: Optional[str] = None,
    domain: Optional[str] = None,
    url: Optional[str] = None,
) -> None:
    """Remember last target for pipeline / menu defaults."""
    if ip is not None:
        _last_context["ip"] = ip
    if domain is not None:
        _last_context["domain"] = domain
    if url is not None:
        _last_context["url"] = url


def get_context() -> Dict[str, Optional[str]]:
    return dict(_last_context)


def normalize_domain(name: str) -> Optional[str]:
    s = name.strip().lower().rstrip(".")
    if not s or " " in s:
        return None
    if s.startswith("http://") or s.startswith("https://"):
        try:
            from urllib.parse import urlparse

            host = urlparse(s).hostname
            return host.lower() if host else None
        except Exception:
            return None
    if re.match(r"^[a-z0-9]([a-z0-9.-]*[a-z0-9])?$", s):
        return s
    return None


def normalize_url(url: str) -> Optional[str]:
    s = url.strip()
    if not s:
        return None
    if not re.match(r"^https?://", s, re.I):
        s = "https://" + s
    try:
        from urllib.parse import urlparse

        p = urlparse(s)
        if not p.netloc:
            return None
        return s
    except Exception:
        return None


def _require_disclaimer(lang: str) -> bool:
    global _disclaimer_accepted
    if _disclaimer_accepted:
        return True
    print(f"{C_WARN}{msg(lang, 'disclaimer')}{C_RESET}")
    try:
        ans = input(f"{C_CYAN}{msg(lang, 'disclaimer_accept')}{C_RESET}").strip().lower()
    except (EOFError, KeyboardInterrupt):
        print()
        return False
    if ans in ("y", "yes", "д", "да"):
        _disclaimer_accepted = True
        return True
    return False


def find_amass() -> Optional[str]:
    return shutil.which("amass")


def find_nettacker() -> Optional[List[str]]:
    """Return argv prefix to invoke Nettacker, or None."""
    if shutil.which("nettacker"):
        return ["nettacker"]
    for candidate in (
        REPO_ROOT / "Nettacker" / "nettacker.py",
        Path.home() / "Nettacker" / "nettacker.py",
    ):
        if candidate.is_file():
            return [sys.executable, str(candidate)]
    return None


def run_external(
    cmd: List[str],
    *,
    lang: str,
    timeout: int = 600,
    cwd: Optional[Path] = None,
) -> Tuple[int, str]:
    print(f"{C_CYAN}{msg(lang, 'cmd_run', cmd=' '.join(cmd))}{C_RESET}")
    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout,
            cwd=str(cwd) if cwd else None,
        )
        out = (proc.stdout or "") + (proc.stderr or "")
        print(f"{C_GREEN}{msg(lang, 'cmd_done', code=proc.returncode)}{C_RESET}")
        return proc.returncode, out
    except subprocess.TimeoutExpired:
        return -1, "timeout"
    except OSError as exc:
        print(f"{C_FAIL}{msg(lang, 'cmd_fail', err=exc)}{C_RESET}")
        return -1, str(exc)


def fetch_response_headers(url: str, timeout: float = 15.0) -> Tuple[Dict[str, str], Optional[str]]:
    """HEAD with GET fallback; returns lower-case header names."""
    ctx = ssl.create_default_context()
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    last_err: Optional[str] = None
    for method in ("HEAD", "GET"):
        try:
            req = urllib.request.Request(
                url,
                method=method,
                headers={"User-Agent": "fnkit-owasp-toolkit/1.0"},
            )
            with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
                return {k.lower(): v.strip() for k, v in resp.headers.items()}, None
        except urllib.error.HTTPError as exc:
            if exc.headers:
                return {k.lower(): v.strip() for k, v in exc.headers.items()}, None
            last_err = str(exc)
        except Exception as exc:
            last_err = str(exc)
    return {}, last_err


def _validate_hsts(value: str) -> Tuple[str, str]:
    """Return (status, detail): pass | warn | fail."""
    m = re.search(r"max-age\s*=\s*(\d+)", value, re.I)
    if not m:
        return "fail", "missing max-age directive"
    age = int(m.group(1))
    if age == 0:
        return "fail", "max-age=0 disables HSTS"
    if age < HSTS_MIN_MAX_AGE:
        return "fail", f"max-age={age} (need >= {HSTS_MIN_MAX_AGE})"
    return "pass", value[:200]


def _validate_csp(value: str) -> Tuple[str, str]:
    lower = value.lower()
    bad: List[str] = []
    if "unsafe-inline" in lower:
        bad.append("unsafe-inline")
    if "unsafe-eval" in lower:
        bad.append("unsafe-eval")
    if bad:
        return "fail", f"contains {', '.join(bad)}"
    return "pass", value[:200]


def _validate_x_frame_options(value: str) -> Tuple[str, str]:
    token = value.strip().split(",")[0].strip().upper()
    if token == "DENY":
        return "pass", value[:200]
    if token == "SAMEORIGIN":
        return "warn", f"{value[:120]} (prefer DENY)"
    return "warn", f"{value[:120]} (expected DENY or SAMEORIGIN)"


def _validate_secure_header_value(name: str, value: str) -> Tuple[str, str]:
    if name == "strict-transport-security":
        return _validate_hsts(value)
    if name == "content-security-policy":
        return _validate_csp(value)
    if name == "x-frame-options":
        return _validate_x_frame_options(value)
    return "pass", value[:200]


def check_secure_headers(url: str, *, lang: str = "en") -> Dict[str, Any]:
    normalized = normalize_url(url)
    if not normalized:
        return {"ok": False, "error": msg(lang, "invalid_url")}
    headers, err = fetch_response_headers(normalized)
    if err and not headers:
        return {"ok": False, "url": normalized, "error": msg(lang, "headers_fetch_fail", err=err)}
    findings: List[Dict[str, str]] = []
    present: List[Dict[str, str]] = []
    missing: List[Dict[str, str]] = []
    for name, severity in SECURE_HEADER_CHECKS:
        val = headers.get(name)
        if not val:
            row = {"name": name, "status": "missing", "severity": severity, "detail": ""}
            findings.append(row)
            missing.append({"name": name, "severity": severity})
            continue
        if name in VALUE_VALIDATED_HEADERS:
            status, detail = _validate_secure_header_value(name, val)
        else:
            status, detail = "pass", val[:200]
        row = {"name": name, "status": status, "severity": severity, "detail": detail, "value": val[:200]}
        findings.append(row)
        if status == "pass":
            present.append({"name": name, "value": detail})
        elif status == "missing":
            missing.append({"name": name, "severity": severity})

    has_fail = any(f["status"] == "fail" for f in findings)
    has_high_missing = any(
        f["status"] == "missing" and f["severity"] == "high" for f in findings
    )
    return {
        "ok": not has_fail and not has_high_missing,
        "url": normalized,
        "findings": findings,
        "present": present,
        "missing": missing,
        "raw_count": len(headers),
    }


def print_secure_headers_report(report: Dict[str, Any], *, lang: str = "en") -> None:
    if not report.get("ok") and report.get("error"):
        print(f"{C_FAIL}{report.get('error', 'error')}{C_RESET}")
        return
    print(f"\n{C_BOLD}{msg(lang, 'headers_title')}{C_RESET}")
    print(msg(lang, "headers_url", url=report["url"]))
    findings = report.get("findings")
    if findings is not None:
        for item in findings:
            st = item.get("status", "missing")
            name = item["name"]
            sev = item.get("severity", "medium")
            if st == "pass":
                print(f"{C_GREEN}{msg(lang, 'headers_present', name=name, value=item.get('detail', ''))}{C_RESET}")
            elif st == "warn":
                print(f"{C_WARN}{msg(lang, 'headers_warn', name=name, detail=item.get('detail', ''), severity=sev)}{C_RESET}")
            elif st == "fail":
                print(f"{C_FAIL}{msg(lang, 'headers_fail', name=name, detail=item.get('detail', ''), severity=sev)}{C_RESET}")
            else:
                print(f"{C_FAIL}{msg(lang, 'headers_missing', name=name, severity=sev)}{C_RESET}")
        return
    for item in report.get("present", []):
        print(f"{C_GREEN}{msg(lang, 'headers_present', name=item['name'], value=item['value'])}{C_RESET}")
    for item in report.get("missing", []):
        print(f"{C_FAIL}{msg(lang, 'headers_missing', name=item['name'], severity=item['severity'])}{C_RESET}")


def parse_tls_target(target: str, *, default_port: int = TLS_DEFAULT_PORT) -> Optional[Dict[str, Any]]:
    """Parse URL, hostname, or host:port into connection parameters."""
    s = target.strip()
    if not s:
        return None
    if re.match(r"^https?://", s, re.I):
        url = normalize_url(s)
        if not url:
            return None
        from urllib.parse import urlparse

        p = urlparse(url)
        host = p.hostname
        if not host:
            return None
        port = p.port or (443 if (p.scheme or "").lower() == "https" else 80)
        return {"host": host, "port": port, "sni": host}
    if s.startswith("[") and "]" in s:
        host = s[1 : s.index("]")]
        rest = s[s.index("]") + 1 :]
        port = default_port
        if rest.startswith(":"):
            try:
                port = int(rest[1:])
            except ValueError:
                return None
        return {"host": host, "port": port, "sni": host}
    if ":" in s and not s.count(":") > 1:
        host_part, port_part = s.rsplit(":", 1)
        try:
            port = int(port_part)
        except ValueError:
            return None
        host = host_part.strip("[]")
        if not host:
            return None
        return {"host": host, "port": port, "sni": host}
    host = normalize_domain(s) or s
    if not host or " " in host:
        return None
    return {"host": host, "port": default_port, "sni": host}


def _parse_cert_gmt(when: str) -> datetime:
    return datetime.strptime(when, "%b %d %H:%M:%S %Y GMT").replace(tzinfo=timezone.utc)


def _cert_cn(dn: Tuple[Tuple[str, str], ...]) -> str:
    for rdn in dn:
        for key, val in rdn:
            if key in ("commonName", "CN"):
                return val
    return ""


def _cert_summary(peercert: Dict[str, Any]) -> Dict[str, Any]:
    not_before = _parse_cert_gmt(peercert["notBefore"])
    not_after = _parse_cert_gmt(peercert["notAfter"])
    now = datetime.now(timezone.utc)
    days_left = int((not_after - now).total_seconds() // 86400)
    sans: List[str] = []
    for typ, val in peercert.get("subjectAltName") or ():
        if typ == "DNS":
            sans.append(val)
    return {
        "subject_cn": _cert_cn(peercert.get("subject", ())),
        "issuer_cn": _cert_cn(peercert.get("issuer", ())),
        "not_before": not_before.isoformat(),
        "not_after": not_after.isoformat(),
        "days_left": days_left,
        "expired": days_left < 0,
        "sans": sans[:20],
    }


def _tcp_open(host: str, port: int, timeout: float) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


def _tls_client_context(*, verify: bool) -> ssl.SSLContext:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    if verify:
        ctx.verify_mode = ssl.CERT_REQUIRED
        ctx.check_hostname = True
        ctx.load_default_certs()
    else:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    return ctx


def _tls_handshake(
    host: str,
    port: int,
    *,
    sni: str,
    timeout: float,
    verify: bool,
) -> Dict[str, Any]:
    ctx = _tls_client_context(verify=verify)
    try:
        with socket.create_connection((host, port), timeout=timeout) as raw:
            with ctx.wrap_socket(raw, server_hostname=sni) as ssock:
                cipher = ssock.cipher()
                return {
                    "ok": True,
                    "version": ssock.version(),
                    "cipher": cipher[0] if cipher else None,
                    "cipher_bits": cipher[2] if cipher else None,
                    "cert": ssock.getpeercert(),
                    "verify_ok": verify,
                }
    except ssl.SSLCertVerificationError as exc:
        return {"ok": False, "verify_ok": False, "verify_error": str(exc)}
    except (ssl.SSLError, OSError, socket.timeout) as exc:
        return {"ok": False, "error": str(exc)}


def _tls_probe_legacy(
    host: str,
    port: int,
    *,
    sni: str,
    label: str,
    attr: str,
    timeout: float,
) -> Optional[Dict[str, str]]:
    ver = getattr(ssl.TLSVersion, attr, None)
    if ver is None:
        return None
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    ctx.minimum_version = ver
    ctx.maximum_version = ver
    try:
        with socket.create_connection((host, port), timeout=timeout) as raw:
            with ctx.wrap_socket(raw, server_hostname=sni) as ssock:  # codeql[py/insecure-protocol]: legacy TLS audit probe
                cipher = ssock.cipher()
                return {
                    "label": label,
                    "version": ssock.version() or label,
                    "cipher": cipher[0] if cipher else "?",
                }
    except (ssl.SSLError, OSError, socket.timeout):
        return None


def _append_tls_finding(
    findings: List[Dict[str, str]],
    *,
    check: str,
    status: str,
    detail: str,
) -> None:
    findings.append({"check": check, "status": status, "detail": detail})


def check_tls(
    target: str,
    *,
    lang: str = "en",
    port: Optional[int] = None,
    timeout: float = TLS_CONNECT_TIMEOUT,
) -> Dict[str, Any]:
    ep = parse_tls_target(target)
    if not ep:
        return {"ok": False, "error": msg(lang, "tls_invalid_target")}
    host, use_port, sni = ep["host"], port if port is not None else ep["port"], ep["sni"]
    findings: List[Dict[str, str]] = []
    legacy_offered: List[Dict[str, str]] = []

    if not _tcp_open(host, use_port, timeout):
        return {
            "ok": False,
            "host": host,
            "port": use_port,
            "sni": sni,
            "port_open": False,
            "error": msg(lang, "tls_port_closed", port=use_port),
            "findings": findings,
        }

    hs = _tls_handshake(host, use_port, sni=sni, timeout=timeout, verify=True)
    cert_pem: Optional[str] = None
    if not hs.get("ok"):
        verify_err = hs.get("verify_error") or hs.get("error", "")
        if verify_err:
            _append_tls_finding(
                findings,
                check="certificate trust",
                status="warn",
                detail=verify_err[:240],
            )
        hs = _tls_handshake(host, use_port, sni=sni, timeout=timeout, verify=False)
        if not hs.get("ok"):
            err = hs.get("error", "TLS handshake failed")
            _append_tls_finding(findings, check="TLS handshake", status="fail", detail=err[:240])
            return {
                "ok": False,
                "host": host,
                "port": use_port,
                "sni": sni,
                "port_open": True,
                "error": err,
                "findings": findings,
            }
    else:
        _append_tls_finding(findings, check="certificate trust", status="pass", detail="chain verified")

    version = hs.get("version") or "?"
    cipher = hs.get("cipher") or "?"
    negotiated = {
        "version": version,
        "cipher": cipher,
        "cipher_bits": hs.get("cipher_bits"),
    }
    if version in ("TLSv1", "TLSv1.1", "SSLv3"):
        proto_st, proto_detail = "fail", f"{version} is deprecated"
    elif version == "TLSv1.2":
        proto_st, proto_detail = "warn", "TLSv1.2 (prefer TLSv1.3)"
    else:
        proto_st, proto_detail = "pass", version
    _append_tls_finding(findings, check="negotiated protocol", status=proto_st, detail=proto_detail)

    if cipher and WEAK_CIPHER_RE.search(cipher):
        cipher_st, cipher_detail = "fail", f"weak cipher: {cipher}"
    else:
        cipher_st, cipher_detail = "pass", cipher
    _append_tls_finding(findings, check="negotiated cipher", status=cipher_st, detail=cipher_detail)

    cert_info: Optional[Dict[str, Any]] = None
    peercert = hs.get("cert")
    if peercert:
        cert_info = _cert_summary(peercert)
        subj = cert_info["subject_cn"] or "(no CN)"
        issuer = cert_info["issuer_cn"] or "(unknown)"
        _append_tls_finding(
            findings,
            check="certificate subject",
            status="pass",
            detail=f"CN={subj}; issuer={issuer}",
        )
        if cert_info["expired"]:
            _append_tls_finding(
                findings,
                check="certificate expiry",
                status="fail",
                detail=f"expired ({cert_info['not_after']})",
            )
        elif cert_info["days_left"] < CERT_EXPIRY_WARN_DAYS:
            _append_tls_finding(
                findings,
                check="certificate expiry",
                status="warn",
                detail=f"{cert_info['days_left']} days left (until {cert_info['not_after'][:10]})",
            )
        else:
            _append_tls_finding(
                findings,
                check="certificate expiry",
                status="pass",
                detail=f"{cert_info['days_left']} days left",
            )
    else:
        try:
            ssl.get_server_certificate((host, use_port), timeout=timeout)
            _append_tls_finding(
                findings,
                check="certificate",
                status="warn",
                detail="PEM via get_server_certificate; parse peer cert unavailable",
            )
        except OSError as exc:
            _append_tls_finding(
                findings, check="certificate", status="fail", detail=str(exc)[:200]
            )

    for label, attr in LEGACY_TLS_PROBES:
        hit = _tls_probe_legacy(host, use_port, sni=sni, label=label, attr=attr, timeout=timeout)
        if hit:
            legacy_offered.append(hit)
            _append_tls_finding(
                findings,
                check=f"legacy {label}",
                status="fail",
                detail=f"accepted ({hit['version']}, {hit['cipher']})",
            )

    has_fail = any(f["status"] == "fail" for f in findings)
    return {
        "ok": not has_fail,
        "host": host,
        "port": use_port,
        "sni": sni,
        "port_open": True,
        "negotiated": negotiated,
        "certificate": cert_info,
        "legacy_offered": legacy_offered,
        "findings": findings,
    }


def print_tls_report(report: Dict[str, Any], *, lang: str = "en") -> None:
    if report.get("error") and not report.get("findings"):
        print(f"{C_FAIL}{report['error']}{C_RESET}")
        return
    print(f"\n{C_BOLD}{msg(lang, 'tls_title')}{C_RESET}")
    if report.get("host"):
        print(
            msg(
                lang,
                "tls_target",
                host=report["host"],
                port=report.get("port", TLS_DEFAULT_PORT),
                sni=report.get("sni", report["host"]),
            )
        )
    if not report.get("port_open", True):
        print(f"{C_FAIL}{report.get('error', msg(lang, 'tls_port_closed', port=report.get('port', 443)))}{C_RESET}")
        return
    for item in report.get("findings", []):
        st = item.get("status", "pass")
        line = msg(
            lang,
            "tls_line_pass" if st == "pass" else ("tls_line_warn" if st == "warn" else "tls_line_fail"),
            check=item.get("check", "?"),
            detail=item.get("detail", ""),
        )
        color = C_GREEN if st == "pass" else (C_WARN if st == "warn" else C_FAIL)
        print(f"{color}{line}{C_RESET}")


def print_wstg_checklist(ctx: str, *, lang: str = "en") -> None:
    print(f"\n{C_BOLD}{msg(lang, 'wstg_title')}{C_RESET}")
    print(f"{C_DIM}{msg(lang, 'wstg_for', ctx=ctx)}{C_RESET}")
    print(f"{C_DIM}{OWASP_LINKS['wstg']}{C_RESET}\n")
    for item in WSTG_ITEMS:
        title = item["ru"] if lang == "ru" else item["en"]
        print(f"  {C_CYAN}{item['id']}{C_RESET} {title}")
        print(f"    {C_DIM}{item['url']}{C_RESET}")


def run_amass_passive(domain: str, *, lang: str = "en", out_dir: Optional[Path] = None) -> Dict[str, Any]:
    exe = find_amass()
    dom = normalize_domain(domain)
    if not dom:
        return {"ok": False, "error": msg(lang, "invalid_domain")}
    if not exe:
        return {"ok": False, "error": msg(lang, "amass_missing")}
    ensure_dirs()
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    base = (out_dir or OWASP_SESSIONS_DIR) / f"amass_{dom}_{stamp}"
    base.mkdir(parents=True, exist_ok=True)
    out_file = base / "amass.txt"
    cmd = [exe, "enum", "-passive", "-d", dom, "-o", str(out_file)]
    code, output = run_external(cmd, lang=lang, timeout=900)
    text = ""
    if out_file.is_file():
        text = out_file.read_text(encoding="utf-8", errors="replace")
    elif output:
        text = output
    names = sorted({line.strip() for line in text.splitlines() if line.strip() and "." in line})
    return {
        "ok": code == 0,
        "tool": "amass",
        "domain": dom,
        "exit_code": code,
        "output_path": str(out_file),
        "discovered_count": len(names),
        "discovered_names": names,
        "discovered_sample": names[:50],
    }


def run_takeover_check(hosts: List[str], *, lang: str = "en") -> Dict[str, Any]:
    rep = subdomain_takeover.check_subdomain_takeover(hosts, lang=lang)
    subdomain_takeover.print_takeover_report(rep, lang=lang)
    return rep


def _takeover_hosts_from_amass(am_result: Dict[str, Any]) -> List[str]:
    return list(am_result.get("discovered_names") or [])


def run_nettacker_scan(target: str, *, lang: str = "en", module: str = "port_scan") -> Dict[str, Any]:
    argv0 = find_nettacker()
    if not argv0:
        return {"ok": False, "error": msg(lang, "nettacker_missing")}
    host = target.strip()
    if not host:
        return {"ok": False, "error": "empty target"}
    cmd = [*argv0, "-i", host, "-m", module]
    code, output = run_external(cmd, lang=lang, timeout=1200)
    return {
        "ok": code == 0,
        "tool": "nettacker",
        "target": host,
        "module": module,
        "exit_code": code,
        "output_excerpt": output[-8000:] if output else "",
    }


def build_pipeline_session(
    *,
    ip: Optional[str],
    domain: Optional[str],
    url: Optional[str],
    steps: List[Dict[str, Any]],
    lang: str,
) -> Dict[str, Any]:
    return {
        "format": OWASP_FORMAT_V1,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "lang": lang,
        "context": {"ip": ip, "domain": domain, "url": url},
        "steps": steps,
        "attribution": OWASP_LINKS,
    }


def save_session(session: Dict[str, Any]) -> Path:
    ensure_dirs()
    ctx = session.get("context") or {}
    label = ctx.get("domain") or ctx.get("ip") or "run"
    label = re.sub(r"[^\w.-]+", "_", str(label))[:40]
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    path = OWASP_SESSIONS_DIR / f"owasp_{label}_{stamp}.json"
    path.write_text(json.dumps(session, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    return path


def list_sessions() -> List[Path]:
    ensure_dirs()
    return sorted(OWASP_SESSIONS_DIR.glob("owasp_*.json"), key=lambda p: p.stat().st_mtime, reverse=True)


def print_session_summary(session: Dict[str, Any], *, lang: str = "en") -> None:
    ctx = session.get("context") or {}
    print(f"\n{C_BOLD}OWASP session{C_RESET} {session.get('created_at', '')}")
    print(msg(lang, "pipeline_ctx", ip=ctx.get("ip") or "—", domain=ctx.get("domain") or "—", url=ctx.get("url") or "—"))
    for step in session.get("steps", []):
        name = step.get("name", "?")
        ok = step.get("ok")
        mark = f"{C_GREEN}ok{C_RESET}" if ok else f"{C_WARN}skip/fail{C_RESET}"
        print(f"  [{mark}] {name}")
        if step.get("discovered_count") is not None:
            print(f"       found: {step['discovered_count']}")
        if step.get("suspect_count") is not None:
            print(f"       takeover suspects: {step['suspect_count']}")


def run_pipeline_interactive(lang: str) -> None:
    if not _require_disclaimer(lang):
        return
    ctx = get_context()
    try:
        ip_in = input(f"{C_CYAN}{msg(lang, 'prompt_ip')}{C_RESET}").strip()
    except (EOFError, KeyboardInterrupt):
        print()
        return
    try:
        dom_in = input(f"{C_CYAN}{msg(lang, 'prompt_domain_opt')}{C_RESET}").strip()
    except (EOFError, KeyboardInterrupt):
        print()
        return
    ip = ip_in or ctx.get("ip")
    domain = normalize_domain(dom_in) if dom_in else (normalize_domain(ctx["domain"]) if ctx.get("domain") else None)
    url = ctx.get("url")
    if not url and domain:
        url = f"https://{domain}/"

    print(f"\n{C_BOLD}{msg(lang, 'pipeline_title')}{C_RESET}")
    print(msg(lang, "pipeline_ctx", ip=ip or "—", domain=domain or "—", url=url or "—"))

    steps: List[Dict[str, Any]] = []

    if url:
        rep = check_secure_headers(url, lang=lang)
        print_secure_headers_report(rep, lang=lang)
        steps.append({"name": "secure_headers", "ok": rep.get("ok"), **rep})
    else:
        print(f"{C_DIM}{msg(lang, 'pipeline_skip', step='secure_headers (no URL)')}{C_RESET}")

    tls_target = url or (f"{domain}" if domain else None) or (str(ip) if ip else None)
    if tls_target:
        tls = check_tls(tls_target, lang=lang)
        print_tls_report(tls, lang=lang)
        steps.append({"name": "tls", "ok": tls.get("ok"), **tls})
    else:
        print(f"{C_DIM}{msg(lang, 'pipeline_skip', step='tls (no host)')}{C_RESET}")

    if domain:
        try:
            go = input(f"{C_CYAN}Run Amass passive on {domain}? (y/n): {C_RESET}").strip().lower()
        except (EOFError, KeyboardInterrupt):
            go = "n"
        if go in ("y", "yes", "д", "да"):
            am = run_amass_passive(domain, lang=lang)
            steps.append({"name": "amass", **am})
            if am.get("discovered_sample"):
                for line in am["discovered_sample"][:15]:
                    print(f"  {C_DIM}{line}{C_RESET}")
            th = _takeover_hosts_from_amass(am)
            if th:
                to = run_takeover_check(th, lang=lang)
                steps.append({"name": "subdomain_takeover", **to})
        else:
            steps.append({"name": "amass", "ok": False, "skipped": True})
    else:
        print(f"{C_DIM}{msg(lang, 'pipeline_skip', step='amass (no domain)')}{C_RESET}")

    target = ip or domain
    if target:
        print(f"{C_WARN}Nettacker is AGPL-3.0 — separate install, heavy scan.{C_RESET}")
        try:
            go = input(f"{C_CYAN}Run Nettacker port_scan on {target}? (y/n): {C_RESET}").strip().lower()
        except (EOFError, KeyboardInterrupt):
            go = "n"
        if go in ("y", "yes", "д", "да"):
            nt = run_nettacker_scan(target, lang=lang)
            steps.append({"name": "nettacker", **nt})
        else:
            steps.append({"name": "nettacker", "ok": False, "skipped": True})

    print_wstg_checklist(domain or ip or "target", lang=lang)
    steps.append({"name": "wstg_checklist", "ok": True})

    session = build_pipeline_session(ip=ip, domain=domain, url=url, steps=steps, lang=lang)
    try:
        save = input(f"{C_WARN}Save pipeline session JSON? (y/n): {C_RESET}").strip().lower()
    except (EOFError, KeyboardInterrupt):
        save = "n"
    if save in ("y", "yes", "д", "да"):
        try:
            path = save_session(session)
            print(f"{C_GREEN}{msg(lang, 'save_ok', path=path)}{C_RESET}")
        except OSError as exc:
            print(f"{C_FAIL}{msg(lang, 'save_fail', err=exc)}{C_RESET}")


def print_legal_notice(lang: str) -> None:
    print(f"\n{C_BOLD}{msg(lang, 'legal_title')}{C_RESET}\n")
    lines = [
        ("FieldNet Kit / fnkit (this repo)", "MIT — see LICENSE"),
        ("Amass", "Apache-2.0 — external CLI, not bundled"),
        ("Nettacker", "AGPL-3.0 — external CLI; if you modify/distribute Nettacker, comply with AGPL"),
        ("WSTG", "CC-BY-SA-4.0 — we only link; no substantial text copied"),
        ("OWASP Secure Headers", "Project docs Apache-2.0; header checks implemented locally"),
    ]
    for name, note in lines:
        print(f"  {C_CYAN}{name}{C_RESET}: {note}")
    print(f"\n{C_DIM}Links:{C_RESET}")
    for key, url in OWASP_LINKS.items():
        print(f"  {key}: {url}")
    print(f"\n{C_DIM}Full text: docs/OWASP_THIRD_PARTY.md{C_RESET}")


def run_owasp_menu(lang: str) -> None:
    """Interactive OWASP submenu (main menu item 11)."""
    ensure_dirs()
    while True:
        ctx = get_context()
        if ctx.get("ip"):
            print(f"{C_DIM}{msg(lang, 'context_set', ip=ctx['ip'])}{C_RESET}")
        print(f"\n{C_BOLD}{msg(lang, 'menu_title')}{C_RESET}")
        for key in ("menu_1", "menu_2", "menu_3", "menu_4", "menu_5", "menu_6", "menu_7", "menu_8", "menu_9", "menu_0"):
            print(msg(lang, key))
        try:
            choice = input(f"{C_CYAN}{msg(lang, 'menu_prompt')}{C_RESET}").strip()
        except (EOFError, KeyboardInterrupt):
            print()
            return
        if choice == "0":
            return
        if choice in ("1", "2", "3", "4", "5", "6", "7", "8", "9"):
            if choice != "7" and not _require_disclaimer(lang):
                continue
        if choice == "1":
            run_pipeline_interactive(lang)
        elif choice == "2":
            try:
                url = input(f"{C_CYAN}{msg(lang, 'prompt_url')}{C_RESET}").strip()
            except (EOFError, KeyboardInterrupt):
                continue
            rep = check_secure_headers(url, lang=lang)
            print_secure_headers_report(rep, lang=lang)
        elif choice == "3":
            try:
                domain = input(f"{C_CYAN}{msg(lang, 'prompt_domain')}{C_RESET}").strip()
            except (EOFError, KeyboardInterrupt):
                continue
            result = run_amass_passive(domain, lang=lang)
            if not result.get("ok"):
                print(f"{C_FAIL}{result.get('error', 'failed')}{C_RESET}")
            else:
                print(f"{C_GREEN}discovered: {result.get('discovered_count', 0)}{C_RESET}")
                th = _takeover_hosts_from_amass(result)
                if th:
                    try:
                        go = input(
                            f"{C_CYAN}{msg(lang, 'takeover_after_amass', n=len(th))}{C_RESET}"
                        ).strip().lower()
                    except (EOFError, KeyboardInterrupt):
                        go = "n"
                    if go in ("y", "yes", "д", "да"):
                        run_takeover_check(th, lang=lang)
        elif choice == "4":
            try:
                target = input(f"{C_CYAN}{msg(lang, 'prompt_target')}{C_RESET}").strip()
            except (EOFError, KeyboardInterrupt):
                continue
            result = run_nettacker_scan(target, lang=lang)
            if not result.get("ok"):
                print(f"{C_FAIL}{result.get('error', 'failed')}{C_RESET}")
        elif choice == "5":
            ctx_label = get_context()
            label = ctx_label.get("domain") or ctx_label.get("ip") or "general"
            print_wstg_checklist(str(label), lang=lang)
        elif choice == "6":
            sessions = list_sessions()
            if not sessions:
                print(msg(lang, "sessions_none"))
                continue
            for i, p in enumerate(sessions[:12], 1):
                print(f"  {i}. {p.name}")
            try:
                pick = input(f"{C_CYAN}{msg(lang, 'sessions_pick')}{C_RESET}").strip()
            except (EOFError, KeyboardInterrupt):
                continue
            if not pick:
                continue
            if pick.isdigit() and 1 <= int(pick) <= min(12, len(sessions)):
                path = sessions[int(pick) - 1]
            else:
                path = Path(pick).expanduser()
            try:
                session = json.loads(path.read_text(encoding="utf-8"))
                print_session_summary(session, lang=lang)
            except (OSError, json.JSONDecodeError) as exc:
                print(f"{C_FAIL}{exc}{C_RESET}")
        elif choice == "7":
            print_legal_notice(lang)
        elif choice == "8":
            try:
                target = input(f"{C_CYAN}{msg(lang, 'prompt_tls')}{C_RESET}").strip()
            except (EOFError, KeyboardInterrupt):
                continue
            if not target:
                ctx = get_context()
                target = ctx.get("url") or ctx.get("domain") or ctx.get("ip") or ""
            if target:
                rep = check_tls(target, lang=lang)
                print_tls_report(rep, lang=lang)
        elif choice == "9":
            try:
                path = input(f"{C_CYAN}{msg(lang, 'prompt_takeover_file')}{C_RESET}").strip()
            except (EOFError, KeyboardInterrupt):
                continue
            if path:
                try:
                    hosts = subdomain_takeover.load_hosts_file(path)
                    run_takeover_check(hosts, lang=lang)
                except OSError as exc:
                    print(f"{C_FAIL}{exc}{C_RESET}")
        else:
            print(f"{C_WARN}?{C_RESET}")


def handle_owasp_cli(args: Any, *, lang: str = "en") -> None:
    """Entry for non-interactive OWASP flags from fnkit.py."""
    steps: List[Dict[str, Any]] = []
    ip = getattr(args, "owasp_ip", None)
    domain = normalize_domain(getattr(args, "owasp_domain", "") or "") if getattr(args, "owasp_domain", None) else None
    url = getattr(args, "owasp_headers", None)

    if getattr(args, "owasp_headers", None):
        rep = check_secure_headers(str(args.owasp_headers), lang=lang)
        print_secure_headers_report(rep, lang=lang)
        steps.append({"name": "secure_headers", **rep})

    if getattr(args, "owasp_tls", None):
        rep = check_tls(str(args.owasp_tls), lang=lang)
        print_tls_report(rep, lang=lang)
        steps.append({"name": "tls", **rep})

    takeover_hosts: List[str] = []

    if getattr(args, "owasp_takeover_file", None):
        try:
            takeover_hosts.extend(subdomain_takeover.load_hosts_file(str(args.owasp_takeover_file)))
        except OSError as exc:
            print(f"{C_FAIL}{exc}{C_RESET}")

    if getattr(args, "owasp_amass", None):
        am = run_amass_passive(str(args.owasp_amass), lang=lang)
        steps.append({"name": "amass", **am})
        if not am.get("ok"):
            print(f"{C_FAIL}{am.get('error')}{C_RESET}")
        if getattr(args, "owasp_takeover", False):
            takeover_hosts.extend(_takeover_hosts_from_amass(am))

    if takeover_hosts:
        seen: set[str] = set()
        deduped: List[str] = []
        for h in takeover_hosts:
            k = h.strip().lower()
            if k and k not in seen:
                seen.add(k)
                deduped.append(h)
        takeover_hosts = deduped
        to = run_takeover_check(takeover_hosts, lang=lang)
        steps.append({"name": "subdomain_takeover", **to})

    if getattr(args, "owasp_nettacker", None):
        nt = run_nettacker_scan(str(args.owasp_nettacker), lang=lang)
        steps.append({"name": "nettacker", **nt})

    if getattr(args, "owasp_wstg", False):
        print_wstg_checklist(domain or ip or "cli", lang=lang)
        steps.append({"name": "wstg_checklist", "ok": True})

    if getattr(args, "owasp_pipeline", False):
        ctx_url = url or (f"https://{domain}/" if domain else None)
        if ctx_url:
            rep = check_secure_headers(ctx_url, lang=lang)
            print_secure_headers_report(rep, lang=lang)
            steps.append({"name": "secure_headers", **rep})
        tls_target = ctx_url or domain or ip
        if tls_target:
            rep = check_tls(str(tls_target), lang=lang)
            print_tls_report(rep, lang=lang)
            steps.append({"name": "tls", **rep})
        if domain:
            am = run_amass_passive(domain, lang=lang)
            steps.append({"name": "amass", **am})
            th = _takeover_hosts_from_amass(am)
            if th:
                to = run_takeover_check(th, lang=lang)
                steps.append({"name": "subdomain_takeover", **to})
        target = ip or domain
        if target and getattr(args, "owasp_nettacker_run", False):
            nt = run_nettacker_scan(str(target), lang=lang)
            steps.append({"name": "nettacker", **nt})
        print_wstg_checklist(domain or ip or "pipeline", lang=lang)
        steps.append({"name": "wstg_checklist", "ok": True})

    if getattr(args, "owasp_save", False) and steps:
        session = build_pipeline_session(
            ip=ip,
            domain=domain,
            url=url or (f"https://{domain}/" if domain else None),
            steps=steps,
            lang=lang,
        )
        path = save_session(session)
        print(f"{C_GREEN}{msg(lang, 'save_ok', path=path)}{C_RESET}")
