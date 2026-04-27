#!/usr/bin/env python3
"""
IP Address Geolocation Checker for macOS
Checks if IP addresses are in their expected geographic locations
Локализованная версия / Localized version
"""

import json
import sys
import argparse
import ipaddress
import io
import re
import time
from contextlib import redirect_stdout
from pathlib import Path
from datetime import datetime, timedelta
from typing import List, Dict, Optional
import urllib.request
import urllib.error
import subprocess
import platform
import shutil
import os
import signal

# Configuration
SCRIPT_DIR = Path(__file__).parent
DATABASE_FILE = SCRIPT_DIR / "asn_database.json"
RESULTS_FILE = SCRIPT_DIR / "scan_results.json"
LANGUAGE_FILE = SCRIPT_DIR / ".language_config"
ENRICHMENT_CONFIG_FILE = SCRIPT_DIR / ".enrichment_config.json"

# Global language setting
CURRENT_LANGUAGE = "en"

# Colors for terminal output
class Colors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    WHITE = '\033[97m'
    BGRED = '\033[41m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'


# Localization dictionary
TRANSLATIONS = {
    "en": {
        "menu_title": "═══════════════════════════════════════════════════════════",
        "menu_select": "🌍 SELECT LANGUAGE / ВЫБЕРИТЕ ЯЗЫК",
        "menu_1": "1. English",
        "menu_2": "2. Русский",
        "menu_prompt": "Select (1 or 2): ",
        "app_title": "IP Address Geolocation Checker",
        "app_subtitle": "Verify if IPs are in their expected geographic locations",
        "db_path": "Database: ",
        "checking": "Checking IP: ",
        "matches": "✓ Matches expected location",
        "mismatch": "✗ MISMATCH DETECTED!",
        "asn": "ASN: ",
        "expected_country": "Expected Country: ",
        "actual_country": "Actual Country: ",
        "pool": "Pool: ",
        "provider_owner": "Provider: ",
        "ip_not_found": "⚠ IP not found in any ASN pool",
        "offer_reclassify": "⚠ MISMATCH FOUND!\nWould you like to reclassify this ASN? (y/n): ",
        "reclassification": "MISMATCH RECLASSIFICATION PROCESS",
        "ip_addr": "IP Address: ",
        "current_provider": "Current Provider: ",
        "detected_provider": "Detected Provider: ",
        "step1": "Step 1: Data Verification",
        "step2": "Step 2: Update Database",
        "step3": "Step 3: Re-checking IP",
        "step4": "Step 4: Verification Result",
        "will_update": "Will update:",
        "from_to": " → ",
        "country": "Country",
        "provider": "Provider",
        "auto_updating": "Auto-updating database...",
        "confirm": "Confirm update? (y/n): ",
        "db_updated": "✓ Database updated successfully",
        "recheck_success": "✓ RE-CHECK SUCCESSFUL",
        "resolved": "The reclassification has resolved the mismatch.",
        "classified": "The IP address is now correctly classified in ",
        "verify_complete": "✗ VERIFICATION COMPLETE",
        "incorrect": "The IP address appears to be incorrectly assigned.",
        "spoofing_warning": "This may indicate IP spoofing or geo-blocking misconfiguration.",
        "cancelled": "Reclassification cancelled",
        "summary": "SCAN SUMMARY",
        "total": "Total IPs checked: ",
        "match_count": "Matches (location correct): ",
        "mismatch_count": "Mismatches (location incorrect): ",
        "failed_geo": "✗ Failed to get geolocation data: ",
        "invalid_ip": "Invalid IP address: ",
        "unknown_ip_title": "Unknown IP Address",
        "unknown_ip_check_offer": "Would you like to verify this IP via WHOIS and add to database? (y/n): ",
        "unknown_ip_no_local_data": "No local data found, requesting WHOIS...",
        "unknown_ip_invalid_yes_no": "Invalid input. Please enter only y or n.",
        "unknown_ip_whois": "Checking WHOIS data...",
        "unknown_ip_detected_asn": "Detected ASN: ",
        "unknown_ip_detected_org": "Detected Provider: ",
        "unknown_ip_detected_country": "Detected Country: ",
        "unknown_ip_add_offer": "Add this information to the database? (y/n): ",
        "unknown_ip_adding": "Adding to database...",
        "unknown_ip_added": "✓ Entry added to database successfully",
        "unknown_ip_not_added": "Entry was not added",
        "unknown_ip_back_menu": "Returning to main menu...",
        "unknown_ip_whois_failed": "Failed to get WHOIS data. Returning to main menu...",
        "unknown_ip_whois_error": "WHOIS error: ",
        "unknown_ip_asn_prompt": "Enter ASN (e.g., AS12345 or 12345): ",
        "unknown_ip_asn_skipped": "ASN not provided. Skipping database entry.",
        "unknown_ip_asn_detect_failed": "Could not detect ASN from WHOIS.",
        "db_update_prompt": "Database update check is required - last check was ",
        "db_update_prompt_days": " days ago. Update now? (y/n): ",
        "db_update_success": "Database updated",
        "db_update_failed": "Database update failed. Reason: ",
        "db_update_started": "Updating database...",
        "db_update_postpone": "Update reminder postponed for 7 days.",
        "db_update_invalid_yes_no": "Invalid input. Please enter only y or n.",
        "save_report_offer": "Save this report to scan_results.json? (y/n): ",
        "save_report_yes": "Report saved: ",
        "save_report_no": "Report not saved.",
        "save_report_failed": "Failed to save report.",
        "startup_public_ip": "Public IP: ",
        "startup_location": "Location: ",
        "startup_isp": "ISP: ",
        "startup_asn": "ASN: ",
        "startup_fetch_fail": "Could not detect public IP (offline or API error).",
        "abuse_contact": "Abuse / complaints: ",
        "abuse_not_found": "(not found in WHOIS — check RIR WHOIS for this prefix)",
        "abuse_whois_lookup": "Looking up abuse contact (WHOIS)...",
        "abuse_rir_fallback_lookup": "Abuse not found in primary WHOIS. Querying RIR WHOIS: ",
        "abuse_rir_fallback_done": "RIR WHOIS query completed: ",
        "abuse_contact_inferred": "Abuse / complaints (inferred from WHOIS emails): ",
        "enrich_title": "Geo enrichment comparison",
        "enrich_primary": "Primary",
        "enrich_maxmind": "MaxMind",
        "enrich_ip2location": "IP2Location",
        "enrich_unavailable": "unavailable",
        "enrich_need_api_key": "no data (API KEY required)",
        "auth_check_title": "Authenticity check: ",
        "auth_check_ok": "no obvious conflict signals",
        "auth_check_warn_geo_whois": "geo country and WHOIS country differ",
        "auth_check_warn_rir_geo": "WHOIS RIR region differs from geo country region",
        "tools_menu_title": "Additional network tools (checked IP)",
        "tools_1": "1. nmap (run with -A -T4)",
        "tools_2": "2. traceroute / tracert to 8.8.8.8 (max 20 hops, bounded wait)",
        "tools_nmap_interrupt_hint": "Stop nmap: Ctrl+C or Ctrl+Z — return to this menu",
        "tools_nmap_interrupt_hint_win": "Stop nmap: Ctrl+C — return to this menu",
        "tools_nmap_interrupted": "nmap stopped — back to tools menu.",
        "tools_3": "3. nslookup  (this IP, system resolver)",
        "tools_0": "0. Skip / back",
        "tools_prompt": "Select (0-3): ",
        "tools_running": "Running: ",
        "tools_done": "— done —",
        "tools_cmd_missing": "Command not found in PATH: ",
        "tools_invalid": "Invalid choice.",
        "menu_7": "7. Configure enrichment API keys",
        "menu_prompt_main": "Select option (0-7): ",
        "enrich_cfg_title": "Enrichment API key setup",
        "enrich_cfg_opt_1": "1. MaxMind",
        "enrich_cfg_opt_2": "2. IP2Location",
        "enrich_cfg_opt_0": "0. Back",
        "enrich_cfg_prompt": "Select (0-2): ",
        "enrich_cfg_mm_prompt": "Enter MaxMind key as ACCOUNT_ID:LICENSE_KEY (or 0 to go back): ",
        "enrich_cfg_ip2_prompt": "Enter IP2Location API key (or 0 to go back): ",
        "enrich_cfg_saved": "Saved.",
        "enrich_cfg_save_failed": "Failed to save config.",
        "enrich_cfg_invalid": "Invalid format.",
        "enrich_cfg_next": "Configure another service key? (y/n): ",
        "enrich_cfg_done": "All done. Return to main menu.",
    },
    "ru": {
        "menu_title": "═══════════════════════════════════════════════════════════",
        "menu_select": "🌍 ВЫБЕРИТЕ ЯЗЫК / SELECT LANGUAGE",
        "menu_1": "1. English",
        "menu_2": "2. Русский",
        "menu_prompt": "Выберите (1 или 2): ",
        "app_title": "Проверка Геолокации IP Адресов",
        "app_subtitle": "Проверка соответствия IP их ожидаемым географическим местоположениям",
        "db_path": "База данных: ",
        "checking": "Проверка IP: ",
        "matches": "✓ Соответствует ожидаемому местоположению",
        "mismatch": "✗ НЕСООТВЕТСТВИЕ ОБНАРУЖЕНО!",
        "asn": "ASN: ",
        "expected_country": "Ожидаемая страна: ",
        "actual_country": "Фактическая страна: ",
        "pool": "Пул: ",
        "provider_owner": "Провайдер: ",
        "ip_not_found": "⚠ IP не найден в пулах БД",
        "offer_reclassify": "⚠ НАЙДЕНО НЕСООТВЕТСТВИЕ!\nХотите переклассифицировать этот ASN? (y/n): ",
        "reclassification": "ПРОЦЕСС ПЕРЕКЛАССИФИКАЦИИ ASN",
        "ip_addr": "IP адрес: ",
        "current_provider": "Текущий провайдер: ",
        "detected_provider": "Обнаруженный провайдер: ",
        "step1": "Шаг 1: Верификация данных",
        "step2": "Шаг 2: Обновление БД",
        "step3": "Шаг 3: Повторная проверка IP",
        "step4": "Шаг 4: Результат верификации",
        "will_update": "Будут обновлены:",
        "from_to": " → ",
        "country": "Страна",
        "provider": "Провайдер",
        "auto_updating": "Автоматическое обновление БД...",
        "confirm": "Подтвердить обновление? (y/n): ",
        "db_updated": "✓ БД успешно обновлена",
        "recheck_success": "✓ ПОВТОРНАЯ ПРОВЕРКА УСПЕШНА",
        "resolved": "Переклассификация разрешила несоответствие.",
        "classified": "IP адрес теперь правильно классифицирован в ",
        "verify_complete": "✗ ПРОВЕРКА ЗАВЕРШЕНА",
        "incorrect": "IP адрес, похоже, неправильно назначен.",
        "spoofing_warning": "Это может указывать на спуфинг IP или неправильную конфигурацию геоблокирования.",
        "cancelled": "Переклассификация отменена",
        "summary": "ИТОГИ СКАНИРОВАНИЯ",
        "total": "Проверено IP: ",
        "match_count": "Совпадения (локация верна): ",
        "mismatch_count": "Несоответствия (локация неверна): ",
        "failed_geo": "✗ Ошибка получения данных геолокации: ",
        "invalid_ip": "Неверный IP адрес: ",
        "unknown_ip_check_offer": "Хотите проверить этот IP через WHOIS и добавить в БД? (y/n): ",
        "unknown_ip_no_local_data": "Локальных данных нет, запрашиваю WHOIS...",
        "unknown_ip_invalid_yes_no": "Неверный ввод. Введите только y или n.",
        "unknown_ip_whois": "Проверка данных WHOIS...",
        "unknown_ip_detected_asn": "Обнаруженный ASN: ",
        "unknown_ip_detected_org": "Обнаруженный провайдер: ",
        "unknown_ip_detected_country": "Обнаруженная страна: ",
        "unknown_ip_add_offer": "Добавить эту информацию в БД? (y/n): ",
        "unknown_ip_adding": "Добавление в БД...",
        "unknown_ip_added": "✓ Запись успешно добавлена в БД",
        "unknown_ip_not_added": "Запись не была добавлена",
        "unknown_ip_back_menu": "Возврат в главное меню...",
        "unknown_ip_whois_failed": "Не удалось получить данные WHOIS. Возврат в главное меню...",
        "unknown_ip_whois_error": "Ошибка WHOIS: ",
        "unknown_ip_asn_prompt": "Введите ASN (например, AS12345 или 12345): ",
        "unknown_ip_asn_skipped": "ASN не предоставлен. Пропуск добавления в БД.",
        "unknown_ip_asn_detect_failed": "Не удалось определить ASN из WHOIS.",
        "db_update_prompt": "Нужно проверить обновление базы - последняя проверка ",
        "db_update_prompt_days": " дней назад. Обновить сейчас? (y/n): ",
        "db_update_success": "База обновлена",
        "db_update_failed": "Ошибка обновления. Причина: ",
        "db_update_started": "Обновление базы...",
        "db_update_postpone": "Напоминание об обновлении отложено на 7 дней.",
        "db_update_invalid_yes_no": "Неверный ввод. Введите только y или n.",
        "save_report_offer": "Сохранить отчет в scan_results.json? (y/n): ",
        "save_report_yes": "Отчет сохранен: ",
        "save_report_no": "Отчет не сохранен.",
        "save_report_failed": "Не удалось сохранить отчет.",
        "startup_public_ip": "Публичный IP: ",
        "startup_location": "Локация: ",
        "startup_isp": "Провайдер: ",
        "startup_asn": "ASN: ",
        "startup_fetch_fail": "Не удалось определить публичный IP (сеть или ошибка API).",
        "abuse_contact": "Abuse / жалобы: ",
        "abuse_not_found": "(не найдено в WHOIS — смотрите WHOIS RIR для этого префикса)",
        "abuse_whois_lookup": "Поиск abuse-контакта (WHOIS)...",
        "abuse_rir_fallback_lookup": "В основном WHOIS abuse не найден. Запрашиваю WHOIS RIR: ",
        "abuse_rir_fallback_done": "Запрос WHOIS RIR выполнен: ",
        "abuse_contact_inferred": "Abuse / жалобы (эвристика по email из WHOIS): ",
        "enrich_title": "Сравнение geo-обогащения",
        "enrich_primary": "Primary",
        "enrich_maxmind": "MaxMind",
        "enrich_ip2location": "IP2Location",
        "enrich_unavailable": "недоступно",
        "enrich_need_api_key": "нет данных (нужен API KEY)",
        "auth_check_title": "Проверка подлинности: ",
        "auth_check_ok": "явных конфликтов не обнаружено",
        "auth_check_warn_geo_whois": "страна geo и страна WHOIS отличаются",
        "auth_check_warn_rir_geo": "регион WHOIS RIR отличается от региона geo-страны",
        "tools_menu_title": "Доп. сетевые инструменты (проверяемый IP)",
        "tools_1": "1. nmap (запуск с ключами -A -T4)",
        "tools_2": "2. traceroute / tracert до 8.8.8.8 (макс. 20 хопов, ограниченное ожидание)",
        "tools_nmap_interrupt_hint": "Остановить nmap: Ctrl+C или Ctrl+Z — возврат в это меню",
        "tools_nmap_interrupt_hint_win": "Остановить nmap: Ctrl+C — возврат в это меню",
        "tools_nmap_interrupted": "nmap остановлен — возврат в меню инструментов.",
        "tools_3": "3. nslookup  (этот IP, системный резолвер)",
        "tools_0": "0. Пропуск / назад",
        "tools_prompt": "Выберите (0-3): ",
        "tools_running": "Запуск: ",
        "tools_done": "— готово —",
        "tools_cmd_missing": "Команда не найдена в PATH: ",
        "tools_invalid": "Неверный выбор.",
        "menu_7": "7. Настроить API ключи обогащения",
        "menu_prompt_main": "Выберите опцию (0-7): ",
        "enrich_cfg_title": "Настройка API ключей обогащения",
        "enrich_cfg_opt_1": "1. MaxMind",
        "enrich_cfg_opt_2": "2. IP2Location",
        "enrich_cfg_opt_0": "0. Назад",
        "enrich_cfg_prompt": "Выберите (0-2): ",
        "enrich_cfg_mm_prompt": "Введите ключ MaxMind в формате ACCOUNT_ID:LICENSE_KEY (или 0 назад): ",
        "enrich_cfg_ip2_prompt": "Введите API ключ IP2Location (или 0 назад): ",
        "enrich_cfg_saved": "Сохранено.",
        "enrich_cfg_save_failed": "Не удалось сохранить конфиг.",
        "enrich_cfg_invalid": "Неверный формат.",
        "enrich_cfg_next": "Настроить ключ для другого сервиса? (y/n): ",
        "enrich_cfg_done": "Готово. Возврат в главное меню.",
    }
}

def t(key: str) -> str:
    """Get translation for key in current language"""
    return TRANSLATIONS.get(CURRENT_LANGUAGE, {}).get(key, key)

def load_language_config():
    """Load saved language preference"""
    global CURRENT_LANGUAGE
    try:
        if LANGUAGE_FILE.exists():
            with open(LANGUAGE_FILE, 'r') as f:
                lang = f.read().strip()
                if lang in ["ru", "en"]:
                    CURRENT_LANGUAGE = lang
                    return
    except:
        pass
    # First time - will be prompted in main menu
    CURRENT_LANGUAGE = None

def save_language_config(lang: str):
    """Save language preference"""
    global CURRENT_LANGUAGE
    CURRENT_LANGUAGE = lang
    try:
        with open(LANGUAGE_FILE, 'w') as f:
            f.write(lang)
    except:
        pass

def load_enrichment_config() -> Dict:
    """Load locally stored enrichment provider credentials."""
    try:
        if ENRICHMENT_CONFIG_FILE.exists():
            with open(ENRICHMENT_CONFIG_FILE, "r", encoding="utf-8") as f:
                data = json.load(f)
                return data if isinstance(data, dict) else {}
    except Exception:
        pass
    return {}

def save_enrichment_config(config: Dict) -> bool:
    """Persist enrichment provider credentials to local config."""
    try:
        with open(ENRICHMENT_CONFIG_FILE, "w", encoding="utf-8") as f:
            json.dump(config, f, indent=2, ensure_ascii=False)
        return True
    except Exception:
        return False

def configure_enrichment_keys_menu() -> None:
    """Interactive setup for MaxMind/IP2Location API keys."""
    if not (sys.stdin.isatty() and sys.stdout.isatty()):
        return
    config = load_enrichment_config()
    while True:
        print(f"\n{Colors.HEADER}{'-' * 60}{Colors.ENDC}")
        print(f"{Colors.BOLD}{t('enrich_cfg_title')}{Colors.ENDC}")
        print(f"{Colors.OKCYAN}{t('enrich_cfg_opt_1')}{Colors.ENDC}")
        print(f"{Colors.OKCYAN}{t('enrich_cfg_opt_2')}{Colors.ENDC}")
        print(f"{Colors.OKCYAN}{t('enrich_cfg_opt_0')}{Colors.ENDC}")
        try:
            choice = input(f"{Colors.WARNING}{t('enrich_cfg_prompt')}{Colors.ENDC}").strip()
        except (EOFError, KeyboardInterrupt):
            print()
            return

        if choice == "0":
            return
        if choice == "1":
            raw = input(f"{Colors.OKCYAN}{t('enrich_cfg_mm_prompt')}{Colors.ENDC}").strip()
            if raw == "0":
                continue
            if ":" not in raw:
                print(f"{Colors.FAIL}{t('enrich_cfg_invalid')}{Colors.ENDC}")
                continue
            account_id, license_key = raw.split(":", 1)
            account_id, license_key = account_id.strip(), license_key.strip()
            if not account_id or not license_key:
                print(f"{Colors.FAIL}{t('enrich_cfg_invalid')}{Colors.ENDC}")
                continue
            config["maxmind_account_id"] = account_id
            config["maxmind_license_key"] = license_key
            if save_enrichment_config(config):
                print(f"{Colors.OKGREEN}{t('enrich_cfg_saved')}{Colors.ENDC}")
            else:
                print(f"{Colors.FAIL}{t('enrich_cfg_save_failed')}{Colors.ENDC}")
        elif choice == "2":
            key = input(f"{Colors.OKCYAN}{t('enrich_cfg_ip2_prompt')}{Colors.ENDC}").strip()
            if key == "0":
                continue
            if not key:
                print(f"{Colors.FAIL}{t('enrich_cfg_invalid')}{Colors.ENDC}")
                continue
            config["ip2location_api_key"] = key
            if save_enrichment_config(config):
                print(f"{Colors.OKGREEN}{t('enrich_cfg_saved')}{Colors.ENDC}")
            else:
                print(f"{Colors.FAIL}{t('enrich_cfg_save_failed')}{Colors.ENDC}")
        else:
            print(f"{Colors.WARNING}{t('tools_invalid')}{Colors.ENDC}")
            continue

        while True:
            nxt = input(f"{Colors.WARNING}{t('enrich_cfg_next')}{Colors.ENDC}").strip().lower()
            if nxt in ("y", "n"):
                break
            print(f"{Colors.WARNING}{t('unknown_ip_invalid_yes_no')}{Colors.ENDC}")
        if nxt == "n":
            print(f"{Colors.OKGREEN}{t('enrich_cfg_done')}{Colors.ENDC}")
            return

def select_language_menu():
    """Interactive language selection"""
    print(f"\n{Colors.HEADER}{Colors.BOLD}{'='*60}{Colors.ENDC}")
    print(f"{Colors.HEADER}{Colors.BOLD}🌍 SELECT LANGUAGE / ВЫБЕРИТЕ ЯЗЫК{Colors.ENDC}")
    print(f"{Colors.HEADER}{Colors.BOLD}{'='*60}{Colors.ENDC}\n")
    print("1. English")
    print("2. Русский")
    print()
    
    try:
        choice = input(f"{Colors.OKCYAN}Select (1 or 2): {Colors.ENDC}").strip()
        if choice == "2":
            save_language_config("ru")
            print(f"\n{Colors.OKGREEN}✓ Язык установлен: Русский{Colors.ENDC}\n")
        else:
            save_language_config("en")
            print(f"\n{Colors.OKGREEN}✓ Language set: English{Colors.ENDC}\n")
    except KeyboardInterrupt:
        return
    except:
        save_language_config("en")

def load_database() -> Dict:
    """Load ASN database from JSON file"""
    try:
        with open(DATABASE_FILE, 'r', encoding='utf-8') as f:
            database = json.load(f)
            ensure_database_metadata(database)
            return database
    except FileNotFoundError:
        print(f"{Colors.FAIL}Error: Database file not found{Colors.ENDC}")
        sys.exit(1)
    except json.JSONDecodeError:
        print(f"{Colors.FAIL}Error: Invalid JSON in database{Colors.ENDC}")
        sys.exit(1)

def save_database(database: Dict) -> None:
    """Persist ASN database to JSON file."""
    with open(DATABASE_FILE, 'w', encoding='utf-8') as f:
        json.dump(database, f, indent=2, ensure_ascii=False)

def ensure_database_metadata(database: Dict) -> None:
    """Ensure required metadata fields exist."""
    metadata = database.setdefault('metadata', {})
    if 'last_updated' not in metadata:
        metadata['last_updated'] = datetime.now().strftime("%Y-%m-%d")
    if 'last_update_check' not in metadata:
        metadata['last_update_check'] = metadata.get('last_updated')
    if 'next_update_prompt_after' not in metadata:
        metadata['next_update_prompt_after'] = metadata.get('last_update_check')

def parse_iso_date(date_str: Optional[str]) -> Optional[datetime]:
    """Parse YYYY-MM-DD into datetime, return None for invalid values."""
    if not date_str:
        return None
    try:
        return datetime.strptime(date_str, "%Y-%m-%d")
    except ValueError:
        return None

def normalize_country_code(value: Optional[str]) -> Optional[str]:
    """Normalize any country-like token to two-letter uppercase code."""
    if not value:
        return None
    token = str(value).strip().upper()
    if len(token) >= 2:
        return token[:2]
    return None

def infer_rir_from_whois_server(server: Optional[str]) -> Optional[str]:
    """Infer RIR from WHOIS referral server hostname."""
    if not server:
        return None
    s = server.lower()
    if "ripe" in s:
        return "RIPE"
    if "arin" in s:
        return "ARIN"
    if "apnic" in s:
        return "APNIC"
    if "lacnic" in s:
        return "LACNIC"
    if "afrinic" in s:
        return "AFRINIC"
    return None

def infer_rir_priority_for_ip(ip: str) -> Dict:
    """
    Best-effort prefix/RIR priority by address family.
    IPv4 defaults to globally mixed trust. IPv6 relies more on RIR WHOIS.
    """
    try:
        ip_obj = ipaddress.ip_address(ip)
    except ValueError:
        return {"preferred_source": "GEO_API", "weight_whois": 0.4, "weight_geo": 0.6}
    if ip_obj.version == 6:
        return {"preferred_source": "WHOIS", "weight_whois": 0.65, "weight_geo": 0.35}
    return {"preferred_source": "GEO_API", "weight_whois": 0.4, "weight_geo": 0.6}

def default_whois_server_for_rir(rir: Optional[str]) -> Optional[str]:
    """Return canonical WHOIS hostname for known RIR labels."""
    mapping = {
        "RIPE": "whois.ripe.net",
        "ARIN": "whois.arin.net",
        "APNIC": "whois.apnic.net",
        "LACNIC": "whois.lacnic.net",
        "AFRINIC": "whois.afrinic.net",
    }
    if not rir:
        return None
    return mapping.get(str(rir).upper())

def country_in_rir_region(country_code: Optional[str], rir: Optional[str]) -> bool:
    """
    Coarse consistency check between geo country and RIR region.
    This is heuristic only; global providers can legitimately differ.
    """
    cc = normalize_country_code(country_code)
    r = (rir or "").upper()
    if not cc or not r:
        return True

    arin = {"US", "CA", "PR", "BM", "GL"}
    lacnic = {"MX", "BR", "AR", "CL", "CO", "PE", "UY", "PY", "BO", "EC", "VE", "PA", "CR", "GT", "HN", "NI", "SV", "DO", "CU", "JM", "TT", "BS", "BB"}
    afrinic = {"ZA", "NG", "KE", "EG", "MA", "DZ", "TN", "GH", "TZ", "UG", "CM", "SN", "CI", "ET", "ZM", "ZW", "BW", "NA", "MZ", "RW", "MU"}
    apnic = {"CN", "JP", "KR", "SG", "IN", "AU", "NZ", "HK", "TW", "TH", "VN", "MY", "PH", "ID", "PK", "BD", "LK", "NP"}
    # RIPE region is broad (Europe, Middle East, parts of Central Asia).
    ripe = {"IT", "DE", "FR", "ES", "NL", "BE", "CH", "AT", "SE", "NO", "FI", "DK", "PL", "CZ", "SK", "HU", "RO", "BG", "GR", "PT", "IE", "GB", "UA", "BY", "RU", "TR", "IL", "AE", "SA", "KZ", "AM", "GE"}

    if r == "ARIN":
        return cc in arin
    if r == "LACNIC":
        return cc in lacnic
    if r == "AFRINIC":
        return cc in afrinic
    if r == "APNIC":
        return cc in apnic
    if r == "RIPE":
        return cc in ripe
    return True

def append_quarantine_case(
    database: Dict,
    *,
    ip: str,
    asn: str,
    pool: str,
    expected_country: str,
    ip_api_country: Optional[str],
    whois_country: Optional[str],
    whois_rir: Optional[str],
    reason: str,
    confidence_score: int,
) -> None:
    """Store a conflict case for later manual triage."""
    metadata = database.setdefault("metadata", {})
    quarantine = metadata.setdefault("quarantine_cases", [])
    quarantine.append(
        {
            "timestamp": datetime.now().isoformat(timespec="seconds"),
            "ip": ip,
            "asn": asn,
            "pool": pool,
            "expected_country": expected_country,
            "ip_api_country": ip_api_country,
            "whois_country": whois_country,
            "whois_rir": whois_rir,
            "reason": reason,
            "confidence_score": confidence_score,
            "status": "open",
        }
    )

def resolve_country_conflict_policy(
    *,
    ip: str,
    expected_country: str,
    ip_api_country: Optional[str],
    whois_country: Optional[str],
    whois_rir: Optional[str],
) -> Dict:
    """
    Resolve mismatch with confidence score and source weighting.
    Returns action:
      - auto_apply: safe to update expected country automatically
      - quarantine: conflicting low-confidence case, do not auto-write
      - keep_expected: no update should be done
    """
    expected = normalize_country_code(expected_country)
    geo = normalize_country_code(ip_api_country)
    whois = normalize_country_code(whois_country)
    rir_pref = infer_rir_priority_for_ip(ip)

    score = 0
    reasons: List[str] = []

    if geo and geo != expected:
        score += int(30 * rir_pref["weight_geo"])
        reasons.append("ip-api differs from expected")
    if whois and whois != expected:
        score += int(30 * rir_pref["weight_whois"])
        reasons.append("whois differs from expected")
    if geo and whois and geo == whois and geo != expected:
        score += 40
        reasons.append("whois and ip-api agree")
    if geo and whois and geo != whois:
        score -= 20
        reasons.append("whois and ip-api conflict")
    if whois_rir:
        score += 5
        reasons.append(f"whois RIR detected: {whois_rir}")

    if score >= 55 and geo and whois and geo == whois:
        return {
            "action": "auto_apply",
            "target_country": geo,
            "confidence_score": score,
            "reason": "; ".join(reasons),
        }

    if score >= 30 and geo and not whois:
        return {
            "action": "auto_apply",
            "target_country": geo,
            "confidence_score": score,
            "reason": "; ".join(reasons + ["no whois country, using geo"]),
        }

    if geo and whois and geo != whois:
        return {
            "action": "quarantine",
            "target_country": None,
            "confidence_score": score,
            "reason": "; ".join(reasons),
        }

    return {
        "action": "keep_expected",
        "target_country": expected,
        "confidence_score": score,
        "reason": "; ".join(reasons) if reasons else "no significant mismatch signals",
    }

def update_database_metadata(database: Dict) -> None:
    """Refresh metadata counters and timestamps."""
    metadata = database.setdefault('metadata', {})
    metadata['last_updated'] = datetime.now().strftime("%Y-%m-%d")
    metadata['total_asns'] = len(database.get('asn_data', []))
    metadata['total_ip_pools'] = sum(len(a.get('ip_pools', [])) for a in database.get('asn_data', []))

def perform_database_update(database: Dict) -> tuple[bool, Optional[str]]:
    """Run database maintenance update and save."""
    try:
        update_database_metadata(database)
        today = datetime.now().strftime("%Y-%m-%d")
        metadata = database.setdefault('metadata', {})
        metadata['last_update_check'] = today
        metadata['next_update_prompt_after'] = today
        save_database(database)
        return True, None
    except Exception as exc:
        return False, str(exc)

def maybe_prompt_database_update(database: Dict) -> None:
    """Prompt for database update when last check is older than threshold."""
    ensure_database_metadata(database)
    metadata = database['metadata']
    now = datetime.now()
    check_interval_days = 30
    postpone_days = 7

    last_update_dt = parse_iso_date(metadata.get('last_updated')) or now
    next_prompt_dt = parse_iso_date(metadata.get('next_update_prompt_after')) or last_update_dt
    days_since_check = max(0, (now - last_update_dt).days)

    if now < next_prompt_dt or days_since_check < check_interval_days:
        return

    while True:
        print(
            f"\n{Colors.WARNING}{t('db_update_prompt')}{days_since_check}{t('db_update_prompt_days')}{Colors.ENDC}",
            end=""
        )
        try:
            choice = input().strip().lower()
        except (EOFError, KeyboardInterrupt):
            choice = 'n'

        if choice in ('y', 'n'):
            break
        print(f"{Colors.WARNING}{t('db_update_invalid_yes_no')}{Colors.ENDC}")

    today = now.strftime("%Y-%m-%d")
    metadata['last_update_check'] = today

    if choice == 'y':
        print(f"{Colors.OKCYAN}{t('db_update_started')}{Colors.ENDC}")
        ok, reason = perform_database_update(database)
        if ok:
            print(f"{Colors.OKGREEN}{t('db_update_success')}{Colors.ENDC}")
        else:
            print(f"{Colors.FAIL}{t('db_update_failed')}{reason or 'unknown error'}{Colors.ENDC}")
    else:
        metadata['next_update_prompt_after'] = (now + timedelta(days=postpone_days)).strftime("%Y-%m-%d")
        try:
            save_database(database)
            print(f"{Colors.OKCYAN}{t('db_update_postpone')}{Colors.ENDC}")
        except Exception as exc:
            print(f"{Colors.FAIL}{t('db_update_failed')}{str(exc)}{Colors.ENDC}")

def get_ip_geolocation(ip: str) -> Optional[Dict]:
    """Get geolocation data for an IP address using ip-api.com"""
    try:
        url = f"http://ip-api.com/json/{ip}?fields=status,country,countryCode,region,city,isp,org,as,reverse"
        req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
        with urllib.request.urlopen(req, timeout=5) as response:
            data = json.loads(response.read().decode('utf-8'))
            
            if data.get('status') == 'success':
                return {
                    'ip': ip,
                    'country_code': data.get('countryCode'),
                    'country': data.get('country'),
                    'region': data.get('region'),
                    'city': data.get('city'),
                    'isp': data.get('isp'),
                    'org': data.get('org'),
                    'asn': data.get('as'),
                    'success': True
                }
            else:
                return {'ip': ip, 'error': data.get('query'), 'success': False}
    except Exception as e:
        return {'ip': ip, 'error': str(e), 'success': False}

def get_maxmind_enrichment(ip: str) -> Dict:
    """
    Optional MaxMind enrichment.
    Requires env MAXMIND_DB_PATH pointing to GeoLite2-City/GeoLite2-Country MMDB.
    """
    cfg = load_enrichment_config()
    account_id = str(cfg.get("maxmind_account_id", "")).strip() or os.getenv("MAXMIND_ACCOUNT_ID", "").strip()
    license_key = str(cfg.get("maxmind_license_key", "")).strip() or os.getenv("MAXMIND_LICENSE_KEY", "").strip()
    if account_id and license_key:
        try:
            import geoip2.webservice  # type: ignore
            client = geoip2.webservice.Client(int(account_id), license_key)
            city = client.city(ip)
            return {
                "available": True,
                "country_code": (city.country.iso_code or "").upper() or None,
                "country": city.country.name or None,
                "city": city.city.name or None,
            }
        except Exception as exc:
            return {"available": False, "reason": str(exc)}

    db_path = os.getenv("MAXMIND_DB_PATH", "").strip()
    if not db_path:
        return {"available": False, "reason": "MAXMIND_ACCOUNT_ID/MAXMIND_LICENSE_KEY or MAXMIND_DB_PATH not set"}
    try:
        import geoip2.database  # type: ignore
        with geoip2.database.Reader(db_path) as reader:
            city = reader.city(ip)
            return {
                "available": True,
                "country_code": (city.country.iso_code or "").upper() or None,
                "country": city.country.name or None,
                "city": city.city.name or None,
            }
    except Exception as exc:
        return {"available": False, "reason": str(exc)}

def get_ip2location_enrichment(ip: str) -> Dict:
    """
    Optional IP2Location enrichment.
    Supports:
      - env IP2LOCATION_API_KEY (web API)
      - env IP2LOCATION_DB_PATH (local BIN via IP2Location python package)
    """
    cfg = load_enrichment_config()
    api_key = str(cfg.get("ip2location_api_key", "")).strip() or os.getenv("IP2LOCATION_API_KEY", "").strip()
    if api_key:
        try:
            url = f"https://api.ip2location.io/?key={api_key}&ip={ip}&format=json"
            req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
            with urllib.request.urlopen(req, timeout=8) as response:
                data = json.loads(response.read().decode("utf-8"))
            return {
                "available": True,
                "country_code": normalize_country_code(data.get("country_code")),
                "country": data.get("country_name"),
                "city": data.get("city_name"),
            }
        except Exception as exc:
            return {"available": False, "reason": str(exc)}

    db_path = os.getenv("IP2LOCATION_DB_PATH", "").strip()
    if db_path:
        try:
            import IP2Location  # type: ignore
            db = IP2Location.IP2Location(db_path)
            rec = db.get_all(ip)
            return {
                "available": True,
                "country_code": normalize_country_code(getattr(rec, "country_short", None)),
                "country": getattr(rec, "country_long", None),
                "city": getattr(rec, "city", None),
            }
        except Exception as exc:
            return {"available": False, "reason": str(exc)}

    return {"available": False, "reason": "IP2LOCATION_API_KEY/IP2LOCATION_DB_PATH not set"}

def print_enrichment_comparison(ip: str, geo_data: Dict) -> None:
    """Print side-by-side country comparison for primary, MaxMind and IP2Location."""
    mm = get_maxmind_enrichment(ip)
    ip2 = get_ip2location_enrichment(ip)
    primary_cc = normalize_country_code(geo_data.get("country_code"))
    primary_name = geo_data.get("country") or "N/A"
    print(f"\n{Colors.HEADER}{'-' * 60}{Colors.ENDC}")
    print(f"{Colors.BOLD}{t('enrich_title')}{Colors.ENDC}")
    print(f"  {t('enrich_primary')}: {primary_cc or 'N/A'} ({primary_name})")
    if mm.get("available"):
        print(f"  {t('enrich_maxmind')}: {mm.get('country_code') or 'N/A'} ({mm.get('country') or 'N/A'})")
    else:
        print(f"  {t('enrich_maxmind')}: {t('enrich_need_api_key')}")
    if ip2.get("available"):
        print(f"  {t('enrich_ip2location')}: {ip2.get('country_code') or 'N/A'} ({ip2.get('country') or 'N/A'})")
    else:
        print(f"  {t('enrich_ip2location')}: {t('enrich_need_api_key')}")

def get_own_public_egress_info() -> Optional[Dict]:
    """Public egress IP and brief geo for this machine (ip-api.com, no target IP in URL)."""
    try:
        url = "http://ip-api.com/json/?fields=status,query,country,countryCode,city,isp,org,as"
        req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
        with urllib.request.urlopen(req, timeout=6) as response:
            data = json.loads(response.read().decode("utf-8"))
        if data.get("status") != "success":
            return None
        return {
            "ip": data.get("query"),
            "country": data.get("country"),
            "country_code": data.get("countryCode"),
            "city": data.get("city"),
            "isp": data.get("isp"),
            "org": data.get("org"),
            "asn": data.get("as"),
        }
    except Exception:
        return None

def print_startup_connection_banner() -> None:
    """ASCII frame with this host's public egress info (once per process)."""
    info = get_own_public_egress_info()
    inner_w = 58
    top = "+" + ("=" * inner_w) + "+"

    def row(text: str) -> str:
        text = text.replace("\r", " ")
        if len(text) > inner_w - 2:
            text = text[: max(1, inner_w - 5)] + "..."
        pad = inner_w - 2 - len(text)
        return "| " + text + (" " * max(0, pad)) + " |"

    # Keep startup frame compact and readable in narrow terminals.
    print(f"\n{Colors.OKBLUE}{top}{Colors.ENDC}")
    if info and info.get("ip"):
        loc = f"{info.get('city') or ''}, {info.get('country') or ''}".strip(", ").strip()
        print(f"{Colors.OKCYAN}{row(t('startup_public_ip') + str(info.get('ip')))}{Colors.ENDC}")
        print(f"{Colors.OKCYAN}{row(t('startup_location') + loc)}{Colors.ENDC}")
        isp = (info.get("isp") or info.get("org") or "")[: max(0, inner_w - 12)]
        print(f"{Colors.OKCYAN}{row(t('startup_isp') + isp)}{Colors.ENDC}")
        asn = (info.get("asn") or "")[: max(0, inner_w - 8)]
        if asn:
            print(f"{Colors.OKCYAN}{row(t('startup_asn') + asn)}{Colors.ENDC}")
    else:
        print(f"{Colors.WARNING}{row(t('startup_fetch_fail'))}{Colors.ENDC}")
    print(f"{Colors.OKBLUE}{top}{Colors.ENDC}\n")

_ABUSE_LINE_PATTERNS = [
    re.compile(r"^\s*abuse-mailbox\s*:\s*(.+)$", re.IGNORECASE | re.MULTILINE),
    re.compile(r"^\s*abuse-e-mail\s*:\s*(.+)$", re.IGNORECASE | re.MULTILINE),
    re.compile(r"^\s*orgabuseemail\s*:\s*(.+)$", re.IGNORECASE | re.MULTILINE),
    re.compile(r"^\s*% abuse contact for .+?:\s*(.+)$", re.IGNORECASE | re.MULTILINE),
]
_ABUSE_HANDLE_RE = re.compile(r"^\s*abuse-c\s*:\s*([A-Z0-9\-_]{2,32})\s*$", re.IGNORECASE | re.MULTILINE)

_EMAIL_RE = re.compile(r"\b[A-Z0-9._%+\-]+@[A-Z0-9.\-]+\.[A-Z]{2,}\b", re.IGNORECASE)

def extract_candidate_abuse_emails(whois_text: str) -> List[str]:
    """Extract likely abuse/security contacts from WHOIS text as fallback."""
    if not whois_text:
        return []
    scored: List[tuple[int, str]] = []
    seen = set()
    for line in whois_text.splitlines():
        emails = _EMAIL_RE.findall(line)
        if not emails:
            continue
        l = line.lower()
        score = 0
        if "abuse" in l:
            score += 100
        if "security" in l or "incident" in l or "cert" in l:
            score += 60
        if "noc" in l or "admin" in l:
            score += 30
        for e in emails:
            key = e.lower()
            if key in seen:
                continue
            seen.add(key)
            scored.append((score, e))
    scored.sort(key=lambda x: (-x[0], x[1]))
    return [e for _, e in scored[:3]]

def parse_abuse_from_whois(whois_text: str) -> Optional[str]:
    """Best-effort abuse contact from WHOIS text."""
    if not whois_text:
        return None
    found: List[str] = []
    for pat in _ABUSE_LINE_PATTERNS:
        for m in pat.finditer(whois_text):
            val = (m.group(1) or "").strip()
            if val and val not in found:
                found.append(val)
    if not found:
        return None
    return " | ".join(found[:3])

def extract_abuse_handle(whois_text: str) -> Optional[str]:
    """Extract abuse-c handle (e.g. ATI) for additional WHOIS lookup."""
    if not whois_text:
        return None
    m = _ABUSE_HANDLE_RE.search(whois_text)
    if not m:
        return None
    return (m.group(1) or "").strip() or None

def print_abuse_line_from_whois_text(whois_text: str) -> None:
    abuse = parse_abuse_from_whois(whois_text)
    if abuse:
        print(f"{Colors.OKCYAN}{t('abuse_contact')}{Colors.ENDC}{abuse}")
    else:
        print(f"{Colors.OKCYAN}{t('abuse_contact')}{Colors.ENDC}{t('abuse_not_found')}")

def print_abuse_with_rir_fallback(ip: str, whois_data: Optional[Dict], whois_timeout: int = 14) -> None:
    """Print abuse contact from current WHOIS data, fallback to explicit RIR WHOIS query."""
    w = whois_data or {}
    all_whois_texts: List[str] = []
    if w.get("whois_text"):
        all_whois_texts.append(w.get("whois_text", ""))
    abuse = parse_abuse_from_whois(w.get("whois_text", ""))
    if abuse:
        print(f"{Colors.OKCYAN}{t('abuse_contact')}{Colors.ENDC}{abuse}")
        return

    handle = extract_abuse_handle(w.get("whois_text", ""))
    if handle:
        resolved = resolve_abuse_handle_contact(handle, w.get("whois_server"), timeout_seconds=max(8, whois_timeout))
        if resolved:
            print(f"{Colors.OKCYAN}{t('abuse_contact')}{Colors.ENDC}{' | '.join(resolved)}")
            return

    fallback_server = default_whois_server_for_rir(w.get("rir"))
    if fallback_server:
        print(f"{Colors.WARNING}{t('abuse_rir_fallback_lookup')}{fallback_server}{Colors.ENDC}")
        wr = get_whois_data(ip, timeout_seconds=max(8, whois_timeout), whois_server=fallback_server)
        print(f"{Colors.OKCYAN}{t('abuse_rir_fallback_done')}{fallback_server}{Colors.ENDC}")
        if wr and wr.get("whois_text"):
            all_whois_texts.append(wr.get("whois_text", ""))
            abuse_rir = parse_abuse_from_whois(wr.get("whois_text", ""))
            if abuse_rir:
                print(f"{Colors.OKCYAN}{t('abuse_contact')}{Colors.ENDC}{abuse_rir}")
                return
            handle_rir = extract_abuse_handle(wr.get("whois_text", ""))
            if handle_rir:
                resolved_rir = resolve_abuse_handle_contact(handle_rir, fallback_server, timeout_seconds=max(8, whois_timeout))
                if resolved_rir:
                    print(f"{Colors.OKCYAN}{t('abuse_contact')}{Colors.ENDC}{' | '.join(resolved_rir)}")
                    return

    # Final fallback: infer likely abuse/security contact emails from WHOIS content.
    candidates: List[str] = []
    for text in all_whois_texts:
        for email in extract_candidate_abuse_emails(text):
            if email not in candidates:
                candidates.append(email)
    if candidates:
        print(f"{Colors.OKCYAN}{t('abuse_contact_inferred')}{Colors.ENDC}{' | '.join(candidates[:3])}")
        return

    print(f"{Colors.OKCYAN}{t('abuse_contact')}{Colors.ENDC}{t('abuse_not_found')}")

def fetch_and_print_abuse_contact(ip: str, whois_timeout: int = 14) -> None:
    """WHOIS lookup and print abuse line (with RIR fallback if primary WHOIS has no abuse)."""
    if sys.stdout.isatty():
        print(f"{Colors.WARNING}{t('abuse_whois_lookup')}{Colors.ENDC}")
    w = get_whois_data(ip, timeout_seconds=whois_timeout)
    if not w or w.get("error"):
        suffix = f" ({w['error']})" if w and w.get("error") else ""
        print(f"{Colors.OKCYAN}{t('abuse_contact')}{Colors.ENDC}{t('abuse_not_found')}{suffix}")
        return
    print_abuse_with_rir_fallback(ip, w, whois_timeout=whois_timeout)

def resolve_abuse_handle_contact(handle: str, whois_server: Optional[str], timeout_seconds: int = 12) -> List[str]:
    """Resolve abuse-c handle into likely contact emails via raw WHOIS query."""
    cmd = ["whois", handle]
    if whois_server:
        cmd = ["whois", "-h", whois_server, handle]
    try:
        r = subprocess.run(cmd, text=True, capture_output=True, timeout=timeout_seconds, check=False)
    except Exception:
        return []
    text = r.stdout or ""
    vals: List[str] = []
    parsed = parse_abuse_from_whois(text)
    if parsed:
        vals.extend([x.strip() for x in parsed.split("|") if x.strip()])
    for e in extract_candidate_abuse_emails(text):
        if e not in vals:
            vals.append(e)
    return vals[:3]

def run_external_tool(argv: List[str]) -> None:
    """Run a command with inherited stdio."""
    try:
        subprocess.run(argv, check=False)
    except FileNotFoundError:
        print(f"{Colors.FAIL}{t('tools_cmd_missing')}{argv[0]}{Colors.ENDC}")
    except OSError as exc:
        print(f"{Colors.FAIL}{str(exc)}{Colors.ENDC}")


def _terminate_process_group(proc: subprocess.Popen) -> None:
    """Stop child process (and its group on POSIX when start_new_session was used)."""
    if proc.poll() is not None:
        return
    if os.name == "nt":
        proc.terminate()
    else:
        try:
            os.killpg(proc.pid, signal.SIGTERM)
        except (ProcessLookupError, PermissionError):
            proc.terminate()
    try:
        proc.wait(timeout=15)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait(timeout=5)


def run_nmap_interruptible(argv: List[str]) -> None:
    """
    Run nmap in its own process group so Ctrl+C / Ctrl+Z (SIGTSTP on POSIX) can stop it
    and return to the tools menu without exiting the checker.
    """
    hint_key = "tools_nmap_interrupt_hint_win" if os.name == "nt" else "tools_nmap_interrupt_hint"
    print(f"{Colors.WARNING}{t(hint_key)}{Colors.ENDC}")
    popen_kw: Dict = {}
    if os.name == "nt":
        popen_kw["creationflags"] = getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0)
    else:
        # Start a separate session to kill nmap cleanly on Ctrl+Z/Ctrl+C.
        popen_kw["start_new_session"] = True
    try:
        proc = subprocess.Popen(argv, **popen_kw)
    except FileNotFoundError:
        print(f"{Colors.FAIL}{t('tools_cmd_missing')}{argv[0]}{Colors.ENDC}")
        return
    except OSError as exc:
        print(f"{Colors.FAIL}{str(exc)}{Colors.ENDC}")
        return

    interrupted = False
    old_tstp = None

    def _on_sigtstp(_signum, _frame) -> None:
        """POSIX: stop nmap group with SIGTERM (async-signal-safe primitives only)."""
        nonlocal interrupted
        interrupted = True
        try:
            os.killpg(proc.pid, signal.SIGTERM)
        except (ProcessLookupError, PermissionError, AttributeError):
            try:
                os.kill(proc.pid, signal.SIGTERM)
            except (ProcessLookupError, PermissionError):
                pass

    if os.name != "nt" and hasattr(signal, "SIGTSTP"):
        old_tstp = signal.signal(signal.SIGTSTP, _on_sigtstp)

    try:
        while proc.poll() is None:
            try:
                time.sleep(0.2)
            except KeyboardInterrupt:
                interrupted = True
                _terminate_process_group(proc)
                break
    finally:
        if old_tstp is not None:
            signal.signal(signal.SIGTSTP, old_tstp)

    try:
        proc.wait(timeout=1)
    except subprocess.TimeoutExpired:
        _terminate_process_group(proc)

    if interrupted:
        print(f"\n{Colors.OKCYAN}{t('tools_nmap_interrupted')}{Colors.ENDC}")


def traceroute_cmd_to_google(is_windows: bool) -> List[str]:
    """Limited hop count and wait so traceroute does not run unbounded."""
    if is_windows:
        # -h limits hops, -w limits per-hop wait in milliseconds.
        return ["tracert", "-h", "20", "-w", "3000", "8.8.8.8"]
    # -m max hops, -q one probe, -w per-probe timeout (seconds).
    return ["traceroute", "-m", "20", "-q", "1", "-w", "3", "8.8.8.8"]


def offer_network_tools_menu(target_ip: str) -> None:
    """Optional nmap / traceroute / nslookup after a check (TTY only)."""
    if not (sys.stdin.isatty() and sys.stdout.isatty()):
        return
    is_win = platform.system().lower().startswith("win")
    while True:
        print(f"\n{Colors.HEADER}{'-' * 60}{Colors.ENDC}")
        print(f"{Colors.BOLD}{t('tools_menu_title')}: {target_ip}{Colors.ENDC}")
        print(f"{Colors.OKCYAN}{t('tools_1')}{Colors.ENDC}")
        print(f"{Colors.OKCYAN}{t('tools_2')}{Colors.ENDC}")
        print(f"{Colors.OKCYAN}{t('tools_3')}{Colors.ENDC}")
        print(f"{Colors.OKCYAN}{t('tools_0')}{Colors.ENDC}")
        try:
            choice = input(f"{Colors.WARNING}{t('tools_prompt')}{Colors.ENDC}").strip()
        except (EOFError, KeyboardInterrupt):
            print()
            break
        if choice == "0":
            break
        if choice == "1":
            if not shutil.which("nmap"):
                print(f"{Colors.FAIL}{t('tools_cmd_missing')}nmap{Colors.ENDC}")
                continue
            cmd = ["nmap", "-A", "-T4", target_ip]
            print(f"{Colors.OKCYAN}{t('tools_running')}{' '.join(cmd)}{Colors.ENDC}")
            run_nmap_interruptible(cmd)
            print(f"{Colors.OKGREEN}{t('tools_done')}{Colors.ENDC}")
        elif choice == "2":
            hop_cmd = traceroute_cmd_to_google(is_win)
            if not shutil.which(hop_cmd[0]):
                print(f"{Colors.FAIL}{t('tools_cmd_missing')}{hop_cmd[0]}{Colors.ENDC}")
                continue
            print(f"{Colors.OKCYAN}{t('tools_running')}{' '.join(hop_cmd)}{Colors.ENDC}")
            run_external_tool(hop_cmd)
            print(f"{Colors.OKGREEN}{t('tools_done')}{Colors.ENDC}")
        elif choice == "3":
            if not shutil.which("nslookup"):
                print(f"{Colors.FAIL}{t('tools_cmd_missing')}nslookup{Colors.ENDC}")
                continue
            cmd = ["nslookup", target_ip]
            print(f"{Colors.OKCYAN}{t('tools_running')}{' '.join(cmd)}{Colors.ENDC}")
            run_external_tool(cmd)
            print(f"{Colors.OKGREEN}{t('tools_done')}{Colors.ENDC}")
        else:
            print(f"{Colors.WARNING}{t('tools_invalid')}{Colors.ENDC}")

def get_whois_data(ip: str, timeout_seconds: int = 20, whois_server: Optional[str] = None) -> Optional[Dict]:
    """Get WHOIS data for an IP address"""
    try:
        cmd = ['whois', ip]
        if whois_server:
            cmd = ['whois', '-h', whois_server, ip]
        process = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )

        show_timer = sys.stdout.isatty()
        start_time = time.monotonic()
        last_remaining = None

        while process.poll() is None:
            elapsed = time.monotonic() - start_time
            remaining = max(0, int(timeout_seconds - elapsed + 0.999))

            if show_timer and remaining != last_remaining:
                if CURRENT_LANGUAGE == "ru":
                    print(f"\rWHOIS запрос... осталось {remaining} сек", end="", flush=True)
                else:
                    print(f"\rWHOIS request... {remaining}s remaining", end="", flush=True)
                last_remaining = remaining

            if elapsed >= timeout_seconds:
                process.kill()
                stdout, stderr = process.communicate()
                if show_timer:
                    print()
                return {'error': f'timeout after {timeout_seconds}s'}

            time.sleep(0.2)

        stdout, stderr = process.communicate()
        if show_timer:
            print("\r" + " " * 60 + "\r", end="", flush=True)

        result = subprocess.CompletedProcess(
            args=cmd,
            returncode=process.returncode,
            stdout=stdout,
            stderr=stderr
        )
        whois_text = result.stdout
        
        asn = None
        country = None
        org = None
        referred_server = None
        
        asn_patterns = [
            re.compile(r'\bAS(\d{1,10})\b', re.IGNORECASE),
            re.compile(r'\basn\s*[:=]?\s*(\d{1,10})\b', re.IGNORECASE),
            re.compile(r'\borigin(?:as)?\s*[:=]?\s*AS?(\d{1,10})\b', re.IGNORECASE),
            re.compile(r'\baut-num\s*[:=]?\s*AS?(\d{1,10})\b', re.IGNORECASE),
        ]

        for line in whois_text.split('\n'):
            line_lower = line.lower()

            if asn is None:
                for pattern in asn_patterns:
                    match = pattern.search(line)
                    if match:
                        asn = f"AS{match.group(1)}"
                        break

            if 'country' in line_lower:
                parts = line.split(':')
                if len(parts) > 1:
                    country = parts[-1].strip()[:2].upper()
            if org is None and (
                'orgname' in line_lower or 'org-name' in line_lower or 'organization' in line_lower
                or line_lower.startswith('owner:') or line_lower.startswith('ownername:')
                or line_lower.startswith('descr:') or line_lower.startswith('netname:')
            ):
                parts = line.split(':')
                if len(parts) > 1:
                    org = parts[-1].strip()
            if referred_server is None and ('refer:' in line_lower or 'whois:' in line_lower):
                parts = line.split(':', 1)
                if len(parts) > 1:
                    candidate = parts[1].strip()
                    if candidate:
                        referred_server = candidate
        
        if not whois_text.strip():
            return {'error': 'empty whois response'}

        inferred_server = whois_server or referred_server

        # Secondary referral lookup for sparse WHOIS outputs (common in some RIR responses).
        if inferred_server and (asn is None or org is None or country is None) and not whois_server:
            wr = get_whois_data(ip, timeout_seconds=max(8, timeout_seconds - 2), whois_server=inferred_server)
            if wr and not wr.get("error"):
                asn = asn or wr.get("asn")
                org = org or wr.get("org")
                country = country or wr.get("country")
                if wr.get("whois_text"):
                    whois_text = f"{whois_text}\n\n{wr.get('whois_text')}"
                inferred_server = wr.get("whois_server") or inferred_server

        rir = infer_rir_from_whois_server(inferred_server)
        return {
            'asn': asn,
            'country': country,
            'org': org,
            'whois_text': whois_text,
            'whois_server': inferred_server,
            'rir': rir,
        }
    except subprocess.TimeoutExpired:
        return {'error': f'timeout after {timeout_seconds}s'}
    except FileNotFoundError:
        return {'error': 'whois command not found'}
    except OSError as exc:
        return {'error': str(exc)}
    except Exception as exc:
        return {'error': str(exc)}

def assess_data_authenticity(
    geo_country: Optional[str],
    whois_country: Optional[str],
    whois_rir: Optional[str],
) -> Dict:
    """Heuristic authenticity signal based on geo vs WHOIS country and RIR region."""
    geo = normalize_country_code(geo_country)
    whois = normalize_country_code(whois_country)
    rir = (whois_rir or "").upper() or None
    warnings: List[str] = []

    if geo and whois and geo != whois:
        warnings.append(t("auth_check_warn_geo_whois"))
    if geo and rir and not country_in_rir_region(geo, rir):
        warnings.append(t("auth_check_warn_rir_geo"))

    return {
        "ok": len(warnings) == 0,
        "warnings": warnings,
        "geo_country": geo,
        "whois_country": whois,
        "whois_rir": rir,
    }

def parse_cli_args():
    """Parse command-line arguments for non-interactive mode."""
    parser = argparse.ArgumentParser(
        description="IP Address Geolocation Checker - Verify if IPs are in expected locations"
    )
    parser.add_argument("-i", "--ip", help="Single IP address to check")
    parser.add_argument(
        "-r", "--range", dest="ip_range", nargs=2, metavar=("START_IP", "END_IP"),
        help="IP range to check (start_ip end_ip)"
    )
    parser.add_argument("-a", "--asn", help="ASN to check (e.g., AS12389 or 12389)")
    parser.add_argument("-s", "--save", action="store_true", help="Save results to file")
    parser.add_argument("--max-ips", type=int, default=256, help="Maximum IPs to scan in range (default: 256)")
    parser.add_argument("--auto-reclass", action="store_true", help="Auto-confirm reclassification (no prompts)")
    parser.add_argument("--quiet", action="store_true", help="Suppress non-essential output")
    return parser.parse_args()

def save_results(results: List[Dict]) -> bool:
    """Save scan results to JSON file."""
    try:
        payload = {
            "timestamp": datetime.now().isoformat(),
            "results": results,
            "mismatches_found": sum(1 for r in results if r.get("mismatches"))
        }
        with open(RESULTS_FILE, "w", encoding="utf-8") as f:
            json.dump(payload, f, indent=2, ensure_ascii=False)
        return True
    except Exception as e:
        print(f"{Colors.FAIL}Failed to save results: {e}{Colors.ENDC}")
        return False

def get_best_pool_match(ip: str, database: Dict):
    """Return the most specific ASN pool matches for an IP."""
    ip_obj = ipaddress.ip_address(ip)
    candidates = []

    for asn_entry in database["asn_data"]:
        for pool in asn_entry["ip_pools"]:
            try:
                network = ipaddress.ip_network(pool, strict=False)
            except ValueError:
                continue
            if ip_obj in network:
                candidates.append((asn_entry, pool, network.prefixlen))

    if not candidates:
        return []

    best_prefix = max(item[2] for item in candidates)
    return [item for item in candidates if item[2] == best_prefix]

def update_database_entry(database: Dict, ip: str, asn: str, country_code: str, country_name: str, pool: str, org: str = None) -> bool:
    """Update or create ASN entry in database"""
    try:
        asn_entry = next((a for a in database['asn_data'] if a['asn'] == asn), None)
        
        if asn_entry:
            asn_entry['expected_country'] = country_code
            asn_entry['expected_country_name'] = country_name
            asn_entry['country_code'] = country_code
            asn_entry['country_name'] = country_name
            
            if org and org.strip():
                asn_entry['owner'] = org
            
            if pool not in asn_entry['ip_pools']:
                asn_entry['ip_pools'].append(pool)
            
            asn_entry['last_checked'] = datetime.now().strftime("%Y-%m-%d")
            asn_entry['notes'] = f"Updated: IP geolocation verified as {country_code} ({country_name})"
        else:
            new_entry = {
                'asn': asn,
                'owner': org or f"Auto-added from IP {ip}",
                'country_code': country_code,
                'country_name': country_name,
                'region': 'Multi-Regional',
                'expected_country': country_code,
                'expected_country_name': country_name,
                'ip_pools': [pool],
                'check_status': 'active',
                'last_checked': datetime.now().strftime("%Y-%m-%d"),
                'verified': False,
                'notes': f'Auto-added entry for {asn}'
            }
            database['asn_data'].append(new_entry)
        
        if 'countries' not in database['metadata']:
            database['metadata']['countries'] = {}
        
        if country_code not in database['metadata']['countries']:
            database['metadata']['countries'][country_code] = {
                'name': country_name,
                'operators_count': 0,
                'description': f'{country_name} operators'
            }
        
        database['metadata']['last_updated'] = datetime.now().strftime("%Y-%m-%d")
        database['metadata']['total_asns'] = len(database['asn_data'])
        database['metadata']['total_ip_pools'] = sum(len(a['ip_pools']) for a in database['asn_data'])
        
        save_database(database)
        
        return True
    except Exception as e:
        print(f"{Colors.FAIL}Error updating database: {e}{Colors.ENDC}")
        return False

def check_single_ip(
    ip: str,
    database: Dict,
    auto_reclass: bool = False,
    interactive_extras: bool = True,
) -> Dict:
    """Check a single IP address. When ``interactive_extras`` is True, show abuse (WHOIS) and optional tool menu."""
    print(f"\n{Colors.OKCYAN}{t('checking')}{ip}{Colors.ENDC}")
    
    try:
        ipaddress.ip_address(ip)
    except ValueError:
        return {'error': f'{t("invalid_ip")} {ip}'}
    
    geo_data = get_ip_geolocation(ip)
    
    if not geo_data['success']:
        print(f"{Colors.FAIL}{t('failed_geo')} {geo_data.get('error')}{Colors.ENDC}")
        return geo_data
    
    result = {
        'ip': ip,
        'actual_country': geo_data['country_code'],
        'actual_country_name': geo_data['country'],
        'region': geo_data['region'],
        'city': geo_data['city'],
        'isp': geo_data['isp'],
        'org': geo_data['org'],
        'asn': geo_data['asn'],
        'geo_data': geo_data,
        'matches': [],
        'mismatches': [],
        '_abuse_shown': False,
    }
    
    best_matches = get_best_pool_match(ip, database)

    if best_matches:
        asn_entry, pool, _ = best_matches[0]
        expected_country = asn_entry['expected_country']
        actual_country = geo_data['country_code']

        if len(best_matches) > 1:
            print(f"{Colors.WARNING}⚠ Multiple equally specific pools matched this IP. Using first match.{Colors.ENDC}")

        match_info = {
            'asn': asn_entry['asn'],
            'owner': asn_entry['owner'],
            'expected_country': expected_country,
            'expected_country_name': asn_entry['expected_country_name'],
            'pool': pool
        }

        if expected_country == actual_country:
            result['matches'].append(match_info)
            print(f"{Colors.OKGREEN}{t('matches')}{Colors.ENDC}")
            print(f"  {t('expected_country')} {expected_country} | {t('actual_country')} {actual_country}")
            print(f"  {t('asn')} {asn_entry['asn']}")
            print(f"  {t('pool')} {pool}")
            print(f"  {t('provider_owner')} {asn_entry['owner']}")
            if interactive_extras:
                fetch_and_print_abuse_contact(ip)
                result['_abuse_shown'] = True
        else:
            result['mismatches'].append({
                **match_info,
                'actual_country': actual_country,
                'actual_country_name': geo_data['country']
            })
            print(f"{Colors.FAIL}{t('mismatch')}{Colors.ENDC}")
            print(f"  {t('expected_country')} {Colors.OKGREEN}{expected_country} ({asn_entry['expected_country_name']}){Colors.ENDC} | {t('actual_country')} {Colors.FAIL}{actual_country} ({geo_data['country']}){Colors.ENDC}")
            print(f"  {t('asn')} {asn_entry['asn']}")
            print(f"  {t('pool')} {pool}")
            print(f"  {t('provider_owner')} {asn_entry['owner']}")
            if interactive_extras:
                fetch_and_print_abuse_contact(ip)
                result['_abuse_shown'] = True

            print(f"\n{Colors.WARNING}{t('offer_reclassify')}{Colors.ENDC}", end="")

            try:
                if auto_reclass:
                    offer_reclass = 'y'
                    print("y (auto)")
                else:
                    offer_reclass = input()
            except (EOFError, KeyboardInterrupt):
                offer_reclass = 'n'

            if offer_reclass.lower() == 'y':
                reclassified = reclassify_asn(result, database, auto_confirm=auto_reclass)
                result['mismatches'] = reclassified.get('mismatches', [])
                result['matches'] = reclassified.get('matches', [])
    else:
        print(f"{Colors.WARNING}{t('ip_not_found')}{Colors.ENDC}")
        result['status'] = 'not_in_database'

        # If IP is not in local pools, immediately run WHOIS report flow.
        print(f"{Colors.OKCYAN}{t('unknown_ip_no_local_data')}{Colors.ENDC}")
        handle_unknown_ip(ip, result, database, interactive_extras=interactive_extras)
    if best_matches:
        result['status'] = 'checked'

    if geo_data.get('success') and interactive_extras:
        if not result.get('_abuse_shown'):
            fetch_and_print_abuse_contact(ip)
            result['_abuse_shown'] = True
        offer_network_tools_menu(ip)

    return result

def handle_unknown_ip(
    ip: str,
    result: Dict,
    database: Dict,
    interactive_extras: bool = True,
) -> None:
    """Handle IP not found in database - check WHOIS and offer to add"""
    print(f"\n{Colors.OKCYAN}{t('unknown_ip_whois')}{Colors.ENDC}")
    
    whois_data = get_whois_data(ip)
    
    if not whois_data or whois_data.get('error'):
        print(f"{Colors.FAIL}{t('unknown_ip_whois_failed')}{Colors.ENDC}")
        if whois_data and whois_data.get('error'):
            print(f"{Colors.WARNING}{t('unknown_ip_whois_error')}{whois_data['error']}{Colors.ENDC}")
        return
    
    # Extract pool from IP (example: 83.1.1.1 -> 83.0.0.0/8)
    try:
        ip_obj = ipaddress.ip_address(ip)
        if isinstance(ip_obj, ipaddress.IPv4Address):
            octets = str(ip_obj).split('.')
            pool = f"{octets[0]}.0.0.0/8"
        else:
            pool = f"{ip}/128"
    except:
        pool = f"{ip}/32"
    
    detected_asn = whois_data.get('asn', 'UNKNOWN')
    detected_org = whois_data.get('org', 'Unknown Organization')
    detected_country = result.get('actual_country', 'UNKNOWN')
    detected_country_name = result.get('actual_country_name', 'Unknown')
    
    # Display detected information
    print(f"\n{Colors.HEADER}{'='*60}{Colors.ENDC}")
    print(f"{Colors.BOLD}WHOIS Information{Colors.ENDC}" if CURRENT_LANGUAGE == 'en' else f"{Colors.BOLD}Информация WHOIS{Colors.ENDC}")
    print(f"{Colors.HEADER}{'='*60}{Colors.ENDC}")
    
    print(f"{Colors.OKCYAN}{t('unknown_ip_detected_asn')}{Colors.ENDC}{detected_asn}")
    print(f"{Colors.OKCYAN}{t('unknown_ip_detected_org')}{Colors.ENDC}{detected_org}")
    print(f"{Colors.OKCYAN}{t('unknown_ip_detected_country')}{Colors.ENDC}{detected_country} ({detected_country_name})")
    print(f"{Colors.OKCYAN}Pool: {Colors.ENDC}{pool}")
    print(f"{Colors.OKCYAN}IP: {Colors.ENDC}{ip}")
    if interactive_extras and whois_data.get("whois_text"):
        print_abuse_with_rir_fallback(ip, whois_data, whois_timeout=12)
        result["_abuse_shown"] = True

    auth = assess_data_authenticity(
        geo_country=result.get("actual_country"),
        whois_country=whois_data.get("country"),
        whois_rir=whois_data.get("rir"),
    )
    if auth["ok"]:
        print(f"{Colors.OKGREEN}{t('auth_check_title')}{t('auth_check_ok')}{Colors.ENDC}")
    else:
        warn_text = f"{t('auth_check_title')}{'; '.join(auth['warnings'])}"
        # High-visibility warning: white text over red background.
        print(f"{Colors.WHITE}{Colors.BGRED}{warn_text}{Colors.ENDC}")

    if interactive_extras:
        print_enrichment_comparison(ip, result.get("geo_data", {}))

    # Ask if user wants to add to database
    print(f"\n{Colors.WARNING}{t('unknown_ip_add_offer')}{Colors.ENDC}", end="")
    try:
        add_choice = input().strip().lower()
    except (EOFError, KeyboardInterrupt):
        add_choice = 'n'
    
    if add_choice == 'y':
        print(f"{Colors.OKCYAN}{t('unknown_ip_adding')}{Colors.ENDC}")
        
        asn_to_add = detected_asn
        
        # If ASN not found, use fallback ASN automatically.
        if not detected_asn or str(detected_asn).upper() in {'UNKNOWN', 'NONE', 'N/A'}:
            print(f"{Colors.WARNING}{t('unknown_ip_asn_detect_failed')}{Colors.ENDC}")
            asn_to_add = 'none_ASN'
        
        if asn_to_add and asn_to_add != 'UNKNOWN':
            asn_clean = asn_to_add if (asn_to_add.startswith('AS') or asn_to_add == 'none_ASN') else f'AS{asn_to_add}'
            success = update_database_entry(
                database,
                ip=ip,
                asn=asn_clean,
                country_code=detected_country,
                country_name=detected_country_name,
                pool=pool,
                org=detected_org
            )
            
            if success:
                print(f"{Colors.OKGREEN}{t('unknown_ip_added')}{Colors.ENDC}")
                result['status'] = 'added_to_database'
            else:
                print(f"{Colors.FAIL}{t('unknown_ip_not_added')}{Colors.ENDC}")
        else:
            print(f"{Colors.WARNING}{t('unknown_ip_asn_skipped')}{Colors.ENDC}")
    else:
        print(f"{Colors.OKCYAN}{t('unknown_ip_not_added')}{Colors.ENDC}")
    
    print(f"{Colors.OKCYAN}{t('unknown_ip_back_menu')}{Colors.ENDC}\n")

def reclassify_asn(result: Dict, database: Dict, auto_confirm: bool = False) -> Dict:
    """Interactive reclassification of ASN"""
    print(f"\n{Colors.WARNING}{'='*60}{Colors.ENDC}")
    print(f"{Colors.BOLD}{t('reclassification')}{Colors.ENDC}")
    print(f"{Colors.WARNING}{'='*60}{Colors.ENDC}")
    
    ip = result['ip']
    print(f"\n📍 {t('ip_addr')} {ip}")
    print(f"{t('expected_country')} {result['mismatches'][0]['expected_country']} ({result['mismatches'][0]['expected_country_name']})")
    print(f"{t('actual_country')} {result['actual_country']} ({result['actual_country_name']})")
    print(f"{t('current_provider')} {result['mismatches'][0]['owner']}")
    print(f"{t('detected_provider')} {result.get('org', 'Unknown')}")
    
    print(f"\n{Colors.OKCYAN}{t('step1')}{Colors.ENDC}")
    whois_data = get_whois_data(ip)
    geo_data = result.get('geo_data', {})
    
    if whois_data:
        print(f"  ASN: {whois_data['asn'] or 'N/A'}")
        print(f"  {t('actual_country')}: {whois_data['country'] or 'N/A'}")
        print(f"  Org: {whois_data['org'] or 'N/A'}")
    
    print(f"  Geo API Org: {geo_data.get('org', 'N/A')}")
    print(f"  Geo API {t('actual_country')}: {geo_data.get('country_code', 'N/A')}")

    mismatch = result['mismatches'][0]
    policy = resolve_country_conflict_policy(
        ip=ip,
        expected_country=mismatch.get('expected_country'),
        ip_api_country=result.get('actual_country'),
        whois_country=(whois_data or {}).get('country'),
        whois_rir=(whois_data or {}).get('rir'),
    )
    print(f"  Policy: {policy['action']} (score={policy['confidence_score']})")
    print(f"  Policy reason: {policy['reason']}")
    if (whois_data or {}).get("rir"):
        print(f"  WHOIS RIR: {(whois_data or {}).get('rir')}")
    
    print(f"\n{Colors.OKCYAN}{t('step2')}{Colors.ENDC}")
    print(f"{Colors.WARNING}{t('will_update')}:{Colors.ENDC}")
    print(f"  {t('country')}: {mismatch['expected_country']}{t('from_to')}{result['actual_country']}")
    print(f"  {t('provider')}: {mismatch['owner']}{t('from_to')}{result.get('org', 'Unknown')}")

    if policy["action"] == "quarantine":
        append_quarantine_case(
            database,
            ip=ip,
            asn=mismatch.get("asn"),
            pool=mismatch.get("pool"),
            expected_country=mismatch.get("expected_country"),
            ip_api_country=result.get("actual_country"),
            whois_country=(whois_data or {}).get("country"),
            whois_rir=(whois_data or {}).get("rir"),
            reason=policy["reason"],
            confidence_score=policy["confidence_score"],
        )
        save_database(database)
        print(f"{Colors.WARNING}⚠ Conflict quarantined: WHOIS and ip-api disagree. No DB write performed.{Colors.ENDC}")
        return result
    if policy["action"] == "keep_expected":
        print(f"{Colors.OKCYAN}Policy decision: keep expected country. Database remains unchanged.{Colors.ENDC}")
        return result
    
    try:
        if auto_confirm:
            confirm = 'y'
            print(f"{t('auto_updating')}")
        else:
            confirm = input(f"{Colors.WARNING}{t('confirm')}{Colors.ENDC}")
    except (EOFError, KeyboardInterrupt):
        confirm = 'y' if auto_confirm else 'n'
    
    if confirm.lower() == 'y':
        pool = mismatch['pool']
        org_name = result.get('org')
        target_country = policy.get("target_country") or result['actual_country']
        target_country_name = result['actual_country_name'] if target_country == result['actual_country'] else result['actual_country_name']
        
        if update_database_entry(database, ip, mismatch['asn'], target_country,
                                target_country_name, pool, org_name):
            print(f"{Colors.OKGREEN}{t('db_updated')}{Colors.ENDC}")
            
            print(f"\n{Colors.OKCYAN}{t('step3')}...{Colors.ENDC}")
            database = load_database()
            recheck_result = check_single_ip(ip, database, interactive_extras=False)
            
            print(f"\n{Colors.OKCYAN}{t('step4')}{Colors.ENDC}")
            if recheck_result.get('matches'):
                print(f"{Colors.OKGREEN}{'='*60}{Colors.ENDC}")
                print(f"{Colors.OKGREEN}{t('recheck_success')}{Colors.ENDC}")
                print(f"{Colors.OKGREEN}{t('resolved')}{Colors.ENDC}")
                print(f"{t('classified')} {result['actual_country']}")
                print(f"{Colors.OKGREEN}{'='*60}{Colors.ENDC}")
                return recheck_result
            else:
                print(f"{Colors.FAIL}{'='*60}{Colors.ENDC}")
                print(f"{Colors.FAIL}{t('verify_complete')}{Colors.ENDC}")
                print(f"{Colors.FAIL}{t('incorrect')}{Colors.ENDC}")
                print(f"{t('spoofing_warning')}")
                print(f"{Colors.FAIL}{'='*60}{Colors.ENDC}")
                return recheck_result
    else:
        print(f"{Colors.WARNING}{t('cancelled')}{Colors.ENDC}")
    
    return result

def check_ip_range(start: str, end: str, database: Dict, max_ips: int = 256, auto_reclass: bool = False) -> List[Dict]:
    """Check IPs in range with a maximum limit."""
    try:
        start_ip = ipaddress.ip_address(start)
        end_ip = ipaddress.ip_address(end)
    except ValueError:
        print(f"{Colors.FAIL}❌ Invalid IP address{Colors.ENDC}")
        return []

    if start_ip.version != end_ip.version or start_ip > end_ip:
        print(f"{Colors.FAIL}❌ Invalid IP range{Colors.ENDC}")
        return []

    results = []
    current = start_ip
    count = 0
    max_ips = max(1, max_ips)

    while current <= end_ip and count < max_ips:
        result = check_single_ip(
            str(current), database, auto_reclass=auto_reclass, interactive_extras=False
        )
        results.append(result)
        current += 1
        count += 1

    return results

def check_asn_operator(asn_input: str, database: Dict, auto_reclass: bool = False, max_ips: int = 256) -> List[Dict]:
    """Check a single ASN by sampling one IP per pool."""
    asn_query = asn_input if asn_input.upper().startswith("AS") else f"AS{asn_input}"
    asn_data = next((a for a in database['asn_data'] if a['asn'].upper() == asn_query.upper()), None)

    if not asn_data:
        print(f"{Colors.FAIL}❌ ASN not found{Colors.ENDC}")
        return []

    print(f"\n{Colors.OKCYAN}Checking ASN: {asn_query}{Colors.ENDC}")
    print(f"  Owner: {asn_data['owner']}")
    print(f"  {t('expected_country')}: {asn_data['expected_country']} ({asn_data['expected_country_name']})")

    results = []
    for pool in asn_data['ip_pools'][:max(1, max_ips)]:
        try:
            network = ipaddress.ip_network(pool, strict=False)
            result = check_single_ip(
                str(network.network_address),
                database,
                auto_reclass=auto_reclass,
                interactive_extras=False,
            )
            results.append(result)
        except ValueError:
            continue

    return results

def run_cli_mode(args):
    """Run command-line mode when direct arguments are provided."""
    database = load_database()
    maybe_prompt_database_update(database)
    tty = sys.stdin.isatty() and sys.stdout.isatty()

    def execute():
        if args.ip:
            return [
                check_single_ip(
                    args.ip,
                    database,
                    auto_reclass=args.auto_reclass,
                    interactive_extras=tty,
                )
            ]
        if args.ip_range:
            return check_ip_range(
                args.ip_range[0],
                args.ip_range[1],
                database,
                max_ips=args.max_ips,
                auto_reclass=args.auto_reclass
            )
        if args.asn:
            return check_asn_operator(
                args.asn,
                database,
                auto_reclass=args.auto_reclass,
                max_ips=args.max_ips
            )
        return []

    if args.quiet and not args.auto_reclass:
        print(f"{Colors.WARNING}--quiet requires --auto-reclass for non-interactive execution. Running with normal output.{Colors.ENDC}")

    use_quiet_capture = args.quiet and args.auto_reclass
    if use_quiet_capture:
        with io.StringIO() as buffer, redirect_stdout(buffer):
            results = execute()
    else:
        results = execute()

    if results:
        show_summary(results)
        if args.save:
            if save_results(results):
                print(f"{Colors.OKGREEN}✓ Results saved: {RESULTS_FILE}{Colors.ENDC}")

def main():
    args = parse_cli_args()

    # Load saved language
    load_language_config()
    
    # If first time (no language set), show language menu
    if CURRENT_LANGUAGE is None:
        select_language_menu()

    print_startup_connection_banner()

    if args.ip or args.ip_range or args.asn:
        run_cli_mode(args)
        return
    
    database = load_database()
    
    # Main interactive loop
    while True:
        print(f"\n{Colors.HEADER}{Colors.BOLD}{'='*60}{Colors.ENDC}")
        print(f"{Colors.BOLD}{t('app_title')}{Colors.ENDC}")
        print(f"{Colors.HEADER}{Colors.BOLD}{'='*60}{Colors.ENDC}\n")
        
        if CURRENT_LANGUAGE == "ru":
            print("1. Проверить IP адрес")
            print("2. Проверить диапазон IP")
            print("3. Проверить ASN оператора")
            print("4. Выбрать язык")
            print("5. Справка")
            print("6. Обновить базу")
            print(t("menu_7"))
            print("0. Выход")
            prompt_text = t("menu_prompt_main")
        else:
            print("1. Check single IP address")
            print("2. Check IP range")
            print("3. Check ASN operator")
            print("4. Change language")
            print("5. Help")
            print("6. Update database")
            print(t("menu_7"))
            print("0. Exit")
            prompt_text = t("menu_prompt_main")
        
        try:
            choice = input(f"{Colors.OKCYAN}{prompt_text}{Colors.ENDC}").strip()
        except KeyboardInterrupt:
            print(f"\n{Colors.OKGREEN}Goodbye!{Colors.ENDC}\n")
            break
        except EOFError:
            break
        
        if choice == "0":
            if CURRENT_LANGUAGE == "ru":
                print(f"{Colors.OKGREEN}До свидания!{Colors.ENDC}\n")
            else:
                print(f"{Colors.OKGREEN}Goodbye!{Colors.ENDC}\n")
            break
        
        elif choice == "1":
            # Check single IP
            try:
                ip_input = input(f"{Colors.OKCYAN}IP: {Colors.ENDC}").strip()
                if ip_input:
                    database = load_database()
                    result = check_single_ip(ip_input, database, auto_reclass=False)
                    if not result.get('error'):
                        show_summary([result])
                        offer_save_report([result])
            except KeyboardInterrupt:
                continue
        
        elif choice == "2":
            # Check IP range
            try:
                start = input(f"{Colors.OKCYAN}Start IP: {Colors.ENDC}").strip()
                end = input(f"{Colors.OKCYAN}End IP: {Colors.ENDC}").strip()
                if start and end:
                    try:
                        start_ip = ipaddress.ip_address(start)
                        end_ip = ipaddress.ip_address(end)
                        current = start_ip
                        count = 0
                        max_ips = 10
                        results = []
                        
                        if CURRENT_LANGUAGE == "ru":
                            print(f"\n{Colors.OKCYAN}Сканирование {max_ips} IP...{Colors.ENDC}\n")
                        else:
                            print(f"\n{Colors.OKCYAN}Scanning {max_ips} IPs...{Colors.ENDC}\n")
                        
                        while current <= end_ip and count < max_ips:
                            database = load_database()
                            result = check_single_ip(
                                str(current), database, interactive_extras=False
                            )
                            results.append(result)
                            current += 1
                            count += 1
                        
                        if results:
                            show_summary(results)
                            offer_save_report(results)
                    except ValueError:
                        if CURRENT_LANGUAGE == "ru":
                            print(f"{Colors.FAIL}❌ Неверный IP адрес{Colors.ENDC}")
                        else:
                            print(f"{Colors.FAIL}❌ Invalid IP address{Colors.ENDC}")
            except KeyboardInterrupt:
                continue
        
        elif choice == "3":
            # Check ASN
            try:
                asn_input = input(f"{Colors.OKCYAN}ASN (e.g., AS12389 or 12389): {Colors.ENDC}").strip()
                if asn_input:
                    asn_query = asn_input if asn_input.startswith('AS') else f'AS{asn_input}'
                    database = load_database()
                    asn_data = next((a for a in database['asn_data'] if a['asn'].upper() == asn_query.upper()), None)
                    
                    if asn_data:
                        if CURRENT_LANGUAGE == "ru":
                            print(f"\n{Colors.OKCYAN}Проверка ASN: {asn_query}{Colors.ENDC}")
                        else:
                            print(f"\n{Colors.OKCYAN}Checking ASN: {asn_query}{Colors.ENDC}")
                        
                        print(f"  Owner: {asn_data['owner']}")
                        print(f"  {t('expected_country')}: {asn_data['expected_country']} ({asn_data['expected_country_name']})")
                        
                        results = []
                        for pool in asn_data['ip_pools'][:3]:
                            try:
                                network = ipaddress.ip_network(pool)
                                result = check_single_ip(
                                    str(network.network_address),
                                    database,
                                    interactive_extras=False,
                                )
                                results.append(result)
                            except:
                                pass
                        
                        if results:
                            show_summary(results)
                            offer_save_report(results)
                    else:
                        if CURRENT_LANGUAGE == "ru":
                            print(f"{Colors.FAIL}❌ ASN не найден{Colors.ENDC}")
                        else:
                            print(f"{Colors.FAIL}❌ ASN not found{Colors.ENDC}")
            except KeyboardInterrupt:
                continue
        
        elif choice == "4":
            # Change language
            select_language_menu()
        
        elif choice == "5":
            # Show help
            show_help()
        
        elif choice == "6":
            print(f"{Colors.OKCYAN}{t('db_update_started')}{Colors.ENDC}")
            ok, reason = perform_database_update(database)
            if ok:
                print(f"{Colors.OKGREEN}{t('db_update_success')}{Colors.ENDC}")
                database = load_database()
            else:
                print(f"{Colors.FAIL}{t('db_update_failed')}{reason or 'unknown error'}{Colors.ENDC}")
        elif choice == "7":
            configure_enrichment_keys_menu()

        else:
            if CURRENT_LANGUAGE == "ru":
                print(f"{Colors.FAIL}❌ Неверный выбор{Colors.ENDC}")
            else:
                print(f"{Colors.FAIL}❌ Invalid choice{Colors.ENDC}")

def show_summary(results: List[Dict]):
    """Display summary of results"""
    mismatches = sum(1 for r in results if r.get('mismatches'))
    matches = sum(1 for r in results if r.get('matches'))
    
    print(f"\n{Colors.BOLD}{'='*60}{Colors.ENDC}")
    print(f"{Colors.BOLD}{t('summary')}{Colors.ENDC}")
    print(f"{Colors.BOLD}{'='*60}{Colors.ENDC}")
    print(f"{t('total')} {len(results)}")
    print(f"{Colors.OKGREEN}{t('match_count')} {matches}{Colors.ENDC}")
    if mismatches > 0:
        print(f"{Colors.FAIL}{t('mismatch_count')} {mismatches}{Colors.ENDC}")
    else:
        print(f"{Colors.OKGREEN}{t('mismatch_count')} 0{Colors.ENDC}")

def offer_save_report(results: List[Dict]) -> None:
    """Offer to persist current report to scan_results.json in interactive mode."""
    if not (sys.stdin.isatty() and sys.stdout.isatty()):
        return

    while True:
        print(f"\n{Colors.WARNING}{t('save_report_offer')}{Colors.ENDC}", end="")
        try:
            choice = input().strip().lower()
        except (EOFError, KeyboardInterrupt):
            print()
            return

        if choice in ("y", "n"):
            break
        print(f"{Colors.WARNING}{t('unknown_ip_invalid_yes_no')}{Colors.ENDC}")

    if choice == "y":
        if save_results(results):
            print(f"{Colors.OKGREEN}{t('save_report_yes')}{RESULTS_FILE}{Colors.ENDC}")
        else:
            print(f"{Colors.FAIL}{t('save_report_failed')}{Colors.ENDC}")
    else:
        print(f"{Colors.OKCYAN}{t('save_report_no')}{Colors.ENDC}")

def show_help():
    """Show help menu"""
    print(f"\n{Colors.BOLD}{'='*60}{Colors.ENDC}")
    if CURRENT_LANGUAGE == "ru":
        print(f"{Colors.BOLD}ℹ️  СПРАВКА{Colors.ENDC}")
        print(f"{Colors.BOLD}{'='*60}{Colors.ENDC}\n")
        print(f"{Colors.OKCYAN}1. Проверить IP адрес{Colors.ENDC}")
        print("   Введите один IP адрес (например: 83.1.1.1)")
        print("   Проверяет, соответствует ли IP ожидаемой стране\n")
        
        print(f"{Colors.OKCYAN}2. Проверить диапазон IP{Colors.ENDC}")
        print("   Введите начальный и конечный IP")
        print("   Проверяет до 10 IP адресов из диапазона\n")
        
        print(f"{Colors.OKCYAN}3. Проверить ASN оператора{Colors.ENDC}")
        print("   Введите ASN (например: AS12389 или 12389)")
        print("   Проверяет все пулы IP этого оператора\n")
        
        print(f"{Colors.OKCYAN}4. Выбрать язык{Colors.ENDC}")
        print("   Переключение между English и Русский\n")

        print(f"{Colors.OKCYAN}6. Обновить базу{Colors.ENDC}")
        print("   Обновляет метаданные БД и дату последнего обновления\n")
        
        print(f"{Colors.OKGREEN}✓ При обнаружении несоответствия:{Colors.ENDC}")
        print("  - Система предложит переклассифицировать ASN")
        print("  - Выполнит WHOIS поиск")
        print("  - Обновит базу с актуальной информацией")
        print("  - Повторно проверит IP\n")
    else:
        print(f"{Colors.BOLD}ℹ️  HELP{Colors.ENDC}")
        print(f"{Colors.BOLD}{'='*60}{Colors.ENDC}\n")
        print(f"{Colors.OKCYAN}1. Check single IP address{Colors.ENDC}")
        print("   Enter one IP address (e.g.: 83.1.1.1)")
        print("   Verifies if IP matches expected country\n")
        
        print(f"{Colors.OKCYAN}2. Check IP range{Colors.ENDC}")
        print("   Enter start and end IP addresses")
        print("   Checks up to 10 IPs from the range\n")
        
        print(f"{Colors.OKCYAN}3. Check ASN operator{Colors.ENDC}")
        print("   Enter ASN (e.g.: AS12389 or 12389)")
        print("   Checks all IP pools for this operator\n")
        
        print(f"{Colors.OKCYAN}4. Change language{Colors.ENDC}")
        print("   Switch between English and Русский\n")

        print(f"{Colors.OKCYAN}6. Update database{Colors.ENDC}")
        print("   Refreshes DB metadata and last update timestamp\n")
        
        print(f"{Colors.OKGREEN}✓ When mismatch is detected:{Colors.ENDC}")
        print("  - System offers to reclassify ASN")
        print("  - Performs WHOIS lookup")
        print("  - Updates database with actual location")
        print("  - Re-checks the IP\n")

if __name__ == '__main__':
    main()
