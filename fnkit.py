#!/usr/bin/env python3
"""
FieldNet Kit (FNkit) — portable network intelligence workbench.

IP/ASN geo integrity, DNS exposure graph, network diagnostics, PCAP, OWASP checks.
"""

import json
import sys
import argparse
import ipaddress
import io
import re
import time
from collections import Counter
from contextlib import redirect_stdout
from pathlib import Path
from datetime import datetime, timedelta
from typing import Dict, List, Optional
import urllib.request
import urllib.error
import subprocess
import platform
import shutil
import os
import signal

from paths import (
    DATABASE_FILE,
    ENRICHMENT_CONFIG_FILE,
    LANGUAGE_FILE,
    REPO_ROOT,
    RESULTS_FILE,
    ensure_data_layout,
    ensure_lib_path,
)
from schema import DocumentKind, load_json_file, save_json_file, validate_schema_version

ensure_data_layout()
ensure_lib_path()

import network_diag
import pcap_diag
import dns_diag
import owasp_toolkit
import pdns_lookup
import ip_egress_check
import ptr_scan
MAX_POOLS_PER_ASN = 3  # legacy alias for ASN sampling display cap
MIN_POOL_PREFIXLEN = 20  # ignore /8–/19 pools (false match risk)
MAX_POOLS_STORE_PER_ASN = 96
MAX_POOLS_SAMPLE_CHECK = 8

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
    DIM = '\033[2m'
    UNDERLINE = '\033[4m'


# Localization dictionary
TRANSLATIONS = {
    "en": {
        "menu_title": "═══════════════════════════════════════════════════════════",
        "menu_select": "🌍 SELECT LANGUAGE / ВЫБЕРИТЕ ЯЗЫК",
        "menu_1": "1. English",
        "menu_2": "2. Русский",
        "menu_prompt": "Select (1 or 2): ",
        "app_title": "FieldNet Kit (FNkit)",
        "app_subtitle": "Portable network intelligence: IP/ASN trust, DNS, diagnostics & exposure checks",
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
        "offer_reclassify": "MISMATCH FOUND!\nWould you like to reclassify this ASN? (y/n): ",
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
        "ip_input_hint": "Enter IPv4/IPv6 only (example: 8.8.8.8). Enter 0 to cancel.",
        "ip_input_cancelled": "IP input cancelled. Returning to main menu.",
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
        "unknown_asn_not_in_db": "ASN is not in the local database — querying WHOIS for this autonomous system…",
        "unknown_asn_whois_title": "WHOIS (aut-num)",
        "unknown_asn_as_name": "AS name: ",
        "unknown_asn_probing": "Sampling up to {n} IP(s) from WHOIS routes for geo check…",
        "unknown_asn_no_prefixes": "No IPv4 route/inetnum found in WHOIS to sample automatically.",
        "unknown_asn_sample_ip_prompt": "Enter any IPv4 from this operator's network (or press Enter to skip): ",
        "unknown_asn_add_offer": "Add this ASN to the local database using the data above? (y/n): ",
        "unknown_asn_added": "✓ ASN entry added to the database",
        "unknown_asn_add_skipped": "ASN was not added to the database.",
        "unknown_asn_invalid": "Invalid ASN. Use e.g. AS12389 or 12389.",
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
        "bgp_lookup_running": "BGP origin lookup (Team Cymru)...",
        "bgp_origin_title": "BGP origin (live routing)",
        "bgp_origin_asn": "Origin ASN: ",
        "bgp_origin_prefix": "BGP prefix: ",
        "bgp_origin_registry": "Registry: ",
        "bgp_origin_as_name": "AS name: ",
        "bgp_origin_match_db": "✓ BGP origin matches local database ASN",
        "bgp_origin_mismatch_db": "✗ BGP origin ASN differs from local database (expected {expected}, live {live})",
        "bgp_origin_mismatch_geo": "⚠ BGP origin ASN differs from geo API ASN ({geo})",
        "bgp_origin_lookup_failed": "BGP origin lookup failed: ",
        "bgp_pools_collecting": "Collecting BGP prefixes for {asn} (WHOIS routes + Team Cymru per IP)...",
        "bgp_pools_found": "BGP prefixes for database: {n} pools (/{min} or longer)",
        "bgp_pools_none": "No specific BGP prefixes found; using /24 from anchor IP.",
        "bgp_pools_coarse_skipped": "Skipped coarse pool (/{plen} < /{min}): {pool}",
        "asn_dedupe_saved": "Merged {n} duplicate ASN row(s) in asn_database.json (one entry per ASN number).",
        "db_maint_title": "ASN database maintenance",
        "db_maint_merged": "  Duplicate ASN rows merged: {n}",
        "db_maint_coarse": "  Coarse pools removed (wider than /{min}): {n}",
        "db_maint_asns": "  ASN rows: {n}",
        "db_maint_pools": "  Acceptable pools (match-ready): {n}",
        "db_maint_empty": "  ASN rows without match-ready pools: {n}",
        "db_maint_empty_hint": "    → refresh via menu IP check / unknown ASN + BGP, or: python3 fnkit.py --maintain-db",
        "db_maint_issues": "  Validation issues: {n}",
        "db_maint_ok": "  Schema/metadata: OK",
        "db_refresh_asn": "  Refreshing {asn} ({i}/{n})...",
        "db_refresh_done": "  BGP/WHOIS pool refresh: {ok} ASN updated, {empty} still empty, {err} errors",
        "pool_match_ambiguous": "⚠ Multiple DB rows match this IP; disambiguated by geo/BGP (ASN {asn}, {country}).",
        "pool_match_ambiguous_unresolved": "⚠ Ambiguous pool match — several ASN records tie; check asn_database.json.",
        "pdns_lookup_running": "Passive DNS / historical context lookup…",
        "egress_check_running": "Egress / NAT context (Tor, proxy, datacenter)…",
        "ptr_reverse": "Reverse DNS (PTR): ",
        "ptr_none": "(no PTR)",
        "ptr_range_prompt_mode": "Range mode: 1=geo check (up to 10 IPs), 2=PTR sweep (rate-limited): ",
        "ptr_range_invalid_mode": "Enter 1 or 2.",
        "ptr_qps_prompt": "PTR queries per second [10]: ",
        "tools_menu_title": "Additional network tools (checked IP)",
        "tools_1": "1. nmap (run with -A -T4)",
        "tools_2": "2. traceroute / tracert to 8.8.8.8 (max 20 hops, bounded wait)",
        "tools_nmap_interrupt_hint": "Stop nmap: Ctrl+C or Ctrl+Z — return to this menu",
        "tools_nmap_interrupt_hint_win": "Stop nmap: Ctrl+C — return to this menu",
        "tools_nmap_interrupted": "nmap stopped — back to tools menu.",
        "tools_3": "3. nslookup  (this IP, system resolver)",
        "tools_4": "4. OWASP Secure Headers (quick, built-in)",
        "tools_5": "5. TLS check (cert, cipher, legacy protocols)",
        "tools_0": "0. Skip / back",
        "tools_prompt": "Select (0-5): ",
        "tools_running": "Running: ",
        "tools_done": "— done —",
        "tools_cmd_missing": "Command not found in PATH: ",
        "tools_invalid": "Invalid choice.",
        "menu_body_ip": "Check single IP address",
        "menu_body_range": "Check IP range",
        "menu_body_asn": "Check ASN operator",
        "menu_body_lang": "Change language",
        "menu_body_help": "Help",
        "menu_body_db": "Update database",
        "menu_body_enrich": "Configure enrichment API keys",
        "menu_body_diag": "Network diagnostics (trace monitor / speed test)",
        "menu_body_iface": "List local network interfaces (NIC parameters)",
        "menu_body_dns": "DNS analysis (graph / subdomains)",
        "menu_body_owasp": "OWASP toolkit (Amass / Nettacker / headers / WSTG)",
        "menu_body_exit": "Exit",
        "menu_prompt_main": "Select option (0-11): ",
        "menu_prompt_hint": "Enter the menu number (0–11) and press Enter.",
        "diag_menu_title": "Network diagnostics",
        "diag_opt_speed": "1. Quick speed test (ping + HTTP download/upload, Cloudflare)",
        "diag_opt_trace": "2. Multi-hop route latency monitor",
        "diag_opt_replay": "3. Replay saved session",
        "diag_opt_pcap_capture": "4. Live capture to .pcap (tcpdump)",
        "diag_opt_pcap_show": "5. Show PCAP like Wireshark (tshark / tcpdump -r)",
        "diag_opt_back": "0. Back",
        "diag_menu_prompt": "Select (0-5): ",
        "diag_host_prompt": "Host or IP to trace (e.g. 8.8.8.8 or example.com): ",
        "diag_replay_prompt": "Path to trace session JSON: ",
        "diag_pcap_prompt": "Path to .pcap / .cap file: ",
        "diag_pcap_capture_iface": "Interface (en0 / eth0 / …): ",
        "diag_pcap_capture_out": "Output .pcap file path: ",
        "diag_pcap_capture_secs": "Duration seconds [10]: ",
        "diag_pcap_capture_filter": "Optional BPF filter (Enter to skip, e.g. tcp port 443): ",
        "diag_replay_intro": "Tip: record via diagnostics item 2 (hop monitor); after q/stop, save JSON — default-route interface is filled in automatically when the OS reports it (otherwise you pick from the list). Sessions folder:\n  {dir}\n",
        "diag_replay_empty": "(No .json in data/sessions/trace/ yet — run hop monitor (item 2) first.)",
        "diag_replay_post_menu": "r — repeat · q — back to diagnostics menu",
        "diag_replay_post_prompt": "Your choice: ",
        "diag_replay_post_invalid": "Enter r or q.",
        "diag_pick_trace_prompt": "Session file number (1–N), full path to .json, or 0 to cancel: ",
        "diag_pcap_intro": "Tip: item 4 saves tcpdump captures under:\n  {dir}\nPick a file from the list, or type another path.\n",
        "diag_pcap_empty_dir": "(No capture files there yet — run item 4 first.)",
        "diag_pcap_pick_prompt": "File number (1–N), full path to .pcap/.cap, or 0 to cancel: ",
        "diag_pcap_default_path": "If you leave output blank, the file will be: {path}",
        "diag_file_not_found": "File not found: {path}",
        "enrich_cfg_title": "Enrichment API key setup",
        "enrich_cfg_opt_1": "1. MaxMind",
        "enrich_cfg_opt_2": "2. IP2Location",
        "enrich_cfg_opt_3": "3. VirusTotal (passive DNS)",
        "enrich_cfg_opt_0": "0. Back",
        "enrich_cfg_prompt": "Select (0-3): ",
        "enrich_cfg_vt_prompt": "Enter VirusTotal API key (or 0 to go back): ",
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
        "app_title": "FieldNet Kit (FNkit)",
        "app_subtitle": "Полевой сетевой набор: IP/ASN, DNS, диагностика и проверка экспозиции",
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
        "offer_reclassify": "НАЙДЕНО НЕСООТВЕТСТВИЕ!\nХотите переклассифицировать этот ASN? (y/n): ",
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
        "ip_input_hint": "Введите только IPv4/IPv6 (например: 8.8.8.8). Введите 0 для отмены.",
        "ip_input_cancelled": "Ввод IP отменен. Возврат в главное меню.",
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
        "unknown_asn_not_in_db": "ASN нет в локальной базе — запрос WHOIS по autonomous system…",
        "unknown_asn_whois_title": "WHOIS (aut-num)",
        "unknown_asn_as_name": "Имя AS: ",
        "unknown_asn_probing": "Проверка до {n} IP из маршрутов WHOIS (геолокация)…",
        "unknown_asn_no_prefixes": "В ответе WHOIS не найдены IPv4 route/inetnum для автоматической выборки.",
        "unknown_asn_sample_ip_prompt": "Введите любой IPv4 из сети этого оператора (или Enter — пропустить): ",
        "unknown_asn_add_offer": "Добавить этот ASN в локальную БД по полученным данным? (y/n): ",
        "unknown_asn_added": "✓ Запись ASN добавлена в базу",
        "unknown_asn_add_skipped": "ASN не добавлен в базу.",
        "unknown_asn_invalid": "Неверный формат ASN. Укажите, например: AS12389 или 12389.",
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
        "bgp_lookup_running": "Проверка BGP origin (Team Cymru)...",
        "bgp_origin_title": "BGP origin (текущая маршрутизация)",
        "bgp_origin_asn": "Origin ASN: ",
        "bgp_origin_prefix": "BGP-префикс: ",
        "bgp_origin_registry": "Реестр: ",
        "bgp_origin_as_name": "Имя AS: ",
        "bgp_origin_match_db": "✓ BGP origin совпадает с ASN в локальной базе",
        "bgp_origin_mismatch_db": "✗ BGP origin ASN не совпадает с базой (ожидался {expected}, в BGP {live})",
        "bgp_origin_mismatch_geo": "⚠ BGP origin ASN отличается от ASN geo API ({geo})",
        "bgp_origin_lookup_failed": "Не удалось получить BGP origin: ",
        "bgp_pools_collecting": "Сбор BGP-префиксов для {asn} (WHOIS route + Team Cymru по IP)...",
        "bgp_pools_found": "Префиксы для базы: {n} пулов (/{min} и точнее)",
        "bgp_pools_none": "Конкретные BGP-префиксы не найдены; используется /24 от якорного IP.",
        "bgp_pools_coarse_skipped": "Пропущен слишком широкий пул (/{plen} < /{min}): {pool}",
        "asn_dedupe_saved": "Объединены дубликаты ASN: {n} строк (одна запись на номер AS).",
        "db_maint_title": "Обслуживание базы ASN",
        "db_maint_merged": "  Объединено дубликатов ASN: {n}",
        "db_maint_coarse": "  Удалено грубых пулов (шире /{min}): {n}",
        "db_maint_asns": "  Строк ASN: {n}",
        "db_maint_pools": "  Рабочих пулов (для match): {n}",
        "db_maint_empty": "  ASN без рабочих пулов: {n}",
        "db_maint_empty_hint": "    → обновите через проверку IP / unknown ASN + BGP или: python3 fnkit.py --maintain-db",
        "db_maint_issues": "  Проблемы валидации: {n}",
        "db_maint_ok": "  Схема/метаданные: OK",
        "db_refresh_asn": "  Обновление {asn} ({i}/{n})...",
        "db_refresh_done": "  Префиксы BGP/WHOIS: обновлено {ok} ASN, пусто {empty}, ошибок {err}",
        "pool_match_ambiguous": "⚠ Несколько записей в базе; выбрано по geo/BGP (ASN {asn}, {country}).",
        "pool_match_ambiguous_unresolved": "⚠ Неоднозначное совпадение пула — проверьте asn_database.json.",
        "pdns_lookup_running": "Запрос passive DNS / исторического контекста…",
        "egress_check_running": "Контекст egress / NAT (Tor, proxy, datacenter)…",
        "ptr_reverse": "Reverse DNS (PTR): ",
        "ptr_none": "(нет PTR)",
        "ptr_range_prompt_mode": "Режим диапазона: 1=geo (до 10 IP), 2=PTR-обход (rate-limit): ",
        "ptr_range_invalid_mode": "Введите 1 или 2.",
        "ptr_qps_prompt": "Запросов PTR в секунду [10]: ",
        "tools_menu_title": "Доп. сетевые инструменты (проверяемый IP)",
        "tools_1": "1. nmap (запуск с ключами -A -T4)",
        "tools_2": "2. traceroute / tracert до 8.8.8.8 (макс. 20 хопов, ограниченное ожидание)",
        "tools_nmap_interrupt_hint": "Остановить nmap: Ctrl+C или Ctrl+Z — возврат в это меню",
        "tools_nmap_interrupt_hint_win": "Остановить nmap: Ctrl+C — возврат в это меню",
        "tools_nmap_interrupted": "nmap остановлен — возврат в меню инструментов.",
        "tools_3": "3. nslookup  (этот IP, системный резолвер)",
        "tools_4": "4. OWASP Secure Headers (быстро, встроенно)",
        "tools_5": "5. Проверка TLS (сертификат, cipher, устаревшие протоколы)",
        "tools_0": "0. Пропуск / назад",
        "tools_prompt": "Выберите (0-5): ",
        "tools_running": "Запуск: ",
        "tools_done": "— готово —",
        "tools_cmd_missing": "Команда не найдена в PATH: ",
        "tools_invalid": "Неверный выбор.",
        "menu_body_ip": "Проверить IP адрес",
        "menu_body_range": "Проверить диапазон IP",
        "menu_body_asn": "Проверить ASN оператора",
        "menu_body_lang": "Выбрать язык",
        "menu_body_help": "Справка",
        "menu_body_db": "Обновить базу",
        "menu_body_enrich": "Настроить API ключи обогащения",
        "menu_body_diag": "Диагностика сети (трассировка / speed test)",
        "menu_body_iface": "Список сетевых интерфейсов (параметры NIC)",
        "menu_body_dns": "DNS-анализ (граф / поддомены)",
        "menu_body_owasp": "OWASP (Amass / Nettacker / headers / WSTG)",
        "menu_body_exit": "Выход",
        "menu_prompt_main": "Выберите опцию (0-11): ",
        "menu_prompt_hint": "Введите номер пункта меню (0–11) и нажмите Enter.",
        "diag_menu_title": "Диагностика сети",
        "diag_opt_speed": "1. Быстрый тест скорости (ping + HTTP загрузка/отдача, Cloudflare)",
        "diag_opt_trace": "2. Монитор задержки по хопам маршрута",
        "diag_opt_replay": "3. Воспроизвести сохранённую сессию",
        "diag_opt_pcap_capture": "4. Захват в .pcap (tcpdump)",
        "diag_opt_pcap_show": "5. Показать PCAP как Wireshark (tshark / tcpdump -r)",
        "diag_opt_back": "0. Назад",
        "diag_menu_prompt": "Выберите (0-5): ",
        "diag_host_prompt": "Хост или IP для трассировки (напр. 8.8.8.8 или example.com): ",
        "diag_replay_prompt": "Путь к JSON сессии трассировки: ",
        "diag_pcap_prompt": "Путь к .pcap / .cap: ",
        "diag_pcap_capture_iface": "Интерфейс (en0 / eth0 / …): ",
        "diag_pcap_capture_out": "Куда сохранить .pcap: ",
        "diag_pcap_capture_secs": "Длительность (сек) [10]: ",
        "diag_pcap_capture_filter": "Опционально BPF (Enter пропуск, пример: tcp port 443): ",
        "diag_replay_intro": "Сначала запишите сессию: в диагностике п.2 (монитор хопов), после q/стоп — сохранение JSON; интерфейс маршрута по умолчанию подставляется автоматически, если ОС его отдаёт, иначе — выбор из списка. Папка сессий:\n  {dir}\n",
        "diag_replay_empty": "(В data/sessions/trace/ пока нет .json — сначала п.2, монитор хопов.)",
        "diag_replay_post_menu": "r — повторить · q — выйти на предыдущее меню",
        "diag_replay_post_prompt": "Ваш выбор: ",
        "diag_replay_post_invalid": "Введите r или q.",
        "diag_pick_trace_prompt": "Номер файла (1–N), полный путь к .json или 0 отмена: ",
        "diag_pcap_intro": "Сначала имеет смысл п.4 — tcpdump пишет захваты в:\n  {dir}\nВыберите файл из списка или укажите другой путь.\n",
        "diag_pcap_empty_dir": "(В папке пока нет .pcap/.cap — сначала п.4.)",
        "diag_pcap_pick_prompt": "Номер файла (1–N), полный путь к .pcap/.cap или 0 отмена: ",
        "diag_pcap_default_path": "Если путь вывода оставить пустым, будет файл: {path}",
        "diag_file_not_found": "Файл не найден: {path}",
        "enrich_cfg_title": "Настройка API ключей обогащения",
        "enrich_cfg_opt_1": "1. MaxMind",
        "enrich_cfg_opt_2": "2. IP2Location",
        "enrich_cfg_opt_3": "3. VirusTotal (passive DNS)",
        "enrich_cfg_opt_0": "0. Назад",
        "enrich_cfg_prompt": "Выберите (0-3): ",
        "enrich_cfg_vt_prompt": "Введите API ключ VirusTotal (или 0 назад): ",
        "enrich_cfg_mm_prompt": "Введите ключ MaxMind в формате ACCOUNT_ID:LICENSE_KEY (или 0 назад): ",
        "enrich_cfg_ip2_prompt": "Введите API ключ IP2Location (или 0 назад): ",
        "enrich_cfg_saved": "Сохранено.",
        "enrich_cfg_save_failed": "Не удалось сохранить конфиг.",
        "enrich_cfg_invalid": "Неверный формат.",
        "enrich_cfg_next": "Настроить ключ для другого сервиса? (y/n): ",
        "enrich_cfg_done": "Готово. Возврат в главное меню.",
    }
}

MAIN_MENU_ITEM_KEYS = (
    "menu_body_ip",
    "menu_body_range",
    "menu_body_asn",
    "menu_body_diag",
    "menu_body_iface",
    "menu_body_db",
    "menu_body_enrich",
    "menu_body_lang",
    "menu_body_help",
    "menu_body_dns",
    "menu_body_owasp",
)


def print_main_menu_lines() -> None:
    """Print main menu: lines 1–11 match the digit you type; 0 exits."""
    for i, body_key in enumerate(MAIN_MENU_ITEM_KEYS, start=1):
        print(f"{i}. {t(body_key)}")
    print(f"0. {t('menu_body_exit')}")


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
        print(f"{Colors.OKCYAN}{t('enrich_cfg_opt_3')}{Colors.ENDC}")
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
        elif choice == "3":
            key = input(f"{Colors.OKCYAN}{t('enrich_cfg_vt_prompt')}{Colors.ENDC}").strip()
            if key == "0":
                continue
            if not key:
                print(f"{Colors.FAIL}{t('enrich_cfg_invalid')}{Colors.ENDC}")
                continue
            config["virustotal_api_key"] = key
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
    """Load ASN database from JSON file (schema migration + compatibility layer)."""
    try:
        database = load_json_file(DATABASE_FILE, DocumentKind.ASN_DATABASE)
        ensure_database_metadata(database)
        merged = dedupe_asn_database(database)
        if merged:
            save_database(database)
            print(f"{Colors.WARNING}{t('asn_dedupe_saved').format(n=merged)}{Colors.ENDC}")
        return database
    except FileNotFoundError:
        print(f"{Colors.FAIL}Error: Database file not found{Colors.ENDC}")
        sys.exit(1)
    except json.JSONDecodeError:
        print(f"{Colors.FAIL}Error: Invalid JSON in database{Colors.ENDC}")
        sys.exit(1)

def save_database(database: Dict) -> None:
    """Persist ASN database to JSON file (current schema version)."""
    save_json_file(DATABASE_FILE, DocumentKind.ASN_DATABASE, database)

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


def prune_coarse_pools_from_database(database: Dict) -> int:
    """Drop pools broader than MIN_POOL_PREFIXLEN; normalize and dedupe the rest."""
    removed = 0
    for entry in database.get("asn_data", []):
        kept: List[str] = []
        seen: set[str] = set()
        for raw in entry.get("ip_pools", []):
            if is_acceptable_pool(raw):
                cidr = normalize_pool_cidr(raw)
                if cidr and cidr not in seen:
                    seen.add(cidr)
                    kept.append(cidr)
            else:
                removed += 1
        entry["ip_pools"] = kept
    return removed


def validate_asn_database(database: Dict) -> Dict:
    """Validate schema, unique ASN keys, and metadata counters."""
    issues: List[str] = []
    asn_data = database.get("asn_data", [])
    if not isinstance(asn_data, list):
        issues.append("asn_data is not a list")
        asn_data = []

    keys: List[Optional[str]] = []
    for idx, entry in enumerate(asn_data):
        if not isinstance(entry, dict):
            issues.append(f"row {idx}: not an object")
            continue
        asn_key = normalize_asn_key(entry.get("asn"))
        if not asn_key:
            issues.append(f"row {idx}: invalid or missing asn")
        keys.append(asn_key)
        for field in ("expected_country", "expected_country_name", "owner", "ip_pools"):
            if field not in entry:
                issues.append(f"{asn_key or idx}: missing field {field}")
        pools = entry.get("ip_pools")
        if pools is not None and not isinstance(pools, list):
            issues.append(f"{asn_key or idx}: ip_pools is not a list")

    dupe_keys = [k for k, c in Counter(k for k in keys if k).items() if c > 1]
    if dupe_keys:
        issues.append(f"duplicate ASN keys: {sorted(dupe_keys)}")

    issues.extend(validate_schema_version(database, DocumentKind.ASN_DATABASE))

    meta = database.setdefault("metadata", {})
    actual_asns = len(asn_data)
    actual_pools = sum(len(e.get("ip_pools") or []) for e in asn_data if isinstance(e, dict))
    if meta.get("total_asns") != actual_asns:
        issues.append(f"metadata.total_asns={meta.get('total_asns')} != actual {actual_asns}")
    if meta.get("total_ip_pools") != actual_pools:
        issues.append(f"metadata.total_ip_pools={meta.get('total_ip_pools')} != actual {actual_pools}")

    acceptable_pool_count = 0
    empty_pool_asns: List[str] = []
    merge_conflicts: List[str] = []
    for entry in asn_data:
        if not isinstance(entry, dict):
            continue
        asn_key = normalize_asn_key(entry.get("asn")) or "?"
        acc = [p for p in entry.get("ip_pools", []) if is_acceptable_pool(p)]
        acceptable_pool_count += len(acc)
        if not acc:
            empty_pool_asns.append(asn_key)
        if "Merged" in (entry.get("notes") or "") and "conflicting countries" in (entry.get("notes") or ""):
            merge_conflicts.append(asn_key)

    return {
        "ok": len(issues) == 0,
        "issues": issues,
        "stats": {
            "asn_rows": actual_asns,
            "pool_rows": actual_pools,
            "acceptable_pools": acceptable_pool_count,
            "empty_pool_asns": empty_pool_asns,
            "merge_conflicts": merge_conflicts,
        },
    }


def refresh_asn_pools_database(
    database: Dict,
    *,
    only_empty: bool = False,
    timeout_seconds: int = 15,
    sleep_between: float = 0.25,
    verbose: bool = True,
) -> Dict:
    """Re-collect /20+ prefixes per ASN from WHOIS routes and Team Cymru (new pool rules)."""
    refreshed = 0
    still_empty: List[str] = []
    errors: List[Dict[str, str]] = []
    today = datetime.now().strftime("%Y-%m-%d")
    rows = [e for e in database.get("asn_data", []) if isinstance(e, dict)]
    total = len(rows)

    for i, entry in enumerate(rows, 1):
        asn_key = normalize_asn_key(entry.get("asn"))
        if not asn_key:
            continue
        acc = [p for p in entry.get("ip_pools", []) if is_acceptable_pool(p)]
        if only_empty and acc:
            continue

        if verbose:
            print(
                f"{Colors.DIM}{t('db_refresh_asn').format(asn=asn_key, i=i, n=total)}{Colors.ENDC}",
                flush=True,
            )

        w = get_whois_asn_data(asn_key, timeout_seconds=timeout_seconds)
        if w.get("error"):
            errors.append({"asn": asn_key, "error": str(w["error"])})
            if not acc:
                still_empty.append(asn_key)
            continue

        whois_text = w.get("whois_text") or ""
        probe_ips = extract_ipv4_probe_ips_from_asn_whois(whois_text, limit=8)
        if len(probe_ips) < 4:
            ripe_extra = _ripe_inverse_routes_for_asn(asn_key, timeout_seconds=timeout_seconds)
            if ripe_extra.strip():
                whois_text = whois_text + "\n\n" + ripe_extra
                probe_ips = extract_ipv4_probe_ips_from_asn_whois(whois_text, limit=8)

        pools = collect_bgp_pools_for_asn(
            asn_key,
            whois_text=whois_text,
            probe_ips=probe_ips,
            timeout_seconds=timeout_seconds,
        )

        if pools:
            entry["ip_pools"] = pools
            entry["last_checked"] = today
            note = f"pools refreshed {today} (BGP/WHOIS, /{MIN_POOL_PREFIXLEN}+)"
            prev = (entry.get("notes") or "").strip()
            entry["notes"] = f"{prev} | {note}" if prev else note
            refreshed += 1
        elif not acc:
            still_empty.append(asn_key)

        if sleep_between > 0:
            time.sleep(sleep_between)

    update_database_metadata(database)
    return {
        "refreshed": refreshed,
        "still_empty": still_empty,
        "errors": errors,
    }


def maintain_asn_database(database: Dict, *, refresh_pools: bool = True) -> Dict:
    """Dedupe ASN rows, prune coarse pools, optional BGP/WHOIS pool refresh, validate."""
    merge_groups = dedupe_asn_database(database)
    coarse_removed = prune_coarse_pools_from_database(database)
    pool_refresh: Optional[Dict] = None
    if refresh_pools:
        pool_refresh = refresh_asn_pools_database(database, only_empty=False, verbose=True)
    update_database_metadata(database)
    report = validate_asn_database(database)
    report["maintenance"] = {
        "merge_groups": merge_groups,
        "coarse_pools_removed": coarse_removed,
        "maintained_at": datetime.now().isoformat(),
    }
    if pool_refresh is not None:
        report["pool_refresh"] = pool_refresh
    database.setdefault("metadata", {})["last_maintenance"] = report["maintenance"]
    return report


def print_database_maintenance_report(report: Dict) -> None:
    """TTY summary after maintain_asn_database / menu item 6."""
    maint = report.get("maintenance") or {}
    stats = report.get("stats") or {}
    print(f"\n{Colors.BOLD}{t('db_maint_title')}{Colors.ENDC}")
    print(t("db_maint_merged").format(n=maint.get("merge_groups", 0)))
    print(t("db_maint_coarse").format(n=maint.get("coarse_pools_removed", 0), min=MIN_POOL_PREFIXLEN))
    print(t("db_maint_asns").format(n=stats.get("asn_rows", 0)))
    print(t("db_maint_pools").format(n=stats.get("acceptable_pools", 0)))
    empty_n = len(stats.get("empty_pool_asns") or [])
    if empty_n:
        print(f"{Colors.WARNING}{t('db_maint_empty').format(n=empty_n)}{Colors.ENDC}")
        print(f"{Colors.DIM}{t('db_maint_empty_hint')}{Colors.ENDC}")
    issues = report.get("issues") or []
    if issues:
        print(f"{Colors.FAIL}{t('db_maint_issues').format(n=len(issues))}{Colors.ENDC}")
        for line in issues[:8]:
            print(f"  {Colors.FAIL}{line}{Colors.ENDC}")
        if len(issues) > 8:
            print(f"  {Colors.DIM}… +{len(issues) - 8}{Colors.ENDC}")
    else:
        print(f"{Colors.OKGREEN}{t('db_maint_ok')}{Colors.ENDC}")
    pool_ref = report.get("pool_refresh")
    if pool_ref:
        print(
            t("db_refresh_done").format(
                ok=pool_ref.get("refreshed", 0),
                empty=len(pool_ref.get("still_empty") or []),
                err=len(pool_ref.get("errors") or []),
            )
        )


def perform_database_update(database: Dict) -> tuple[bool, Optional[str]]:
    """Run full ASN database maintenance (dedupe, prune coarse pools, metadata) and save."""
    try:
        report = maintain_asn_database(database)
        today = datetime.now().strftime("%Y-%m-%d")
        metadata = database.setdefault("metadata", {})
        metadata["last_update_check"] = today
        metadata["next_update_prompt_after"] = today
        save_database(database)
        print_database_maintenance_report(report)
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
        url = (
            f"http://ip-api.com/json/{ip}"
            "?fields=status,country,countryCode,region,city,isp,org,as,reverse,proxy,hosting,mobile"
        )
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
                    'proxy': bool(data.get('proxy')),
                    'hosting': bool(data.get('hosting')),
                    'mobile': bool(data.get('mobile')),
                    'reverse': (data.get('reverse') or '').strip() or None,
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
        print(f"  {t('abuse_contact')}{abuse}")
    else:
        print(f"  {t('abuse_contact')}{t('abuse_not_found')}")

def print_abuse_with_rir_fallback(ip: str, whois_data: Optional[Dict], whois_timeout: int = 14) -> None:
    """Print abuse contact from current WHOIS data, fallback to explicit RIR WHOIS query."""
    w = whois_data or {}
    all_whois_texts: List[str] = []
    if w.get("whois_text"):
        all_whois_texts.append(w.get("whois_text", ""))
    abuse = parse_abuse_from_whois(w.get("whois_text", ""))
    if abuse:
        print(f"  {t('abuse_contact')}{abuse}")
        return

    handle = extract_abuse_handle(w.get("whois_text", ""))
    if handle:
        resolved = resolve_abuse_handle_contact(handle, w.get("whois_server"), timeout_seconds=max(8, whois_timeout))
        if resolved:
            print(f"  {t('abuse_contact')}{' | '.join(resolved)}")
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
                print(f"  {t('abuse_contact')}{abuse_rir}")
                return
            handle_rir = extract_abuse_handle(wr.get("whois_text", ""))
            if handle_rir:
                resolved_rir = resolve_abuse_handle_contact(handle_rir, fallback_server, timeout_seconds=max(8, whois_timeout))
                if resolved_rir:
                    print(f"  {t('abuse_contact')}{' | '.join(resolved_rir)}")
                    return

    # Final fallback: infer likely abuse/security contact emails from WHOIS content.
    candidates: List[str] = []
    for text in all_whois_texts:
        for email in extract_candidate_abuse_emails(text):
            if email not in candidates:
                candidates.append(email)
    if candidates:
        print(f"  {t('abuse_contact_inferred')}{' | '.join(candidates[:3])}")
        return

    print(f"  {t('abuse_contact')}{t('abuse_not_found')}")

def fetch_and_print_abuse_contact(ip: str, whois_timeout: int = 14) -> None:
    """WHOIS lookup and print abuse line (with RIR fallback if primary WHOIS has no abuse)."""
    w = get_whois_data(ip, timeout_seconds=whois_timeout)
    if not w or w.get("error"):
        suffix = f" ({w['error']})" if w and w.get("error") else ""
        print(f"  {t('abuse_contact')}{t('abuse_not_found')}{suffix}")
        return
    print_abuse_with_rir_fallback(ip, w, whois_timeout=whois_timeout)

def resolve_abuse_handle_contact(handle: str, whois_server: Optional[str], timeout_seconds: int = 12) -> List[str]:
    """Resolve abuse-c handle into likely contact emails via raw WHOIS query."""
    cmd = ["whois", handle]
    if whois_server:
        cmd = ["whois", "-h", whois_server, handle]
    try:
        r = subprocess.run(
            cmd,
            text=True,
            capture_output=True,
            timeout=timeout_seconds,
            check=False,
            encoding="utf-8",
            errors="replace",
        )
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
        print(f"{Colors.OKCYAN}{t('tools_4')}{Colors.ENDC}")
        print(f"{Colors.OKCYAN}{t('tools_5')}{Colors.ENDC}")
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
        elif choice == "4":
            lang = CURRENT_LANGUAGE if CURRENT_LANGUAGE in ("en", "ru") else "en"
            owasp_toolkit.set_context(ip=target_ip)
            url = f"https://{target_ip}/"
            rep = owasp_toolkit.check_secure_headers(url, lang=lang)
            owasp_toolkit.print_secure_headers_report(rep, lang=lang)
        elif choice == "5":
            lang = CURRENT_LANGUAGE if CURRENT_LANGUAGE in ("en", "ru") else "en"
            owasp_toolkit.set_context(ip=target_ip)
            rep = owasp_toolkit.check_tls(target_ip, lang=lang)
            owasp_toolkit.print_tls_report(rep, lang=lang)
        else:
            print(f"{Colors.WARNING}{t('tools_invalid')}{Colors.ENDC}")

def _run_whois_raw_query(
    target: str,
    *,
    whois_server: Optional[str] = None,
    timeout_seconds: int = 20,
) -> Dict:
    """Run system ``whois`` for an IP or ``AS`` object. Returns ok+stdout or error dict."""
    try:
        cmd: List[str] = ["whois", target]
        if whois_server:
            cmd = ["whois", "-h", whois_server, "--", target]
        process = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            errors="replace",
        )

        show_timer = sys.stdout.isatty()
        start_time = time.monotonic()
        last_remaining: Optional[int] = None

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
                if show_timer:
                    print()
                process.communicate()
                return {"error": f"timeout after {timeout_seconds}s"}

            time.sleep(0.2)

        stdout, stderr = process.communicate()
        if show_timer:
            print("\r" + " " * 60 + "\r", end="", flush=True)

        return {
            "ok": True,
            "stdout": stdout or "",
            "stderr": stderr or "",
            "returncode": process.returncode,
        }
    except FileNotFoundError:
        return {"error": "whois command not found"}
    except OSError as exc:
        return {"error": str(exc)}
    except Exception as exc:
        return {"error": str(exc)}


def get_whois_data(ip: str, timeout_seconds: int = 20, whois_server: Optional[str] = None) -> Optional[Dict]:
    """Get WHOIS data for an IP address"""
    try:
        raw = _run_whois_raw_query(ip, whois_server=whois_server, timeout_seconds=timeout_seconds)
        if raw.get("error"):
            return raw
        whois_text = raw["stdout"]

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


def normalize_asn_key(raw: str) -> Optional[str]:
    """Return canonical ``AS<number>`` or None if the string is not a plain ASN."""
    s = (raw or "").strip().replace(" ", "")
    if not s:
        return None
    upper = s.upper()
    num = upper[2:] if upper.startswith("AS") else upper
    if not num.isdigit():
        return None
    return f"AS{int(num)}"


CYMRU_WHOIS_HOST = "whois.cymru.com"


def _parse_cymru_bgp_row(line: str) -> Optional[Dict]:
    stripped = line.strip()
    if not stripped or "|" not in stripped:
        return None
    if stripped.startswith("AS ") or "BGP Prefix" in stripped:
        return None
    parts = [part.strip() for part in stripped.split("|")]
    if len(parts) < 7 or not parts[0].isdigit():
        return None
    asn_number = int(parts[0])
    return {
        "asn": f"AS{asn_number}",
        "asn_number": asn_number,
        "ip": parts[1],
        "bgp_prefix": parts[2],
        "country_code": parts[3],
        "registry": parts[4],
        "allocated": parts[5],
        "as_name": parts[6],
        "source": "team-cymru",
    }


def parse_cymru_bgp_verbose(whois_text: str) -> Optional[Dict]:
    """Parse Team Cymru ``whois -h whois.cymru.com " -v <IP>"`` table output."""
    for line in (whois_text or "").splitlines():
        row = _parse_cymru_bgp_row(line)
        if row:
            return row
    return None


def pool_prefixlen(cidr: str) -> Optional[int]:
    try:
        net = ipaddress.ip_network(cidr, strict=False)
        return net.prefixlen
    except ValueError:
        return None


def normalize_pool_cidr(cidr: str) -> Optional[str]:
    try:
        net = ipaddress.ip_network((cidr or "").strip(), strict=False)
        if isinstance(net, ipaddress.IPv4Network):
            return str(net)
    except ValueError:
        return None
    return None


def is_acceptable_pool(cidr: str) -> bool:
    plen = pool_prefixlen(cidr)
    return plen is not None and plen >= MIN_POOL_PREFIXLEN


def extract_ipv4_route_cidrs_from_whois(whois_text: str) -> List[str]:
    """Collect IPv4 route: objects; most specific first; drop /8–/19."""
    seen: set[str] = set()
    out: List[str] = []
    for m in re.finditer(
        r"(?im)^\s*route:\s*(\d{1,3}(?:\.\d{1,3}){3}/\d{1,2})\s*$",
        whois_text or "",
    ):
        cidr = normalize_pool_cidr(m.group(1).strip())
        if not cidr or not is_acceptable_pool(cidr) or cidr in seen:
            continue
        seen.add(cidr)
        out.append(cidr)
    out.sort(key=lambda c: pool_prefixlen(c) or 0, reverse=True)
    return out


def collect_bgp_pools_for_asn(
    asn_key: str,
    *,
    whois_text: str = "",
    probe_ips: Optional[List[str]] = None,
    timeout_seconds: int = 15,
) -> List[str]:
    """
    Build IP pool list from WHOIS ``route:`` objects and live Cymru BGP prefix per probe IP.
    Rejects aggregates broader than MIN_POOL_PREFIXLEN (/8-style false matches).
    """
    asn_norm = normalize_asn_key(asn_key)
    if not asn_norm:
        return []

    pools: set[str] = set()
    for cidr in extract_ipv4_route_cidrs_from_whois(whois_text):
        pools.add(cidr)

    if len(pools) < 4:
        ripe_routes = _ripe_inverse_routes_for_asn(asn_norm, timeout_seconds=timeout_seconds)
        for cidr in extract_ipv4_route_cidrs_from_whois(ripe_routes):
            pools.add(cidr)

    for ip in (probe_ips or [])[:16]:
        bgp = bgp_lookup_ip(ip, timeout_seconds=timeout_seconds)
        if not bgp.get("success"):
            continue
        live_asn = normalize_asn_key(bgp.get("asn"))
        if live_asn and live_asn != asn_norm:
            continue
        cidr = normalize_pool_cidr(bgp.get("bgp_prefix") or "")
        if cidr and is_acceptable_pool(cidr):
            pools.add(cidr)

    ordered = sorted(pools, key=lambda c: pool_prefixlen(c) or 0, reverse=True)
    return ordered[:MAX_POOLS_STORE_PER_ASN]


def bgp_lookup_ip(ip: str, timeout_seconds: int = 15) -> Dict:
    """Live BGP origin for *ip* via Team Cymru (one ``whois`` subprocess)."""
    try:
        ipaddress.ip_address(ip)
    except ValueError:
        return {"success": False, "error": f"invalid IP: {ip}"}

    raw = _run_whois_raw_query(
        f" -v {ip}",
        whois_server=CYMRU_WHOIS_HOST,
        timeout_seconds=timeout_seconds,
    )
    if raw.get("error"):
        return {"success": False, "error": raw["error"]}

    parsed = parse_cymru_bgp_verbose(raw.get("stdout") or "")
    if not parsed:
        return {"success": False, "error": "no BGP origin in Team Cymru response"}

    return {"success": True, **parsed}


def print_bgp_origin_verification(
    ip: str,
    *,
    expected_asn: Optional[str] = None,
    geo_asn: Optional[str] = None,
    timeout_seconds: int = 15,
) -> Dict:
    """Query live BGP origin and compare with local DB / geo ASN when provided."""
    print(f"{Colors.OKCYAN}{t('bgp_lookup_running')}{Colors.ENDC}")
    bgp = bgp_lookup_ip(ip, timeout_seconds=timeout_seconds)
    if not bgp.get("success"):
        print(f"{Colors.WARNING}{t('bgp_origin_lookup_failed')}{bgp.get('error', 'unknown')}{Colors.ENDC}")
        return bgp

    print(f"\n{Colors.BOLD}{t('bgp_origin_title')}{Colors.ENDC}")
    print(f"  {t('bgp_origin_asn')}{Colors.OKGREEN}{bgp['asn']}{Colors.ENDC}")
    print(f"  {t('bgp_origin_prefix')}{bgp.get('bgp_prefix', 'N/A')}")
    print(f"  {t('bgp_origin_registry')}{bgp.get('registry', 'N/A')}")
    if bgp.get("as_name"):
        print(f"  {t('bgp_origin_as_name')}{bgp['as_name']}")

    expected_key = normalize_asn_key(expected_asn) if expected_asn else None
    geo_key = normalize_asn_key(geo_asn) if geo_asn else None
    live_key = bgp["asn"]

    bgp["matches_db"] = expected_key is not None and expected_key == live_key
    bgp["matches_geo"] = geo_key is None or geo_key == live_key

    if expected_key:
        if bgp["matches_db"]:
            print(f"  {Colors.OKGREEN}{t('bgp_origin_match_db')}{Colors.ENDC}")
        else:
            print(
                f"  {Colors.FAIL}{t('bgp_origin_mismatch_db').format(expected=expected_key, live=live_key)}{Colors.ENDC}"
            )
    if geo_key and geo_key != live_key:
        print(
            f"  {Colors.WARNING}{t('bgp_origin_mismatch_geo').format(geo=geo_key)}{Colors.ENDC}"
        )

    return bgp


def _ipv4_first_probe_host(net: ipaddress.IPv4Network) -> str:
    if net.num_addresses <= 1:
        return str(net.network_address)
    return str(net.network_address + 1)


def extract_ipv4_probe_ips_from_asn_whois(whois_text: str, limit: int = 8) -> List[str]:
    """Pick a few IPv4 addresses from route / inetnum lines in an ASN WHOIS dump."""
    out: List[str] = []
    seen: set[str] = set()
    text = whois_text or ""

    for m in re.finditer(
        r"(?im)^\s*route:\s*(\d{1,3}(?:\.\d{1,3}){3}/\d{1,2})\s*$",
        text,
    ):
        try:
            net = ipaddress.ip_network(m.group(1).strip(), strict=False)
            if isinstance(net, ipaddress.IPv4Network):
                h = _ipv4_first_probe_host(net)
                if h not in seen:
                    seen.add(h)
                    out.append(h)
        except ValueError:
            continue
        if len(out) >= limit:
            return out

    for m in re.finditer(
        r"(?im)^\s*(?:inetnum|netrange):\s*(\d{1,3}(?:\.\d{1,3}){3})\s*-\s*(\d{1,3}(?:\.\d{1,3}){3})\s*$",
        text,
    ):
        try:
            a = ipaddress.ip_address(m.group(1).strip())
            if isinstance(a, ipaddress.IPv4Address):
                h = str(a)
                if h not in seen:
                    seen.add(h)
                    out.append(h)
        except ValueError:
            continue
        if len(out) >= limit:
            break

    return out[:limit]


def first_ipv4_route_cidr_from_asn_whois(whois_text: str) -> Optional[str]:
    routes = extract_ipv4_route_cidrs_from_whois(whois_text)
    return routes[0] if routes else None


def _ripe_inverse_routes_for_asn(asn_key: str, timeout_seconds: int = 15) -> str:
    """RIPE Database inverse: IPv4 ``route`` objects announcing this ``AS``."""
    raw = _run_whois_raw_query(
        f"-i origin {asn_key}",
        whois_server="whois.ripe.net",
        timeout_seconds=timeout_seconds,
    )
    if raw.get("ok"):
        return raw.get("stdout") or ""
    return ""


def _default_ipv4_pool_from_ip(ip: str) -> str:
    addr = ipaddress.ip_address(ip)
    if isinstance(addr, ipaddress.IPv4Address):
        return str(ipaddress.IPv4Network(f"{addr}/24", strict=False))
    return f"{ip}/128"


def ipv4_pool_from_whois(whois_text: str, ip: str) -> str:
    """Derive the most specific IPv4 pool from WHOIS text, else /24 for the address."""
    try:
        addr = ipaddress.ip_address(ip)
        if not isinstance(addr, ipaddress.IPv4Address):
            return f"{ip}/128"
    except ValueError:
        return f"{ip}/32"

    candidates: List[ipaddress.IPv4Network] = []
    text = whois_text or ""

    for m in re.finditer(
        r"(?im)^\s*(?:route|cidr):\s*(\d{1,3}(?:\.\d{1,3}){3}/\d{1,2})\s*$",
        text,
    ):
        try:
            net = ipaddress.ip_network(m.group(1).strip(), strict=False)
            if isinstance(net, ipaddress.IPv4Network) and addr in net:
                candidates.append(net)
        except ValueError:
            continue

    for m in re.finditer(
        r"(?im)^\s*(?:inetnum|netrange):\s*(\d{1,3}(?:\.\d{1,3}){3})\s*-\s*(\d{1,3}(?:\.\d{1,3}){3})\s*$",
        text,
    ):
        try:
            start = ipaddress.ip_address(m.group(1).strip())
            end = ipaddress.ip_address(m.group(2).strip())
            if not isinstance(start, ipaddress.IPv4Address) or not (start <= addr <= end):
                continue
            for net in ipaddress.summarize_address_range(start, end):
                if isinstance(net, ipaddress.IPv4Network) and addr in net:
                    candidates.append(net)
                    break
        except ValueError:
            continue

    acceptable = [n for n in candidates if n.prefixlen >= MIN_POOL_PREFIXLEN]
    if acceptable:
        return str(max(acceptable, key=lambda n: n.prefixlen))

    return _default_ipv4_pool_from_ip(ip)


def get_whois_asn_data(
    asn_raw: str,
    timeout_seconds: int = 25,
    whois_server: Optional[str] = None,
) -> Dict:
    """WHOIS lookup for an autonomous system (``AS`` + digits only)."""
    asn_key = normalize_asn_key(asn_raw)
    if not asn_key:
        return {"error": "invalid ASN format"}

    raw = _run_whois_raw_query(asn_key, whois_server=whois_server, timeout_seconds=timeout_seconds)
    if raw.get("error"):
        return raw

    whois_text = raw["stdout"]
    if not whois_text.strip():
        return {"error": "empty whois response"}

    referred_server: Optional[str] = None
    for line in whois_text.split("\n"):
        line_lower = line.lower()
        if referred_server is None and (
            "refer:" in line_lower
            or "whois:" in line_lower
            or "referralserver:" in line_lower
        ):
            parts = line.split(":", 1)
            if len(parts) > 1:
                candidate = parts[1].strip()
                if candidate and not candidate.lower().startswith("http"):
                    referred_server = candidate.split()[0].strip()

    inferred_server = whois_server or referred_server
    if referred_server and not whois_server:
        raw2 = _run_whois_raw_query(
            asn_key,
            whois_server=referred_server,
            timeout_seconds=max(8, timeout_seconds - 4),
        )
        if raw2.get("ok") and (raw2.get("stdout") or "").strip():
            whois_text = f"{whois_text}\n\n{raw2['stdout']}"
            inferred_server = referred_server

    aut_num: Optional[str] = None
    as_name: Optional[str] = None
    org: Optional[str] = None
    country: Optional[str] = None

    aut_re = re.compile(r"(?im)^aut-num:\s*AS?(\d+)\s*$")
    asname_re = re.compile(r"(?im)^as-name:\s*(.+)\s*$")
    orgname_re = re.compile(r"(?im)^org-name:\s*(.+)\s*$")
    org_arin_re = re.compile(r"(?im)^organization:\s*(.+)\s*$")
    owner_re = re.compile(r"(?im)^owner:\s*(.+)\s*$")
    netname_re = re.compile(r"(?im)^netname:\s*(.+)\s*$")

    for line in whois_text.split("\n"):
        m = aut_re.match(line.strip())
        if m:
            aut_num = f"AS{int(m.group(1))}"
            continue
        m = asname_re.match(line.strip())
        if m and not as_name:
            as_name = m.group(1).strip()
            continue
        m = orgname_re.match(line.strip())
        if m and not org:
            org = m.group(1).strip()
            continue
        m = org_arin_re.match(line.strip())
        if m and not org:
            org = m.group(1).strip()
            continue
        m = owner_re.match(line.strip())
        if m and not org:
            org = m.group(1).strip()
            continue
        m = netname_re.match(line.strip())
        if m and not org:
            org = m.group(1).strip()
            continue
        line_lower = line.lower()
        if "country:" in line_lower:
            parts = line.split(":", 1)
            if len(parts) > 1:
                cc = parts[1].strip().split()[0][:2].upper()
                if len(cc) == 2 and cc.isalpha():
                    country = cc

    if re.search(r"(?i)no match( found)?|not found in the database", whois_text) and not aut_num:
        return {"error": "ASN not found in WHOIS registry response"}

    display_org = org or as_name
    rir = infer_rir_from_whois_server(inferred_server)
    return {
        "asn": aut_num or asn_key,
        "as_name": as_name,
        "org": display_org,
        "country": country,
        "whois_text": whois_text,
        "whois_server": inferred_server,
        "rir": rir,
    }


def _country_display_name_from_db(database: Dict, code: Optional[str]) -> str:
    if not code:
        return "Unknown"
    meta = database.get("metadata", {}).get("countries", {}).get(code.upper(), {})
    return str(meta.get("name") or code.upper())


def investigate_unknown_asn(asn_input: str, database: Dict, *, interactive: bool) -> List[Dict]:
    """
    When an ASN is missing from ``asn_database.json``: WHOIS aut-num, sample geo via ip-api,
    optional add to the local database (TTY only).
    """
    asn_key = normalize_asn_key(asn_input)
    if not asn_key:
        print(f"{Colors.FAIL}{t('unknown_asn_invalid')}{Colors.ENDC}")
        return []

    print(f"\n{Colors.OKCYAN}{t('unknown_asn_not_in_db')}{Colors.ENDC}")

    w = get_whois_asn_data(asn_key)
    if w.get("error"):
        print(f"{Colors.FAIL}{t('unknown_ip_whois_failed')}{Colors.ENDC}")
        print(f"{Colors.WARNING}{t('unknown_ip_whois_error')}{w['error']}{Colors.ENDC}")
        return []

    print(f"\n{Colors.HEADER}{'='*60}{Colors.ENDC}")
    print(f"{Colors.BOLD}{t('unknown_asn_whois_title')}{Colors.ENDC} {w.get('asn')}")
    if w.get("as_name"):
        print(f"{Colors.OKCYAN}{t('unknown_asn_as_name')}{Colors.ENDC}{w['as_name']}")
    if w.get("org"):
        print(f"{Colors.OKCYAN}{t('unknown_ip_detected_org')}{Colors.ENDC}{w['org']}")
    if w.get("country"):
        cname = _country_display_name_from_db(database, w.get("country"))
        print(f"{Colors.OKCYAN}{t('unknown_ip_detected_country')}{Colors.ENDC}{w['country']} ({cname})")
    if w.get("rir"):
        print(f"{Colors.OKCYAN}RIR:{Colors.ENDC} {w['rir']}")

    whois_blob = w.get("whois_text") or ""
    probe_ips = extract_ipv4_probe_ips_from_asn_whois(whois_blob, limit=8)

    if not probe_ips:
        blob_lower = whois_blob.lower()
        srv = (w.get("whois_server") or "").lower()
        if "ripe" in blob_lower or "ripe" in srv:
            extra = _ripe_inverse_routes_for_asn(asn_key)
            if extra.strip():
                whois_blob = whois_blob + "\n\n" + extra
                w["whois_text"] = whois_blob
                probe_ips = extract_ipv4_probe_ips_from_asn_whois(whois_blob, limit=8)

    if not probe_ips:
        print(f"{Colors.WARNING}{t('unknown_asn_no_prefixes')}{Colors.ENDC}")
        if interactive and sys.stdin.isatty() and sys.stdout.isatty():
            try:
                manual = input(f"{Colors.OKCYAN}{t('unknown_asn_sample_ip_prompt')}{Colors.ENDC}").strip()
            except (EOFError, KeyboardInterrupt):
                manual = ""
            if manual:
                try:
                    ipaddress.ip_address(manual)
                    probe_ips = [manual]
                except ValueError:
                    print(f"{Colors.WARNING}{t('invalid_ip')} {manual}{Colors.ENDC}")

    results: List[Dict] = []
    if probe_ips:
        n = min(3, len(probe_ips))
        print(f"\n{Colors.OKCYAN}{t('unknown_asn_probing').format(n=n)}{Colors.ENDC}")
        for ip in probe_ips[:3]:
            results.append(
                check_single_ip(
                    ip,
                    database,
                    auto_reclass=False,
                    interactive_extras=False,
                    invoke_unknown_ip_flow=False,
                )
            )

    results_ok = [r for r in results if r and not r.get("error")]

    auth = assess_data_authenticity(
        geo_country=(results_ok[0].get("actual_country") if results_ok else None),
        whois_country=w.get("country"),
        whois_rir=w.get("rir"),
    )
    if results_ok:
        if auth["ok"]:
            print(f"{Colors.OKGREEN}{t('auth_check_title')}{t('auth_check_ok')}{Colors.ENDC}")
        else:
            warn_text = f"{t('auth_check_title')}{'; '.join(auth['warnings'])}"
            print(f"{Colors.WHITE}{Colors.BGRED}{warn_text}{Colors.ENDC}")

    if not interactive or not (sys.stdin.isatty() and sys.stdout.isatty()):
        return results_ok

    print(f"\n{Colors.WARNING}{t('unknown_asn_add_offer')}{Colors.ENDC}", end="")
    try:
        add_choice = input().strip().lower()
    except (EOFError, KeyboardInterrupt):
        add_choice = "n"

    if add_choice != "y":
        print(f"{Colors.OKCYAN}{t('unknown_asn_add_skipped')}{Colors.ENDC}")
        return results_ok

    anchor_ip: Optional[str] = None
    if results_ok:
        anchor_ip = str(results_ok[0].get("ip") or "")
    elif probe_ips:
        anchor_ip = probe_ips[0]
    elif first_ipv4_route_cidr_from_asn_whois(w.get("whois_text") or ""):
        try:
            net = ipaddress.ip_network(first_ipv4_route_cidr_from_asn_whois(w["whois_text"]), strict=False)
            if isinstance(net, ipaddress.IPv4Network):
                anchor_ip = _ipv4_first_probe_host(net)
        except ValueError:
            pass

    if not anchor_ip:
        print(f"{Colors.FAIL}{t('unknown_asn_add_skipped')}{Colors.ENDC} ({t('unknown_asn_no_prefixes')})")
        return results_ok

    print(f"{Colors.OKCYAN}{t('bgp_pools_collecting', asn=asn_key)}{Colors.ENDC}")
    pools = collect_bgp_pools_for_asn(
        asn_key,
        whois_text=w.get("whois_text") or "",
        probe_ips=probe_ips or ([anchor_ip] if anchor_ip else None),
    )
    if not pools:
        fallback = _default_ipv4_pool_from_ip(anchor_ip)
        pools = [fallback]
        print(f"{Colors.WARNING}{t('bgp_pools_none')}{Colors.ENDC}")
    else:
        print(
            f"{Colors.OKGREEN}{t('bgp_pools_found', n=len(pools), min=MIN_POOL_PREFIXLEN)}{Colors.ENDC}"
        )
        for sample in pools[:5]:
            print(f"  {Colors.DIM}{sample}{Colors.ENDC}")
        if len(pools) > 5:
            print(f"  {Colors.DIM}… +{len(pools) - 5} more{Colors.ENDC}")

    cc = (results_ok[0].get("actual_country") if results_ok else None) or w.get("country")
    if not cc:
        print(f"{Colors.FAIL}{t('unknown_asn_add_skipped')}{Colors.ENDC} (no country from WHOIS/geo)")
        return results_ok

    cname = (
        (results_ok[0].get("actual_country_name") if results_ok else None)
        or _country_display_name_from_db(database, cc)
    )
    org = w.get("org") or w.get("as_name") or asn_key

    if update_database_entry(database, anchor_ip, asn_key, cc, cname, pools=pools, org=org):
        print(f"{Colors.OKGREEN}{t('unknown_asn_added')}{Colors.ENDC}")
    else:
        print(f"{Colors.FAIL}{t('unknown_ip_not_added')}{Colors.ENDC}")

    return results_ok


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

def cli_bgp_lookup_enabled(args, *, for_range: bool = False) -> bool:
    """Resolve --bgp / --no-bgp for geo checks. Default: on for single IP/ASN, off for ranges."""
    if getattr(args, "no_bgp", False):
        return False
    if getattr(args, "bgp", False):
        return True
    return not for_range


def cli_pdns_lookup_enabled(args, *, for_range: bool = False) -> bool:
    """Resolve --pdns / --no-pdns. Default: on for single IP/ASN, off for ranges."""
    if getattr(args, "no_pdns", False):
        return False
    if getattr(args, "pdns", False):
        return True
    return not for_range


def cli_egress_check_enabled(args, *, for_range: bool = False) -> bool:
    """Resolve --egress / --no-egress. Default: on for single IP/ASN, off for ranges."""
    if getattr(args, "no_egress", False):
        return False
    if getattr(args, "egress", False):
        return True
    return not for_range


def run_ptr_range_scan_cli(
    start: str,
    end: str,
    *,
    max_ips: int = 256,
    qps: float = 10.0,
    save: bool = False,
) -> Dict:
    """Bulk PTR sweep; returns session dict (not geo scan results list)."""
    lang = CURRENT_LANGUAGE if CURRENT_LANGUAGE in ("en", "ru") else "en"
    session = ptr_scan.scan_ptr_range(
        start,
        end,
        max_ips=max_ips,
        qps=qps,
        show_progress=True,
        lang=lang,
    )
    ptr_scan.print_ptr_scan_report(
        session,
        lang=lang,
        colors={
            "bold": Colors.BOLD,
            "ok": Colors.OKGREEN,
            "warn": Colors.WARNING,
            "fail": Colors.FAIL,
            "dim": "\033[2m",
            "end": Colors.ENDC,
        },
    )
    if save and session.get("success"):
        try:
            path = ptr_scan.save_ptr_session(session)
            print(f"{Colors.OKGREEN}{ptr_scan.msg(lang, 'save_ok', path=path)}{Colors.ENDC}")
        except OSError as exc:
            print(f"{Colors.FAIL}{ptr_scan.msg(lang, 'save_fail', err=exc)}{Colors.ENDC}")
    return session


def run_egress_check_for_ip(ip: str, geo_data: Dict) -> Dict:
    """Tor exit, ip-api proxy/hosting/mobile, ipinfo bogon, ASN heuristics."""
    print(f"{Colors.OKCYAN}{t('egress_check_running')}{Colors.ENDC}")
    lang = CURRENT_LANGUAGE if CURRENT_LANGUAGE in ("en", "ru") else "en"
    report = ip_egress_check.lookup_egress_context(ip, geo_data, lang=lang)
    ip_egress_check.print_egress_report(
        report,
        lang=lang,
        colors={
            "bold": Colors.BOLD,
            "ok": Colors.OKGREEN,
            "warn": Colors.WARNING,
            "fail": Colors.FAIL,
            "end": Colors.ENDC,
        },
    )
    return report


def get_pdns_api_keys() -> Dict[str, str]:
    """Return optional passive-DNS provider keys from config and environment."""
    cfg = load_enrichment_config()
    return {
        "virustotal": str(cfg.get("virustotal_api_key", "")).strip() or os.getenv("VIRUSTOTAL_API_KEY", "").strip(),
        "securitytrails": str(cfg.get("securitytrails_api_key", "")).strip()
        or os.getenv("SECURITYTRAILS_API_KEY", "").strip(),
    }


def run_pdns_lookup_for_ip(ip: str) -> Dict:
    """Query and print passive DNS / routing history for an IP."""
    print(f"{Colors.OKCYAN}{t('pdns_lookup_running')}{Colors.ENDC}")
    keys = get_pdns_api_keys()
    lang = CURRENT_LANGUAGE if CURRENT_LANGUAGE in ("en", "ru") else "en"
    report = pdns_lookup.lookup_passive_dns(
        ip,
        virustotal_api_key=keys.get("virustotal"),
        securitytrails_api_key=keys.get("securitytrails"),
        lang=lang,
    )
    pdns_lookup.print_pdns_report(
        report,
        lang=lang,
        colors={
            "bold": Colors.BOLD,
            "ok": Colors.OKGREEN,
            "warn": Colors.WARNING,
            "fail": Colors.FAIL,
            "end": Colors.ENDC,
        },
    )
    return report


def parse_cli_args():
    """Parse command-line arguments for non-interactive mode."""
    parser = argparse.ArgumentParser(
        prog="fnkit",
        description="FieldNet Kit (FNkit) — IP/ASN geo integrity, DNS graph, network diagnostics & exposure checks",
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
    bgp_opts = parser.add_mutually_exclusive_group()
    bgp_opts.add_argument(
        "--bgp",
        action="store_true",
        help="Enable live BGP origin lookup (Team Cymru whois -h whois.cymru.com). "
        "Default: on for -i/--asn, off for -r (one extra whois per IP).",
    )
    bgp_opts.add_argument(
        "--no-bgp",
        action="store_true",
        help="Disable live BGP origin lookup (skip Team Cymru whois).",
    )
    pdns_opts = parser.add_mutually_exclusive_group()
    pdns_opts.add_argument(
        "--pdns",
        action="store_true",
        help="Enable passive/historical DNS (RIPE Stat + optional VirusTotal/SecurityTrails). "
        "Default: on for -i/--asn, off for -r.",
    )
    pdns_opts.add_argument(
        "--no-pdns",
        action="store_true",
        help="Disable passive DNS / routing-history lookup.",
    )
    egress_opts = parser.add_mutually_exclusive_group()
    egress_opts.add_argument(
        "--egress",
        action="store_true",
        help="Egress/NAT check: Tor exits, ip-api proxy/hosting, ipinfo bogon. "
        "Default: on for -i/--asn, off for -r.",
    )
    egress_opts.add_argument(
        "--no-egress",
        action="store_true",
        help="Skip Tor / proxy / datacenter egress checks.",
    )
    parser.add_argument(
        "--ptr-scan",
        action="store_true",
        help="Bulk reverse DNS (PTR) for -r range (rate-limited; use --ptr-qps). Skips geo per-IP loop.",
    )
    parser.add_argument(
        "--ptr-qps",
        type=float,
        default=10.0,
        help="Max PTR lookups per second for --ptr-scan (default: 10).",
    )
    parser.add_argument(
        "--ptr-save",
        action="store_true",
        help="Save PTR sweep JSON to ptr_sessions/ (also use -s for scan_results).",
    )
    parser.add_argument(
        "--trace-monitor",
        metavar="HOST",
        dest="trace_monitor_host",
        default=None,
        help="Append-only trace log + save/replay JSON; keys: p pause, q quit (needs traceroute + ping).",
    )
    parser.add_argument(
        "--trace-interval",
        type=float,
        default=3.0,
        help="Seconds between probe rounds for --trace-monitor (default: 3)",
    )
    parser.add_argument(
        "--trace-max-hops",
        type=int,
        default=30,
        help="Max hops for traceroute in --trace-monitor (default: 30)",
    )
    parser.add_argument(
        "--trace-rediscover",
        type=int,
        default=45,
        help="Re-run traceroute every N rounds (0=disable, default: 45)",
    )
    parser.add_argument(
        "--speed-test",
        action="store_true",
        help="ICMP ping + HTTP download/upload throughput (Cloudflare endpoints, approximate).",
    )
    parser.add_argument(
        "--speed-streams",
        type=int,
        default=None,
        metavar="N",
        help="Parallel HTTP streams for --speed-test (default 4, or FNKIT_SPEED_STREAMS).",
    )
    parser.add_argument(
        "--trace-replay",
        metavar="FILE",
        dest="trace_replay",
        default=None,
        help="Replay a JSON session saved after --trace-monitor (see data/sessions/trace/).",
    )
    parser.add_argument(
        "--trace-replay-delay",
        type=float,
        default=0.25,
        metavar="SEC",
        help="Pause between rounds when using --trace-replay (default: 0.25; use 0 for instant dump).",
    )
    parser.add_argument(
        "--pcap-show",
        metavar="FILE",
        dest="pcap_show",
        default=None,
        help="Print packet summaries (tshark preferred) or tcpdump -r fallback.",
    )
    parser.add_argument(
        "--pcap-max-packets",
        type=int,
        default=80,
        dest="pcap_max_packets",
        help="Cap rows for --pcap-show (default: 80).",
    )
    parser.add_argument(
        "--pcap-hex",
        action="store_true",
        dest="pcap_hex",
        help="With --pcap-show, add hex (tshark -x) when available.",
    )
    parser.add_argument(
        "--pcap-capture",
        metavar="IFACE",
        dest="pcap_capture",
        default=None,
        help="Capture on interface via tcpdump (needs --pcap-out; often sudo).",
    )
    parser.add_argument(
        "--pcap-out",
        metavar="FILE",
        dest="pcap_out",
        default=None,
        help="Write path for live capture (--pcap-capture).",
    )
    parser.add_argument(
        "--pcap-seconds",
        type=float,
        default=10.0,
        dest="pcap_seconds",
        help="Capture duration seconds (default: 10).",
    )
    parser.add_argument(
        "--pcap-filter",
        metavar="BPF",
        dest="pcap_filter",
        default=None,
        help="Optional tcpdump BPF filter expression (quoted if spaces).",
    )
    parser.add_argument("--dns", metavar="DOMAIN", default=None, help="DNS graph crawl from domain (needs dnspython).")
    parser.add_argument("--dns-depth", type=int, default=4, help="Max BFS depth for --dns (default: 4).")
    parser.add_argument("--dns-max-domains", type=int, default=500, help="Max domains for --dns (default: 500).")
    parser.add_argument("--dns-save", action="store_true", help="Save DNS session JSON to data/sessions/dns/.")
    parser.add_argument("--dns-wordlist", metavar="FILE", default=None, help="Subdomain wordlist for --dns.")
    parser.add_argument("--dns-crtsh", action="store_true", help="Passive subdomains from crt.sh for --dns.")
    parser.add_argument("--dns-qps", type=float, default=20.0, help="Max DNS queries per second (default: 20).")
    parser.add_argument("--dns-replay", metavar="FILE", default=None, help="Print summary for saved DNS session JSON.")
    parser.add_argument("--dns-export", metavar="FILE", default=None, help="Export DNS session to HTML graph.")
    parser.add_argument("--dns-pcap", metavar="FILE", default=None, help="Seed DNS crawl from DNS names in PCAP (tshark).")
    parser.add_argument(
        "--owasp-headers",
        metavar="URL",
        default=None,
        help="Built-in Secure Headers check (OWASP-aligned, no extra install).",
    )
    parser.add_argument(
        "--owasp-tls",
        metavar="HOST",
        default=None,
        help="TLS check on :443 (cert expiry, cipher, TLSv1.0/1.1/SSLv3 probe; stdlib ssl).",
    )
    parser.add_argument("--owasp-amass", metavar="DOMAIN", default=None, help="Run passive Amass enum (needs amass in PATH).")
    parser.add_argument(
        "--owasp-takeover",
        action="store_true",
        help="After --owasp-amass, check CNAME dangling / takeover fingerprints (needs dnspython).",
    )
    parser.add_argument(
        "--owasp-takeover-file",
        metavar="FILE",
        default=None,
        help="Host list (one FQDN per line) for subdomain takeover check.",
    )
    parser.add_argument(
        "--owasp-nettacker",
        metavar="HOST",
        default=None,
        help="Run Nettacker port_scan (needs separate AGPL install).",
    )
    parser.add_argument("--owasp-wstg", action="store_true", help="Print WSTG checklist links.")
    parser.add_argument(
        "--owasp-pipeline",
        action="store_true",
        help="Run headers + TLS + optional Amass + WSTG (use with --owasp-domain / --owasp-ip).",
    )
    parser.add_argument("--owasp-ip", metavar="IP", default=None, help="Target IP for --owasp-pipeline.")
    parser.add_argument("--owasp-domain", metavar="DOMAIN", default=None, help="Target domain for --owasp-pipeline / Amass.")
    parser.add_argument(
        "--owasp-nettacker-run",
        action="store_true",
        help="With --owasp-pipeline, also run Nettacker port_scan.",
    )
    parser.add_argument("--owasp-save", action="store_true", help="Save OWASP pipeline session to data/sessions/owasp/.")
    parser.add_argument(
        "--check-deps",
        action="store_true",
        help="Verify dependencies from dependencies.manifest.json and exit.",
    )
    parser.add_argument(
        "--check-deps-group",
        action="append",
        dest="check_deps_groups",
        default=None,
        metavar="GROUP",
        help="With --check-deps: minimal, dns, pcap, owasp, full, etc. (repeatable).",
    )
    parser.add_argument(
        "--check-deps-hints",
        action="store_true",
        help="With --check-deps: print install hints from manifest.",
    )
    parser.add_argument(
        "--maintain-db",
        action="store_true",
        help="Maintain asn_database.json (dedupe ASN, prune coarse pools, fix metadata) and exit.",
    )
    parser.add_argument(
        "--validate-db",
        action="store_true",
        help="Validate asn_database.json schema/counters (no writes) and exit.",
    )
    return parser.parse_args()

def save_results(results: List[Dict]) -> bool:
    """Save scan results to JSON file."""
    try:
        payload = {
            "timestamp": datetime.now().isoformat(),
            "results": results,
            "mismatches_found": sum(1 for r in results if r.get("mismatches")),
        }
        save_json_file(RESULTS_FILE, DocumentKind.SCAN_RESULTS, payload)
        return True
    except Exception as e:
        print(f"{Colors.FAIL}Failed to save results: {e}{Colors.ENDC}")
        return False

def find_asn_entry(database: Dict, asn_raw: str) -> Optional[Dict]:
    """Return the single ASN row for this number (after dedupe there is at most one)."""
    key = normalize_asn_key(asn_raw)
    if not key:
        return None
    for entry in database.get("asn_data", []):
        if normalize_asn_key(entry.get("asn")) == key:
            return entry
    return None


def _pool_match_score(
    item: tuple,
    *,
    geo_asn: Optional[str] = None,
    geo_country: Optional[str] = None,
    bgp_asn: Optional[str] = None,
) -> int:
    """Higher score = preferred when several pools share the same prefix length."""
    asn_entry, _pool, prefixlen = item
    score = int(prefixlen) * 100
    asn_norm = normalize_asn_key(asn_entry.get("asn"))
    geo_asn_norm = normalize_asn_key(geo_asn) if geo_asn else None
    bgp_asn_norm = normalize_asn_key(bgp_asn) if bgp_asn else None
    geo_cc = normalize_country_code(geo_country)
    expected_cc = normalize_country_code(asn_entry.get("expected_country"))

    if geo_cc and expected_cc and geo_cc == expected_cc:
        score += 50_000
    if geo_asn_norm and asn_norm and geo_asn_norm == asn_norm:
        score += 10_000
    if bgp_asn_norm and asn_norm and bgp_asn_norm == asn_norm:
        score += 20_000
    if asn_entry.get("verified"):
        score += 500
    return score


def _merge_asn_entry_group(asn_key: str, group: List[Dict]) -> Dict:
    """Merge duplicate rows that share the same ASN number."""

    def _entry_rank(entry: Dict) -> tuple:
        acceptable = [p for p in entry.get("ip_pools", []) if is_acceptable_pool(p)]
        max_plen = max((pool_prefixlen(p) or 0 for p in acceptable), default=0)
        return (len(acceptable), max_plen, entry.get("verified", False), entry.get("last_checked", ""))

    primary = max(group, key=_entry_rank)
    merged = dict(primary)
    merged["asn"] = asn_key

    pools: set[str] = set()
    for entry in group:
        for raw in entry.get("ip_pools", []):
            cidr = normalize_pool_cidr(raw)
            if cidr and is_acceptable_pool(cidr):
                pools.add(cidr)
    merged["ip_pools"] = sorted(pools, key=lambda c: pool_prefixlen(c) or 0, reverse=True)[
        :MAX_POOLS_STORE_PER_ASN
    ]

    countries = {normalize_country_code(e.get("expected_country")) for e in group} - {None}
    owners = [e.get("owner") for e in group if e.get("owner")]
    if len(countries) > 1:
        merged["verified"] = False
        merged["notes"] = (
            f"Merged {len(group)} duplicate {asn_key} rows; conflicting countries "
            f"{sorted(countries)}. Owners: {owners}. Pool match uses geo/BGP disambiguation."
        )
    elif len(set(owners)) > 1:
        merged["notes"] = f"Merged duplicate {asn_key}; owners were: {owners}"

    return merged


def dedupe_asn_database(database: Dict) -> int:
    """Collapse multiple ``asn_data`` rows with the same ASN number. Returns merge group count."""
    grouped: Dict[str, List[Dict]] = {}
    for entry in database.get("asn_data", []):
        key = normalize_asn_key(entry.get("asn"))
        if not key:
            continue
        grouped.setdefault(key, []).append(entry)

    merged_rows: List[Dict] = []
    merge_groups = 0
    for key in sorted(grouped.keys()):
        group = grouped[key]
        if len(group) > 1:
            merge_groups += 1
            merged_rows.append(_merge_asn_entry_group(key, group))
        else:
            row = dict(group[0])
            row["asn"] = key
            merged_rows.append(row)

    database["asn_data"] = merged_rows
    if merge_groups:
        meta = database.setdefault("metadata", {})
        meta["total_asns"] = len(merged_rows)
        meta["total_ip_pools"] = sum(len(a.get("ip_pools", [])) for a in merged_rows)
        meta["last_updated"] = datetime.now().strftime("%Y-%m-%d")
        log = meta.setdefault("asn_dedupe_log", [])
        log.append(
            {
                "at": datetime.now().isoformat(),
                "merge_groups": merge_groups,
            }
        )
    return merge_groups


def get_best_pool_match(
    ip: str,
    database: Dict,
    *,
    geo_asn: Optional[str] = None,
    geo_country: Optional[str] = None,
    bgp_asn: Optional[str] = None,
) -> List[tuple]:
    """Return the best ASN pool match(es) for an IP, disambiguated by geo/BGP when needed."""
    ip_obj = ipaddress.ip_address(ip)
    candidates: List[tuple] = []

    for asn_entry in database["asn_data"]:
        for pool in asn_entry["ip_pools"]:
            if not is_acceptable_pool(pool):
                continue
            try:
                network = ipaddress.ip_network(pool, strict=False)
            except ValueError:
                continue
            if ip_obj in network:
                candidates.append((asn_entry, pool, network.prefixlen))

    if not candidates:
        return []

    best_prefix = max(item[2] for item in candidates)
    tied = [item for item in candidates if item[2] == best_prefix]
    if len(tied) == 1:
        return tied

    ranked = sorted(
        tied,
        key=lambda item: _pool_match_score(
            item, geo_asn=geo_asn, geo_country=geo_country, bgp_asn=bgp_asn
        ),
        reverse=True,
    )
    top = _pool_match_score(ranked[0], geo_asn=geo_asn, geo_country=geo_country, bgp_asn=bgp_asn)
    winners = [
        item
        for item in ranked
        if _pool_match_score(item, geo_asn=geo_asn, geo_country=geo_country, bgp_asn=bgp_asn) == top
    ]
    return winners

def update_database_entry(
    database: Dict,
    ip: str,
    asn: str,
    country_code: str,
    country_name: str,
    pool: Optional[str] = None,
    org: str = None,
    *,
    pools: Optional[List[str]] = None,
) -> bool:
    """Update or create ASN entry in database with one or more BGP-derived pools."""
    try:
        incoming: List[str] = []
        if pools:
            incoming.extend(pools)
        if pool:
            incoming.append(pool)
        normalized: List[str] = []
        for raw in incoming:
            cidr = normalize_pool_cidr(raw)
            if not cidr:
                continue
            if not is_acceptable_pool(cidr):
                plen = pool_prefixlen(cidr)
                if plen is not None:
                    print(
                        f"{Colors.DIM}{t('bgp_pools_coarse_skipped', plen=plen, min=MIN_POOL_PREFIXLEN, pool=cidr)}{Colors.ENDC}"
                    )
                continue
            if cidr not in normalized:
                normalized.append(cidr)

        asn_norm = normalize_asn_key(asn) or asn
        asn_entry = find_asn_entry(database, asn_norm)
        
        if asn_entry:
            asn_entry['expected_country'] = country_code
            asn_entry['expected_country_name'] = country_name
            asn_entry['country_code'] = country_code
            asn_entry['country_name'] = country_name
            
            if org and org.strip():
                asn_entry['owner'] = org

            kept = [p for p in asn_entry.get('ip_pools', []) if is_acceptable_pool(p)]
            for cidr in normalized:
                if cidr not in kept:
                    kept.append(cidr)
            asn_entry['ip_pools'] = kept[:MAX_POOLS_STORE_PER_ASN]
            
            asn_entry['last_checked'] = datetime.now().strftime("%Y-%m-%d")
            asn_entry['notes'] = f"Updated: IP geolocation verified as {country_code} ({country_name})"
        else:
            if not normalized:
                normalized = [_default_ipv4_pool_from_ip(ip)]
            new_entry = {
                'asn': asn_norm,
                'owner': org or f"Auto-added from IP {ip}",
                'country_code': country_code,
                'country_name': country_name,
                'region': 'Multi-Regional',
                'expected_country': country_code,
                'expected_country_name': country_name,
                'ip_pools': normalized[:MAX_POOLS_STORE_PER_ASN],
                'check_status': 'active',
                'last_checked': datetime.now().strftime("%Y-%m-%d"),
                'verified': False,
                'notes': f'Auto-added entry for {asn} (BGP/WHOIS prefixes)'
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

def display_provider_name(db_owner: Optional[str], detected_org: Optional[str], detected_isp: Optional[str] = None) -> str:
    """
    Prefer a real provider/org name in output.
    If DB owner is an auto-added placeholder, use detected org when available.
    """
    owner = (db_owner or "").strip()
    detected = (detected_org or "").strip()
    isp = (detected_isp or "").strip()
    if owner.lower().startswith("auto-added from ip"):
        return detected or isp or owner
    return owner or detected or isp or "Unknown"

def check_single_ip(
    ip: str,
    database: Dict,
    auto_reclass: bool = False,
    interactive_extras: bool = True,
    invoke_unknown_ip_flow: bool = True,
    bgp_lookup: bool = True,
    pdns_lookup: bool = True,
    egress_check: bool = True,
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

    rev = geo_data.get('reverse')
    if rev:
        print(f"  {t('ptr_reverse')}{Colors.OKGREEN}{rev}{Colors.ENDC}")
    else:
        print(f"  {t('ptr_reverse')}{Colors.WARNING}{t('ptr_none')}{Colors.ENDC}")
    
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
        'bgp_origin': None,
        'passive_dns': None,
        'egress_context': None,
        '_abuse_shown': False,
    }

    if egress_check:
        result['egress_context'] = run_egress_check_for_ip(ip, geo_data)

    best_matches = get_best_pool_match(
        ip,
        database,
        geo_asn=geo_data.get("asn"),
        geo_country=geo_data.get("country_code"),
    )
    pool_match_ambiguous = len(best_matches) > 1
    expected_db_asn = best_matches[0][0]["asn"] if best_matches else None
    defer_bgp = invoke_unknown_ip_flow and not best_matches
    defer_pdns = invoke_unknown_ip_flow and not best_matches

    if bgp_lookup and not defer_bgp:
        result["bgp_origin"] = print_bgp_origin_verification(
            ip,
            expected_asn=expected_db_asn,
            geo_asn=geo_data.get("asn"),
        )
        if len(best_matches) > 1 and result.get("bgp_origin", {}).get("success"):
            refined = get_best_pool_match(
                ip,
                database,
                geo_asn=geo_data.get("asn"),
                geo_country=geo_data.get("country_code"),
                bgp_asn=result["bgp_origin"].get("asn"),
            )
            if len(refined) == 1:
                best_matches = refined

    if pdns_lookup and not defer_pdns:
        result['passive_dns'] = run_pdns_lookup_for_ip(ip)

    if best_matches:
        asn_entry, pool, _ = best_matches[0]
        expected_country = asn_entry['expected_country']
        actual_country = geo_data['country_code']

        if len(best_matches) > 1:
            print(f"{Colors.WARNING}{t('pool_match_ambiguous_unresolved')}{Colors.ENDC}")
        elif pool_match_ambiguous and len(best_matches) == 1:
            entry = best_matches[0][0]
            print(
                f"{Colors.WARNING}{t('pool_match_ambiguous').format(asn=entry['asn'], country=entry.get('expected_country'))}{Colors.ENDC}"
            )

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
            provider_name = display_provider_name(
                asn_entry.get('owner'),
                geo_data.get('org'),
                geo_data.get('isp'),
            )
            print(f"  {t('provider_owner')} {provider_name}")
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
            provider_name = display_provider_name(
                asn_entry.get('owner'),
                geo_data.get('org'),
                geo_data.get('isp'),
            )
            print(f"  {t('provider_owner')} {provider_name}")
            pdns = result.get("passive_dns") or {}
            for sig in pdns.get("rotation_signals") or []:
                print(f"  {Colors.WARNING}⚠ {sig}{Colors.ENDC}")
            if interactive_extras:
                fetch_and_print_abuse_contact(ip)
                result['_abuse_shown'] = True

            print(f"\n{Colors.WARNING}{t('offer_reclassify')}{Colors.ENDC}", end="")

            while True:
                try:
                    if auto_reclass:
                        offer_reclass = 'y'
                        print("y (auto)")
                    else:
                        offer_reclass = input().strip().lower()
                except (EOFError, KeyboardInterrupt):
                    offer_reclass = 'n'
                if offer_reclass in ('y', 'n'):
                    break
                print(f"{Colors.WARNING}{t('unknown_ip_invalid_yes_no')}{Colors.ENDC}")

            if offer_reclass == 'y':
                reclassified = reclassify_asn(result, database, auto_confirm=auto_reclass)
                result['mismatches'] = reclassified.get('mismatches', [])
                result['matches'] = reclassified.get('matches', [])
    else:
        print(f"{Colors.WARNING}{t('ip_not_found')}{Colors.ENDC}")
        result['status'] = 'not_in_database'

        if invoke_unknown_ip_flow:
            # If IP is not in local pools, run WHOIS report flow (interactive add).
            print(f"{Colors.OKCYAN}{t('unknown_ip_no_local_data')}{Colors.ENDC}")
            handle_unknown_ip(ip, result, database, interactive_extras=interactive_extras)
    if best_matches:
        result['status'] = 'checked'

    if geo_data.get('success') and interactive_extras:
        if not result.get('_abuse_shown'):
            fetch_and_print_abuse_contact(ip)
            result['_abuse_shown'] = True
        owasp_toolkit.set_context(ip=ip)
        offer_network_tools_menu(ip)

    return result

def prompt_valid_ip_or_cancel() -> Optional[str]:
    """Prompt until a valid IP is entered, or return None when user cancels with 0."""
    while True:
        ip_input = input(f"{Colors.OKCYAN}IP: {Colors.ENDC}").strip()
        if ip_input == "0":
            print(f"{Colors.OKCYAN}{t('ip_input_cancelled')}{Colors.ENDC}")
            return None
        try:
            ipaddress.ip_address(ip_input)
            return ip_input
        except ValueError:
            print(f"{Colors.WARNING}{t('invalid_ip')} {ip_input}{Colors.ENDC}")
            print(f"{Colors.OKCYAN}{t('ip_input_hint')}{Colors.ENDC}")

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
    
    pool = ipv4_pool_from_whois(whois_data.get("whois_text") or "", ip)
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

    if not (result.get('bgp_origin') or {}).get('success'):
        result['bgp_origin'] = print_bgp_origin_verification(
            ip,
            expected_asn=normalize_asn_key(detected_asn) if detected_asn else None,
            geo_asn=result.get('asn'),
        )
    if not (result.get('passive_dns') or {}).get('success'):
        result['passive_dns'] = run_pdns_lookup_for_ip(ip)
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
            pools_for_db: List[str] = []
            if asn_clean != 'none_ASN':
                print(f"{Colors.OKCYAN}{t('bgp_pools_collecting', asn=asn_clean)}{Colors.ENDC}")
                pools_for_db = collect_bgp_pools_for_asn(
                    asn_clean,
                    whois_text=whois_data.get("whois_text") or "",
                    probe_ips=[ip],
                )
            if not pools_for_db:
                bgp = result.get("bgp_origin") or {}
                if bgp.get("success") and bgp.get("bgp_prefix"):
                    cidr = normalize_pool_cidr(bgp["bgp_prefix"])
                    if cidr and is_acceptable_pool(cidr):
                        pools_for_db = [cidr]
                if not pools_for_db and is_acceptable_pool(pool):
                    pools_for_db = [normalize_pool_cidr(pool) or pool]
                if not pools_for_db:
                    pools_for_db = [_default_ipv4_pool_from_ip(ip)]
                    print(f"{Colors.WARNING}{t('bgp_pools_none')}{Colors.ENDC}")
            else:
                print(
                    f"{Colors.OKGREEN}{t('bgp_pools_found', n=len(pools_for_db), min=MIN_POOL_PREFIXLEN)}{Colors.ENDC}"
                )
            success = update_database_entry(
                database,
                ip=ip,
                asn=asn_clean,
                country_code=detected_country,
                country_name=detected_country_name,
                pools=pools_for_db,
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
    
    if whois_data and not whois_data.get("error"):
        print(f"  ASN: {whois_data.get('asn') or 'N/A'}")
        print(f"  {t('actual_country')}: {whois_data.get('country') or 'N/A'}")
        print(f"  Org: {whois_data.get('org') or 'N/A'}")
    elif whois_data and whois_data.get("error"):
        print(f"  WHOIS: error ({whois_data.get('error')})")
    
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
    
    confirm = 'y' if auto_confirm else 'n'
    try:
        if auto_confirm:
            print(f"{t('auto_updating')}")
        else:
            confirm = input(f"{Colors.WARNING}{t('confirm')}{Colors.ENDC}")
    except (EOFError, KeyboardInterrupt):
        confirm = 'y' if auto_confirm else 'n'
    
    if confirm.lower() == 'y':
        org_name = result.get('org')
        target_country = policy.get("target_country") or result['actual_country']
        target_country_name = result['actual_country_name'] if target_country == result['actual_country'] else result['actual_country_name']
        pools_rec = collect_bgp_pools_for_asn(mismatch['asn'], probe_ips=[ip])
        if not pools_rec:
            fallback = mismatch.get('pool') or _default_ipv4_pool_from_ip(ip)
            if is_acceptable_pool(fallback):
                pools_rec = [normalize_pool_cidr(fallback) or fallback]
            else:
                pools_rec = [_default_ipv4_pool_from_ip(ip)]

        if update_database_entry(
            database,
            ip,
            mismatch['asn'],
            target_country,
            target_country_name,
            pools=pools_rec,
            org=org_name,
        ):
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

def check_ip_range(
    start: str,
    end: str,
    database: Dict,
    max_ips: int = 256,
    auto_reclass: bool = False,
    bgp_lookup: bool = False,
    pdns_lookup: bool = False,
    egress_check: bool = False,
) -> List[Dict]:
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
            str(current),
            database,
            auto_reclass=auto_reclass,
            interactive_extras=False,
            bgp_lookup=bgp_lookup,
            pdns_lookup=pdns_lookup,
            egress_check=egress_check,
        )
        results.append(result)
        current += 1
        count += 1

    return results

def check_asn_operator(
    asn_input: str,
    database: Dict,
    auto_reclass: bool = False,
    bgp_lookup: bool = True,
    pdns_lookup: bool = True,
    egress_check: bool = True,
) -> List[Dict]:
    """Check a single ASN by sampling one IP per pool."""
    asn_query = asn_input if asn_input.upper().startswith("AS") else f"AS{asn_input}"
    asn_data = find_asn_entry(database, asn_query)

    if not asn_data:
        tty = sys.stdin.isatty() and sys.stdout.isatty()
        return investigate_unknown_asn(asn_input, database, interactive=tty)

    print(f"\n{Colors.OKCYAN}Checking ASN: {asn_query}{Colors.ENDC}")
    print(f"  Owner: {asn_data['owner']}")
    print(f"  {t('expected_country')}: {asn_data['expected_country']} ({asn_data['expected_country_name']})")

    results = []
    sample_pools = [p for p in asn_data['ip_pools'] if is_acceptable_pool(p)][:MAX_POOLS_SAMPLE_CHECK]
    for pool in sample_pools:
        try:
            network = ipaddress.ip_network(pool, strict=False)
            result = check_single_ip(
                str(network.network_address),
                database,
                auto_reclass=auto_reclass,
                interactive_extras=False,
                invoke_unknown_ip_flow=False,
                bgp_lookup=bgp_lookup,
                pdns_lookup=pdns_lookup,
                egress_check=egress_check,
            )
            results.append(result)
        except ValueError:
            continue

    return results


def _dns_enrich_ip_node(ip: str, node: Dict) -> None:
    """Attach ip-api geo fields to DNS graph IP nodes."""
    geo = get_ip_geolocation(ip)
    if geo.get("success"):
        node["geo_country"] = geo.get("country_code")
        node["geo_country_name"] = geo.get("country")
        node["isp"] = geo.get("isp")


def handle_dns_cli(args) -> None:
    """Non-interactive DNS graph crawl / replay / export."""
    lang = CURRENT_LANGUAGE if CURRENT_LANGUAGE in ("en", "ru") else "en"
    enrich = _dns_enrich_ip_node

    if getattr(args, "dns_replay", None):
        path = Path(str(args.dns_replay)).expanduser()
        try:
            session = dns_diag.load_session(path)
            dns_diag.print_session_summary(session, lang=lang)
        except (OSError, ValueError, json.JSONDecodeError) as exc:
            print(f"{Colors.FAIL}{dns_diag.msg(lang, 'load_fail', err=exc)}{Colors.ENDC}")
        if getattr(args, "dns_export", None):
            out = Path(str(args.dns_export)).expanduser()
            try:
                session = dns_diag.load_session(path)
                out_path = dns_diag.export_html(session, out, lang=lang)
                print(f"{Colors.OKGREEN}{dns_diag.msg(lang, 'html_ok', path=out_path)}{Colors.ENDC}")
            except (OSError, ValueError, json.JSONDecodeError) as exc:
                print(f"{Colors.FAIL}{dns_diag.msg(lang, 'html_fail', err=exc)}{Colors.ENDC}")
        return

    session: Dict = {}
    if getattr(args, "dns_pcap", None):
        session = dns_diag.crawl_from_pcap_seed(
            Path(str(args.dns_pcap)).expanduser(),
            getattr(args, "dns", None),
            enrich_ip=enrich,
            lang=lang,
            max_depth=int(args.dns_depth),
            max_domains=int(args.dns_max_domains),
            qps=float(args.dns_qps),
            wordlist=Path(args.dns_wordlist).expanduser() if getattr(args, "dns_wordlist", None) else None,
        )
    elif getattr(args, "dns", None):
        session = dns_diag.crawl_dns(
            str(args.dns),
            max_depth=int(args.dns_depth),
            max_domains=int(args.dns_max_domains),
            qps=float(args.dns_qps),
            use_crtsh=bool(getattr(args, "dns_crtsh", False)),
            wordlist=Path(args.dns_wordlist).expanduser() if getattr(args, "dns_wordlist", None) else None,
            enrich_ip=enrich,
            lang=lang,
        )
    else:
        return

    if not session:
        return
    dns_diag.print_session_summary(session, lang=lang)
    if getattr(args, "dns_save", False):
        path = dns_diag.save_session(session)
        print(f"{Colors.OKGREEN}{dns_diag.msg(lang, 'save_ok', path=path)}{Colors.ENDC}")
    if getattr(args, "dns_export", None):
        out = Path(str(args.dns_export)).expanduser()
        out_path = dns_diag.export_html(session, out, lang=lang)
        print(f"{Colors.OKGREEN}{dns_diag.msg(lang, 'html_ok', path=out_path)}{Colors.ENDC}")


def handle_network_diag_cli(args) -> None:
    """Non-interactive trace monitor and/or speed test (no ASN database load)."""
    lang = CURRENT_LANGUAGE if CURRENT_LANGUAGE in ("en", "ru") else "en"
    pcap_sh = getattr(args, "pcap_show", None)
    if pcap_sh:
        pcap_diag.show_pcap_file(
            Path(str(pcap_sh)),
            lang=lang,
            max_packets=max(1, int(getattr(args, "pcap_max_packets", 80))),
            hex_dump=bool(getattr(args, "pcap_hex", False)),
        )
    cap_if = getattr(args, "pcap_capture", None)
    if cap_if:
        out_p = getattr(args, "pcap_out", None)
        if not out_p:
            print(f"{Colors.FAIL}{pcap_diag.msg(lang, 'pcap_need_iface_out')}{Colors.ENDC}")
        else:
            bpf = getattr(args, "pcap_filter", None)
            if bpf and not pcap_diag.validate_bpf_relaxed(bpf):
                print(f"{Colors.FAIL}{pcap_diag.msg(lang, 'pcap_filter_invalid')}{Colors.ENDC}")
            elif not pcap_diag.validate_capture_interface(str(cap_if)):
                print(f"{Colors.FAIL}{pcap_diag.msg(lang, 'pcap_capture_err', err='bad interface name')}{Colors.ENDC}")
            else:
                outp = pcap_diag.sanitize_out_path(str(out_p))
                if outp is None:
                    print(f"{Colors.FAIL}{pcap_diag.msg(lang, 'pcap_capture_err', err='bad output path')}{Colors.ENDC}")
                else:
                    pcap_diag.capture_pcap(
                        str(cap_if).strip(),
                        outp,
                        lang=lang,
                        duration_sec=float(getattr(args, "pcap_seconds", 10.0)),
                        bpf_filter=bpf,
                    )
    replay_arg = getattr(args, "trace_replay", None)
    if replay_arg:
        delay = float(getattr(args, "trace_replay_delay", 0.25))
        network_diag.replay_trace_path(str(replay_arg), lang=lang, delay_sec=delay)
    if getattr(args, "speed_test", False):
        network_diag.run_speed_test(lang=lang, streams=getattr(args, "speed_streams", None))
    host = getattr(args, "trace_monitor_host", None)
    if host:
        host = str(host).strip()
        if not network_diag.validate_trace_host(host):
            print(f"{Colors.FAIL}{network_diag.localized(lang, 'invalid_host', host=host)}{Colors.ENDC}")
            return
        interval = max(0.5, min(float(args.trace_interval), 600.0))
        rediscover = max(0, int(args.trace_rediscover))
        network_diag.run_trace_monitor(
            host,
            lang=lang,
            interval=interval,
            max_hops=max(2, min(int(args.trace_max_hops), 64)),
            rediscover_every=rediscover,
        )


def _diagnostics_select_trace_json() -> Optional[Path]:
    """List trace_sessions/*.json; number, path, or 0 to cancel."""
    files = network_diag.list_trace_session_json_files()
    td = network_diag.TRACE_SESSIONS_DIR.resolve()
    print(f"{Colors.OKCYAN}{t('diag_replay_intro').format(dir=str(td))}{Colors.ENDC}\n")
    if files:
        for i, p in enumerate(files, 1):
            sz = p.stat().st_size
            print(f"  {i}) {p.name}  ({sz} bytes)")
    else:
        print(f"{Colors.WARNING}{t('diag_replay_empty')}{Colors.ENDC}\n")
    try:
        raw = input(f"{Colors.WARNING}{t('diag_pick_trace_prompt')}{Colors.ENDC}").strip()
    except (EOFError, KeyboardInterrupt):
        print()
        return None
    if not raw or raw == "0":
        return None
    if raw.isdigit():
        idx = int(raw)
        if files and 1 <= idx <= len(files):
            return files[idx - 1]
    return Path(raw).expanduser()


def _diagnostics_select_pcap_file() -> Optional[Path]:
    """List network capture folder; number, path, or 0 to cancel."""
    files = pcap_diag.list_network_capture_files()
    cd = pcap_diag.network_capture_dir().resolve()
    print(f"{Colors.OKCYAN}{t('diag_pcap_intro').format(dir=str(cd))}{Colors.ENDC}\n")
    if files:
        for i, p in enumerate(files, 1):
            sz = p.stat().st_size
            print(f"  {i}) {p.name}  ({sz} bytes)")
    else:
        print(f"{Colors.WARNING}{t('diag_pcap_empty_dir')}{Colors.ENDC}\n")
    try:
        raw = input(f"{Colors.WARNING}{t('diag_pcap_pick_prompt')}{Colors.ENDC}").strip()
    except (EOFError, KeyboardInterrupt):
        print()
        return None
    if not raw or raw == "0":
        return None
    if raw.isdigit():
        idx = int(raw)
        if files and 1 <= idx <= len(files):
            return files[idx - 1]
    return Path(raw).expanduser()


def network_diagnostics_menu() -> None:
    """Interactive entry: speed test, trace monitor, replay, PCAP tools."""
    if not (sys.stdin.isatty() and sys.stdout.isatty()):
        return
    lang = CURRENT_LANGUAGE if CURRENT_LANGUAGE in ("en", "ru") else "en"
    while True:
        print(f"\n{Colors.HEADER}{'-' * 60}{Colors.ENDC}")
        print(f"{Colors.BOLD}{t('diag_menu_title')}{Colors.ENDC}")
        print(f"{Colors.OKCYAN}{t('diag_opt_speed')}{Colors.ENDC}")
        print(f"{Colors.OKCYAN}{t('diag_opt_trace')}{Colors.ENDC}")
        print(f"{Colors.OKCYAN}{t('diag_opt_replay')}{Colors.ENDC}")
        print(f"{Colors.OKCYAN}{t('diag_opt_pcap_capture')}{Colors.ENDC}")
        print(f"{Colors.OKCYAN}{t('diag_opt_pcap_show')}{Colors.ENDC}")
        print(f"{Colors.OKCYAN}{t('diag_opt_back')}{Colors.ENDC}")
        try:
            choice = input(f"{Colors.WARNING}{t('diag_menu_prompt')}{Colors.ENDC}").strip()
        except (EOFError, KeyboardInterrupt):
            print()
            break
        if choice == "0":
            break
        if choice == "1":
            network_diag.run_speed_test(lang=lang)
        elif choice == "2":
            try:
                raw = input(f"{Colors.OKCYAN}{t('diag_host_prompt')}{Colors.ENDC}").strip()
            except (EOFError, KeyboardInterrupt):
                print()
                continue
            if not raw:
                continue
            if not network_diag.validate_trace_host(raw):
                print(f"{Colors.FAIL}{network_diag.localized(lang, 'invalid_host', host=raw)}{Colors.ENDC}")
                continue
            network_diag.run_trace_monitor(
                raw,
                lang=lang,
                interval=3.0,
                max_hops=30,
                rediscover_every=45,
            )
        elif choice == "3":
            sel = _diagnostics_select_trace_json()
            if sel is None:
                continue
            if not sel.exists():
                print(f"{Colors.FAIL}{t('diag_file_not_found').format(path=sel)}{Colors.ENDC}")
                continue
            leave_replay = False
            while not leave_replay:
                played = network_diag.replay_trace_path(str(sel), lang=lang, delay_sec=0.25)
                if not played:
                    break
                print(f"{Colors.OKCYAN}{t('diag_replay_post_menu')}{Colors.ENDC}")
                while True:
                    try:
                        act = input(
                            f"{Colors.WARNING}{t('diag_replay_post_prompt')}{Colors.ENDC}"
                        ).strip().lower()
                    except (EOFError, KeyboardInterrupt):
                        print()
                        leave_replay = True
                        break
                    if act == "q":
                        leave_replay = True
                        break
                    if act == "r":
                        break
                    print(f"{Colors.WARNING}{t('diag_replay_post_invalid')}{Colors.ENDC}")
        elif choice == "4":
            pcap_diag.ensure_network_capture_dir()
            default_out = pcap_diag.default_capture_out_path()
            print(f"{Colors.OKCYAN}{t('diag_pcap_default_path').format(path=str(default_out))}{Colors.ENDC}")
            try:
                ifc = input(f"{Colors.OKCYAN}{t('diag_pcap_capture_iface')}{Colors.ENDC}").strip()
                outp = input(f"{Colors.OKCYAN}{t('diag_pcap_capture_out')}{Colors.ENDC}").strip()
                secs_raw = input(f"{Colors.OKCYAN}{t('diag_pcap_capture_secs')}{Colors.ENDC}").strip()
                filt = input(f"{Colors.OKCYAN}{t('diag_pcap_capture_filter')}{Colors.ENDC}").strip()
            except (EOFError, KeyboardInterrupt):
                print()
                continue
            if not ifc:
                continue
            try:
                secs = float(secs_raw) if secs_raw else 10.0
            except ValueError:
                secs = 10.0
            if not pcap_diag.validate_capture_interface(ifc):
                print(f"{Colors.FAIL}{pcap_diag.msg(lang, 'pcap_capture_err', err='bad interface name')}{Colors.ENDC}")
                continue
            out_path = pcap_diag.sanitize_out_path(outp) if outp else default_out
            if out_path is None:
                continue
            if filt and not pcap_diag.validate_bpf_relaxed(filt):
                print(f"{Colors.FAIL}{pcap_diag.msg(lang, 'pcap_filter_invalid')}{Colors.ENDC}")
                continue
            bpf = filt or None
            pcap_diag.capture_pcap(ifc, out_path, lang=lang, duration_sec=secs, bpf_filter=bpf)
        elif choice == "5":
            sel = _diagnostics_select_pcap_file()
            if sel is None:
                continue
            if not sel.exists():
                print(f"{Colors.FAIL}{t('diag_file_not_found').format(path=sel)}{Colors.ENDC}")
                continue
            try:
                hx = input(f"{Colors.OKCYAN}Hex dump? (y/n) [n]: {Colors.ENDC}").strip().lower()
            except (EOFError, KeyboardInterrupt):
                print()
                continue
            pcap_diag.show_pcap_file(
                sel,
                lang=lang,
                max_packets=80,
                hex_dump=hx == "y",
            )
        else:
            print(f"{Colors.WARNING}{t('tools_invalid')}{Colors.ENDC}")


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
                    bgp_lookup=cli_bgp_lookup_enabled(args),
                    pdns_lookup=cli_pdns_lookup_enabled(args),
                    egress_check=cli_egress_check_enabled(args),
                )
            ]
        if args.ip_range:
            if getattr(args, "ptr_scan", False):
                run_ptr_range_scan_cli(
                    args.ip_range[0],
                    args.ip_range[1],
                    max_ips=args.max_ips,
                    qps=float(getattr(args, "ptr_qps", 10.0) or 10.0),
                    save=bool(getattr(args, "save", False) or getattr(args, "ptr_save", False)),
                )
                return []
            return check_ip_range(
                args.ip_range[0],
                args.ip_range[1],
                database,
                max_ips=args.max_ips,
                auto_reclass=args.auto_reclass,
                bgp_lookup=cli_bgp_lookup_enabled(args, for_range=True),
                pdns_lookup=cli_pdns_lookup_enabled(args, for_range=True),
                egress_check=cli_egress_check_enabled(args, for_range=True),
            )
        if args.asn:
            return check_asn_operator(
                args.asn,
                database,
                auto_reclass=args.auto_reclass,
                bgp_lookup=cli_bgp_lookup_enabled(args),
                pdns_lookup=cli_pdns_lookup_enabled(args),
                egress_check=cli_egress_check_enabled(args),
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

def _run_check_deps_cli(args) -> None:
    """Delegate to scripts/check_deps.py (same repo, no extra pip package)."""
    script = REPO_ROOT / "scripts" / "check_deps.py"
    cmd: List[str] = [sys.executable, str(script)]
    groups = getattr(args, "check_deps_groups", None) or ["minimal"]
    for g in groups:
        cmd.extend(["--group", g])
    if getattr(args, "check_deps_hints", False):
        cmd.append("--hints")
    raise SystemExit(subprocess.run(cmd, check=False).returncode)


def main():
    global CURRENT_LANGUAGE
    args = parse_cli_args()

    if getattr(args, "check_deps", False):
        _run_check_deps_cli(args)
        return

    if getattr(args, "maintain_db", False):
        load_language_config()
        if CURRENT_LANGUAGE is None:
            CURRENT_LANGUAGE = "en"
        database = load_database()
        ok, reason = perform_database_update(database)
        sys.exit(0 if ok else 1)

    if getattr(args, "validate_db", False):
        load_language_config()
        if CURRENT_LANGUAGE is None:
            CURRENT_LANGUAGE = "en"
        database = load_database()
        report = validate_asn_database(database)
        print_database_maintenance_report(
            {
                "maintenance": database.get("metadata", {}).get("last_maintenance", {}),
                "stats": report.get("stats", {}),
                "issues": report.get("issues", []),
            }
        )
        sys.exit(0 if report.get("ok") else 1)

    # Load saved language
    load_language_config()
    dns_requested = bool(
        getattr(args, "dns", None)
        or getattr(args, "dns_replay", None)
        or getattr(args, "dns_pcap", None)
    )
    owasp_requested = bool(
        getattr(args, "owasp_headers", None)
        or getattr(args, "owasp_tls", None)
        or getattr(args, "owasp_amass", None)
        or getattr(args, "owasp_takeover", False)
        or getattr(args, "owasp_takeover_file", None)
        or getattr(args, "owasp_nettacker", None)
        or getattr(args, "owasp_wstg", False)
        or getattr(args, "owasp_pipeline", False)
    )
    diag_requested = bool(
        args.trace_monitor_host
        or args.speed_test
        or getattr(args, "trace_replay", None)
        or getattr(args, "pcap_show", None)
        or getattr(args, "pcap_capture", None)
    )

    # First-time language: skip interactive prompt for standalone network CLI
    if CURRENT_LANGUAGE is None and not diag_requested and not dns_requested and not owasp_requested:
        select_language_menu()
    elif CURRENT_LANGUAGE is None:
        CURRENT_LANGUAGE = "en"

    print_startup_connection_banner()

    if args.ip_range and getattr(args, "ptr_scan", False) and not (args.ip or args.asn):
        load_language_config()
        if CURRENT_LANGUAGE is None:
            CURRENT_LANGUAGE = "en"
        print_startup_connection_banner()
        run_ptr_range_scan_cli(
            args.ip_range[0],
            args.ip_range[1],
            max_ips=args.max_ips,
            qps=float(getattr(args, "ptr_qps", 10.0) or 10.0),
            save=bool(getattr(args, "save", False) or getattr(args, "ptr_save", False)),
        )
        return

    if args.ip or args.ip_range or args.asn:
        run_cli_mode(args)
        return

    if dns_requested:
        handle_dns_cli(args)
        return

    if owasp_requested:
        lang = CURRENT_LANGUAGE if CURRENT_LANGUAGE in ("en", "ru") else "en"
        owasp_toolkit.handle_owasp_cli(args, lang=lang)
        return

    if diag_requested:
        handle_network_diag_cli(args)
        return

    database = load_database()
    
    # Main interactive loop
    while True:
        print(f"\n{Colors.HEADER}{Colors.BOLD}{'='*60}{Colors.ENDC}")
        print(f"{Colors.BOLD}{t('app_title')}{Colors.ENDC}")
        print(f"{Colors.HEADER}{Colors.BOLD}{'='*60}{Colors.ENDC}\n")

        print_main_menu_lines()

        print()
        print(f"{Colors.BOLD}{t('menu_prompt_hint')}{Colors.ENDC}")
        prompt_text = t("menu_prompt_main")
        sys.stdout.flush()
        try:
            choice = input(f"{Colors.WARNING}{prompt_text}{Colors.ENDC}").strip()
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
                ip_input = prompt_valid_ip_or_cancel()
                if not ip_input:
                    continue
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
                        mode = input(f"{Colors.OKCYAN}{t('ptr_range_prompt_mode')}{Colors.ENDC}").strip() or "1"
                        if mode == "2":
                            qps_raw = input(f"{Colors.OKCYAN}{t('ptr_qps_prompt')}{Colors.ENDC}").strip()
                            qps = 10.0
                            if qps_raw:
                                try:
                                    qps = max(0.5, float(qps_raw))
                                except ValueError:
                                    qps = 10.0
                            session = run_ptr_range_scan_cli(start, end, max_ips=256, qps=qps, save=False)
                            save_ans = input(
                                f"{Colors.WARNING}{t('save_report_offer')}{Colors.ENDC}",
                                end="",
                            ).strip().lower()
                            if save_ans == "y" and session.get("success"):
                                lang = CURRENT_LANGUAGE if CURRENT_LANGUAGE in ("en", "ru") else "en"
                                try:
                                    path = ptr_scan.save_ptr_session(session)
                                    print(f"{Colors.OKGREEN}{ptr_scan.msg(lang, 'save_ok', path=path)}{Colors.ENDC}")
                                except OSError as exc:
                                    print(f"{Colors.FAIL}{ptr_scan.msg(lang, 'save_fail', err=exc)}{Colors.ENDC}")
                        elif mode == "1":
                            start_ip = ipaddress.ip_address(start)
                            end_ip = ipaddress.ip_address(end)
                            current = start_ip
                            count = 0
                            max_ips = 10
                            results = []
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
                        else:
                            print(f"{Colors.WARNING}{t('ptr_range_invalid_mode')}{Colors.ENDC}")
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
                    asn_data = find_asn_entry(database, asn_query)
                    
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
                                network = ipaddress.ip_network(pool, strict=False)
                                result = check_single_ip(
                                    str(network.network_address),
                                    database,
                                    interactive_extras=False,
                                    invoke_unknown_ip_flow=False,
                                )
                                results.append(result)
                            except Exception:
                                pass
                        
                        if results:
                            show_summary(results)
                            offer_save_report(results)
                    else:
                        results = investigate_unknown_asn(asn_input, database, interactive=True)
                        if results:
                            show_summary(results)
                            offer_save_report(results)
            except KeyboardInterrupt:
                continue

        elif choice == "4":
            network_diagnostics_menu()

        elif choice == "5":
            network_diag.print_network_interfaces(CURRENT_LANGUAGE or "en")

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

        elif choice == "8":
            select_language_menu()

        elif choice == "9":
            show_help()

        elif choice == "10":
            lang = CURRENT_LANGUAGE if CURRENT_LANGUAGE in ("en", "ru") else "en"
            dns_diag.run_dns_menu(lang, enrich_ip=_dns_enrich_ip_node)

        elif choice == "11":
            lang = CURRENT_LANGUAGE if CURRENT_LANGUAGE in ("en", "ru") else "en"
            owasp_toolkit.run_owasp_menu(lang)

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
        print("   Режим 1: geo (до 10 IP) · режим 2: PTR-обход (до 256, rate-limit)\n")
        
        print(f"{Colors.OKCYAN}3. Проверить ASN оператора{Colors.ENDC}")
        print("   Введите ASN (например: AS12389 или 12389)")
        print("   Если ASN есть в базе — проверка по пулам; если нет — WHOIS и выборочная геопроверка\n")

        print(f"{Colors.OKCYAN}4. Диагностика сети{Colors.ENDC}")
        print("   Монитор задержки по хопам маршрута и быстрый HTTP speed test;\n")
        print(f"{Colors.OKCYAN}5. Сетевые интерфейсы{Colors.ENDC}")
        print("   Список NIC из ОС: имя, тип (оценка), состояние, MTU, MAC, IPv4/IPv6\n")

        print(f"{Colors.OKCYAN}6. Обновить базу{Colors.ENDC}")
        print("   Обновляет метаданные БД и дату последнего обновления\n")

        print(f"{Colors.OKCYAN}7. Настроить API ключи обогащения{Colors.ENDC}")
        print("   Локальное сохранение ключей MaxMind / IP2Location / VirusTotal\n")

        print(f"{Colors.OKCYAN}8. Выбрать язык{Colors.ENDC}")
        print("   Переключение между English и Русский\n")

        print(f"{Colors.OKCYAN}9. Справка{Colors.ENDC}")
        print("   Этот экран подсказок по пунктам главного меню\n")

        print(f"{Colors.OKCYAN}10. DNS-анализ{Colors.ENDC}")
        print("   Обход DNS-графа, crt.sh, wordlist, HTML-экспорт (нужен dnspython)\n")

        print(f"{Colors.OKCYAN}11. OWASP toolkit{Colors.ENDC}")
        print("   Secure Headers (встроенно), Amass/Nettacker (опц.), WSTG-ссылки; см. docs/OWASP_INTEGRATION.md\n")
        print(f"{Colors.WHITE}CLI:{Colors.ENDC} --speed-test, --trace-monitor HOST,\n")
        print("           --trace-replay FILE [--trace-replay-delay SEC],\n")
        print(
            "           --pcap-show FILE [--pcap-hex],\n",
        )
        print(
            "           --pcap-capture IFACE --pcap-out FILE [--pcap-filter BPF] [--pcap-seconds N]\n",
        )
        print(
            "           --dns DOMAIN [--dns-crtsh] [--dns-wordlist FILE] [--dns-save] [--dns-export out.html]\n",
        )
        print(
            "           --owasp-headers URL | --owasp-tls HOST | --owasp-amass DOMAIN [--owasp-takeover]\n"
            "           | --owasp-takeover-file FILE | --owasp-nettacker HOST\n",
        )
        print(
            "           --owasp-pipeline [--owasp-ip IP] [--owasp-domain DOM] [--owasp-save]\n",
        )
        print(
            "           --check-deps [--check-deps-group dns] [--check-deps-hints]\n",
        )
        print(
            "  Установка: ./scripts/install-deps.sh full  |  .\\scripts\\install-deps.ps1 -Profile full\n",
        )
        print("  SBOM: docs/SBOM.md · sbom.cdx.json\n")
        
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
        print("   Mode 1: geo (up to 10 IPs) · mode 2: PTR sweep (up to 256, rate-limited)\n")
        
        print(f"{Colors.OKCYAN}3. Check ASN operator{Colors.ENDC}")
        print("   Enter ASN (e.g.: AS12389 or 12389)")
        print("   If the ASN is in the DB — checks pools; if not — WHOIS + sampled geo checks\n")

        print(f"{Colors.OKCYAN}4. Network diagnostics{Colors.ENDC}")
        print("   Multi-hop latency monitor (route over time) and HTTP speed test;\n")
        print(f"{Colors.OKCYAN}5. Network interfaces{Colors.ENDC}")
        print("   OS-level NIC list: name, guessed kind, state, MTU, MAC, IPv4/IPv6\n")

        print(f"{Colors.OKCYAN}6. Update database{Colors.ENDC}")
        print("   Refreshes DB metadata and last update timestamp\n")

        print(f"{Colors.OKCYAN}7. Enrichment API keys{Colors.ENDC}")
        print("   Local setup for MaxMind / IP2Location / VirusTotal keys\n")

        print(f"{Colors.OKCYAN}8. Change language{Colors.ENDC}")
        print("   Switch between English and Русский\n")

        print(f"{Colors.OKCYAN}9. Help{Colors.ENDC}")
        print("   This screen — short notes for each main menu item\n")
        print(f"{Colors.WHITE}CLI:{Colors.ENDC} --speed-test, --trace-monitor HOST,\n")
        print("           --trace-replay FILE [--trace-replay-delay SEC],\n")
        print(
            "           --pcap-show FILE [--pcap-hex],\n",
        )
        print(
            "           --pcap-capture IFACE --pcap-out FILE [--pcap-filter BPF] [--pcap-seconds N]\n",
        )
        print(
            "           --dns DOMAIN [--dns-crtsh] [--dns-wordlist FILE] [--dns-save] [--dns-export out.html]\n",
        )
        print(
            "           --owasp-headers URL | --owasp-tls HOST | --owasp-amass DOMAIN [--owasp-takeover]\n"
            "           | --owasp-takeover-file FILE | --owasp-nettacker HOST\n",
        )
        print(
            "           --owasp-pipeline [--owasp-ip IP] [--owasp-domain DOM] [--owasp-save]\n",
        )
        print(
            "           --check-deps [--check-deps-group dns] [--check-deps-hints]\n",
        )
        print(
            "  Install: ./scripts/install-deps.sh full  |  .\\scripts\\install-deps.ps1 -Profile full\n",
        )
        print("  SBOM: docs/SBOM.md · sbom.cdx.json\n")

        print(f"{Colors.OKCYAN}10. DNS analysis{Colors.ENDC}")
        print("   DNS graph crawl, crt.sh, HTML export (pip install dnspython)\n")

        print(f"{Colors.OKCYAN}11. OWASP toolkit{Colors.ENDC}")
        print("   Secure Headers (built-in), optional Amass/Nettacker, WSTG links; see docs/OWASP_INTEGRATION.md\n")
        
        print(f"{Colors.OKGREEN}✓ When mismatch is detected:{Colors.ENDC}")
        print("  - System offers to reclassify ASN")
        print("  - Performs WHOIS lookup")
        print("  - Updates database with actual location")
        print("  - Re-checks the IP\n")

if __name__ == '__main__':
    main()
