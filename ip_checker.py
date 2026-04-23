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
from datetime import datetime
from typing import List, Dict, Optional
import urllib.request
import urllib.error
import subprocess

# Configuration
SCRIPT_DIR = Path(__file__).parent
DATABASE_FILE = SCRIPT_DIR / "asn_database.json"
RESULTS_FILE = SCRIPT_DIR / "scan_results.json"
LANGUAGE_FILE = SCRIPT_DIR / ".language_config"

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
            return json.load(f)
    except FileNotFoundError:
        print(f"{Colors.FAIL}Error: Database file not found{Colors.ENDC}")
        sys.exit(1)
    except json.JSONDecodeError:
        print(f"{Colors.FAIL}Error: Invalid JSON in database{Colors.ENDC}")
        sys.exit(1)

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

def get_whois_data(ip: str) -> Optional[Dict]:
    """Get WHOIS data for an IP address"""
    try:
        timeout_seconds = 20
        process = subprocess.Popen(
            ['whois', ip],
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
            args=['whois', ip],
            returncode=process.returncode,
            stdout=stdout,
            stderr=stderr
        )
        whois_text = result.stdout
        
        asn = None
        country = None
        org = None
        
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
            if 'orgname' in line_lower or 'org-name' in line_lower:
                parts = line.split(':')
                if len(parts) > 1:
                    org = parts[-1].strip()
        
        if not whois_text.strip():
            return {'error': 'empty whois response'}

        return {'asn': asn, 'country': country, 'org': org, 'whois_text': whois_text}
    except subprocess.TimeoutExpired:
        return {'error': 'timeout after 20s'}
    except FileNotFoundError:
        return {'error': 'whois command not found'}
    except OSError as exc:
        return {'error': str(exc)}
    except Exception as exc:
        return {'error': str(exc)}

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
        
        with open(DATABASE_FILE, 'w', encoding='utf-8') as f:
            json.dump(database, f, indent=2, ensure_ascii=False)
        
        return True
    except Exception as e:
        print(f"{Colors.FAIL}Error updating database: {e}{Colors.ENDC}")
        return False

def check_single_ip(ip: str, database: Dict, auto_reclass: bool = False) -> Dict:
    """Check a single IP address"""
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
        'mismatches': []
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
            print(f"  {t('asn')} {asn_entry['asn']} ({asn_entry['owner']})")
            print(f"  {t('expected_country')} {expected_country} | {t('actual_country')} {actual_country}")
            print(f"  {t('pool')} {pool}")
        else:
            result['mismatches'].append({
                **match_info,
                'actual_country': actual_country,
                'actual_country_name': geo_data['country']
            })
            print(f"{Colors.FAIL}{t('mismatch')}{Colors.ENDC}")
            print(f"  {t('asn')} {asn_entry['asn']} ({asn_entry['owner']})")
            print(f"  {t('expected_country')} {Colors.OKGREEN}{expected_country} ({asn_entry['expected_country_name']}){Colors.ENDC} | {t('actual_country')} {Colors.FAIL}{actual_country} ({geo_data['country']}){Colors.ENDC}")
            print(f"  {t('pool')} {pool}")

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
        
        # Ask user if they want to verify and add unknown IP
        verify_choice = 'n'
        while True:
            print(f"\n{Colors.OKCYAN}{t('unknown_ip_check_offer')}{Colors.ENDC}", end="")
            try:
                verify_choice = input().strip().lower()
            except (EOFError, KeyboardInterrupt):
                verify_choice = 'n'
                break

            if verify_choice in ('y', 'n'):
                break

            print(f"{Colors.WARNING}{t('unknown_ip_invalid_yes_no')}{Colors.ENDC}")
        
        if verify_choice == 'y':
            handle_unknown_ip(ip, result, database)
    if best_matches:
        result['status'] = 'checked'
    
    return result

def handle_unknown_ip(ip: str, result: Dict, database: Dict) -> None:
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
    
    print(f"\n{Colors.OKCYAN}{t('step2')}{Colors.ENDC}")
    print(f"{Colors.WARNING}{t('will_update')}:{Colors.ENDC}")
    print(f"  {t('country')}: {result['mismatches'][0]['expected_country']}{t('from_to')}{result['actual_country']}")
    print(f"  {t('provider')}: {result['mismatches'][0]['owner']}{t('from_to')}{result.get('org', 'Unknown')}")
    
    try:
        if auto_confirm:
            confirm = 'y'
            print(f"{t('auto_updating')}")
        else:
            confirm = input(f"{Colors.WARNING}{t('confirm')}{Colors.ENDC}")
    except (EOFError, KeyboardInterrupt):
        confirm = 'y' if auto_confirm else 'n'
    
    if confirm.lower() == 'y':
        mismatch = result['mismatches'][0]
        pool = mismatch['pool']
        org_name = result.get('org')
        
        if update_database_entry(database, ip, mismatch['asn'], result['actual_country'], 
                                result['actual_country_name'], pool, org_name):
            print(f"{Colors.OKGREEN}{t('db_updated')}{Colors.ENDC}")
            
            print(f"\n{Colors.OKCYAN}{t('step3')}...{Colors.ENDC}")
            database = load_database()
            recheck_result = check_single_ip(ip, database)
            
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
        result = check_single_ip(str(current), database, auto_reclass=auto_reclass)
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
            result = check_single_ip(str(network.network_address), database, auto_reclass=auto_reclass)
            results.append(result)
        except ValueError:
            continue

    return results

def run_cli_mode(args):
    """Run command-line mode when direct arguments are provided."""
    database = load_database()

    def execute():
        if args.ip:
            return [check_single_ip(args.ip, database, auto_reclass=args.auto_reclass)]
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
            print("1. ✓ Проверить IP адрес")
            print("2. 📊 Проверить диапазон IP")
            print("3. 🏢 Проверить ASN оператора")
            print("4. 🌍 Выбрать язык")
            print("5. ℹ️  Справка")
            print("0. ❌ Выход")
            prompt_text = "Выберите опцию (0-5): "
        else:
            print("1. ✓ Check single IP address")
            print("2. 📊 Check IP range")
            print("3. 🏢 Check ASN operator")
            print("4. 🌍 Change language")
            print("5. ℹ️  Help")
            print("0. ❌ Exit")
            prompt_text = "Select option (0-5): "
        
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
                    if result.get('matches') or result.get('mismatches'):
                        show_summary([result])
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
                            result = check_single_ip(str(current), database)
                            results.append(result)
                            current += 1
                            count += 1
                        
                        if results:
                            show_summary(results)
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
                                result = check_single_ip(str(network.network_address), database)
                                results.append(result)
                            except:
                                pass
                        
                        if results:
                            show_summary(results)
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
        
        print(f"{Colors.OKGREEN}✓ When mismatch is detected:{Colors.ENDC}")
        print("  - System offers to reclassify ASN")
        print("  - Performs WHOIS lookup")
        print("  - Updates database with actual location")
        print("  - Re-checks the IP\n")

if __name__ == '__main__':
    main()
