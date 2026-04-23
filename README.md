# IP Address Geolocation Checker

Система для проверки IP адресов и валидации их географического расположения на соответствие ожидаемым значениям.

## 📋 Структура проекта

```
ip_address_checker/
├── asn_database.json      # JSON база данных с ASN, пулами адресов и геолокацией
├── ip_checker.py          # Основной Python скрипт для проверки IP
├── ip_checker.sh          # Shell обёртка для удобного запуска на macOS
├── scan_results.json      # Результаты сканирования (генерируется автоматически)
└── README.md              # Этот файл
```

## 🎯 Возможности

- ✅ Проверка одиночного IP адреса
- ✅ Проверка диапазонов IP адресов
- ✅ Проверка всех IP в пуле определённого ASN
- ✅ Валидация соответствия IP ожидаемой геолокации
- ✅ Обнаружение несоответствий (например, IP должен быть в BY, а находится в RU)
- ✅ **🆕 Интерактивная переклассификация ASN при обнаружении несоответствий**
- ✅ **🆕 WHOIS lookup для верификации ASN данных**
- ✅ **🆕 Автоматическое обновление базы данных с актуальными геолокациями**
- ✅ Сохранение результатов в JSON формате
- ✅ Поддержка цветного вывода в терминале

## 📦 Структура JSON базы данных

### asn_database.json

Каждый элемент содержит:

```json
{
  "asn": "AS12389",                    // Номер ASN
  "owner": "Rostelecom",               // Владелец пула
  "expected_country": "RU",            // Ожидаемый код страны (ISO 3166-1 alpha-2)
  "expected_country_name": "Russia",   // Название страны
  "ip_pools": [                        // Пулы IP адресов в CIDR формате
    "83.0.0.0/8",
    "84.0.0.0/8"
  ],
  "check_status": "active",            // Статус проверки: active/inactive
  "last_checked": "2026-04-17",        // Дата последней проверки
  "verified": true                     // Проверено ли вручную
}
```

## 🚀 Установка и подготовка

### Требования
- macOS 10.12+
- Python 3.7+
- Интернет соединение (для получения геолокации IP)

### Установка

```bash
# Скопировать файлы в нужную директорию (уже сделано)
cd /path/to/ip_address_checker

# Сделать shell скрипт исполняемым
chmod +x ip_checker.sh
chmod +x ip_checker.py

# Проверить наличие Python 3
python3 --version
```

## 💻 Использование

### Вариант 1: Использование shell скрипта (рекомендуется)

```bash
./ip_checker.sh [options]
```

### Вариант 2: Прямой запуск Python скрипта

```bash
python3 ip_checker.py [options]
```

## 📝 Примеры использования

### 1. Проверка одного IP адреса

```bash
# Проверка IP 83.1.1.1
./ip_checker.sh -i 83.1.1.1

# Проверка с сохранением результатов
./ip_checker.sh -i 83.1.1.1 -s
```

**Результат:**
```
IP Address Geolocation Checker
Database: /path/to/asn_database.json

Checking IP: 83.1.1.1
✓ Matches expected location
  ASN: AS12389 (Rostelecom (RosTelecom))
  Expected: RU | Actual: RU
  Pool: 83.0.0.0/8

============================================================
SCAN SUMMARY
============================================================
Total IPs checked: 1
Matches (location correct): 1
Mismatches: 0
```

### 2. Проверка диапазона IP адресов

```bash
# Проверка диапазона 83.0.0.1 - 83.0.0.10
./ip_checker.sh -r 83.0.0.1 83.0.0.10

# Проверка диапазона с максимум 50 адресами
./ip_checker.sh -r 83.0.0.1 83.0.255.255 --max-ips 50

# Проверка и сохранение результатов
./ip_checker.sh -r 83.0.0.1 83.0.0.255 -s
```

### 3. Проверка ASN оператора

```bash
# Проверка ASN с префиксом AS
./ip_checker.sh -a AS12389

# Проверка ASN без префикса
./ip_checker.sh -a 12389

# Проверка с сохранением результатов
./ip_checker.sh -a AS3216 -s
```

**Результат:**
```
Checking ASN: AS12389
Owner: Rostelecom (RosTelecom)
Expected Country: RU (Russia)
IP Pools: 83.0.0.0/8, 84.0.0.0/8, 85.0.0.0/8

Scanning 12 sampled IP(s) from 3 pool(s)...

[1/12] Checking IP: 83.0.0.0
✓ Matches expected location
...
```

### 4. Пример несоответствия геолокации

```bash
./ip_checker.sh -i 195.20.1.1
```

**Результат:**
```
Checking IP: 195.20.1.1
✗ MISMATCH DETECTED!
  ASN: AS3216 (OJSC Beltelecom)
  Expected: BY (Belarus) | Actual: RU (Russia)
  Pool: 195.19.0.0/16
```

## 🔍 Справка по командам

```
usage: ip_checker.py [-h] [-i IP] [-r START_IP END_IP] [-a ASN] [-s] [--max-ips MAX_IPS]

IP Address Geolocation Checker - Verify if IPs are in expected locations

optional arguments:
  -h, --help              show this help message and exit
  -i IP, --ip IP          Single IP address to check
  -r START_IP END_IP,
  --range START_IP END_IP IP range to check (start_ip end_ip)
  -a ASN, --asn ASN       ASN to check (e.g., AS12389 or 12389)
  -s, --save              Save results to file
  --max-ips MAX_IPS       Maximum IPs to scan in range (default: 256)
```

## 📊 Результаты сканирования

При использовании флага `-s` результаты сохраняются в `scan_results.json`:

```json
{
  "timestamp": "2026-04-17T14:30:45.123456",
  "results": [
    {
      "ip": "83.1.1.1",
      "actual_country": "RU",
      "actual_country_name": "Russia",
      "region": "Moscow",
      "city": "Moscow",
      "isp": "Rostelecom",
      "org": "Rostelecom",
      "asn": "AS12389",
      "matches": [
        {
          "asn": "AS12389",
          "owner": "Rostelecom (RosTelecom)",
          "expected_country": "RU",
          "expected_country_name": "Russia",
          "pool": "83.0.0.0/8"
        }
      ],
      "mismatches": [],
      "status": "checked"
    }
  ],
  "mismatches_found": 0
}
```

## 🛠️ Расширение базы данных

Для добавления новых ASN в базу данных отредактируйте `asn_database.json`:

```json
{
  "asn": "AS12345",
  "owner": "Your Company Name",
  "expected_country": "YOUR_CODE",
  "expected_country_name": "Your Country",
  "ip_pools": [
    "192.0.0.0/16",
    "192.1.0.0/16"
  ],
  "check_status": "active",
  "last_checked": "2026-04-17",
  "verified": true
}
```

### Коды стран (ISO 3166-1 alpha-2)

- `RU` - Россия
- `BY` - Беларусь
- `KZ` - Казахстан
- `UA` - Украина
- `IT` - Италия
- `EG` - Египет
- `US` - США
- `DE` - Германия
- [и другие ISO коды](https://en.wikipedia.org/wiki/ISO_3166-1_alpha-2)

## ⚙️ Расширенные опции

### Ограничение количества IP при сканировании диапазона

По умолчанию сканируется максимум 256 IP адресов. Для больших диапазонов:

```bash
# Сканировать только 50 IP из диапазона /16
./ip_checker.sh -r 10.0.0.0 10.0.255.255 --max-ips 50
```

### Автоматическое сохранение результатов

```bash
# Все результаты будут сохранены в scan_results.json
./ip_checker.sh -i 83.1.1.1 -s
```

## 📡 Источник геолокации

Система использует бесплатный API сервис **ip-api.com** для получения информации о геолокации IP адреса:

- ✅ Бесплатный доступ
- ✅ До 45 запросов в минуту (Free tier)
- ✅ Информация о стране, регионе, городе
- ✅ Информация об ISP и организации
- ⚠️ Для массовых проверок может потребоваться платный план

## 🔐 Примечания безопасности

- Скрипт НЕ отправляет персональные данные куда-либо
- Все запросы идут исключительно на ip-api.com для геолокации
- Результаты сохраняются локально в JSON файле
- Используется только публичная информация об IP адресах

## 🐛 Устранение неполадок

### Ошибка: "Python 3 is not installed"

```bash
# Установить Python 3 через Homebrew
brew install python3
```

### Ошибка: "Database file not found"

Убедитесь, что файл `asn_database.json` находится в той же директории, что и скрипт:

```bash
ls -la asn_database.json
```

### Ошибка при сканировании большого диапазона

Ограничьте количество проверяемых IP:

```bash
./ip_checker.sh -r 10.0.0.0 10.0.255.255 --max-ips 100 -s
```

### Медленное сканирование

Это нормально - каждый IP проверяется через API с таймаутом 5 секунд. При 45 запросах в минуту сканирование занимает некоторое время.

## 📚 Примеры использования в скриптах

### Bash скрипт для мониторинга

```bash
#!/bin/bash
# Проверка критичных ASN каждый день

IPS=(
  "AS12389"
  "AS3216"
  "AS20485"
)

for asn in "${IPS[@]}"; do
  echo "Checking $asn..."
  python3 /path/to/ip_checker.py -a "$asn" -s
done

# Отправить результаты
if grep -q '"mismatches": \[\]' scan_results.json; then
  echo "All checks passed"
else
  echo "Found mismatches! Check scan_results.json"
fi
```

## 📖 Документация по API

Скрипт использует встроенные API без зависимостей. Все используемые библиотеки входят в стандартную поставку Python 3:

- `json` - работа с JSON
- `ipaddress` - валидация IP адресов и работа с подсетями
- `urllib` - HTTP запросы для геолокации
- `argparse` - парсинг аргументов командной строки

## 🤝 Расширение функциональности

### Добавление нового источника геолокации

Отредактируйте функцию `get_ip_geolocation()` в `ip_checker.py` для использования другого API.

### Интеграция с другими сервисами

Результаты в формате JSON легко интегрируются:

```bash
# Экспорт результатов в CSV
./ip_checker.sh -i 83.1.1.1 -s && python3 -c "import json; data=json.load(open('scan_results.json')); print(','.join([r.get('ip','') for r in data['results']]))"

# Отправка в другой сервис
curl -X POST -d @scan_results.json https://your-api.com/check
```

## 📞 Поддержка

Для вопросов или предложений по улучшению:

1. Проверьте логи в `scan_results.json`
2. Убедитесь в корректности формата IP адресов
3. Проверьте наличие интернета для API запросов
4. Обновите базу данных ASN если IP не найден

## 📄 Лицензия

Это ПО предоставляется "как есть" для внутреннего использования.

## 🔄 История версий

- **v1.0** (2026-04-17) - Начальная версия с поддержкой:
  - Проверка одного IP
  - Проверка диапазона IP
  - Проверка ASN
  - Сохранение результатов в JSON
  - Цветной вывод в терминал

## 🧪 Примеры аргументов CLI

### `-i` / `--ip` (проверка одного IP)

```bash
./ip_checker.sh -i 83.1.1.1
python3 ip_checker.py --ip 83.1.1.1
```

### `-r` / `--range START_IP END_IP` (проверка диапазона)

```bash
./ip_checker.sh -r 83.0.0.1 83.0.0.10
python3 ip_checker.py --range 83.0.0.1 83.0.0.10
```

### `-a` / `--asn` (проверка ASN)

```bash
./ip_checker.sh -a AS12389
./ip_checker.sh -a 12389
python3 ip_checker.py --asn AS12389
python3 ip_checker.py --asn 12389
```
