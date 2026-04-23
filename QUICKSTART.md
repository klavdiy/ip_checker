# QUICK START GUIDE
# Быстрый старт

## Первая установка

```bash
# 1. Перейти в директорию проекта
cd /Users/klavdiy/Library/Mobile\ Documents/com~apple~CloudDocs/OZON\ /ip_adress_checker

# 2. Запустить установку
chmod +x setup.sh
./setup.sh

# 3. Проверить, что всё работает
./ip_checker.sh -h
```

## Использование

### Вариант 1: Проверка одного IP адреса

```bash
./ip_checker.sh -i 83.1.1.1
```

Результат:
```
IP Address Geolocation Checker
Checking IP: 83.1.1.1
✓ Matches expected location
  ASN: AS12389 (Rostelecom)
  Expected: RU | Actual: RU
  Pool: 83.0.0.0/8
```

### Вариант 2: Проверка диапазона адресов

```bash
# Проверить 10 адресов
./ip_checker.sh -r 83.0.0.1 83.0.0.10

# Проверить с ограничением на 50 адресов
./ip_checker.sh -r 83.0.0.1 83.0.255.255 --max-ips 50
```

### Вариант 3: Проверка ASN оператора

```bash
# С префиксом AS
./ip_checker.sh -a AS12389

# Без префикса AS
./ip_checker.sh -a 12389
```

### Вариант 4: Сохранить результаты

```bash
./ip_checker.sh -i 83.1.1.1 -s
# Результаты сохранены в scan_results.json
```

### 🆕 Вариант 5: Переклассификация ASN при несоответствии

Если обнаружено несоответствие между ожидаемой и фактической локацией:

**Интерактивный режим (с вопросами):**
```bash
./ip_checker.sh -i 210.5.4.241
# Система спросит: "Would you like to reclassify this ASN? (y/n):"
# Ответить "y" для автоматического обновления базы данных
```

**Автоматический режим (без вопросов):**
```bash
./ip_checker.sh -i 210.5.4.241 --auto-reclass
# Система автоматически обновит базу данных с актуальной геолокацией
```

Процесс переклассификации:
1. 🔍 WHOIS lookup - получение данных о ASN
2. ⚙️ Database update - обновление базы с фактической страной
3. 🔄 Re-check - повторная проверка IP
4. ✅ Report - итоговый результат (успешно или данные неверны)

Дополнительно см. [RECLASSIFICATION_FEATURE.md](RECLASSIFICATION_FEATURE.md)

## Примеры проверки разных операторов

```bash
# Ростелеком (Россия)
./ip_checker.sh -a AS12389

# Белтелеком (Беларусь)
./ip_checker.sh -a AS3216

# Телеком Италия
./ip_checker.sh -a AS6679

# TeData (Египет)
./ip_checker.sh -a AS8331
```

## Добавление нового оператора

Редактируйте файл `asn_database.json` и добавьте новый элемент:

```json
{
  "asn": "AS65000",
  "owner": "My ISP",
  "expected_country": "XX",
  "expected_country_name": "My Country",
  "ip_pools": [
    "10.0.0.0/16",
    "10.1.0.0/16"
  ],
  "check_status": "active",
  "last_checked": "2026-04-17",
  "verified": true
}
```

Затем используйте:
```bash
./ip_checker.sh -a AS65000
```

## Расшифровка результатов

### ✓ Matches expected location
IP находится в ожидаемом месте - всё в порядке

### ✗ MISMATCH DETECTED!
IP должен быть в одной стране, но находится в другой - ПРОБЛЕМА

### ⚠ IP not found in any ASN pool
IP не найден в базе данных ASN

## Автоматическая проверка в cron

```bash
# Отредактировать cron
crontab -e

# Добавить строку для ежедневной проверки в 9:00
0 9 * * * cd /path/to/ip_address_checker && ./ip_checker.sh -a AS12389 -s >> /tmp/ip_checker.log 2>&1
```

## Интеграция с другими скриптами

```bash
#!/bin/bash
# Проверить несколько ASN и отправить результаты

for asn in AS12389 AS3216 AS20485; do
  echo "Checking $asn..."
  /path/to/ip_checker.sh -a "$asn" -s
done

# Отправить результаты на сервер
curl -F "file=@scan_results.json" https://your-server.com/upload
```

## Часто задаваемые вопросы

**Q: Почему скрипт медленный?**
A: Каждый IP запрашивается через API с таймаутом 5 сек. Это нормально. За минуту обрабатывается ~45 адресов.

**Q: Могу ли я проверять больше адресов за раз?**
A: Используйте `--max-ips` параметр, но помните про лимит API (45 в минуту).

**Q: Что если нет интернета?**
A: Скрипт не будет работать, т.к. использует API для геолокации IP адресов.

**Q: Могу ли я использовать другой API для геолокации?**
A: Да, отредактируйте функцию `get_ip_geolocation()` в файле `ip_checker.py`.

**Q: Как удалить старые результаты?**
A: `rm scan_results.json` или просто перепишет файл при следующем сканировании с флагом `-s`.

## Дополнительные команды

```bash
# Справка
./ip_checker.sh -h

# Запустить Python скрипт напрямую
python3 ip_checker.py -i 83.1.1.1

# Просмотреть результаты
cat scan_results.json
jq . scan_results.json  # если установлен jq

# Экспортировать в CSV (простой пример)
python3 -c "import json; data=json.load(open('scan_results.json')); 
for r in data['results']: print(f\"{r.get('ip')},{r.get('actual_country')},{len(r.get('mismatches', []))}\")"
```

## Поддержка

Если что-то не работает:

1. Проверьте наличие Python 3: `python3 --version`
2. Проверьте наличие файлов: `ls -la`
3. Проверьте интернет: `ping 1.1.1.1`
4. Запустите setup.sh заново: `./setup.sh`
5. Посмотрите логи: `cat scan_results.json`

## Примеры аргументов CLI

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
