# IP Address Checker - Project Overview
# Проверитель IP адресов - Обзор проекта

## 📁 Структура проекта

```
ip_address_checker/
│
├── 📋 ДОКУМЕНТАЦИЯ
│   ├── README.md              - Полная документация на русском языке
│   ├── QUICKSTART.md          - Быстрый старт и примеры использования
│   └── INDEX.md               - Этот файл (обзор проекта)
│
├── 🔧 СКРИПТЫ
│   ├── setup.sh               - Скрипт установки и инициализации
│   ├── ip_checker.sh          - Shell обёртка для запуска (macOS)
│   ├── ip_checker.py          - Основной Python скрипт
│   ├── monitor.sh             - Скрипт для автоматического мониторинга
│   └── config.sh              - Конфигурационный файл
│
├── 💾 БАЗА ДАННЫХ
│   ├── asn_database.json      - JSON база данных ASN операторов
│   └── scan_results.json      - Результаты последнего сканирования
│
└── 📂 ЛОГИ (создаётся при запуске monitor.sh)
    └── logs/                  - Директория с логами мониторинга
```

## 🎯 Основные файлы

### 1. asn_database.json
**Назначение:** Хранилище данных об ASN операторов с ожидаемыми геолокациями

**Содержит:**
- Номер ASN (например, AS12389)
- Владельца ASN (например, Rostelecom)
- Ожидаемую страну (код ISO и название)
- Пулы IP адресов (в CIDR формате)
- Статус проверки и дату последней проверки

**Пример:**
```json
{
  "asn": "AS12389",
  "owner": "Rostelecom (RosTelecom)",
  "expected_country": "RU",
  "expected_country_name": "Russia",
  "ip_pools": ["83.0.0.0/8", "84.0.0.0/8", "85.0.0.0/8"],
  "check_status": "active",
  "last_checked": "2026-04-17",
  "verified": true
}
```

### 2. ip_checker.py
**Назначение:** Основной Python скрипт для проверки IP адресов

**Функции:**
- Получение геолокации IP через API (ip-api.com)
- Сравнение с ожидаемой локацией из базы данных
- Обнаружение несоответствий
- Поддержка трёх режимов: одиночный IP, диапазон, ASN

**Параметры:**
```
-i, --ip IP              Проверить одиночный IP адрес
-r, --range START END    Проверить диапазон IP адресов
-a, --asn ASN            Проверить ASN оператора
-s, --save               Сохранить результаты в JSON
--max-ips MAX_IPS        Максимум IP в диапазоне (по умолчанию 256)
```

### 3. ip_checker.sh
**Назначение:** Shell обёртка для удобного запуска на macOS

**Использование:**
```bash
./ip_checker.sh -i 83.1.1.1          # Проверить IP
./ip_checker.sh -r 83.0.0.1 83.0.0.255  # Диапазон
./ip_checker.sh -a AS12389           # ASN оператора
```

### 4. setup.sh
**Назначение:** Скрипт первоначальной установки и проверки

**Проверяет:**
- Наличие Python 3
- Права доступа скриптов
- Наличие базы данных
- Работоспособность системы

**Использование:**
```bash
chmod +x setup.sh
./setup.sh
```

### 5. monitor.sh
**Назначение:** Скрипт для автоматического мониторинга ASN

**Особенности:**
- Проверка нескольких ASN за раз
- Проверка отдельных IP адресов
- Проверка диапазонов IP
- Логирование результатов
- Автоматическое обнаружение проблем

**Использование:**
```bash
chmod +x monitor.sh
./monitor.sh
```

## ⚡ Быстрые команды

### Проверка одного IP
```bash
./ip_checker.sh -i 83.1.1.1
```

### Проверка ASN
```bash
./ip_checker.sh -a AS12389
./ip_checker.sh -a 12389    # без префикса AS
```

### Проверка диапазона
```bash
./ip_checker.sh -r 83.0.0.1 83.0.255.255
./ip_checker.sh -r 83.0.0.1 83.0.255.255 --max-ips 50
```

### Сохранение результатов
```bash
./ip_checker.sh -i 83.1.1.1 -s
./ip_checker.sh -a AS12389 -s
```

### Запуск мониторинга
```bash
./monitor.sh
```

## 📊 Результаты сканирования

Результаты сохраняются в `scan_results.json`:

```json
{
  "timestamp": "2026-04-17T13:09:35.040511",
  "results": [
    {
      "ip": "83.1.1.1",
      "actual_country": "PL",
      "actual_country_name": "Poland",
      "region": "14",
      "city": "Warsaw",
      "isp": "Orange Polska Spolka Akcyjna",
      "asn": "AS5617 Orange Polska Spolka Akcyjna",
      "matches": [],
      "mismatches": [
        {
          "asn": "AS12389",
          "owner": "Rostelecom (RosTelecom)",
          "expected_country": "RU",
          "expected_country_name": "Russia",
          "actual_country": "PL",
          "pool": "83.0.0.0/8"
        }
      ],
      "status": "checked"
    }
  ],
  "mismatches_found": 1
}
```

## 🔍 Интерпретация результатов

### ✓ Matches expected location
IP находится в ожидаемой стране - нормально

### ✗ MISMATCH DETECTED!
IP должен быть в одной стране, но находится в другой - ПРОБЛЕМА

Пример:
```
Expected: RU (Russia) | Actual: PL (Poland)
```

### ⚠ IP not found in any ASN pool
IP не найден в базе данных ASN - может быть не добавлен

## 🛠️ Установка и инициализация

### Первый запуск

```bash
# 1. Перейти в директорию
cd "/Users/klavdiy/Library/Mobile Documents/com~apple~CloudDocs/OZON /ip_adress_checker"

# 2. Запустить установку
chmod +x setup.sh
./setup.sh

# 3. Проверить справку
./ip_checker.sh -h
```

### Для использования в автоматизации

```bash
# Добавить в crontab
crontab -e

# Пример: каждый день в 9:00 проверить AS12389
0 9 * * * cd /path/to/ip_address_checker && ./ip_checker.sh -a AS12389 -s
```

## 🌍 Поддерживаемые страны в базе

- RU (Россия) - AS12389, AS20485
- BY (Беларусь) - AS3216
- IT (Италия) - AS6679
- EG (Египет) - AS8331

## ➕ Расширение базы данных

Для добавления нового ASN отредактируйте `asn_database.json`:

```json
{
  "asn": "AS65000",
  "owner": "My Company",
  "expected_country": "XX",
  "expected_country_name": "My Country",
  "ip_pools": ["10.0.0.0/16"],
  "check_status": "active",
  "last_checked": "2026-04-17",
  "verified": false
}
```

Затем используйте:
```bash
./ip_checker.sh -a AS65000
```

## 📡 API и источники данных

### IP Geolocation API
- **Сервис:** ip-api.com
- **Тип:** REST JSON
- **Лимиты:** 45 запросов/минуту (Free tier)
- **Данные:** Страна, регион, город, ISP, ASN

## 📋 Примечания

1. **Python 3 требуется** - установите через `brew install python3` если нет
2. **Интернет необходимо** - для получения геолокации IP адресов
3. **Цветной вывод** - зависит от терминала (работает в Terminal.app и iTerm2)
4. **Лимит API** - максимум 45 запросов в минуту для Free tier
5. **Таймаут** - каждый запрос ждёт максимум 5 секунд

## 🚀 Типичные рабочие процессы

### Сценарий 1: Разовая проверка IP
```bash
./ip_checker.sh -i 83.1.1.1
```

### Сценарий 2: Проверка пула ASN
```bash
./ip_checker.sh -a AS12389 -s
cat scan_results.json
```

### Сценарий 3: Автоматический ежедневный мониторинг
```bash
# Добавить в crontab
0 9 * * * /path/to/monitor.sh >> /var/log/ip_checker.log 2>&1

# Или запустить вручную
./monitor.sh
```

### Сценарий 4: Интеграция с другими сервисами
```bash
# Отправить результаты на сервер
./ip_checker.sh -a AS12389 -s
curl -F "file=@scan_results.json" https://your-server.com/upload
```

## 📞 Диагностика проблем

### Python не найден
```bash
brew install python3
python3 --version
```

### Скрипты не исполняемы
```bash
chmod +x ip_checker.sh ip_checker.py monitor.sh
```

### Медленное сканирование
Нормально - ограничение API (45 запросов в минуту)

### Нет результатов
Проверьте:
1. Интернет соединение
2. Файл asn_database.json существует
3. IP адрес корректен
4. Файл scan_results.json доступен для записи

## 📚 Дополнительные ресурсы

- [README.md](README.md) - Полная документация
- [QUICKSTART.md](QUICKSTART.md) - Примеры использования
- [asn_database.json](asn_database.json) - База данных
- [ip-api.com](http://ip-api.com/) - Документация API

## ✅ Чек-лист после установки

- [ ] Python 3 установлен
- [ ] setup.sh успешно выполнен
- [ ] Файлы имеют права на исполнение (755)
- [ ] ip_checker.sh -h работает
- [ ] Тест с одним IP выполнен успешно
- [ ] Результаты сохранены в scan_results.json
- [ ] README.md и QUICKSTART.md прочитаны

## 📄 Версионирование

- **v1.0** (2026-04-17) - Первоначальный релиз
  - Проверка одного IP
  - Проверка диапазона IP
  - Проверка ASN
  - Автоматический мониторинг
  - JSON результаты
  - Полная документация на русском

---

**Система полностью готова к использованию!** ✅

Для быстрого старта см. [QUICKSTART.md](QUICKSTART.md)
