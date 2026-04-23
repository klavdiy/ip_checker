# IP Address Geolocation Checker

Утилита для проверки IP/ASN по геолокации и поддержки локальной ASN-базы.

## Что умеет сейчас

- Проверка одного IP, диапазона IP и ASN.
- Сравнение фактической страны IP с ожидаемой страной из `asn_database.json`.
- Интерактивная переклассификация ASN при mismatch.
- Обработка неизвестных IP: WHOIS, определение ASN/провайдера, добавление в базу.
- Live-таймер WHOIS-запроса (`осталось N сек`) с таймаутом 20 секунд.
- Валидация `y/n` в критичных вопросах (повторный запрос при неверном вводе).
- Автопроверка обновления базы:
  - если с `last_updated` прошло более 30 дней -> запрос на обновление;
  - при `n` повторный запрос откладывается на 7 дней.
- Ручное обновление базы из меню (пункт `6`).
- CLI-режим с опциями `--auto-reclass`, `--quiet`, `--max-ips`, `--save`.
- Двуязычный интерфейс (RU/EN), цветной вывод, сохранение результатов в JSON.

## Структура проекта

```text
ip_checker/
├── asn_database.json      # ASN база и metadata
├── ip_checker.py          # Основной скрипт
├── ip_checker.sh          # Обёртка запуска
├── scan_results.json      # Результаты (создается при -s/--save)
├── .language_config       # Выбранный язык (создается автоматически)
└── README.md
```

## Требования

- macOS/Linux
- Python 3.10+
- Утилита `whois` в системе (`whois 1.0+`)
- Интернет для `ip-api.com` и WHOIS-серверов

## Быстрый старт

```bash
chmod +x ip_checker.sh
./ip_checker.sh
```

Или напрямую:

```bash
python3 ip_checker.py
```

## Интерактивное меню

Текущие пункты:

- `1` — Проверить IP
- `2` — Проверить диапазон IP
- `3` — Проверить ASN
- `4` — Сменить язык
- `5` — Справка
- `6` — Обновить базу
- `0` — Выход

## Формат вывода проверки IP

При совпадении и mismatch используется порядок:

1. Страна (ожидаемая/фактическая)
2. ASN
3. Пул
4. Провайдер

Пример:

```text
✓ Соответствует ожидаемому местоположению
  Ожидаемая страна:  BY | Фактическая страна:  BY
  ASN:  AS41700
  Пул:  109.0.0.0/8
  Провайдер:  Unitary enterprise A1
```

## Автообновление базы (30/7 логика)

В `metadata` базы поддерживаются поля:

- `last_updated` — дата последнего обновления базы.
- `last_update_check` — дата последней проверки обновления.
- `next_update_prompt_after` — дата, раньше которой не спрашиваем снова.

Поведение:

- Если `last_updated` старше 30 дней, скрипт предлагает обновить базу.
- При ответе `y`:
  - выполняется обновление метаданных;
  - выводится `База обновлена` / `Database updated`.
- При ответе `n`:
  - запрос откладывается на 7 дней;
  - выводится сообщение об отложенном напоминании.
- При ошибке выводится:
  - `Ошибка обновления. Причина: YY`
  - `Database update failed. Reason: YY`

## CLI аргументы

```text
usage: ip_checker.py [-h] [-i IP] [-r START_IP END_IP] [-a ASN] [-s]
                     [--max-ips MAX_IPS] [--auto-reclass] [--quiet]

options:
  -h, --help              show this help message and exit
  -i, --ip IP             Single IP address to check
  -r, --range START_IP END_IP
                          IP range to check (start_ip end_ip)
  -a, --asn ASN           ASN to check (e.g., AS12389 or 12389)
  -s, --save              Save results to scan_results.json
  --max-ips MAX_IPS       Maximum IPs to scan (default: 256)
  --auto-reclass          Auto-confirm reclassification prompts
  --quiet                 Suppress non-essential output (requires --auto-reclass)
```

Примеры:

```bash
./ip_checker.sh -i 83.1.1.1
./ip_checker.sh -r 83.0.0.1 83.0.0.20 --max-ips 10
./ip_checker.sh -a AS12389 -s
./ip_checker.sh -i 195.20.1.1 --auto-reclass
./ip_checker.sh -i 195.20.1.1 --auto-reclass --quiet -s
```

## Что сохраняется в базе автоматически

При добавлении/переклассификации могут обновляться:

- `asn_data[*].expected_country / expected_country_name`
- `asn_data[*].owner`
- `asn_data[*].ip_pools`
- `metadata.last_updated`
- `metadata.total_asns`
- `metadata.total_ip_pools`
- `metadata.last_update_check`
- `metadata.next_update_prompt_after`

## Troubleshooting

- **WHOIS не отрабатывает**
  - проверь `whois` в системе: `whois 8.8.8.8`
  - проверь доступ в интернет и DNS
  - в скрипте есть таймер и явная причина ошибки (`WHOIS error: ...`)
- **`--quiet` не работает как ожидается**
  - `--quiet` применяется только вместе с `--auto-reclass`
- **IP не найден в базе**
  - используй встроенный flow WHOIS-добавления в интерактивном режиме
  - или добавь ASN/пул вручную в `asn_database.json`

## Источники данных

- Геолокация: `ip-api.com`
- ASN/route/provider: системный `whois` с реферальными WHOIS-серверами

## Лицензия

Внутреннее использование, без гарантий.
