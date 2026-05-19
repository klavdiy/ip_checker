# IP Address Geolocation Checker

Утилита для проверки IP/ASN по геолокации и поддержки локальной ASN-базы.

## Что умеет сейчас

- Проверка одного IP, диапазона IP и ASN.
- При старте выводит публичный egress IP текущей машины в ASCII-рамке.
- Сравнение фактической страны IP с ожидаемой страной из `asn_database.json`.
- При выводе результатов показывает контакт `abuse` (best-effort из WHOIS).
- Если в WHOIS встречается только handle (например `abuse-c`), скрипт делает дополнительный lookup и пытается получить реальный контакт.
- Интерактивная переклассификация ASN при mismatch.
- Policy-разрешение конфликтов `whois` vs `ip-api`:
  - confidence score по источникам;
  - при конфликте источников кейс уходит в карантин (`metadata.quarantine_cases`);
  - спорные кейсы не записываются в БД автоматически.
- Обработка неизвестных IP: WHOIS, определение ASN/провайдера, добавление в базу.
- Live-таймер WHOIS-запроса (`осталось N сек`) с таймаутом 20 секунд.
- Валидация `y/n` в критичных вопросах (повторный запрос при неверном вводе).
- Автопроверка обновления базы:
  - если с `last_updated` прошло более 30 дней -> запрос на обновление;
  - при `n` повторный запрос откладывается на 7 дней.
- Ручное обновление базы из меню (пункт `6`).
- CLI-режим с опциями `--auto-reclass`, `--quiet`, `--max-ips`, `--save`.
- Дополнительные инструменты после проверки IP:
  - `nmap -A -T4` для проверяемого адреса;
  - `traceroute/tracert` до `8.8.8.8` с ограничением хопов/ожидания;
  - `nslookup` для проверяемого адреса.
- Управление long-run задачами: для `nmap` поддержано прерывание и возврат в предыдущее меню.
- Geo-enrichment сравнение источников: Primary (`ip-api`), MaxMind, IP2Location.
- Пункт меню `7` для настройки API ключей enrichment-провайдеров с сохранением в локальный конфиг.
- Двуязычный интерфейс (RU/EN), смена языка из главного меню (пункт **`8`**), цветной вывод, сохранение результатов в JSON.
- Диагностика сети (пункт меню **`4`**), см. ниже отдельно:
  - быстрый speed-test: ICMP к публичному адресу + HTTP загрузка/выгрузка через Cloudflare;
  - монитор задержки по хопам: `traceroute`/`tracert` + периодический `ping` по известным hop-IPv4; в **TTY** таблица обновляется в одном окне (альтернативный экран терминала), без TTY — накопительный лог;
  - клавиши **`p`** — пауза, **`q`** или **Ctrl+C** — остановить; после остановки можно сохранить сессию в JSON (поле **`capture_iface`** по умолчанию берётся с интерфейса маршрута ОС, иначе — выбор из списка) и позже воспроизвести;
  - воспроизведение JSON: после просмотра **r** — повтор, **q** — назад в меню диагностики;
  - сохранённые сессии трассировки — каталог **`trace_sessions/`** (в **`.gitignore`**, по умолчанию не коммитится);
  - PCAP: захват **`tcpdump -w`** в папку **`network capture/`** (в **`.gitignore`**); после захвата автоматически проверяются заголовок (classic / PCAPNG), **SHA-256** и расшифровка полей; просмотр кадров — **`tshark`** или **`tcpdump -r`** (часто нужны права администратора / разрешения захвата на macOS).
- **DNS-анализ** (пункт меню **`10`**, модуль `dns_diag.py`, стиль DNSDumper):
  - BFS по записям **A / AAAA / CNAME / MX / NS / TXT / SOA** от seed-домена;
  - граф узлов (домены, IP) и рёбер (тип записи, `same_ip` для общих адресов);
  - опционально: wordlist поддоменов, пассивные имена **crt.sh**, сравнение резолверов (system / 1.1.1.1 / 8.8.8.8);
  - geo на IP-узлах через **ip-api**; метрики (глубина, shared IP, CNAME-циклы, внешние NS);
  - сессии JSON в **`dns_sessions/`**, интерактивный HTML-граф в **`dns_graph/`** (vis-network, нужен браузер);
  - из PCAP: извлечение имён DNS через **`tshark`** (п. `5` в подменю DNS).
- **OWASP toolkit** (пункт меню **`11`**, модуль `owasp_toolkit.py`):
  - встроенная проверка **Secure Headers** (HTTP, без установки OWASP-кода);
  - опционально **Amass** (пассивный enum) и **Nettacker** (`port_scan`) — внешние CLI, см. [docs/OWASP_THIRD_PARTY.md](docs/OWASP_THIRD_PARTY.md);
  - чеклист **WSTG** — краткие пункты и ссылки (без копирования текста руководства);
  - сценарий **pipeline** и JSON-сессии в **`owasp_sessions/`**;
  - после проверки IP контекст (IP) подставляется в pipeline; в меню инструментов — быстрый Secure Headers.

## Структура проекта

```text
ip_checker/
├── asn_database.json      # ASN база и metadata
├── ip_checker.py          # Основной скрипт
├── network_diag.py       # трасс-монитор, speed-test, сохранение/повтор JSON
├── pcap_diag.py          # проверка и просмотр .pcap, захват через tcpdump
├── dns_diag.py           # DNS-граф, поддомены, экспорт HTML
├── owasp_toolkit.py      # OWASP: headers, Amass/Nettacker bridge, WSTG links
├── requirements-dns.txt  # опционально: dnspython
├── docs/OWASP_THIRD_PARTY.md   # лицензии сторонних OWASP-инструментов
├── docs/OWASP_INTEGRATION.md   # примеры, pipeline, связь с модулями
├── dependencies.manifest.json  # источник правды: все внешние зависимости
├── requirements-dns.txt        # pip: dnspython
├── requirements-optional.txt   # pip: geoip2, IP2Location
├── scripts/check_deps.py       # проверка зависимостей (все ОС)
├── scripts/install-deps.sh     # установка macOS/Linux
├── scripts/install-deps.ps1    # установка Windows
├── tools/generate_sbom.py      # генерация SBOM из манифеста
├── sbom.cdx.json               # SBOM (CycloneDX 1.5)
├── sbom.spdx.json              # SBOM (SPDX 2.3)
├── docs/SBOM.md                # описание SBOM и групп
├── ip_checker.sh          # Обёртка запуска
├── ip_checker.ps1         # Обёртка запуска для Windows PowerShell
├── .gitignore
├── .language_config       # Создается автоматически при первом выборе языка
├── .enrichment_config.json # Создается локально при настройке API ключей
├── .github/workflows/manual-run.yml # ручной запуск проверки через Actions
├── trace_sessions/        # JSON-сессии мониторинга (в .gitignore)
├── dns_sessions/          # JSON-сессии DNS-графа (в .gitignore)
├── dns_graph/             # HTML-графы (в .gitignore)
├── owasp_sessions/        # JSON-сессии OWASP pipeline (в .gitignore)
├── network capture/      # выход tcpdump -w (в .gitignore)
├── scan_results.json      # Создается при -s/--save
└── README.md
```

## Требования и зависимости

Полный перечень — в [`dependencies.manifest.json`](dependencies.manifest.json). SBOM: [`sbom.cdx.json`](sbom.cdx.json), [`docs/SBOM.md`](docs/SBOM.md).

| Группа | Компоненты | Назначение |
|--------|------------|------------|
| **core** | Python 3.10+, `whois`, `ping`, ip-api, RIR WHOIS | IP/ASN |
| **diagnostics** | `traceroute` / `tracert`, `nslookup` | Меню 4, инструменты |
| **scan** | `nmap` | nmap после проверки IP |
| **pcap** | `tcpdump`, `tshark` | PCAP |
| **dns** | `dnspython`, crt.sh, `tshark` | Меню 10 |
| **enrichment** | `geoip2`, `IP2Location` | Меню 7 |
| **owasp** | `amass`, Nettacker (AGPL) | Меню 11 |

### Проверка и установка (macOS / Linux / Windows)

```bash
# Проверить, что установлено
python3 scripts/check_deps.py --group minimal
python3 ip_checker.py --check-deps

# Установить (macOS/Linux)
chmod +x scripts/install-deps.sh
./scripts/install-deps.sh minimal   # базовый набор
./scripts/install-deps.sh full      # brew/apt + pip по максимуму
```

```powershell
# Windows
.\scripts\install-deps.ps1 -Profile minimal
.\scripts\install-deps.ps1 -Profile full
```

```bash
# Pip-зависимости вручную
pip install -r requirements-dns.txt
pip install -r requirements-optional.txt

# SBOM после изменения манифеста
python3 tools/generate_sbom.py
```

## Быстрый старт

```bash
chmod +x ip_checker.sh
./ip_checker.sh
```

Или напрямую:

```bash
python3 ip_checker.py
```

Windows PowerShell:

```powershell
.\ip_checker.ps1
```

## Интерактивное меню

Текущие пункты главного меню (цифра в консоли совпадает с номером строки **`1`…`11`**, **`0`** — выход):

- `1` — Проверить IP
- `2` — Проверить диапазон IP
- `3` — Проверить ASN (если ASN нет в `asn_database.json`: WHOIS aut-num, для RIPE — дополнительно маршруты `-i origin`, выборочная геопроверка IP, опционально добавление в БД)
- `4` — Диагностика сети (speed-test / монитор маршрута / PCAP)
- `5` — Список сетевых интерфейсов
- `6` — Обновить базу
- `7` — Настроить API ключи обогащения
- `8` — Сменить язык
- `9` — Справка
- `10` — DNS-анализ (граф, поддомены, HTML, PCAP→DNS)
- `11` — OWASP toolkit (Secure Headers, Amass, Nettacker, WSTG)
- `0` — Выход

CLI OWASP:

```bash
python3 ip_checker.py --owasp-headers https://example.com
python3 ip_checker.py --owasp-amass example.com --owasp-save
python3 ip_checker.py --owasp-pipeline --owasp-domain example.com --owasp-ip 203.0.113.1 --owasp-save
```

Подробнее: [docs/OWASP_INTEGRATION.md](docs/OWASP_INTEGRATION.md).

CLI DNS (после `pip install dnspython`):

```bash
python3 ip_checker.py --dns example.com --dns-crtsh --dns-save
python3 ip_checker.py --dns-replay dns_sessions/example_*.json
python3 ip_checker.py --dns-replay dns_sessions/example.json --dns-export dns_graph/example.html
python3 ip_checker.py --dns-pcap "network capture/cap.pcap" --dns example.com
```

Внутри **диагностики сети** (главное меню **`4`**) — подменю:

- `1` — Быстрый тест скорости (ping + HTTP через Cloudflare)
- `2` — Монитор задержки по хопам (дашборд в TTY / лог; сохранение JSON после выхода)
- `3` — Воспроизвести сохранённую сессию трассировки (после просмотра: **r** — повтор, **q** — назад в меню диагностики)
- `4` — Захват трафика в `.pcap` через `tcpdump` (интерфейс, файл, длительность, опционально BPF)
- `5` — Показать содержимое PCAP (поля через `tshark` или резерв через `tcpdump -r`; опционально hex)

В меню `7`:
- `1` — MaxMind (`ACCOUNT_ID:LICENSE_KEY`)
- `2` — IP2Location (API key)
- `0` — Назад

## Формат вывода проверки IP

При совпадении и mismatch используется порядок:

1. Страна (ожидаемая/фактическая)
2. ASN
3. Пул
4. Провайдер
5. Abuse-контакт для обращения (если найден в WHOIS)

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

Полное описание флагов: `python3 ip_checker.py -h`.

Геопроверка и база:

- `-i/--ip`, `-r/--range`, `-a/--asn`, `-s/--save`, `--max-ips`, `--auto-reclass`, `--quiet` (режим **`--quiet`** только в связке с **`--auto-reclass`**).

Если указаны только флаги **диагностики** (`--speed-test`, `--trace-monitor`, `--trace-replay`, `--pcap-*`), главное меню и запрос языка при первом запуске **не блокируют**: используется язык по умолчанию **`en`** при отсутствии сохранённого `.language_config`. При указании **`--ip`/`-r`/`-a`** сначала выполняется режим ASN/геопроверки (без смешения в одном прогоне с диагностикой того же процесса — при необходимости запускайте команды дважды).

### Трассировка во времени

| Флаг | Назначение |
|------|------------|
| `--trace-monitor HOST` | Живой лог по хопам; см. управление **`p`** / **`q`** в описании ниже |
| `--trace-interval SEC` | Пауза между циклами зондирования (по умолчанию `3`) |
| `--trace-max-hops N` | Число хопов traceroute |
| `--trace-rediscover N` | Повторный полный traceroute каждые N завершённых циклов; `0` — не пересканировать |

После **`q`** или **Ctrl+C** в интерактивном режиме предлагается сохранить JSON; воспроизведение:

| Флаг | Назначение |
|------|------------|
| `--trace-replay FILE` | Последовательный вывод записанных циклов (как при живой сессии) |
| `--trace-replay-delay SEC` | Пауза между циклами при воспроизведении (по умолчанию `0.25`; `0` — без паузы) |

### Speed-test (ориентировочно)

| Флаг | Назначение |
|------|------------|
| `--speed-test` | Медианный ICMP к `1.1.1.1` и HTTP download/upload через `speed.cloudflare.com` |

### PCAP

| Флаг | Назначение |
|------|------------|
| `--pcap-show FILE` | Список пакетов: предпочтительно **`tshark`**, иначе **`tcpdump -r`** |
| `--pcap-max-packets N` | Ограничение числа кадров при `--pcap-show` (по умолчанию `80`) |
| `--pcap-hex` | К `--pcap-show`: дамп **`tshark -x`** при доступности |
| `--pcap-capture IFACE` | Захват; обязательно задать **`--pcap-out FILE`** |
| `--pcap-out FILE` | Путь сохранения `.pcap` |
| `--pcap-seconds SEC` | Длительность захвата (по умолчанию `10`) |
| `--pcap-filter BPF` | Опциональное BPF-выражение (при пробелах — заключите в кавычки) |

Примеры (геопроверка):

| Пример команды | Пример вывода (фрагмент) | Что получили |
|----------------|--------------------------|--------------|
| `./ip_checker.sh -i 83.1.1.1` | Сводка: страны (ожидаемая/фактическая), ASN, пул, провайдер; при несовпадении — предупреждения и подсказки по abuse | Одна проверка IP: гео (`ip-api`) + сверка с ожиданиями из базы, при необходимости WHOIS |
| `./ip_checker.sh -r 83.0.0.1 83.0.0.20 --max-ips 10` | Несколько строк результата по IP из диапазона (до `--max-ips`), затем общая сводка | Проход по диапазону с ограничением числа адресов |
| `./ip_checker.sh -a AS12389 -s` | Проверка пулов ASN и строка вида `✓ Results saved: scan_results.json` | Проверка ASN и запись отчёта в `scan_results.json` |
| `./ip_checker.sh -i 195.20.1.1 --auto-reclass` | При mismatch — автоматическое применение политики переклассификации без интерактивных `y/n` | Неинтерактивное исправление базы там, где политика это допускает |
| `./ip_checker.sh -i 195.20.1.1 --auto-reclass --quiet -s` | Минимум текста в консоли + подтверждение сохранения файла | То же, но без лишнего вывода (`--quiet` только с `--auto-reclass`) и с `--save` |

Примеры диагностики из CLI:

| Пример команды | Пример вывода (фрагмент) | Что получили |
|----------------|--------------------------|--------------|
| `python3 ip_checker.py --speed-test` | Медиана ICMP к `1.1.1.1`, строки download/upload (Mbps) через Cloudflare | Ориентировочная задержка и HTTP throughput |
| `python3 ip_checker.py --trace-monitor 8.8.8.8 --trace-interval 2.5` | Построчный журнал по хопам и раундам зондирования (управление `p` / `q`) | Живой монитор маршрута |
| `python3 ip_checker.py --trace-replay trace_sessions/trace_8.8.8.8_20260510.json --trace-replay-delay 0` | Те же типы строк, что при живой сессии, без реального traceroute | Воспроизведение сохранённой JSON-сессии |
| `python3 ip_checker.py --pcap-show capture.pcap --pcap-max-packets 120 --pcap-hex` | Список кадров (`tshark` или `tcpdump -r`), при `--pcap-hex` — hex при наличии `tshark` | Текстовый просмотр пакетов в консоли |
| `sudo python3 ip_checker.py --pcap-capture en0 --pcap-out ./out.pcap --pcap-seconds 15 --pcap-filter 'tcp port 443'` | Сообщения о запуске `tcpdump` и пути к файлу `./out.pcap` | Захват трафика на интерфейсе с BPF-фильтром (нужны права) |

PowerShell:

| Пример команды | Пример вывода (фрагмент) | Что получили |
|----------------|--------------------------|--------------|
| `.\ip_checker.ps1 -i 83.1.1.1` | Как у bash-обёртки: сводка по IP, страны, ASN | Проверка одного IP в Windows |
| `.\ip_checker.ps1 -a AS12389 -s` | Сводка по ASN + при `-s` — сохранение `scan_results.json` | Проверка ASN с сохранением отчёта |
| `.\ip_checker.ps1 --speed-test` | ICMP + HTTP throughput, как в Unix-примере | Тот же speed-test из PowerShell |

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

## Устранение неполадок (диагностика и PCAP)

- **Traceroute/ping не находятся** — добавьте пакеты `traceroute` / `tracert` и **`ping`** в PATH; на Linux при отсутствии `tcpdump`/Wireshark PCAP-функции ограничены.
- **`--trace-monitor`: нет ключей `p`/`q`** — требуется TTY stdin; на Unix включается cbreak только для символьного ввода; на Windows допустимы те же ключи через консоль.
- **Захват PCAP пустой или мгновенно завершился** — обычно не хватает прав (**`sudo`** / разрешений macOS для захвата) или неверное имя интерфейса (**`ifconfig`** / **`ip link`**).
- **Файл после захвата «не похож на pcap»** — при остановке захвата используется корректное завершение `tcpdump` (SIGINT); проверка classic PCAP учитывает магические числа libpcap (LE/BE). При сомнениях откройте файл в Wireshark.
- **`tshark` нет в PATH** — установите Wireshark CLI и включите программу в PATH; для простого текста возможен только **`tcpdump -r`**.
- **Cloudflare speed-test вернул 403 на download** — в коде задаётся User-Agent для HTTP; ограничение размера запроса `__down` учтено (~10 MiB). При блокировках со стороны провайдера проверка может отличаться.

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
- **`nmap` не прерывается как ожидается**
  - на macOS/Linux используй `Ctrl+C` или `Ctrl+Z` во время `nmap`
  - на Windows для возврата в меню используй `Ctrl+C`

## Источники данных

- Геолокация: `ip-api.com`
- ASN/route/provider: системный `whois` с реферальными WHOIS-серверами
- Опциональное enrichment-сравнение:
  - MaxMind (Web Service или локальная MMDB)
  - IP2Location (API или локальная BIN)

## SBOM (Software Bill of Materials)

В репозитории ведётся **SBOM** — перечень зависимостей, системных утилит и внешних сервисов для поставки и аудита (не путать с «SDOM»).

| Файл | Формат |
|------|--------|
| `sbom.cdx.json` | [CycloneDX](https://cyclonedx.org/) 1.5 |
| `sbom.spdx.json` | [SPDX](https://spdx.dev/) 2.3 |

Генератор: `tools/generate_sbom.py` (версия приложения в SBOM: **0.1.0**).

**Что входит в SBOM:**

| Категория | Примеры |
|-----------|---------|
| Runtime | Python 3.10+ |
| Опциональные PyPI | `geoip2`, `IP2Location`, `dnspython` (из `requirements-dns.txt`) |
| Системные CLI | `whois`, `ping`, `traceroute`/`tracert`, `nslookup`, `nmap`, `tcpdump`, `tshark` |
| Внешние сервисы | `ip-api.com`, RIR WHOIS, `crt.sh`, `speed.cloudflare.com` |

После изменения зависимостей (`requirements-dns.txt`), добавления внешних API или системных утилит — перегенерируйте SBOM и закоммитьте оба файла:

```bash
python3 tools/generate_sbom.py
git diff -- sbom.cdx.json sbom.spdx.json
```

В CI (job **check**, Python 3.10) шаг **Ensure SBOM files are up to date** падает, если `sbom.*.json` не совпадают с выводом генератора.

## GitHub Actions (ручной запуск)

- Workflow: `Manual Run` (`.github/workflows/manual-run.yml`).
- Запуск: GitHub -> **Actions** -> **Manual Run** -> **Run workflow**.
- Поддерживаемые входы: `ip`, `asn`, `range_start` + `range_end`, `save`, `auto_reclass`, `quiet`, `max_ips`.
- Режим должен быть один: `ip` **или** `asn` **или** `range`.
- При `save=true` файл `scan_results.json` доступен в `Artifacts`.

## Политика рассинхронизации источников

При mismatch используется policy-движок:

- Считается confidence score на основе:
  - расхождения с `expected_country`;
  - согласованности/конфликта между `whois` и `ip-api`;
  - наличия RIR-контекста из WHOIS referral (`RIPE/ARIN/APNIC/LACNIC/AFRINIC`).
- Если `whois` и `ip-api` подтверждают одну страну и score высокий — допускается обновление.
- Если `whois` и `ip-api` расходятся — кейс уходит в `metadata.quarantine_cases`, БД не переписывается.
- Если сигналов недостаточно — сохраняется текущее `expected_country` без изменений.

## Сообщество и правила

- [Code of Conduct](CODE_OF_CONDUCT.md)
- [Contributing](CONTRIBUTING.md)
- [Security policy](.github/SECURITY.md)

## Лицензия

Распространяется по лицензии **MIT** — см. файл [`LICENSE`](LICENSE).
