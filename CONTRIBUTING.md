# Contributing to FieldNet Kit (FNkit)

Спасибо за интерес к проекту. Ниже — как предложить изменения и на что обратить внимание.

## Окружение

- **Python 3.10+** (см. CI в `.github/workflows/ci.yml`).
- Зависимости описаны в **`dependencies.manifest.json`**; SBOM — **`sbom.cdx.json`** / **`docs/SBOM.md`**.
- Установка: `./scripts/install-deps.sh minimal` (macOS/Linux) или `.\scripts\install-deps.ps1 -Profile minimal` (Windows).
- Pip (опционально): `requirements-dns.txt`, `requirements-optional.txt`.

## Локальный запуск

```bash
python3 scripts/check_deps.py --group minimal
python3 fnkit.py -h
./fnkit.sh               # INSTALL_DEPS=1 ./fnkit.sh — установить deps перед запуском
```

## Проверки перед PR

Выполните те же шаги, что и в CI:

```bash
pip install -r requirements-dns.txt -r requirements-optional.txt
python3 -m compileall -q fnkit.py network_diag.py pcap_diag.py dns_diag.py owasp_toolkit.py
python3 fnkit.py -h
python3 scripts/check_deps.py --group minimal --no-fail
python3 tools/generate_sbom.py
git diff --exit-code -- sbom.cdx.json sbom.spdx.json dependencies.manifest.json
```

При добавлении внешней зависимости обновите **`dependencies.manifest.json`**, при необходимости `requirements-*.txt`, перегенерируйте SBOM и **`scripts/install-deps.*`**.

## Рекомендации по коду

- Соблюдайте стиль существующих файлов (именование, отступы, локализация `TRANSLATIONS` / строк в `network_diag` / `pcap_diag`).
- Изменения по возможности **узко сфокусированы** на задаче; избегайте массового рефакторинга в одном PR без обсуждения.
- Новые CLI-флаги и пункты меню документируйте в **README.md** (полный мануал).
- Не коммитьте секреты, API-ключи и локальные артефакты (см. `.gitignore`).

## Pull Request

1. Опишите **что** меняется и **зачем** (можно коротко, но связными предложениями).
2. Убедитесь, что ветка проходит **GitHub Actions** на вашем fork (или после открытия PR).
3. При изменении пользовательского поведения упомяните это в описании PR.

## Коммиты и авторство

- Указывайте своё имя и email в конфигурации Git (`git config user.name`, `git config user.email`), чтобы история репозитория однозначно отражала автора изменений.
- Не добавляйте в текст коммита посторонние строки-трейлеры (`Co-authored-by:` и т.п.), если это не осознанное совместное авторство — они навсегда остаются в истории и могут появляться в интерфейсе GitHub.

## Вопросы и идеи

Через вкладку **Issues** в репозитории (шаблоны *Bug report* и *Feature request*) или в существующем обсуждении.

Спасибо.
