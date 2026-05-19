# Версии схем и миграции данных

FNkit хранит JSON в `data/` с явными **версиями схем**. Модуль [`schema.py`](../schema.py) отвечает за:

- определение текущих версий;
- цепочку **миграций** при загрузке;
- **слой совместимости** со старыми форматами (`ip_checker_*`, файлы без `schema_version`).

При старте `paths.ensure_data_layout()` переносит legacy-пути и вызывает `schema.run_startup_migrations()`.

## Текущие версии

| Документ | ID схемы / `format` | Файл / каталог |
|----------|---------------------|----------------|
| ASN database | `fnkit.asn_database/2` | `data/asn_database.json` |
| Scan results | `fnkit.scan_results/1` | `data/scan_results.json` |
| Trace session | `fnkit_trace_v1` | `data/sessions/trace/*.json` |
| DNS session | `fnkit_dns_v1` | `data/sessions/dns/*.json` |
| OWASP session | `fnkit_owasp_v1` | `data/sessions/owasp/*.json` |
| PTR session | `fnkit_ptr_v1` | `data/sessions/ptr/*.json` |

### Legacy-алиасы (читаются, при сохранении нормализуются)

| Legacy `format` | Канонический |
|-----------------|--------------|
| `ip_checker_trace_v1` | `fnkit_trace_v1` |
| `ip_checker_dns_v1` | `fnkit_dns_v1` |
| `ip_checker_owasp_v1` | `fnkit_owasp_v1` |

ASN-база без `metadata.schema_version` считается `fnkit.asn_database/1` и при загрузке/старте обновляется до **`/2`**.

## Миграции ASN (`/1` → `/2`)

- поле `metadata.schema_version` = `fnkit.asn_database/2`;
- `metadata.schema_migrated_at` (UTC ISO);
- гарантированы `quarantine_cases[]`, `last_maintenance{}`, список `asn_data[]`.

## API для разработчиков

```python
from schema import DocumentKind, load_json_file, save_json_file, compatibility_view

db = load_json_file("data/asn_database.json", DocumentKind.ASN_DATABASE)
save_json_file("data/asn_database.json", DocumentKind.ASN_DATABASE, db)

view = compatibility_view(session_dict, DocumentKind.TRACE_SESSION)
```

Проверка в CI / вручную:

```bash
python3 scripts/validate_asn_db.py
python3 -c "from schema import run_startup_migrations; print(run_startup_migrations())"
```

## Добавление новой версии

1. Константа `SCHEMA_*_V3` / `FORMAT_*_V2` в `schema.py`.
2. Функция `_migrate_*_v2_to_v3` и запись в цепочку `*_MIGRATIONS`.
3. Обновить `CURRENT_SCHEMA`.
4. Документировать здесь и в [USER_GUIDE.md](USER_GUIDE.md) при изменении полей.
