# EDL Project Improvements — Design Spec

> **Status:** Approved
> **Date:** 2026-03-15
> **Scope:** 9 improvements across 3 groups (infrastructure, core optimization, observability)

---

## Grup A: Altyapi (Temel)

### A1. defusedxml Dependency

**Goal:** Make defusedxml a required dependency instead of optional fallback.

**Changes:**
- Add `defusedxml>=0.7.1` to `requirements.txt`
- In `routes/system.py` `_parse_import_file()`: replace `try: import defusedxml ... except ImportError` with direct `import defusedxml.ElementTree as ET`

### A2. Test Isolation

**Goal:** Tests run against an isolated temp DB, not the real data directory.

**Files:**
- Create `tests/conftest.py` with fixtures:
  - `test_db` — creates temp SQLite DB via `TEST_DB_NAME` env var, calls `init_db()`, yields path, cleans up
  - `app_client` — Flask test client with `app.config['TESTING'] = True`
  - `auth_client` — test client with pre-seeded admin session
- Add basic route tests in `tests/test_routes.py`:
  - Login page renders (GET 200)
  - Login with wrong password (POST, check flash message)
  - CSRF rejection on POST without token
  - Backup endpoint requires system:rw permission
  - Destructive endpoints reject GET (405)

**Mechanism:** `connection.py` line 25 already reads `TEST_DB_NAME` env var. The fixture sets this before importing the app.

### A3. CI Pipeline Enhancement

**Goal:** Add linting and security scanning to CI.

**Changes to `.github/workflows/ci.yml`:**
- Add step after dependency install: `ruff check threat_feed_aggregator/`
- Add step: `bandit -r threat_feed_aggregator/ -c threat-feed-aggregator/pyproject.toml`
- Add `pip install ruff bandit` to the install step

---

## Grup B: Core Optimization

### B4. SQLite Upsert Unification

**Goal:** Use `INSERT ... ON CONFLICT` for both SQLite and PostgreSQL, eliminating the divergent code paths.

**Rationale:** Python 3.13 ships SQLite 3.43+ which fully supports `ON CONFLICT` syntax.

**Changes in `indicator_repo.py` `upsert_indicators_bulk()`:**
- Remove the `if DB_TYPE == 'postgres': ... else: ...` branch
- Use a single query path:
  ```sql
  INSERT INTO indicators (...) SELECT ... FROM temp_bulk_indicators
  ON CONFLICT (indicator) DO UPDATE SET last_seen = EXCLUDED.last_seen
  ```
- `PostgresCursorWrapper` already converts `?` to `%s` and handles `ON CONFLICT`
- Keep `INSERT OR IGNORE` conversion in `PostgresCursorWrapper` for backward compat with other callers

### B5. Aggregator Split

**Goal:** Break `aggregator.py` (~500 lines) into 3 focused modules.

**New files:**
- `edl_generator.py`: `regenerate_edl_files()`, `_REGEN_LOCK`, temp-file-then-rename logic
- `feed_processor.py`: `FeedAggregator` class, `aggregate_sources_async()`, `aggregate_single_source()`, `test_feed_source()`
- `aggregator.py` stays as orchestration: `run_aggregator()`, `fetch_and_process_single_feed()`, `_cleanup_whitelisted_items_from_db()`, re-exports from the other two modules for backward compatibility

**Import compatibility:** `aggregator.py` re-exports:
```python
from .edl_generator import regenerate_edl_files
from .feed_processor import FeedAggregator, aggregate_single_source, test_feed_source
```
Existing imports from `aggregator` continue to work.

### B6. Feed Health Monitoring

**Goal:** Track consecutive feed failures and auto-disable after 3.

**Data model:** In `config.json`, add `source_health` dict:
```json
{
  "source_health": {
    "FireHOL Level 1": {
      "consecutive_failures": 0,
      "last_error": null,
      "disabled_at": null
    }
  }
}
```

**Logic in `fetch_and_process_single_feed()`:**
- On success: reset `consecutive_failures` to 0
- On failure: increment `consecutive_failures`, store `last_error`
- If `consecutive_failures >= 3`: set `disabled_at` to current ISO timestamp, log WARNING
- Before fetching: skip source if `disabled_at` is set

**UI:** Dashboard source table shows red "Disabled" badge. System Settings has a "Re-enable" button that clears `disabled_at` and resets counter.

---

## Grup C: Observability

### C7. Structured Logging with structlog

**Goal:** JSON-formatted logs in production, colored console in development.

**Changes:**
- Add `structlog>=24.1.0` to `requirements.txt`
- Create `log_config.py` (or modify existing `log_manager.py`):
  - Configure `structlog` with stdlib integration
  - Production (`FLASK_ENV=production`): JSON renderer
  - Development: `ConsoleRenderer` with colors
  - Bind `trace_id` from ITAI middleware context var automatically via a processor
- Replace `logging.basicConfig()` in `app.py` with structlog configuration
- Existing `logger.info("message")` calls continue working via `structlog.stdlib.BoundLogger`

### C8. Webhook Notifications

**Goal:** Notify external systems on key events.

**New file:** `services/webhook_service.py`
```python
class WebhookService:
    def notify(self, event: str, data: dict) -> None
```

**Config:**
```json
{
  "webhooks": [
    {
      "name": "Slack Ops",
      "url": "https://hooks.slack.com/...",
      "events": ["aggregation_complete", "high_risk_indicator", "feed_disabled"]
    }
  ]
}
```

**Events fired from:**
- `run_aggregator()` completion → `aggregation_complete`
- `upsert_indicators_bulk()` when risk_score >= 90 → `high_risk_indicator`
- Feed health auto-disable → `feed_disabled`

**Implementation:** Fire-and-forget via `threading.Thread`. Timeout 5s. Failures logged, never raised.

**Payload format:**
```json
{
  "event": "aggregation_complete",
  "timestamp": "2026-03-15T...",
  "data": {"sources_processed": 5, "total_indicators": 12345}
}
```

### C9. Config Validation with Pydantic

**Goal:** Validate config.json structure on read and write.

**New file:** `config/schema.py`
```python
from pydantic import BaseModel

class SourceConfig(BaseModel):
    name: str
    url: str
    format: str = "text"
    confidence: int = 50
    # ...

class ProxyConfig(BaseModel):
    enabled: bool = False
    server: str = ""
    port: int = 0

class AppConfig(BaseModel):
    source_urls: list[SourceConfig] = []
    indicator_lifetime_days: int = 30
    proxy: ProxyConfig = ProxyConfig()
    webhooks: list = []
    # ...
```

**Integration:**
- `read_config()`: after JSON load, call `AppConfig.model_validate(data)`. On `ValidationError`, log ERROR and return previous cached config (or default).
- `write_config()`: validate before writing. Reject invalid config with error message.
- Add `pydantic>=2.5` to `requirements.txt`

---

## Implementation Order

1. **A1** (defusedxml) — standalone, 2 min
2. **A3** (CI) — standalone, 5 min
3. **A2** (test isolation) — enables safe refactoring
4. **B4** (upsert unification) — simple, reduces code
5. **B5** (aggregator split) — biggest refactor, needs tests first
6. **B6** (feed health) — new feature, independent
7. **C9** (config validation) — needed by C8
8. **C7** (structured logging) — independent
9. **C8** (webhooks) — depends on C9 config schema
