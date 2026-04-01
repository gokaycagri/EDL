# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Enterprise threat intelligence aggregation platform that collects, normalizes, deduplicates, scores, and generates External Dynamic Lists (EDLs) for Palo Alto Networks, Fortinet, and other security infrastructure. Built with Flask 3.0 + Python 3.13.

## Commands

```bash
# Install dependencies (from repo root)
pip install -r threat-feed-aggregator/requirements.txt

# Run application (development)
cd threat-feed-aggregator
python -m threat_feed_aggregator.app

# Run all tests
cd threat-feed-aggregator
python -m pytest tests/ -v --tb=short --import-mode=importlib

# Run a single test file
python -m pytest tests/test_contract.py -v --import-mode=importlib

# Run ITAI integration contract tests (subset run in CI)
python -m pytest tests/test_contract.py tests/test_sso.py tests/test_manifest_compat.py -v --tb=short --import-mode=importlib

# Lint
ruff check threat_feed_aggregator/

# Format
ruff format threat_feed_aggregator/

# Security scan
bandit -r threat_feed_aggregator/ --skip B608,B301,B403,B404,B603,B605,B607

# Docker build & run
cd threat-feed-aggregator
docker-compose up -d --build

# Docker build — Community edition (ITAI_MODE=false default)
docker build -t edl:latest threat-feed-aggregator/

# Docker build — ITAI edition (ITAI_MODE=true baked in)
docker build --build-arg ITAI_MODE=true -t edl:latest-itai threat-feed-aggregator/

# Production (Gunicorn)
gunicorn --worker-class=gthread --workers=2 --threads=4 --bind 0.0.0.0:8080 --timeout 300 threat_feed_aggregator.app:app
```

System dependencies for CI/dev: `libldap2-dev libsasl2-dev libssl-dev whois libjpeg-dev zlib1g-dev`

## Architecture

All application code lives under `threat-feed-aggregator/threat_feed_aggregator/`.

### Layered Structure

- **`app.py`** — Flask app, Blueprint registration, CSRF setup, ITAI middleware init
- **`routes/`** — Flask Blueprints: `dashboard.py`, `api.py`, `auth.py`, `system.py`, `tools.py`, `analysis.py`
- **`services/`** — Business logic: `analysis_service.py`, `dns_deduplication.py`, `investigation_service.py`, `job_service.py`, `feed_health.py`, `webhook_service.py`
- **`repositories/`** — Data access: `indicator_repo.py`, `user_repo.py`, `whitelist_repo.py`, `custom_list_repo.py`, `job_repo.py`
- **`database/`** — DB abstraction: `connection.py` (pooling, thread-safe locking, `db_transaction` context manager), `schema.py` (table definitions, migrations)
- **`config/`** — `schema.py` (Pydantic models for config validation)
- **`middleware/`** — ITAI Hub SSO integration (`itai.py`)
- **`aggregator.py`** — Aggregation orchestration: `run_aggregator()`, `fetch_and_process_single_feed()`, whitelist cleanup. Re-exports from `edl_generator.py` and `feed_processor.py`
- **`edl_generator.py`** — Atomic EDL file generation with temp-file-then-rename
- **`feed_processor.py`** — `FeedAggregator` class, async source processing, `aggregate_sources_async()`

### Key Patterns

- **Dual DB support**: SQLite (dev, WAL mode) + PostgreSQL (prod), abstracted via connection pooling
- **Transaction ownership**: `db_transaction` context manager is the sole owner of commit/rollback — repositories never call `db.commit()` directly
- **Async aggregation**: `aggregator.py` uses `asyncio`/`aiohttp` for concurrent feed fetching; DB ops run in thread executors via `loop.run_in_executor()`
- **Factory pattern**: `get_parser` in parsers for handling different feed formats
- **Atomic file writes**: EDL files and config.json are written to `.tmp` then `os.replace()`'d to prevent serving partial data
- **APScheduler**: Recurring feed fetches, DNS dedup batching
- **ITAI Hub integration**: Conditional via `ITAI_MODE=true` env var. JWT-based SSO (`/auth/sso`), trace ID propagation
- **CSRF protection**: Enabled globally via Flask-WTF. Machine-to-machine API endpoints (firewall EDL, SOAR, deceptor, SSO) are exempted. All HTML forms and AJAX calls include CSRF tokens.

### Frontend

Jinja2 templates in `templates/`, static assets in `static/`. Uses Bootstrap/Soft UI, jsVectorMap, SweetAlert2, jQuery. All destructive operations use POST forms with CSRF tokens.

### Configuration

- **Runtime config**: `data/config.json` (threat sources, scheduling, proxy, LDAP, `ssl_bypass_hosts`). Access via `config_manager.py` which caches with mtime-based invalidation. Example config at `threat_feed_aggregator/config/config.json.example`.
- **Environment**: `SECRET_KEY` (required for production), `ADMIN_PASSWORD`, `PORT`, `DB_TYPE`, `ITAI_MODE`, `ITAI_JWT_SECRET`, `FLASK_DEBUG`, `SESSION_TIMEOUT_MINUTES` (default 60)
- **Version**: `threat_feed_aggregator/version.py` — auto-bumped by CI based on conventional commit messages (feat → minor, fix → patch, BREAKING CHANGE → major)
- **Container init**: `prestart.py` (called by `entrypoint.sh`) initializes DB schema, sets admin user from `ADMIN_PASSWORD`, generates self-signed SSL certs, and runs any pending migration SQL

## Code Style

- **Ruff** with 120-char line length, target py311+
- **Double quotes**, space indentation
- Lint rules: E, W, F, C, I (isort), B (bugbear), UP (pyupgrade), TID, PERF, N (pep8-naming)
- E501 (line too long) is ignored (handled by formatter)
- Bandit for security scanning (excludes tests/venv)
- No bare `except:` — always use `except Exception:` or a specific type

## Important Conventions

- All state-changing endpoints must be POST (not GET)
- All POST forms must include `{{ csrf_token() }}`
- LDAP filter values must be escaped with `ldap3.utils.conv.escape_filter_chars()`
- IP addresses from user input must be validated with `ipaddress.ip_address()` before external calls
- Never log sensitive data (API keys, TOTP codes, full request headers)
- SSL bypass hosts are configured via `config.json` `ssl_bypass_hosts` list, not hardcoded
- Use `asyncio.get_running_loop()` (not `get_event_loop()`) inside coroutines
- Use `aiohttp.ClientTimeout(total=N)` (not raw integer) for aiohttp timeouts

## ITAI Hub Integration

This application integrates with the ITAI Hub as a module. Integration is conditional — controlled by `ITAI_MODE=true` env var.

### SSO Flow (middleware/itai.py)
1. ITAI Core generates HS256 JWT with `exp`, `preferred_username`, `permissions`
2. Hub iframe sends `POST /auth/sso` with `Authorization: Bearer <jwt>`
3. EDL verifies signature via `hmac.compare_digest()` + checks `exp` claim
4. Creates Flask session with user info and permissions
5. Cookie: `SameSite=None; Secure` (required for iframe embedding)

### Trace ID Propagation
- `X-ITAI-Trace-ID` header extracted in `before_request`, stored in `trace_id_var` (contextvar)
- Injected in `after_request` response header for end-to-end tracing
- Always include trace_id in log metadata when available

### ITAI Adapter Contract
An adapter in the ITAI repo (`modules/external/EDL/adapter.py`) proxies 28 tools to this Flask backend. When adding/modifying API endpoints:
- Update ITAI adapter's `manifest.json` if adding new tools
- Run contract tests to verify compatibility:
  ```bash
  python -m pytest tests/test_contract.py tests/test_sso.py tests/test_manifest_compat.py -v
  ```
- The adapter maps ITAI tool calls to these endpoint patterns:
  - `GET /api/*` — status, stats, history, scheduled jobs
  - `POST /api/*` — aggregation triggers, indicator CRUD, cloud feeds
  - `POST /tools/api/*` — investigation tools (lookup, DNS dedup)
  - `GET /analysis/*` — filtering and analytics

### Environment Variables (ITAI-specific)
| Variable | Default | Description |
|----------|---------|-------------|
| `ITAI_MODE` | `false` | Enable ITAI Hub SSO and trace ID middleware |
| `ITAI_JWT_SECRET` | — | HS256 secret for SSO token validation |

### Key Rules for ITAI Compatibility
- API endpoints must return JSON (not HTML redirects) for machine-to-machine calls
- State-changing operations must be POST (adapter uses GET/POST mapping)
- API key auth endpoints must NOT require CSRF tokens
- Response envelope `{status: "success", data: {...}}` is expected by the adapter's `_unwrap()` helper
- New endpoints should follow existing URL patterns (`/api/` for data, `/tools/api/` for investigation)

**Full endpoint-to-tool mapping:** See [docs/itai-adapter-contract.md](docs/itai-adapter-contract.md)

## Testing

### Test Fixtures (conftest.py)

- **`auth_client`** — pre-authenticated Flask test client with admin permissions
- **`readonly_client`** — test client with read-only user permissions
- **`_isolate_db`** — each test gets an isolated temp SQLite DB; APScheduler is mocked to prevent background job interference
- Tests must use `--import-mode=importlib` (required for project structure compatibility)

### Database Migrations

Schema migrations use inline `ALTER TABLE IF NOT EXISTS` in `database/schema.py` — there is no Alembic/Flyway. New columns are added directly in `schema.py` and applied automatically on startup.

## Branching

- Main branch: `master`
- ITAI integration branch: `feature/itai-integration`
