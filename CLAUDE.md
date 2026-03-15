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
python -m pytest tests/ -v --tb=short

# Run a single test file
python -m pytest tests/test_contract.py -v

# Run ITAI integration contract tests (subset run in CI)
python -m pytest tests/test_contract.py tests/test_sso.py tests/test_manifest_compat.py -v --tb=short

# Lint
ruff check threat_feed_aggregator/

# Format
ruff format threat_feed_aggregator/

# Docker build & run
cd threat-feed-aggregator
docker-compose up -d --build

# Production (Gunicorn)
gunicorn --worker-class=gthread --workers=2 --threads=4 --bind 0.0.0.0:8080 --timeout 300 threat_feed_aggregator.app:app
```

System dependencies for CI/dev: `libldap2-dev libsasl2-dev libssl-dev whois`

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

- **Runtime config**: `data/config.json` (threat sources, scheduling, proxy, LDAP, `ssl_bypass_hosts`)
- **Environment**: `SECRET_KEY` (required for production), `ADMIN_PASSWORD`, `PORT`, `DB_TYPE`, `ITAI_MODE`, `ITAI_JWT_SECRET`, `FLASK_DEBUG`
- **Version**: `threat_feed_aggregator/version.py`

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

## Branching

- Main branch: `master`
