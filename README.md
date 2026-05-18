# Threat Feed Aggregator

<p align="center">
  <img src="https://img.shields.io/badge/Version-2.3.0-blue?style=for-the-badge" alt="Version 2.3.0">
  <img src="https://img.shields.io/badge/Python-3.13+-green?style=for-the-badge&logo=python" alt="Python 3.13+">
  <img src="https://img.shields.io/badge/Flask-3.0-lightgrey?style=for-the-badge&logo=flask" alt="Flask 3.0">
  <img src="https://img.shields.io/badge/Docker-Ready-cyan?style=for-the-badge&logo=docker" alt="Docker Ready">
</p>

<p align="center">
  <strong>Enterprise Intelligence Engine for External Dynamic Lists (EDL)</strong><br>
  Normalize, aggregate, and score multi-source threat intelligence for Palo Alto Networks, Fortinet, and beyond.
</p>

---

## Overview

**Threat Feed Aggregator** is an enterprise-grade platform designed to simplify the management of threat intelligence feeds. It fetches raw indicators (IPs, CIDRs, Domains, URLs) from disparate sources, standardizes them, calculates risk scores, and generates optimized lists for security infrastructure consumption.

---

## Key Features

### Intelligence Engine
- **DNS Deduplication V2:** Background batch resolution — automatically removes domains pointing to already-blocked IPs.
- **Generic EDL Builder:** Custom lists with selectable types (IP/Domain/URL) and formats (Text/CSV/JSON) via GUI or API.
- **API Mode Feed Fetching:** Consume any paginated REST API (e.g. SGB/USOM) as a threat source — no hardcoded provider logic required. Configurable response path (dot notation), headers, page parameter, and max pages.
- **SGB (Siber Güvenlik Başkanlığı) Integration:** Dedicated `sgb` feed format with automatic pagination, native type tagging, and rich metadata enrichment (description, source, date, criticality) stored in `sgb_metadata` table.
- **Authenticated Feeds:** HTTP Basic Authentication support for premium/restricted sources.
- **CIDR Aggregation:** Merges contiguous IP addresses and overlapping subnets into optimal CIDR blocks.
- **Smart Scoring:** Risk scores (0-100) based on source confidence and indicator overlap across feeds.
- **Auto-Retention:** Granular, per-source aging policies to keep blocklists fresh.
- **Atomic EDL Generation:** Writes to temp files first, renames on success — firewalls never receive empty lists on error.

### Real-Time Dashboard
- **Live Terminal:** Operational logs with smart filtering.
- **Dynamic Stats:** AJAX-driven summary cards and activity history.
- **Visual Distribution:** Interactive world map for threat indicator geolocation.
- **Threat Analysis:** DataTables-powered paginated indicator browser with advanced filtering.

### Enterprise Readiness
- **Multi-Factor Auth (MFA):** TOTP-based 2FA (Google/Microsoft Authenticator).
- **Advanced RBAC:** Role-Based Access Control with custom permission profiles (Read/Write/None per module).
- **LDAP/AD Integration:** Active Directory support with Group-to-Profile mapping.
- **ITAI Hub SSO:** JWT-based single sign-on for iframe integration (conditional via `ITAI_MODE`).
- **CSRF Protection:** All state-changing operations protected by CSRF tokens.
- **Secure Infrastructure:** System-wide proxy, custom Root CAs, SSL certificate management.
- **Multi-Client API:** Per-client API keys for SOAR/SIEM with IP allowlist enforcement.
- **FortiDeceptor Integration:** Automated block/unblock via webhook API.
- **Trend Micro DDEI Integration:** `/api/ddei/submit` endpoint with HTTP Basic Auth for ingesting DDEI-detected threat indicators in bulk or single format.

### Investigation Tools
- **Deep Lookup:** IP investigation with WHOIS, Geo-location (IP-API), and Reverse DNS (THC).
- **Internal Lookup:** Cross-reference indicators against all configured threat sources.

---

## Editions

Two editions are published from the same codebase:

| Edition | Image Tag | Description |
|---------|-----------|-------------|
| **Community** | `ghcr.io/mustafacagricaliskan/edl:latest` | Standalone deployment with local auth, MFA, LDAP/AD |
| **ITAI** | `ghcr.io/mustafacagricaliskan/edl:latest-itai` | ITAI Hub integration with SSO, trace propagation, iframe embedding |

Both editions contain the same code — the difference is the default `ITAI_MODE` environment variable (`false` for Community, `true` for ITAI). You can override this at runtime via `docker-compose.yml` or `-e ITAI_MODE=true/false`.

---

## Quick Start

### 1. Docker — Pre-built Image (Recommended)

```bash
# Community edition (standalone)
docker pull ghcr.io/mustafacagricaliskan/edl:latest
docker run -d -p 8080:8080 -e SECRET_KEY=changeme ghcr.io/mustafacagricaliskan/edl:latest

# ITAI edition (Hub integration)
docker pull ghcr.io/mustafacagricaliskan/edl:latest-itai
docker run -d -p 8080:8080 -e ITAI_JWT_SECRET=shared_secret ghcr.io/mustafacagricaliskan/edl:latest-itai
```

### 2. Docker — Build from Source

```bash
git clone https://github.com/mustafacagricaliskan/EDL.git
cd EDL

# Configure environment
cp .env.example .env
# Edit .env — set SECRET_KEY and ADMIN_PASSWORD

# Start with docker-compose
cd threat-feed-aggregator
docker-compose up -d --build
```

- **Dashboard:** `https://localhost:8080`
- **Health Check:** `http://localhost:8080/health`

> **Important:** Always set a strong `SECRET_KEY` in `.env`. The application will generate a random key if none is set, but sessions will not persist across restarts.

### 2. Local Python Setup

```bash
# System dependencies (Ubuntu/Debian)
sudo apt-get install libldap2-dev libsasl2-dev libssl-dev whois

# Setup environment
python -m venv venv
source venv/bin/activate       # Linux/macOS
# .\venv\Scripts\Activate.ps1  # Windows

# Install dependencies
pip install -r threat-feed-aggregator/requirements.txt

# Configure
cp .env.example .env

# Run (development)
cd threat-feed-aggregator
python -m threat_feed_aggregator.app
```

### 3. Production (Gunicorn)

```bash
gunicorn --worker-class=gthread --workers=2 --threads=4 \
  --bind 0.0.0.0:8080 --timeout 300 \
  threat_feed_aggregator.app:app
```

---

## Environment Variables

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `SECRET_KEY` | Yes | (random) | Flask session signing key. **Must be set for production.** |
| `ADMIN_PASSWORD` | No | - | Initial admin password (first run only) |
| `PORT` | No | 8080 | HTTP listen port |
| `DB_TYPE` | No | sqlite | `sqlite` or `postgres` |
| `DB_HOST`, `DB_PORT`, `DB_NAME`, `DB_USER`, `DB_PASS` | If postgres | - | PostgreSQL connection details |
| `REDIS_HOST`, `REDIS_PORT` | No | - | Redis for distributed sessions |
| `ITAI_MODE` | No | false | Enable ITAI Hub SSO integration |
| `ITAI_JWT_SECRET` | If ITAI | - | JWT secret for SSO token verification |
| `FLASK_DEBUG` | No | 0 | Set to `1` for debug mode (dev only) |

---

## Configuration

The platform is designed to be **Config-via-GUI** first. Navigate to **System Settings** to manage:
- **General:** Timezone, global retention, and threat sources
- **Network:** Centralized proxy, custom DNS, SSL bypass hosts
- **Auth:** LDAP server clusters and AD group mapping
- **Security:** SSL certificates, MFA, API key management, system backups

Runtime configuration is stored in `data/config.json`.

---

## Architecture

```
threat_feed_aggregator/
  app.py              # Flask app, Blueprint registration, CSRF setup
  aggregator.py       # Async feed aggregation engine (aiohttp + asyncio)
  routes/             # Flask Blueprints (dashboard, api, auth, system, tools, analysis)
  services/           # Business logic (DNS dedup, investigation, job tracking)
  repositories/       # Data access layer (indicators, users, whitelist, jobs)
  database/           # DB abstraction (connection pooling, schema migrations)
  middleware/         # ITAI Hub SSO integration
  templates/          # Jinja2 HTML templates
  static/             # CSS, JS, images
```

- **Database:** PostgreSQL (production) or SQLite with WAL mode (development)
- **Sessions:** Redis-backed (if configured) or server-side filesystem
- **Async Core:** `asyncio` + `aiohttp` for concurrent feed fetching
- **Transaction Management:** `db_transaction` context manager handles all commit/rollback — repositories never call `commit()` directly.
- **Scheduling:** APScheduler for recurring feed fetches and DNS deduplication

---

## API Endpoints

### Public (No auth required)
- `GET /health` — Health check
- `GET /api/edl/firewall/<filename>` — EDL file download for firewalls
- `GET /api/edl/custom/<token>` — Custom EDL by token

### API Key Required
- `GET /api/edl/generic` — Generic EDL with type/format/source filters
- `POST /api/indicators` — Add indicator (SOAR integration)
- `DELETE /api/indicators` — Remove indicator
- `POST /api/deceptor/block` — FortiDeceptor auto-block webhook
- `POST /api/deceptor/unblock` — FortiDeceptor auto-unblock webhook

### Session Required (Dashboard)
- `GET /api/run` — Trigger full aggregation
- `GET /api/run_single/<name>` — Trigger single source fetch
- `GET /api/status` — Aggregation status
- `GET /api/backup` — System backup (admin only)

---

## Changelog

### [v2.2.0] - 2026-05-15

#### 🌐 API Mode Feed Fetching
- **New `fetch_type: api` source option:** Any paginated REST API can now be used as a threat source without writing provider-specific code.
- **Dot-notation response path:** Extract nested indicator arrays from complex JSON responses (e.g. `data.items.url`).
- **Configurable pagination:** Set `api_page_param`, `api_page_start`, and `api_max_pages` to fully control page iteration. Stops automatically when a page returns an empty result.
- **Per-source API headers:** Custom HTTP headers (e.g. `Authorization: Bearer <token>`) per source, stored in config.
- **Proxy & SSL-bypass aware:** Inherits global proxy and SSL bypass settings — no extra config needed for corporate environments.
- **UI toggle in Add/Edit Source modal:** "API Mode" section with response path, headers, and pagination controls.

#### 🔗 Trend Micro DDEI Integration
- **`POST /api/ddei/submit` endpoint:** Accepts DDEI webhook payloads and ingests them as threat indicators.
- **HTTP Basic Auth:** Authenticates requests against local EDL user accounts (username + password).
- **Flexible payload formats:** JSON bulk (`{ips:[...], urls:[...]}`), JSON single (`{type, value}`), indicators array (`{indicators:[...]}`), and plain-text (newline/comma delimited).
- **Auto EDL refresh:** Triggers background EDL file regeneration after successful ingestion.
- **Audit log integration:** All DDEI submissions are recorded under the `ddei_api` user.

#### 🐛 Bug Fixes
- **PostgreSQL RETURNING id:** Fixed `INSERT INTO users ... RETURNING id` failure on PostgreSQL — cursor now correctly handles rowcount check before fetching.
- **Scheduler startup:** Fixed `init_scheduler` missing method — uses `scheduler.start()` + `update_scheduled_jobs()` directly.
- **API error response:** Corrected argument order in `api_error()` calls (status code was being passed as message).
- **XSS in testSource:** HTML-escaped feed preview content in SweetAlert2 modal.
- **RBAC coverage:** Added `@permission_required` to 12 write routes that were missing access control.
- **Password change:** `change_password` now validates against the current user's account, not just admin.
- **JS deduplication:** Removed duplicate modal functions from `dashboard.js`; all source management now goes through `source_manager.js`.
- **innerHTML → textContent:** Prevented XSS in LDAP/DNS/proxy status display elements.

#### 🔒 Security
- **CSRF cookie hardening for OpenShift/HTTPS:** Added `SESSION_COOKIE_SECURE`, `SESSION_COOKIE_HTTPONLY`, and `SESSION_COOKIE_SAMESITE=Lax` when running behind an HTTPS ingress (`FORCE_HTTPS` env var). Fixes "CSRF session token is missing" on login behind proxies.

### [v1.26.12] - 2026-04-14

#### 🔐 Authentication & LDAP
- **`has_local_password()`** helper added to `user_repo` — distinguishes true local accounts from LDAP-only users (password_hash = `LDAP_USER`) to prevent local login bypass.
- **`auth_manager`** now falls back to LDAP credential check when a user has no local password, preventing silent login failures for hybrid users.
- **LDAP group mapping error messages** now return a human-readable error when a user's LDAP groups are not mapped to any Admin Profile.
- **System route** (`/system/test_ldap`) uses `_check_ldap_credentials` directly for on-demand LDAP connectivity testing.

#### 📋 Indicator Repository
- Added paginated and filtered indicator fetch methods to `indicator_repo` for improved dashboard performance with large datasets.
- Bulk upsert logic hardened against race conditions in multi-worker Gunicorn environments.

#### 🔄 EDL Generator
- Atomic temp-file-then-rename pattern extended: each regeneration run now uses a UUID-based unique temp filename (`.<run_id>.tmp`) to prevent cross-worker file collisions.
- RFC 1918 private IP guard applied consistently to both feed indicators and API blacklist items during EDL generation.
- Legacy compatibility copies (`palo_alto_edl.txt`, `fortinet_edl.txt`) preserved after regeneration.

#### 🌐 API Routes
- Custom EDL cache invalidation now treats empty files as invalid (force-regeneration on next request).
- EDL cache path uses UUID-based temp files for concurrent-safe atomic writes.
- `active_sources` endpoint returns only sources with actual data in the DB (not just config entries).

#### 💻 Dashboard (UI/JS)
- `dashboard.js` refactored with improved error handling and visual feedback for feed health status.
- Indicator browser updated with smoother filtering and pagination state preservation.
- Template (`index.html`) minor accessibility and layout fixes.

---

## License

This project is licensed under the [MIT License](LICENSE).
