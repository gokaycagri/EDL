<div align="center">

<img src="https://img.shields.io/badge/Version-2.4.12-6366f1?style=for-the-badge&logoColor=white" alt="Version">
<img src="https://img.shields.io/badge/Python-3.13+-3b82f6?style=for-the-badge&logo=python&logoColor=white" alt="Python">
<img src="https://img.shields.io/badge/Flask-3.1-22c55e?style=for-the-badge&logo=flask&logoColor=white" alt="Flask">
<img src="https://img.shields.io/badge/Docker-Ready-0ea5e9?style=for-the-badge&logo=docker&logoColor=white" alt="Docker">
<img src="https://img.shields.io/badge/PostgreSQL-16-336791?style=for-the-badge&logo=postgresql&logoColor=white" alt="PostgreSQL">
<img src="https://img.shields.io/badge/License-MIT-f59e0b?style=for-the-badge" alt="License">

<br/><br/>

# 🛡️ Threat Feed Aggregator

**Enterprise Intelligence Engine for External Dynamic Lists (EDL)**

*Aggregate, normalize, score, and deliver multi-source threat intelligence — ready for Palo Alto Networks, Fortinet, and any HTTP-capable security control.*

[Features](#-key-features) · [Quick Start](#-quick-start) · [Architecture](#-architecture) · [API Reference](#-api-reference) · [Changelog](#-changelog)

</div>

---

## 📋 Overview

**Threat Feed Aggregator** is a production-grade threat intelligence platform built on **Flask 3.1 + Python 3.13**. It collects indicators (IPs, CIDRs, Domains, URLs) from dozens of simultaneous sources — including REST APIs, STIX/TAXII feeds, authenticated premium feeds, and native SGB/USOM integrations — then normalizes, deduplicates, scores, and publishes them as External Dynamic Lists consumable by any modern firewall or security control.

Designed for enterprise environments requiring **auditability**, **granular access control**, and **high availability** under OpenShift/Kubernetes.

---

## ✨ Key Features

### 🔍 Intelligence Engine

| Capability | Description |
|---|---|
| **Async Feed Fetching** | `asyncio` + `aiohttp` — all sources fetched concurrently, never blocking the UI |
| **CIDR Aggregation** | Merges overlapping subnets and contiguous IPs into optimal CIDR blocks |
| **Risk Scoring** | 0–100 confidence score per indicator, weighted by source confidence and overlap |
| **DNS Deduplication v2** | Background batch resolver — domains pointing to already-blocked IPs are automatically pruned |
| **Per-Source Retention** | Configurable aging policies per source — stale indicators expire independently |
| **Atomic EDL Generation** | Write-to-temp-then-rename — firewalls never receive a partial or empty list |
| **Generic EDL Builder** | On-demand lists: choose indicator type (IP/Domain/URL), format (Text/CSV/JSON), and source |
| **API Mode Feeds** | Consume any paginated REST API as a threat source — dot-notation response path, custom headers, configurable pagination |
| **SGB / USOM Integration** | Native tab-separated format with automatic pagination, type tagging, and rich metadata |
| **Authenticated Feeds** | HTTP Basic Auth for premium or restricted feed sources |
| **STIX/TAXII Support** | Industry-standard threat intelligence exchange protocol |
| **Whitelist / Blacklist** | Manual safe-list and block-list with import, export, and FortiDeceptor tagging |
| **Feed Health Monitoring** | Auto-disables sources after 3 consecutive failures; one-click re-enable |

### 🖥️ Real-Time Dashboard

- **Live Log Stream** — Server-Sent Events (SSE) push new log lines without polling
- **Dynamic Stats** — AJAX-driven summary cards: total indicators, active sources, last run time
- **Interactive World Map** — jsVectorMap visualization of indicator geographic distribution
- **Indicator Browser** — DataTables-powered paginated view with type, source, score, and country filters
- **Job History** — Timeline of all past aggregation runs with duration and record counts
- **Scheduled Jobs** — Live countdown to next scheduled fetch per source

### 🔒 Security & Access Control

| Feature | Detail |
|---|---|
| **MFA / TOTP** | Google/Microsoft Authenticator — setup wizard, QR code, replay protection (60s window) |
| **RBAC** | Per-module permissions (Read / Write / None) via Admin Profiles |
| **LDAP / AD** | Multi-server clusters, group-to-profile mapping, hybrid local+LDAP users |
| **ITAI Hub SSO** | JWT-based single sign-on for iframe integration (`ITAI_MODE=true`) |
| **CSRF Protection** | Double-submit cookie pattern on all state-changing routes |
| **Audit Log** | Immutable record of login, config changes, aggregation triggers, user actions |
| **Multi-Client API Keys** | Per-client keys with IP allowlist enforcement for SOAR/SIEM integrations |
| **LDAP Injection Guard** | `base_dn` validated via strict regex before any LDAP bind |
| **Granular List Permissions** | `lists:rw` permission grants Safe/Block List access without full system rights |

### 🔗 Integrations

| Integration | Type | Endpoint |
|---|---|---|
| **FortiDeceptor** | Webhook auto-block/unblock | `POST /api/deceptor/block`, `/api/deceptor/unblock` |
| **Trend Micro DDEI** | Bulk/single indicator ingestion | `POST /api/ddei/submit` |
| **Palo Alto Networks** | EDL firewall pull | `GET /api/edl/firewall/<filename>` |
| **Fortinet** | EDL firewall pull | `GET /api/edl/firewall/<filename>` |
| **SOAR / SIEM** | Indicator add/remove | `POST/DELETE /api/indicators` |
| **Prometheus** | Metrics scraping | `GET /metrics` |

### 🔎 Investigation Tools

- **IP Deep Lookup** — WHOIS, Geo-IP (IP-API), Reverse DNS (THC), and Hosting data
- **Internal Cross-Reference** — Check any indicator against all configured threat sources
- **Google Maps Integration** — One-click geo visualization for any IP

---

## 🚀 Quick Start

### Option 1: Docker Compose (Recommended for Production)

```bash
git clone https://github.com/mustafacagricaliskan/EDL.git
cd EDL

# Configure environment
cp .env.example .env
# Edit .env — set SECRET_KEY and ADMIN_PASSWORD

# Start all services (app + PostgreSQL + Redis)
docker compose up -d --build
```

Access the dashboard at **`https://localhost`**

> **Default credentials:** `admin` / (value of `ADMIN_PASSWORD` in `.env`)

### Option 2: Internal Registry (Offline / Air-Gapped)

```bash
# Pull the pre-built image from internal registry
docker pull quay.mfa.gov.tr/admin/threat-feed-aggregator:2.4.5

# Or use latest
docker pull quay.mfa.gov.tr/admin/threat-feed-aggregator:latest
```

### Option 3: Local Python Development

```bash
# System dependencies (Ubuntu/Debian)
sudo apt-get install libldap2-dev libsasl2-dev libssl-dev whois

# Create virtual environment
python -m venv venv
source venv/bin/activate          # Linux/macOS
# .\venv\Scripts\Activate.ps1     # Windows PowerShell

# Install dependencies
pip install -r threat-feed-aggregator/requirements.txt

# Configure
cp .env.example .env

# Run (development mode)
cd threat-feed-aggregator
python -m threat_feed_aggregator.app
```

---

## ⚙️ Environment Variables

| Variable | Required | Default | Description |
|---|---|---|---|
| `SECRET_KEY` | **Yes** | (random) | Flask session signing key — must be set for production |
| `ADMIN_PASSWORD` | **Yes** | `123456` | Initial admin password — **always set this** |
| `PORT` | No | `8080` | HTTP listen port inside container |
| `DB_TYPE` | No | `sqlite` | `sqlite` or `postgres` |
| `DB_HOST` | If postgres | — | PostgreSQL hostname |
| `DB_PORT` | If postgres | `5432` | PostgreSQL port |
| `DB_NAME` | If postgres | — | Database name |
| `DB_USER` | If postgres | — | Database user |
| `DB_PASS` | If postgres | — | Database password |
| `REDIS_HOST` | No | — | Redis hostname (for distributed sessions) |
| `REDIS_PORT` | No | `6379` | Redis port |
| `ITAI_MODE` | No | `false` | Enable ITAI Hub SSO integration |
| `ITAI_JWT_SECRET` | If ITAI | — | JWT secret for SSO token verification |
| `FLASK_DEBUG` | No | `0` | Set `1` for debug mode (dev only) |
| `FORCE_HTTPS` | No | `0` | Set `1` when running behind an HTTPS ingress |

> ⚠️ **Security:** Never use the default `ADMIN_PASSWORD=123456` in production. The application will start but this is a critical security risk.

---

## 🏗️ Architecture

```
EDL/
├── threat-feed-aggregator/
│   ├── threat_feed_aggregator/
│   │   ├── app.py                # Flask factory, Blueprint registration, CSRF, rate limiting
│   │   ├── aggregator.py         # Async orchestration engine (asyncio + aiohttp)
│   │   ├── feed_processor.py     # Per-source async fetch, parse, and store
│   │   ├── config_manager.py     # Atomic config.json read/write
│   │   ├── auth_manager.py       # Login, TOTP, LDAP, RBAC decorators
│   │   ├── scheduler_manager.py  # APScheduler + SQLAlchemyJobStore
│   │   ├── routes/               # Flask Blueprints
│   │   │   ├── api.py            # EDL serving, aggregation control, indicators CRUD
│   │   │   ├── dashboard.py      # Main dashboard views
│   │   │   ├── auth.py           # Login, logout, MFA flows
│   │   │   ├── system.py         # Settings, users, LDAP, certs, API keys
│   │   │   ├── tools.py          # IP investigation, lookup
│   │   │   └── analysis.py       # Feed analysis views
│   │   ├── services/             # Business logic layer
│   │   │   ├── audit_service.py  # Audit log write/query
│   │   │   ├── feed_health.py    # Source failure tracking, auto-disable
│   │   │   ├── job_service.py    # Job status tracking
│   │   │   └── webhook_service.py
│   │   ├── repositories/         # Data access layer (no business logic)
│   │   │   ├── indicator_repo.py
│   │   │   ├── user_repo.py
│   │   │   └── whitelist_repo.py
│   │   ├── database/
│   │   │   ├── connection.py     # Connection pool, SQLite/PostgreSQL abstraction
│   │   │   └── schema.py         # Schema initialization and migrations
│   │   ├── middleware/
│   │   │   └── itai.py           # ITAI Hub JWT SSO middleware
│   │   ├── parsers.py            # Feed format parsers (Text, JSON, CSV, SGB, TAXII)
│   │   ├── templates/            # Jinja2 HTML templates
│   │   └── static/               # CSS, JS, vendor assets
│   ├── Dockerfile                # Full multi-stage build (internet required)
│   ├── Dockerfile.offline        # Incremental build on top of registry base
│   └── requirements.txt
├── docker-compose.yml            # App + PostgreSQL 16 + Redis 7
├── openshift/                    # OpenShift / Kubernetes manifests
└── helm/                         # Helm chart
```

### Technology Stack

| Layer | Technology |
|---|---|
| **Web Framework** | Flask 3.1 + Gunicorn (4 workers, gthread) |
| **Async I/O** | `asyncio` + `aiohttp` for concurrent feed fetching |
| **Database** | PostgreSQL 16 (production) / SQLite with WAL (development) |
| **Sessions** | Flask-Session (filesystem or Redis-backed) |
| **Scheduling** | APScheduler 3.x + SQLAlchemyJobStore |
| **Auth** | Werkzeug password hashing, `pyotp` TOTP, `python-ldap` |
| **ORM** | Raw SQL with parameterized queries via `db_transaction` context manager |
| **SSL** | Auto-generated self-signed cert via `prestart.py` at startup |

---

## 📡 API Reference

### Public Endpoints (No Authentication)

| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/health` | Health check — returns `{"status": "ok"}` |
| `GET` | `/api/edl/firewall/<filename>` | EDL file download for firewalls (plain text) |
| `GET` | `/api/edl/custom/<token>` | Custom EDL by token |

### API Key Required

| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/api/edl/generic` | Generic EDL with type/format/source filters |
| `POST` | `/api/indicators` | Add indicator (SOAR/automation) |
| `DELETE` | `/api/indicators` | Remove indicator |
| `POST` | `/api/deceptor/block` | FortiDeceptor auto-block webhook |
| `POST` | `/api/deceptor/unblock` | FortiDeceptor auto-unblock webhook |
| `POST` | `/api/ddei/submit` | Trend Micro DDEI bulk/single indicator ingestion |

### Session Required (Dashboard/Admin)

| Method | Endpoint | Description |
|---|---|---|
| `POST` | `/api/run` | Trigger full aggregation (audited) |
| `POST` | `/api/run_single/<name>` | Trigger single source fetch |
| `GET` | `/api/status` | Aggregation status |
| `GET` | `/api/status_detailed` | Per-job detailed status |
| `GET` | `/api/feed_health` | Health status for all sources |
| `GET` | `/api/blacklist` | Paginated blacklist (`?exclude_deceptor=true` / `?only_deceptor=true`) |
| `GET` | `/api/audit` | Audit log (admin only) |
| `GET` | `/api/backup` | System backup download (admin only) |
| `GET` | `/metrics` | Prometheus metrics |

---

## 🚢 Deployment

### Docker Compose (Standard)

```bash
docker compose up -d --build
```

Services started:
- `threat-feed-aggregator` — Application (port 443 → 8080)
- `threat-feed-postgres` — PostgreSQL 16
- `threat-feed-redis` — Redis 7

### OpenShift / Kubernetes

```bash
# Update image path in manifest first
kubectl apply -f openshift/deployment.yaml
```

Or use the Helm chart:

```bash
helm install threat-feed ./helm/ \
  --set image.tag=2.4.5 \
  --set env.SECRET_KEY=your-secret
```

### Production Checklist

- [ ] `SECRET_KEY` set to a strong random value (min 32 chars)
- [ ] `ADMIN_PASSWORD` set (not default `123456`)
- [ ] `DB_TYPE=postgres` with external persistent volume
- [ ] Redis configured for multi-worker session consistency
- [ ] `FORCE_HTTPS=1` if behind a TLS-terminating proxy
- [ ] LDAP integration configured (optional)
- [ ] MFA enabled for admin accounts

---

## 📦 Container Images

| Registry | Tag | Description |
|---|---|---|
| `quay.mfa.gov.tr/admin/threat-feed-aggregator` | `2.4.5` | Specific version |
| `quay.mfa.gov.tr/admin/threat-feed-aggregator` | `latest` | Latest stable |

---

## 📝 Changelog

### [v2.4.12] — 2026-07-16

#### 🧹 Data Lifecycle & TTL Management
- **Nightly Indicator TTL Cleanup**: Added a new background job to automatically delete stale indicators that haven't been seen within their source's configured `retention_days` (or the global `indicator_lifetime_days`). 
- **Immediate Re-generation**: The TTL cleanup job automatically triggers an EDL regeneration if any stale indicators are removed, ensuring firewalls receive the updated, lighter lists immediately.

#### 🛡️ Safe List / Block List UX & Validation
- **Smart Block List Expiry Handling**: When adding a Safe List item, the system warns if the item is already manually blocklisted. It now correctly respects the expiration date (`expires_at`) of manual blocklist entries; if the manual block has expired, it allows the safelisting without warning, treating it as an automated block.
- **Immediate EDL Sync**: Adding or removing items from the Safe List now instantly triggers an EDL regeneration to push the changes.
- **Anchor Navigation**: Adding/removing Safe List items now redirects the user to the `#safelist` anchor instead of the generic dashboard top.

#### 🔔 Notification & UI Improvements
- **Modal Alerts for Critical Messages**: SweetAlert2 flash messages for `warning` and `danger` categories have been upgraded from transient toast notifications to centered modal dialogs that require user acknowledgment (clicking 'OK'). This prevents users from missing critical error messages or warnings.

#### 🔧 Internal
- Version bumped from 2.4.9 to **2.4.12**.

---

### [v2.4.9] — 2026-07-14

#### ⚡ Concurrency & EDL Generation Fixes
- **Concurrent Regeneration Safety**: Added a `_REGEN_PENDING` flag to `edl_generator.py`. If a regeneration request (e.g. adding a blacklist item) arrives while an EDL generation is already running, a follow-up regeneration is automatically queued. This prevents race conditions where DB changes made during regeneration were omitted from the final EDL.
- **Global EDL Deduplication**: Implemented in-memory deduplication (`seen_ip`, `seen_domain`, `seen_url`) during EDL generation to ensure that indicators existing in both feed sources and the manual API blacklist are only written once.
- **Blacklist Type Normalization**: Fixed a bug where `ip/cidr` types from manual blacklist entries were not correctly matched in the generator. They are now mapped to `ip` and correctly appear in the output.

#### 🧭 UX Improvements
- **Blocklist Anchor Redirects**: Adding, updating, or removing blacklist/whitelist items now correctly redirects the user to `system.index#blocklist` instead of the generic dashboard. User context is preserved.

#### 🔧 Internal
- Version bumped from 2.4.7 to **2.4.9**.

---

### [v2.4.7] — 2026-07-03

#### 🎨 Login Page Redesign
- **Complete `login.html` overhaul** (+507 lines): Modern, professional design with animated background, glassmorphism card, and smooth transitions
- **Conditional LDAP section**: Login page dynamically shows/hides the LDAP login button based on server-side configuration — no client-side guessing
- **LDAP config backward compatibility**: Auth module now reads `ldap_enabled` from both `auth.ldap_enabled` and the legacy `ldap.enabled` key, ensuring smooth upgrades

#### 🧭 UX — Source Management Navigation
- **Anchor-based redirects**: Add/update/remove source actions now redirect to `system.index#sources` instead of the page top — user stays on the Sources section after every operation

#### 🔒 Security
- **Improved CSRF error message**: Users now see *"Your session has expired or an invalid request was detected. Please try again."* instead of a generic error — clearer, actionable feedback

#### 🔧 Internal
- Version bumped to **2.4.7**

---

### [v2.4.6] — 2026-07-02

#### 🧹 Blacklist Lifecycle Management
- **`GET /api/cleanup/blacklist/preview`** — Dry-run endpoint: lists all expired `api_blacklist` items without removing them (requires `system:rw`)
- **`POST /api/cleanup/blacklist`** — Manual cleanup trigger: removes all expired items, regenerates EDL files, records full audit log with list of removed IPs
- **`get_expired_blacklist_items()`** — New repository function; exported via `db_manager` for scheduler and API use
- **Auto-cleanup scheduling** — `scheduler_manager.py` updated to run periodic expired-item cleanup

#### 📋 Audit Log Enrichment
- **FortiDeceptor block/unblock** — Audit entries now include blocked IP list, count, expiry type, and `expires_at` timestamp
- **Backup download** — Audit records now log which files were included (`config.json + threat_feed.db + safe_list.txt`)
- **System restore** — Audit records now include filename list and zip size
- **Aggregation start** — Audit entries now include active feed count (`feeds=N`)

#### 🐛 Bug Fixes
- `whitelist_repo.py`: Improved handling of edge cases in expired item queries
- `routes/auth.py`: Minor session handling fixes
- `routes/system.py`: Stability improvements

#### 🔧 Internal
- `db_manager.py`: `get_expired_blacklist_items` and `remove_expired_blacklist_items` added to `__all__`
- Version bumped to **2.4.6**

---

### [v2.4.5] — 2026-07-02

#### 🔒 Security Hardening
- **TOTP replay window narrowed**: `valid_window` reduced from 2→1 (120s → 60s attack window)
- **LDAP injection protection**: `base_dn` validated via strict regex (`^(DC=...)+$`) — malformed values rejected before bind attempt
- **`list_management_required` decorator**: New granular `lists:rw` permission for Safe/Block List management without requiring full `system:rw`
- **Custom EDL token validation**: Regex `^[A-Za-z0-9_-]{1,64}$` rejects malformed tokens at route entry

#### ✨ New Features
- **LDAP Group Mapping update**: `POST /system/ldap/mappings/update` — in-place profile reassignment without delete/recreate
- **Blacklist filter params**: `exclude_deceptor=true` / `only_deceptor=true` query params for FortiDeceptor and DDEI workflows
- **Aggregation audit logging**: Manual aggregation triggers now recorded with username and IP in audit log
- **`clamp_int()` helper**: Bounds-checked integer parsing for query params prevents oversized DB queries

#### 🎨 UI Overhaul
- **Dashboard redesign** (`index.html` +449 lines, `dashboard.js` +177 lines): improved layout, real-time status, new widgets
- **System settings** (`system.html` +36 lines): LDAP mapping edit UI, better form organization
- **Theme polish** (`theme.css` +18 lines): visual consistency improvements

#### 🐛 Bug Fixes
- Safe list removal now uses `request.get_json(silent=True)` — prevents 400 errors on missing `Content-Type` header
- Webhook service reliability improvements — better error recovery
- `db_manager.py` export alignment fixes
- `whitelist_repo.py` and `indicator_repo.py` edge case fixes

#### 🔧 Internal
- `constants.py`: Added `MAX_IMPORT_FILE_BYTES` for file import size enforcement
- `data_collector.py`: Async session handling refactored
- `utils.py`: Added `validate_permissions()` and `clamp_int()` helpers
- `repositories/user_repo.py`: `update_ldap_group_mapping` function added
- Version bumped to **2.4.5**

---

### [v2.4.0] — 2026-06-15

- Audit log with full UI: security-relevant events recorded and browsable
- Event Log page with pagination, username/action/date filtering
- SGB / USOM feed improvements with richer metadata storage
- PostgreSQL migration hardening — non-destructive `ALTER TABLE` pattern
- CSRF token fix for OpenShift HTTPS ingress environments

### [v2.3.0] — 2026-05-20

- SGB (Siber Güvenlik Başkanlığı) integration with native tab-separated format
- HTTPS auto-detection via `X-Forwarded-Proto` header
- PostgreSQL migration stability fixes

### [v2.2.0] — 2026-05-15

- API Mode feed fetching (any paginated REST API as a threat source)
- Trend Micro DDEI integration (`POST /api/ddei/submit`)
- RBAC coverage expanded to 12 additional write routes
- XSS fixes in feed preview and status display elements

### [v2.1.0] — 2026-04-20

- Multi-Factor Authentication (TOTP) with setup wizard and QR code
- Authenticated feed sources (HTTP Basic Auth)
- Gunicorn + server-side sessions for multi-worker deployments
- Generic EDL Builder (`/api/edl/generic`)
- Nested JSON parsing with dot notation

### [v2.0.0] — 2026-03-15

- Complete rewrite: Flask Blueprints, async aggregation, PostgreSQL support
- Role-Based Access Control (RBAC) with Admin Profiles
- LDAP/AD integration with group-to-profile mapping
- FortiDeceptor webhook integration
- IP Investigation tool
- STIX/TAXII feed support
- Rootless Docker (UID 1001) + OpenShift compatibility

---

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feat/my-feature`)
3. Commit your changes with a descriptive message following [Conventional Commits](https://www.conventionalcommits.org/)
4. Run tests: `pytest --import-mode=importlib`
5. Run linter: `ruff check . && ruff format .`
6. Open a Pull Request

---

## 📄 License

This project is licensed under the [MIT License](LICENSE).

---

<div align="center">

Made with ❤️ for enterprise security operations teams

</div>
