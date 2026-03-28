# Threat Feed Aggregator

<p align="center">
  <img src="https://img.shields.io/badge/Version-1.20.0-blue?style=for-the-badge" alt="Version 1.20.0">
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

## License

This project is licensed under the [MIT License](LICENSE).
