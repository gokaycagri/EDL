# 🛡️ Threat Feed Aggregator

<p align="center">
  <img src="https://img.shields.io/badge/Version-1.15.0-blue?style=for-the-badge" alt="Version 1.15.0">
  <img src="https://img.shields.io/badge/Python-3.13+-green?style=for-the-badge&logo=python" alt="Python 3.13+">
  <img src="https://img.shields.io/badge/Flask-3.0-lightgrey?style=for-the-badge&logo=flask" alt="Flask 3.0">
  <img src="https://img.shields.io/badge/Docker-Ready-cyan?style=for-the-badge&logo=docker" alt="Docker Ready">
</p>

<p align="center">
  <strong>The Ultimate Intelligence Engine for External Dynamic Lists (EDL)</strong><br>
  Normalize, aggregate, and score multi-source threat intelligence for Palo Alto Networks, Fortinet, and beyond.
</p>

---

## 📖 Overview

**Threat Feed Aggregator** is an enterprise-grade platform designed to simplify the management of threat intelligence feeds. It fetches raw indicators (IPs, CIDRs, Domains, URLs) from disparate sources, standardizes them, calculates risk scores, and generates optimized lists for security infrastructure consumption.

---

## ✨ Key Features

### 🧠 Intelligence Engine
- **DNS Deduplication V2:** Re-architected for high-performance. Automatically resolves domains in background batches and removes those pointing to already-blocked IPs.
- **Generic EDL Builder:** Generate custom lists on-the-fly with selectable types (IP/Domain) and formats (Text/CSV/JSON) via GUI or API.
- **Authenticated Feeds:** Fetch data from premium sources requiring HTTP Basic Authentication.
- **CIDR Aggregation:** Automatically merges contiguous IP addresses and overlapping subnets into optimal CIDR blocks.
- **Smart Scoring:** Assigns risk scores (0-100) based on source confidence and indicator overlap.
- **Auto-Retention:** Granular, per-source aging policies to keep your blocklists fresh and relevant.

### 📊 Real-Time Dashboard
- **Modern DNS Dedup UI:** Dedicated manager with live operational logs, real-time status, and batch processing controls.
- **Live Terminal:** High-performance operational logs with smart filtering (Hide heartbeats/static assets).
- **Dynamic Stats:** AJAX-driven summary cards and activity history—no refresh required.
- **Visual Distribution:** Interactive world map visualizing the geographical origin of threat indicators.

### 🏢 Enterprise Readiness
- **Background DB Optimization:** Non-blocking asynchronous index creation ensures fast startup even with millions of records.
- **Multi-Factor Auth (MFA):** TOTP-based 2FA (Google/Microsoft Authenticator) for local accounts.
- **Advanced RBAC:** Role-Based Access Control with custom permission profiles (Read/Write/None).
- **LDAP/AD Integration:** Native Active Directory support with Group-to-Profile mapping and internal DNS server configuration.
- **Secure Infrastructure:** Support for System-wide Proxies, custom Root CAs, and high-security SSL configurations.
- **Multi-Client API:** Unique API keys for SOAR/SIEM consumers with Trusted Host (IP) enforcement.

### 🔍 Investigation Tools
- **Deep Lookup:** Integrated IP investigation with WHOIS, Geo-location (IP-API), and Reverse DNS (THC).

---

## 🚀 Quick Start

### 1. Docker Deployment (Recommended)
The fastest way to get up and running is using Docker Compose.

```bash
# Clone the repository
git clone https://github.com/mustafacagricaliskan/EDL.git
cd EDL

# Start the environment
docker-compose up -d --build
```
- **Dashboard:** `https://localhost`
- **Default Credentials:** `admin` / `123456` (Change via .env)

### 2. Local Python Setup
```bash
# Setup Environment
python -m venv venv
source venv/bin/activate  # Linux/macOS
.\venv\Scripts\Activate.ps1 # Windows

# Install Dependencies
pip install -r threat-feed-aggregator/requirements.txt

# Initial Configuration
cp .env.example .env
cp threat-feed-aggregator/data/config.json.example threat-feed-aggregator/threat_feed_aggregator/data/config.json

# Run
python -m threat_feed_aggregator.app
```

---

## ⚙️ Configuration & Security

The platform is designed to be "Config-via-GUI" first. Navigate to **System Settings** to manage:
- **General:** Timezone, global retention, and threat sources.
- **Network:** Centralized Proxy and custom DNS servers.
- **Auth:** LDAP server clusters and AD group mapping.
- **Security:** SSL Certificate management, password complexity, and System Backups.

---

## 🏗 Architecture (Clean Code)

- **Production Server:** **Gunicorn** (WSGI) with 4 workers and automated SSL certificate generation.
- **Session Management:** Redis-backed sessions (if configured) or server-side filesystem sessions.
- **Asynchronous Core:** Uses `asyncio` and `aiohttp` for high-speed concurrent feed fetching.
- **Database:** **PostgreSQL** (Production Recommended) or SQLite with WAL Mode enabled.
- **Optimization:** Background threading for heavy DB maintenance tasks to ensure zero-downtime availability.

---

## 📄 License

This project is licensed under the [MIT License](LICENSE).

---

<p align="center">
  Built with ❤️ for Security Operations Teams.
</p>
