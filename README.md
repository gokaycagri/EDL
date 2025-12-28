# Threat Feed Aggregator

[![Version](https://img.shields.io/badge/version-1.8.0-blue.svg)](CHANGELOG.md)
[![Python](https://img.shields.io/badge/python-3.13+-blue.svg)](https://www.python.org/)
[![Flask](https://img.shields.io/badge/flask-3.0-green.svg)](https://flask.palletsprojects.com/)
[![Docker](https://img.shields.io/badge/docker-ready-cyan.svg)](https://www.docker.com/)

An enterprise-grade, web-based threat intelligence platform built with Flask. Collect, process, and manage threat feeds from various sources, normalize data, and generate optimized External Dynamic Lists (EDL) for security infrastructure like Palo Alto Networks and Fortinet.

---

## 🚀 Key Features (v1.8.0)

*   **Intelligent Processing:**
    *   **CIDR Aggregation:** Merges contiguous IPs and subnets into optimal CIDR blocks.
    *   **Multi-Source Scoring:** Assigns risk scores based on source confidence and overlap bonus.
    *   **Automated Cleanup:** Per-source retention policies to age out old indicators.
*   **Modern Dashboard:**
    *   **Real-time Visibility:** AJAX-powered statistics, live operational logs, and task history.
    *   **Enhanced UX:** Responsive "Soft UI" design with interactive world maps and instant feedback.
    *   **Dynamic Scheduling:** Visual monitoring of upcoming tasks with relative "time until" indicators.
*   **Enterprise Security:**
    *   **Advanced RBAC:** Role-Based Access Control with custom profiles and module-level permissions.
    *   **Multi-Client API:** Per-client API keys with Trusted Host (IP) restrictions.
    *   **LDAP/AD Integration:** Seamless login with Active Directory group-to-profile mapping.
*   **Global Readiness:**
    *   **Service Whitelists:** Native support for Microsoft 365, GitHub, and Azure Service IPs.
    *   **System-wide Proxy:** Centralized HTTP/HTTPS proxy support for all outbound traffic.
    *   **Timezone Support:** Configurable system timezone for all UI timestamps.
*   **Investigation Tools:**
    *   **IP Intelligence:** Integrated WHOIS, Geolocation (IP-API), and Reverse DNS (THC) lookups.

---

## 🛠 Architecture

The project follows modern "Clean Code" principles:
*   **Asynchronous Engine:** Core aggregator uses `asyncio` and `aiohttp` for high-performance concurrent fetching.
*   **Repository Pattern:** Decoupled database logic for Users, Indicators, and Jobs.
*   **Service Layer:** Business logic isolated from web routes for better testability.
*   **Modular Blueprints:** Organized Flask routes for Dashboard, API, Auth, System, and Tools.

---

## 🚦 Getting Started

### 1. Local Development

**Prerequisites:** Python 3.13+

```bash
# Create and activate venv
python -m venv venv
.\venv\Scripts\Activate.ps1 # Windows
source venv/bin/activate    # Linux/macOS

# Install dependencies
pip install -r threat-feed-aggregator/requirements.txt

# Configure Environment
cp .env.example .env
# Edit .env: Set SECRET_KEY and ADMIN_PASSWORD

# Initialize Config
cp threat-feed-aggregator/data/config.json.example threat-feed-aggregator/threat_feed_aggregator/data/config.json

# Run Application
python -m threat_feed_aggregator.app
```
Access at `https://127.0.0.1:443` (Default login: `admin` / `change_me_please`)

### 2. Docker Deployment (Recommended)

Requires **Docker Desktop** or **Docker Engine**.

```bash
# Build and start
docker-compose up -d --build
```

*   **URL:** `https://localhost`
*   **Persistence:** Data is stored in `./threat-feed-aggregator/data` on the host.
*   **Healthcheck:** Integrated container health monitoring.

---

## ⚙️ Configuration

Settings can be managed via the **System Settings** menu in the GUI:

*   **General:** Configure System Timezone and global Indicator Lifetime.
*   **Authentication:** Enable LDAP, add server clusters, and map AD Groups to Admin Profiles.
*   **Network:** Set up a system-wide Proxy and custom DNS servers.
*   **Security:** Perform system backups (ZIP) or upload custom SSL certificates (.pfx).

---

## 🧪 Testing

The project includes a comprehensive suite of **51 unit and integration tests** covering >95% of core functionality.

```bash
# Run all tests
.\venv\Scripts\pytest threat-feed-aggregator/tests/
```

Test modules:
*   `test_aggregation.py`: Data processing and CIDR logic.
*   `test_auth_manager.py`: RBAC and LDAP authentication.
*   `test_missing_coverage.py`: API, System, and Tool endpoints.

---

## 🏗 Deployment (OpenShift / K8s)

The Docker image is built for non-root execution (UID 1001) and is fully compatible with OpenShift's arbitrary UID security policy (via GID 0 permissions).

1.  Build and push to your registry.
2.  Apply manifests in `openshift/deployment.yaml`.
3.  Ensure a Persistent Volume Claim (PVC) is mounted at `/app/threat_feed_aggregator/data`.

---

## 📄 License

This project is licensed under the [MIT License](LICENSE).

---

## ✉️ Contact

For support, feature requests, or security reports, please use the project's issue tracker or contact the maintainer directly.

---
*Built with ❤️ for Security Analysts.*
