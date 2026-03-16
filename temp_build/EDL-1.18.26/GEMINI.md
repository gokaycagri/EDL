# Threat Feed Aggregator Project

## Project Overview

This project is a web-based Threat Feed Aggregator built with Flask. Its purpose is to collect, process, and manage threat intelligence feeds from various sources. It allows users to define threat intelligence sources (URLs), specify their data format, and configure scheduling for automatic updates.

**Key Features & Enhancements:**
*   **Intelligent Processing:**
    *   **CIDR Aggregation:** Optimizes IP lists by merging contiguous IP addresses and smaller subnets into larger CIDR blocks.
    *   **Confidence Scoring:** Assigns a confidence score (0-100) to each source, influencing indicator risk scores.
    *   **Per-Source Aging/Retention:** Configurable retention periods for granular control over indicator lifespan.
*   **Diverse Threat Intelligence Sources:**
    *   **Extended Whitelist Sources:** Microsoft 365, GitHub Service IPs, Azure Public Cloud IPs.
    *   **STIX/TAXII Support:** Integration with industry-standard STIX/TAXII feeds for broader threat intelligence collection.
*   **Output Formatting:** Generates downloadable External Dynamic Lists (EDLs) for Palo Alto Networks and Fortinet.
*   **User Authentication:** Basic login functionality with optional LDAP integration.

## Recent Major Updates (v1.11.0 - Security & Core Enhancements)

### 1. Advanced Authentication & Security
*   **Multi-Factor Authentication (MFA):** Implemented TOTP-based 2FA (compatible with Google/Microsoft Authenticator) for local user accounts. Features a setup wizard, QR code generation, and a secure secondary verification screen.
*   **Authenticated Threat Feeds:** Added support for HTTP Basic Authentication (Username/Password) when fetching data from premium or restricted threat feed sources.
*   **Production-Ready SSL & WSGI:** Switched the Docker entrypoint to use **Gunicorn** with 4 workers for high concurrency. Added a `prestart.py` script to automatically generate self-signed SSL certificates and initialize the database before the server starts.

### 2. Generic EDL & Data Flexibility
*   **Generic EDL Builder:** Introduced a new API endpoint (`/api/edl/generic`) and a dashboard GUI tool. This allows users to generate custom External Dynamic Lists by selecting specific indicator types (IP, Domain, URL) and output formats (Text, CSV, JSON) on the fly.
*   **Nested JSON Parsing:** Enhanced the JSON parser to support dot notation (e.g., `data.attributes.ip_address`), enabling the extraction of indicators from complex, nested JSON structures.

### 3. Architecture & Reliability
*   **Server-Side Sessions:** Migrated session management to `Flask-Session` (filesystem-based). This solves session persistence issues in multi-worker Gunicorn environments, ensuring users stay logged in while navigating between different worker processes.
*   **Unified Source Management:** Refactored the frontend logic (`source_manager.js`) to provide a consistent "Add/Edit Source" experience across both the Dashboard and System Settings pages, eliminating code duplication.

## Recent Major Updates (v1.5 - Enterprise Security Features)

### 1. Advanced API Management (Multi-Client & IP Restriction)
*   **Per-Client API Keys:** Replaced the single global API key with a robust client management system. Administrators can now generate unique API keys for different consumers (e.g., SOAR, SIEM, Monitor).
*   **Trusted Host Enforcement:** Each API client can be restricted to specific source IP addresses. This provides an additional layer of security, ensuring that valid keys cannot be misused from unauthorized networks.
*   **Key Rotation:** Added one-click key regeneration for individual clients, allowing for seamless key rotation without affecting other integrations.

### 2. Enhanced Authentication & Networking
*   **LDAP Group Authorization:** Extended LDAP integration to support "Admin Group DN". Login can now be restricted to members of a specific Active Directory/LDAP group.
*   **System-Wide Proxy:** Implemented a centralized Proxy configuration (Server, Port, Auth) in System Settings. All outbound connections (Feed fetching, Microsoft/Azure/GitHub services, Investigation tools) now automatically route through the configured proxy.
*   **SSL Certificate Feedback:** Improved the UI feedback loop when uploading custom SSL certificates (.pfx), reminding users to restart the container.

### 3. Data Integrity & Deduplication
*   **Stricter Normalization:** Updated data parsers to strictly normalize incoming data before database insertion. Domains are lowercased, and IPs/CIDRs are standardized. This ensures the database's unique constraints work effectively, preventing duplicate entries across multiple feed sources.

## Recent Major Updates (v1.4 - IP Investigation Tool)

### 1. New Investigation Capabilities
*   **IP Investigation Tool:** A new dedicated dashboard page (`/tools/investigate`) allows analysts to manually query IP addresses.
*   **Reverse DNS & Hosting Data:** Integrated with **ip.thc.org** API to retrieve and display domains hosted on a specific IP address, providing crucial context for threat analysis.
*   **Contextual Map Links:** Direct links to Google Maps for IP geolocation visualization.

## Recent Major Updates (v1.3 - Refactoring & Architecture)

### 1. Modernized Architecture (AsyncIO & Modularization)
*   **Asynchronous Processing:** The core aggregation engine (`aggregator.py`) has been rewritten using `asyncio` and `aiohttp`. This allows for concurrent fetching of threat feeds, significantly improving performance when dealing with multiple sources. Database operations are handled in a non-blocking manner using thread executors.
*   **Flask Blueprints:** The monolithic `app.py` has been refactored into a modular Blueprint structure. Routes are now organized in `routes/` directory (`dashboard.py`, `api.py`, `auth.py`, `system.py`), making the codebase cleaner and easier to maintain.
*   **Dependency Injection:** The `db_manager.py` module now supports dependency injection via a context manager, enabling better testability and transaction management.
*   **Factory Pattern:** A `get_parser` factory has been implemented in `parsers.py` to standardize how different feed formats (Text, JSON, CSV, TAXII) are handled.

### 2. Enhanced User Interface (Soft UI & Modern Design)
*   **Soft UI Theme:** Clean, modern light "Soft UI" design.
*   **Live Logs:** Improved visibility of live application logs with a high-contrast terminal-like window in the dashboard.
*   **Responsive Design:** Improved responsiveness for better display on various screen sizes.
*   **SweetAlert2 Integration:** Modern pop-ups for alerts and confirmations.
*   **Interactive World Map:** `jsVectorMap` for visualizing threat origins.

### 3. Deployment & Security
*   **Rootless Docker:** The Docker configuration (`Dockerfile` and `docker-compose.yml`) has been updated to run as a non-root user (UID 1001) for enhanced security.
*   **Port Mapping:** The container internally listens on port 8080 (unprivileged), mapped to host port 443 (or other) via Docker Compose.
*   **Python 3.13 Compatibility:** Updated dependencies to ensure compatibility with Python 3.13 (replaced `uvloop` with standard `asyncio` due to build issues).

## Getting Started

### 1. Local Development Setup

This project is a Python application. It uses a virtual environment for dependency management.

**a. Create and Activate Virtual Environment:**
```bash
python -m venv venv
```
Then activate it:
```bash
# On Windows (Command Prompt)
.\venv\Scripts\activate.bat

# On Windows (PowerShell)
.\venv\Scripts\Activate.ps1

# On Linux/macOS
source venv/bin/activate
```

**b. Install Dependencies:**
Ensure your virtual environment is activated, then install the required packages:
```bash
pip install -r threat-feed-aggregator/requirements.txt
```

**c. Configure Environment Variables:**
Copy the example environment file and fill in your secrets.
```bash
cp .env.example .env
# Edit .env to set SECRET_KEY and ADMIN_PASSWORD
```

**d. Initialize Configuration (First Run):**
If `threat-feed-aggregator/threat_feed_aggregator/data/config.json` does not exist, copy the example:
```bash
cp threat-feed-aggregator/data/config.json.example threat-feed-aggregator/threat_feed_aggregator/data/config.json
```
_Note:_ The application is designed to automatically create `threat_feed.db` and `jobs.sqlite` on first run if they are missing.

**e. Run the Application:**
The Flask application can be run directly as a Python module. Ensure your virtual environment is activated.
```bash
python -m threat_feed_aggregator.app
```
The application will typically be accessible at `https://127.0.0.1:443` (or the port defined in ENV).

**Login Credentials:**
- Username: `admin`
- Password: (Set in your `.env` file, default `123456` if not set)

### 2. Docker Deployment

The project is configured for easy deployment using Docker (Rootless).

**a. Environment Setup:**
Place your `.env` file (copied from `.env.example` with your secrets) in the project root (`EDL/`).

**b. Build and Run with Docker Compose:**
Navigate to the project root (`EDL/`) and run:
```bash
docker-compose up -d --build
```
This command will build the Docker image, create a container running as user 1001, and map port 443 (host) to 8080 (container).

**c. Access the Application:**
The application will be accessible via HTTPS at `https://localhost`.

**d. Data Persistence:**
The `threat-feed-aggregator/data/` directory on your host machine is mapped as a Docker volume to `/app/threat_feed_aggregator/data` inside the container. This ensures your data persists even if the Docker container is removed or recreated.

**e. Stopping the Application:**
To stop the running container:
```bash
docker-compose down
```

### 3. OpenShift / Kubernetes Deployment

The application is configured for OpenShift/Kubernetes, prioritizing non-root execution and persistent storage.

**a. Build the Docker Image:**
First, build your Docker image and push it to an accessible registry.
```bash
docker build -t threat-feed-aggregator:latest ./threat-feed-aggregator
docker push your-registry/your-project/threat-feed-aggregator:latest
```

**b. Deploy:**
Apply the manifests in `openshift/deployment.yaml`. Ensure you update the image path in the yaml file first.

## Development Conventions

-   **Python Version:** Python 3.13.
-   **Web Framework:** Flask (Modularized with Blueprints).
-   **Async:** `asyncio` & `aiohttp` for data fetching.
-   **Scheduler:** APScheduler (with SQLAlchemyJobStore).
-   **Configuration:** `config.json` & `threat_feed.db`.
-   **Testing:** Unit tests are organized under the `tests/` directory. Run with `pytest`.

## Cleanup for Transfer

To prepare the project for transfer to another PC:
1.  **Stop the Application:** If running, stop it first.
2.  **Delete Temporary Files:** You can safely remove `__pycache__`, `.pytest_cache`, and the `venv/` directory.
3.  **Data Files:** Decide if you want to keep `threat-feed-aggregator/data/` (contains DB and config). For a clean start on a new machine, exclude `*.db` and `*.sqlite` but keep `config.json`.
4.  **Zip:** Compress the entire project folder (excluding `venv` and cache).

## Building an Executable (Windows)

To create a standalone `.exe` file for easier deployment:
1.  **Install PyInstaller:** `pip install pyinstaller`
2.  **Build:** Run the command from the project root:
    ```bash
    pyinstaller --onefile --name threat-feed-aggregator --add-data "threat-feed-aggregator/threat_feed_aggregator/templates;threat_feed_aggregator/templates" --add-data "threat-feed-aggregator/threat_feed_aggregator/config;threat_feed_aggregator/config" --hidden-import="apscheduler.schedulers.background" --hidden-import="apscheduler.triggers.interval" threat-feed-aggregator/threat_feed_aggregator/app.py
    ```
3.  **Run:** The executable will be in the `dist/` folder. Ensure a `data/` folder exists next to it.