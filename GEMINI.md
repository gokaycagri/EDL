# Threat Feed Aggregator Project

## Project Overview

This project is a web-based Threat Feed Aggregator built with Flask. Its purpose is to collect, process, and manage threat intelligence feeds from various sources. It allows users to define threat intelligence sources (URLs), specify their data format, and configure scheduling for automatic updates.

**Key enhancements inspired by MineMeld:**
*   **Intelligent Processing:**
    *   **CIDR Aggregation:** Optimizes IP lists by merging contiguous IP addresses and smaller subnets into larger CIDR blocks, reducing firewall EDL entry count.
    *   **Confidence Scoring:** Assigns a confidence score (0-100) to each source. Indicator risk scores are dynamically calculated based on the maximum confidence of reporting sources and a bonus for multiple source overlaps.
    *   **Per-Source Aging/Retention:** Configurable retention periods (in days) for each feed source, allowing granular control over how long stale indicators remain in the database after disappearing from their feed.
*   **Extended Whitelist Sources:**
    *   **Microsoft 365 Endpoints:** Fetches and generates allow-lists for Exchange, Teams/Skype, SharePoint, and Common M365 IPs/URLs.
    *   **GitHub Service IPs:** Fetches and generates allow-lists for GitHub Git operations, Web, Actions, and Webhooks IPs.
    *   **Azure Public Cloud IPs:** Scrapes Microsoft's download center for the latest Azure Service Tags JSON to generate allow-lists for various Azure services and regions.
*   **Output Formatting:** Generates downloadable External Dynamic Lists (EDLs) for Palo Alto Networks and Fortinet.
*   **User Authentication:** Basic login functionality protects access to the management interface.

## Building and Running (Local)

This project is a Python application. It uses a virtual environment for dependency management.

**1. Create and Activate Virtual Environment:**

If you don't have a virtual environment set up for this project, you can create one:
```bash
python -m venv threat-feed-aggregator/venv
```
Then activate it:
```bash
# On Windows (Command Prompt)
threat-feed-aggregator\venv\Scripts\activate.bat

# On Windows (PowerShell)
threat-feed-aggregator\venv\Scripts\Activate.ps1

# On Linux/macOS
source threat-feed-aggregator/venv/bin/activate
```

**2. Install Dependencies:**

Ensure your virtual environment is activated, then install the required packages:
```bash
pip install -r threat-feed-aggregator/requirements.txt
```

**3. Run the Application:**

The Flask application can be run directly as a Python module. Ensure your virtual environment is activated.

```bash
python -m threat_feed_aggregator.app
```
The application will typically be accessible at `https://127.0.0.1:443`. You will see console output as the application starts and processes feeds. Your browser might warn about a self-signed certificate, which you can safely bypass for local development.

**Login Credentials:**
- Username: `admin`
- Password: `123456` (Default from `docker-compose.yml` or initial setup)

**4. Initial Data Aggregation:**

Upon first running the application or after clearing `threat_feed.db`, the "Total Unique IPs" will show 0. To populate the data:
- Go to `https://127.0.0.1:443` in your browser.
- Perform a **hard refresh** (`Ctrl+F5` or `Shift+F5`).
- Go to the "Manage Sources" section.
- Click on an existing feed (e.g., `firehol_level1`).
- Enter desired values for "Confidence %", "Retention (d)", and "Interval (m)".
- Click the "Update" button.
- The page will refresh. Perform another **hard refresh**.
- You should now see the "Total Unique IPs" updated, and the "Last Updated" timestamp for that source will reflect the current local time.

Alternatively, a "Run All Feeds" button may be present on the GUI under "Feeds Aggregation" to trigger a full update for all configured feeds.

## Building an Executable (Windows)

To create a standalone `.exe` file for easier deployment:

1.  **Install PyInstaller:**
    ```bash
    pip install pyinstaller
    ```

2.  **Build the Executable:**
    Run the following command from the project root (ensure `threat-feed-aggregator/venv/Scripts/pyinstaller.exe` is in your PATH or use the full path):
    ```bash
    pyinstaller --onefile --name threat-feed-aggregator --add-data "threat-feed-aggregator/threat_feed_aggregator/templates;threat_feed_aggregator/templates" --add-data "threat-feed-aggregator/threat_feed_aggregator/config;threat_feed_aggregator/config" --hidden-import="apscheduler.schedulers.background" --hidden-import="apscheduler.triggers.interval" threat-feed-aggregator/threat_feed_aggregator/app.py
    ```

3.  **Run:**
    The executable will be in the `dist/` folder.
    *   Copy `threat-feed-aggregator.exe` to your desired location.
    *   Ensure a `data/` folder exists next to it (it will be created automatically if not present).
    *   The application will listen on port `443` (HTTPS) by default.

## Docker Integration

The project is configured for easy deployment using Docker.

**1. Build and Run with Docker Compose:**
Navigate to the `threat-feed-aggregator` directory and run:
```bash
docker-compose up -d --build
```
This command will build the Docker image (if not already built or if changes are detected), create a container, and run it in detached mode.

**2. Access the Application:**
The application will be accessible via HTTPS at `https://localhost`.
Your browser might warn about a self-signed certificate, which you can safely bypass.

**3. Data Persistence:**
The `data/` directory (containing `threat_feed.db`, `config.json`, output EDLs, etc.) is mapped as a Docker volume to `./data` on your host machine. This ensures your data persists even if the Docker container is removed or recreated.

**4. Stopping the Application:**
To stop the running container:
```bash
docker-compose down
```
To stop and remove containers, networks, and volumes (but preserving data in `./data` on your host):
```bash
docker-compose down -v
```

## Development Conventions

-   **Python Version:** The project uses Python 3.13.
-   **Web Framework:** Flask is used for the web interface.
-   **Scheduler:** APScheduler (with SQLAlchemyJobStore for persistence) is used for scheduling feed updates.
-   **Configuration:** `config.json` stores source URLs and application settings. `threat_feed.db` stores the aggregated unique indicators, whitelist, users, and job history.
-   **Code Structure:** The core logic is modularized within the `threat_feed_aggregator` package, with separate modules for data collection, processing, and output formatting.
    *   `microsoft_services.py`: Handles fetching and processing of Microsoft 365 endpoint data.
    *   `github_services.py`: Handles fetching and processing of GitHub service IP data.
    *   `azure_services.py`: Handles fetching and processing of Azure Public Cloud Service Tag IP data.
-   **Testing:** Unit tests are organized under the `tests/` directory.
    *   `test_data_collector.py`, `test_data_processor.py`, `test_output_formatter.py`, `test_parsers.py`: Core logic unit tests.
    *   `test_app_integration.py`: Basic application integration (startup, login redirects).
    *   `test_web_endpoints.py`: Tests API endpoints for M365, GitHub, Azure updates.
    *   `test_gui_views.py`: Tests web GUI views (login, dashboard, form submissions).
-   **Version Control:** Git is used for version control, with a `.gitignore` file to exclude virtual environments, IDE files, and build artifacts.