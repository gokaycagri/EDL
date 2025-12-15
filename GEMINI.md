# Threat Feed Aggregator Project

## Project Overview

This project is a web-based Threat Feed Aggregator built with Flask. Its purpose is to collect, process, and manage threat intelligence feeds from various sources. It allows users to define threat intelligence sources (URLs), specify their data format, and configure scheduling for automatic updates. The aggregated and processed data (unique IP addresses) can then be downloaded in formats compatible with security devices like Palo Alto and Fortinet.

Key features include:
- **Web-based UI:** For managing threat feed sources, viewing statistics, and triggering updates.
- **Configurable Sources:** Define multiple threat feed URLs with different parsing formats (text, JSON, CSV).
- **Scheduled Aggregation (APScheduler):** Automatically fetch and process feeds at defined intervals for each source.
- **Data Processing:** Aggregates unique indicators (IPs) and manages their lifetime.
- **Output Formatting:** Generates downloadable External Dynamic Lists (EDLs) for Palo Alto Networks and Fortinet.
- **User Authentication:** Basic login functionality protects access to the management interface.

## Building and Running

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
The application will typically be accessible at `http://127.0.0.1:5000`. You will see console output as the application starts and processes feeds.

**Login Credentials:**
- Username: `admin`
- Password: `123456`

**4. Initial Data Aggregation:**

Upon first running the application or after clearing `threat_feed.db`, the "Total Unique IPs" will show 0. To populate the data:
- Go to `http://127.0.0.1:5000` in your browser.
- Perform a **hard refresh** (`Ctrl+F5` or `Shift+F5`).
- Go to the "Manage Sources" section.
- Click on an existing feed (e.g., `firehol_level1`).
- Enter a value (e.g., `1` or `5`) in the "Schedule (mins, optional)" field.
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
    Run the following command from the project root:
    ```bash
    pyinstaller --onefile --name threat-feed-aggregator --add-data "threat-feed-aggregator/threat_feed_aggregator/templates;threat_feed_aggregator/templates" --add-data "threat-feed-aggregator/threat_feed_aggregator/config;threat_feed_aggregator/config" --hidden-import="apscheduler.schedulers.background" --hidden-import="apscheduler.triggers.interval" threat-feed-aggregator/threat_feed_aggregator/app.py
    ```

3.  **Run:**
    The executable will be in the `dist/` folder.
    *   Copy `threat-feed-aggregator.exe` to your desired location.
    *   Ensure a `data/` folder exists next to it (it will be created automatically if not present).
    *   The application will listen on port 5000 by default.

## Development Conventions

- **Python Version:** The project uses Python 3.13 (inferred from `cpython-313.pyc` files).
- **Web Framework:** Flask is used for the web interface.
- **Scheduler:** APScheduler (with SQLAlchemyJobStore for persistence) is used for scheduling feed updates.
- **Configuration:** `config.json` stores source URLs and application settings. `threat_feed.db` stores the aggregated unique indicators, whitelist, users, and job history.
- **Code Structure:** The core logic is modularized within the `threat_feed_aggregator` package, with separate modules for data collection, processing, and output formatting.
- **Testing:** Unit tests are organized under the `tests/` directory (e.g., `test_data_collector.py`, `test_data_processor.py`). To run tests, use `python -m pytest threat-feed-aggregator/tests`.
- **Version Control:** Git is used for version control, with a `.gitignore` file to exclude virtual environments, IDE files, and build artifacts.