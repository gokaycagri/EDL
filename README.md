# Threat Feed Aggregator

[![Python Version](https://img.shields.io/badge/python-3.13-blue.svg)](https://www.python.org/downloads/)
[![Flask](https://img.shields.io/badge/framework-Flask-lightgrey.svg)](https://flask.palletsprojects.com/)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)

A web-based Threat Feed Aggregator built with Flask. This tool collects, processes, and manages threat intelligence feeds from various sources, optimizing them for security infrastructure like Palo Alto Networks and Fortinet.

## 🚀 Key Features

*   **Intelligent IP Processing:**
    *   **CIDR Aggregation:** Merges contiguous IP addresses and smaller subnets into larger CIDR blocks to optimize firewall performance.
    *   **Confidence Scoring:** Assigns confidence scores (0-100) to sources, influencing indicator risk scores.
    *   **Granular Retention:** Per-source aging/retention periods for precise control over indicator lifespan.
*   **Diverse Intelligence Sources:**
    *   Supports Text, JSON, CSV, and industry-standard **STIX/TAXII** feeds.
    *   Built-in whitelist sources: Microsoft 365, GitHub Service IPs, Azure Public Cloud IPs.
*   **Modern Architecture:**
    *   Asynchronous fetching using `asyncio` and `aiohttp` for high performance.
    *   Modular Flask Blueprint structure.
*   **User-Friendly Interface:**
    *   Modern "Soft UI" design.
    *   Live application logs in a terminal-like dashboard window.
    *   Interactive world map for visualizing threat origins using `jsVectorMap`.
*   **Output Formats:** Generates External Dynamic Lists (EDLs) compatible with **Palo Alto Networks** and **Fortinet**.

## 🛠️ Getting Started

### Prerequisites

*   Python 3.13+
*   Virtual environment (recommended)
*   Docker (optional, for containerized deployment)

### Local Installation

1.  **Clone the repository:**
    ```bash
    git clone https://github.com/your-username/threat-feed-aggregator.git
    cd threat-feed-aggregator
    ```

2.  **Set up a virtual environment:**
    ```bash
    python -m venv venv
    # Windows
    .\venv\Scripts\activate
    # Linux/macOS
    source venv/bin/activate
    ```

3.  **Install dependencies:**
    ```bash
    pip install -r threat-feed-aggregator/requirements.txt
    ```

4.  **Configure environment variables:**
    ```bash
    cp .env.example .env
    # Edit .env to set SECRET_KEY and ADMIN_PASSWORD
    ```

5.  **Initialize configuration:**
    ```bash
    cp threat-feed-aggregator/data/config.json.example threat-feed-aggregator/threat_feed_aggregator/data/config.json
    ```

6.  **Run the application:**
    ```bash
    python -m threat_feed_aggregator.app
    ```
    Access the UI at `https://127.0.0.1:443` (or the port defined in your `.env`).

    **Default Credentials:**
    *   Username: `admin`
    *   Password: (The one set in `.env`, default is `123456`)

## 🐳 Docker Deployment

The project is configured for **Rootless Docker** for enhanced security.

1.  Ensure your `.env` file is in the project root.
2.  Build and run with Docker Compose:
    ```bash
    docker-compose up -d --build
    ```
    The application will internally listen on port 8080 and map to host port 443.

## ☁️ Cloud Deployment (OpenShift / Kubernetes)

1.  Build and push the image:
    ```bash
    docker build -t threat-feed-aggregator:latest ./threat-feed-aggregator
    docker push your-registry/threat-feed-aggregator:latest
    ```
2.  Deploy using the provided manifests:
    ```bash
    oc apply -f openshift/deployment.yaml
    ```

## 🧪 Testing

Run the test suite using `pytest`:
```bash
pytest threat-feed-aggregator/tests
```

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details. (Note: Ensure you create a LICENSE file if it doesn't exist).
