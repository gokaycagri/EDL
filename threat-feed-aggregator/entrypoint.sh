#!/bin/bash
set -e

# Data directory
DATA_DIR="/app/threat_feed_aggregator/data"
CONFIG_FILE="$DATA_DIR/config.json"
EXAMPLE_CONFIG="/app/data/config.json.example"

# Ensure data directory exists
if [ ! -d "$DATA_DIR" ]; then
    echo "Creating data directory..."
    mkdir -p "$DATA_DIR"
fi

# Check for config.json, create from example if missing
if [ ! -f "$CONFIG_FILE" ]; then
    echo "Config file not found. Initializing from example..."
    
    if [ -f "$EXAMPLE_CONFIG" ]; then
         cp "$EXAMPLE_CONFIG" "$CONFIG_FILE"
         echo "Copied default configuration."
    else
         # Fallback default content
         echo '{"source_urls":[],"indicator_lifetime_days":30,"auth":{"ldap_enabled":false}}' > "$CONFIG_FILE"
         echo "Created minimal default configuration."
    fi
fi

# Run pre-start checks (DB Init, SSL Cert generation)
echo "Running pre-start initialization..."
python -m threat_feed_aggregator.prestart

# Run the application with Gunicorn (Production WSGI)
echo "Starting Threat Feed Aggregator with Gunicorn..."

CERT_FILE="/app/threat_feed_aggregator/certs/cert.pem"
KEY_FILE="/app/threat_feed_aggregator/certs/key.pem"

# Single worker + multiple threads: avoids APScheduler duplication and DB deadlocks
if [ -f "$CERT_FILE" ] && [ -f "$KEY_FILE" ]; then
    echo "SSL certificates found — starting in HTTPS mode."
    export FORCE_HTTPS=true
    exec gunicorn --worker-class=gthread --workers=1 --threads=8 --bind 0.0.0.0:8080 \
        --certfile="$CERT_FILE" --keyfile="$KEY_FILE" \
        --access-logfile - \
        --timeout 300 \
        threat_feed_aggregator.app:app
else
    echo "No SSL certificates found — starting in HTTP mode."
    export FORCE_HTTPS=false
    exec gunicorn --worker-class=gthread --workers=1 --threads=8 --bind 0.0.0.0:8080 \
        --access-logfile - \
        --timeout 300 \
        threat_feed_aggregator.app:app
fi
