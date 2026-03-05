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
echo "Starting Threat Feed Aggregator with Gunicorn (HTTPS Mode)..."

CERT_FILE="/app/threat_feed_aggregator/certs/cert.pem"
KEY_FILE="/app/threat_feed_aggregator/certs/key.pem"

# Re-enabled SSL certs for Gunicorn
exec gunicorn --workers 4 --threads 2 --bind 0.0.0.0:8080 \
    --certfile "$CERT_FILE" --keyfile "$KEY_FILE" \
    --access-logfile - \
    --timeout 60 \
    threat_feed_aggregator.app:app
