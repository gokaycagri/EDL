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

GUNICORN_BASE="gunicorn --worker-class=gthread --workers=1 --threads=16 --bind 0.0.0.0:8080 --access-logfile - --timeout 300 threat_feed_aggregator.app:app"

# Single worker + multiple threads: avoids APScheduler duplication and DB deadlocks
#
# FORCE_HTTP_MODE=true  → always run plain HTTP regardless of cert presence.
#                         Use this when TLS is terminated by the platform (OpenShift Route,
#                         Kubernetes Ingress, load balancer) so platform health probes
#                         can reach the container over HTTP without SSL mismatch warnings.
if [ "${FORCE_HTTP_MODE:-false}" = "true" ]; then
    echo "FORCE_HTTP_MODE is set — starting in HTTP mode (TLS handled by platform)."
    export FORCE_HTTPS=false
    exec $GUNICORN_BASE
elif [ -f "$CERT_FILE" ] && [ -f "$KEY_FILE" ]; then
    echo "SSL certificates found — starting in HTTPS mode."
    export FORCE_HTTPS=true
    exec $GUNICORN_BASE \
        --certfile="$CERT_FILE" --keyfile="$KEY_FILE"
else
    echo "No SSL certificates found — starting in HTTP mode."
    export FORCE_HTTPS=false
    exec $GUNICORN_BASE
fi
