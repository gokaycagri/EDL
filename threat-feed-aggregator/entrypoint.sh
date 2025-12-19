#!/bin/bash
set -e

# Data directory
DATA_DIR="/app/threat_feed_aggregator/data"
CONFIG_FILE="$DATA_DIR/config.json"
EXAMPLE_CONFIG="/app/threat_feed_aggregator/config/config.json.example"

# Ensure data directory exists
if [ ! -d "$DATA_DIR" ]; then
    echo "Creating data directory..."
    mkdir -p "$DATA_DIR"
fi

# Check for config.json, create from example if missing
if [ ! -f "$CONFIG_FILE" ]; then
    echo "Config file not found. Initializing from example..."
    # If we have an example in the code folder, use it. 
    # Otherwise check if there is one in the data folder (from previous setup steps)
    if [ -f "/app/data/config.json.example" ]; then
         cp "/app/data/config.json.example" "$CONFIG_FILE"
    else
         # Fallback default content
         echo '{"source_urls":[],"indicator_lifetime_days":30,"auth":{"ldap":{"enabled":false}}}' > "$CONFIG_FILE"
    fi
fi

# Run the application
# We use python directly because Gunicorn with APScheduler inside the same process 
# can cause double-execution of jobs if multiple workers are spawned.
# Since this is an internal tool, single-process is fine.
echo "Starting Threat Feed Aggregator..."
exec python -m threat_feed_aggregator.app