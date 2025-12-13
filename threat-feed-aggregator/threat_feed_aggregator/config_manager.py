import os
import json
from datetime import datetime, timezone

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA_DIR = os.path.join(BASE_DIR, "data") # Added DATA_DIR definition
CONFIG_FILE = os.path.join(BASE_DIR, "threat_feed_aggregator", "config", "config.json")
STATS_FILE = os.path.join(BASE_DIR, "stats.json")

def read_config():
    if not os.path.exists(CONFIG_FILE):
        return {"source_urls": []}
    with open(CONFIG_FILE, "r") as f:
        return json.load(f)

def write_config(config):
    with open(CONFIG_FILE, "w") as f:
        json.dump(config, f, indent=4)

def read_stats():
    if not os.path.exists(STATS_FILE):
        return {}
    with open(STATS_FILE, "r") as f:
        try:
            stats = json.load(f)
            if isinstance(stats, dict):
                for key, value in stats.items():
                    if not isinstance(value, dict):
                        stats[key] = {}
                return stats
        except json.JSONDecodeError:
            pass
    return {}

def write_stats(stats):
    with open(STATS_FILE, "w") as f:
        json.dump(stats, f, indent=4)

def update_stats_last_updated(stats=None):
    if stats is None:
        stats = read_stats()
    stats["last_updated"] = datetime.now(timezone.utc).isoformat()
    write_stats(stats)