import os
import json
from datetime import datetime, timezone
from .data_collector import fetch_data_from_url
from .data_processor import process_data
from .db_manager import remove_old_indicators, get_all_indicators
import time

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
CONFIG_FILE = os.path.join(BASE_DIR, "config", "config.json")
STATS_FILE = os.path.join(BASE_DIR, "stats.json")

def read_config():
    if not os.path.exists(CONFIG_FILE):
        return {"source_urls": []}
    with open(CONFIG_FILE, "r") as f:
        return json.load(f)

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

def aggregate_single_source(source_config):
    """
    Fetches and processes data for a single threat feed source.
    Updates the global indicators database and stats.
    """
    name = source_config["name"]
    url = source_config["url"]
    data_format = source_config.get("format", "text")
    key_or_column = source_config.get("key_or_column")

    config = read_config()
    lifetime_days = config.get("indicator_lifetime_days", 30)

    # Clean up old indicators before processing new ones (or could be a separate scheduled job)
    # Doing it here ensures we keep the DB clean regularly.
    remove_old_indicators(lifetime_days)

    start_time_fetch = time.time()
    raw_data = fetch_data_from_url(url)
    end_time_fetch = time.time()
    fetch_duration = f"{end_time_fetch - start_time_fetch:.2f} seconds"

    current_stats = read_stats()
    
    count = 0
    if raw_data:
        count = process_data(raw_data, data_format, key_or_column)
        current_stats[name] = {
            "count": count,
            "fetch_time": fetch_duration,
            "last_updated": datetime.now(timezone.utc).isoformat()
        }
    else:
        current_stats[name] = {
            "count": 0,
            "fetch_time": fetch_duration,
            "last_updated": datetime.now(timezone.utc).isoformat()
        }

    current_stats["last_updated"] = datetime.now(timezone.utc).isoformat()
    write_stats(current_stats)

    return {
        "name": name,
        "count": current_stats[name]["count"],
        "fetch_time": current_stats[name]["fetch_time"]
    }

def main(source_urls):
    """
    Aggregates and processes threat feeds from a list of source URLs.
    This function is primarily for initial full runs or when schedules are not used.
    """
    all_url_counts = {}

    for source in source_urls:
        single_source_result = aggregate_single_source(source)
        all_url_counts[single_source_result["name"]] = {
            "count": single_source_result["count"],
            "fetch_time": single_source_result["fetch_time"]
        }
        
    all_indicators = get_all_indicators()
    return {"url_counts": all_url_counts, "processed_data": list(all_indicators.keys())}
