import os
import json
from datetime import datetime, timezone
from concurrent.futures import ThreadPoolExecutor, as_completed
from .data_collector import fetch_data_from_url
from .parsers import parse_text, parse_json, parse_csv # Imported for direct parsing in aggregate_single_source
from .db_manager import remove_old_indicators, get_all_indicators, get_whitelist, upsert_indicators_bulk, delete_whitelisted_indicators as db_delete_whitelisted_indicators # Alias to avoid conflict
from .utils import filter_whitelisted_items, is_ip_whitelisted # Import is_ip_whitelisted for cleanup
from .geoip_manager import get_country_code # Import GeoIP
import time
import ipaddress # For CIDR checks in cleanup
import logging

logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG) # Set to DEBUG for this module

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CONFIG_FILE = os.path.join(BASE_DIR, "threat_feed_aggregator", "config", "config.json") # Config remains in package
STATS_FILE = os.path.join(BASE_DIR, "stats.json") # Stats in root
DATA_DIR = os.path.join(BASE_DIR, "data") # Data in root

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

def _cleanup_whitelisted_items_from_db():
    """
    Scans the entire indicators DB and removes any item that matches the whitelist.
    This is called after each aggregation run to ensure existing DB is clean.
    """
    whitelist_db_items = get_whitelist()
    whitelist_filters = [w['item'] for w in whitelist_db_items]
    
    if not whitelist_filters:
        logging.info("Whitelist is empty, skipping cleanup.")
        return

    all_current_indicators_dict = get_all_indicators()
    all_current_indicators_list = list(all_current_indicators_dict.keys())
    logging.info(f"Total indicators before cleanup: {len(all_current_indicators_list)}")

    # Filter out indicators that are in the whitelist
    indicators_to_delete = []

    for indicator in all_current_indicators_list:
        if is_ip_whitelisted(indicator, whitelist_filters):
            indicators_to_delete.append(indicator)
    
    if indicators_to_delete:
        logging.info(f"Attempting to delete {len(indicators_to_delete)} whitelisted items: {indicators_to_delete[:5]}...")
        
        # Chunk deletion to avoid SQLite limits (typically 999 variables)
        chunk_size = 900
        for i in range(0, len(indicators_to_delete), chunk_size):
            chunk = indicators_to_delete[i:i + chunk_size]
            db_delete_whitelisted_indicators(chunk)
            
        logging.info(f"Cleaned up {len(indicators_to_delete)} whitelisted items from main DB.")
    else:
        logging.info("No whitelisted items found in main DB for cleanup.")


def aggregate_single_source(source_config):
    """
    Fetches and processes data for a single threat feed source.
    Updates the global indicators database and stats.
    """
    name = source_config["name"]
    url = source_config["url"]
    data_format = source_config.get("format", "text")
    key_or_column = source_config.get("key_or_column")

    start_time_fetch = time.time()
    raw_data = fetch_data_from_url(url)
    end_time_fetch = time.time()
    fetch_duration = f"{end_time_fetch - start_time_fetch:.2f} seconds"

    count = 0
    if raw_data:
        items = []
        if data_format == "text":
            items = parse_text(raw_data)
        elif data_format == "json":
            items = parse_json(raw_data, key=key_or_column)
        elif data_format == "csv":
            items = parse_csv(raw_data, column=key_or_column)
            
        # 2. Filter Whitelist
        whitelist_db = get_whitelist()
        whitelist_items = [w['item'] for w in whitelist_db]
        
        filtered_items = filter_whitelisted_items(items, whitelist_items)
        
        # 3. Enrich with GeoIP
        enriched_items = []
        for item in filtered_items:
            country = get_country_code(item)
            enriched_items.append((item, country))

        # 4. Upsert
        if enriched_items:
            upsert_indicators_bulk(enriched_items)
            
        count = len(enriched_items)
    
    # Return stats data
    return {
        "name": name,
        "count": count,
        "fetch_time": fetch_duration,
        "last_updated": datetime.now(timezone.utc).isoformat()
    }

def fetch_and_process_single_feed(source_config):
    """
    Fetches and processes data for a single threat feed source, updates DB and stats,
    then updates the output files (Palo Alto, Fortinet) based on the current full DB.
    This function is designed to be run by the scheduler for individual sources.
    """
    name = source_config["name"]
    print(f"Starting scheduled fetch for {name}...")

    # Call the single source aggregation function
    aggregate_single_source(source_config)

    # Perform cleanup of whitelisted items to ensure DB consistency
    _cleanup_whitelisted_items_from_db()

    # After updating a single source, re-generate the full output files
    # This requires reading the entire indicators_db
    indicators_data = get_all_indicators()
    processed_data = list(indicators_data.keys())

    from .output_formatter import format_for_palo_alto, format_for_fortinet # Import locally to avoid circular

    # Format and save for Palo Alto
    palo_alto_output = format_for_palo_alto(processed_data)
    palo_alto_file_path = os.path.join(DATA_DIR, "palo_alto_edl.txt")
    with open(palo_alto_file_path, "w") as f:
        f.write(palo_alto_output)

    # Format and save for Fortinet
    fortinet_output = format_for_fortinet(processed_data)
    fortinet_file_path = os.path.join(DATA_DIR, "fortinet_edl.txt")
    with open(fortinet_file_path, "w") as f:
        f.write(fortinet_output)
    
    print(f"Completed scheduled fetch for {name}.")

def main(source_urls):
    """
    Aggregates and processes threat feeds from a list of source URLs in PARALLEL.
    """
    config = read_config()
    lifetime_days = config.get("indicator_lifetime_days", 30)
    
    # Clean up old indicators once per run
    remove_old_indicators(lifetime_days)

    all_url_counts = {}
    current_stats = read_stats()

    # Use ThreadPoolExecutor for parallel processing
    # Max workers can be adjusted based on system resources, 10 is a safe start for IO-bound tasks.
    with ThreadPoolExecutor(max_workers=10) as executor:
        future_to_source = {executor.submit(aggregate_single_source, source): source for source in source_urls}
        
        for future in as_completed(future_to_source):
            source = future_to_source[future]
            try:
                result = future.result()
                name = result["name"]
                
                # Update local stats dict
                current_stats[name] = {
                    "count": result["count"],
                    "fetch_time": result["fetch_time"],
                    "last_updated": result["last_updated"]
                }
                
                all_url_counts[name] = {
                    "count": result["count"],
                    "fetch_time": result["fetch_time"]
                }
                logging.info(f"Finished processing {name}")
                
            except Exception as exc:
                logging.error(f"{source['name']} generated an exception: {exc}")

    # After all sources processed, perform a full cleanup of whitelisted items from the main DB
    _cleanup_whitelisted_items_from_db()

    # Update global stats file once at the end
    current_stats["last_updated"] = datetime.now(timezone.utc).isoformat()
    write_stats(current_stats)

    all_indicators = get_all_indicators()
    return {"url_counts": all_url_counts, "processed_data": list(all_indicators.keys())}
