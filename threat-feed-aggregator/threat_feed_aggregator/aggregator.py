import os
import time
import logging
from datetime import datetime, timezone
from concurrent.futures import ThreadPoolExecutor, as_completed

from .data_collector import fetch_data_from_url
from .parsers import parse_text, parse_json, parse_csv, parse_mixed_text, identify_indicator_type
from .db_manager import (
    remove_old_indicators, 
    get_all_indicators, 
    get_whitelist, 
    upsert_indicators_bulk, 
    delete_whitelisted_indicators as db_delete_whitelisted_indicators,
    log_job_start,
    log_job_end,
    recalculate_scores
)
from .utils import is_whitelisted # Import is_whitelisted for cleanup
from .geoip_manager import get_country_code
from .config_manager import read_config, read_stats, write_stats, BASE_DIR, DATA_DIR

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

# Global in-memory status tracker
CURRENT_JOB_STATUS = {}

def update_job_status(source_name, status, details=None):
    """Updates the in-memory status of a job."""
    CURRENT_JOB_STATUS[source_name] = {
        "status": status,
        "details": details,
        "timestamp": datetime.now(timezone.utc).isoformat()
    }

def clear_job_status(source_name):
    """Removes a job from the in-memory status tracker."""
    if source_name in CURRENT_JOB_STATUS:
        del CURRENT_JOB_STATUS[source_name]

def _cleanup_whitelisted_items_from_db():
    whitelist_db_items = get_whitelist()
    whitelist_filters = [w['item'] for w in whitelist_db_items]
    
    if not whitelist_filters:
        return

    all_current_indicators_dict = get_all_indicators()
    indicators_to_delete = []

    for indicator, data in all_current_indicators_dict.items():
        indicator_type = data['type']
        # Check against whitelist using universal function
        whitelisted, _ = is_whitelisted(indicator, whitelist_filters)
        if whitelisted:
            indicators_to_delete.append(indicator)
    
    if indicators_to_delete:
        chunk_size = 900
        for i in range(0, len(indicators_to_delete), chunk_size):
            chunk = indicators_to_delete[i:i + chunk_size]
            db_delete_whitelisted_indicators(chunk)

def regenerate_edl_files():
    """
    Regenerates the Palo Alto, Fortinet EDL, and URL List text files based on the current
    content of the indicators database.
    """
    logger.info("Regenerating EDL files from database...")
    try:
        indicators_data = get_all_indicators()
        
        from .output_formatter import format_for_palo_alto, format_for_fortinet, format_for_url_list

        palo_alto_output = format_for_palo_alto(indicators_data)
        with open(os.path.join(DATA_DIR, "palo_alto_edl.txt"), "w") as f:
            f.write(palo_alto_output)

        fortinet_output = format_for_fortinet(indicators_data)
        with open(os.path.join(DATA_DIR, "fortinet_edl.txt"), "w") as f:
            f.write(fortinet_output)

        url_list_output = format_for_url_list(indicators_data)
        with open(os.path.join(DATA_DIR, "url_list.txt"), "w") as f:
            f.write(url_list_output)
            
        logger.info("EDL files regenerated successfully.")
        return True, "Lists regenerated successfully."
    except Exception as e:
        logger.error(f"Error regenerating EDL files: {e}")
        return False, str(e)

def aggregate_single_source(source_config, recalculate=True):
    name = source_config["name"]
    url = source_config["url"]
    data_format = source_config.get("format", "text")
    key_or_column = source_config.get("key_or_column")

    # DB Log Start
    job_id = log_job_start(name)
    update_job_status(name, "Fetching", f"Downloading from {url}")

    start_time_fetch = time.time()
    count = 0
    fetch_duration = 0

    try:
        raw_data = fetch_data_from_url(url)
        end_time_fetch = time.time()
        fetch_duration = end_time_fetch - start_time_fetch
        
        if raw_data:
            update_job_status(name, "Parsing", "Parsing data format...")
            items_with_type = []
            
            if data_format == "text":
                items_with_type = parse_mixed_text(raw_data, source_name=name)
            elif data_format == "json":
                items = parse_json(raw_data, key=key_or_column)
                items_with_type = [(item, identify_indicator_type(item)) for item in items]
            elif data_format == "csv":
                items = parse_csv(raw_data, column=key_or_column)
                items_with_type = [(item, identify_indicator_type(item)) for item in items]
                
            items_with_type = [(item, item_type) for item, item_type in items_with_type if item and item_type != "unknown"]

            update_job_status(name, "Filtering", f"Filtering whitelist ({len(items_with_type)} items)...")
            
            whitelist_db = get_whitelist()
            whitelist_filters = [w['item'] for w in whitelist_db]
            
            filtered_items_with_type = []
            for item, item_type in items_with_type:
                # Universal check for all types using the improved is_whitelisted function
                whitelisted, reason = is_whitelisted(item, whitelist_filters)
                if not whitelisted:
                    filtered_items_with_type.append((item, item_type))
                else:
                    pass # Skipped
            
            # --- GeoIP Enrichment (Batch) ---
            update_job_status(name, "Enriching", f"Enriching {len(filtered_items_with_type)} items...")
            data_for_upsert = []
            total_items = len(filtered_items_with_type)
            
            for i, (item, item_type) in enumerate(filtered_items_with_type):
                country = None
                if item_type == 'ip':
                    try:
                        country = get_country_code(item)
                    except Exception:
                        pass
                data_for_upsert.append((item, country, item_type))
                
                # Progress update for enrichment
                if (i + 1) % 10000 == 0:
                     update_job_status(name, "Enriching", f"Enriched {i + 1}/{total_items} items...")

            # --- DB Upsert (Batch) ---
            if data_for_upsert:
                batch_size = 5000
                total_batches = (len(data_for_upsert) + batch_size - 1) // batch_size
                
                logger.info(f"[{name}] Starting DB upsert for {len(data_for_upsert)} items in {total_batches} batches.")
                update_job_status(name, "Saving", f"Writing {len(data_for_upsert)} items (0/{total_batches} batches)...")
                
                for i in range(0, len(data_for_upsert), batch_size):
                    batch = data_for_upsert[i:i + batch_size]
                    current_batch_num = (i // batch_size) + 1
                    
                    # Retry mechanism for DB lock
                    max_retries = 3
                    for attempt in range(max_retries):
                        try:
                            upsert_indicators_bulk(batch, source_name=name)
                            
                            # Log and Update Status
                            msg = f"Written batch {current_batch_num}/{total_batches} ({len(batch)} items)"
                            logger.info(f"[{name}] {msg}")
                            update_job_status(name, "Saving", msg)
                            break # Success
                        except Exception as e:
                            if attempt < max_retries - 1:
                                logger.warning(f"[{name}] Error writing batch {current_batch_num} (Attempt {attempt+1}): {e}. Retrying...")
                                time.sleep(2 * (attempt + 1))
                            else:
                                logger.error(f"[{name}] Failed to write batch {current_batch_num} after {max_retries} attempts: {e}")
                
            count = len(data_for_upsert)
            
            # Recalculate scores
            if recalculate:
                update_job_status(name, "Scoring", "Recalculating risk scores...")
                recalculate_scores()
            
            # DB Log Success
            log_job_end(job_id, "success", count, f"Fetch time: {fetch_duration:.2f}s")
            update_job_status(name, "Completed", f"Processed {count} items.")
        else:
            log_job_end(job_id, "warning", 0, "No data fetched")
            update_job_status(name, "Completed", "No data fetched.")

    except Exception as e:
        logger.error(f"Error processing {name}: {e}")
        log_job_end(job_id, "failure", 0, str(e))
        update_job_status(name, "Failed", str(e))
        raise # Re-raise for ThreadPoolExecutor to catch
    finally:
        pass

    return {
        "name": name,
        "count": count,
        "fetch_time": f"{fetch_duration:.2f} seconds",
        "last_updated": datetime.now(timezone.utc).isoformat()
    }

def fetch_and_process_single_feed(source_config):
    name = source_config["name"]
    logger.info(f"Starting scheduled fetch for {name}...")

    try:
        aggregate_single_source(source_config)
        _cleanup_whitelisted_items_from_db()
        regenerate_edl_files() 
        logger.info(f"Completed scheduled fetch for {name}.")
    except Exception as e:
        logger.error(f"Scheduled fetch failed for {name}: {e}")
    finally:
        pass

def main(source_urls):
    config = read_config()
    lifetime_days = config.get("indicator_lifetime_days", 30)
    
    remove_old_indicators(lifetime_days)

    all_url_counts = {}
    current_stats = read_stats()

    # Clear previous statuses
    CURRENT_JOB_STATUS.clear()

    with ThreadPoolExecutor(max_workers=10) as executor:
        # Pass recalculate=False to avoid locking DB for every source
        future_to_source = {executor.submit(aggregate_single_source, source, recalculate=False): source for source in source_urls}
        
        for future in as_completed(future_to_source):
            source = future_to_source[future]
            try:
                result = future.result()
                name = result["name"]
                
                current_stats[name] = {
                    "count": result["count"],
                    "fetch_time": result["fetch_time"],
                    "last_updated": result["last_updated"]
                }
                
                all_url_counts[name] = {
                    "count": result["count"],
                    "fetch_time": result["fetch_time"]
                }
                
            except Exception as exc:
                logger.error(f"{source['name']} generated an exception: {exc}")

    # Recalculate scores once after all sources are processed
    logger.info("Recalculating risk scores for all indicators...")
    recalculate_scores()

    _cleanup_whitelisted_items_from_db()

    current_stats["last_updated"] = datetime.now(timezone.utc).isoformat()
    write_stats(current_stats)

    regenerate_edl_files() 
    return {"url_counts": all_url_counts, "processed_data": []} 
