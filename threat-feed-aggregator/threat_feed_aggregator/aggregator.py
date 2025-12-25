import os
import time
import logging
import asyncio
from datetime import datetime, timezone
from concurrent.futures import ThreadPoolExecutor

from .data_collector import fetch_data_from_url_async, fetch_data_from_url
from .parsers import get_parser, identify_indicator_type
from .db_manager import (
    remove_old_indicators, 
    get_all_indicators, 
    get_whitelist, 
    upsert_indicators_bulk, 
    delete_whitelisted_indicators as db_delete_whitelisted_indicators,
    log_job_start,
    log_job_end,
    recalculate_scores,
    save_historical_stats,
    db_transaction,
    get_api_blacklist_items
)
from .utils import is_whitelisted
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
        
        # --- Merge API Blacklist Items ---
        # Treat them as high-confidence (Risk Score 100) items
        api_blacklist_items = get_api_blacklist_items()
        for item in api_blacklist_items:
            ind = item['item']
            if ind not in indicators_data:
                indicators_data[ind] = {
                    'last_seen': item['added_at'],
                    'country': 'Unknown', # Could try to enrich if needed
                    'type': item['type'],
                    'risk_score': 100, # Max risk for manually added items
                    'source_count': 1
                }
            else:
                # Override existing score if lower
                indicators_data[ind]['risk_score'] = 100

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

class FeedAggregator:
    """
    Encapsulates logic for fetching, parsing, and storing threat feed data (Async).
    """
    def __init__(self, db_conn=None):
        self.db_conn = db_conn

    async def fetch_data(self, source_config):
        """
        Fetches data from the source asynchronously.
        """
        url = source_config["url"]
        data_format = source_config.get("format", "text")
        start_time = time.time()
        
        raw_data = None
        items_with_type = []

        if data_format == "taxii":
            # TAXII lib might be sync, keep it simple for now or wrap in executor if needed
            # For this iteration, we assume fetch_and_parse_taxii is sync
            from .taxii_services import fetch_and_parse_taxii
            username = source_config.get("username")
            password = source_config.get("password")
            collection_id = source_config.get("collection_id")
            
            loop = asyncio.get_event_loop()
            items_with_type = await loop.run_in_executor(None, fetch_and_parse_taxii, url, collection_id, username, password)
            raw_data = "TAXII_PROCESSED"
        else:
            raw_data = await fetch_data_from_url_async(url)
        
        duration = time.time() - start_time
        return raw_data, items_with_type, duration

    def parse_data(self, raw_data, source_config):
        """
        Parses raw data (CPU bound, but usually fast enough to keep sync).
        """
        data_format = source_config.get("format", "text")
        key_or_column = source_config.get("key_or_column")
        name = source_config["name"]

        if data_format == "taxii":
            return [] 

        parser = get_parser(data_format)
        return parser(raw_data, source_name=name, key=key_or_column, column=key_or_column)

    def filter_whitelist(self, items):
        whitelist_db = get_whitelist(conn=self.db_conn)
        whitelist_filters = [w['item'] for w in whitelist_db]
        
        filtered_items = []
        for item, item_type in items:
            if not item or item_type == "unknown":
                continue
            whitelisted, _ = is_whitelisted(item, whitelist_filters)
            if not whitelisted:
                filtered_items.append((item, item_type))
        return filtered_items

    def enrich_data(self, items, source_name):
        enriched_data = []
        total = len(items)
        for i, (item, item_type) in enumerate(items):
            country = None
            if item_type == 'ip':
                try:
                    country = get_country_code(item)
                except Exception:
                    pass
            enriched_data.append((item, country, item_type))
            
            if (i + 1) % 10000 == 0:
                update_job_status(source_name, "Enriching", f"Enriched {i + 1}/{total} items...")
        return enriched_data

    def save_batch(self, items, source_name):
        """
        Sync DB operation. Should be run in executor.
        """
        batch_size = 5000
        total_batches = (len(items) + batch_size - 1) // batch_size
        
        logger.info(f"[{source_name}] Starting DB upsert for {len(items)} items in {total_batches} batches.")
        update_job_status(source_name, "Saving", f"Writing {len(items)} items (0/{total_batches} batches)...")
        
        for i in range(0, len(items), batch_size):
            batch = items[i:i + batch_size]
            current_batch_num = (i // batch_size) + 1
            
            max_retries = 3
            for attempt in range(max_retries):
                try:
                    upsert_indicators_bulk(batch, source_name=source_name, conn=self.db_conn)
                    msg = f"Written batch {current_batch_num}/{total_batches} ({len(batch)} items)"
                    logger.info(f"[{source_name}] {msg}")
                    update_job_status(source_name, "Saving", msg)
                    break
                except Exception as e:
                    if attempt < max_retries - 1:
                        logger.warning(f"[{source_name}] Error writing batch {current_batch_num} (Attempt {attempt+1}): {e}. Retrying...")
                        time.sleep(2 * (attempt + 1))
                    else:
                        logger.error(f"[{source_name}] Failed to write batch {current_batch_num} after {max_retries} attempts: {e}")

    async def process_source(self, source_config, recalculate=True):
        name = source_config["name"]
        loop = asyncio.get_event_loop()
        
        # Log Start (DB Op - Run in Executor)
        job_id = await loop.run_in_executor(None, log_job_start, name, self.db_conn)
        update_job_status(name, "Fetching", f"Downloading from {source_config['url']}")

        try:
            raw_data, items, duration = await self.fetch_data(source_config)
            
            if raw_data:
                if not items and source_config.get("format") != "taxii":
                    update_job_status(name, "Parsing", "Parsing data format...")
                    items = self.parse_data(raw_data, source_config)

                update_job_status(name, "Filtering", f"Filtering whitelist ({len(items)} items)...")
                # Whitelist Check (DB Op - Run in Executor)
                filtered_items = await loop.run_in_executor(None, self.filter_whitelist, items)

                update_job_status(name, "Enriching", f"Enriching {len(filtered_items)} items...")
                enriched_items = self.enrich_data(filtered_items, name)

                if enriched_items:
                    # Save Batch (DB Op - Run in Executor)
                    await loop.run_in_executor(None, self.save_batch, enriched_items, name)

                count = len(enriched_items)
                
                if recalculate:
                    update_job_status(name, "Scoring", "Recalculating risk scores...")
                    try:
                        full_config = read_config()
                        confidence_map = {s['name']: s.get('confidence', 50) for s in full_config.get('source_urls', [])}
                    except:
                        confidence_map = {name: source_config.get('confidence', 50)}
                    
                    await loop.run_in_executor(None, recalculate_scores, confidence_map, self.db_conn)

                await loop.run_in_executor(None, log_job_end, job_id, "success", count, f"Fetch time: {duration:.2f}s", self.db_conn)
                update_job_status(name, "Completed", f"Processed {count} items.")
                
                return {
                    "name": name,
                    "count": count,
                    "fetch_time": f"{duration:.2f} seconds",
                    "last_updated": datetime.now(timezone.utc).isoformat()
                }
            else:
                await loop.run_in_executor(None, log_job_end, job_id, "warning", 0, "No data fetched", self.db_conn)
                update_job_status(name, "Completed", "No data fetched.")
                return {"name": name, "count": 0, "fetch_time": f"{duration:.2f} seconds", "last_updated": datetime.now(timezone.utc).isoformat()}

        except Exception as e:
            logger.error(f"Error processing {name}: {e}")
            await loop.run_in_executor(None, log_job_end, job_id, "failure", 0, str(e), self.db_conn)
            update_job_status(name, "Failed", str(e))
            raise

async def aggregate_sources_async(source_urls):
    aggregator = FeedAggregator()
    tasks = [aggregator.process_source(source, recalculate=False) for source in source_urls]
    results = []
    
    # Process all feeds concurrently
    # return_exceptions=True allows others to finish even if one fails
    results_or_exceptions = await asyncio.gather(*tasks, return_exceptions=True)
    
    for res in results_or_exceptions:
        if isinstance(res, Exception):
            logger.error(f"Task failed with: {res}")
        else:
            results.append(res)
            
    return results

def run_aggregator(source_urls):
    """
    Main entry point for aggregation (Sync wrapper around Async).
    """
    config = read_config()
    default_lifetime = config.get("indicator_lifetime_days", 30)
    
    # Cleanup Old Indicators
    retention_map = {s['name']: s.get('retention_days', default_lifetime) for s in source_urls}
    remove_old_indicators(retention_map, default_lifetime)

    all_url_counts = {}
    current_stats = read_stats()
    CURRENT_JOB_STATUS.clear()

    # --- Run Async Event Loop ---
    try:
        results = asyncio.run(aggregate_sources_async(source_urls))
        
        for result in results:
            if result:
                name = result["name"]
                current_stats[name] = {
                    "count": result["count"],
                    "fetch_time": result["fetch_time"],
                    "last_updated": result["last_updated"]
                }
                all_url_counts[name] = {"count": result["count"], "fetch_time": result["fetch_time"]}
    except Exception as e:
        logger.error(f"Critical error in async aggregation loop: {e}")

    # Final Score Recalculation & Cleanup (Sync)
    logger.info("Recalculating risk scores for all indicators...")
    confidence_map = {s['name']: s.get('confidence', 50) for s in source_urls}
    recalculate_scores(confidence_map)

    _cleanup_whitelisted_items_from_db()

    current_stats["last_updated"] = datetime.now(timezone.utc).isoformat()
    write_stats(current_stats)
    save_historical_stats()
    regenerate_edl_files() 
    return {"url_counts": all_url_counts, "processed_data": []}

def aggregate_single_source(source_config, recalculate=True):
    """
    Sync wrapper for single source (Backward compatibility).
    """
    aggregator = FeedAggregator()
    return asyncio.run(aggregator.process_source(source_config, recalculate))

def fetch_and_process_single_feed(source_config):
    """
    Scheduled task wrapper.
    """
    name = source_config["name"]
    logger.info(f"Starting scheduled fetch for {name}...")
    try:
        aggregate_single_source(source_config)
        _cleanup_whitelisted_items_from_db()
        regenerate_edl_files() 
        logger.info(f"Completed scheduled fetch for {name}.")
    except Exception as e:
        logger.error(f"Scheduled fetch failed for {name}: {e}")

# Re-alias main to run_aggregator for app.py compatibility if needed, 
# though we changed app.py to import 'run_aggregator' from 'aggregator' via 'main as run_aggregator'
# so keeping function name 'run_aggregator' but aliasing it as main is safer.
main = run_aggregator

def test_feed_source(source_config):
    """
    Tests a feed source using the FeedAggregator logic without saving.
    """
    name = source_config.get("name", "Test Source")
    aggregator = FeedAggregator()

    async def _test():
        try:
            if not source_config["url"].startswith(('http://', 'https://')):
                 return False, "Invalid URL format.", []

            # 1. Fetch
            raw_data, items, _ = await aggregator.fetch_data(source_config)
            if not raw_data:
                 return False, "No data fetched from URL.", []

            # 2. Parse
            if not items and source_config.get("format") != "taxii":
                items = aggregator.parse_data(raw_data, source_config)

            valid_items = [item for item, item_type in items if item and item_type != "unknown"]
            
            count = len(valid_items)
            sample = valid_items[:5]
            
            if count == 0:
                 return False, "Data fetched but no valid indicators found.", []
                 
            return True, f"Success! Found {count} valid indicators.", sample

        except Exception as e:
            return False, f"Error testing feed: {str(e)}", []
            
    return asyncio.run(_test())
