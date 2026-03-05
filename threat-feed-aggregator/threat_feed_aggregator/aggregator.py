import asyncio
import logging
import os
import time
from datetime import UTC, datetime

from aiohttp import BasicAuth

from .config_manager import DATA_DIR, read_config, read_stats, write_stats
from .data_collector import fetch_data_from_url_async, get_async_session
from .db_manager import (
    delete_whitelisted_indicators as db_delete_whitelisted_indicators,
    get_all_indicators,
    get_all_indicators_iter,
    get_api_blacklist_items,
    get_whitelist,
    log_job_end,
    log_job_start,
    recalculate_scores,
    remove_old_indicators,
    save_historical_stats,
    upsert_indicators_bulk,
    get_source_counts,
    remove_expired_blacklist_items
)
from .geoip_manager import get_country_code
from .output_formatter import (
    format_for_fortinet, 
    format_for_palo_alto, 
    format_for_url_list,
    format_for_palo_alto_domain,
    format_for_fortinet_domain
)
from .parsers import get_parser
from .services.job_service import job_service
from .utils import is_whitelisted

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)


def _cleanup_whitelisted_items_from_db():
    whitelist_db_items = get_whitelist()
    if not whitelist_db_items:
        return

    # 1. Exact Match Cleanup (Fast SQL)
    # Extract exact items (no slash)
    exact_items = [w['item'] for w in whitelist_db_items if '/' not in w['item']]
    if exact_items:
        # DB delete in chunks to avoid too many SQL variables
        chunk_size = 900
        for i in range(0, len(exact_items), chunk_size):
            chunk = exact_items[i:i + chunk_size]
            db_delete_whitelisted_indicators(chunk)

    # 2. CIDR Match Cleanup (Iterative)
    # Only need to iterate if we have CIDRs in whitelist
    cidr_filters = [w['item'] for w in whitelist_db_items if '/' in w['item']]
    if not cidr_filters:
        return

    # Use iterator to avoid loading 1M+ items into RAM dict
    indicators_to_delete = []
    # We only need the indicator string for checking
    # get_all_indicators_iter yields rows, row['indicator'] is what we need
    
    # Pre-compile whitelist logic
    # We can pass cidr_filters to is_whitelisted but it expects the full list usually.
    # Let's optimize is_whitelisted usage here or re-implement for speed.
    
    count = 0
    for row in get_all_indicators_iter():
        indicator = row['indicator']
        # Check only against CIDRs since exacts are done
        whitelisted, _ = is_whitelisted(indicator, cidr_filters)
        if whitelisted:
            indicators_to_delete.append(indicator)
            
        if len(indicators_to_delete) >= 1000:
            db_delete_whitelisted_indicators(indicators_to_delete)
            indicators_to_delete = []
            
    # Final flush
    if indicators_to_delete:
        db_delete_whitelisted_indicators(indicators_to_delete)


import shutil
import threading

# Global lock and status for EDL regeneration
_REGEN_LOCK = threading.Lock()
_REGEN_ACTIVE = False

def regenerate_edl_files():
    """
    Highly Optimized: Regenerates EDL files using streaming to handle millions of records with minimal memory.
    Ensures only one instance runs at a time using a lock.
    """
    global _REGEN_ACTIVE
    
    if not _REGEN_LOCK.acquire(blocking=False):
        logger.info("EDL regeneration already in progress, skipping redundant call.")
        return False, "Regeneration already in progress."
    
    _REGEN_ACTIVE = True
    logger.info("Regenerating EDL files from database using streaming...")
    try:
        # File paths
        paths = {
            "palo_alto_ip": os.path.join(DATA_DIR, "palo_alto_ip.txt"),
            "palo_alto_domain": os.path.join(DATA_DIR, "palo_alto_domain.txt"),
            "fortinet_ip": os.path.join(DATA_DIR, "fortinet_ip.txt"),
            "fortinet_domain": os.path.join(DATA_DIR, "fortinet_domain.txt"),
            "url_list": os.path.join(DATA_DIR, "url_list.txt")
        }

        # Open all files for writing
        with open(paths["palo_alto_ip"], "w") as pa_ip, \
             open(paths["palo_alto_domain"], "w") as pa_dom, \
             open(paths["fortinet_ip"], "w") as fn_ip, \
             open(paths["fortinet_domain"], "w") as fn_dom, \
             open(paths["url_list"], "w") as url_l:

            count = 0
            # Use iterator to stream from DB
            for row in get_all_indicators_iter():
                ind = row['indicator']
                itype = row['type']
                
                if itype in ['ip', 'cidr']:
                    pa_ip.write(f"{ind}\n")
                    fn_ip.write(f"{ind}\n")
                elif itype == 'domain':
                    pa_dom.write(f"{ind}\n")
                    fn_dom.write(f"{ind}\n")
                elif itype == 'url':
                    url_l.write(f"{ind}\n")
                
                count += 1

            # --- Handle API Blacklist (Treat as Score 100) ---
            api_blacklist_items = get_api_blacklist_items()
            for item in api_blacklist_items:
                ind = item['item']
                itype = item['type']
                if itype in ['ip', 'cidr']:
                    pa_ip.write(f"{ind}\n")
                    fn_ip.write(f"{ind}\n")
                elif itype == 'domain':
                    pa_dom.write(f"{ind}\n")
                    fn_dom.write(f"{ind}\n")
                
            # Legacy file compatibility
            shutil.copy(paths["palo_alto_ip"], os.path.join(DATA_DIR, "palo_alto_edl.txt"))
            shutil.copy(paths["fortinet_ip"], os.path.join(DATA_DIR, "fortinet_edl.txt"))

        logger.info(f"EDL files regenerated successfully. (Processed: {count} records)")
        return True, "Lists regenerated successfully."
    except Exception as e:
        logger.error(f"Error regenerating EDL files: {e}")
        return False, str(e)
    finally:
        _REGEN_ACTIVE = False
        _REGEN_LOCK.release()

def trigger_background_regeneration():
    """
    Triggers EDL regeneration in a background thread to prevent blocking API responses.
    """
    if _REGEN_LOCK.locked():
        logger.info("Background regeneration already queued or running.")
        return
    
    thread = threading.Thread(target=regenerate_edl_files, name="EDLRegenThread")
    thread.daemon = True
    thread.start()
    logger.info("Started background EDL regeneration thread.")


class FeedAggregator:
    """
    Encapsulates logic for fetching, parsing, and storing threat feed data (Async).
    """
    def __init__(self, db_conn=None):
        self.db_conn = db_conn

    async def fetch_data(self, source_config, session=None):
        """
        Fetches data from the source asynchronously.
        """
        url = source_config["url"]
        start_time = time.time()

        auth = None
        if source_config.get("auth_user") and source_config.get("auth_pass"):
            auth = BasicAuth(source_config["auth_user"], source_config["auth_pass"])

        raw_data = await fetch_data_from_url_async(url, session=session, auth=auth)

        duration = time.time() - start_time
        return raw_data, [], duration

    def parse_data(self, raw_data, source_config):
        """
        Parses raw data (CPU bound, but usually fast enough to keep sync).
        """
        data_format = source_config.get("format", "text")
        key_or_column = source_config.get("key_or_column")
        name = source_config["name"]

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
                job_service.update_job_status(source_name, "Enriching", f"Enriched {i + 1}/{total} items...")
        return enriched_data

    def save_batch(self, items, source_name):
        """
        Sync DB operation. Should be run in executor.
        Optimized to use a single connection transaction for all batches.
        """
        from .database.connection import db_transaction
        
        batch_size = 5000
        total_batches = (len(items) + batch_size - 1) // batch_size

        logger.info(f"[{source_name}] Starting DB upsert for {len(items)} items in {total_batches} batches.")
        job_service.update_job_status(source_name, "Saving", f"Writing {len(items)} items (0/{total_batches} batches)...")

        # Use a single connection/transaction for the whole process to avoid overhead
        with db_transaction(self.db_conn) as conn:
            for i in range(0, len(items), batch_size):
                batch = items[i:i + batch_size]
                current_batch_num = (i // batch_size) + 1

                max_retries = 3
                for attempt in range(max_retries):
                    try:
                        # Pass the existing connection to avoid creating new ones
                        upsert_indicators_bulk(batch, source_name=source_name, conn=conn)
                        
                        msg = f"Written batch {current_batch_num}/{total_batches} ({len(batch)} items)"
                        # Reduce log noise for huge files, log every 5 batches
                        if current_batch_num % 5 == 0 or current_batch_num == total_batches:
                            logger.info(f"[{source_name}] {msg}")
                        
                        job_service.update_job_status(source_name, "Saving", msg)
                        break
                    except Exception as e:
                        # CRITICAL FIX: Rollback the transaction to clear "aborted" state before retry
                        try:
                            conn.rollback()
                        except Exception as rb_e:
                            logger.error(f"Failed to rollback transaction: {rb_e}")

                        if attempt < max_retries - 1:
                            logger.warning(f"[{source_name}] Error writing batch {current_batch_num} (Attempt {attempt+1}): {e}. Retrying...")
                            time.sleep(2 * (attempt + 1))
                        else:
                            logger.error(f"[{source_name}] Failed to write batch {current_batch_num} after {max_retries} attempts: {e}")

    async def process_source(self, source_config, recalculate=True, session=None):
        name = source_config["name"]
        loop = asyncio.get_event_loop()

        # Log Start (DB Op - Run in Executor)
        job_id = await loop.run_in_executor(None, log_job_start, name, self.db_conn)
        job_service.update_job_status(name, "Fetching", f"Downloading from {source_config['url']}")

        try:
            raw_data, items, duration = await self.fetch_data(source_config, session=session)

            if raw_data:
                if not items and source_config.get("format") != "taxii":
                    job_service.update_job_status(name, "Parsing", "Parsing data format...")
                    items = self.parse_data(raw_data, source_config)

                job_service.update_job_status(name, "Filtering", f"Filtering whitelist ({len(items)} items)...")
                # Whitelist Check (DB Op - Run in Executor)
                filtered_items = await loop.run_in_executor(None, self.filter_whitelist, items)

                job_service.update_job_status(name, "Enriching", f"Enriching {len(filtered_items)} items...")
                enriched_items = self.enrich_data(filtered_items, name)

                if enriched_items:
                    # Save Batch (DB Op - Run in Executor)
                    await loop.run_in_executor(None, self.save_batch, enriched_items, name)

                count = len(enriched_items)

                if recalculate:
                    job_service.update_job_status(name, "Scoring", "Recalculating risk scores...")
                    try:
                        full_config = read_config()
                        confidence_map = {s['name']: s.get('confidence', 50) for s in full_config.get('source_urls', [])}
                    except Exception:
                        confidence_map = {name: source_config.get('confidence', 50)}

                    await loop.run_in_executor(None, recalculate_scores, confidence_map, self.db_conn, name)

                await loop.run_in_executor(None, log_job_end, job_id, "success", count, f"Fetch time: {duration:.2f}s", self.db_conn)
                job_service.update_job_status(name, "Completed", f"Processed {count} items.")

                return {
                    "name": name,
                    "count": count,
                    "fetch_time": f"{duration:.2f} seconds",
                    "last_updated": datetime.now(UTC).isoformat()
                }
            else:
                msg = "No data fetched"
                # If we want to be very precise, we could pass the status from collector, 
                # but the collector already logged the 404 warning.
                # Let's check if the source is still in config but failing.
                await loop.run_in_executor(None, log_job_end, job_id, "warning", 0, msg, self.db_conn)
                job_service.update_job_status(name, "Completed", "No data fetched (Source might be offline).")
                return {"name": name, "count": 0, "fetch_time": f"{duration:.2f} seconds", "last_updated": datetime.now(UTC).isoformat()}

        except Exception as e:
            logger.error(f"Error processing {name}: {e}")
            await loop.run_in_executor(None, log_job_end, job_id, "failure", 0, str(e), self.db_conn)
            job_service.update_job_status(name, "Failed", str(e))
            raise


async def aggregate_sources_async(source_urls):
    aggregator = FeedAggregator()

    # Create a single session for all requests
    async with await get_async_session() as session:
        tasks = [aggregator.process_source(source, recalculate=False, session=session) for source in source_urls]
        results = []

        # Process all feeds concurrently
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

    # Cleanup Old Indicators & Expired Blacklist
    remove_expired_blacklist_items()
    retention_map = {s['name']: s.get('retention_days', default_lifetime) for s in source_urls}
    remove_old_indicators(retention_map, default_lifetime)

    all_url_counts = {}
    current_stats = read_stats()
    job_service.clear_all_job_statuses()

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

    # --- FIX: Update Stats with ACTUAL DB Counts ---
    actual_db_counts = get_source_counts()
    for name, count in actual_db_counts.items():
        if name in current_stats:
            current_stats[name]["count"] = count
        else:
            # If source exists in DB but not in current run stats (maybe disabled in config but has old data)
            # We can choose to show it or not. For now, let's only update existing entries or ensure structure.
            pass
            
    # Also ensure any source in source_urls has its count updated from DB if it exists
    for s in source_urls:
        s_name = s['name']
        if s_name in actual_db_counts:
            if s_name not in current_stats:
                current_stats[s_name] = {"fetch_time": "N/A", "last_updated": "N/A"}
            current_stats[s_name]["count"] = actual_db_counts[s_name]

    current_stats["last_updated"] = datetime.now(UTC).isoformat()
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
        # Run aggregation and capture result
        result = aggregate_single_source(source_config)

        # Update Stats immediately
        if result:
            current_stats = read_stats()
            
            # Use actual DB count instead of fetch count
            actual_db_counts = get_source_counts()
            db_count = actual_db_counts.get(name, result["count"]) # Fallback to result count if not in DB yet (unlikely)

            current_stats[name] = {
                "count": db_count,
                "fetch_time": result["fetch_time"],
                "last_updated": result["last_updated"]
            }
            # Update global last_updated too
            current_stats["last_updated"] = datetime.now(UTC).isoformat()
            write_stats(current_stats)

        _cleanup_whitelisted_items_from_db()
        regenerate_edl_files()
        logger.info(f"Completed scheduled fetch for {name}.")
    except Exception as e:
        logger.error(f"Scheduled fetch failed for {name}: {e}")


# Re-alias main to run_aggregator
main = run_aggregator


def test_feed_source(source_config):
    """
    Tests a feed source using the FeedAggregator logic without saving.
    """
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
