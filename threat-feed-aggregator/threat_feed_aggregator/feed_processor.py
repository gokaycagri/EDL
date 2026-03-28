"""
Feed processing — async fetch, parse, filter, enrich, and save threat feed data.
"""
import asyncio
from datetime import UTC, datetime
import logging
import time

from aiohttp import BasicAuth

from .config_manager import read_config
from .data_collector import fetch_data_from_url_async, get_async_session
from .db_manager import (
    get_whitelist,
    log_job_end,
    log_job_start,
    recalculate_scores,
    upsert_indicators_bulk,
)
from .geoip_manager import get_country_code
from .parsers import get_parser
from .services.job_service import job_service
from .utils import is_whitelisted

logger = logging.getLogger(__name__)


class FeedAggregator:
    """Encapsulates logic for fetching, parsing, and storing threat feed data (Async)."""

    def __init__(self, db_conn=None):
        self.db_conn = db_conn

    async def fetch_data(self, source_config, session=None):
        url = source_config["url"]
        start_time = time.time()

        auth = None
        if source_config.get("auth_user") and source_config.get("auth_pass"):
            auth = BasicAuth(source_config["auth_user"], source_config["auth_pass"])

        raw_data = await fetch_data_from_url_async(url, session=session, auth=auth)
        duration = time.time() - start_time
        return raw_data, [], duration

    def parse_data(self, raw_data, source_config):
        data_format = source_config.get("format", "text")
        key_or_column = source_config.get("key_or_column")
        name = source_config["name"]
        parser = get_parser(data_format)
        return parser(raw_data, source_name=name, key=key_or_column, column=key_or_column)

    def filter_whitelist(self, items):
        whitelist_db = get_whitelist(conn=self.db_conn)
        whitelist_filters = [w["item"] for w in whitelist_db]
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
            if item_type == "ip":
                try:
                    country = get_country_code(item)
                except Exception:
                    pass
            enriched_data.append((item, country, item_type))
            if (i + 1) % 10000 == 0:
                job_service.update_job_status(source_name, "Enriching", f"Enriched {i + 1}/{total} items...")
        return enriched_data

    def save_batch(self, items, source_name):
        """Each batch gets its own transaction so a failure in batch N does not roll back 1..N-1."""
        batch_size = 5000
        total_batches = (len(items) + batch_size - 1) // batch_size

        logger.info(f"[{source_name}] Starting DB upsert for {len(items)} items in {total_batches} batches.")
        job_service.update_job_status(source_name, "Saving", f"Writing {len(items)} items (0/{total_batches} batches)...")

        for i in range(0, len(items), batch_size):
            batch = items[i : i + batch_size]
            current_batch_num = (i // batch_size) + 1

            max_retries = 3
            for attempt in range(max_retries):
                try:
                    upsert_indicators_bulk(batch, source_name=source_name)
                    msg = f"Written batch {current_batch_num}/{total_batches} ({len(batch)} items)"
                    if current_batch_num % 5 == 0 or current_batch_num == total_batches:
                        logger.info(f"[{source_name}] {msg}")
                    job_service.update_job_status(source_name, "Saving", msg)
                    break
                except Exception as e:
                    if attempt < max_retries - 1:
                        logger.warning(f"[{source_name}] Error writing batch {current_batch_num} (Attempt {attempt+1}): {e}. Retrying...")
                        time.sleep(0.5 * (attempt + 1))
                    else:
                        logger.error(f"[{source_name}] Failed to write batch {current_batch_num} after {max_retries} attempts: {e}")

    async def process_source(self, source_config, recalculate=True, session=None):
        name = source_config["name"]
        loop = asyncio.get_running_loop()

        job_id = await loop.run_in_executor(None, log_job_start, name, self.db_conn)
        job_service.update_job_status(name, "Fetching", f"Downloading from {source_config['url']}")

        try:
            raw_data, items, duration = await self.fetch_data(source_config, session=session)

            if raw_data:
                if not items and source_config.get("format") != "taxii":
                    job_service.update_job_status(name, "Parsing", "Parsing data format...")
                    items = self.parse_data(raw_data, source_config)

                job_service.update_job_status(name, "Filtering", f"Filtering whitelist ({len(items)} items)...")
                filtered_items = await loop.run_in_executor(None, self.filter_whitelist, items)

                job_service.update_job_status(name, "Enriching", f"Enriching {len(filtered_items)} items...")
                enriched_items = self.enrich_data(filtered_items, name)

                if enriched_items:
                    await loop.run_in_executor(None, self.save_batch, enriched_items, name)

                count = len(enriched_items)

                if recalculate:
                    job_service.update_job_status(name, "Scoring", "Recalculating risk scores...")
                    try:
                        full_config = read_config()
                        confidence_map = {s["name"]: s.get("confidence", 50) for s in full_config.get("source_urls", [])}
                    except Exception:
                        confidence_map = {name: source_config.get("confidence", 50)}
                    await loop.run_in_executor(None, recalculate_scores, confidence_map, self.db_conn, name)

                await loop.run_in_executor(None, log_job_end, job_id, "success", count, f"Fetch time: {duration:.2f}s", self.db_conn)
                job_service.update_job_status(name, "Completed", f"Processed {count} items.")

                return {
                    "name": name,
                    "count": count,
                    "fetch_time": f"{duration:.2f} seconds",
                    "last_updated": datetime.now(UTC).isoformat(),
                }
            else:
                msg = "No data fetched"
                await loop.run_in_executor(None, log_job_end, job_id, "warning", 0, msg, self.db_conn)
                job_service.update_job_status(name, "Completed", "No data fetched (Source might be offline).")
                return {"name": name, "count": 0, "fetch_time": f"{duration:.2f} seconds", "last_updated": datetime.now(UTC).isoformat()}

        except Exception as e:
            logger.error(f"Error processing {name}: {e}")
            await loop.run_in_executor(None, log_job_end, job_id, "failure", 0, str(e), self.db_conn)
            job_service.update_job_status(name, "Failed", str(e))
            raise


async def aggregate_sources_async(source_urls):
    """Process all sources concurrently with a shared aiohttp session."""
    aggregator = FeedAggregator()
    async with await get_async_session() as session:
        tasks = [aggregator.process_source(source, recalculate=False, session=session) for source in source_urls]
        results_or_exceptions = await asyncio.gather(*tasks, return_exceptions=True)
        results = []
        for res in results_or_exceptions:
            if isinstance(res, Exception):
                logger.error(f"Task failed with: {res}")
            else:
                results.append(res)
        return results


def aggregate_single_source(source_config, recalculate=True):
    """Sync wrapper for single source."""
    aggregator = FeedAggregator()
    return asyncio.run(aggregator.process_source(source_config, recalculate))


def test_feed_source(source_config):
    """Tests a feed source without saving to DB."""
    aggregator = FeedAggregator()

    async def _test():
        try:
            if not source_config["url"].startswith(("http://", "https://")):
                return False, "Invalid URL format.", []
            raw_data, items, _ = await aggregator.fetch_data(source_config)
            if not raw_data:
                return False, "No data fetched from URL.", []
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
