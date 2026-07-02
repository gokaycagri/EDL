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
    upsert_sgb_metadata,
)
from .geoip_manager import get_country_code
from .parsers import get_parser
from .services.job_service import job_service
from .utils import is_rfc1918_private_ipv4_indicator, is_whitelisted

logger = logging.getLogger(__name__)


def _extract_items(data, response_path: str | None, key_or_column: str | None) -> list[str]:
    """Extract a flat list of indicator strings from a JSON response.

    response_path: dot-notation path to the list inside the response, e.g. "models" or "data.items".
                   If None/empty, data itself is expected to be a list.
    key_or_column: field name to extract from each list element when elements are dicts.
                   If None, str(element) is used.
    """
    node = data
    if response_path:
        for key in response_path.split("."):
            if isinstance(node, dict):
                node = node.get(key)
            else:
                node = None
            if node is None:
                return []

    if not isinstance(node, list):
        return []

    results = []
    for item in node:
        if isinstance(item, dict) and key_or_column:
            keys = key_or_column.split(".")
            val = item
            for k in keys:
                val = val.get(k) if isinstance(val, dict) else None
            if val:
                results.append(str(val))
        elif not isinstance(item, dict):
            results.append(str(item))
    return results


class FeedAggregator:
    """Encapsulates logic for fetching, parsing, and storing threat feed data (Async)."""

    def __init__(self, db_conn=None):
        self.db_conn = db_conn
        self._sgb_metadata: dict[str, dict] = {}

    async def fetch_data(self, source_config, session=None):
        start_time = time.time()

        if source_config.get("format") == "sgb":
            raw_data = await self._fetch_sgb_paginated(source_config, session=session)
        elif source_config.get("fetch_type") == "api":
            raw_data = await self._fetch_api_paginated(source_config, session=session)
        else:
            url = source_config["url"]
            auth = None
            if source_config.get("auth_user") and source_config.get("auth_pass"):
                auth = BasicAuth(source_config["auth_user"], source_config["auth_pass"])
            raw_data = await fetch_data_from_url_async(url, session=session, auth=auth)

        duration = time.time() - start_time
        return raw_data, [], duration

    async def _fetch_sgb_paginated(self, source_config, session=None):
        """SGB (Siber Güvenlik Başkanlığı) dedicated fetcher.

        Fetches paginated SGB API and returns tab-separated 'url<TAB>type' lines.
        Uses the 'pageCount' field from the first response to avoid over-fetching.
        """
        import aiohttp as _aiohttp

        from .config_manager import read_config as _read_config
        from .utils import get_proxy_settings as _get_proxy_settings

        url = source_config.get("url", "https://siberguvenlik.gov.tr/api/address/index")
        page_start = source_config.get("api_page_start", 0)
        max_pages = source_config.get("api_max_pages", 25000)

        _, proxy_url, _ = _get_proxy_settings()
        config = _read_config()
        bypass_hosts = config.get("ssl_bypass_hosts", [])
        ssl_param = False if any(h in url for h in bypass_hosts) else None
        timeout = _aiohttp.ClientTimeout(total=60)

        all_lines: list[str] = []
        self._sgb_metadata.clear()

        async def _fetch_all(s):
            page_count_limit = None
            consecutive_errors = 0
            for page_num in range(page_start, page_start + max_pages):
                if page_count_limit is not None and page_num >= page_count_limit:
                    break
                try:
                    async with s.get(
                        url, params={"page": page_num}, timeout=timeout, proxy=proxy_url, ssl=ssl_param
                    ) as resp:
                        resp.raise_for_status()
                        data = await resp.json(content_type=None)
                except Exception as page_err:
                    consecutive_errors += 1
                    logger.warning("SGB: page %d fetch error (%s) — %d consecutive", page_num, page_err, consecutive_errors)
                    if consecutive_errors >= 5:
                        logger.error("SGB: aborting after %d consecutive page errors at page %d", consecutive_errors, page_num)
                        break
                    await asyncio.sleep(1)
                    continue
                consecutive_errors = 0

                # Learn total pages from first response
                if page_count_limit is None and "pageCount" in data:
                    page_count_limit = data["pageCount"]
                    logger.info("SGB: total pages = %d", page_count_limit)

                models = data.get("models", [])
                if not models:
                    break
                for item in models:
                    item_url = item.get("url")
                    item_type = item.get("type", "")
                    if item_url:
                        all_lines.append(f"{item_url}\t{item_type}")
                        self._sgb_metadata[item_url] = {
                            "sgb_desc": item.get("desc"),
                            "sgb_source": item.get("source"),
                            "sgb_date": item.get("date"),
                            "sgb_criticality": item.get("criticality_level"),
                        }
                logger.debug("SGB page %d: %d items (total so far: %d)", page_num, len(models), len(all_lines))

        try:
            if session:
                await _fetch_all(session)
            else:
                resolver = _aiohttp.ThreadedResolver()
                connector = _aiohttp.TCPConnector(resolver=resolver, ssl=ssl_param)
                async with _aiohttp.ClientSession(connector=connector) as new_session:
                    await _fetch_all(new_session)
        except Exception as e:
            logger.error("SGB fetch failed for %s: %s", url, e, exc_info=True)
            if all_lines:
                logger.warning("SGB: returning %d partially fetched indicators despite error", len(all_lines))
            else:
                return None

        if not all_lines:
            return None
        return "\n".join(all_lines)

    async def _fetch_api_paginated(self, source_config, session=None):
        """Generic REST API fetcher with optional pagination support."""
        import base64 as _base64

        import aiohttp as _aiohttp

        from .config_manager import read_config as _read_config
        from .utils import get_proxy_settings as _get_proxy_settings

        url = source_config["url"]

        headers = dict(source_config.get("api_headers") or {})
        if source_config.get("auth_user") and source_config.get("auth_pass"):
            credentials = f"{source_config['auth_user']}:{source_config['auth_pass']}"
            encoded = _base64.b64encode(credentials.encode()).decode()
            headers["Authorization"] = f"Basic {encoded}"

        response_path = source_config.get("api_response_path")
        pagination_enabled = source_config.get("api_pagination_enabled", False)
        page_param = source_config.get("api_page_param")
        page_start = source_config.get("api_page_start", 0)
        max_pages = source_config.get("api_max_pages", 50)
        key_or_column = source_config.get("key_or_column")

        _, proxy_url, _ = _get_proxy_settings()
        config = _read_config()
        bypass_hosts = config.get("ssl_bypass_hosts", [])
        ssl_param = False if any(h in url for h in bypass_hosts) else None
        timeout = _aiohttp.ClientTimeout(total=30)

        all_items: list[str] = []

        async def _do_request(s, params):
            async with s.get(url, headers=headers, params=params, timeout=timeout, proxy=proxy_url, ssl=ssl_param) as resp:
                resp.raise_for_status()
                return await resp.json(content_type=None)

        async def _fetch_with_session(s):
            if not pagination_enabled or not page_param:
                data = await _do_request(s, {})
                return _extract_items(data, response_path, key_or_column)

            collected = []
            for page_num in range(page_start, page_start + max_pages):
                data = await _do_request(s, {page_param: page_num})
                items = _extract_items(data, response_path, key_or_column)
                if not items:
                    break
                collected.extend(items)
                logger.debug("API fetch page %d: %d items", page_num, len(items))
            return collected

        try:
            if session:
                all_items = await _fetch_with_session(session)
            else:
                resolver = _aiohttp.ThreadedResolver()
                connector = _aiohttp.TCPConnector(resolver=resolver, ssl=ssl_param)
                async with _aiohttp.ClientSession(connector=connector) as new_session:
                    all_items = await _fetch_with_session(new_session)
        except Exception as e:
            logger.error("API fetch failed for %s: %s", url, e)
            return None

        if not all_items:
            return None
        return "\n".join(all_items)

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
        dropped_private = 0
        for item, item_type in items:
            if not item or item_type == "unknown":
                continue
            if is_rfc1918_private_ipv4_indicator(item, item_type):
                dropped_private += 1
                continue
            whitelisted, _ = is_whitelisted(item, whitelist_filters)
            if not whitelisted:
                filtered_items.append((item, item_type))
        if dropped_private:
            logger.warning("Skipped %s RFC1918 private IPv4 indicators during feed filtering.", dropped_private)
        return filtered_items

    def enrich_data(self, items, source_name):
        enriched_data = []
        total = len(items)
        for i, (item, item_type) in enumerate(items):
            country = None
            if item_type == "ip":
                try:
                    country = get_country_code(item)
                except Exception as e:
                    logger.warning("GeoIP lookup failed for %r: %s", item, e)
            enriched_data.append((item, country, item_type))
            if (i + 1) % 10000 == 0:
                job_service.update_job_status(source_name, "Enriching", f"Enriched {i + 1}/{total} items...")
        return enriched_data

    def save_batch(self, items, source_name):
        """Each batch gets its own transaction so a failure in batch N does not roll back 1..N-1."""
        batch_size = 5000
        total_batches = (len(items) + batch_size - 1) // batch_size

        logger.info(f"[{source_name}] Starting DB upsert for {len(items)} items in {total_batches} batches.")
        job_service.update_job_status(
            source_name, "Saving", f"Writing {len(items)} items (0/{total_batches} batches)..."
        )

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
                        logger.warning(
                            f"[{source_name}] Error writing batch {current_batch_num} (Attempt {attempt + 1}): {e}. Retrying..."
                        )
                        time.sleep(0.5 * (attempt + 1))
                    else:
                        logger.error(
                            f"[{source_name}] Failed to write batch {current_batch_num} after {max_retries} attempts: {e}"
                        )

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
                enriched_items = await loop.run_in_executor(None, self.enrich_data, filtered_items, name)

                if enriched_items:
                    await loop.run_in_executor(None, self.save_batch, enriched_items, name)

                # Save SGB metadata sidecar (only for sgb format sources)
                if source_config.get("format") == "sgb" and self._sgb_metadata:
                    sgb_meta_for_save = {}
                    for norm_ind, _itype in filtered_items:
                        meta = self._sgb_metadata.get(norm_ind) or self._sgb_metadata.get(norm_ind.lower())
                        if meta:
                            sgb_meta_for_save[norm_ind] = meta
                        else:
                            logger.debug("SGB: no metadata for normalized indicator %r", norm_ind)
                    if sgb_meta_for_save:
                        await loop.run_in_executor(None, upsert_sgb_metadata, sgb_meta_for_save)

                count = len(enriched_items)

                if recalculate:
                    job_service.update_job_status(name, "Scoring", "Recalculating risk scores...")
                    try:
                        full_config = read_config()
                        confidence_map = {
                            s["name"]: s.get("confidence", 50) for s in full_config.get("source_urls", [])
                        }
                    except Exception:
                        confidence_map = {name: source_config.get("confidence", 50)}
                    await loop.run_in_executor(None, recalculate_scores, confidence_map, self.db_conn, name)

                await loop.run_in_executor(
                    None, log_job_end, job_id, "success", count, f"Fetch time: {duration:.2f}s", self.db_conn
                )
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
                return {
                    "name": name,
                    "count": 0,
                    "fetch_time": f"{duration:.2f} seconds",
                    "last_updated": datetime.now(UTC).isoformat(),
                }

        except BaseException as e:
            # Catches Exception AND asyncio.CancelledError / KeyboardInterrupt / SystemExit
            # so job_history is always closed even on container shutdown.
            err_msg = f"{type(e).__name__}: {e}"
            logger.error(f"Error processing {name}: {err_msg}")
            try:
                await loop.run_in_executor(None, log_job_end, job_id, "failure", 0, err_msg, self.db_conn)
            except Exception as e:
                logger.warning("log_job_end failed for job %s: %s", job_id, e)
            job_service.update_job_status(name, "Failed", err_msg)
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
            valid_items = [
                item
                for item, item_type in items
                if item and item_type != "unknown" and not is_rfc1918_private_ipv4_indicator(item, item_type)
            ]
            count = len(valid_items)
            sample = valid_items[:5]
            if count == 0:
                return False, "Data fetched but no valid indicators found.", []
            return True, f"Success! Found {count} valid indicators.", sample
        except Exception as e:
            return False, f"Error testing feed: {str(e)}", []

    return asyncio.run(_test())
