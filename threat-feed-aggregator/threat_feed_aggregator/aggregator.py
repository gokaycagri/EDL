"""
Aggregation orchestration — coordinates feed fetching, cleanup, scoring, and EDL generation.

This module is the main entry point for aggregation. The heavy lifting is in:
  - feed_processor.py: FeedAggregator class, async source processing
  - edl_generator.py: EDL file generation with atomic writes
"""

import asyncio
from datetime import UTC, datetime
import logging

from .config_manager import read_config, read_stats, write_stats
from .db_manager import (
    delete_whitelisted_indicators as db_delete_whitelisted_indicators,
)
from .db_manager import (
    get_all_indicators_iter,
    get_source_counts,
    get_whitelist,
    recalculate_scores,
    remove_expired_blacklist_items,
    remove_old_indicators,
    save_historical_stats,
)

# Re-exports for backward compatibility
from .edl_generator import regenerate_edl_files  # noqa: F401
from .feed_processor import (  # noqa: F401
    FeedAggregator,
    aggregate_single_source,
    aggregate_sources_async,
    test_feed_source,
)
from .services.feed_health import is_source_disabled, record_failure, record_success
from .services.job_service import job_service
from .services.webhook_service import notify as webhook_notify
from .utils import is_whitelisted

logger = logging.getLogger(__name__)


def _cleanup_whitelisted_items_from_db():
    """Remove indicators that match whitelist entries (exact + CIDR)."""
    whitelist_db_items = get_whitelist()
    if not whitelist_db_items:
        return

    # 1. Exact match cleanup (fast SQL)
    exact_items = [w["item"] for w in whitelist_db_items if "/" not in w["item"]]
    if exact_items:
        chunk_size = 900
        for i in range(0, len(exact_items), chunk_size):
            db_delete_whitelisted_indicators(exact_items[i : i + chunk_size])

    # 2. CIDR match cleanup (iterative)
    cidr_filters = [w["item"] for w in whitelist_db_items if "/" in w["item"]]
    if not cidr_filters:
        return

    indicators_to_delete = []
    for row in get_all_indicators_iter():
        indicator = row["indicator"]
        whitelisted, _ = is_whitelisted(indicator, cidr_filters)
        if whitelisted:
            indicators_to_delete.append(indicator)
        if len(indicators_to_delete) >= 1000:
            db_delete_whitelisted_indicators(indicators_to_delete)
            indicators_to_delete = []
    if indicators_to_delete:
        db_delete_whitelisted_indicators(indicators_to_delete)


def run_aggregator(source_urls):
    """Main entry point for full aggregation (sync wrapper around async)."""
    config = read_config()
    default_lifetime = config.get("indicator_lifetime_days", 30)

    # Pre-cleanup
    remove_expired_blacklist_items()
    retention_map = {s["name"]: s.get("retention_days", default_lifetime) for s in source_urls}
    remove_old_indicators(retention_map, default_lifetime)

    all_url_counts = {}
    current_stats = read_stats()
    job_service.clear_all_job_statuses()

    # Async aggregation
    try:
        results = asyncio.run(aggregate_sources_async(source_urls))
        for result in results:
            if result:
                name = result["name"]
                current_stats[name] = {
                    "count": result["count"],
                    "fetch_time": result["fetch_time"],
                    "last_updated": result["last_updated"],
                }
                all_url_counts[name] = {"count": result["count"], "fetch_time": result["fetch_time"]}
    except Exception as e:
        logger.error(f"Critical error in async aggregation loop: {e}")

    # Post-processing: cleanup first, then score
    _cleanup_whitelisted_items_from_db()

    logger.info("Recalculating risk scores for all indicators...")
    confidence_map = {s["name"]: s.get("confidence", 50) for s in source_urls}
    recalculate_scores(confidence_map)

    # Update stats with actual DB counts
    actual_db_counts = get_source_counts()
    for name, count in actual_db_counts.items():
        if name in current_stats:
            current_stats[name]["count"] = count
    for s in source_urls:
        s_name = s["name"]
        if s_name in actual_db_counts:
            if s_name not in current_stats:
                current_stats[s_name] = {"fetch_time": "N/A", "last_updated": "N/A"}
            current_stats[s_name]["count"] = actual_db_counts[s_name]

    current_stats["last_updated"] = datetime.now(UTC).isoformat()
    write_stats(current_stats)
    save_historical_stats()
    regenerate_edl_files()

    # Webhook notification
    total_indicators = sum(v.get("count", 0) for v in all_url_counts.values())
    webhook_notify(
        "aggregation_complete",
        {
            "sources_processed": len(all_url_counts),
            "total_new_indicators": total_indicators,
        },
    )

    return {"url_counts": all_url_counts, "processed_data": []}


def fetch_and_process_single_feed(source_config):
    """Scheduled task wrapper for single-source fetch."""
    name = source_config["name"]

    # Skip auto-disabled sources
    if is_source_disabled(name):
        logger.info(f"Skipping disabled source: {name}")
        return

    logger.info(f"Starting scheduled fetch for {name}...")
    job_service.update_job_status(name, "Running", f"Scheduled fetch for {name}")
    try:
        result = aggregate_single_source(source_config)

        if result:
            record_success(name)
            current_stats = read_stats()
            actual_db_counts = get_source_counts()
            db_count = actual_db_counts.get(name, result["count"])
            current_stats[name] = {
                "count": db_count,
                "fetch_time": result["fetch_time"],
                "last_updated": result["last_updated"],
            }
            current_stats["last_updated"] = datetime.now(UTC).isoformat()
            write_stats(current_stats)

        # Skip full whitelist cleanup on single-feed runs — it runs during full aggregation.
        regenerate_edl_files()
        logger.info(f"Completed scheduled fetch for {name}.")
    except Exception as e:
        logger.error(f"Scheduled fetch failed for {name}: {e}")
        disabled = record_failure(name, str(e))
        if disabled:
            webhook_notify("feed_disabled", {"source": name, "error": str(e)[:200]})


# Backward-compatible alias
main = run_aggregator
