import logging
import os
from urllib.parse import quote as _url_quote

from apscheduler.jobstores.sqlalchemy import SQLAlchemyJobStore
from apscheduler.schedulers.background import BackgroundScheduler

from .config_manager import DATA_DIR, read_config

logger = logging.getLogger(__name__)

# Scheduler Initialization
db_type = os.getenv("DB_TYPE", "sqlite")
if db_type == "postgres":
    db_user = os.getenv("DB_USER", "threat_user")
    db_pass = os.getenv("DB_PASS", "")
    db_host = os.getenv("DB_HOST", "postgres")
    db_port = os.getenv("DB_PORT", "5432")
    db_name = os.getenv("DB_NAME", "threat_feed")
    db_url = f"postgresql://{db_user}:{_url_quote(db_pass, safe='')}@{db_host}:{db_port}/{db_name}"
    try:
        jobstores = {"default": SQLAlchemyJobStore(url=db_url)}
    except Exception as _e:
        _safe_url = f"postgresql://{db_user}:***@{db_host}:{db_port}/{db_name}"
        logger.error("Failed to connect to scheduler job store at %s: %s", _safe_url, _e)
        raise
else:
    jobstores = {"default": SQLAlchemyJobStore(url=f"sqlite:///{os.path.join(DATA_DIR, 'jobs.sqlite')}")}

# misfire_grace_time: If a job is missed by more than X seconds, don't run it (Prevents thundering herd on startup)
# coalesce: If multiple runs of a job are missed, run it only once.
job_defaults = {"misfire_grace_time": 60, "coalesce": True, "max_instances": 1}

scheduler = BackgroundScheduler(jobstores=jobstores, job_defaults=job_defaults)


def _fetch_feed_by_name(source_name):
    """Look up the current config for a source by name and fetch it."""
    from .aggregator import fetch_and_process_single_feed

    config = read_config()
    source_config = next(
        (s for s in config.get("source_urls", []) if s["name"] == source_name),
        None,
    )
    if not source_config:
        logger.warning(f"Source '{source_name}' no longer in config, skipping scheduled fetch.")
        return
    fetch_and_process_single_feed(source_config)


def _run_expired_blacklist_cleanup():
    """
    Scheduled task: purge expired api_blacklist entries and immediately
    regenerate EDL files so firewalls stop enforcing removed blocks.

    Runs every 6 hours. First execution is triggered immediately on
    scheduler start (next_run_time=now) so any already-expired items
    accumulated before this job existed are cleaned up without waiting.
    """
    from .aggregator import regenerate_edl_files
    from .repositories.whitelist_repo import remove_expired_blacklist_items
    from .services.audit_service import log_action

    try:
        deleted, expired_items = remove_expired_blacklist_items()
        if deleted > 0:
            # Log each removed item for traceability
            for item in expired_items:
                logger.info(
                    "Blacklist cleanup: expired item removed — ip=%s type=%s comment=%r expired_at=%s",
                    item["item"], item["type"], item["comment"], item["expires_at"],
                )
            # Single audit log entry summarising the batch
            removed_ips = ", ".join(i["item"] for i in expired_items[:50])
            log_action(
                "scheduler",
                "blacklist_cleanup",
                target=f"{deleted} expired item(s)",
                details=removed_ips,
                ip_address="scheduler",
            )
            logger.info("Blacklist cleanup: %d item(s) removed — regenerating EDL files.", deleted)
            regenerate_edl_files()
        else:
            logger.debug("Blacklist cleanup: no expired items found.")
    except Exception as e:
        logger.error("Blacklist cleanup job failed: %s", e)


def _run_indicator_ttl_cleanup():
    """
    Nightly TTL cleanup — deletes indicators not seen within indicator_lifetime_days.
    Respects per-source retention_days overrides from config.
    After cleanup, regenerates EDL files so firewalls see the updated list immediately.
    """
    try:
        from .edl_generator import regenerate_edl_files
        from .repositories.indicator_repo import remove_old_indicators

        config = read_config()
        lifetime_days = config.get("indicator_lifetime_days", 30)
        retention_map = {
            s["name"]: s.get("retention_days", lifetime_days)
            for s in config.get("source_urls", [])
        }
        deleted = remove_old_indicators(
            source_retention_map=retention_map,
            default_days=lifetime_days,
        )
        if deleted > 0:
            logger.info(
                "Indicator TTL cleanup: removed %d stale indicators (lifetime=%d days).",
                deleted,
                lifetime_days,
            )
            regenerate_edl_files()
        else:
            logger.debug("Indicator TTL cleanup: no stale indicators found (lifetime=%d days).", lifetime_days)
    except Exception as e:
        logger.error("Indicator TTL cleanup job failed: %s", e, exc_info=True)


def update_scheduled_jobs():
    """Refreshes the scheduler jobs based on current config."""
    from apscheduler.jobstores.base import ConflictingIdError
    from sqlalchemy.exc import IntegrityError

    from .azure_services import process_azure_feeds
    from .github_services import process_github_feeds
    from .microsoft_services import process_microsoft_feeds

    config = read_config()
    configured_sources = {source["name"]: source for source in config.get("source_urls", [])}

    try:
        # Clear only relevant jobs instead of all to avoid disrupting other master processes
        from apscheduler.jobstores.base import JobLookupError

        for job in scheduler.get_jobs():
            if job.id.startswith("feed_fetch_") or job.id in [
                "update_ms365",
                "update_github",
                "update_azure",
                "dns_deduplication_job",
                "cleanup_expired_blacklist",
                "cleanup_expired_indicators",
            ]:
                try:
                    scheduler.remove_job(job.id)
                except JobLookupError:
                    pass

        for source_name, source_config in configured_sources.items():
            interval_minutes = source_config.get("schedule_interval_minutes")
            if interval_minutes:
                job_id = f"feed_fetch_{source_name}"
                try:
                    scheduler.add_job(
                        _fetch_feed_by_name,
                        "interval",
                        minutes=interval_minutes,
                        id=job_id,
                        name=source_name,
                        args=[source_name],
                        replace_existing=True,
                    )
                    logger.info(f"Scheduled job for {source_name} to run every {interval_minutes} minutes.")
                except (ConflictingIdError, IntegrityError):
                    pass

        # Scheduled Service Updates (Every 24 hours)
        try:
            scheduler.add_job(
                process_microsoft_feeds,
                "interval",
                minutes=1440,
                id="update_ms365",
                name="Microsoft 365 Feeds",
                replace_existing=True,
            )
            scheduler.add_job(
                process_github_feeds,
                "interval",
                minutes=1440,
                id="update_github",
                name="GitHub Feeds",
                replace_existing=True,
            )
            scheduler.add_job(
                process_azure_feeds,
                "interval",
                minutes=1440,
                id="update_azure",
                name="Azure Feeds",
                replace_existing=True,
            )
        except (ConflictingIdError, IntegrityError):
            pass

        # DNS Deduplication Schedule
        dedup_config = config.get("dns_dedup_schedule", {})
        if dedup_config.get("enabled", False):
            interval = dedup_config.get("interval_minutes", 60)
            try:
                scheduler.add_job(
                    check_and_run_dns_dedup,
                    "interval",
                    minutes=interval,
                    id="dns_deduplication_job",
                    name="DNS Deduplication",
                    replace_existing=True,
                )
            except (ConflictingIdError, IntegrityError):
                pass

        # Expired Blacklist Cleanup — every 6 hours.
        # next_run_time=now ensures the job fires immediately on scheduler start so
        # any items that expired while this job did not yet exist are purged at boot.
        try:
            from datetime import UTC, datetime

            scheduler.add_job(
                _run_expired_blacklist_cleanup,
                "interval",
                hours=6,
                id="cleanup_expired_blacklist",
                name="Expired Blacklist Cleanup",
                replace_existing=True,
                next_run_time=datetime.now(UTC),
            )
            logger.info("Scheduled expired blacklist cleanup every 6 hours (first run: immediate).")
        except (ConflictingIdError, IntegrityError):
            pass

        # Indicator TTL Cleanup — every 24 hours.
        # next_run_time=now fires immediately on startup to clear the existing backlog
        # of stale indicators accumulated before this job was introduced.
        try:
            from datetime import UTC, datetime

            scheduler.add_job(
                _run_indicator_ttl_cleanup,
                "interval",
                hours=24,
                id="cleanup_expired_indicators",
                name="Indicator TTL Cleanup",
                replace_existing=True,
                next_run_time=datetime.now(UTC),
            )
            logger.info("Scheduled indicator TTL cleanup every 24 hours (first run: immediate).")
        except (ConflictingIdError, IntegrityError):
            pass

    except Exception as e:
        logger.error(f"Failed to update scheduled jobs: {e}")


def check_and_run_dns_dedup():
    """Checks if current time is within the allowed window and runs DNS Deduplication batch."""
    import asyncio
    from datetime import datetime

    from .services.dns_deduplication import process_background_dns_batch, run_deduplication_sweep

    config = read_config()
    conf = config.get("dns_dedup_schedule", {})
    if not conf.get("enabled", False):
        logger.info("DNS Deduplication: Scheduler trigger skipped (disabled in config).")
        return

    now = datetime.now().time()
    try:
        start_time = datetime.strptime(conf.get("start_time", "00:00"), "%H:%M").time()
        end_time = datetime.strptime(conf.get("end_time", "23:59"), "%H:%M").time()

        in_window = (
            (start_time <= now <= end_time) if start_time <= end_time else (start_time <= now or now <= end_time)
        )

        if in_window:
            batch_size = conf.get("batch_size", 50)
            logger.info(f"DNS Deduplication: Running batch (batch_size={batch_size}).")
            # Create a new event loop explicitly for thread safety
            loop = asyncio.new_event_loop()
            try:
                processed_count = loop.run_until_complete(process_background_dns_batch(batch_size=batch_size))
            finally:
                loop.close()
            logger.info(f"DNS Deduplication: Batch completed (processed={processed_count}).")
            if conf.get("auto_delete", False):
                deleted_count = run_deduplication_sweep()
                logger.info(f"DNS Deduplication: Auto-delete sweep completed (deleted={deleted_count}).")
            else:
                logger.info("DNS Deduplication: Auto-delete disabled; sweep skipped.")
        else:
            logger.info(f"DNS Deduplication: Scheduler trigger skipped (outside window {start_time}-{end_time}).")
    except Exception as e:
        logger.error(f"Background DNS Dedup failed: {e}")
