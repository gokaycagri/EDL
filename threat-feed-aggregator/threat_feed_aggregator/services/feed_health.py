"""
Feed health monitoring — tracks consecutive failures per source and auto-disables after threshold.
"""

from datetime import UTC, datetime
import logging
import threading

from ..config_manager import read_config, write_config

logger = logging.getLogger(__name__)

MAX_CONSECUTIVE_FAILURES = 3
_health_lock = threading.Lock()


def _get_health(config, source_name):
    """Get health entry for a source, initializing if needed."""
    health = config.setdefault("source_health", {})
    return health.setdefault(
        source_name,
        {
            "consecutive_failures": 0,
            "last_error": None,
            "disabled_at": None,
        },
    )


def is_source_disabled(source_name):
    """Check if a source has been auto-disabled due to repeated failures."""
    config = read_config()
    entry = config.get("source_health", {}).get(source_name, {})
    return entry.get("disabled_at") is not None


def record_success(source_name):
    """Reset failure counter on successful fetch."""
    with _health_lock:
        config = read_config()
        entry = _get_health(config, source_name)
        if entry["consecutive_failures"] > 0 or entry["disabled_at"]:
            entry["consecutive_failures"] = 0
            entry["last_error"] = None
            entry["disabled_at"] = None
            write_config(config)


def record_failure(source_name, error_message):
    """Increment failure counter. Auto-disable after MAX_CONSECUTIVE_FAILURES."""
    with _health_lock:
        config = read_config()
        entry = _get_health(config, source_name)
        entry["consecutive_failures"] += 1
        entry["last_error"] = str(error_message)[:200]

        if entry["consecutive_failures"] >= MAX_CONSECUTIVE_FAILURES and not entry["disabled_at"]:
            entry["disabled_at"] = datetime.now(UTC).isoformat()
            logger.warning(
                f"Feed '{source_name}' auto-disabled after {MAX_CONSECUTIVE_FAILURES} consecutive failures. "
                f"Last error: {error_message}"
            )

        write_config(config)
        return entry["consecutive_failures"] >= MAX_CONSECUTIVE_FAILURES


def reenable_source(source_name):
    """Manually re-enable a disabled source."""
    with _health_lock:
        config = read_config()
        entry = _get_health(config, source_name)
        entry["consecutive_failures"] = 0
        entry["last_error"] = None
        entry["disabled_at"] = None
        write_config(config)
        logger.info(f"Feed '{source_name}' manually re-enabled.")


def get_all_health_statuses():
    """Return health status for all sources."""
    config = read_config()
    return config.get("source_health", {})
