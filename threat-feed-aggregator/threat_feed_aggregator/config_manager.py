from datetime import UTC, datetime
import json
import os
import sys


def get_base_path():
    """Get absolute path to resource, works for dev and for PyInstaller"""
    try:
        # PyInstaller creates a temp folder and stores path in _MEIPASS
        base_path = sys._MEIPASS
    except Exception:
        base_path = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    return base_path


def get_executable_dir():
    """Get the directory where the executable (or script) is located"""
    if getattr(sys, "frozen", False):
        return os.path.dirname(sys.executable)
    else:
        # Return the directory containing this script (threat_feed_aggregator)
        # So that data dir becomes .../threat_feed_aggregator/data
        return os.path.dirname(os.path.abspath(__file__))


# Internal resources (templates, default config) are in the code/temp dir
CODE_BASE_DIR = get_base_path()

# User data (DB, stats, output lists) should be next to the executable
USER_DATA_DIR = get_executable_dir()

# Paths
BASE_DIR = CODE_BASE_DIR  # For backward compatibility if needed internally
DATA_DIR = os.path.join(USER_DATA_DIR, "data")
CONFIG_FILE_DEFAULT = os.path.join(CODE_BASE_DIR, "threat_feed_aggregator", "config", "config.json")
# We copy config to user dir to allow editing
CONFIG_FILE = os.path.join(DATA_DIR, "config.json")
STATS_FILE = os.path.join(DATA_DIR, "stats.json")

# Ensure Data Dir Exists
if not os.path.exists(DATA_DIR):
    os.makedirs(DATA_DIR)

# Initialize User Config if not exists
if not os.path.exists(CONFIG_FILE) and os.path.exists(CONFIG_FILE_DEFAULT):
    import shutil

    try:
        shutil.copy(CONFIG_FILE_DEFAULT, CONFIG_FILE)
    except Exception:
        pass  # Handle case where source might be missing in some builds

import logging

# Configure logging to stdout
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(name)s - %(levelname)s - %(message)s")
logger = logging.getLogger(__name__)

import threading

_config_cache = None
_config_cache_mtime = 0
_config_lock = threading.Lock()


def read_config():
    global _config_cache, _config_cache_mtime
    target_file = CONFIG_FILE

    # Fallback to default if user config missing
    if not os.path.exists(target_file):
        # logger.warning(f"[Config] User config not found at {target_file}. Trying default.")
        target_file = CONFIG_FILE_DEFAULT

    if not os.path.exists(target_file):
        # logger.error(f"[Config] No config file found anywhere. Returning empty.")
        return {"source_urls": []}

    try:
        with _config_lock:
            current_mtime = os.stat(target_file).st_mtime
            if _config_cache is not None and current_mtime == _config_cache_mtime:
                return _config_cache

            with open(target_file) as f:
                data = json.load(f)
                _validate_config_safe(data)
                _config_cache = data
                _config_cache_mtime = current_mtime
                return data
    except Exception as e:
        logger.error(f"[Config] ERROR reading {target_file}: {e}")
        # Emergency fallback logic remains...
        if target_file != CONFIG_FILE_DEFAULT and os.path.exists(CONFIG_FILE_DEFAULT):
            try:
                # logger.warning(f"[Config] Attempting fallback to default config due to corruption.")
                with open(CONFIG_FILE_DEFAULT) as f:
                    return json.load(f)
            except Exception:
                pass
        return {"source_urls": []}


def _validate_config_safe(config):
    """Validate config and log errors. Returns True if valid."""
    try:
        from .config.schema import validate_config

        errors = validate_config(config)
        if errors:
            for err in errors:
                logger.warning(f"[Config Validation] {err}")
            return False
        return True
    except ImportError:
        return True  # pydantic not installed, skip validation
    except Exception as e:
        logger.error(f"[Config Validation] Unexpected error: {e}")
        return True  # don't block writes on validation crashes


def write_config(config):
    global _config_cache, _config_cache_mtime

    # Validate before writing — log warnings but don't block
    _validate_config_safe(config)

    try:
        # Write to temp file then rename for atomicity
        tmp_path = CONFIG_FILE + ".tmp"
        with open(tmp_path, "w") as f:
            json.dump(config, f, indent=4)
            f.flush()
            os.fsync(f.fileno())

        # Invalidate cache under lock BEFORE os.replace to prevent stale reads
        with _config_lock:
            os.replace(tmp_path, CONFIG_FILE)
            _config_cache = config
            _config_cache_mtime = os.stat(CONFIG_FILE).st_mtime

        # Verify write (Optional, can be removed for production speed)
        # with open(CONFIG_FILE, "r") as f: ...

    except Exception as e:
        logger.error(f"[Config] ERROR writing config: {e}")


def read_stats():
    if not os.path.exists(STATS_FILE):
        return {}
    with open(STATS_FILE) as f:
        try:
            stats = json.load(f)
            if isinstance(stats, dict):
                # Ensure existing source entries are dicts, but don't touch top-level strings like last_updated
                # Actually, let's just return what's in the file and handle types where used.
                return stats
        except json.JSONDecodeError:
            pass
    return {}


_stats_lock = threading.Lock()


def write_stats(stats):
    tmp_path = f"{STATS_FILE}.{os.getpid()}.tmp"
    with _stats_lock:
        with open(tmp_path, "w") as f:
            json.dump(stats, f, indent=4)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp_path, STATS_FILE)


def update_stats_last_updated(stats=None):
    if stats is None:
        stats = read_stats()
    stats["last_updated"] = datetime.now(UTC).isoformat()
    write_stats(stats)
