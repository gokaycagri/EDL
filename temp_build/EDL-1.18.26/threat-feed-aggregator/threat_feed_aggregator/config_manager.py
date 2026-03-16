import json
import os
import sys
from datetime import UTC, datetime


def get_base_path():
    """ Get absolute path to resource, works for dev and for PyInstaller """
    try:
        # PyInstaller creates a temp folder and stores path in _MEIPASS
        base_path = sys._MEIPASS
    except Exception:
        base_path = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    return base_path

def get_executable_dir():
    """ Get the directory where the executable (or script) is located """
    if getattr(sys, 'frozen', False):
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
BASE_DIR = CODE_BASE_DIR # For backward compatibility if needed internally
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
        pass # Handle case where source might be missing in some builds

import logging

# Configure logging to stdout
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

_config_cache = None
_config_cache_mtime = 0

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
        current_mtime = os.stat(target_file).st_mtime
        if _config_cache and current_mtime == _config_cache_mtime:
            return _config_cache

        # Debug: Check file stats
        # stats = os.stat(target_file)
        # logger.info(f"[Config] Reading {target_file} | Size: {stats.st_size} | Mtime: {stats.st_mtime}")

        with open(target_file) as f:
            data = json.load(f)
            _config_cache = data
            _config_cache_mtime = current_mtime

            # Check specific keys to debug the issue
            # if 'proxy' in data:
            #      logger.info(f"[Config] READ CONTENT: Proxy Enabled={data['proxy'].get('enabled')}, Server={data['proxy'].get('server')}")
            # else:
            #      logger.info(f"[Config] READ CONTENT: Proxy key MISSING")
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

def write_config(config):
    global _config_cache, _config_cache_mtime
    try:
        # logger.info(f"[Config] WRITING to {CONFIG_FILE}. Proxy Enabled: {config.get('proxy', {}).get('enabled')}")
        with open(CONFIG_FILE, "w") as f:
            json.dump(config, f, indent=4)
            f.flush()
            os.fsync(f.fileno()) # Force write to disk

        # Update cache immediately to prevent stale reads
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

def write_stats(stats):
    with open(STATS_FILE, "w") as f:
        json.dump(stats, f, indent=4)

def update_stats_last_updated(stats=None):
    if stats is None:
        stats = read_stats()
    stats["last_updated"] = datetime.now(UTC).isoformat()
    write_stats(stats)
