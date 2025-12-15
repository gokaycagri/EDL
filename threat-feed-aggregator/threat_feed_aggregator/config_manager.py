import os
import json
import sys
from datetime import datetime, timezone

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
        return os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

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

def read_config():
    target_file = CONFIG_FILE
    # Fallback to default if user config missing
    if not os.path.exists(target_file):
        target_file = CONFIG_FILE_DEFAULT
        
    if not os.path.exists(target_file):
        return {"source_urls": []}
        
    with open(target_file, "r") as f:
        return json.load(f)

def write_config(config):
    # Always write to user config
    with open(CONFIG_FILE, "w") as f:
        json.dump(config, f, indent=4)

def read_stats():
    if not os.path.exists(STATS_FILE):
        return {}
    with open(STATS_FILE, "r") as f:
        try:
            stats = json.load(f)
            if isinstance(stats, dict):
                for key, value in stats.items():
                    if not isinstance(value, dict):
                        stats[key] = {}
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
    stats["last_updated"] = datetime.now(timezone.utc).isoformat()
    write_stats(stats)