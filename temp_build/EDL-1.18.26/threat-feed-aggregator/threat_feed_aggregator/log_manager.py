import collections
import logging
import os
from logging.handlers import RotatingFileHandler
from datetime import datetime

import pytz

from .config_manager import DATA_DIR

# Circular buffer to hold the last 1000 log lines in memory
LOG_BUFFER = collections.deque(maxlen=1000)
LOG_FILE_PATH = os.path.join(DATA_DIR, 'app.log')

class TimezoneFormatter(logging.Formatter):
    """
    Custom formatter that handles timezone conversion.
    """
    def formatTime(self, record, datefmt=None):
        try:
            from .config_manager import read_config
            config = read_config()
            tz_name = config.get('timezone', 'UTC')
            tz = pytz.timezone(tz_name)

            dt = datetime.fromtimestamp(record.created, tz=pytz.utc)
            local_dt = dt.astimezone(tz)

            if datefmt:
                return local_dt.strftime(datefmt)
            return local_dt.strftime('%Y-%m-%d %H:%M:%S,%f')[:-3]
        except Exception:
            return super().formatTime(record, datefmt)

class MemoryLogHandler(logging.Handler):
    """
    Custom logging handler that stores log records in a memory buffer.
    """
    def __init__(self):
        super().__init__()
        self.setFormatter(TimezoneFormatter('%(asctime)s - %(levelname)s - %(name)s - %(message)s'))

    def emit(self, record):
        try:
            msg = self.format(record)
            LOG_BUFFER.append(msg)
        except Exception:
            self.handleError(record)

def _load_buffer_from_file():
    """
    Populates LOG_BUFFER with the last 1000 lines from the log file on startup.
    """
    if not os.path.exists(LOG_FILE_PATH):
        return

    try:
        with open(LOG_FILE_PATH, 'r', encoding='utf-8', errors='ignore') as f:
            # Efficiently read last 1000 lines
            # For simplicity in this context, reading all and taking last 1000 is okay for moderate file sizes (5MB rotation)
            lines = f.readlines()
            for line in lines[-1000:]:
                LOG_BUFFER.append(line.strip())
    except Exception as e:
        print(f"Error loading logs from file: {e}")

def get_live_logs():
    """
    Returns the current contents of the log buffer as a list.
    """
    return list(LOG_BUFFER)

def clear_logs():
    """
    Clears the log buffer.
    """
    LOG_BUFFER.clear()

class SessionFilter(logging.Filter):
    """
    Filters out harmless race-condition warnings from cachelib/flask_session.
    Happens when a session file is deleted while being accessed.
    """
    def filter(self, record):
        msg = record.getMessage()
        if "Exception raised while handling cache file" in msg and "flask_session" in msg:
            return False
        return True

def setup_memory_logging():
    """
    Attaches the memory handler and file handler to the root logger and adds filters.
    """
    root_logger = logging.getLogger()
    formatter = TimezoneFormatter('%(asctime)s - %(levelname)s - %(name)s - %(message)s')

    # 1. Setup Memory Handler (if not exists)
    has_memory_handler = any(isinstance(h, MemoryLogHandler) for h in root_logger.handlers)
    if not has_memory_handler:
        memory_handler = MemoryLogHandler()
        root_logger.addHandler(memory_handler)
        # Pre-load buffer from file if it exists
        _load_buffer_from_file()

    # 2. Setup File Handler (Persistent)
    has_file_handler = any(isinstance(h, RotatingFileHandler) for h in root_logger.handlers)
    if not has_file_handler:
        # Rotate at 5MB, keep 2 backups
        file_handler = RotatingFileHandler(LOG_FILE_PATH, maxBytes=5*1024*1024, backupCount=2)
        file_handler.setFormatter(formatter)
        file_handler.setLevel(logging.INFO)
        root_logger.addHandler(file_handler)
    
    # Add Filter to ignore noisy session warnings
    root_logger.addFilter(SessionFilter())
