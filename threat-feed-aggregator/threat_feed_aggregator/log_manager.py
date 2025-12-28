import logging
import collections
import pytz
from datetime import datetime

# Circular buffer to hold the last 1000 log lines in memory
LOG_BUFFER = collections.deque(maxlen=1000)

class MemoryLogHandler(logging.Handler):
    """
    Custom logging handler that stores log records in a memory buffer.
    """
    def __init__(self):
        super().__init__()
        self.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(name)s - %(message)s'))

    def formatTime(self, record, datefmt=None):
        """
        Overridden to use the configured system timezone.
        """
        try:
            from .config_manager import read_config
            config = read_config()
            tz_name = config.get('timezone', 'UTC')
            tz = pytz.timezone(tz_name)
            
            # Convert record created time (UTC timestamp) to local datetime
            dt = datetime.fromtimestamp(record.created, tz=pytz.utc)
            local_dt = dt.astimezone(tz)
            
            if datefmt:
                return local_dt.strftime(datefmt)
            return local_dt.strftime('%Y-%m-%d %H:%M:%S,%f')[:-3]
        except Exception:
            return super().formatTime(record, datefmt)

    def emit(self, record):
        try:
            msg = self.format(record)
            LOG_BUFFER.append(msg)
        except Exception:
            self.handleError(record)

def get_live_logs():
    """
    Returns the current contents of the log buffer as a list.
    """
    return list(LOG_BUFFER)

def setup_memory_logging():
    """
    Attaches the memory handler to the root logger.
    """
    root_logger = logging.getLogger()
    
    # Check if we already added the handler to avoid duplicates on reload
    for h in root_logger.handlers:
        if isinstance(h, MemoryLogHandler):
            return

    memory_handler = MemoryLogHandler()
    root_logger.addHandler(memory_handler)
