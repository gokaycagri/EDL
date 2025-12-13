import logging
import collections
from datetime import datetime, timezone

# Circular buffer to hold the last 1000 log lines in memory
LOG_BUFFER = collections.deque(maxlen=1000)

class MemoryLogHandler(logging.Handler):
    """
    Custom logging handler that stores log records in a memory buffer.
    """
    def __init__(self):
        super().__init__()
        # Use a standard formatter
        self.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(name)s - %(message)s'))

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
