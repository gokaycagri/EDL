import logging
import threading
from datetime import UTC, datetime

logger = logging.getLogger(__name__)

class JobService:
    _instance = None
    _lock = threading.Lock()

    def __new__(cls):
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:
                    cls._instance = super(JobService, cls).__new__(cls)
                    cls._instance._initialized = False
        return cls._instance

    def __init__(self):
        if self._initialized:
            return
        self._initialized = True
        
        # Global Aggregation Status (e.g., "idle", "running")
        self._aggregation_status = "idle"
        
        # Detailed Job Status Map (source_name -> {status, details, timestamp})
        self._current_job_status = {}
        
        self._status_lock = threading.Lock()

    @property
    def aggregation_status(self):
        with self._status_lock:
            return self._aggregation_status

    @aggregation_status.setter
    def aggregation_status(self, value):
        with self._status_lock:
            self._aggregation_status = value
            logger.debug(f"Global Aggregation Status changed to: {value}")

    def update_job_status(self, source_name, status, details=None):
        """Updates the in-memory status of a specific job."""
        with self._status_lock:
            self._current_job_status[source_name] = {
                "status": status,
                "details": details,
                "timestamp": datetime.now(UTC).isoformat()
            }

    def clear_job_status(self, source_name):
        """Removes a job from the in-memory status tracker."""
        with self._status_lock:
            if source_name in self._current_job_status:
                del self._current_job_status[source_name]
    
    def clear_all_job_statuses(self):
        with self._status_lock:
            self._current_job_status.clear()

    def get_all_job_statuses(self):
        with self._status_lock:
            return self._current_job_status.copy()

# Singleton Instance
job_service = JobService()
