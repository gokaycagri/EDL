# Application Constants

# Database
DB_TIMEOUT = 30.0
BULK_INSERT_CHUNK_SIZE = 5000  # Rows per batch for indicator upsert

# Network
REQUEST_TIMEOUT_DEFAULT = 10
REQUEST_TIMEOUT_LONG = 30
FEED_FETCH_TIMEOUT_SECONDS = 30   # aiohttp ClientTimeout total for feed fetch
WEBHOOK_TIMEOUT_SECONDS = 5       # requests timeout for outbound webhook calls
USER_AGENT = "ThreatFeedAggregator/1.0"

# Scheduling
DEFAULT_SCHEDULE_INTERVAL_MINUTES = 60
DAILY_SCHEDULE_INTERVAL_MINUTES = 1440

# Defaults
DEFAULT_INDICATOR_LIFETIME_DAYS = 30

# File Import
MAX_IMPORT_FILE_BYTES = 10 * 1024 * 1024  # 10 MB
