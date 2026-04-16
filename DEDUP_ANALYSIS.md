# DNS Deduplication Issue Analysis

## Problem
The DNS deduplication system shows **0 deleted items** every time, even when there should be duplicates.

## Root Cause Found
The DNS resolution cache is **completely empty** (0 entries):
```
=== DNS CACHE ===
Total entries: 0
```

However, there ARE indicators in the database:
```
=== INDICATORS ===
cidr: 9,771
domain: 456,508
ip: 162,508
url: 6,228
```

## Why This Happens

### Issue #1: DNS Deduplication is Disabled by Default
In `threat_feed_aggregator/config/schema.py`, the default configuration is:
```python
class DnsDedupSchedule(BaseModel):
    enabled: bool = False  # ← DISABLED BY DEFAULT
    auto_delete: bool = False
    start_time: str = "00:00"
    end_time: str = "23:59"
    interval_minutes: int = 60
    batch_size: int = 50
```

Since `dns_dedup_schedule` is not defined in your `config.json`, the system uses these defaults with `enabled: False`.

### Issue #2: When Disabled, the Batch Job Never Runs
In `threat_feed_aggregator/scheduler_manager.py`:
```python
dedup_config = config.get('dns_dedup_schedule', {})
if dedup_config.get('enabled', False):  # ← This is False, so job is never scheduled
    scheduler.add_job(check_and_run_dns_dedup, ...)
```

Without the scheduled job:
1. `process_background_dns_batch()` is never called
2. DNS cache never gets populated with resolved domain→IP mappings
3. `run_deduplication_sweep()` has nothing to process
4. Result: **deleted = 0**

## The Deduplication Workflow (Correct Order)

1. **Phase 1: DNS Resolution (Batch)**
   - Finds domains in indicators table
   - Resolves them to IPs using DNS queries
   - Stores in `dns_resolution_cache` table

2. **Phase 2: Duplicate Detection (Sweep)**
   - Loads all IP indicators into memory
   - Checks each cached domain's resolved IPs against the IP list
   - If match found → domain is a duplicate (resolves to a known threat IP)
   - Deletes matching domains from indicators table

## Solution

### Option A: Enable DNS Deduplication in config.json (Recommended)

Add this to your `threat-feed-aggregator/data/config.json`:

```json
{
    "indicator_lifetime_days": 30,
    "dns_dedup_schedule": {
        "enabled": true,
        "auto_delete": false,
        "start_time": "00:00",
        "end_time": "23:59",
        "interval_minutes": 60,
        "batch_size": 50
    },
    "source_urls": [
        ...existing sources...
    ]
}
```

Then:
1. **Restart the application** - scheduler will pick up the new config
2. **Wait for the next batch** - deduplication batch job will run every 60 minutes
3. **Monitor logs** - check for DNS resolution progress
4. **Deletions will happen** - once cache is populated and sweep runs

### Option B: Manual Testing via API

If you want to test immediately without restarting:
1. Enable DNS dedup in config
2. Restart app
3. Call the manual endpoint:
   ```
   POST /tools/api/dns_deduplication/analyze
   ```
   This will:
   - Resolve 50 domains (populate cache)
   - Run deduplication sweep immediately
   - Return: `{resolved: N, deleted: M}`

## Expected Behavior After Fix

Once DNS deduplication is enabled:
1. Cache gradually fills with resolved domains (50 per batch cycle)
2. After first batch: `GET dns_resolution_cache` shows entries
3. In sweep phase: domains that resolve to threat IPs get deleted
4. Log shows: `Deduplication Sweep Complete. Scanned X cached domains. Removed Y duplicates.`

## Monitoring

Check progress with:
```python
import sqlite3
conn = sqlite3.connect('threat-feed-aggregator/data/threat_feed.db')
cursor = conn.execute('SELECT COUNT(*) FROM dns_resolution_cache')
cache_count = cursor.fetchone()[0]
print(f"DNS Cache entries: {cache_count}")  # Should increase over time
```

## Performance Notes

- **Batch size**: 50 domains per cycle (configurable)
- **Interval**: Default 60 minutes between batches
- **Window**: Resolves during 00:00-23:59 (full day)
- **Retry**: Domains retry every 7 days if not improved
- **Memory**: All threat IPs loaded to memory for set intersection check

## Code Locations

- Config schema: `threat_feed_aggregator/config/schema.py` (line 54-80)
- DNS service: `threat_feed_aggregator/services/dns_deduplication.py`
- Scheduler: `threat_feed_aggregator/scheduler_manager.py` (line 79-125)
- API endpoint: `threat_feed_aggregator/routes/tools.py` (line 128-150)
