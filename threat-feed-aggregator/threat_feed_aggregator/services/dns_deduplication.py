import asyncio
from datetime import UTC, datetime
import logging
from urllib.parse import urlparse

import aiodns

from ..db_manager import (
    delete_indicators,
    get_all_indicators_iter,
    get_dns_resolution_cache_iter,
    get_domains_for_resolution,
    update_dns_cache_batch,
)
from ..config_manager import read_stats, write_stats

logger = logging.getLogger(__name__)

async def resolve_domain(resolver, domain):
    try:
        # A record lookup
        result = await resolver.query(domain, 'A')
        return [r.host for r in result]
    except Exception:
        return []

def extract_domain(indicator, itype):
    if itype == 'url':
        try:
            parsed = urlparse(indicator)
            if parsed.hostname:
                return parsed.hostname
        except Exception:
            pass
        # If urlparse fails, skip rather than return nonsense like "http:"
        return None
    return indicator

async def process_background_dns_batch(batch_size=50):
    """
    Background task: Only resolves domains and updates the cache.
    Does NOT delete anything. Deletion is handled by run_deduplication_sweep.
    """
    # 1. Get candidates (Domains not resolved recently)
    candidates = get_domains_for_resolution(limit=batch_size, retry_days=7)
    logger.info(f"DNS Batch: Started (batch_size={batch_size}).")

    if not candidates:
        logger.info("DNS Batch: No domains found for resolution.")
        return 0

    logger.info(f"DNS Batch: Resolving {len(candidates)} domains...")

    # 2. Resolve Async
    loop = asyncio.get_running_loop()
    resolver = aiodns.DNSResolver(loop=loop)

    tasks = []
    items_to_process = []

    for item in candidates:
        original = item['indicator']
        itype = item['type']
        domain = extract_domain(original, itype)

        if not domain:
            continue

        items_to_process.append({
            'original': original,
            'domain': domain
        })
        tasks.append(resolve_domain(resolver, domain))

    results = await asyncio.gather(*tasks)

    # 3. Prepare Data for Cache
    cache_updates = []
    now_iso = datetime.now(UTC).isoformat()

    for idx, ips in enumerate(results):
        item = items_to_process[idx]

        # Store IPs as comma-separated string
        ip_str = ",".join(ips)
        cache_updates.append({
            'domain': item['original'],
            'resolved_ips': ip_str,
            'last_resolved': now_iso
        })

    # 4. Update Cache Only
    if cache_updates:
        update_dns_cache_batch(cache_updates)
        resolved_non_empty = sum(1 for item in cache_updates if item['resolved_ips'])
        logger.info(
            f"DNS Batch: Cache updated for {len(cache_updates)} domains; "
            f"{resolved_non_empty} resolved with at least one A record."
        )
    else:
        logger.info("DNS Batch: No cache updates were generated.")

    return len(candidates)

def run_deduplication_sweep():
    """
    Core Logic:
    1. Loads ALL known malicious IPs from DB.
    2. Iterates through the DNS Resolution Cache.
    3. If a cached domain resolves to a malicious IP, delete the domain.
    """
    logger.info("Starting DNS Deduplication Sweep (Cache vs IP List)...")

    # 1. Load all Threat IPs into memory (efficient Set)
    threat_ips = set()
    for row in get_all_indicators_iter():
        if row['type'] == 'ip':
            threat_ips.add(row['indicator'])

    if not threat_ips:
        logger.info("Deduplication Sweep: No IP indicators found to check against.")
        return 0

    # 2. Iterate Cache and Check
    domains_to_delete = []
    scanned_count = 0

    # Batch delete to manage memory
    BATCH_DELETE_SIZE = 1000
    total_deleted = 0

    cache_iter = get_dns_resolution_cache_iter()

    for row in cache_iter:
        domain = row['domain']
        resolved_ips_str = row['resolved_ips']
        scanned_count += 1

        if not resolved_ips_str:
            continue

        # Parse IPs from CSV
        resolved_ips = resolved_ips_str.split(',')

        # Check intersection
        # If ANY resolved IP is in our threat_ips set
        if any(ip in threat_ips for ip in resolved_ips):
            domains_to_delete.append(domain)

        if len(domains_to_delete) >= BATCH_DELETE_SIZE:
            count = delete_indicators(domains_to_delete)
            total_deleted += count
            domains_to_delete = []

    # Final Flush
    if domains_to_delete:
        count = delete_indicators(domains_to_delete)
        total_deleted += count

    logger.info(f"Deduplication Sweep Complete. Scanned {scanned_count} cached domains. Removed {total_deleted} duplicates.")
    
    # Update stats.json with deduplication results
    try:
        stats = read_stats()
        if "dedup_stats" not in stats:
            stats["dedup_stats"] = {
                "total_deleted": 0,
                "last_run": None,
                "last_deleted": 0
            }
        stats["dedup_stats"]["total_deleted"] += total_deleted
        stats["dedup_stats"]["last_run"] = datetime.now(UTC).isoformat()
        stats["dedup_stats"]["last_deleted"] = total_deleted
        write_stats(stats)
        logger.info(f"Stats updated. Total duplicates removed so far: {stats['dedup_stats']['total_deleted']}")
    except Exception as e:
        logger.error(f"Failed to update dedup stats: {e}")
    
    return total_deleted
