#!/usr/bin/env python3
"""Test DNS deduplication with stats update"""

import json
import sys
sys.path.insert(0, 'threat-feed-aggregator')

from threat_feed_aggregator.services.dns_deduplication import run_deduplication_sweep

# Run the sweep
result = run_deduplication_sweep()
print(f'\n✓ Sweep completed. Removed: {result}')

# Check stats file
with open('threat-feed-aggregator/data/stats.json') as f:
    stats = json.load(f)
    if 'dedup_stats' in stats:
        print('\nStats Updated:')
        print(json.dumps(stats['dedup_stats'], indent=2, ensure_ascii=False))
    else:
        print('Dedup stats not found in stats.json')

# Summary
print('\n=== DURUMU KONTROL ETTİ ===')
print(f'En son tarama: {result} duplicate silindi')
if 'dedup_stats' in stats:
    total = stats['dedup_stats'].get('total_deleted', 0)
    print(f'Toplamda silinmiş: {total} duplicate')
