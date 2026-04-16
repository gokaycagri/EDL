#!/usr/bin/env python3
"""Monitor DNS deduplication progress and effectiveness"""

import sqlite3
import json
from pathlib import Path
from datetime import datetime

db_path = Path('threat-feed-aggregator/data/threat_feed.db')

def get_stats():
    conn = sqlite3.connect(str(db_path))
    conn.row_factory = sqlite3.Row
    
    # Get counts by type
    cursor = conn.execute('''
        SELECT type, COUNT(*) as cnt FROM indicators 
        GROUP BY type 
        ORDER BY cnt DESC
    ''')
    indicators = {row['type']: row['cnt'] for row in cursor}
    
    # Get DNS cache status
    cursor = conn.execute('SELECT COUNT(*) as cnt FROM dns_resolution_cache')
    cache_count = cursor.fetchone()[0]
    
    # Get resolved vs unresolved
    cursor = conn.execute('''
        SELECT 
            COUNT(*) as total,
            SUM(CASE WHEN resolved_ips != '' THEN 1 ELSE 0 END) as resolved,
            SUM(CASE WHEN resolved_ips = '' THEN 1 ELSE 0 END) as unresolved
        FROM dns_resolution_cache
    ''')
    row = cursor.fetchone()
    cache_stats = {
        'total': row['total'] or 0,
        'resolved': row['resolved'] or 0,
        'unresolved': row['unresolved'] or 0
    }
    
    conn.close()
    
    return {
        'timestamp': datetime.now().isoformat(),
        'indicators': indicators,
        'dns_cache': cache_stats
    }

if __name__ == '__main__':
    stats = get_stats()
    print(json.dumps(stats, indent=2))
    
    # Summary
    print("\n=== DEDUPLICATION STATUS ===")
    print(f"Total Indicators: {sum(stats['indicators'].values()):,}")
    print(f"  - IPs: {stats['indicators'].get('ip', 0):,}")
    print(f"  - Domains: {stats['indicators'].get('domain', 0):,}")
    print(f"  - URLs: {stats['indicators'].get('url', 0):,}")
    print(f"  - CIDR: {stats['indicators'].get('cidr', 0):,}")
    
    cache = stats['dns_cache']
    print(f"\nDNS Cache: {cache['total']:,} entries")
    if cache['total'] > 0:
        pct = (cache['resolved'] / cache['total']) * 100
        print(f"  - Resolved: {cache['resolved']:,} ({pct:.1f}%)")
        print(f"  - Unresolved: {cache['unresolved']:,}")
