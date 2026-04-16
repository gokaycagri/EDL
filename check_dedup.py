#!/usr/bin/env python3
"""Check DNS deduplication status in the database"""

import sqlite3
from pathlib import Path

db_path = Path('threat-feed-aggregator/data/threat_feed.db')

if db_path.exists():
    conn = sqlite3.connect(str(db_path))
    conn.row_factory = sqlite3.Row
    
    # Check indicators
    cursor = conn.execute('SELECT COUNT(*) as cnt, type FROM indicators GROUP BY type')
    print('=== INDICATORS ===')
    rows = cursor.fetchall()
    if rows:
        for row in rows:
            print(f'{row["type"]}: {row["cnt"]}')
    else:
        print('No indicators found')
    
    # Check specific IP count
    cursor = conn.execute('SELECT COUNT(*) as ip_count FROM indicators WHERE type = "ip"')
    ip_count = cursor.fetchone()[0]
    print(f'Total IPs: {ip_count}')
    
    if ip_count > 0:
        cursor = conn.execute('SELECT indicator FROM indicators WHERE type = "ip" LIMIT 3')
        print('Sample IPs:')
        for row in cursor:
            print(f'  {row[0]}')
    
    # Check DNS cache
    cursor = conn.execute('SELECT COUNT(*) as cnt FROM dns_resolution_cache')
    dns_count = cursor.fetchone()[0]
    print(f'\n=== DNS CACHE ===')
    print(f'Total entries: {dns_count}')
    
    if dns_count > 0:
        cursor = conn.execute('SELECT domain, resolved_ips FROM dns_resolution_cache LIMIT 5')
        print('Sample entries:')
        for row in cursor:
            resolved = row[1] if row[1] else "(empty)"
            print(f'  {row[0]} -> {resolved}')
    
    conn.close()
else:
    print('Database file not found at:', db_path)
