#!/usr/bin/env python3
"""Test stats.json writing functionality"""

import sys
import os
import json
import tempfile
import shutil

sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'threat-feed-aggregator'))

print("=" * 70)
print("STATS.JSON WRITE FUNCTIONALITY TEST")
print("=" * 70)

# Test 1: config_manager functions
print("\n1. Testing config_manager read/write functions:")
try:
    from threat_feed_aggregator.config_manager import read_stats, write_stats
    print("   ✓ Imports successful")
    
    # Create temp dir
    test_dir = tempfile.mkdtemp()
    stats_file = os.path.join(test_dir, 'stats.json')
    
    # Test write
    test_stats = {
        "dedup_stats": {
            "total_deleted": 5,
            "last_run": "2026-03-19T12:00:00",
            "last_deleted": 2
        },
        "test": "value"
    }
    
    # Monkey patch the stats file location
    import threat_feed_aggregator.config_manager as cm
    original_stats_file = cm.STATS_FILE
    cm.STATS_FILE = stats_file
    
    # Write stats
    write_stats(test_stats)
    print("   ✓ write_stats() executed")
    
    # Verify file was created
    if os.path.exists(stats_file):
        print("   ✓ stats.json file created")
        
        # Read file
        with open(stats_file) as f:
            read_data = json.load(f)
        
        # Verify content
        if read_data.get('dedup_stats', {}).get('total_deleted') == 5:
            print("   ✓ total_deleted value preserved")
        else:
            print("   ✗ total_deleted value NOT correct")
        
        if read_data.get('dedup_stats', {}).get('last_run') == "2026-03-19T12:00:00":
            print("   ✓ last_run timestamp preserved")
        else:
            print("   ✗ last_run timestamp NOT correct")
    else:
        print("   ✗ stats.json file NOT created")
    
    # Cleanup
    cm.STATS_FILE = original_stats_file
    shutil.rmtree(test_dir)
    print("   ✓ Cleanup successful")

except Exception as e:
    print(f"   ✗ ERROR: {e}")
    import traceback
    traceback.print_exc()

# Test 2: Check the logic in dns_deduplication.py
print("\n2. Testing dedup stats update logic:")
dns_file = "threat-feed-aggregator/threat_feed_aggregator/services/dns_deduplication.py"
with open(dns_file) as f:
    content = f.read()

checks = [
    ('stats = read_stats()', "Reading stats"),
    ('stats["dedup_stats"]', "Getting dedup_stats key"),
    ('total_deleted: 0', "Initializing total_deleted"),
    ('stats["dedup_stats"]["total_deleted"] +=' , "Incrementing total_deleted"),
    ('stats["dedup_stats"]["last_run"]', "Setting last_run"),
    ('stats["dedup_stats"]["last_deleted"]', "Setting last_deleted"),
    ('write_stats(stats)', "Writing stats back"),
]

for check_str, desc in checks:
    if check_str in content:
        print(f"   ✓ {desc}")
    else:
        print(f"   ✗ {desc} - NOT FOUND")

print("\n" + "=" * 70)
print("STATS TEST COMPLETE")
print("=" * 70)
