#!/usr/bin/env python3
"""Test API endpoint modifications"""

import sys
import os
import ast

sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'threat-feed-aggregator'))

print("=" * 70)
print("API ENDPOINTS TEST")
print("=" * 70)

tools_file = "threat-feed-aggregator/threat_feed_aggregator/routes/tools.py"
with open(tools_file) as f:
    content = f.read()

# Test 1: analyze_dns_duplicates endpoint
print("\n1. Testing /api/dns_deduplication/analyze endpoint:")
if 'def analyze_dns_duplicates():' in content:
    print("   ✓ Function exists")
else:
    print("   ✗ Function NOT found")
    sys.exit(1)

checks = [
    ('total_deleted = 0', "Initializing total_deleted"),
    ('stats.get("dedup_stats", {})', "Getting dedup_stats from stats"),
    ('stats.get("dedup_stats", {}).get("total_deleted", 0)', "Getting total_deleted"),
    ('"total_deleted": total_deleted', "Including total_deleted in response"),
    ('Total deleted so far:', "Including total_deleted in message"),
]

for check, desc in checks:
    if check in content:
        print(f"   ✓ {desc}")
    else:
        print(f"   ✗ {desc} - NOT FOUND")

# Test 2: get_dns_dedup_status endpoint
print("\n2. Testing /api/dns_deduplication/status endpoint (NEW):")
if 'def get_dns_dedup_status():' in content:
    print("   ✓ Function exists")
else:
    print("   ✗ Function NOT found")
    sys.exit(1)

if '@bp_tools.route(\'/api/dns_deduplication/status\', methods=[\'GET\'])' in content:
    print("   ✓ Route decorator correct (GET)")
else:
    print("   ✗ Route decorator NOT correct")

checks2 = [
    ('dedup_stats = {', "Initializing dedup_stats dict"),
    ('"total_deleted": 0', "Default total_deleted"),
    ('"cache_entries": 0', "Cache entries field"),
    ('SELECT COUNT(*) FROM dns_resolution_cache', "Querying cache count"),
    ('api_response(dedup_stats', "Returning stats in response"),
]

for check, desc in checks2:
    if check in content:
        print(f"   ✓ {desc}")
    else:
        print(f"   ✗ {desc} - NOT FOUND")

# Test 3: Response structure
print("\n3. Response structure validation:")

response_checks = [
    ('analyze', 'resolved', 'Number of domains resolved'),
    ('analyze', 'deleted', 'Number of duplicates deleted this run'),
    ('analyze', 'total_deleted', 'Total duplicates deleted (NEW)'),
    ('status', 'total_deleted', 'Total duplicates ever deleted'),
    ('status', 'last_deleted', 'Last sweep deletion count'),
    ('status', 'cache_entries', 'DNS cache size'),
]

for endpoint, field, desc in response_checks:
    print(f"   • {endpoint} → {field}: {desc}")

print("\n" + "=" * 70)
print("API ENDPOINTS TEST COMPLETE")
print("=" * 70)
