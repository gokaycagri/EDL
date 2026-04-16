#!/usr/bin/env python3
"""Test all modified imports"""

import sys
import os
import traceback

# Add threat-feed-aggregator to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'threat-feed-aggregator'))

print("=" * 60)
print("TESTING IMPORTS")
print("=" * 60)

# Test 1: dns_deduplication imports
print("\n1. Testing dns_deduplication.py imports...")
try:
    from threat_feed_aggregator.services.dns_deduplication import (
        run_deduplication_sweep,
        process_background_dns_batch
    )
    print("   ✓ dns_deduplication imports OK")
except Exception as e:
    print(f"   ✗ ERROR: {e}")
    traceback.print_exc()
    sys.exit(1)

# Test 2: tools.py imports
print("\n2. Testing tools.py imports...")
try:
    from threat_feed_aggregator.routes.tools import (
        analyze_dns_duplicates,
        get_dns_dedup_status
    )
    print("   ✓ tools.py imports OK")
except Exception as e:
    print(f"   ✗ ERROR: {e}")
    traceback.print_exc()
    sys.exit(1)

# Test 3: config_manager imports
print("\n3. Testing config_manager imports...")
try:
    from threat_feed_aggregator.config_manager import read_stats, write_stats
    print("   ✓ config_manager imports OK")
except Exception as e:
    print(f"   ✗ ERROR: {e}")
    traceback.print_exc()
    sys.exit(1)

print("\n" + "=" * 60)
print("ALL IMPORTS SUCCESSFUL ✓")
print("=" * 60)
