#!/usr/bin/env python3
"""Test code quality and error handling"""

import sys
import os

print("=" * 70)
print("CODE QUALITY & ERROR HANDLING TEST")
print("=" * 70)

# Test 1: Error handling in dns_deduplication.py
print("\n1. DNS Deduplication error handling:")
dns_file = "threat-feed-aggregator/threat_feed_aggregator/services/dns_deduplication.py"
with open(dns_file) as f:
    content = f.read()

error_checks = [
    ('try:', "Try block for stats update"),
    ('except Exception as e:', "Exception catching"),
    ('logger.error(f"Failed to update dedup stats:', "Error logging"),
]

for check, desc in error_checks:
    if check in content:
        print(f"   ✓ {desc}")
    else:
        print(f"   ✗ {desc} - NOT FOUND")

# Test 2: Error handling in tools.py
print("\n2. Tools.py error handling:")
tools_file = "threat-feed-aggregator/threat_feed_aggregator/routes/tools.py"
with open(tools_file) as f:
    content = f.read()

# Count try-except blocks in analyze_dns_duplicates
if 'def analyze_dns_duplicates():' in content:
    print("   ✓ analyze_dns_duplicates exists")
    
    # Extract function
    start = content.find('def analyze_dns_duplicates():')
    end = content.find('\n@', start + 1)
    func_content = content[start:end]
    
    if 'try:' in func_content and 'except Exception as e:' in func_content:
        print("   ✓ Error handling in analyze_dns_duplicates")
    else:
        print("   ✗ Error handling missing in analyze_dns_duplicates")

if 'def get_dns_dedup_status():' in content:
    print("   ✓ get_dns_dedup_status exists")
    
    # Check for error handling
    start = content.find('def get_dns_dedup_status():')
    end = content.find('\n@', start + 1)
    if end == -1:
        end = len(content)
    func_content = content[start:end]
    
    if 'try:' in func_content and 'except Exception as e:' in func_content:
        print("   ✓ Error handling in get_dns_dedup_status")
    else:
        print("   ✗ Error handling missing in get_dns_dedup_status")

# Test 3: Logging statements
print("\n3. Logging coverage:")
dns_file = "threat-feed-aggregator/threat_feed_aggregator/services/dns_deduplication.py"
with open(dns_file) as f:
    content = f.read()

if 'logger.info(f"Stats updated' in content:
    print("   ✓ Logging for successful stats update")
else:
    print("   ✗ Logging for stats update NOT found")

if 'logger.error(f"Failed to update dedup stats' in content:
    print("   ✓ Logging for stats update error")
else:
    print("   ✗ Logging for stats error NOT found")

# Test 4: Type of operations
print("\n4. Data integrity checks:")
if 'write_stats(stats)' in content:
    print("   ✓ Stats are persisted to disk")
else:
    print("   ✗ Stats persistence NOT found")

if 'db_readonly' in open(tools_file).read():
    print("   ✓ Using read-only DB connection for status queries")
else:
    print("   ? Database connection type not clearly verified")

# Test 5: Backward compatibility
print("\n5. Backward compatibility:")
tools_content = open(tools_file).read()

if '"success": True' in tools_content and '"deleted": deleted_count' in tools_content:
    print("   ✓ Original response fields preserved")
else:
    print("   ✗ Original fields might be missing")

if '"success": True' in tools_content:
    print("   ✓ Uses standard API response format")
else:
    print("   ✗ Non-standard response format")

print("\n" + "=" * 70)
print("CODE QUALITY TEST COMPLETE")
print("=" * 70)
